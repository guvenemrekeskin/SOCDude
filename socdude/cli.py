"""Entry point: wires the SIEM adapter, gating, IOC extraction,
enrichment, correlation, confidence scoring, AI analysis, and Telegram
delivery together.

Supports three extra flags on top of the normal Wazuh invocation
(`custom-socdude <alert_file> <hook_url> <api_key>`), for local testing
without a live Wazuh manager:

  --test <alert.json>   Run the full pipeline against a local alert
                          file (see samples/) instead of one Wazuh wrote.
                          Uses a throw-away state DB so repeated test
                          runs never get suppressed by the cooldown.
  --dry-run              Print the final Telegram message to stdout
                          instead of sending it.
  --config <path>        Load config from a path other than
                          /etc/socdude/config.json (handy for testing
                          before running install.sh at all).

Example (from a checked-out repo, before installing anything):
  python3 run_test_alert.py samples/alert_ssh_bruteforce.json --dry-run \\
      --config config.example.json
"""

from __future__ import annotations

import logging
import sys
import tempfile
from typing import List, Optional

from . import ai_analyzer, correlation, enrichment, ioc_extractor, mitre, notifier, risk_scoring, state
from .config import CONFIG_FILE, load_config
from .siem import get_adapter, render_structured_fields

LOG_FILE = "/var/ossec/logs/integrations.log"


def _setup_logging() -> None:
    try:
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.DEBUG,
            format="%(asctime)s [custom-socdude] %(message)s",
        )
    except (PermissionError, FileNotFoundError):
        # Local/test runs outside the installed environment won't have
        # write access to /var/ossec/logs - fall back to stderr rather
        # than crashing before we've even parsed args.
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [custom-socdude] %(message)s",
        )


def _parse_args(args: List[str]):
    dry_run = False
    persist_state = False
    test_alert_path: Optional[str] = None
    config_path = CONFIG_FILE
    passthrough: List[str] = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--dry-run":
            dry_run = True
        elif arg == "--persist-state":
            persist_state = True
        elif arg == "--test":
            i += 1
            test_alert_path = args[i] if i < len(args) else None
        elif arg == "--config":
            i += 1
            config_path = args[i] if i < len(args) else CONFIG_FILE
        else:
            passthrough.append(arg)
        i += 1

    return dry_run, persist_state, test_alert_path, config_path, passthrough


def main(argv: Optional[List[str]] = None) -> None:
    argv = argv if argv is not None else sys.argv
    _setup_logging()
    logging.debug("Script triggered. argv=%s", argv)

    dry_run, persist_state, test_alert_path, config_path, passthrough = _parse_args(argv[1:])
    cfg = load_config(config_path)
    adapter = get_adapter(cfg["siem_platform"])

    if test_alert_path:
        parse_argv = ["socdude", test_alert_path]
        if persist_state:
            # Opt-in: reuse the configured state DB so correlation can
            # actually build up history across multiple --test runs.
            db_path = cfg["state_db_path"]
            logging.debug("TEST MODE: alert=%s, persistent state db=%s", test_alert_path, db_path)
        else:
            # Default: a fresh throw-away DB per run, so repeated test
            # runs never get eaten by the per-rule cooldown.
            db_path = tempfile.mktemp(prefix="socdude_test_", suffix=".db")
            logging.debug("TEST MODE: alert=%s, ephemeral state db=%s", test_alert_path, db_path)
    else:
        parse_argv = ["socdude"] + passthrough if passthrough else argv
        db_path = cfg["state_db_path"]

    try:
        alert = adapter.parse_alert(parse_argv)
    except NotImplementedError as exc:
        logging.error(str(exc))
        return

    if alert is None:
        return

    logging.debug("Alert level=%s, min_level=%s, rule_id=%s", alert.level, cfg["min_level"], alert.rule_id)
    if alert.level < cfg["min_level"]:
        logging.debug("Below severity threshold, skipping.")
        if test_alert_path:
            print(f"Alert level {alert.level} is below min_level {cfg['min_level']} - "
                  f"pipeline would not run for this alert in production. "
                  f"Lower min_level in {config_path} to test it anyway.")
        return

    if not state.gate_check(db_path, alert.rule_id, alert.agent_id, cfg):
        logging.debug("Suppressed by cooldown/burst limiter.")
        if test_alert_path:
            print("Suppressed by cooldown/burst limiter (unexpected in test mode - "
                  "the ephemeral DB should prevent this; check for a leftover temp file).")
        return

    # Fetch correlation history BEFORE recording this event, so the
    # current alert doesn't show up inside its own "recent activity".
    correlation_events = correlation.gather_context(db_path, alert.agent_id, cfg)
    state.record_event(db_path, alert.agent_id, alert.rule_id, alert.level, alert.description, alert.raw)

    iocs = ioc_extractor.extract_iocs(alert.raw, alert.full_log)
    ioc_table = ioc_extractor.render_ioc_table(iocs)

    structured_fields_text = render_structured_fields(alert.structured_fields)

    mitre_hints = mitre.get_mitre_hints(alert.raw)
    mitre_text = mitre.render_mitre_hints(mitre_hints)

    logging.debug("Running IOC enrichment...")
    enrichment_results = enrichment.enrich_iocs(iocs, cfg, db_path)
    enrichment_text = enrichment.render_enrichment(enrichment_results)

    correlation_text = correlation.render_timeline(correlation_events)

    confidence = risk_scoring.compute_confidence(
        alert.level, enrichment_results, correlation_events, len(mitre_hints)
    )
    confidence_text = risk_scoring.render_confidence(confidence)
    logging.debug("Computed confidence: %s", confidence)

    logging.debug("Requesting AI analysis...")
    prompt = ai_analyzer.build_prompt(
        alert, ioc_table, mitre_text, enrichment_text, correlation_text,
        structured_fields_text, confidence_text,
    )
    analysis = ai_analyzer.get_ai_analysis(prompt, cfg)

    message = notifier.build_message(alert, ioc_table, analysis, confidence)

    if dry_run or test_alert_path:
        import html as _html
        plain = _html.unescape(message)
        plain = plain.replace("<b>", "").replace("</b>", "").replace("<pre>", "").replace("</pre>", "")
        print(plain)
        logging.debug("Dry run / test mode - message printed to stdout, not sent to Telegram.")
        return

    ok = notifier.send_telegram(message, cfg)
    logging.debug("Telegram send result: %s", ok)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        # Catch-all so nothing fails silently - Wazuh gives no other
        # indication that the integration script crashed.
        logging.error("UNEXPECTED ERROR: %s", exc, exc_info=True)
