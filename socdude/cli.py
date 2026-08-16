"""Entry point: wires the SIEM adapter, gating, IOC extraction,
enrichment, correlation, AI analysis, and Telegram delivery together.
"""

from __future__ import annotations

import logging
import sys
from typing import List, Optional

from . import ai_analyzer, correlation, enrichment, ioc_extractor, mitre, notifier, state
from .config import load_config
from .siem import get_adapter

LOG_FILE = "/var/ossec/logs/integrations.log"


def _setup_logging() -> None:
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.DEBUG,
        format="%(asctime)s [custom-socdude] %(message)s",
    )


def main(argv: Optional[List[str]] = None) -> None:
    argv = argv if argv is not None else sys.argv
    _setup_logging()
    logging.debug("Script triggered. argv=%s", argv)

    cfg = load_config()
    adapter = get_adapter(cfg["siem_platform"])

    try:
        alert = adapter.parse_alert(argv)
    except NotImplementedError as exc:
        logging.error(str(exc))
        return

    if alert is None:
        return

    logging.debug("Alert level=%s, min_level=%s, rule_id=%s", alert.level, cfg["min_level"], alert.rule_id)
    if alert.level < cfg["min_level"]:
        logging.debug("Below severity threshold, skipping.")
        return

    db_path = cfg["state_db_path"]

    if not state.gate_check(db_path, alert.rule_id, alert.agent_id, cfg):
        logging.debug("Suppressed by cooldown/burst limiter.")
        return

    # Fetch correlation history BEFORE recording this event, so the
    # current alert doesn't show up inside its own "recent activity".
    correlation_events = correlation.gather_context(db_path, alert.agent_id, cfg)
    state.record_event(db_path, alert.agent_id, alert.rule_id, alert.level, alert.description, alert.raw)

    iocs = ioc_extractor.extract_iocs(alert.raw, alert.full_log)
    ioc_table = ioc_extractor.render_ioc_table(iocs)

    mitre_hints = mitre.get_mitre_hints(alert.raw)
    mitre_text = mitre.render_mitre_hints(mitre_hints)

    logging.debug("Running IOC enrichment...")
    enrichment_results = enrichment.enrich_iocs(iocs, cfg, db_path)
    enrichment_text = enrichment.render_enrichment(enrichment_results)

    correlation_text = correlation.render_timeline(correlation_events)

    logging.debug("Requesting AI analysis...")
    prompt = ai_analyzer.build_prompt(alert, ioc_table, mitre_text, enrichment_text, correlation_text)
    analysis = ai_analyzer.get_ai_analysis(prompt, cfg)

    message = notifier.build_message(alert, ioc_table, analysis)
    ok = notifier.send_telegram(message, cfg)
    logging.debug("Telegram send result: %s", ok)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        # Catch-all so nothing fails silently - Wazuh gives no other
        # indication that the integration script crashed.
        logging.error("UNEXPECTED ERROR: %s", exc, exc_info=True)
