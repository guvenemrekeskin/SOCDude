"""SIEM adapters.

SOCDude is built around a small adapter interface so support for other
platforms can be added without touching the enrichment/correlation/AI/
notification pipeline, which is entirely SIEM-agnostic. Wazuh is the
only implemented adapter today; Splunk and QRadar are stubbed out below
with the shape a real implementation would need - sketching that out
now costs nothing and documents the intended extension point.
"""

from __future__ import annotations

import json
import logging
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


class NormalizedAlert:
    """SIEM-agnostic alert shape the rest of the pipeline operates on."""

    def __init__(self, level: int, rule_id: str, agent_id: str, agent_name: str,
                 description: str, full_log: str, raw: Dict[str, Any],
                 structured_fields: Optional[Dict[str, Any]] = None):
        self.level = level
        self.rule_id = rule_id
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.description = description
        self.full_log = full_log
        self.raw = raw
        # Fields Wazuh already parsed out for us (data.srcip, data.url, ...).
        # Handed to the LLM as ground truth alongside the raw log, per
        # provider key, so it isn't solely reliant on re-deriving them
        # from free text - see _extract_structured_fields() below.
        self.structured_fields = structured_fields or {}


# Common keys Wazuh's decoders populate under alert["data"] across many
# rulesets (auth logs, web/nginx, firewall, Windows Sysmon, etc). Not
# exhaustive - anything not listed here still gets picked up by the
# regex-based IOC extractor against full_log as a fallback.
_STRUCTURED_FIELD_KEYS = [
    "srcip", "src_ip", "dstip", "dst_ip", "src_port", "dst_port",
    "url", "uri", "protocol", "proto", "user", "srcuser", "dstuser",
    "status", "action", "id", "win.eventdata.image",
    "win.eventdata.commandLine", "win.eventdata.targetUserName",
]


def _dig(d: Dict[str, Any], dotted_key: str) -> Any:
    """Look up a possibly dotted key path ('win.eventdata.image') in a
    nested dict. Returns None if any segment is missing."""
    cur: Any = d
    for part in dotted_key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _extract_structured_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    data = alert.get("data", {}) or {}
    found: Dict[str, Any] = {}
    for key in _STRUCTURED_FIELD_KEYS:
        value = _dig(data, key)
        if value not in (None, ""):
            found[key] = value
    return found


def render_structured_fields(fields: Dict[str, Any]) -> str:
    """Render Wazuh's own pre-parsed fields as prompt context. These are
    handed to the LLM alongside (not instead of) the raw log, so it has
    a ground-truth source IP/URL/user/etc. rather than having to
    re-derive everything itself from free text."""
    if not fields:
        return "Wazuh did not populate structured data.* fields for this rule; rely on the raw log below."
    lines = ["Fields Wazuh already parsed out (ground truth - prefer these over re-deriving from the raw log):"]
    for key, value in fields.items():
        lines.append(f"  - {key}: {value}")
    return "\n".join(lines)


class SIEMAdapter(ABC):
    platform_name: str = "base"

    @abstractmethod
    def parse_alert(self, argv: List[str]) -> Optional[NormalizedAlert]:
        """Parse whatever the platform hands this process and return a
        NormalizedAlert, or None if the alert should be silently skipped."""
        raise NotImplementedError


class WazuhAdapter(SIEMAdapter):
    """Wazuh's wazuh-integratord calls the integration script as:
        script <alert_file_path> <hook_url> <api_key>
    with the alert JSON written to alert_file_path (requires
    alert_format=json in the <integration> block of ossec.conf).
    """

    platform_name = "wazuh"

    def parse_alert(self, argv: List[str]) -> Optional[NormalizedAlert]:
        if len(argv) < 2:
            log.error("Missing argument: no alert file path provided by Wazuh.")
            return None

        alert_file = argv[1]
        try:
            with open(alert_file, "r", encoding="utf-8") as f:
                alert = json.loads(f.read())
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to read/parse alert file %s: %s", alert_file, exc)
            return None

        try:
            level = int(alert["rule"]["level"])
            rule_id = str(alert["rule"].get("id", "unknown"))
            agent = alert.get("agent", {})
            agent_id = str(agent.get("id", "unknown"))
            agent_name = agent.get("name", "unknown")
            description = alert.get("rule", {}).get("description", "No description")
            full_log = alert.get("full_log") or json.dumps(alert)
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to read expected alert fields: %s", exc)
            return None

        structured_fields = _extract_structured_fields(alert)
        return NormalizedAlert(level, rule_id, agent_id, agent_name, description,
                                full_log, alert, structured_fields)


class SplunkAdapter(SIEMAdapter):
    """Not implemented yet.

    Sketch for whoever picks this up: Splunk alert actions are usually
    scripted alert actions / HTTP webhooks rather than a per-event
    subprocess call like Wazuh's, so parse_alert() would likely need to
    read a search-result payload (JSON on stdin, or a results file path
    passed via argv, depending on how the alert action is configured)
    and map Splunk's field names (severity, host, sourcetype, _raw,
    ...) onto NormalizedAlert. Splunk's severity isn't a 1-15 integer
    scale like Wazuh's, so 'level' will need an explicit mapping table
    (e.g. informational/low/medium/high/critical -> a comparable int
    scale) to stay compatible with min_level gating.
    """

    platform_name = "splunk"

    def parse_alert(self, argv: List[str]) -> Optional[NormalizedAlert]:
        raise NotImplementedError(
            "Splunk support is planned but not implemented yet. "
            "Set siem_platform to 'wazuh' in config.json for now."
        )


class QRadarAdapter(SIEMAdapter):
    """Not implemented yet.

    Sketch for whoever picks this up: QRadar would most likely be
    integrated via its REST API (polling the /siem/offenses endpoint)
    rather than a per-alert script invocation, which means this adapter
    will eventually need its own polling loop / systemd timer instead
    of being called synchronously the way the Wazuh integration is.
    Left as a stub so the adapter interface and the config's platform
    selection are already in place for it.
    """

    platform_name = "qradar"

    def parse_alert(self, argv: List[str]) -> Optional[NormalizedAlert]:
        raise NotImplementedError(
            "QRadar support is planned but not implemented yet. "
            "Set siem_platform to 'wazuh' in config.json for now."
        )


_ADAPTERS = {
    "wazuh": WazuhAdapter,
    "splunk": SplunkAdapter,
    "qradar": QRadarAdapter,
}


def get_adapter(platform_name: str) -> SIEMAdapter:
    cls = _ADAPTERS.get(platform_name)
    if cls is None:
        log.error("Unknown SIEM platform '%s'.", platform_name)
        sys.exit(1)
    return cls()
