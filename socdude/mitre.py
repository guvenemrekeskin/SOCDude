"""MITRE ATT&CK context.

Wazuh already ships MITRE mappings for many of its rules
(rule.mitre.id / .tactic / .technique in the alert JSON), curated by
the Wazuh rule authors. We treat that as ground truth and pass it to
the LLM as context, rather than asking the model to guess technique
IDs from nothing. The LLM's job is to explain *why* the mapping fits
this specific log line (the "evidence" it's asked for) and rate its
own confidence - not to invent new technique IDs.
"""

from __future__ import annotations

from typing import Any, Dict, List


def get_mitre_hints(alert: Dict[str, Any]) -> List[Dict[str, str]]:
    mitre = alert.get("rule", {}).get("mitre", {}) or {}
    if not mitre:
        return []

    ids = mitre.get("id", []) or []
    tactics = mitre.get("tactic", []) or []
    techniques = mitre.get("technique", []) or []

    n = max(len(ids), len(tactics), len(techniques), 1 if (ids or tactics or techniques) else 0)
    if n == 0:
        return []

    def pick(lst: List[str], i: int) -> str:
        return lst[i] if i < len(lst) else (lst[0] if lst else "unknown")

    return [
        {
            "technique_id": pick(ids, i),
            "tactic": pick(tactics, i),
            "technique_name": pick(techniques, i),
        }
        for i in range(n)
    ]


def render_mitre_hints(hints: List[Dict[str, str]]) -> str:
    if not hints:
        return "Wazuh did not provide a MITRE mapping for this rule."
    lines = ["Wazuh-provided MITRE mapping for this rule (ground truth - do not contradict):"]
    for h in hints:
        lines.append(f"  - {h['technique_id']} ({h['technique_name']}) - tactic: {h['tactic']}")
    return "\n".join(lines)
