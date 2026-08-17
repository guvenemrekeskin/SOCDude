"""Deterministic confidence/risk scoring.

Mirrors the project's core design principle (see ai_analyzer.py and
enrichment.py): a number that ends up in a SOC analyst's Telegram feed
should come from real signals, not from asking the LLM to guess a
score in free text. This module turns the Wazuh rule level, the real
enrichment verdicts, the correlation chain length, and the number of
MITRE techniques Wazuh itself mapped into a 0-100 score and a five-band
label. That score is handed to the LLM as ground truth; the model's
job in its Risk Assessment section is to *explain* the number, not
invent its own.

Bands: LOW < MEDIUM < HIGH < CRITICAL < URGENT. "URGENT" is reserved
for alerts that are both a high Wazuh severity AND independently
confirmed malicious by real threat intel - the combination that
actually warrants waking someone up.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

BANDS: List[Tuple[int, str]] = [
    (85, "URGENT"),
    (65, "CRITICAL"),
    (45, "HIGH"),
    (25, "MEDIUM"),
    (0, "LOW"),
]


def _band_for(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "LOW"  # pragma: no cover - BANDS always has a 0 floor


def compute_confidence(level: int, enrichment: Dict[str, Any],
                        correlation_events: List[Dict[str, Any]],
                        mitre_hint_count: int) -> Dict[str, Any]:
    """Returns {"score": int, "band": str, "reasons": [str, ...]}.

    Point budget (sums to at most 100):
      - Wazuh rule level (0-15 scale)          -> up to 35 pts
      - Real threat-intel verdicts on the IOCs  -> up to 40 pts
      - Correlation chain length on this agent  -> up to 15 pts
      - MITRE techniques Wazuh itself mapped    -> up to 10 pts
    """
    score = 0
    reasons: List[str] = []

    level_pts = min(35, round((max(0, level) / 15) * 35))
    score += level_pts
    reasons.append(f"Wazuh rule level {level}/15 (+{level_pts} pts)")

    ti_pts = 0
    for sources in enrichment.values():
        for source, data in sources.items():
            if not isinstance(data, dict):
                continue
            malicious = data.get("malicious")
            if isinstance(malicious, int) and malicious > 0:
                ti_pts += min(15, malicious * 3)
            abuse_score = data.get("abuse_confidence_score")
            if isinstance(abuse_score, (int, float)) and abuse_score > 0:
                ti_pts += min(15, int(abuse_score) // 10)
            if data.get("classification") == "malicious":
                ti_pts += 10
            pulses = data.get("pulse_count")
            if isinstance(pulses, int) and pulses > 0:
                ti_pts += min(10, pulses)
    ti_pts = min(40, ti_pts)
    if ti_pts:
        reasons.append(f"Confirmed-malicious threat-intel verdicts on enriched IOCs (+{ti_pts} pts)")
    score += ti_pts

    chain_pts = min(15, len(correlation_events) * 3)
    if chain_pts:
        reasons.append(
            f"{len(correlation_events)} related alert(s) on this agent within the "
            f"correlation window (+{chain_pts} pts)"
        )
    score += chain_pts

    mitre_pts = min(10, mitre_hint_count * 5)
    if mitre_pts:
        reasons.append(f"{mitre_hint_count} MITRE technique(s) mapped by Wazuh's own rule metadata (+{mitre_pts} pts)")
    score += mitre_pts

    score = min(100, score)
    if not reasons:
        reasons.append("No contributing signals above baseline (low Wazuh level, no enrichment matches, no correlation).")

    return {"score": score, "band": _band_for(score), "reasons": reasons}


def render_confidence(result: Dict[str, Any]) -> str:
    lines = [f"Computed confidence score: {result['score']}/100 -> {result['band']}"]
    lines.append("Basis for this score (treat as ground truth - explain it, do not override it):")
    for r in result["reasons"]:
        lines.append(f"  - {r}")
    return "\n".join(lines)
