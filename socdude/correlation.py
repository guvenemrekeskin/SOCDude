"""Event correlation: give the LLM a timeline of recent activity for the
same agent instead of analyzing every alert in total isolation. This is
what lets it say things like "this looks like stage 4 of a brute-force
-> valid-account -> privilege-escalation chain" instead of describing
one SSH login in a vacuum.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

from . import state as state_mod


def gather_context(db_path: str, agent_id: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fetch recent events for this agent. Call this BEFORE recording the
    current event, so the current alert doesn't show up in its own history."""
    return state_mod.get_related_events(
        db_path,
        agent_id,
        window_seconds=cfg["correlation_window_seconds"],
        max_events=cfg["correlation_max_events"],
    )


def render_timeline(events: List[Dict[str, Any]]) -> str:
    if not events:
        return "No other alerts recorded for this agent in the correlation window."
    lines = ["Recent alerts for this agent, most recent first:"]
    now = time.time()
    for e in events:
        age = int(now - e["ts"])
        lines.append(f"  - T-{age}s | level {e['level']} | rule {e['rule_id']} | {e['description']}")
    return "\n".join(lines)
