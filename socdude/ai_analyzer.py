"""Prompt construction and the Ollama call.

Output is forced to English regardless of the raw log's language. The
prompt hands the model the real extracted IOC table, the real
enrichment data, the real MITRE hints from Wazuh, and the real
correlation timeline, then asks it to *interpret and write*, not to
*invent facts* - each section explicitly tells the model what ground
truth it has to work from and forbids fabricating beyond it.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict

import requests

log = logging.getLogger(__name__)


def build_prompt(alert, ioc_table: str, mitre_hints: str, enrichment_text: str,
                  correlation_text: str) -> str:
    return f"""You are a senior SOC (Security Operations Center) analyst writing an
incident note for a Tier-2 analyst who will read this in a Telegram alert.
Write ONLY in English, regardless of the language of the raw log below.
Be specific and technical, not generic. Do not pad with filler sentences.

=== ALERT ===
Rule level: {alert.level}
Rule ID: {alert.rule_id}
Rule description: {alert.description}
Agent: {alert.agent_name} ({alert.agent_id})

=== RAW LOG ===
{alert.full_log[:3000]}

=== EXTRACTED IOCs (already parsed programmatically - reference, don't re-derive) ===
{ioc_table}

=== MITRE MAPPING (from Wazuh's own rule metadata - treat as ground truth) ===
{mitre_hints}

=== THREAT INTELLIGENCE DATA (real API results - interpret this, never invent a
    number or verdict for a source that is not listed here) ===
{enrichment_text}

=== RECENT ACTIVITY ON THIS AGENT (for correlation) ===
{correlation_text}

Write your analysis using EXACTLY these seven section headers, in this order,
each with 2-5 sentences (or a short bullet list where noted). Do not add
extra sections and do not restate the raw IOC table verbatim.

1. EVENT SUMMARY
What happened, in plain terms: event type, source device/hostname, user,
application/service involved, and your own severity call
(Info / Low / Medium / High / Critical) - which may differ from the raw
Wazuh rule level if context (correlation, threat intel) changes your
assessment.

2. MITRE ATT&CK / TTP ANALYSIS
For each technique actually supported by the log evidence, give: Tactic,
Technique ID + name, Sub-technique (if applicable), your confidence as a
percentage, and the specific evidence in the log that supports it. Only
cite techniques you can justify from the log or the Wazuh MITRE mapping
above - do not pad this with speculative techniques.

3. THREAT INTELLIGENCE ASSESSMENT
Interpret the threat intelligence data above, per IOC (reputation scores,
ASN/geo, known-malicious indicators). If no threat intel data was
retrieved for an IOC, say so plainly instead of guessing. Give an overall
verdict per IOC (HIGH RISK / MEDIUM RISK / LOW RISK / UNKNOWN) based only
on the data given.

4. CORRELATION / RELATED ACTIVITY
Based on the recent-activity list above, state whether this alert looks
like an isolated event or part of a broader sequence on this agent, and
why. Reference specific prior alerts by rule/time if relevant.

5. ATTACK CHAIN
If the correlated events above suggest a multi-stage attack, lay out the
stages (e.g. Initial Access -> Execution -> Privilege Escalation -> ...)
and which specific alert/log line supports each stage. If there isn't
enough evidence for a chain, say exactly that - do not invent one.

6. RISK ASSESSMENT
One overall risk rating (LOW / MEDIUM / HIGH / CRITICAL) with 1-2 sentences
of justification that ties together sections 1-5.

7. ANALYST RECOMMENDATION
Concrete, actionable next steps for the on-call analyst (e.g. isolate host,
reset credentials, block IP at the firewall, escalate to IR). Be specific
to this alert, not generic advice.
"""


def with_retries(fn: Callable, max_retries: int, backoff_seconds: float, label: str):
    last_err: Exception = RuntimeError(f"{label} never ran")
    for attempt in range(1, max_retries + 2):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            log.warning("%s attempt %d failed: %s", label, attempt, exc)
            if attempt <= max_retries:
                time.sleep(backoff_seconds * attempt)
    raise last_err


def get_ai_analysis(prompt: str, cfg: Dict[str, Any]) -> str:
    def do_call():
        r = requests.post(
            cfg["ollama_url"],
            json={
                "model": cfg["ollama_model"],
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": cfg["ollama_num_predict"]},
            },
            timeout=cfg["ollama_timeout_seconds"],
        )
        r.raise_for_status()
        return r

    try:
        r = with_retries(do_call, cfg["max_retries"], cfg["retry_backoff_seconds"], "Ollama call")
        return (r.json().get("response") or "").strip() or "(Ollama returned an empty response.)"
    except Exception as exc:  # noqa: BLE001
        log.error("Ollama error after retries: %s", exc)
        return f"(AI analysis failed: {exc})"
