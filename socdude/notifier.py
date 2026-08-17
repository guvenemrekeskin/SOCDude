"""Telegram delivery, with HTML escaping and message-length splitting
(Telegram hard-caps a single message at 4096 UTF-16 code units)."""

from __future__ import annotations

import html
import logging
from typing import Any, Dict, List

import requests

from .ai_analyzer import with_retries

log = logging.getLogger(__name__)

TELEGRAM_MAX_LEN = 4000  # a safety margin under the real 4096 cap


def build_message(alert, ioc_table: str, analysis: str, confidence: Dict[str, Any]) -> str:
    header = (
        f"<b>SECURITY ALERT (Level {alert.level})</b>\n"
        f"<b>Confidence:</b> {html.escape(confidence['band'])} ({confidence['score']}/100)\n\n"
        f"<b>Agent:</b> {html.escape(str(alert.agent_name))} ({html.escape(str(alert.agent_id))})\n"
        f"<b>Rule:</b> {html.escape(str(alert.description))}\n"
    )
    ioc_block = f"\n<b>IOCs</b>\n<pre>{html.escape(ioc_table)}</pre>\n"
    analysis_block = f"\n<b>AI Analysis</b>\n{html.escape(analysis)}"
    return header + ioc_block + analysis_block


def _split_message(text: str, max_len: int = TELEGRAM_MAX_LEN) -> List[str]:
    if len(text) <= max_len:
        return [text]
    chunks: List[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= max_len:
            chunks.append(remaining)
            break
        cut = remaining.rfind("\n", 0, max_len)
        if cut <= 0:
            cut = max_len
        chunks.append(remaining[:cut])
        remaining = remaining[cut:].lstrip("\n")
    return chunks


def send_telegram(text: str, cfg: Dict[str, Any]) -> bool:
    url = f"https://api.telegram.org/bot{cfg['telegram_token']}/sendMessage"
    ok_all = True
    for chunk in _split_message(text):
        payload = {
            "chat_id": cfg["chat_id"],
            "text": chunk,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        def do_send(payload=payload):
            r = requests.post(url, json=payload, timeout=cfg["http_timeout_seconds"])
            r.raise_for_status()
            return r

        try:
            r = with_retries(do_send, cfg["max_retries"], cfg["retry_backoff_seconds"], "Telegram send")
            log.debug("Telegram status=%s", r.status_code)
        except Exception as exc:  # noqa: BLE001
            log.error("Telegram send failed after retries: %s", exc)
            ok_all = False
    return ok_all
