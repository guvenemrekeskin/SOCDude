#!/usr/bin/env python3
"""
SOCDude - Wazuh -> Ollama (local LLM) -> Telegram integration.

Wazuh calls this script for every alert (via the <integration> block in
ossec.conf). It filters by severity level, deduplicates repeated alerts
of the same rule within a cooldown window, applies a global rate limit
so a burst of different rules can't flood Telegram either, asks a local
Ollama model for a short SOC-style analysis, and forwards the result to
Telegram.

Configuration lives in /etc/socdude/config.json (installed with 640
perms, owned by root:wazuh) instead of being hardcoded here, so this
file is safe to version-control / share.

NOTE ON THE INTEGRATION NAME: Wazuh's wazuh-integratord only accepts a
fixed list of "known" integration names (slack, pagerduty, virustotal,
shuffle, etc). Anything else is rejected UNLESS it starts with the
"custom-" prefix, which is Wazuh's mechanism for user-defined scripts.
That's why this script is installed as /var/ossec/integrations/custom-socdude
and referenced as <name>custom-socdude</name> in ossec.conf, even though
the project itself is called "SOCDude". Renaming it back to just
"socdude" will make wazuh-integratord silently reject it with
"Invalid integration: 'socdude'. Not currently supported." Don't rename it.
"""

import sys
import json
import logging
import os
import time
import fcntl

try:
    import requests
except ImportError:
    # Wazuh integrations run non-interactively; if this fails we can't
    # even log to Telegram, so just write to the log file and exit.
    logging.basicConfig(
        filename='/var/ossec/logs/integrations.log',
        level=logging.ERROR,
        format='%(asctime)s [custom-socdude] %(message)s'
    )
    logging.error("python 'requests' module not installed. Run install.sh again.")
    sys.exit(1)

# --- Paths ---
LOG_FILE = '/var/ossec/logs/integrations.log'
CONFIG_FILE = '/etc/socdude/config.json'
STATE_FILE = '/var/ossec/logs/socdude_state.json'
LOCK_FILE = STATE_FILE + '.lock'

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s [custom-socdude] %(message)s'
)

# --- Defaults (overridden by config.json) ---
DEFAULTS = {
    "telegram_token": "",
    "chat_id": "",
    "ollama_url": "http://localhost:11434/api/generate",
    "ollama_model": "llama3.1",
    "min_level": 12,
    "cooldown_seconds": 300,       # per rule+agent dedup window
    "global_rate_limit_seconds": 5,  # min gap between ANY two Telegram sends
    "global_rate_limit_max_burst": 5,  # allow short bursts before throttling
    "http_timeout_seconds": 10,
    "ollama_timeout_seconds": 150,
    "ollama_num_predict": 180,
    "max_retries": 2,
    "retry_backoff_seconds": 2,
}


def load_config():
    """Load config.json and merge over defaults. Fail loudly if missing token/chat_id."""
    cfg = dict(DEFAULTS)
    if not os.path.exists(CONFIG_FILE):
        logging.error(f"Config file not found at {CONFIG_FILE}. Run install.sh.")
        sys.exit(1)
    try:
        with open(CONFIG_FILE, 'r') as f:
            user_cfg = json.load(f)
        cfg.update({k: v for k, v in user_cfg.items() if v is not None})
    except Exception as e:
        logging.error(f"Failed to parse {CONFIG_FILE}: {e}")
        sys.exit(1)

    if not cfg.get("telegram_token") or not cfg.get("chat_id"):
        logging.error("telegram_token / chat_id missing in config.json.")
        sys.exit(1)

    return cfg


def load_state():
    if not os.path.exists(STATE_FILE):
        return {"rules": {}, "last_global_send": 0, "burst_count": 0, "burst_window_start": 0}
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            data.setdefault("rules", {})
            data.setdefault("last_global_send", 0)
            data.setdefault("burst_count", 0)
            data.setdefault("burst_window_start", 0)
            return data
    except Exception:
        return {"rules": {}, "last_global_send": 0, "burst_count": 0, "burst_window_start": 0}


def save_state(state):
    tmp_file = STATE_FILE + '.tmp'
    with open(tmp_file, 'w') as f:
        json.dump(state, f)
    os.replace(tmp_file, STATE_FILE)


def gate_check(rule_id, agent_id, cfg):
    """
    Single locked check that combines:
      1. Per-(rule,agent) cooldown - stop the same alert repeating.
      2. Global soft rate limit - stop a burst of *different* rules
         from flooding Telegram all at once.

    Returns True if we should send, False if suppressed. Updates state
    under a file lock so concurrent Wazuh-spawned instances don't race.
    """
    with open(LOCK_FILE, 'w') as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            state = load_state()
            now = time.time()
            key = f"{rule_id}_{agent_id}"

            # 1. Per-rule cooldown
            last_sent = state["rules"].get(key, 0)
            if now - last_sent < cfg["cooldown_seconds"]:
                remaining = cfg["cooldown_seconds"] - (now - last_sent)
                logging.debug(f"Per-rule cooldown active for {key}, {remaining:.0f}s left.")
                return False

            # 2. Global burst limiter (token-bucket-ish, simple version)
            window = cfg["global_rate_limit_seconds"]
            max_burst = cfg["global_rate_limit_max_burst"]
            if now - state["burst_window_start"] > window:
                state["burst_window_start"] = now
                state["burst_count"] = 0

            if state["burst_count"] >= max_burst:
                logging.debug("Global burst limit reached, suppressing this alert.")
                return False

            state["burst_count"] += 1
            state["rules"][key] = now
            state["last_global_send"] = now

            # Prune old rule entries so the state file doesn't grow forever
            cutoff = now - (cfg["cooldown_seconds"] * 4)
            state["rules"] = {k: v for k, v in state["rules"].items() if v > cutoff}

            save_state(state)
            return True
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def with_retries(fn, max_retries, backoff_seconds, label):
    """Small helper: retry fn() on exception, with linear backoff."""
    last_err = None
    for attempt in range(1, max_retries + 2):
        try:
            return fn()
        except Exception as e:
            last_err = e
            logging.warning(f"{label} attempt {attempt} failed: {e}")
            if attempt <= max_retries:
                time.sleep(backoff_seconds * attempt)
    raise last_err


def send_telegram(text, cfg):
    url = f"https://api.telegram.org/bot{cfg['telegram_token']}/sendMessage"
    payload = {"chat_id": cfg["chat_id"], "text": text}

    def do_send():
        r = requests.post(url, json=payload, timeout=cfg["http_timeout_seconds"])
        r.raise_for_status()
        return r

    try:
        r = with_retries(
            do_send, cfg["max_retries"], cfg["retry_backoff_seconds"], "Telegram send"
        )
        logging.debug(f"Telegram status={r.status_code}")
        return True
    except Exception as e:
        logging.error(f"Telegram send failed after retries: {e}")
        return False


def get_ai_analysis(log_data, cfg):
    """
    Ask the local Ollama model for a short SOC-style analysis of the
    raw log line. Prompt is in English (models tend to follow English
    instructions more reliably) but explicitly requests Turkish output.
    """
    prompt = (
        "You are a SOC analyst. Analyze this security log:\n"
        f"{log_data}\n\n"
        "Respond ONLY in Turkish, using EXACTLY this format, no extra text:\n"
        "Saldiri turu: <kisa aciklama>\n"
        "Ciddiyet: <Dusuk, Orta, Yuksek veya Kritik>\n"
        "Onlem: <tek, net cumle>\n\n"
        "Keep it short. Do not translate literally word-by-word; "
        "write natural, grammatically correct Turkish."
    )

    def do_call():
        r = requests.post(cfg["ollama_url"], json={
            "model": cfg["ollama_model"],
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": cfg["ollama_num_predict"]}
        }, timeout=cfg["ollama_timeout_seconds"])
        r.raise_for_status()
        return r

    try:
        r = with_retries(
            do_call, cfg["max_retries"], cfg["retry_backoff_seconds"], "Ollama call"
        )
        return r.json().get('response', 'Analiz alinamadi.').strip()
    except Exception as e:
        logging.error(f"Ollama error after retries: {e}")
        return f"(AI analizi basarisiz oldu: {e})"


def main():
    logging.debug(f"Script triggered. argv={sys.argv}")
    cfg = load_config()

    if len(sys.argv) < 2:
        logging.error("Missing argument: no alert file path provided.")
        return

    alert_file = sys.argv[1]

    try:
        with open(alert_file, 'r') as f:
            alert = json.loads(f.read())
    except Exception as e:
        logging.error(f"Failed to read/parse alert file: {e}")
        return

    try:
        level = int(alert['rule']['level'])
        rule_id = alert['rule'].get('id', 'unknown')
        agent_id = alert.get('agent', {}).get('id', 'unknown')
        agent_name = alert.get('agent', {}).get('name', 'unknown')
    except Exception as e:
        logging.error(f"Failed to read alert fields: {e}")
        return

    logging.debug(f"Alert level={level}, min_level={cfg['min_level']}, rule_id={rule_id}")

    if level < cfg["min_level"]:
        logging.debug("Below severity threshold, skipping.")
        return

    if not gate_check(rule_id, agent_id, cfg):
        return  # cooldown or burst limit active, stay silent

    desc = alert.get('rule', {}).get('description', 'No description')
    full_log = alert.get('full_log', json.dumps(alert))

    logging.debug("Requesting AI analysis...")
    analysis = get_ai_analysis(full_log, cfg)

    message = (
        f"GUVENLIK ALARMI (Level {level})\n\n"
        f"Ajan: {agent_name} ({agent_id})\n"
        f"Kural: {desc}\n\n"
        f"AI Analizi:\n{analysis}"
    )

    ok = send_telegram(message, cfg)
    logging.debug(f"Telegram send result: {ok}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Catch-all so nothing fails silently - Wazuh gives no other
        # indication that the integration script crashed.
        logging.error(f"UNEXPECTED ERROR: {e}", exc_info=True)