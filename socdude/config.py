"""Configuration loading and validation for SOCDude."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Dict

CONFIG_FILE = "/etc/socdude/config.json"

DEFAULTS: Dict[str, Any] = {
    # --- SIEM platform ---
    # "wazuh" is the only implemented adapter today. "splunk" / "qradar"
    # are accepted values so the config schema is forward-compatible,
    # but selecting them currently logs a "not implemented yet" error
    # and exits (see socdude/siem.py).
    "siem_platform": "wazuh",

    # --- Telegram ---
    "telegram_token": "",
    "chat_id": "",

    # --- Ollama / local LLM ---
    "ollama_url": "http://localhost:11434/api/generate",
    "ollama_model": "llama3.1",
    "ollama_timeout_seconds": 180,
    "ollama_num_predict": 900,

    # --- Alert gating ---
    "min_level": 12,
    "cooldown_seconds": 300,               # per rule+agent dedup window
    "global_rate_limit_seconds": 5,        # burst window
    "global_rate_limit_max_burst": 5,      # max alerts per burst window

    # --- HTTP / retries (Telegram + Ollama) ---
    "http_timeout_seconds": 10,
    "max_retries": 2,
    "retry_backoff_seconds": 2,

    # --- Correlation ---
    "correlation_window_seconds": 1800,    # look back 30 min on the same agent
    "correlation_max_events": 15,

    # --- IOC enrichment ---
    "enrichment_enabled": True,
    "enrichment_cache_ttl_seconds": 3600,
    "enrichment_max_iocs_per_type": 5,     # cap calls per alert (free-tier friendly)
    "enrichment_timeout_seconds": 8,

    # Threat-intel API keys - all optional. No key = that provider is
    # skipped, never faked. See README for where to get free-tier keys.
    "virustotal_api_key": "",
    "abuseipdb_api_key": "",
    "greynoise_api_key": "",
    "shodan_api_key": "",
    "otx_api_key": "",

    # --- State ---
    "state_db_path": "/var/ossec/logs/socdude_state.db",
}

REQUIRED_KEYS = ("telegram_token", "chat_id")
VALID_PLATFORMS = ("wazuh", "splunk", "qradar")


def load_config(config_file: str = CONFIG_FILE) -> Dict[str, Any]:
    """Load config.json, merge over DEFAULTS, validate required keys.

    Exits the process on fatal misconfiguration. This mirrors the
    original script's behaviour deliberately: when invoked by
    wazuh-integratord there is no other feedback channel than the
    integrations log, so failing loudly (and only there) is correct.
    """
    cfg = dict(DEFAULTS)

    if not os.path.exists(config_file):
        logging.error("Config file not found at %s. Run install.sh.", config_file)
        sys.exit(1)

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
    except Exception as exc:  # noqa: BLE001 - log and exit regardless of cause
        logging.error("Failed to parse %s: %s", config_file, exc)
        sys.exit(1)

    if not isinstance(user_cfg, dict):
        logging.error("%s must contain a JSON object.", config_file)
        sys.exit(1)

    cfg.update({k: v for k, v in user_cfg.items() if v is not None})

    missing = [k for k in REQUIRED_KEYS if not cfg.get(k)]
    if missing:
        logging.error("Missing required config keys: %s", ", ".join(missing))
        sys.exit(1)

    if cfg["siem_platform"] not in VALID_PLATFORMS:
        logging.error(
            "Unknown siem_platform '%s' (expected one of %s).",
            cfg["siem_platform"], VALID_PLATFORMS,
        )
        sys.exit(1)

    return cfg
