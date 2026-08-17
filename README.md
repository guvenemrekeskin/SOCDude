# SOCDude

**Your AI-powered SOC teammate.** Wazuh alert -> IOC extraction -> real
threat-intel enrichment -> event correlation -> local LLM (Ollama)
analysis -> Telegram. No cloud AI API, no log data leaving your network.

## Why this exists

A raw Wazuh alert tells you a rule fired. It doesn't tell you which
IOCs are actually in the log, whether any of them have a bad
reputation, whether this is the fourth alert in a brute-force chain on
the same host, or which MITRE technique it maps to and why. SOCDude
fills that gap automatically, using a **locally-hosted** LLM so nothing
about your environment gets sent to a third-party AI API.

## Installation

```bash
git clone <this repo>
cd SOCDude
sudo bash install.sh

```

## Security notes

- **Never commit `/etc/socdude/config.json` or any API/bot token to
  this repo.** It's excluded via `.gitignore` - double-check before
  pushing.
- If a token or key is ever accidentally exposed, revoke and rotate it
  immediately (BotFather `/revoke` for Telegram; each provider's
  dashboard for API keys).

## Status

Actively developed lab/portfolio project. Contributions and issue
reports welcome.
