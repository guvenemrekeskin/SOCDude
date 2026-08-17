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

## Security notes

- **Never commit `/etc/socdude/config.json` or any API/bot token to
  this repo.** It's excluded via `.gitignore` - double-check before
  pushing.
- If a token or key is ever accidentally exposed, revoke and rotate it
  immediately (BotFather `/revoke` for Telegram; each provider's
  dashboard for API keys).
- `config.json` is installed with `640` permissions - only root and
  the Wazuh service group can read it.
- All Telegram output is HTML-escaped before sending, and long reports
  are split at line boundaries to stay under Telegram's message-length
  limit rather than being truncated mid-word.
- State (cooldown/rate-limit gating, correlation history, enrichment
  cache) lives in a local SQLite database with WAL mode and proper
  transactions (`BEGIN IMMEDIATE`), replacing the earlier JSON file +
  `fcntl` lock - correct under concurrent invocations from
  wazuh-integratord, and gives correlation/caching a real query layer
  instead of a second ad hoc file format.
- The LLM is explicitly instructed never to fabricate threat-intel
  scores or MITRE technique IDs beyond what it's given - see the
  "Design principle" above.

## Status

Actively developed lab/portfolio project. Contributions and issue
reports welcome.
