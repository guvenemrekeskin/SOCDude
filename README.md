# SOCDude

Wazuh &rarr; local LLM (Ollama) &rarr; Telegram integration. When Wazuh raises
a high-severity alert, SOCDude asks a local Llama 3.1 model for a short
SOC-analyst-style summary (attack type, severity, recommended action) and
pushes it straight to a Telegram chat — no cloud API, no data leaving your
network.

> **Status:** early / lab project. Built and tested against a Wazuh manager
> monitoring a Kali + OWASP Juice Shop attack lab. Expect rough edges.

## How it works

```
Wazuh alert (level >= threshold)
        |
        v
wazuh-integratord --> integrations/custom-socdude (this script)
        |
        v
   Ollama (llama3.1, local) 
        |
        v
   Telegram Bot API --> your chat
```

- Alerts below `min_level` are ignored.
- Per-rule cooldown stops the same rule from spamming you repeatedly.
- A global burst limit stops several *different* rules firing at once from
  flooding your chat.
- All credentials and tunables live outside the script, in
  `/etc/socdude/config.json`.

## Requirements

- A working Wazuh manager (this was tested with the alert being triggered
  via `<integration>` in `ossec.conf`)
- Ubuntu/Debian-based manager host (the installer uses `apt-get`)
- Enough CPU/RAM to run Ollama locally (4+ vCPU / 8GB+ RAM recommended for
  `llama3.1` 8B — a smaller model like `llama3.2:3b` works fine on more
  modest hardware, just edit `ollama_model` in the config afterward)
- A Telegram bot token and chat ID ([BotFather](https://t.me/BotFather) to
  create a bot, then message it once and check
  `https://api.telegram.org/bot<TOKEN>/getUpdates` to find your chat ID)

## Installation

```bash
git clone 
cd SOCDude
sudo bash install.sh
```

The installer is idempotent — safe to re-run. It will:

1. Install Python3/pip and the `requests` library if missing
2. Install Ollama and pull `llama3.1` if missing
3. Ask for your Telegram bot token and chat ID (skipped if already configured)
4. Write `/etc/socdude/config.json` (mode `640`, owned by `root:wazuh` or
   `root:ossec`, whichever group your Wazuh install uses)
5. Install the integration script to
   `/var/ossec/integrations/custom-socdude`
6. Add the `<integration>` block to `ossec.conf` (backing up the original
   first)
7. Restart `wazuh-manager` and send a test Telegram message to confirm
   everything is wired up correctly

## Configuration

All tunables live in `/etc/socdude/config.json`:

| Key | Default | Meaning |
|---|---|---|
| `telegram_token` | — | Your bot token |
| `chat_id` | — | Your chat ID |
| `ollama_url` | `http://localhost:11434/api/generate` | Ollama API endpoint |
| `ollama_model` | `llama3.1` | Model to use for analysis |
| `min_level` | `12` | Minimum Wazuh rule level to trigger analysis |
| `cooldown_seconds` | `300` | Per-rule dedup window |
| `global_rate_limit_seconds` | `5` | Burst window for the global rate limit |
| `global_rate_limit_max_burst` | `5` | Max alerts allowed per burst window |
| `ollama_num_predict` | `180` | Caps LLM output length (keeps latency down) |
| `max_retries` | `2` | Retries for both Ollama and Telegram calls |

Edit the file and re-run `install.sh` (or just restart `wazuh-manager`) to
apply changes.

## Logs

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Every run is tagged `[custom-socdude]`.

## Security notes

- **Never commit `/etc/socdude/config.json` or a token to this repo.**
  It's excluded via `.gitignore`, but double-check before pushing.
- If a token is ever accidentally exposed (committed, pasted, shared),
  revoke it immediately via [BotFather](https://t.me/BotFather) (`/revoke`)
  and generate a new one.
- `config.json` is installed with `640` permissions so only root and the
  Wazuh service group can read it.