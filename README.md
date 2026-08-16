# SOCDude

**Your AI-powered SOC teammate.** Wazuh alert -> IOC extraction -> real
threat-intel enrichment -> event correlation -> local LLM (Ollama)
analysis -> Telegram. No cloud AI API, no log data leaving your network.

> Built and tested against a Wazuh manager monitoring a Kali + OWASP
> Juice Shop attack lab.

## Why this exists

A raw Wazuh alert tells you a rule fired. It doesn't tell you which
IOCs are actually in the log, whether any of them have a bad
reputation, whether this is the fourth alert in a brute-force chain on
the same host, or which MITRE technique it maps to and why. SOCDude
fills that gap automatically, using a **locally-hosted** LLM so nothing
about your environment gets sent to a third-party AI API.

## How it works

```
Wazuh alert (level >= threshold)
        |
        v
wazuh-integratord --> /var/ossec/integrations/custom-socdude (launcher)
        |
        v
        socdude package (/opt/socdude)
        |
        +--> IOC extraction (regex, deterministic - IPs, domains, URLs,
        |    hashes, emails, MACs, file paths, User-Agents)
        |
        +--> Threat-intel enrichment (VirusTotal, AbuseIPDB, GreyNoise,
        |    Shodan, GeoIP/ASN, RDAP/WHOIS, DNS, URLhaus, MalwareBazaar,
        |    OTX - each optional, real API calls only, never faked)
        |
        +--> MITRE ATT&CK context (from Wazuh's own rule.mitre mapping)
        |
        +--> Correlation (recent alerts for the same agent, from a
        |    local SQLite event log)
        |
        v
   Ollama (llama3.1, local) -- interprets the above, writes a
   7-section analyst-style report in English
        |
        v
   Telegram Bot API --> your chat
```

**Design principle:** the LLM never invents data. IOCs are extracted
by regex, threat-intel scores come from real API responses, and the
MITRE mapping comes from Wazuh's own rule metadata. The model's job is
to *interpret and explain* that data - not to fabricate it. This is
enforced explicitly in the prompt (see `socdude/ai_analyzer.py`).

### The 7-section AI report

1. **Event Summary** - what happened, severity call
2. **MITRE ATT&CK / TTP Analysis** - tactic, technique ID + name,
   sub-technique, confidence, evidence
3. **Threat Intelligence Assessment** - interprets the real enrichment
   data per IOC
4. **Correlation / Related Activity** - is this isolated or part of a
   sequence on this agent?
5. **Attack Chain** - multi-stage breakdown when the evidence supports it
6. **Risk Assessment** - one overall rating with justification
7. **Analyst Recommendation** - concrete next steps

The IOC table itself is rendered separately, by code, directly under
the alert header - not by the model (see "Design principle" above).

## Requirements

- A working Wazuh manager (`ossec.conf` with `<integration>` support)
- Ubuntu/Debian-based manager host (the installer uses `apt-get`)
- 4+ vCPU / 8GB+ RAM recommended for `llama3.1` 8B locally - a smaller
  model like `llama3.2:3b` works on more modest hardware (edit
  `ollama_model` in the config afterward)
- A Telegram bot token and chat ID ([BotFather](https://t.me/BotFather))
- Optional, for richer threat-intel: free-tier API keys from
  [VirusTotal](https://www.virustotal.com/gui/join-us),
  [AbuseIPDB](https://www.abuseipdb.com/register),
  [GreyNoise](https://viz.greynoise.io/account/), and
  [Shodan](https://account.shodan.io/register). GeoIP, RDAP, DNS,
  URLhaus, and MalwareBazaar lookups need no key and run automatically.

## Installation

```bash
git clone <this repo>
cd SOCDude
sudo bash install.sh
```

The installer is idempotent - safe to re-run. It will:

1. Ask which SIEM platform you're using (Wazuh works today; Splunk and
   QRadar are recognized choices for the config schema but not
   implemented yet - see [Roadmap](#roadmap))
2. Install Python3/pip and the `requests` library if missing
3. Install Ollama and pull `llama3.1` if missing
4. Deploy the `socdude` Python package to `/opt/socdude`
5. Ask for your Telegram bot token/chat ID and (optionally) threat-intel
   API keys, and write `/etc/socdude/config.json` (mode `640`, owned by
   `root:wazuh`/`root:ossec`)
6. Install the Wazuh launcher script to
   `/var/ossec/integrations/custom-socdude`
7. Add the `<integration>` block to `ossec.conf` (backing up the
   original first)
8. Restart `wazuh-manager` and send a test Telegram message

## Architecture

```
SOCDude/
  custom-socdude          <- thin launcher Wazuh actually calls
  install.sh
  config.example.json
  socdude/                <- the real package, deployed to /opt/socdude
    config.py             <- config loading + validation
    state.py              <- SQLite: cooldown/rate-limit, event history, IOC cache
    siem.py                <- SIEM adapter interface (Wazuh implemented; Splunk/QRadar stubbed)
    ioc_extractor.py       <- deterministic regex-based IOC extraction
    mitre.py                <- MITRE context from Wazuh's own rule metadata
    enrichment.py           <- real threat-intel API calls, parallelized + cached
    correlation.py          <- recent-activity timeline per agent
    ai_analyzer.py           <- prompt construction + Ollama call
    notifier.py               <- Telegram formatting + delivery
    cli.py                     <- wires it all together
```

Why a package instead of one script: the original single-file script
worked for what it did, but every new capability requested here -
multi-SIEM support, real enrichment, correlation, a much richer AI
report - is a separable concern with its own failure modes. Splitting
them means a broken VirusTotal key can't take down IOC extraction, and
means Splunk/QRadar support is "write a new adapter class," not
"rewrite the whole script."

### Adding a new SIEM platform

Implement a new `SIEMAdapter` subclass in `socdude/siem.py` with a
`parse_alert(argv) -> NormalizedAlert` method, register it in
`_ADAPTERS`, and set `siem_platform` in `config.json`. Everything
downstream (extraction, enrichment, correlation, AI, Telegram) is
already SIEM-agnostic. `SplunkAdapter` and `QRadarAdapter` are stubbed
with notes on what each platform's integration would actually need.

## Configuration

See [`config.example.json`](config.example.json) for every key with
its default. Highlights beyond the original script:

| Key | Meaning |
|---|---|
| `siem_platform` | `wazuh` (only one implemented today) |
| `enrichment_enabled` | Turn all threat-intel lookups on/off |
| `enrichment_max_iocs_per_type` | Cap API calls per alert (free-tier friendly) |
| `enrichment_cache_ttl_seconds` | Avoid re-querying the same IOC repeatedly |
| `correlation_window_seconds` / `correlation_max_events` | How far back / how many events to correlate per agent |
| `virustotal_api_key`, `abuseipdb_api_key`, `greynoise_api_key`, `shodan_api_key`, `otx_api_key` | Optional - missing key = that provider is skipped |
| `state_db_path` | SQLite file for gating/correlation/cache |

Edit `/etc/socdude/config.json` directly (or re-run `install.sh`) and
restart `wazuh-manager` to apply changes.

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

## Logs

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Every run is tagged `[custom-socdude]`.

## Status

Actively developed lab/portfolio project. Contributions and issue
reports welcome.
