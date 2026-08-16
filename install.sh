#!/bin/bash
#
# SOCDude Installer
#
# Installs/configures: Python deps, Ollama + llama3.1, the socdude
# Python package (to /opt/socdude), the Wazuh launcher script, its
# config file, and the Wazuh ossec.conf hook.
#
# Safe to re-run: every step checks current state first and skips work
# that's already done, unless you explicitly ask to reconfigure.

set -uo pipefail   # no -e: failures are handled explicitly per step so
                    # one bad check doesn't kill the whole install

# ---------- Paths ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_SRC_DIR="$SCRIPT_DIR/socdude"
LAUNCHER_SRC="$SCRIPT_DIR/custom-socdude"

INSTALL_DIR="/opt/socdude"
PKG_DEST_DIR="$INSTALL_DIR/socdude"

WAZUH_INT_DIR="/var/ossec/integrations"
LAUNCHER_DEST="$WAZUH_INT_DIR/custom-socdude"
INTEGRATION_NAME="custom-socdude"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

CONFIG_DIR="/etc/socdude"
CONFIG_FILE="$CONFIG_DIR/config.json"

# ---------- Colors / helpers ----------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }
step() { echo -e "\n${YELLOW}==>${NC} $1"; }
fail_exit() { err "$1"; err "Installation aborted."; exit 1; }

detect_wazuh_group() {
    if getent group wazuh >/dev/null 2>&1; then echo "wazuh";
    elif getent group ossec >/dev/null 2>&1; then echo "ossec";
    else echo "root"; fi
}

# ---------- 0. Root check ----------
if [ "$EUID" -ne 0 ]; then
    fail_exit "Please run this script with sudo or as root."
fi

echo "=================================================="
echo "  SOCDude Installer  "
echo "=================================================="

if [ ! -d "$PKG_SRC_DIR" ] || [ ! -f "$LAUNCHER_SRC" ]; then
    fail_exit "socdude/ package or custom-socdude launcher not found next to install.sh."
fi

# ---------- 1. SIEM platform selection ----------
# Only Wazuh is implemented today. This still asks up front so the
# config schema and the rest of the flow are already future-proofed
# for Splunk/QRadar - selecting them just tells you they're not ready.
step "SIEM platform"
SIEM_PLATFORM="wazuh"
if [ -f "$CONFIG_FILE" ] && grep -q '"siem_platform"' "$CONFIG_FILE" 2>/dev/null; then
    SIEM_PLATFORM=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('siem_platform','wazuh'))" 2>/dev/null || echo "wazuh")
    ok "Using previously configured SIEM platform: $SIEM_PLATFORM"
else
    echo "Which SIEM product are you using?"
    echo "  1) Wazuh   (supported)"
    echo "  2) Splunk  (planned - not implemented yet)"
    echo "  3) QRadar  (planned - not implemented yet)"
    read -p "Choice [1]: " SIEM_CHOICE
    case "${SIEM_CHOICE:-1}" in
        2) SIEM_PLATFORM="splunk" ;;
        3) SIEM_PLATFORM="qradar" ;;
        *) SIEM_PLATFORM="wazuh" ;;
    esac
fi

if [ "$SIEM_PLATFORM" != "wazuh" ]; then
    warn "$SIEM_PLATFORM support isn't implemented yet - see socdude/siem.py for the planned adapter shape."
    warn "Continuing the install with siem_platform=$SIEM_PLATFORM saved in config.json, but Wazuh"
    warn "integration steps below will be skipped. Re-run and choose Wazuh to actually get alerts flowing."
fi

# ---------- 2. Python3 + pip ----------
step "Checking Python3"
if ! command -v python3 >/dev/null 2>&1; then
    warn "Python3 not found. Installing..."
    apt-get update -qq && apt-get install -y python3 python3-pip || fail_exit "Failed to install Python3."
    ok "Python3 installed."
else
    ok "Python3 already installed ($(python3 --version 2>&1))."
fi

if ! command -v pip3 >/dev/null 2>&1; then
    warn "pip3 not found. Installing..."
    apt-get install -y python3-pip || fail_exit "Failed to install pip3."
fi

step "Checking Python 'requests' library"
if python3 -c "import requests" >/dev/null 2>&1; then
    ok "'requests' already installed."
else
    warn "'requests' not found. Installing..."
    if pip3 install --quiet requests 2>/dev/null; then
        ok "'requests' installed."
    elif pip3 install --quiet --break-system-packages requests 2>/dev/null; then
        ok "'requests' installed (system-managed environment)."
    else
        fail_exit "Failed to install 'requests' via pip3."
    fi
fi

# ---------- 3. Ollama ----------
step "Checking Ollama"
if ! command -v ollama >/dev/null 2>&1; then
    warn "Ollama not found. Installing..."
    curl -fsSL https://ollama.com/install.sh | sh || fail_exit "Ollama install script failed."
    ok "Ollama installed."
else
    ok "Ollama already installed ($(ollama --version 2>&1 | head -n1))."
fi

step "Ensuring Ollama service is running"
if systemctl is-active --quiet ollama 2>/dev/null; then
    ok "Ollama service already running."
else
    systemctl enable --now ollama >/dev/null 2>&1 || warn "Could not manage ollama via systemctl (may be running another way)."
    sleep 2
    systemctl is-active --quiet ollama 2>/dev/null && ok "Ollama service started." \
        || warn "Ollama service status unknown; continuing anyway."
fi

step "Checking Llama 3.1 model"
if ollama list 2>/dev/null | grep -q "llama3.1"; then
    ok "Llama 3.1 model already present."
else
    warn "Llama 3.1 not found locally. Pulling model (this can take a while)..."
    ollama pull llama3.1 || fail_exit "Failed to pull llama3.1 model."
    ok "Llama 3.1 model pulled."
fi

# ---------- 4. Deploy the socdude Python package ----------
step "Installing socdude package to $PKG_DEST_DIR"
mkdir -p "$INSTALL_DIR" || fail_exit "Could not create $INSTALL_DIR."
rm -rf "$PKG_DEST_DIR"
cp -r "$PKG_SRC_DIR" "$PKG_DEST_DIR" || fail_exit "Failed to copy the socdude package."
chmod -R a+rX "$INSTALL_DIR"
ok "Package deployed to $PKG_DEST_DIR."

WAZUH_GROUP="root"
if [ "$SIEM_PLATFORM" = "wazuh" ]; then
    step "Checking Wazuh installation"
    if [ ! -d "$WAZUH_INT_DIR" ]; then
        fail_exit "Wazuh integrations directory not found at $WAZUH_INT_DIR. Is Wazuh manager installed?"
    fi
    if [ ! -f "$OSSEC_CONF" ]; then
        fail_exit "ossec.conf not found at $OSSEC_CONF."
    fi
    ok "Wazuh manager detected."
    WAZUH_GROUP="$(detect_wazuh_group)"
    if [ "$WAZUH_GROUP" = "root" ]; then
        warn "Could not find 'wazuh' or 'ossec' group; falling back to root ownership."
    else
        ok "Wazuh runs under the '$WAZUH_GROUP' group. Files will be owned by root:$WAZUH_GROUP."
    fi
fi

# ---------- 5. Telegram credentials + config file ----------
step "Configuring SOCDude"
NEED_CREDS=1
if [ -f "$CONFIG_FILE" ]; then
    ok "Existing config found at $CONFIG_FILE."
    read -p "  Reconfigure Telegram token / chat ID / threat-intel API keys? [y/N]: " RECONF
    if [[ ! "$RECONF" =~ ^[Yy]$ ]]; then
        NEED_CREDS=0
    fi
fi

if [ "$NEED_CREDS" -eq 1 ]; then
    read -p "Enter your Telegram Bot Token: " TELEGRAM_TOKEN
    read -p "Enter your Telegram Chat ID: " CHAT_ID
    if [ -z "$TELEGRAM_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        fail_exit "Token and Chat ID cannot be empty."
    fi

    echo ""
    echo "Optional threat-intel API keys (press Enter to skip any of these -"
    echo "that provider is simply skipped at analysis time, nothing breaks):"
    read -p "  VirusTotal API key []: " VT_KEY
    read -p "  AbuseIPDB API key []: " ABUSEIPDB_KEY
    read -p "  GreyNoise API key []: " GREYNOISE_KEY
    read -p "  Shodan API key []: " SHODAN_KEY
    read -p "  AlienVault OTX API key []: " OTX_KEY

    mkdir -p "$CONFIG_DIR"

    python3 - "$CONFIG_FILE" "$TELEGRAM_TOKEN" "$CHAT_ID" "$SIEM_PLATFORM" \
        "$VT_KEY" "$ABUSEIPDB_KEY" "$GREYNOISE_KEY" "$SHODAN_KEY" "$OTX_KEY" <<'PYEOF'
import json, sys, os

(path, token, chat_id, siem_platform,
 vt_key, abuseipdb_key, greynoise_key, shodan_key, otx_key) = sys.argv[1:10]

cfg = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

cfg["telegram_token"] = token
cfg["chat_id"] = chat_id
cfg["siem_platform"] = siem_platform
cfg["virustotal_api_key"] = vt_key
cfg["abuseipdb_api_key"] = abuseipdb_key
cfg["greynoise_api_key"] = greynoise_key
cfg["shodan_api_key"] = shodan_key
cfg["otx_api_key"] = otx_key

# Sensible defaults for anything not already present (kept in sync with
# socdude/config.py DEFAULTS - these are just the ones worth seeding
# explicitly into the on-disk file for visibility/editability).
cfg.setdefault("ollama_url", "http://localhost:11434/api/generate")
cfg.setdefault("ollama_model", "llama3.1")
cfg.setdefault("min_level", 12)
cfg.setdefault("cooldown_seconds", 300)
cfg.setdefault("global_rate_limit_seconds", 5)
cfg.setdefault("global_rate_limit_max_burst", 5)
cfg.setdefault("correlation_window_seconds", 1800)
cfg.setdefault("correlation_max_events", 15)
cfg.setdefault("enrichment_enabled", True)
cfg.setdefault("enrichment_max_iocs_per_type", 5)
cfg.setdefault("state_db_path", "/var/ossec/logs/socdude_state.db")

with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF

    chmod 640 "$CONFIG_FILE"
    chown "root:$WAZUH_GROUP" "$CONFIG_FILE" 2>/dev/null || warn "Could not set group ownership on config."
    ok "Config written to $CONFIG_FILE (mode 640, root:$WAZUH_GROUP)."
else
    ok "Keeping existing configuration."
    chmod 640 "$CONFIG_FILE" 2>/dev/null
    chown "root:$WAZUH_GROUP" "$CONFIG_FILE" 2>/dev/null || warn "Could not set group ownership on config."
fi

if [ "$SIEM_PLATFORM" != "wazuh" ]; then
    echo "--------------------------------------------------"
    ok "Config saved. Wazuh-specific steps skipped (siem_platform=$SIEM_PLATFORM)."
    echo "--------------------------------------------------"
    exit 0
fi

# ---------- 6. Install the Wazuh launcher script ----------
step "Installing Wazuh launcher script"
cp "$LAUNCHER_SRC" "$LAUNCHER_DEST" || fail_exit "Failed to copy the launcher script."
chmod 750 "$LAUNCHER_DEST"
chown "root:$WAZUH_GROUP" "$LAUNCHER_DEST" 2>/dev/null || warn "Could not set group ownership on launcher."
ok "Launcher installed at $LAUNCHER_DEST."

# Clean up any leftover legacy install (pre-2.0 single-file version, or
# a script installed under the old unprefixed 'socdude' name that
# wazuh-integratord silently rejects).
LEGACY_SCRIPT="$WAZUH_INT_DIR/socdude"
if [ -f "$LEGACY_SCRIPT" ]; then
    warn "Found leftover script at $LEGACY_SCRIPT (unprefixed name, not usable by Wazuh). Removing."
    rm -f "$LEGACY_SCRIPT"
fi

# ---------- 7. Wire into ossec.conf ----------
step "Updating ossec.conf"
if grep -q "<name>${INTEGRATION_NAME}</name>" "$OSSEC_CONF"; then
    ok "Integration block already present in ossec.conf."
else
    BACKUP="${OSSEC_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$OSSEC_CONF" "$BACKUP" || fail_exit "Failed to back up ossec.conf."
    ok "Backed up ossec.conf to $BACKUP."

    if grep -q "<name>socdude</name>" "$OSSEC_CONF"; then
        warn "Removing leftover unprefixed <name>socdude</name> block."
        python3 - "$OSSEC_CONF" <<'PYEOF'
import re, sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
content = re.sub(r'\s*<integration>\s*<name>socdude</name>.*?</integration>', '', content, flags=re.DOTALL)
with open(path, 'w') as f:
    f.write(content)
PYEOF
    fi

    sed -i "/<\/ossec_config>/i \\
  <integration>\\n    <name>${INTEGRATION_NAME}</name>\\n    <level>12</level>\\n    <alert_format>json</alert_format>\\n  </integration>" \
        "$OSSEC_CONF" || fail_exit "Failed to edit ossec.conf. Restore from $BACKUP if needed."

    if command -v xmllint >/dev/null 2>&1; then
        if ! xmllint --noout "$OSSEC_CONF" 2>/dev/null; then
            cp "$BACKUP" "$OSSEC_CONF"
            fail_exit "ossec.conf became invalid XML after edit. Reverted from backup."
        fi
    fi
    ok "Integration block added to ossec.conf as <name>${INTEGRATION_NAME}</name>."
fi

if grep -q "<name>custom-ai-telegram</name>" "$OSSEC_CONF"; then
    warn "Old 'custom-ai-telegram' integration block still present in ossec.conf."
    warn "Remove it manually (or re-run this installer) to avoid duplicate Telegram messages."
fi

step "Restarting Wazuh manager"
if systemctl restart wazuh-manager; then
    sleep 2
    if systemctl is-active --quiet wazuh-manager; then
        ok "Wazuh manager restarted successfully."
    else
        warn "Wazuh manager restart command succeeded but service is not active. Check: systemctl status wazuh-manager"
    fi
else
    warn "Failed to restart wazuh-manager via systemctl. Restart it manually."
fi

# ---------- 8. Send a test Telegram message ----------
step "Sending a test message to Telegram"
TEST_RESULT=$(python3 - "$CONFIG_FILE" <<'PYEOF'
import json, sys
try:
    import requests
except ImportError:
    print("SKIP: requests not importable")
    sys.exit(0)

path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)

url = f"https://api.telegram.org/bot{cfg['telegram_token']}/sendMessage"
payload = {"chat_id": cfg["chat_id"], "text": "SOCDude 2.0 installed successfully. This is a test message."}
try:
    r = requests.post(url, json=payload, timeout=10)
    print("OK" if r.ok else f"FAIL: HTTP {r.status_code} - {r.text[:200]}")
except Exception as e:
    print(f"FAIL: {e}")
PYEOF
)

if [[ "$TEST_RESULT" == "OK" ]]; then
    ok "Test message sent - check your Telegram chat."
elif [[ "$TEST_RESULT" == SKIP* ]]; then
    warn "Could not run Telegram test (requests not importable in this shell)."
else
    warn "Test message failed: $TEST_RESULT"
    warn "Double-check your bot token and chat ID in $CONFIG_FILE, then re-run this installer."
fi

echo "--------------------------------------------------"
ok "SOCDude installation completed!"
MIN_LEVEL_DISPLAY=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('min_level', 12))" 2>/dev/null || echo 12)
echo "Alerts at level >= $MIN_LEVEL_DISPLAY will now be analyzed by AI and sent to Telegram."
echo "Logs:    tail -f /var/ossec/logs/integrations.log"
echo "Config:  $CONFIG_FILE"
echo "Package: $PKG_DEST_DIR"
echo "--------------------------------------------------"
