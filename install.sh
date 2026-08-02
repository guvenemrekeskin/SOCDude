#!/bin/bash
#
# SOCDude Installer
# Installs/configures: Python deps, Ollama + llama3.1, the socdude
# integration script, its config file, and the Wazuh ossec.conf hook.
# Safe to re-run: every step checks current state first and skips
# work that's already done, unless you explicitly ask to reconfigure.

set -uo pipefail  # no -e: we handle failures explicitly per step so
                   # one bad check doesn't kill the whole script

# ---------- Paths ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_SCRIPT="$SCRIPT_DIR/socdude.py"
WAZUH_INT_DIR="/var/ossec/integrations"
DEST_SCRIPT="$WAZUH_INT_DIR/custom-socdude"
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

fail_exit() {
    err "$1"
    err "Installation aborted."
    exit 1
}

# Detect the group Wazuh's own processes run as. Newer Wazuh versions
# use the 'wazuh' user/group; older ones used 'ossec'. We need this to
# set correct file permissions so wazuh-integratord (running as this
# user) can actually read the script and config file.
detect_wazuh_group() {
    if getent group wazuh >/dev/null 2>&1; then
        echo "wazuh"
    elif getent group ossec >/dev/null 2>&1; then
        echo "ossec"
    else
        echo "root"  # fallback, will warn later
    fi
}

# ---------- 0. Root check ----------
if [ "$EUID" -ne 0 ]; then
    fail_exit "Please run this script with sudo or as root."
fi

echo "=================================================="
echo "          SOCDude Installer                       "
echo "=================================================="

# ---------- 0b. Sanity: source script present ----------
if [ ! -f "$SRC_SCRIPT" ]; then
    fail_exit "socdude.py not found next to install.sh (expected at $SRC_SCRIPT)."
fi

# ---------- 1. Python3 + pip ----------
step "Checking Python3"
if ! command -v python3 >/dev/null 2>&1; then
    warn "Python3 not found. Installing..."
    apt-get update -qq && apt-get install -y python3 python3-pip \
        || fail_exit "Failed to install Python3."
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
    # --break-system-packages needed on newer Debian/Ubuntu (PEP 668);
    # harmless flag on older systems that don't require it... but to be
    # safe we try without it first, then with it.
    if pip3 install --quiet requests 2>/dev/null; then
        ok "'requests' installed."
    elif pip3 install --quiet --break-system-packages requests 2>/dev/null; then
        ok "'requests' installed (system-managed environment)."
    else
        fail_exit "Failed to install 'requests' via pip3."
    fi
fi

# ---------- 2. Ollama ----------
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
    systemctl enable --now ollama >/dev/null 2>&1 \
        || warn "Could not manage ollama via systemctl (may be running another way)."
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

# ---------- 3. Wazuh presence check ----------
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

# ---------- 4. Telegram credentials / config file ----------
step "Configuring Telegram credentials"
NEED_CREDS=1
if [ -f "$CONFIG_FILE" ]; then
    ok "Existing config found at $CONFIG_FILE."
    read -p "    Reconfigure Telegram token / chat ID? [y/N]: " RECONF
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

    mkdir -p "$CONFIG_DIR"

    # Preserve existing tunables if a config already exists; otherwise
    # start from sensible defaults (kept in sync with socdude.py DEFAULTS).
    if [ -f "$CONFIG_FILE" ]; then
        python3 - "$CONFIG_FILE" "$TELEGRAM_TOKEN" "$CHAT_ID" <<'PYEOF'
import json, sys
path, token, chat_id = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    cfg = json.load(f)
cfg["telegram_token"] = token
cfg["chat_id"] = chat_id
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF
    else
        cat > "$CONFIG_FILE" <<EOF
{
  "telegram_token": "$TELEGRAM_TOKEN",
  "chat_id": "$CHAT_ID",
  "ollama_url": "http://localhost:11434/api/generate",
  "ollama_model": "llama3.1",
  "min_level": 12,
  "cooldown_seconds": 300,
  "global_rate_limit_seconds": 5,
  "global_rate_limit_max_burst": 5,
  "http_timeout_seconds": 10,
  "ollama_timeout_seconds": 150,
  "ollama_num_predict": 180,
  "max_retries": 2,
  "retry_backoff_seconds": 2
}
EOF
    fi

    chmod 640 "$CONFIG_FILE"
    chown "root:$WAZUH_GROUP" "$CONFIG_FILE" 2>/dev/null || warn "Could not set group ownership on config."
    ok "Config written to $CONFIG_FILE (mode 640, root:$WAZUH_GROUP)."
else
    ok "Keeping existing Telegram credentials."
    chmod 640 "$CONFIG_FILE" 2>/dev/null
    chown "root:$WAZUH_GROUP" "$CONFIG_FILE" 2>/dev/null || warn "Could not set group ownership on config."
fi

# ---------- 5. Install the integration script ----------
step "Installing socdude integration script"
cp "$SRC_SCRIPT" "$DEST_SCRIPT" || fail_exit "Failed to copy socdude.py."
chmod 750 "$DEST_SCRIPT"
chown "root:$WAZUH_GROUP" "$DEST_SCRIPT" 2>/dev/null || warn "Could not set group ownership on script."
ok "Script installed at $DEST_SCRIPT."

# Clean up any leftover legacy integration (old manual custom-ai-telegram
# setup, or a script installed under the old unprefixed 'socdude' name
# that wazuh-integratord silently rejects).
LEGACY_SCRIPT="$WAZUH_INT_DIR/socdude"
if [ -f "$LEGACY_SCRIPT" ]; then
    warn "Found leftover script at $LEGACY_SCRIPT (unprefixed name, not usable by Wazuh). Removing."
    rm -f "$LEGACY_SCRIPT"
fi

# ---------- 6. Wire into ossec.conf ----------
# IMPORTANT: wazuh-integratord only accepts a fixed list of built-in
# integration names (slack, pagerduty, virustotal, shuffle, ...) unless
# the name starts with "custom-". Using a bare "socdude" name makes it
# fail with "Invalid integration: 'socdude'. Not currently supported."
# and silently never call the script. So the <name> here MUST be
# "custom-socdude", matching $INTEGRATION_NAME / $DEST_SCRIPT above.
step "Updating ossec.conf"

if grep -q "<name>${INTEGRATION_NAME}</name>" "$OSSEC_CONF"; then
    ok "Integration block already present in ossec.conf."
else
    BACKUP="${OSSEC_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$OSSEC_CONF" "$BACKUP" || fail_exit "Failed to back up ossec.conf."
    ok "Backed up ossec.conf to $BACKUP."

    # Remove any leftover block using the old unprefixed 'socdude' name
    # (from an earlier version of this installer) so we don't end up
    # with a dead duplicate entry.
    if grep -q "<name>socdude</name>" "$OSSEC_CONF"; then
        warn "Removing leftover unprefixed <name>socdude</name> block."
        python3 - "$OSSEC_CONF" <<'PYEOF'
import re, sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
content = re.sub(
    r'\s*<integration>\s*<name>socdude</name>.*?</integration>',
    '', content, flags=re.DOTALL
)
with open(path, 'w') as f:
    f.write(content)
PYEOF
    fi

    sed -i "/<\/ossec_config>/i \\
  <integration>\\n    <name>${INTEGRATION_NAME}</name>\\n    <level>12</level>\\n    <alert_format>json</alert_format>\\n  </integration>" \
        "$OSSEC_CONF" || fail_exit "Failed to edit ossec.conf. Restore from $BACKUP if needed."

    # Sanity check: make sure the file is still valid XML before restarting.
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

# ---------- 7. Send a test Telegram message ----------
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
payload = {"chat_id": cfg["chat_id"], "text": "SOCDude installed successfully. This is a test message."}
try:
    r = requests.post(url, json=payload, timeout=10)
    if r.ok:
        print("OK")
    else:
        print(f"FAIL: HTTP {r.status_code} - {r.text[:200]}")
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
MIN_LEVEL_DISPLAY=$(grep -oP '"min_level":\s*\K[0-9]+' "$CONFIG_FILE" 2>/dev/null || echo 12)
echo "Alerts at level >= $MIN_LEVEL_DISPLAY will now be analyzed by AI and sent to Telegram."
echo "Logs: tail -f /var/ossec/logs/integrations.log"
echo "Config: $CONFIG_FILE"
echo "--------------------------------------------------"