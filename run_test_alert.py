#!/usr/bin/env python3
"""Run SOCDude's full pipeline against a local alert JSON file, without
needing a live Wazuh manager or a system install.

Usage:
    python3 run_test_alert.py samples/alert_ssh_bruteforce.json --dry-run \\
        --config config.example.json

Flags:
    --dry-run          Print the message instead of sending to Telegram.
    --persist-state    Reuse the configured state DB across runs instead
                        of a fresh throw-away one, so correlation can
                        build up history across repeated --test calls.
    --config <path>    Config file to use (defaults to /etc/socdude/config.json,
                        which almost certainly doesn't exist yet on a dev
                        machine - pass config.example.json, or better, your
                        own copy with real API keys filled in, to see real
                        enrichment results).

Any other args are forwarded as-is.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from socdude.cli import main  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    alert_path = sys.argv[1]
    extra_args = sys.argv[2:]
    main(["run_test_alert.py", "--test", alert_path] + extra_args)
