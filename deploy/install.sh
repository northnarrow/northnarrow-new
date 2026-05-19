#!/usr/bin/env bash
# NorthNarrow XDR install skeleton (Tappa 7 task 6 Watchdog W7).
#
# Copies the release-mode agent + watchdog binaries to
# /usr/local/bin/ and the two systemd unit files to
# /etc/systemd/system/, then `daemon-reload`s. Does NOT enable
# or start the units — operators run that explicitly after
# inspecting the install layout.
#
# Usage:
#   sudo ./deploy/install.sh
#
# Assumes the repo's `cargo build --release` has already run and
# produced ./target/release/{northnarrow-agent,northnarrow-watchdog}.
# Pre-flights every step so an incomplete invocation surfaces an
# actionable error instead of leaving a half-installed system.

set -euo pipefail

# ── configuration ───────────────────────────────────────────────────
REPO_ROOT=${REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
TARGET_DIR=${TARGET_DIR:-"$REPO_ROOT/target/release"}
BIN_DIR=${BIN_DIR:-/usr/local/bin}
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}

AGENT_BIN="$TARGET_DIR/northnarrow-agent"
WATCHDOG_BIN="$TARGET_DIR/northnarrow-watchdog"
AGENT_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-agent.service"
WATCHDOG_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-watchdog.service"

# ── pre-flight ──────────────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "install.sh: must run as root (use sudo)" >&2
        exit 1
    fi
}

require_file() {
    local path=$1
    local hint=$2
    if [[ ! -f "$path" ]]; then
        echo "install.sh: required file missing: $path" >&2
        echo "install.sh: $hint" >&2
        exit 1
    fi
}

require_root
require_file "$AGENT_BIN"    "run \`cargo build --release -p northnarrow-agent\` first"
require_file "$WATCHDOG_BIN" "run \`cargo build --release -p northnarrow-watchdog\` first"
require_file "$AGENT_UNIT_SRC"    "expected at $AGENT_UNIT_SRC (this script's sibling deploy/systemd/)"
require_file "$WATCHDOG_UNIT_SRC" "expected at $WATCHDOG_UNIT_SRC"

# ── install ─────────────────────────────────────────────────────────
echo "install.sh: copying binaries to $BIN_DIR/"
install -m 755 -o root -g root "$AGENT_BIN"    "$BIN_DIR/northnarrow-agent"
install -m 755 -o root -g root "$WATCHDOG_BIN" "$BIN_DIR/northnarrow-watchdog"

echo "install.sh: copying systemd unit files to $UNIT_DIR/"
install -m 644 -o root -g root "$AGENT_UNIT_SRC"    "$UNIT_DIR/northnarrow-agent.service"
install -m 644 -o root -g root "$WATCHDOG_UNIT_SRC" "$UNIT_DIR/northnarrow-watchdog.service"

echo "install.sh: reloading systemd unit catalogue"
systemctl daemon-reload

echo ""
echo "install.sh: install complete."
echo ""
echo "Next steps (operator runs explicitly — install.sh does NOT auto-start):"
echo ""
echo "  1. Verify the install layout:"
echo "       systemctl status northnarrow-agent.service"
echo "       systemctl status northnarrow-watchdog.service"
echo ""
echo "  2. Confirm /etc/northnarrow/ has admin.pub + combat-rules.v4 +"
echo "     agent_id (the agent will bootstrap agent_id on first start;"
echo "     admin.pub + combat-rules.v4 are operator-provided)."
echo ""
echo "  3. Confirm bpffs is mounted at /sys/fs/bpf:"
echo "       mount | grep ' /sys/fs/bpf'"
echo "     If absent: mount -t bpf bpf /sys/fs/bpf"
echo ""
echo "  4. Confirm the 'bpf' LSM is in the kernel's lsm= chain:"
echo "       cat /sys/kernel/security/lsm"
echo "     If absent: edit /etc/default/grub to add 'lsm=…,bpf' then"
echo "       update-grub && reboot. (See docs/TAPPA7_PREREQ.md.)"
echo ""
echo "  5. Enable + start:"
echo "       systemctl enable --now northnarrow-agent.service"
echo "       systemctl enable --now northnarrow-watchdog.service"
echo ""
echo "  6. Follow logs:"
echo "       journalctl -u northnarrow-agent.service -f"
echo "       journalctl -u northnarrow-watchdog.service -f"
