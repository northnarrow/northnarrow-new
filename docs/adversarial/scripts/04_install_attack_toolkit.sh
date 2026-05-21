#!/usr/bin/env bash
# Tappa 10.7 V1 — install the offensive toolkit on kalidev.
#
# RUNS ON: inside the attacker guest (kalidev), with NAT temporarily
# attached (run `02_configure_network.sh nat-on attacker` first; detach
# with `nat-off` + snapshot afterwards — §2.1 provisioning lifecycle).
#
# Per §13 Q2/Q3: full Atomic Red Team clone (curated execution later) +
# Sliver + Metasploit + LaZagne + Pupy. Each install is guarded so the
# script is idempotent and re-runnable.
# Design ref: §3, §10.1, §13 Q2/Q3.
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

require_cmd git
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"

apt_ensure() {
    for pkg in "$@"; do
        dpkg -s "$pkg" >/dev/null 2>&1 \
            && log "apt: $pkg already installed" \
            || { log "apt: installing $pkg"; $SUDO apt-get install -y "$pkg"; }
    done
}

log "Refreshing apt metadata..."
$SUDO apt-get update -y

# 1. Atomic Red Team — full clone, curated Linux execution (Q2).
ART_DIR="${ART_DIR:-$HOME/atomic-red-team}"
if [ -d "$ART_DIR/.git" ]; then
    log "Atomic Red Team already cloned at $ART_DIR"
else
    log "Cloning Atomic Red Team (full repo)..."
    git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git "$ART_DIR"
fi

# 2. Metasploit (Kali repo package).
command -v msfconsole >/dev/null 2>&1 \
    && log "Metasploit already present" \
    || apt_ensure metasploit-framework

# 3. Sliver C2 (official installer; pinned by the operator if desired).
if command -v sliver-server >/dev/null 2>&1; then
    log "Sliver already present"
else
    log "Installing Sliver..."
    curl -fsSL https://sliver.sh/install | $SUDO bash
fi

# 4. LaZagne — Linux credential dumping (pip, guarded).
LAZAGNE_DIR="${LAZAGNE_DIR:-$HOME/LaZagne}"
[ -d "$LAZAGNE_DIR/.git" ] \
    && log "LaZagne already cloned at $LAZAGNE_DIR" \
    || git clone --depth 1 https://github.com/AlessandroZ/LaZagne.git "$LAZAGNE_DIR"

# 5. Pupy RAT.
PUPY_DIR="${PUPY_DIR:-$HOME/pupy}"
[ -d "$PUPY_DIR/.git" ] \
    && log "Pupy already cloned at $PUPY_DIR" \
    || git clone --depth 1 --recurse-submodules https://github.com/n1nj4sec/pupy.git "$PUPY_DIR"

log "Attack toolkit install complete."
log "REMINDER (§2.1): detach NAT and snapshot 'armed' BEFORE any run:"
log "  ./02_configure_network.sh nat-off attacker && ./06_baseline_snapshot.sh"
