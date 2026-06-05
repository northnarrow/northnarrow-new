#!/usr/bin/env bash
# Tappa 10.7 V1 — provision the offensive toolkit on kalidev.
#
# ┌─────────────────────────────────────────────────────────────────────┐
# │ STATUS: ALREADY DONE on the live range (kalidev provisioned in prior │
# │ sessions: Atomic Red Team, Sliver, Metasploit, LaZagne, Pupy,        │
# │ Caldera). This script is shipped for REPRODUCIBILITY + documentation │
# │ — it is NOT part of the normal V1 run. Re-run it only when rebuilding │
# │ kalidev from a fresh Kali image. Every step is idempotent, so a       │
# │ re-run on the provisioned box is a no-op that simply reports "already │
# │ present".                                                             │
# └─────────────────────────────────────────────────────────────────────┘
#
# RUNS ON: inside the attacker guest (kalidev).
# PROVISIONING NETWORK: needs the temporary NAT adapter attached (it
# downloads tools). On the host: re-attach NAT, run this, then DETACH NAT
# + Tailscale and snapshot 'armed' before any attack run — the
# C2-containment invariant (RANGE_SETUP.md §containment, design §2.1).
# Design ref: §3, §10.1, §13 Q2/Q3.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00_config.sh"

# Refuse to run on the wrong VM — this installs offensive tooling.
if [ -r /etc/os-release ] && ! grep -qi kali /etc/os-release; then
    die "this is not a Kali system — provision-kali.sh runs on $ATTACKER_VM only"
fi
require_cmd git
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"

# Optional version pins (§13 Q2 — reproducible toolchain). Empty = latest.
: "${ART_REF:=}"        # Atomic Red Team git ref/tag
: "${SLIVER_VERSION:=}" # Sliver release tag, if pinning the installer

apt_ensure() {
    for pkg in "$@"; do
        dpkg -s "$pkg" >/dev/null 2>&1 \
            && log "apt: $pkg already installed" \
            || { log "apt: installing $pkg"; $SUDO apt-get install -y "$pkg"; }
    done
}
clone_or_skip() {  # $1=dir $2=url  [$3=extra git args]
    if [ -d "$1/.git" ]; then log "already cloned: $1"; else
        log "cloning $2 → $1"; git clone --depth 1 ${3:-} "$2" "$1"; fi
}

log "Refreshing apt metadata..."
$SUDO apt-get update -y

# 1. Atomic Red Team — full clone (curated Linux execution happens in V2).
ART_DIR="${ART_DIR:-$HOME/atomic-red-team}"
clone_or_skip "$ART_DIR" "https://github.com/redcanaryco/atomic-red-team.git"
[ -n "$ART_REF" ] && git -C "$ART_DIR" checkout "$ART_REF" || true

# 2. Metasploit (Kali repo package).
command -v msfconsole >/dev/null 2>&1 \
    && log "Metasploit already present" || apt_ensure metasploit-framework

# 3. Sliver C2.
if command -v sliver-server >/dev/null 2>&1; then log "Sliver already present"; else
    log "Installing Sliver..."; curl -fsSL https://sliver.sh/install | $SUDO bash; fi

# 4. LaZagne — credential dumping.
clone_or_skip "${LAZAGNE_DIR:-$HOME/LaZagne}" "https://github.com/AlessandroZ/LaZagne.git"

# 5. Pupy RAT.
clone_or_skip "${PUPY_DIR:-$HOME/pupy}" \
    "https://github.com/n1nj4sec/pupy.git" "--recurse-submodules"

# 6. Caldera (optional — §13 Q3 upper band).
if [ "${INSTALL_CALDERA:-0}" = 1 ]; then
    clone_or_skip "${CALDERA_DIR:-$HOME/caldera}" \
        "https://github.com/mitre/caldera.git" "--recurse-submodules"
fi

# 7. Verify the toolchain is callable.
log "Verifying toolchain..."
for t in msfconsole sliver-server; do
    command -v "$t" >/dev/null 2>&1 && log "  ok: $t" || warn "  MISSING: $t"
done
[ -d "$ART_DIR/atomics" ] && log "  ok: Atomic Red Team atomics/" || warn "  MISSING: atomics/"

log "Toolkit provisioning complete (or already complete)."
log "BEFORE any attack run (host side): detach NAT on BOTH VMs, stop"
log "Tailscale on kalidev, run isolation verify, then snapshot '$ATTACKER_SNAPSHOT'."
log "See RANGE_SETUP.md §containment."
