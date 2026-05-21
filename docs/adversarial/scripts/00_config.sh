#!/usr/bin/env bash
# Tappa 10.7 — Adversarial Validation range — shared config + helpers.
#
# SOURCED by every 0N_*.sh script (`source "$(dirname "$0")/00_config.sh"`).
# Not meant to be run directly. Override any value via the environment,
# e.g.  KALI_ISO=/isos/kali.iso ./01_provision_kalidev.sh
#
# Design refs: TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md §2 (environment),
# §10 (deployment), §13 Q10 (snapshot strategy).

# ── VM identity ──────────────────────────────────────────────────────
: "${ATTACKER_VM:=kalidev}"          # VM2 — Kali attacker
: "${TARGET_VM:=northnarrowdev}"     # VM1 — NorthNarrow target (prod mode)

# ── network (§2.1 — intnet-adversarial, static IPs, no DHCP) ─────────
: "${INTNET:=intnet-adversarial}"    # VirtualBox Internal Network name
: "${ATTACKER_IP:=192.168.56.10}"    # Kali (attacker)
: "${TARGET_IP:=192.168.56.20}"      # northnarrowdev (target)
: "${INTNET_CIDR:=24}"
: "${INTNET_NIC:=2}"                 # NIC slot used for the isolated intnet
: "${NAT_NIC:=1}"                    # NIC slot used for provisioning-only NAT

# ── media + snapshot (§13 Q10) ───────────────────────────────────────
: "${KALI_ISO:=}"                    # REQUIRED for 01 — path to Kali 2025.x ISO
: "${BASELINE_SNAPSHOT:=v1-baseline}"

# ── VM hardware ──────────────────────────────────────────────────────
: "${ATTACKER_RAM_MB:=4096}"
: "${ATTACKER_CPUS:=2}"
: "${ATTACKER_DISK_MB:=40960}"

# ── repo / build (§10.2 — target prod-mode bootstrap) ────────────────
: "${NN_REPO_DIR:=/opt/northnarrow-new}"
: "${NN_ETC_DIR:=/etc/northnarrow}"
: "${EXPECTED_RULE_COUNT:=61}"       # T10.5 engine pin

# ── shared helpers ───────────────────────────────────────────────────
log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s] WARN: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# Idempotency primitives — each is a pure query, safe to call repeatedly.
vm_exists()       { VBoxManage showvminfo "$1" >/dev/null 2>&1; }
vm_running()      { VBoxManage list runningvms | grep -q "\"$1\""; }
snapshot_exists() { VBoxManage snapshot "$1" list >/dev/null 2>&1 \
                    && VBoxManage snapshot "$1" list 2>/dev/null | grep -qF "$2"; }

# Interactive guard for destructive steps; honours FORCE=1 for automation.
confirm() {
    [ "${FORCE:-0}" = "1" ] && return 0
    printf '%s [y/N] ' "$1"
    read -r reply || return 1
    [ "$reply" = "y" ] || [ "$reply" = "Y" ]
}
