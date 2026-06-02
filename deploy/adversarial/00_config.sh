#!/usr/bin/env bash
# Tappa 10.7 — Adversarial Validation range — shared config + helpers.
#
# SOURCED by the in-guest V1 scripts (bootstrap-target-prod.sh,
# provision-kali.sh): `source "$(dirname "$0")/00_config.sh"`.
# Not meant to be run directly. Override any value via the environment,
# e.g.  EXPECTED_RULE_COUNT=70 ./bootstrap-target-prod.sh
#
# Design of record: docs/design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md
# Operator runbook:  RANGE_SETUP.md  (current, reflects the live range)
#
# NOTE: this supersedes docs/adversarial/scripts/00_config.sh, which
# carried the pre-build placeholder values (192.168.56.x IPs, /opt repo
# path, the 61-rule pin, the wrong `northnarrow.service` unit name). The
# values here are the ones verified on the live range on 2026-06-02.

# ── VM identity ──────────────────────────────────────────────────────
: "${ATTACKER_VM:=kalidev}"            # VM2 — Kali attacker
: "${TARGET_VM:=northnarrowdev}"       # VM1 — NorthNarrow target (prod mode)

# ── network (§2.1 — intnet-adversarial, static IPs, no DHCP) ─────────
# CORRECTED to the live range (was 192.168.56.x in the old draft).
: "${INTNET:=intnet-adversarial}"      # VirtualBox Internal Network name
: "${ATTACKER_IP:=10.10.10.10}"        # Kali  — eth1 (NetworkManager)
: "${TARGET_IP:=10.10.10.20}"          # northnarrowdev — enp0s8 (netplan)
: "${INTNET_CIDR:=24}"
: "${TARGET_INTNET_IF:=enp0s8}"        # target NIC on the isolated intnet
: "${ATTACKER_INTNET_IF:=eth1}"        # attacker NIC on the isolated intnet

# ── snapshots (§6.1 cadence, §13 Q10) ────────────────────────────────
: "${TARGET_SNAPSHOT:=clean-prod}"     # target revert point (post-bootstrap)
: "${ATTACKER_SNAPSHOT:=armed}"        # attacker revert point (toolchain ready)

# ── repo / build / runtime (verified on the live target) ─────────────
# NN_REPO_DIR auto-derives from this script's location (repo/deploy/adversarial
# → repo root) so the bootstrap works regardless of where the repo is cloned.
: "${NN_REPO_DIR:=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
: "${NN_ETC_DIR:=/etc/northnarrow}"
: "${NN_STATE_DIR:=/var/lib/northnarrow}"
: "${NN_RUN_DIR:=/run/northnarrow}"
: "${NN_BIN_DIR:=/usr/local/bin}"
: "${NN_AGENT_UNIT:=northnarrow-agent.service}"       # CORRECTED (was northnarrow.service)
: "${NN_WATCHDOG_UNIT:=northnarrow-watchdog.service}"
: "${NN_JOURNAL_NS:=northnarrow}"      # LogNamespace — plain journalctl shows nothing
# T10.5→T10.6→BUG-034 engine: current SOURCE loads 69 rules (verified
# 2026-06-02 against agent/src/decision/tests.rs). The live binary on the
# range reports 68 only because it was built before BUG-034 R018 landed;
# bootstrap rebuilds from source → 69. NOT the stale-doc 61.
: "${EXPECTED_RULE_COUNT:=69}"

# Exact CapabilityBoundingSet the BUG-042-corrected unit must yield
# (deploy/systemd/northnarrow-agent.service). The health check decodes the
# running agent's CapEff and asserts this set is present AND that the
# near-root CAP_SYS_ADMIN is ABSENT (the BUG-042 regression guard).
: "${REQUIRED_CAPS:=cap_bpf cap_perfmon cap_net_admin cap_linux_immutable cap_sys_ptrace cap_dac_override}"
: "${FORBIDDEN_CAPS:=cap_sys_admin}"

# ── shared helpers ───────────────────────────────────────────────────
log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s] WARN: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

require_cmd()  { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
require_root() { [ "$(id -u)" = 0 ] || die "must run as root: $*"; }

# Confirm guard for destructive steps; honours FORCE=1 for automation.
confirm() {
    [ "${FORCE:-0}" = "1" ] && return 0
    printf '%s [y/N] ' "$1"; read -r reply || return 1
    [ "$reply" = "y" ] || [ "$reply" = "Y" ]
}
