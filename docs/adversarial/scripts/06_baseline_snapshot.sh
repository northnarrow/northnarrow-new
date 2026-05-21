#!/usr/bin/env bash
# Tappa 10.7 V1 — take the 'v1-baseline' snapshot of both VMs.
#
# RUNS ON: the VirtualBox host.
# This is the clean revert point the test protocol rolls back to between
# TTP families (per-family) and per-TTP for state-mutating tests
# (§13 Q10). Idempotent: skips a VM whose '$BASELINE_SNAPSHOT' snapshot
# already exists.
# Design ref: §2.2, §2.3, §6.1, §13 Q10.
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

require_cmd VBoxManage

# Snapshot only powered-off VMs by default (online snapshots include
# volatile RAM state we don't want as the clean baseline).
snapshot_vm() {
    local vm="$1"
    vm_exists "$vm" || { warn "VM '$vm' missing — skipping"; return; }
    if snapshot_exists "$vm" "$BASELINE_SNAPSHOT"; then
        log "Snapshot '$BASELINE_SNAPSHOT' already exists for '$vm' — skipping (idempotent)."
        return
    fi
    if vm_running "$vm"; then
        warn "'$vm' is running; powering off for a clean offline baseline..."
        VBoxManage controlvm "$vm" acpipowerbutton 2>/dev/null || true
        # Give ACPI shutdown a moment; fall back to poweroff.
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            vm_running "$vm" || break
            VBoxManage list runningvms >/dev/null 2>&1
        done
        vm_running "$vm" && VBoxManage controlvm "$vm" poweroff 2>/dev/null || true
    fi
    log "Taking snapshot '$BASELINE_SNAPSHOT' of '$vm'..."
    VBoxManage snapshot "$vm" take "$BASELINE_SNAPSHOT" \
        --description "Tappa 10.7 V1 clean baseline (provisioned, isolated)"
}

snapshot_vm "$TARGET_VM"
snapshot_vm "$ATTACKER_VM"

log "Baseline snapshots complete. Revert with:"
log "  VBoxManage snapshot <vm> restore '$BASELINE_SNAPSHOT'"
