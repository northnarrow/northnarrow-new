#!/usr/bin/env bash
# Tappa 10.7 V1 — full range teardown + cleanup.
#
# RUNS ON: the VirtualBox host.
# Powers off and unregisters both VMs (deleting their disks) so the
# range leaves no residue. DESTRUCTIVE — guarded by confirm() (set
# FORCE=1 to skip the prompt in automation). The intnet 'intnet-adversarial'
# is implicit in VirtualBox and disappears once no NIC references it.
#
# By default the disks ARE deleted; pass KEEP_DISKS=1 to unregister only.
# Design ref: §2, §6.1.
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

require_cmd VBoxManage

confirm "Tear down VMs '$ATTACKER_VM' and '$TARGET_VM' (disks ${KEEP_DISKS:+kept}${KEEP_DISKS:-DELETED})?" \
    || die "aborted by operator"

teardown_vm() {
    local vm="$1"
    if ! vm_exists "$vm"; then
        log "VM '$vm' does not exist — nothing to tear down (idempotent)."
        return
    fi
    if vm_running "$vm"; then
        log "Powering off '$vm'..."
        VBoxManage controlvm "$vm" poweroff 2>/dev/null || true
    fi
    if [ "${KEEP_DISKS:-0}" = 1 ]; then
        log "Unregistering '$vm' (keeping disks)..."
        VBoxManage unregistervm "$vm"
    else
        log "Unregistering + deleting '$vm' and its media..."
        VBoxManage unregistervm "$vm" --delete
    fi
}

teardown_vm "$ATTACKER_VM"
teardown_vm "$TARGET_VM"

log "Teardown complete. The intnet '$INTNET' is released automatically"
log "once no NIC references it (no explicit deletion needed)."
