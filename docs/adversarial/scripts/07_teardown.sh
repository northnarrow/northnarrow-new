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
#
# External audit LAB-019 (NN-AUD-409, lab PR 211): the prompt said
# "disks kept0" for KEEP_DISKS=0 and deleted them, and FORCE=1 printed
# nothing at all. KEEP_DISKS is 0 (the default) or 1, anything else stops
# here; the same value names the action in the line always printed, in the
# prompt and in the branch. Before anything is powered off, every disk image
# `--delete` would remove must lie in that VM's own folder (next to its
# .vbox): a disk attached from elsewhere (a shared or copied image, another
# VM's) stops the teardown instead of being deleted with the VM.
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

require_cmd VBoxManage

case "${KEEP_DISKS:-0}" in
    0) keep=0; disks="disks DELETED" ;;
    1) keep=1; disks="disks KEPT" ;;
    *) die "KEEP_DISKS must be 0 (delete the disks, the default) or 1 (keep them), not '${KEEP_DISKS}'" ;;
esac

# The disk images attached to a VM, one per line: every attachment that
# names a file, except a removable drive's (DVD or floppy: an IsEjected key)
# that VirtualBox does not open as a hard disk — `unregistervm --delete`
# deletes hard disks, not ISOs. When in doubt a file counts as a disk.
vm_disks() {
    local info ctl pd path
    info=$(VBoxManage showvminfo "$1" --machinereadable 2>/dev/null) || return 1
    sed -n 's/^"\(.*\)-\([0-9][0-9]*-[0-9][0-9]*\)"="\(.*\)"$/\1\t\2\t\3/p' <<<"$info" |
        while IFS=$'\t' read -r ctl pd path; do
            case "$path" in /* | [A-Za-z]:[\\/]*) ;; *) continue ;; esac
            if grep -qF "\"$ctl-IsEjected-$pd\"=" <<<"$info" \
                && ! VBoxManage showmediuminfo disk "$path" >/dev/null 2>&1; then
                continue
            fi
            printf '%s\n' "$path"
        done
}
# Every disk of the VM in its folder (the directory of its .vbox), or say
# which is not.
disks_in_vm_folder() {
    local cfg folder d bad=0
    cfg=$(VBoxManage showvminfo "$1" --machinereadable 2>/dev/null | sed -n 's/^CfgFile="\(.*\)"$/\1/p')
    [ -n "$cfg" ] || { warn "VM '$1': no CfgFile in showvminfo — cannot tell where its disks belong"; return 1; }
    folder=${cfg%[/\\]*}
    while IFS= read -r d; do
        case "$d" in
            *[/\\]..[/\\]*) warn "VM '$1': disk $d is not a plain path — not deleting it"; bad=1 ;;
            "$folder"[/\\]*) ;;
            *) warn "VM '$1': disk $d is outside its folder $folder — not deleting it"; bad=1 ;;
        esac
    done < <(vm_disks "$1")
    return "$bad"
}

if [ "$keep" = 0 ]; then
    for vm in "$ATTACKER_VM" "$TARGET_VM"; do
        if vm_exists "$vm"; then
            disks_in_vm_folder "$vm" \
                || die "refusing to delete '$vm' with its disks: detach the disks above, or KEEP_DISKS=1 to unregister only"
        fi
    done
fi

log "Teardown of VMs '$ATTACKER_VM' and '$TARGET_VM': $disks"
confirm "Tear down VMs '$ATTACKER_VM' and '$TARGET_VM' ($disks)?" \
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
    if [ "$keep" = 1 ]; then
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
