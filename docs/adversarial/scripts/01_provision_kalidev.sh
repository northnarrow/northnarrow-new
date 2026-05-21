#!/usr/bin/env bash
# Tappa 10.7 V1 — provision the kalidev attacker VM.
#
# RUNS ON: the VirtualBox host.
# Creates the Kali VM shell, attaches the Kali 2025.x ISO, and boots it
# for OS install. Idempotent: skips creation if the VM already exists.
#
# Prereq: set KALI_ISO to a Kali 2025.x installer ISO path.
# Design ref: §2.3, §10.1, §12 V1.
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

require_cmd VBoxManage
[ -n "$KALI_ISO" ] || die "KALI_ISO is unset — point it at a Kali 2025.x ISO"
[ -f "$KALI_ISO" ] || die "KALI_ISO not found: $KALI_ISO"

if vm_exists "$ATTACKER_VM"; then
    log "VM '$ATTACKER_VM' already exists — skipping creation (idempotent)."
else
    log "Creating VM '$ATTACKER_VM'..."
    VBoxManage createvm --name "$ATTACKER_VM" --ostype Debian_64 --register
    VBoxManage modifyvm "$ATTACKER_VM" \
        --memory "$ATTACKER_RAM_MB" --cpus "$ATTACKER_CPUS" \
        --rtcuseutc on --firmware efi

    local_disk="$(VBoxManage list systemproperties | awk -F': *' \
        '/Default machine folder/{print $2}')/$ATTACKER_VM/$ATTACKER_VM.vdi"
    if [ ! -f "$local_disk" ]; then
        log "Creating disk ($ATTACKER_DISK_MB MB)..."
        VBoxManage createmedium disk --filename "$local_disk" \
            --size "$ATTACKER_DISK_MB" --format VDI
    fi
    VBoxManage storagectl "$ATTACKER_VM" --name SATA --add sata --controller IntelAhci
    VBoxManage storageattach "$ATTACKER_VM" --storagectl SATA \
        --port 0 --device 0 --type hdd --medium "$local_disk"
fi

log "Attaching Kali ISO: $KALI_ISO"
VBoxManage storagectl "$ATTACKER_VM" --name IDE --add ide 2>/dev/null || true
VBoxManage storageattach "$ATTACKER_VM" --storagectl IDE \
    --port 0 --device 0 --type dvddrive --medium "$KALI_ISO"
VBoxManage modifyvm "$ATTACKER_VM" --boot1 dvd --boot2 disk

log "Done. Next: run 02_configure_network.sh, then start the VM and"
log "complete the Kali install interactively (or via your preseed)."
log "  VBoxManage startvm '$ATTACKER_VM'"
