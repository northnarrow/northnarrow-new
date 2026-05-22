#!/usr/bin/env bash
# Tappa 10.7 V1 — configure the isolated adversarial network.
#
# RUNS ON: the VirtualBox host.
# Wires both VMs onto the `intnet-adversarial` Internal Network (NIC
# slot $INTNET_NIC) and manages the NAT-only-during-provisioning
# lifecycle (§2.1): NAT lives on slot $NAT_NIC and is attached ONLY
# while provisioning the attacker, then detached before isolated runs.
#
# Usage:
#   02_configure_network.sh intnet              # both VMs onto intnet (default)
#   02_configure_network.sh nat-on   attacker   # provisioning: NAT on Kali
#   02_configure_network.sh nat-off  attacker   # ARM: detach NAT (isolate)
#   02_configure_network.sh nat-off  target     # target NEVER keeps NAT
# Design ref: §2.1, §2.2, §13 (cross-cutting network note).
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

require_cmd VBoxManage

attach_intnet() {
    local vm="$1" ip="$2"
    vm_exists "$vm" || die "VM '$vm' does not exist — run 01 / 03 first"
    log "Attaching '$vm' NIC$INTNET_NIC to intnet '$INTNET' (static $ip/$INTNET_CIDR in-guest)"
    VBoxManage modifyvm "$vm" \
        --"nic${INTNET_NIC}" intnet \
        --"intnet${INTNET_NIC}" "$INTNET" \
        --"cableconnected${INTNET_NIC}" on
    # Static addressing is applied in-guest (no DHCP on intnet); emit the
    # netplan snippet the operator drops on the guest.
    cat <<EOF
  # in-guest ($vm): /etc/netplan/99-intnet.yaml
  network: {version: 2, ethernets: {eth$((INTNET_NIC-1)): {addresses: [$ip/$INTNET_CIDR]}}}
EOF
}

nat_set() {
    local state="$1" who="$2" vm
    case "$who" in
        attacker) vm="$ATTACKER_VM" ;;
        target)   vm="$TARGET_VM" ;;
        *) die "unknown target '$who' (expected: attacker|target)" ;;
    esac
    vm_exists "$vm" || die "VM '$vm' does not exist"
    if [ "$state" = on ]; then
        [ "$who" = target ] && die "refusing: the target VM must NEVER have NAT (§2.1)"
        log "Provisioning NAT ON: '$vm' NIC$NAT_NIC → nat"
        VBoxManage modifyvm "$vm" --"nic${NAT_NIC}" nat --"cableconnected${NAT_NIC}" on
    else
        log "Isolating: '$vm' NIC$NAT_NIC → none (NAT detached)"
        VBoxManage modifyvm "$vm" --"nic${NAT_NIC}" none
    fi
}

case "${1:-intnet}" in
    intnet)
        attach_intnet "$ATTACKER_VM" "$ATTACKER_IP"
        attach_intnet "$TARGET_VM"   "$TARGET_IP"
        # Target is isolated from the start.
        nat_set off target
        ;;
    nat-on)  nat_set on  "${2:?usage: nat-on attacker}" ;;
    nat-off) nat_set off "${2:?usage: nat-off attacker|target}" ;;
    *) die "usage: $0 [intnet|nat-on <who>|nat-off <who>]" ;;
esac
log "Network step complete."
