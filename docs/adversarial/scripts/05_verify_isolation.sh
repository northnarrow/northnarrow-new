#!/usr/bin/env bash
# Tappa 10.7 V1 — pre-attack isolation validation (the C2-containment gate).
#
# RUNS ON: the VirtualBox host (NIC-config checks) — and prints the
# in-guest checks the operator runs inside each VM. MUST pass before any
# attack run: a leaked NAT adapter would let a C2 implant reach the real
# internet (§2.1).
#
# Exit non-zero if any host-side isolation check fails.
# Design ref: §2.1, §6.
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

require_cmd VBoxManage
fail=0

check_no_nat() {
    local vm="$1"
    vm_exists "$vm" || { warn "VM '$vm' missing"; fail=1; return; }
    # Any NIC of type 'nat' is a containment breach for an isolated run.
    if VBoxManage showvminfo "$vm" --machinereadable | grep -qiE '^nic[0-9]+="nat"'; then
        warn "ISOLATION BREACH: '$vm' has a NAT adapter attached"
        fail=1
    else
        log "OK: '$vm' has no NAT adapter"
    fi
}

check_on_intnet() {
    local vm="$1"
    vm_exists "$vm" || { warn "VM '$vm' missing"; fail=1; return; }
    if VBoxManage showvminfo "$vm" --machinereadable \
        | grep -qE "^intnet${INTNET_NIC}=\"${INTNET}\""; then
        log "OK: '$vm' NIC$INTNET_NIC on intnet '$INTNET'"
    else
        warn "'$vm' is NOT on intnet '$INTNET' (NIC$INTNET_NIC)"
        fail=1
    fi
}

log "=== Host-side isolation checks ==="
check_no_nat "$ATTACKER_VM"
check_no_nat "$TARGET_VM"
check_on_intnet "$ATTACKER_VM"
check_on_intnet "$TARGET_VM"

cat <<EOF

=== In-guest checks (run manually inside each VM) ===
  On TARGET ($TARGET_VM) — internet MUST be unreachable:
    ! ping -c1 -W2 1.1.1.1   # expect: 100% packet loss
    ! curl -sS --max-time 3 https://example.com   # expect: failure
  Attacker <-> target reachability over intnet (expect success):
    kalidev:  ping -c1 -W2 $TARGET_IP
    target :  ping -c1 -W2 $ATTACKER_IP
EOF

if [ "$fail" -ne 0 ]; then
    die "isolation checks FAILED — do not start attack runs"
fi
log "Host-side isolation checks PASSED."
