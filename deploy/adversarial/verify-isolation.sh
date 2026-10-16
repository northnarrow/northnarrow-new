#!/usr/bin/env bash
# Tappa 10.7 — the C2-containment gate of the adversarial range (external
# audit NN-AUD-219, LAB-014). Required before the revert snapshots are taken
# and before any run: a leaked adapter would let a C2 implant reach the
# real internet (design §2.1).
#
#   verify-isolation.sh host       on the VirtualBox host: every adapter of
#                                  both VMs is of an allowed type (target:
#                                  intnet on $INTNET, plus one host-only NIC
#                                  for management when ALLOW_TARGET_HOSTONLY=1;
#                                  attacker: intnet only); then the guest
#                                  probes, through `VBoxManage guestcontrol`
#                                  when GUEST_USER and GUEST_PASSFILE are set
#   verify-isolation.sh guest      inside one guest: no tailscale0 / wg*
#                                  interface, `ip route get 1.1.1.1` fails, a
#                                  TCP connect to a public address times out,
#                                  the intnet peer answers (PEER_IP)
#   verify-isolation.sh snapshot   `host`, then the snapshots (TARGET_SNAPSHOT,
#                                  ATTACKER_SNAPSHOT) — refused unless it passed
#   verify-isolation.sh selftest   the adapter parser on canned showvminfo text
#
# Exit 0 only when every check passed. Guest probes that could not run are a
# FAIL in `host` (run `guest` inside each VM and pass GUEST_PROBES_DONE=1 only
# after both reported PASS).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00_config.sh"

: "${ALLOW_TARGET_HOSTONLY:=1}"   # RANGE_SETUP §5: one host-only NIC for SSH
: "${PUBLIC_PROBE_IP:=1.1.1.1}"

fail=0
pass() { log "  PASS: $*"; }
bad()  { warn "  FAIL: $*"; fail=1; }

# adapters_verdict <role> <showvminfo --machinereadable text>: one line per
# NIC slot that is attached; FAIL lines for a type the role may not have.
# Allowed: none/null; intnet on $INTNET; hostonly for the target when
# ALLOW_TARGET_HOSTONLY=1 (at most one). Anything else — nat, natnetwork,
# bridged, generic, cloud, an intnet of another name — is a breach.
adapters_verdict() {
    local role=$1 info=$2 slot type net hostonly=0 intnet=0 rc=0
    while IFS='=' read -r key val; do
        [[ $key =~ ^nic([0-9]+)$ ]] || continue
        slot=${BASH_REMATCH[1]}; type=${val//\"/}
        case $type in
            none|null) continue ;;
            intnet)
                net=$(grep -E "^intnet${slot}=" <<<"$info" | head -1 | cut -d= -f2 | tr -d '"')
                if [ "$net" = "$INTNET" ]; then
                    echo "OK nic$slot intnet $net"; intnet=$((intnet + 1))
                else
                    echo "BREACH nic$slot intnet '$net' (not $INTNET)"; rc=1
                fi ;;
            hostonly)
                if [ "$role" = target ] && [ "$ALLOW_TARGET_HOSTONLY" = 1 ] && [ "$hostonly" = 0 ]; then
                    echo "OK nic$slot hostonly (management)"; hostonly=1
                else
                    echo "BREACH nic$slot hostonly (not allowed for the $role)"; rc=1
                fi ;;
            *) echo "BREACH nic$slot $type"; rc=1 ;;
        esac
    done <<<"$info"
    [ "$intnet" -ge 1 ] || { echo "BREACH no adapter on intnet $INTNET"; rc=1; }
    return $rc
}

check_vm_adapters() { # role vm
    local role=$1 vm=$2 info out
    if ! info=$(VBoxManage showvminfo "$vm" --machinereadable 2>&1); then
        bad "$vm: showvminfo failed: $info"; return
    fi
    if out=$(adapters_verdict "$role" "$info"); then
        pass "$vm ($role) adapters: $(tr '\n' ';' <<<"$out")"
    else
        bad "$vm ($role) adapters: $(tr '\n' ';' <<<"$out")"
    fi
}

# The in-guest probes, as one shell snippet (run locally or through
# guestcontrol). Prints PASS/FAIL lines, exits non-zero on any FAIL.
GUEST_PROBES='
f=0
if ip -o link show 2>/dev/null | grep -qE ": (tailscale[0-9]*|wg[0-9]*)[:@]"; then echo "FAIL: a tailscale/wg interface is present"; f=1; else echo "PASS: no tailscale/wg interface"; fi
if ip route get PUBLIC_IP >/dev/null 2>&1; then echo "FAIL: a route to PUBLIC_IP exists"; f=1; else echo "PASS: no route to PUBLIC_IP"; fi
if timeout 5 bash -c "exec 3<>/dev/tcp/PUBLIC_IP/443" 2>/dev/null; then echo "FAIL: TCP to PUBLIC_IP:443 connected"; f=1; else echo "PASS: TCP to PUBLIC_IP:443 does not connect"; fi
if [ -n "PEER" ]; then if ping -c1 -W2 PEER >/dev/null 2>&1; then echo "PASS: intnet peer PEER answers"; else echo "FAIL: intnet peer PEER does not answer"; f=1; fi; fi
exit $f'

guest_probes() { # peer
    local s=${GUEST_PROBES//PUBLIC_IP/$PUBLIC_PROBE_IP}
    printf '%s' "${s//PEER/$1}"
}

run_guest_probes_via_guestcontrol() { # vm peer
    local vm=$1 peer=$2 out
    if out=$(VBoxManage guestcontrol "$vm" run --exe /bin/bash --username "$GUEST_USER" \
            --passwordfile "$GUEST_PASSFILE" --wait-stdout --wait-stderr -- -c "$(guest_probes "$peer")" 2>&1); then
        pass "$vm guest probes: $(grep -c '^PASS' <<<"$out") passed"
    else
        bad "$vm guest probes: $(grep -E '^FAIL' <<<"$out" | tr '\n' ';')${out:+ }$(grep -vE '^(PASS|FAIL)' <<<"$out" | head -2 | tr '\n' ' ')"
    fi
}

cmd_host() {
    require_cmd VBoxManage
    log "── C2 containment gate (host) ─────────────────────────────"
    check_vm_adapters target "$TARGET_VM"
    check_vm_adapters attacker "$ATTACKER_VM"
    if [ -n "${GUEST_USER:-}" ] && [ -n "${GUEST_PASSFILE:-}" ]; then
        run_guest_probes_via_guestcontrol "$TARGET_VM" "$ATTACKER_IP"
        run_guest_probes_via_guestcontrol "$ATTACKER_VM" "$TARGET_IP"
    elif [ "${GUEST_PROBES_DONE:-0}" = 1 ]; then
        warn "  guest probes: taken from the operator (GUEST_PROBES_DONE=1 — run 'guest' in both VMs first)"
    else
        bad "guest probes not run: set GUEST_USER + GUEST_PASSFILE (guestcontrol), or run '$0 guest' inside both VMs and re-run with GUEST_PROBES_DONE=1"
    fi
    [ "$fail" = 0 ] && log "── CONTAINMENT GATE PASSED ──" || warn "── CONTAINMENT GATE FAILED: do not snapshot, do not run ──"
    return $fail
}

cmd_guest() {
    local peer=${PEER_IP:-}
    if [ -z "$peer" ]; then
        case "$(ip -o -4 addr show 2>/dev/null)" in
            *" $TARGET_IP/"*) peer=$ATTACKER_IP ;;
            *" $ATTACKER_IP/"*) peer=$TARGET_IP ;;
        esac
    fi
    log "── C2 containment gate (guest $(hostname), peer ${peer:-none}) ──"
    bash -c "$(guest_probes "$peer")"
}

cmd_snapshot() {
    cmd_host || die "the containment gate failed: no snapshot taken"
    VBoxManage snapshot "$TARGET_VM" take "$TARGET_SNAPSHOT" --description "isolated (verify-isolation.sh passed $(date -u +%FT%TZ))" \
        || die "snapshot of $TARGET_VM failed"
    VBoxManage snapshot "$ATTACKER_VM" take "$ATTACKER_SNAPSHOT" --description "isolated (verify-isolation.sh passed $(date -u +%FT%TZ))" \
        || die "snapshot of $ATTACKER_VM failed"
    log "snapshots taken: $TARGET_VM/$TARGET_SNAPSHOT, $ATTACKER_VM/$ATTACKER_SNAPSHOT"
}

cmd_selftest() {
    local n=0 bad_n=0
    t() { n=$((n + 1)); if "$@"; then :; else bad_n=$((bad_n + 1)); echo "  selftest FAIL: ${*: -1}" >&2; fi; }
    expect_ok()   { adapters_verdict "$1" "$2" >/dev/null; }
    expect_fail() { ! adapters_verdict "$1" "$2" >/dev/null; }
    local intnet="nic1=\"none\"
nic2=\"intnet\"
intnet2=\"$INTNET\""
    t expect_ok target "$intnet"
    t expect_ok attacker "$intnet"
    t expect_ok target "$intnet
nic3=\"hostonly\""
    t expect_fail attacker "$intnet
nic3=\"hostonly\""
    t expect_fail target "$intnet
nic1=\"bridged\""
    t expect_fail target "$intnet
nic4=\"nat\""
    t expect_fail attacker "nic1=\"natnetwork\"
$intnet"
    t expect_fail target "nic1=\"none\"
nic2=\"intnet\"
intnet2=\"some-other-net\""
    t expect_fail target "nic1=\"none\""
    t expect_fail target "$intnet
nic3=\"hostonly\"
nic4=\"hostonly\""
    echo "verify-isolation selftest: $n checks, $bad_n failed"
    [ "$bad_n" = 0 ]
}

case "${1:-}" in
    host) cmd_host ;;
    guest) cmd_guest ;;
    snapshot) cmd_snapshot ;;
    selftest) cmd_selftest ;;
    *) sed -n '2,25p' "$0"; exit 2 ;;
esac
