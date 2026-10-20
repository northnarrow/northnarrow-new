#!/usr/bin/env bash
# Exploit post-condition guard — lab check (lab PR 219). LAB GUESTS ONLY:
# it restarts the agent inside a trusted-installer window and, for the
# injection cases, needs an agent built with `--features debug-trigger`.
#
# Nothing here changes a credential, a namespace or a root of anyone: the
# positive cases use the guard's debug-build fault injection (a process
# named nn-epg-probe: its getppid() exit in strict, its first use point —
# capable(), exec — in lite, is reported as an anomaly marked injected).
# What they verify is everything after the kernel's comparison: the ring
# record, NN-L-EPG-001 with the mode and the point that caught it, the
# signed detection, the posture trigger, and in enforce the SIGKILL
# delivered before the return to user mode (lite: and the use refused).
#
# Run as root on the guest, through a TTY wrapper (R009 kills a root script
# run from a home directory without one):
#   script -qec "sudo LAB_USER=nn deploy/lab/epg/epg-check.sh <case>" /dev/null </dev/null
#
# Cases:
#   mode lite|strict|off [detect|enforce]
#                             restart the agent with NN_EXPLOIT_GUARD=<variant>,
#                             NN_EXPLOIT_GUARD_RESPONSE=<response> (default detect)
#                             and NN_EPG_INJECT_COMM=nn-epg-probe (runtime drop-in)
#   negative                  the negative suite: legitimate transitions, zero records
#   inject getppid|capable|exec detect|enforce
#                             getppid in strict, capable / exec in lite: detect = the
#                             probe survives, one injected record, recorded only;
#                             enforce = killed before it prints, record says so.
#                             capable: an unprivileged capable() is refused by
#                             commoncap before the BPF LSM hook runs, so the probe
#                             asks for a capability it holds in a user namespace of
#                             its own; where that is refused before the hook too
#                             (no unprivileged user namespaces, AppArmor's
#                             restriction of them) the case is a SKIP, not a PASS
#   status                    nn-admin status (signed telemetry): the guard's line
#   bench [N]                 getppid / rdzero ns per call, as the lab user and as root
#   cleanup                   remove the drop-in, restart the agent in its installed mode
set -uo pipefail

LAB_USER=${LAB_USER:-nn}
HERE=$(cd "$(dirname "$0")" && pwd)
LIB="$HERE/../lib/lab-records.py"
AGENT_EXE=${AGENT_EXE:-/usr/local/bin/northnarrow-agent}
NNADMIN=$(dirname "$AGENT_EXE")/nn-admin
KEY=${ADMIN_KEY:-/root/northnarrow-admin.key}
[[ -r "$KEY" ]] || KEY=/etc/northnarrow/admin.key
DROPIN_DIR=/run/systemd/system/northnarrow-agent.service.d
DROPIN="$DROPIN_DIR/90-epg-lab.conf"
DETECTIONS=/var/lib/northnarrow/detections/detections.jsonl
# The probe and the benchmark run from a root-owned directory outside the
# staging locations: from /var/tmp, /tmp or /dev/shm the rules R003 / R001 /
# R002 (which predate the guard) would kill them at their exec. The lab
# user's benchmark files go to a directory of its own (nn-bench refuses a
# work directory that is not its user's, closed to others).
WORK=$(mktemp -d /opt/nn-epg.XXXXXXXX)
UWORK=$(runuser -u "$LAB_USER" -- mktemp -d /tmp/nn-epg-bench.XXXXXXXX)
trap 'rm -rf "$WORK" "$UWORK"' EXIT
chmod 0755 "$WORK"
PROBE="$WORK/epg-probe"
BENCH="$WORK/nn-bench"

fail=0
pass() { echo "PASS $*"; }
bad() { echo "FAIL $*"; fail=1; }
as_user() { runuser -u "$LAB_USER" -- "$@"; }

[[ $(id -u) -eq 0 ]] || { echo "run as root (on the lab guest)"; exit 2; }
id "$LAB_USER" >/dev/null 2>&1 || { echo "no lab user $LAB_USER"; exit 2; }

build_tools() {
    cc -O2 -o "$PROBE" "$HERE/epg-probe.c" || { echo "cc epg-probe failed"; exit 2; }
    cc -O2 -o "$BENCH" "$HERE/../overhead/nn-bench.c" || { echo "cc nn-bench failed"; exit 2; }
    chmod 0755 "$PROBE" "$BENCH"
}

# Journal entries of the agent's own stdout, at ERROR, whose message starts
# with the guard's line (lab-records.py: trusted journald fields only).
guard_lines_since() {
    journalctl --namespace=northnarrow -u northnarrow-agent -o json --since "@$1" 2>/dev/null \
        | python3 -I "$LIB" journal northnarrow-agent.service - ERROR "EXPLOIT POST-CONDITION"
}
count_guard_lines_since() { guard_lines_since "$1" | grep -c "EXPLOIT POST-CONDITION" || true; }

det_lines() { wc -l < "$DETECTIONS" 2>/dev/null || echo 0; }
# Signed detection rows after line $1 that name a guard rule.
epg_records_after() { tail -n +"$(( $1 + 1 ))" "$DETECTIONS" 2>/dev/null | grep -E 'NN-L-EPG-00[12]' || true; }
# The `response` of each signed NN-L-EPG-001 record after line $1 whose
# principal is the probe (comm nn-epg-probe, the injection's name), one per
# line. The record stores no reasoning — "LAB INJECTION" is only in the
# journal's VERDICT line — so the probe is told by the fields the record
# keeps: rule id, principal comm, and the response, which names the variant,
# the response mode and the point that caught it.
probe_responses_after() {
    tail -n +"$(( $1 + 1 ))" "$DETECTIONS" 2>/dev/null | python3 -I -c '
import json, sys
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if not (r.get("rule_id") or "").startswith("NN-L-EPG-001"):
        continue
    if (r.get("principal") or {}).get("comm") != "nn-epg-probe":
        continue
    print(r.get("response") or "")
'
}

wait_attached() {
    local since=$1 i
    for i in $(seq 1 60); do
        if journalctl --namespace=northnarrow -u northnarrow-agent -o json --since "@$since" 2>/dev/null \
            | python3 -I "$LIB" journal northnarrow-agent.service - INFO "exploit post-condition guard attached" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# The unit refuses `systemctl restart` (RefuseManualStop, external audit
# EBPF-001): inside the signed trusted-installer window the caller opened,
# SIGTERM, and the watchdog starts the agent again with the unit's current
# environment (deploy/lab/malsim/exec-check.sh restarts it the same way).
restart_agent() {
    local old new i
    old=$(cat /run/northnarrow/agent.pid 2>/dev/null)
    systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 40); do
        sleep 1
        new=$(cat /run/northnarrow/agent.pid 2>/dev/null)
        if [[ -n $new && $new != "$old" ]] && kill -0 "$new" 2>/dev/null; then
            return 0
        fi
    done
    systemctl start northnarrow-agent
}

set_mode() {
    local mode=$1 response=${2:-detect} since
    since=$(date +%s)
    "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 300 >/dev/null 2>&1 \
        || { echo "trusted-installer-grant failed (key $KEY)"; exit 2; }
    mkdir -p "$DROPIN_DIR"
    printf '[Service]\nEnvironment=NN_EXPLOIT_GUARD=%s\nEnvironment=NN_EXPLOIT_GUARD_RESPONSE=%s\nEnvironment=NN_EPG_INJECT_COMM=nn-epg-probe\n' \
        "$mode" "$response" > "$DROPIN"
    systemctl daemon-reload
    restart_agent
    if [[ $mode == off ]]; then
        sleep 5
        echo "mode off (guard not attached; a signed subsystem_degraded records it)"
        return 0
    fi
    if wait_attached "$since"; then
        echo "mode $mode $response: guard attached"
    else
        echo "mode $mode $response: guard NOT attached within 60 s — journalctl --namespace=northnarrow -u northnarrow-agent"
        exit 1
    fi
    sleep 2
}

negative() {
    # negative suite: legitimate privilege, namespace and root transitions.
    # Every one must leave zero guard records.
    local since lines0 g
    since=$(date +%s)
    lines0=$(det_lines)
    g=$(id -gn "$LAB_USER")
    run() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "ran  $what"; else echo "skip $what (exit $?)"; fi; }
    if as_user sudo -n true 2>/dev/null; then
        run "sudo (user → root, setuid exec)" as_user sudo -n true
        run "sudo -u nobody" as_user sudo -n -u nobody true
    else
        echo "skip sudo (no NOPASSWD sudo for $LAB_USER)"
    fi
    run "su root → user" su -s /bin/sh -c true "$LAB_USER"
    run "passwd -S (setuid exec)" as_user passwd -S "$LAB_USER"
    run "sg (newgrp's group switch)" as_user sg "$g" -c true
    command -v newgrp >/dev/null && run "newgrp" as_user sh -c "echo true | newgrp $g"
    run "setpriv --no-new-privs (user)" as_user setpriv --no-new-privs --inh-caps=-all true
    run "setpriv --reuid (root → user)" setpriv --reuid="$LAB_USER" --regid="$g" --init-groups true
    command -v capsh >/dev/null && run "capsh --print (user)" as_user capsh --print
    command -v capsh >/dev/null && run "capsh --drop (root)" capsh --drop=cap_net_raw -- -c true
    run "unshare -U" as_user unshare -U true
    run "unshare -r" as_user unshare -r id -u
    run "unshare -rm + tmpfs mount" as_user unshare -rm sh -c 'mount -t tmpfs none /mnt && umount /mnt'
    run "unshare -rpf --mount-proc" as_user unshare -rpf --mount-proc true
    run "unshare -rm + chroot" as_user unshare -rm chroot / true
    if command -v podman >/dev/null && as_user podman image exists docker.io/library/alpine 2>/dev/null; then
        run "podman run (rootless)" as_user podman run --rm docker.io/library/alpine true
    else
        echo "skip podman (not installed, or no alpine image for $LAB_USER: podman pull docker.io/library/alpine)"
    fi
    if command -v docker >/dev/null && docker image inspect alpine >/dev/null 2>&1; then
        run "docker run (rootful)" docker run --rm alpine true
    else
        echo "skip docker (not installed, or no alpine image)"
    fi
    run "systemd-run --uid (PID 1 → user)" systemd-run --quiet --wait --pipe --uid="$LAB_USER" true
    if [[ -d /etc/cron.d ]] && systemctl is-active --quiet cron 2>/dev/null; then
        local mark="$WORK/cron.ok" i
        echo "* * * * * $LAB_USER touch $mark" > /etc/cron.d/nn-epg-check
        for i in $(seq 1 75); do [[ -e $mark ]] && break; sleep 1; done
        rm -f /etc/cron.d/nn-epg-check
        [[ -e $mark ]] && echo "ran  cron job as $LAB_USER" || echo "skip cron (job did not run in 75 s)"
    else
        echo "skip cron (no cron service)"
    fi
    sleep 3
    local j r
    j=$(count_guard_lines_since "$since")
    r=$(epg_records_after "$lines0" | wc -l)
    if [[ $j -eq 0 && $r -eq 0 ]]; then
        pass "negative suite: zero guard journal lines, zero NN-L-EPG records"
    else
        bad "negative suite: $j guard journal line(s), $r NN-L-EPG record(s) — false positive(s):"
        guard_lines_since "$since" | head -20
        epg_records_after "$lines0" | head -5 | cut -c1-400
    fi
}

inject() {
    # injected anomaly: <what> = getppid (strict) | capable | exec (lite)
    local what=$1 want=$2 since lines0 out rc point marker
    case $what in
        # point: an extended regex (a capability check may come before
        # bprm_check_security in an exec: still the first use)
        getppid) point="sys_exit"; marker="alive-after-getppid" ;;
        capable) point="capable\\(\\)"; marker="alive-after-capable" ;;
        exec) point="(exec|capable\\(\\))"; marker="alive-after-exec" ;;
        *) echo "inject getppid|capable|exec detect|enforce"; exit 2 ;;
    esac
    since=$(date +%s)
    lines0=$(det_lines)
    out=$(as_user "$PROBE" "$what" 2>&1)
    rc=$?
    sleep 3
    if [[ $what == capable && $rc -eq 3 ]]; then
        echo "SKIP $what $want: the probe's capability check was refused before the BPF LSM hook ([$out]) — nothing to inject at"
        return 0
    fi
    local rec
    rec=$(probe_responses_after "$lines0")
    case $want in
        detect)
            [[ $rc -eq 0 && $out == *"$marker"* ]] \
                && pass "$what detect: the probe continued in user mode" \
                || bad "$what detect: probe rc=$rc output=[$out]"
            # the point is followed by its hook when it has one:
            # "caught at exec (bprm_check_security))"
            if grep -qE "^recorded only \(exploit guard [a-z]+, detect, caught at $point" <<<"$rec"; then
                pass "$what detect: signed NN-L-EPG-001 record of nn-epg-probe, recorded only, caught at $point"
            else
                bad "$what detect: no recorded-only NN-L-EPG-001 record of nn-epg-probe caught at $point"
                head -c 600 <<<"$rec"; echo
            fi
            ;;
        enforce)
            [[ $rc -eq 137 && $out != *"$marker"* ]] \
                && pass "$what enforce: killed (137) before it could print in user mode" \
                || bad "$what enforce: probe rc=$rc output=[$out]"
            local want_resp="killed in kernel"
            [[ $what != getppid ]] && want_resp="refused \\(-EPERM\\) and killed in kernel at $point"
            if grep -qE "^$want_resp" <<<"$rec"; then
                pass "$what enforce: signed NN-L-EPG-001 record of nn-epg-probe: $want_resp"
            else
                bad "$what enforce: no NN-L-EPG-001 record of nn-epg-probe saying \"$want_resp\""
                head -c 600 <<<"$rec"; echo
            fi
            ;;
        *) echo "inject <what> detect|enforce"; exit 2 ;;
    esac
    [[ $(count_guard_lines_since "$since") -ge 1 ]] \
        && pass "$what $want: journal line EXPLOIT POST-CONDITION" \
        || bad "$what $want: no journal line"
}

status() {
    "$NNADMIN" status --key "$KEY" 2>&1 | grep -E "^exploit guard|^response mode" \
        || bad "status: no exploit guard line (agent predates the guard?)"
}

bench() {
    local n=${1:-5000000} m who
    for who in "$LAB_USER" root; do
        for m in getppid rdzero; do
            local best=0 r ops
            for r in 1 2 3; do
                if [[ $who == root ]]; then
                    ops=$("$BENCH" "$m" "$n" "$WORK/bench-root" | awk '{print $2}')
                else
                    ops=$(as_user "$BENCH" "$m" "$n" "$UWORK/bench" | awk '{print $2}')
                fi
                (( ops > best )) && best=$ops
            done
            awk -v w="$who" -v m="$m" -v o="$best" 'BEGIN { printf "bench %-6s %-8s %10.1f ns/call (best of 3, %d ops/s)\n", w, m, 1e9 / o, o }'
        done
    done
}

cleanup() {
    "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 300 >/dev/null 2>&1 || true
    rm -f "$DROPIN"
    systemctl daemon-reload
    restart_agent
    echo "drop-in removed, agent restarted in its installed mode"
}

case ${1:-} in
    mode) set_mode "${2:?lite|strict|off}" "${3:-detect}" ;;
    negative) build_tools; negative ;;
    inject) build_tools; inject "${2:?getppid|capable|exec}" "${3:?detect|enforce}" ;;
    status) status ;;
    bench) build_tools; bench "${2:-}" ;;
    cleanup) cleanup ;;
    *) sed -n '2,38p' "$0"; exit 2 ;;
esac
exit $fail
