#!/usr/bin/env bash
# Lot 290 — foreign BPF (`nn-lab.sh foreign-bpf-check`; run by the lab user
# from the synced tree, sudo inside, the lab key with the trusted-installer
# role). On a LAB GUEST ONLY.
#
#  F1  the cross-view runs: its status file (/run/northnarrow/bpf-foreign)
#      names the host's foreign programs; the start's baseline signed;
#  F2  a kprobe program calling bpf_probe_write_user, loaded outside a
#      window: refused (EPERM), signed bpf_prog_type High; inside a window
#      loaded;
#  F3  bpftrace outside a window: refused (bpf_prog_type); inside a window:
#      runs; with a signed `bpf-loader-allow <bpftrace> kprobe,tracing`:
#      runs outside a window, each type's load signed bpf_prog_opt_out (Low);
#  F4  (the guard enforcing: NN_BPF_DEFENSE_ENFORCE=1) the agent's objects
#      off limits outside a window: BPF_MAP_GET_FD_BY_ID of the tracker's
#      map (read-write and read-only), BPF_PROG_GET_FD_BY_ID of one of the
#      agent's programs, BPF_OBJ_GET of the tracker map's pin and of the same
#      pin through a bind mount of the bpffs: EPERM, signed bpf_handle;
#      `bpftool prog show` measured;
#  F5  the configuration maps frozen (BPF_DEFENSE_MODE, OWN_EXE_INODES,
#      OWN_PIN_NAMES, SYSCTL_KERNEL_JUDGE, DNS_EXEMPT_UIDS when loaded);
#  F6  the cross-view's gap: inside a window the agent ended by a signal, a
#      kprobe and a socket-filter program loaded and pinned while no agent
#      runs, the agent started: both signed bpf_baseline at its start (the
#      kprobe High, the filter Low);
#  F7  systemd's BPF unit features (IPAddressDeny, DevicePolicy,
#      RestrictFileSystems, RestrictNetworkInterfaces, SocketBindDeny) on a
#      transient unit: it runs, no load refused;
#  F8  R011: a plain `modprobe dummy` by root recorded Low.
# FOREIGN_BPF_ONLY="F2 F4" runs a subset (the 22.04 round).
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
STATUS=/run/northnarrow/bpf-foreign
PROBE="python3 -I $HERE/bpf-probe.py"
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
ONLY=${FOREIGN_BPF_ONLY:-}
[[ -n $ONLY ]] || ONLY="F1 F2 F3 F4 F5 F6 F7 F8"
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
measure() { printf 'MEASURE %s\n' "$*"; }
want() { [[ " $ONLY " == *" $1 "* ]]; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null; }
recs() { since "$DET" "$1" | grep "\"operation\":\"$2\""; }
count() { recs "$1" "$2" | wc -l; }
sev_of() { recs "$1" "$2" | grep -o '"severity":"[A-Za-z]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ' '; }
WIN_END=0
window() { WIN_END=$(( $(date +%s) + ${1:-60} )); sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs "${1:-60}" >/dev/null 2>&1; }
no_window() { while (( $(date +%s) <= WIN_END + 2 )); do sleep 1; done; }
agent_pid() { sudo cat /run/northnarrow/agent.pid 2>/dev/null; }
restart_agent() {
    local old new i
    window 300 || { bad "trusted-installer-grant"; return 1; }
    old=$(agent_pid)
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 60); do
        sleep 1
        new=$(agent_pid)
        [[ -n $new && $new != "$old" ]] && sudo kill -0 "$new" 2>/dev/null && { sleep 12; WIN_END=0; return 0; }
    done
    sudo systemctl start northnarrow-agent; sleep 12; WIN_END=0
}
echo "nn-admin: $NNADMIN  key: $KEY  kernel $(uname -r)"
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 12; }

if want F1; then
    echo "== F1. the cross-view's status file"
    for i in $(seq 1 30); do sudo test -s "$STATUS" && sudo grep -q ' baseline\| seen\| pending' "$STATUS" 2>/dev/null && break; sleep 1; done
    if sudo test -s "$STATUS"; then
        sudo head -1 "$STATUS" | sed 's/^/    /'
        measure "F1 foreign objects: $(sudo grep -cE '^(prog|link) ' "$STATUS"); by state: $(sudo awk '/^(prog|link) /{print $7}' "$STATUS" | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
        sudo grep -E '^(prog|link) ' "$STATUS" | head -40 | sed 's/^/    /'
        pass "F1 the cross-view writes its status file"
    else
        bad "F1 no status file $STATUS"
    fi
    measure "F1 signed baseline at this start: $(sudo grep -c '"operation":"bpf_baseline"' "$DET" 2>/dev/null) records; severities: $(sudo grep '"operation":"bpf_baseline"' "$DET" | grep -o '"severity":"[A-Za-z]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
fi

if want F2; then
    echo "== F2. a kprobe program with bpf_probe_write_user"
    no_window
    n0=$(lines "$DET")
    out=$(sudo $PROBE load-kprobe-write-user --name k290_wu)
    [[ $out == "ERR EPERM"* ]] && pass "F2 refused outside a window ($out)" || bad "F2 outside a window: $out"
    sleep 2
    (( $(count "$n0" bpf_prog_type) >= 1 )) && pass "F2 signed bpf_prog_type ($(sev_of "$n0" bpf_prog_type))" || bad "F2 no bpf_prog_type record"
    recs "$n0" bpf_prog_type | head -1 | grep -o '"reasoning":"[^"]*' | cut -c1-260 | sed 's/^/    /'
    window 60
    out=$(sudo $PROBE load-kprobe-write-user --name k290_wu)
    [[ $out == OK* ]] && pass "F2 loaded inside a window ($out)" || bad "F2 inside a window: $out"
    no_window
fi

if want F3; then
    echo "== F3. bpftrace"
    BTI=0
    command -v bpftrace >/dev/null || { sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpftrace >/dev/null 2>&1 && BTI=1; }
    BT=$(readlink -f "$(command -v bpftrace)")
    echo "    bpftrace: $BT (installed by this check: $BTI)"
    no_window
    n0=$(lines "$DET")
    o=$(sudo timeout 30 bpftrace -e 'kprobe:do_nanosleep { printf("k290-hit\n"); exit(); }' -c '/bin/sleep 0.2' 2>&1); rc=$?
    [[ $rc -ne 0 && $o != *k290-hit* ]] && pass "F3 bpftrace refused outside a window (rc $rc: $(echo "$o" | grep -m1 -iE 'permit|error' | cut -c1-120))" || bad "F3 bpftrace ran outside a window (rc $rc)"
    sleep 2
    (( $(count "$n0" bpf_prog_type) >= 1 )) && pass "F3 signed bpf_prog_type for bpftrace ($(recs "$n0" bpf_prog_type | grep -c bpftrace) naming it)" || bad "F3 no record"
    window 120
    o=$(sudo timeout 60 bpftrace -e 'kprobe:do_nanosleep { printf("k290-hit\n"); exit(); }' -c '/bin/sleep 0.2' 2>&1); rc=$?
    [[ $o == *k290-hit* ]] && pass "F3 bpftrace runs inside a window" || bad "F3 inside a window (rc $rc): $(echo "$o" | tail -2 | tr '\n' ' ')"
    no_window
    # the signed per-loader opt-out
    printf 'bpf-loader-allow %s kprobe,tracing\n' "$BT" > /tmp/k290-rp.local
    sudo "$NNADMIN" policy set --file /tmp/k290-rp.local --key "$KEY" 2>&1 | tail -1 | sed 's/^/    /'
    n0=$(lines "$DET")
    o=$(sudo timeout 60 bpftrace -e 'kprobe:do_nanosleep { printf("k290-hit\n"); exit(); }' -c '/bin/sleep 0.2' 2>&1); rc=$?
    [[ $o == *k290-hit* ]] && pass "F3 bpftrace runs outside a window under the signed opt-out" || bad "F3 opt-out (rc $rc): $(echo "$o" | tail -2 | tr '\n' ' ')"
    sleep 2
    (( $(count "$n0" bpf_prog_opt_out) >= 1 )) && pass "F3 signed bpf_prog_opt_out ($(sev_of "$n0" bpf_prog_opt_out))" || bad "F3 no bpf_prog_opt_out record"
    (( $(count "$n0" bpf_prog_type) == 0 )) && pass "F3 nothing refused under the opt-out" || bad "F3 $(count "$n0" bpf_prog_type) refused under the opt-out"
    o=$(sudo $PROBE load-kprobe-write-user --name k290_wu2)
    [[ $o == "ERR EPERM"* ]] && pass "F3 another loader still refused under bpftrace's opt-out" || bad "F3 another loader: $o"
    # put back: no directive, then the files removed inside a window
    printf '# no directive\n' > /tmp/k290-rp-empty.local
    sudo "$NNADMIN" policy set --file /tmp/k290-rp-empty.local --key "$KEY" >/dev/null 2>&1
    window 30
    sudo rm -f /etc/northnarrow/rule-policy.local /etc/northnarrow/rule-policy.local.sig /tmp/k290-rp.local /tmp/k290-rp-empty.local
    no_window
    o=$(sudo timeout 30 bpftrace -e 'kprobe:do_nanosleep { printf("k290-hit\n"); exit(); }' -c '/bin/sleep 0.2' 2>&1)
    [[ $o != *k290-hit* ]] && pass "F3 the opt-out withdrawn with the policy: refused again" || bad "F3 still allowed after the policy's removal"
    (( BTI )) && sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq bpftrace >/dev/null 2>&1
fi

if want F4; then
    echo "== F4. the agent's objects off limits (the guard enforcing)"
    ENF=0
    if ! sudo grep -qa 'NN_BPF_DEFENSE_ENFORCE=1' "/proc/$(agent_pid)/environ" 2>/dev/null; then
        sudo systemctl set-environment NN_BPF_DEFENSE_ENFORCE=1 && ENF=1 && restart_agent
    fi
    TDIR=$(ls -d /sys/fs/bpf/northnarrow-cgroup-join-v* 2>/dev/null | head -1)
    window 60
    MID=$(sudo bpftool -j map show pinned "$TDIR/CGROUP_JOINED" 2>/dev/null | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)
    PID_=$(sudo awk '$1 ~ /^[0-9]+$/ {print $1; exit}' /run/northnarrow/bpf-own-ids 2>/dev/null)
    echo "    tracker map CGROUP_JOINED id ${MID:-?} ($TDIR), an agent program id ${PID_:-?}"
    o=$(sudo $PROBE map-fd-by-id "$MID")
    [[ $o == OK* ]] && pass "F4 inside a window a handle is given ($o)" || bad "F4 inside a window: $o"
    no_window
    n0=$(lines "$DET")
    for c in "map-fd-by-id $MID" "map-fd-by-id $MID --rdonly" "prog-fd-by-id $PID_" "obj-get $TDIR/CGROUP_JOINED"; do
        o=$(sudo $PROBE $c)
        [[ $o == "ERR EPERM"* ]] && pass "F4 $c: EPERM" || bad "F4 $c: $o"
    done
    sudo mkdir -p /run/k290-bpfbind && sudo mount --bind /sys/fs/bpf /run/k290-bpfbind
    o=$(sudo $PROBE obj-get "/run/k290-bpfbind/${TDIR##*/}/CGROUP_JOINED")
    [[ $o == "ERR EPERM"* ]] && pass "F4 the same pin through a bind mount: EPERM (judged on the map)" || bad "F4 bind mount: $o"
    sudo umount /run/k290-bpfbind; sudo rmdir /run/k290-bpfbind
    sleep 2
    measure "F4 bpf_handle records: $(count "$n0" bpf_handle) ($(sev_of "$n0" bpf_handle))"
    (( $(count "$n0" bpf_handle) >= 5 )) && pass "F4 each refusal signed bpf_handle" || bad "F4 records: $(count "$n0" bpf_handle)"
    n0=$(lines "$DET")
    o=$(sudo bpftool prog show 2>&1); rc=$?
    measure "F4 bpftool prog show outside a window: rc $rc, $(echo "$o" | grep -cE '^[0-9]+: ') programs listed, last line: $(echo "$o" | tail -1 | cut -c1-120)"
    sleep 2
    measure "F4 records of that bpftool run: $(since "$DET" "$n0" | grep -o '"operation":"bpf_[a-z_]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
    if (( ENF )); then sudo systemctl unset-environment NN_BPF_DEFENSE_ENFORCE; restart_agent; fi
fi

if want F5; then
    echo "== F5. the configuration maps frozen"
    window 60
    sudo bpftool -j map show 2>/dev/null | python3 -I -c '
import json, sys
want = {"BPF_DEFENSE_MOD", "OWN_EXE_INODES", "OWN_PIN_NAMES", "SYSCTL_KERNEL_J", "DNS_EXEMPT_UIDS", "NET_CONNECT_DEN", "BTF_OFFSETS", "EXECPOL_CONF", "EXECQ_CONF"}
best = {}
for m in json.load(sys.stdin):
    n = m.get("name")
    if n in want and m["id"] > best.get(n, {"id": -1})["id"]:
        best[n] = m
for n in sorted(want):
    m = best.get(n)
    print("MAP", n, "absent" if m is None else ("frozen" if m.get("frozen") else "NOT-frozen"))
' > /tmp/k290-frozen.txt
    no_window
    sed 's/^/    /' /tmp/k290-frozen.txt
    for n in BPF_DEFENSE_MOD OWN_EXE_INODES OWN_PIN_NAMES SYSCTL_KERNEL_J; do
        grep -q "MAP $n frozen" /tmp/k290-frozen.txt && pass "F5 $n frozen" || bad "F5 $n: $(grep "MAP $n " /tmp/k290-frozen.txt)"
    done
    grep -q "MAP DNS_EXEMPT_UIDS NOT-frozen" /tmp/k290-frozen.txt && bad "F5 DNS_EXEMPT_UIDS not frozen"
    rm -f /tmp/k290-frozen.txt
fi

if want F6; then
    echo "== F6. a program loaded while the agent is stopped (inside a window)"
    window 300
    old=$(agent_pid)
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 100); do sudo kill -0 "$old" 2>/dev/null || break; sleep 0.1; done
    st=$(systemctl is-active northnarrow-agent)
    kp=$(sudo $PROBE load-kprobe-write-user --name k290_gap_kp --pin /sys/fs/bpf/k290-gap/kp)
    sf=$(sudo $PROBE load-socket-filter --name k290_gap_sf --pin /sys/fs/bpf/k290-gap/sf)
    echo "    agent $st when loaded: kprobe $kp; socket filter $sf"
    n0=$(lines "$DET")
    for i in $(seq 1 30); do new=$(agent_pid); [[ -n $new && $new != "$old" ]] && sudo kill -0 "$new" 2>/dev/null && break; sleep 1; done
    [[ -n ${new:-} && $new != "$old" ]] || sudo systemctl start northnarrow-agent
    sleep 25
    WIN_END=0
    b=$(recs "$n0" bpf_baseline)
    echo "$b" | grep -q 'k290_gap_kp' && pass "F6 the kprobe loaded in the gap signed at the start ($(echo "$b" | grep 'k290_gap_kp' | grep -o '"severity":"[A-Za-z]*"' | head -1))" || bad "F6 no baseline record of k290_gap_kp"
    echo "$b" | grep -q 'k290_gap_sf' && pass "F6 the socket filter signed at the start ($(echo "$b" | grep 'k290_gap_sf' | grep -o '"severity":"[A-Za-z]*"' | head -1))" || bad "F6 no baseline record of k290_gap_sf"
    echo "$b" | grep 'k290_gap_kp' | grep -o '"reasoning":"[^"]*' | cut -c1-300 | sed 's/^/    /'
    measure "F6 baseline records at this start: $(echo "$b" | grep -c bpf_baseline) ($(sev_of "$n0" bpf_baseline))"
    sudo rm -rf /sys/fs/bpf/k290-gap
    sleep 12
    sudo grep -c 'k290_gap' "$STATUS" >/dev/null 2>&1 && measure "F6 status after the unpin: $(sudo grep -c 'k290_gap' "$STATUS") k290_gap lines"
fi

if want F7; then
    echo "== F7. systemd's BPF unit features"
    n0=$(lines "$DET")
    props=(-p IPAddressDeny=any -p DevicePolicy=closed -p DeviceAllow=/dev/null -p RestrictNetworkInterfaces=lo -p SocketBindDeny=any)
    systemctl show -p Version --value 2>/dev/null | head -1 | sed 's/^/    systemd /'
    o=$(sudo systemd-run --wait --quiet --collect "${props[@]}" -p RestrictFileSystems=ext4 /bin/true 2>&1); rc=$?
    if (( rc != 0 )); then
        echo "    with RestrictFileSystems: rc $rc ($o) — again without it"
        o=$(sudo systemd-run --wait --quiet --collect "${props[@]}" /bin/true 2>&1); rc=$?
    fi
    (( rc == 0 )) && pass "F7 the transient unit ran" || bad "F7 rc $rc: $o"
    sleep 6
    (( $(count "$n0" bpf_prog_type) == 0 )) && pass "F7 no load refused" || bad "F7 refused: $(recs "$n0" bpf_prog_type | grep -o '"comm":"[^"]*' | sort | uniq -c | tr '\n' ' ')"
    measure "F7 loads seen by pid 1 since the start: $(sudo awk '$1=="load" && $4=="pid=1"{print $3}' "$STATUS" | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
fi

if want F8; then
    echo "== F8. R011: a plain modprobe by root"
    n0=$(lines "$DET")
    sudo modprobe dummy; sudo modprobe -r dummy
    sleep 3
    r=$(since "$DET" "$n0" | grep 'R011_KernelModuleTooling')
    measure "F8 R011 records: $(echo "$r" | grep -c R011) ($(echo "$r" | grep -o '"severity":"[A-Za-z]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ' '))"
    [[ -n $r ]] && ! echo "$r" | grep -q '"severity":"High"' && pass "F8 recorded Low, no High" || bad "F8 $(echo "$r" | grep -o '"severity":"[A-Za-z]*"' | tr '\n' ' ')"
fi

echo "== the loaders and types the hook saw since the agent's start"
sudo awk '$1=="load"{c[$3" "$6]++} END{for(k in c) print "    "c[k], k}' "$STATUS" 2>/dev/null | sort -k2
echo "== foreign-bpf-check: $([[ $fail == 0 ]] && echo ALL PASS || echo FAILURES)"
exit $fail
