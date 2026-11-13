#!/usr/bin/env bash
# Lot 341 — the host's integrity and the agent's self-protection under
# every response profile (`nn-lab.sh host-deny-check`; run by the lab user
# from the synced tree, sudo inside). On a LAB GUEST ONLY, with an installed
# agent whose BPF guard enforces (`NN_BPF_DEFENSE_ENFORCE=1` in its
# environment, the production default: a lab build observes its own objects
# otherwise).
#
# `alpha` leaves the users' programs alone (no kill, isolation, quarantine,
# exec hold, exec-policy deny, connect deny, exploit-guard response); the
# denies below protect the agent from being blinded, frozen or killed and
# hold under `alpha` as under `enforcing` (the review of #550). A foreign
# tracing BPF load is let through only for a loader the signed policy
# names (`bpf-loader-allow`: install.sh --allow-bpf-tools /
# --allow-bpf-loader), recorded `bpf_prog_opt_out`:
#
#  H0  the install's profile and the policy's bpf-loader-allow lines;
#  H1  a foreign tracing program's load (bpf-probe.py, run by python3: a
#      tracepoint and a kprobe program, never attached): EPERM and a signed
#      bpf_prog_type — loaded, and bpf_prog_opt_out, when python3 is named;
#  H2  bpftrace -e 'tracepoint:syscalls:sys_enter_openat { … }': refused —
#      runs when bpftrace is named;
#  H3  a BCC tool (opensnoop-bpfcc: its interpreter is the loader) or
#      libbpf-tools' opensnoop, else bpf-probe.py's raw_tracepoint loader:
#      refused — runs when its loader is named;
#  H4  a BPF operation on the agent's own maps and programs — BPF_OBJ_GET of
#      PROTECTED_PIDS's pin (read-write and read-only), `bpftool map delete`
#      on it, BPF_PROG_GET_FD_BY_ID of one of its programs: EPERM;
#  H5  a detach of one of the agent's links — BPF_OBJ_GET of a link pin,
#      `bpftool link detach pinned`, BPF_LINK_GET_FD_BY_ID of every link of
#      the host (the agent's refused: no handle, no detach; no foreign link
#      is ever detached): refused, every pin still there, the agent active;
#  H6  `sysctl -w kernel.ftrace_enabled=0` (it would silence the deny hooks'
#      trampolines) and `kprobes/enabled=0`: refused, the values unchanged;
#      then a SIGSTOP to the agent: refused (put back at once if not);
#  H7  a cgroup v1 freezer hierarchy: a move into it (a sleeper of the
#      check's, never the agent) refused on a unified-only host.
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
PROBE="python3 -I $HERE/bpf-probe.py"
ROOT=/sys/fs/bpf/northnarrow
POLICY=/etc/northnarrow/rule-policy.local
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
measure() { printf 'MEASURE %s\n' "$*"; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null; }
recs() { since "$DET" "$1" | grep "\"operation\":\"$2\""; }
count() { recs "$1" "$2" | wc -l; }
agent_pid() { sudo cat /run/northnarrow/agent.pid 2>/dev/null; }
# the files the policy's bpf-loader-allow lines name, resolved as the agent
# resolves them (a symlink followed)
ALLOWED=$(sudo awk '$1 == "bpf-loader-allow" { print $2 }' "$POLICY" 2>/dev/null </dev/null | while read -r p; do readlink -f "$p"; done)
allowed() { local r; r=$(readlink -f "$1" 2>/dev/null) && grep -qxF "$r" <<< "$ALLOWED"; }

APID=$(agent_pid)
[[ -n $APID ]] || { bad "no agent running"; exit 1; }
# the agent's environment is not readable (the ptrace hook refuses root a
# read of /proc/<agent>/environ): its start's own line says how its guard runs
JOURNAL=$(sudo journalctl --namespace=northnarrow -b -u northnarrow-agent --no-pager 2>/dev/null)
GUARD=$(printf '%s\n' "$JOURNAL" | grep -o 'BPF self-defence: own objects registered.*' | tail -1)
[[ $GUARD == *DENIED* ]] \
    || { bad "the agent's BPF guard observes its own objects (NN_BPF_DEFENSE_ENFORCE=1 not in the units' environment): H4/H5 would prove nothing — ${GUARD:0:160}"; exit 1; }
PROFILE=$(sudo python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("profile") or "")' /etc/northnarrow/install-manifest.json 2>/dev/null)
echo "== H0. the agent: pid $APID, install profile ${PROFILE:-?}; bpf-loader-allow: $(echo $ALLOWED)"
[[ -n $PROFILE ]] && pass "H0 the install's profile: $PROFILE" || bad "H0 no profile in the install manifest"
LINKS0=$(sudo sh -c "ls -d $ROOT/link_* 2>/dev/null" | wc -l)

# $1 case, $2 the loader, $3 rc of the load (0: loaded), $4 what it said
expect_load() {
    if allowed "$2"; then
        [[ $3 -eq 0 ]] && pass "$1 loaded: $2 is named by the signed policy" || bad "$1 refused although $2 is named: ${4:0:200}"
    else
        [[ $3 -ne 0 ]] && pass "$1 refused ($(echo "$4" | grep -m1 -iE 'EPERM|permit|error|fail' | cut -c1-120))" || bad "$1 loaded under profile ${PROFILE:-?} with $2 not named"
    fi
}

echo "== H1. a foreign tracing program's load"
PY=$(command -v python3)
n0=$(lines "$DET")
for t in tracepoint kprobe; do
    o=$(sudo $PROBE load-kprobe-write-user --type "$t" --name "k341_hd_${t:0:5}")
    [[ $o == OK* ]]; ran=$?
    expect_load "H1 $t" "$PY" "$ran" "$o"
    sleep 1.2
done
sleep 3
if allowed "$PY"; then
    (( $(count "$n0" bpf_prog_opt_out) >= 1 )) && pass "H1 signed bpf_prog_opt_out ($(count "$n0" bpf_prog_opt_out))" || bad "H1 no bpf_prog_opt_out record"
else
    (( $(count "$n0" bpf_prog_type) >= 2 )) && pass "H1 signed bpf_prog_type refused ($(count "$n0" bpf_prog_type))" || bad "H1 $(count "$n0" bpf_prog_type) refusal records"
fi
recs "$n0" bpf_prog_type | grep -c 'would deny' | grep -qx 0 || bad "H1 a record says 'would deny'"
recs "$n0" bpf_prog_type | grep -o '"response":"[^"]*' | sort | uniq -c | cut -c1-200 | sed 's/^/    /'

echo "== H2. bpftrace"
command -v bpftrace >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpftrace >/dev/null 2>&1 </dev/null
if command -v bpftrace >/dev/null; then
    n0=$(lines "$DET")
    o=$(sudo timeout 30 bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @opens = count(); } interval:s:1 { exit(); }' </dev/null 2>&1); rc=$?
    echo "    bpftrace rc $rc: $(echo "$o" | grep -v '^$' | head -4 | tr '\n' ' ' | cut -c1-240)"
    [[ $rc -eq 0 && $o == *@opens* ]]; ran=$?
    expect_load "H2 bpftrace" "$(command -v bpftrace)" "$ran" "rc $rc $(echo "$o" | tail -2 | tr '\n' ' ')"
    sleep 2
    measure "H2 records: bpf_prog_type $(count "$n0" bpf_prog_type), bpf_prog_opt_out $(count "$n0" bpf_prog_opt_out)"
else
    measure "H2 bpftrace not installable here"
fi

echo "== H3. a BCC or libbpf tool"
TOOL="" LOADER=""
for c in opensnoop-bpfcc /usr/sbin/opensnoop-bpfcc; do command -v "$c" >/dev/null 2>&1 && { TOOL=$(command -v "$c"); break; }; done
if [[ -n $TOOL ]]; then
    read -r LOADER _ < <(head -n1 "$TOOL" | sed -n 's/^#![[:space:]]*//p')
    [[ $LOADER == */env ]] && LOADER=$(command -v "$(head -n1 "$TOOL" | awk '{print $2}')")
elif [[ -x /usr/sbin/opensnoop ]]; then
    TOOL=/usr/sbin/opensnoop LOADER=/usr/sbin/opensnoop
fi
n0=$(lines "$DET")
if [[ -n $TOOL ]]; then
    o=$(sudo timeout -s INT 4 "$TOOL" </dev/null 2>&1); rc=$?
    echo "    $TOOL (loader $LOADER) rc $rc: $(echo "$o" | head -2 | tr '\n' ' ' | cut -c1-160)"
    # a BCC that cannot compile here (Debian's cloud kernel ships no
    # kheaders) never reaches a load: it says nothing about the guard
    if [[ $o == *"Failed to compile BPF module"* ]]; then
        measure "H3 $TOOL cannot compile on this kernel (no kernel headers): bpf-probe.py's raw_tracepoint loader instead"
        TOOL=""
    fi
fi
if [[ -n $TOOL ]]; then
    [[ $rc -eq 0 || $rc -eq 124 || $rc -eq 130 ]] && [[ $o != *"failed to load"* && $o != *"ermission"* && $o != *"Failed"* ]]; ran=$?
    expect_load "H3 $TOOL" "$LOADER" "$ran" "$o"
else
    measure "H3 no BCC or libbpf tool here: bpf-probe.py's raw_tracepoint loader instead"
    o=$(sudo $PROBE load-kprobe-write-user --type raw_tracepoint --name k341_hd_raw)
    [[ $o == OK* ]]; ran=$?
    expect_load "H3 raw_tracepoint" "$PY" "$ran" "$o"
fi
sleep 2
measure "H3 records: bpf_prog_type $(count "$n0" bpf_prog_type), bpf_prog_opt_out $(count "$n0" bpf_prog_opt_out)"

echo "== H4. a BPF operation on the agent's own maps and programs"
n0=$(lines "$DET")
RPIN=$ROOT/PROTECTED_PIDS
PID_=$(sudo awk '$1 ~ /^[0-9]+$/ {print $1; exit}' /run/northnarrow/bpf-own-ids 2>/dev/null)
for c in "obj-get $RPIN" "obj-get $RPIN --rdonly" "prog-fd-by-id ${PID_:-0}"; do
    o=$(sudo $PROBE $c)
    [[ $o == "ERR EPERM"* ]] && pass "H4 $c: EPERM" || bad "H4 $c: $o"
done
# a key no pid has: refused at the map's handle (EPERM), before any lookup
o=$(sudo bpftool map delete pinned "$RPIN" key 1 0 0 0 2>&1); rc=$?
[[ $rc -ne 0 && $o == *"not permitted"* ]] && pass "H4 bpftool map delete on PROTECTED_PIDS refused at its handle ($(echo "$o" | head -1 | cut -c1-100))" || bad "H4 bpftool map delete: rc $rc $(echo "$o" | head -1 | cut -c1-100)"
sleep 2
measure "H4 bpf_handle / bpf_map records: $(count "$n0" bpf_handle) / $(count "$n0" bpf_map)"

echo "== H5. a detach of one of the agent's links"
LPIN=$(sudo sh -c "ls -d $ROOT/link_* 2>/dev/null" | head -1)
if [[ -n $LPIN ]]; then
    o=$(sudo $PROBE obj-get "$LPIN"); [[ $o == "ERR EPERM"* ]] && pass "H5 obj-get $LPIN: EPERM" || bad "H5 obj-get $LPIN: $o"
    o=$(sudo bpftool link detach pinned "$LPIN" 2>&1); rc=$?
    [[ $rc -ne 0 ]] && pass "H5 bpftool link detach pinned $(basename "$LPIN") refused ($(echo "$o" | head -1 | cut -c1-100))" || bad "H5 bpftool link detach went through"
else
    bad "H5 no link pin under $ROOT"
fi
# a handle by id on every link of the host, never a detach (a foreign
# link, systemd's, is given and left alone): the agent's are refused, and
# without a handle there is no BPF_LINK_DETACH
refused=0
for id in $(sudo $PROBE link-ids | sed 's/^OK//'); do
    o=$(sudo $PROBE link-fd-by-id "$id")
    [[ $o == "ERR EPERM"* ]] && refused=$((refused + 1))
done
LINKS1=$(sudo sh -c "ls -d $ROOT/link_* 2>/dev/null" | wc -l)
measure "H5 links refused a handle by id: $refused (the agent pins $LINKS1)"
(( refused >= LINKS1 && LINKS1 > 0 )) && pass "H5 every link of the agent's refused a handle (and its detach)" || bad "H5 $refused refused, $LINKS1 pinned"
[[ $LINKS1 -eq $LINKS0 ]] && pass "H5 every link pin still there ($LINKS1)" || bad "H5 link pins $LINKS0 → $LINKS1"

echo "== H6. the switches that would blind the agent, then a signal to it"
n0=$(lines "$DET")
v0=$(cat /proc/sys/kernel/ftrace_enabled 2>/dev/null)
o=$(sudo timeout 10 sysctl -w kernel.ftrace_enabled=0 </dev/null 2>&1); rc=$?
v1=$(cat /proc/sys/kernel/ftrace_enabled 2>/dev/null)
if [[ $v1 != "$v0" ]]; then
    sudo timeout 10 sysctl -w "kernel.ftrace_enabled=$v0" </dev/null >/dev/null 2>&1
    bad "H6 kernel.ftrace_enabled $v0 → $v1 (put back to $(cat /proc/sys/kernel/ftrace_enabled))"
else
    [[ $rc -ne 0 ]] && pass "H6 sysctl -w kernel.ftrace_enabled=0 refused (rc $rc: $(echo "$o" | head -1 | cut -c1-100)), still $v1" || bad "H6 sysctl rc 0 but the value unchanged ($v1)"
fi
KP=/sys/kernel/debug/kprobes/enabled
if sudo test -e "$KP"; then
    k0=$(sudo cat "$KP" </dev/null)
    sudo timeout 10 sh -c "echo 0 > $KP" </dev/null 2>/dev/null; rc=$?
    k1=$(sudo cat "$KP" </dev/null)
    if [[ $k1 != "$k0" ]]; then
        sudo timeout 10 sh -c "echo $k0 > $KP" </dev/null 2>/dev/null
        bad "H6 kprobes/enabled $k0 → $k1 (put back)"
    else
        [[ $rc -ne 0 ]] && pass "H6 kprobes/enabled=0 refused, still $k1" || bad "H6 kprobes/enabled write rc 0, value $k1"
    fi
else
    measure "H6 no debugfs kprobes/enabled here"
fi
o=$(sudo timeout 10 kill -STOP "$APID" </dev/null 2>&1); rc=$?
st=$(awk '{print $3}' "/proc/$APID/stat" 2>/dev/null)
if [[ $st == T ]]; then
    sudo kill -CONT "$APID" </dev/null 2>/dev/null
    bad "H6 SIGSTOP stopped the agent (continued)"
else
    [[ $rc -ne 0 ]] && pass "H6 SIGSTOP to the agent refused ($(echo "$o" | cut -c1-80)), state $st" || bad "H6 SIGSTOP rc 0, state $st"
fi
sleep 2
measure "H6 records: sysctl $(count "$n0" sysctl), kprobes $(count "$n0" kprobes), signal $(count "$n0" signal)"

echo "== H7. a cgroup v1 freezer hierarchy"
n0=$(lines "$DET")
MNT=/tmp/nn341-v1
sudo mkdir -p "$MNT" </dev/null
if sudo timeout 10 mount -t cgroup -o freezer nn341v1 "$MNT" </dev/null 2>/dev/null; then
    sudo mkdir -p "$MNT/k341" </dev/null 2>/dev/null
    sleep 300 </dev/null >/dev/null 2>&1 &
    SP=$!
    o=$(sudo timeout 10 sh -c "echo $SP > $MNT/k341/cgroup.procs" </dev/null 2>&1); rc=$?
    in=$(grep -c "^$SP\$" "$MNT/k341/cgroup.procs" 2>/dev/null)
    [[ $rc -ne 0 && $in == 0 ]] && pass "H7 a move into the v1 freezer refused ($(echo "$o" | head -1 | cut -c1-100))" || bad "H7 the move went through (rc $rc, in $in)"
    kill "$SP" 2>/dev/null
    sleep 1
    sudo rmdir "$MNT/k341" </dev/null 2>/dev/null
    sudo umount "$MNT" </dev/null 2>/dev/null
else
    measure "H7 the v1 freezer hierarchy cannot be mounted here"
fi
sudo rmdir "$MNT" </dev/null 2>/dev/null
sleep 2
measure "H7 records: cgroup_v1 $(count "$n0" cgroup_v1)"
systemctl is-active --quiet northnarrow-agent && [[ $(agent_pid) == "$APID" ]] && pass "H7 the agent active, same pid" || bad "H7 the agent restarted or stopped"
exit $fail
