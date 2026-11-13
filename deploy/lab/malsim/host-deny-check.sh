#!/usr/bin/env bash
# Lot 341 — the host-wide denies under the response profile
# (`nn-lab.sh host-deny-check`; run by the lab user from the synced tree,
# sudo inside). On a LAB GUEST ONLY, with an installed agent whose BPF
# guard enforces (`NN_BPF_DEFENSE_ENFORCE=1` in its environment, the
# production default: a lab build observes its own objects otherwise).
#
# The expectation is the profile the agent's start reports (its boot line
# `host-wide denies OBSERVED` / `ENFORCED`; HOST_DENY_EXPECT=observe|enforce
# overrides):
#
#  H1  a foreign tracing program's load (bpf-probe.py: a tracepoint and a
#      kprobe program, never attached): observe → loaded, signed
#      bpf_prog_type "would deny"; enforce → EPERM, signed bpf_prog_type;
#  H2  bpftrace -e 'tracepoint:syscalls:sys_enter_openat { … }': observe →
#      runs and counts; enforce → refused;
#  H3  a BCC or libbpf tool (opensnoop-bpfcc, else libbpf-tools' opensnoop,
#      else bpf-probe.py's raw_tracepoint loader): observe → runs; enforce
#      → refused;
#  H4  a BPF operation on the agent's own maps and programs — BPF_OBJ_GET of
#      PROTECTED_PIDS's pin (read-write and read-only), `bpftool map delete`
#      on it, BPF_PROG_GET_FD_BY_ID of one of its programs: EPERM under
#      BOTH profiles;
#  H5  a detach of one of the agent's links — BPF_OBJ_GET of a link pin,
#      `bpftool link detach pinned`, BPF_LINK_GET_FD_BY_ID of every link of
#      the host (the agent's refused: no handle, no detach; no foreign link
#      is ever detached): refused under BOTH, every pin still there and the
#      agent active after.
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
PROBE="python3 -I $HERE/bpf-probe.py"
ROOT=/sys/fs/bpf/northnarrow
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
measure() { printf 'MEASURE %s\n' "$*"; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null; }
recs() { since "$DET" "$1" | grep "\"operation\":\"$2\""; }
would() { recs "$1" "$2" | grep -c 'would deny'; }
denied() { recs "$1" "$2" | grep -vc 'would deny'; }
agent_pid() { sudo cat /run/northnarrow/agent.pid 2>/dev/null; }

APID=$(agent_pid)
[[ -n $APID ]] || { bad "no agent running"; exit 1; }
# the agent's environment is not readable (the ptrace hook refuses root a
# read of /proc/<agent>/environ): its start's own line says how its guard runs
JOURNAL=$(sudo journalctl --namespace=northnarrow -b -u northnarrow-agent --no-pager 2>/dev/null)
GUARD=$(printf '%s\n' "$JOURNAL" | grep -o 'BPF self-defence: own objects registered.*' | tail -1)
[[ $GUARD == *DENIED* ]] \
    || { bad "the agent's BPF guard observes its own objects (NN_BPF_DEFENSE_ENFORCE=1 not in the units' environment): H4/H5 would prove nothing — ${GUARD:0:160}"; exit 1; }
BOOT=$(printf '%s\n' "$JOURNAL" | grep -o 'host-wide denies [A-Z]*' | tail -1)
EXPECT=${HOST_DENY_EXPECT:-}
if [[ -z $EXPECT ]]; then
    case $BOOT in
        *OBSERVED) EXPECT=observe ;;
        *ENFORCED) EXPECT=enforce ;;
        *) bad "no 'host-wide denies' line in the agent's journal ($BOOT)"; exit 1 ;;
    esac
fi
PROFILE=$(sudo python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("profile") or "")' /etc/northnarrow/install-manifest.json 2>/dev/null)
echo "== the agent: pid $APID, install profile ${PROFILE:-?}, boot line '${BOOT:-?}' → expect $EXPECT"
case "$PROFILE/$EXPECT" in
    alpha/observe | enforcing/enforce) pass "H0 the boot line follows the install's profile" ;;
    *) bad "H0 profile ${PROFILE:-?} but host-wide denies $EXPECT" ;;
esac
LINKS0=$(sudo sh -c "ls -d $ROOT/link_* 2>/dev/null" | wc -l)

echo "== H1. a foreign tracing program's load"
n0=$(lines "$DET")
for t in tracepoint kprobe; do
    o=$(sudo $PROBE load-kprobe-write-user --type "$t" --name "k341_hd_${t:0:5}")
    if [[ $EXPECT == observe ]]; then
        [[ $o == OK* ]] && pass "H1 $t loaded ($o)" || bad "H1 $t refused under the observe-only gate: $o"
    else
        [[ $o == "ERR EPERM"* ]] && pass "H1 $t refused ($o)" || bad "H1 $t under enforce: $o"
    fi
    sleep 1.2
done
sleep 3
if [[ $EXPECT == observe ]]; then
    (( $(would "$n0" bpf_prog_type) >= 2 )) && pass "H1 signed bpf_prog_type 'would deny' ($(would "$n0" bpf_prog_type))" || bad "H1 $(would "$n0" bpf_prog_type) 'would deny' records"
    (( $(denied "$n0" bpf_prog_type) == 0 )) || bad "H1 a refusal record under the observe-only gate"
else
    (( $(denied "$n0" bpf_prog_type) >= 2 )) && pass "H1 signed bpf_prog_type refused ($(denied "$n0" bpf_prog_type))" || bad "H1 $(denied "$n0" bpf_prog_type) refusal records"
    (( $(would "$n0" bpf_prog_type) == 0 )) || bad "H1 a 'would deny' record under enforce"
fi
recs "$n0" bpf_prog_type | grep -o '"response":"[^"]*' | sort | uniq -c | cut -c1-200 | sed 's/^/    /'

echo "== H2. bpftrace"
command -v bpftrace >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpftrace >/dev/null 2>&1 </dev/null
if command -v bpftrace >/dev/null; then
    n0=$(lines "$DET")
    o=$(sudo timeout 30 bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @opens = count(); } interval:s:1 { exit(); }' </dev/null 2>&1); rc=$?
    if [[ $EXPECT == observe ]]; then
        [[ $rc -eq 0 && $o == *@opens* ]] && pass "H2 bpftrace ran ($(echo "$o" | grep -m1 '@opens'))" || bad "H2 bpftrace under the observe-only gate: rc $rc $(echo "$o" | tail -2 | tr '\n' ' ' | cut -c1-200)"
        sleep 2
        (( $(would "$n0" bpf_prog_type) >= 1 )) && pass "H2 recorded 'would deny' ($(would "$n0" bpf_prog_type))" || bad "H2 no 'would deny' record"
    else
        [[ $rc -ne 0 && $o != *@opens* ]] && pass "H2 bpftrace refused (rc $rc: $(echo "$o" | grep -m1 -iE 'permit|error|fail' | cut -c1-120))" || bad "H2 bpftrace ran under enforce (rc $rc)"
    fi
else
    measure "H2 bpftrace not installable here"
fi

echo "== H3. a BCC or libbpf tool"
TOOL=""
for c in opensnoop-bpfcc /usr/sbin/opensnoop-bpfcc; do command -v "$c" >/dev/null 2>&1 && { TOOL=$(command -v "$c"); break; }; done
if [[ -z $TOOL ]]; then
    [[ -x /usr/sbin/opensnoop ]] || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libbpf-tools >/dev/null 2>&1 </dev/null
    [[ -x /usr/sbin/opensnoop ]] && TOOL=/usr/sbin/opensnoop
fi
n0=$(lines "$DET")
if [[ -n $TOOL ]]; then
    o=$(sudo timeout -s INT 4 "$TOOL" </dev/null 2>&1); rc=$?
    echo "    $TOOL rc $rc: $(echo "$o" | head -2 | tr '\n' ' ' | cut -c1-160)"
    if [[ $EXPECT == observe ]]; then
        [[ $rc -eq 0 || $rc -eq 124 || $rc -eq 130 ]] && [[ $o != *"failed to load"* && $o != *"ermission"* ]] && pass "H3 $TOOL ran" || bad "H3 $TOOL under the observe-only gate: rc $rc"
    else
        [[ $o == *"failed to load"* || $o == *"ermission"* || $o == *"Failed"* ]] && pass "H3 $TOOL refused" || bad "H3 $TOOL under enforce: rc $rc"
    fi
else
    measure "H3 no BCC or libbpf tool installable: bpf-probe.py's raw_tracepoint loader instead"
    o=$(sudo $PROBE load-kprobe-write-user --type raw_tracepoint --name k341_hd_raw)
    if [[ $EXPECT == observe ]]; then [[ $o == OK* ]] && pass "H3 raw_tracepoint loaded ($o)" || bad "H3 $o"
    else [[ $o == "ERR EPERM"* ]] && pass "H3 raw_tracepoint refused ($o)" || bad "H3 $o"; fi
fi
sleep 2
measure "H3 bpf_prog_type records: would deny $(would "$n0" bpf_prog_type), refused $(denied "$n0" bpf_prog_type)"

echo "== H4. a BPF operation on the agent's own maps and programs (refused under both)"
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
measure "H4 bpf_handle / bpf_map records: $(recs "$n0" bpf_handle | wc -l) / $(recs "$n0" bpf_map | wc -l) ('would deny' among them: $(( $(would "$n0" bpf_handle) + $(would "$n0" bpf_map) )))"
(( $(would "$n0" bpf_handle) + $(would "$n0" bpf_map) == 0 )) && pass "H4 none of them a 'would deny'" || bad "H4 an own-object refusal marked 'would deny'"

echo "== H5. a detach of one of the agent's links (refused under both)"
n0=$(lines "$DET")
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
systemctl is-active --quiet northnarrow-agent && [[ $(agent_pid) == "$APID" ]] && pass "H5 the agent active, same pid" || bad "H5 the agent restarted or stopped"
exit $fail
