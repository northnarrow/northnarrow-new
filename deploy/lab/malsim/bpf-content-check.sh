#!/usr/bin/env bash
# Lot 345 — what a loader the signed per-loader opt-out names still cannot
# load (`nn-lab.sh bpf-content-check`; run by the lab user from the synced
# tree, sudo inside). On a LAB GUEST ONLY, with an agent installed by
# `install.sh --allow-bpf-tools` (python3 and bpftrace named by signed
# bpf-loader-allow lines). Every case reads stdin from /dev/null; nothing is
# attached; nothing is left behind. One `=== CASE <label>: rc=<n> …` line
# per case, then PASS/FAIL, then the records' reasons.
#
#  B0  the policy names python3 (BCC's loader) and bpftrace;
#  B1  python3, a kprobe that calls no helper: loaded (bpf_prog_opt_out);
#  B2  python3, a kprobe calling bpf_send_signal / bpf_send_signal_thread /
#      bpf_override_return / bpf_probe_write_user: refused, each with a signed
#      bpf_prog_type naming the helper (6.9+: at bpf_prog_load, EPERM; before:
#      at bpf_prog once verified, EPERM — bpf_probe_write_user at the
#      verifier's lockdown question, which the verifier reports EINVAL);
#      bpf_override_return absent from the kernel's build: measured;
#  B3  python3, an fmod_ret (BPF_MODIFY_RETURN) on security_file_open:
#      refused (EPERM), signed "fmod_ret"; an fentry there: loaded;
#  B4  bpftrace, a one-liner: runs; `bpftrace --unsafe` with signal():
#      refused;
#  B5  a BCC tool (opensnoop-bpfcc): runs (measured where BCC cannot
#      compile, Debian's cloud kernels);
#  B6  the agent still active, same pid; the content judge's stage at its
#      start (its journal line).
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
PROBE="python3 -I $HERE/bpf-probe.py"
POLICY=/etc/northnarrow/rule-policy.local
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
measure() { printf 'MEASURE %s\n' "$*"; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null </dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null </dev/null; }
recs() { since "$DET" "$1" | grep "\"operation\":\"$2\""; }
count() { recs "$1" "$2" | wc -l; }
agent_pid() { sudo cat /run/northnarrow/agent.pid 2>/dev/null </dev/null; }
# the signed record's `response` names what the content judge refused
reason() { recs "$1" bpf_prog_type | grep -o '"response":"[^"]*' | tail -1 | cut -c13-230; }

APID=$(agent_pid)
[[ -n $APID ]] || { bad "no agent running"; exit 1; }
PY=$(readlink -f "$(command -v python3)")
BT=$(readlink -f "$(command -v bpftrace 2>/dev/null)" 2>/dev/null)
ALLOWED=$(sudo awk '$1 == "bpf-loader-allow" { print $2, $3 }' "$POLICY" 2>/dev/null </dev/null)
echo "=== CASE B0 policy: rc=0 kernel $(uname -r); bpf-loader-allow: $(echo "$ALLOWED" | tr '\n' ';')"
named() { local r; while read -r p _; do r=$(readlink -f "$p"); [[ $r == "$1" ]] && return 0; done <<< "$ALLOWED"; return 1; }
named "$PY" && pass "B0 python3 ($PY) is named" || bad "B0 python3 ($PY) is not named: install with --allow-bpf-tools"
[[ -n $BT ]] && { named "$BT" && pass "B0 bpftrace ($BT) is named" || bad "B0 bpftrace ($BT) is not named"; }
JOURNAL=$(sudo journalctl --namespace=northnarrow -b -u northnarrow-agent --no-pager </dev/null 2>/dev/null)
STAGE=$(printf '%s\n' "$JOURNAL" | grep -oE 'BPF self-defence: content judge [^"]*' | tail -2 | tr '\n' ' ' | cut -c1-200)
echo "    the content judge at the agent's start: ${STAGE:-(no line)}"

n0=$(lines "$DET")
o=$(sudo $PROBE load-tracing --type kprobe --call none --name k345_none </dev/null 2>&1); rc=$?
echo "=== CASE B1 python3 kprobe no helper: rc=$rc $o"
[[ $o == OK* ]] && pass "B1 an opted-out loader's plain kprobe loaded" || bad "B1 refused: $o"
sleep 1.2

for call in send_signal send_signal_thread override_return write_user; do
    n0=$(lines "$DET")
    o=$(sudo $PROBE load-tracing --type kprobe --call "$call" --name "k345_${call:0:10}" </dev/null 2>&1); rc=$?
    sleep 1.5
    r=$(reason "$n0")
    echo "=== CASE B2 python3 kprobe bpf_$call: rc=$rc $o"
    echo "    record: ${r:-(none)}"
    if [[ $o == OK* ]]; then
        bad "B2 bpf_$call loaded by an opted-out loader"
    elif [[ $call == override_return && -z $r ]]; then
        measure "B2 bpf_override_return refused by the kernel itself ($o): no CONFIG_BPF_KPROBE_OVERRIDE here"
    elif [[ $r == *"a call of bpf_$call"* || ( $call == write_user && $r == *"a call of bpf_probe_write_user"* ) ]]; then
        pass "B2 bpf_$call refused ($o), signed: the helper named"
    else
        bad "B2 bpf_$call refused ($o) without its signed record"
    fi
done

n0=$(lines "$DET")
o=$(sudo $PROBE load-fmod-ret --func security_file_open --name k345_fmod </dev/null 2>&1); rc=$?
sleep 1.5
r=$(reason "$n0")
echo "=== CASE B3 python3 fmod_ret security_file_open: rc=$rc $o"
echo "    record: ${r:-(none)}"
[[ $o == "ERR EPERM"* && $r == *"an fmod_ret"* ]] && pass "B3 fmod_ret refused to an opted-out loader, signed" || bad "B3 fmod_ret: $o / ${r:-no record}"
o=$(sudo $PROBE load-fmod-ret --func security_file_open --fentry --name k345_fentry </dev/null 2>&1); rc=$?
echo "=== CASE B3 python3 fentry security_file_open: rc=$rc $o"
[[ $o == OK* ]] && pass "B3 an fentry (tracing) still loads under the opt-out" || bad "B3 fentry refused: $o"
sleep 1.2

if [[ -n $BT ]]; then
    o=$(sudo timeout 30 bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @opens = count(); } interval:s:1 { exit(); }' </dev/null 2>&1); rc=$?
    echo "=== CASE B4 bpftrace one-liner: rc=$rc $(echo "$o" | grep -v '^$' | head -2 | tr '\n' ' ' | cut -c1-160)"
    # 7.0: a syscall tracepoint fires for the calls made on CPU 0 only (lot
    # 322) — the count may stay empty; the load and attach are what is judged
    [[ $rc -eq 0 && ( $o == *@opens* || $o == *Attach* ) ]] && pass "B4 bpftrace runs under the opt-out" || bad "B4 bpftrace did not run (rc $rc)"
    n0=$(lines "$DET")
    o=$(sudo timeout 30 bpftrace --unsafe -e 'kprobe:do_nanosleep { signal("SIGCONT"); exit(); }' -c '/bin/sleep 0.2' </dev/null 2>&1); rc=$?
    sleep 1.5
    r=$(reason "$n0")
    echo "=== CASE B4 bpftrace --unsafe signal(): rc=$rc $(echo "$o" | grep -iE -m1 'permit|error|fail' | cut -c1-160)"
    echo "    record: ${r:-(none)}"
    [[ $rc -ne 0 && $r == *"a call of bpf_send_signal"* ]] && pass "B4 bpftrace's signal() refused, signed" || bad "B4 bpftrace --unsafe signal(): rc $rc, ${r:-no record}"
else
    measure "B4 no bpftrace here"
fi

TOOL=$(command -v opensnoop-bpfcc 2>/dev/null)
if [[ -n $TOOL ]]; then
    o=$(sudo timeout -s INT 6 "$TOOL" </dev/null 2>&1); rc=$?
    echo "=== CASE B5 $TOOL: rc=$rc $(echo "$o" | head -2 | tr '\n' ' ' | cut -c1-160)"
    if [[ $o == *"Failed to compile BPF module"* ]]; then
        measure "B5 BCC cannot compile on this kernel (no kernel headers)"
    elif [[ ( $rc -eq 0 || $rc -eq 124 || $rc -eq 130 ) && $o != *"failed to load"* && $o != *"ermission"* ]]; then
        pass "B5 BCC's opensnoop runs under the opt-out"
    else
        bad "B5 BCC's opensnoop did not run (rc $rc)"
    fi
else
    measure "B5 no BCC tool here"
fi

systemctl is-active --quiet northnarrow-agent && [[ $(agent_pid) == "$APID" ]] && pass "B6 the agent active, same pid" || bad "B6 the agent restarted or stopped"
echo "=== CASE B-END: rc=$fail"
exit $fail
