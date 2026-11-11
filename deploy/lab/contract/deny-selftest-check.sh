#!/usr/bin/env bash
# Lot 302 — every deny hook proves it denies, every round, and the bpf()
# guard pinned (`nn-lab.sh deny-selftest-check`; run by the lab user from the
# synced tree, sudo inside, the lab key with the trusted-installer role; a
# debug-trigger build: `nn-lab.sh install`). On a LAB GUEST ONLY: D4
# detaches a deny hook until the agent's next start, G stops the units.
#
#  D0  the BPF guard enforces for the run (the lab build observes:
#      NN_BPF_DEFENSE_ENFORCE=1 in the manager's environment, the agent
#      restarted in a window; put back after unless KEEP_ENFORCE=1) — its
#      handle refusals are attempted only then;
#  D1  ROUNDS rounds (default 10): in each, every deny hook attempted was
#      refused and its refusal arrived (the journal's summary every 10
#      rounds: deny_all_refused = rounds; ROUNDS below 10: no summary, the
#      rounds counted by the debug lines are not read — no deny_selftest row
#      signed over them is the check), how many were attempted, which were
#      not and why; no deny_selftest row signed;
#  D2  the self-test's refusals reached no judge: no detection of the
#      probe child, the posture observing, no ringbuf_drop row naming the
#      denials' budgets (nothing held back);
#  D3  the denials' budgets spent on every CPU before each round
#      (debug-deny-budget-spent, 2 rounds): every refusal still arrives (no
#      deny_selftest row), none held back (no ringbuf_drop row);
#  D4  a hook detached on purpose (debug-deny-detach names DETACH, default
#      inode_mknod): the next round signs deny_selftest naming it, the one
#      after deny_selftest_alert; the agent restarted in a window after (the
#      hook attached again);
#  G   the bpf() guard through a restart gap: the units stopped inside a
#      window, the window over, no agent: a handle by id on each link of the
#      start-in-cgroup tracker, one on a program of the agent's and a kprobe
#      load refused (EPERM); the units started again: the agent up, its
#      hooks attached;
#  T   the rounds' cost (child and target CPU, the agent's checks) within
#      50 ms.
# SKIP_DETACH=1 / SKIP_GAP=1 leave D4 / G out (the 22.04 round).
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
ROUNDS=${ROUNDS:-10}
DETACH=${DETACH:-inode_mknod}
AUDIT=/etc/northnarrow/audit.log
DET=/var/lib/northnarrow/detections/detections.jsonl
PROBE="python3 -I $HERE/../malsim/bpf-probe.py"
RECORDS="$HERE/../lib/lab-records.py"
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
measure() { printf 'MEASURE %s\n' "$*"; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null; }
agent_pid() { sudo cat /run/northnarrow/agent.pid 2>/dev/null; }
WIN_END=0
window() { WIN_END=$(( $(date +%s) + ${1:-30} )); sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs "${1:-30}" >/dev/null 2>&1; }
no_window() { while (( $(date +%s) <= WIN_END + 2 )); do sleep 1; done; }
# the agent's own events (journald's attribution, lab-records.py)
event() {   # <pid> <level> <message prefix>
    sudo journalctl --namespace=northnarrow -u northnarrow-agent _PID="$1" --no-pager -o json 2>/dev/null \
        | python3 -I "$RECORDS" journal northnarrow-agent.service "$1" "$2" "$3"
}
mode_of() { event "$1" INFO "BPF self-defence: own objects registered " | tail -1 | grep -oE 'mode="[a-z]+"$'; }
enforcing() { [[ $(mode_of "$(agent_pid)") == 'mode="enforce"' ]]; }
summaries() { event "$(agent_pid)" INFO "sensor self-test: the rounds' cost"; }
audit_op() { since "$AUDIT" "$2" | grep -a "\"op\":\"$1\""; }
deny_rows() { since "$AUDIT" "$1" | grep -a '"kind":"subsystem_degraded"' | grep -a '"source":"deny_selftest"'; }
budget_drops() { since "$AUDIT" "$1" | grep -a '"op":"ringbuf_drop"' | grep -aE 'denial_rate'; }
wait_for() { local end=$((SECONDS + $2)) out; while ((SECONDS < end)); do out=$($1 "${@:3}"); [ -n "$out" ] && { echo "$out"; return 0; }; sleep 5; done; return 1; }
restart_agent() {
    local old new i
    window 120 || { bad "trusted-installer-grant"; return 1; }
    old=$(agent_pid)
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 60); do
        sleep 1
        new=$(agent_pid)
        [[ -n $new && $new != "$old" ]] && sudo kill -0 "$new" 2>/dev/null && break
    done
    sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl reset-failed northnarrow-agent; sudo systemctl start northnarrow-agent; }
    sleep 15; WIN_END=0
}
# N rounds ended since the agent's start (its debug lines are not logged at
# INFO): the summary's rounds, or the wait for N round lengths
wait_rounds() { sleep $(( $1 * 75 )); }
sudo rm -f /run/northnarrow/debug-deny-detach /run/northnarrow/debug-deny-budget-spent
sudo systemctl is-active --quiet northnarrow-agent || { echo "the agent is not active"; exit 1; }
[ -n "$KEY" ] || { echo "no lab admin key"; exit 1; }
echo "nn-admin: $NNADMIN  key: $KEY  kernel $(uname -r)"

echo "== D0 the BPF guard enforces"
SET=0
if ! enforcing; then
    sudo systemctl set-environment NN_BPF_DEFENSE_ENFORCE=1 && SET=1 && restart_agent
fi
A=$(agent_pid)
enforcing && pass "D0 the guard enforces (agent $A)" || bad "D0 the guard does not enforce (agent $A: $(mode_of "$A"))"
LB=$(sudo sh -c 'ls /sys/fs/bpf/northnarrow' 2>/dev/null | grep -cE '^link_bpf(_prog)?$')
[ "$LB" = 2 ] && pass "D0 the bpf() and bpf_prog guards pinned (link_bpf, link_bpf_prog)" || bad "D0 the guard's pins: $LB of link_bpf, link_bpf_prog"
A0=$(lines "$AUDIT"); D0=$(lines "$DET")

echo "== D1 $ROUNDS rounds: every deny hook attempted refused and reported"
want=$(( ROUNDS / 10 ))
if (( want > 0 )); then
    end=$((SECONDS + ROUNDS * 80 + 150))
    while ((SECONDS < end)); do
        (( $(summaries | grep -c .) >= want )) && break
        sleep 15
    done
    summaries | sed 's/^/  /' | cut -c1-420
    rounds=$(summaries | grep -oE ' rounds=[0-9]+' | awk -F= '{s += $2} END {print s + 0}')
    refused=$(summaries | grep -oE ' deny_all_refused=[0-9]+' | awk -F= '{s += $2} END {print s + 0}')
    attempted=$(summaries | grep -oE ' deny_attempted_max=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
    measure "D1 rounds $rounds, every attempt refused and reported in $refused, hooks attempted a round: ${attempted:-?}"
    if (( rounds >= ROUNDS )) && [ "$rounds" = "$refused" ] && [ -z "$(deny_rows "$A0")" ]; then
        pass "D1 $rounds rounds, every deny hook attempted ($attempted) refused and reported in each, no deny_selftest row"
    else
        bad "D1 rounds $rounds, all refused $refused; deny_selftest rows $(deny_rows "$A0" | wc -l)"
        deny_rows "$A0" | grep -o '"detail":"[^"]*"' | head -8 | sed 's/^/    /'
    fi
else
    wait_rounds "$ROUNDS"
    [ -z "$(deny_rows "$A0")" ] && pass "D1 $ROUNDS round lengths, no deny_selftest row signed" \
        || { bad "D1 deny_selftest rows $(deny_rows "$A0" | wc -l)"; deny_rows "$A0" | grep -o '"detail":"[^"]*"' | head -8 | sed 's/^/    /'; }
fi
event "$A" WARN "deny self-test: this hook's attempt cannot run here" | cut -c1-260 | sort -u | sed 's/^/  not exercised: /'

echo "== D2 the self-test's refusals reached no judge"
posture=$(sudo "$NNADMIN" status --key "$KEY" 2>/dev/null | grep -im1 posture | tr -s ' ')
det=$(since "$DET" "$D0" | grep -ac '"northnarrow-age')
held=$(budget_drops "$A0" | wc -l)
echo "  $posture; detections of the agent's binary since D1: $det; ringbuf_drop rows of the denials' budgets: $held"
if echo "$posture" | grep -qi observing && [ "$det" = 0 ] && [ "$held" = 0 ]; then
    pass "D2 no rule, no posture, nothing held back"
else
    bad "D2 posture [$posture], detections $det, budget drops $held"
fi

echo "== D3 the denials' budgets spent before each round (2 rounds)"
A3=$(lines "$AUDIT")
sudo touch /run/northnarrow/debug-deny-budget-spent
spent_rounds() { event "$A" WARN "debug-trigger: the denials' budgets spent on every CPU before the round" | grep -c .; }
s0=$(spent_rounds)
end=$((SECONDS + 300))
while ((SECONDS < end)) && (( $(spent_rounds) < s0 + 2 )); do sleep 10; done
sleep 8   # the second round's end (its refusals, the drops sampler)
spent=$(( $(spent_rounds) - s0 ))
sudo rm -f /run/northnarrow/debug-deny-budget-spent
measure "D3 rounds with the budgets spent: $spent"
if (( spent >= 2 )) && [ -z "$(deny_rows "$A3")" ] && [ -z "$(budget_drops "$A3")" ]; then
    pass "D3 $spent rounds after a spent budget on every CPU: every refusal arrived, none held back"
else
    bad "D3 spent rounds $spent; deny_selftest rows $(deny_rows "$A3" | wc -l); budget drops $(budget_drops "$A3" | wc -l)"
    deny_rows "$A3" | grep -o '"detail":"[^"]*"' | head -5 | sed 's/^/    /'
fi

if [[ ${SKIP_DETACH:-0} != 1 ]]; then
    echo "== D4 $DETACH detached on purpose"
    A4=$(lines "$AUDIT")
    echo "$DETACH" | sudo tee /run/northnarrow/debug-deny-detach > /dev/null
    t4=$(date +%s)
    if row=$(wait_for deny_rows 200 "$A4"); then
        echo "$row" | grep -o '"detail":"[^"]*"' | head -3 | sed 's/^/    /'
        echo "$row" | grep -q "deny hook $DETACH:" && pass "D4 the signed degradation within $(( $(date +%s) - t4 )) s, naming $DETACH" \
            || bad "D4 a deny_selftest row not naming $DETACH"
    else
        bad "D4 no deny_selftest degradation within 200 s"
    fi
    if row=$(wait_for audit_op 200 deny_selftest_alert "$A4"); then
        echo "$row" | grep -oE '"(hook|rounds_missed)":[^,]*' | tr '\n' ' ' | sed 's/^/    /'; echo
        echo "$row" | grep -q "\"hook\":\"$DETACH\"" && pass "D4 the alert within $(( $(date +%s) - t4 )) s" || bad "D4 an alert not naming $DETACH"
    else
        bad "D4 no deny_selftest_alert within 200 s"
    fi
    measure "D4 the link self-check: $(audit_op bpf_link_missing "$A4" | wc -l) bpf_link_missing row(s); the hook's other rows: $(deny_rows "$A4" | grep -vc "deny hook $DETACH:")"
    sudo rm -f /run/northnarrow/debug-deny-detach
    restart_agent
    A=$(agent_pid)
    [[ -n $A ]] && sudo test -e "/sys/fs/bpf/northnarrow/link_$DETACH" && pass "D4 restarted ($A): $DETACH attached again" || bad "D4 after the restart: agent ${A:-none}, link_$DETACH $(sudo test -e /sys/fs/bpf/northnarrow/link_$DETACH && echo pinned || echo absent)"
fi

if [[ ${SKIP_GAP:-0} != 1 ]]; then
    echo "== G the bpf() guard through a restart gap"
    A=$(agent_pid)
    TDIR=$(sudo sh -c "ls -d /sys/fs/bpf/northnarrow-cgroup-join-v* 2>/dev/null" | head -1)
    REG=$(event "$A" INFO "BPF self-defence: the links pinned in this directory registered as the agent's own " | sed 's/^.*registered as the agent.s own //')
    TIDS=$(echo "$REG" | grep -F "dir=$TDIR " | grep -oE 'links=\[[0-9, ]*\]' | tr -dc '0-9 ,' | tr ',' ' ')
    PROG=$(sudo awk '$1 ~ /^[0-9]+$/ && $2 == "task_kill" {print $1; exit}' /run/northnarrow/bpf-own-ids 2>/dev/null)
    echo "  tracker $TDIR links: ${TIDS:-none}; the agent's task_kill program: ${PROG:-?}"
    window 20
    for u in northnarrow-watchdog northnarrow-agent; do
        sudo systemctl kill --signal=SIGTERM "$u" 2>/dev/null
        for _ in $(seq 1 20); do
            [ -z "$(sudo cat /sys/fs/cgroup/northnarrow.slice/$u.service/cgroup.procs /sys/fs/cgroup/system.slice/$u.service/cgroup.procs 2>/dev/null)" ] && break
            sleep 0.5
        done
    done
    no_window
    st=$(systemctl is-active northnarrow-agent northnarrow-watchdog | tr '\n' ' ')
    echo "  in the gap (the window over): units $st"
    [[ $st == inactive\ inactive* ]] || bad "G the units did not stop: $st"
    n=0; refused=0
    for id in $TIDS; do
        n=$((n + 1)); r=$(sudo $PROBE link-fd-by-id "$id")
        [[ $r == "ERR EPERM"* ]] && refused=$((refused + 1)) || bad "G tracker link $id in the gap: $r"
    done
    (( n > 0 && refused == n )) && pass "G a handle by id on each of the tracker's $n links refused in the gap (EPERM)" || bad "G tracker links refused $refused of $n"
    if [[ -n $PROG ]]; then
        r=$(sudo $PROBE prog-fd-by-id "$PROG")
        [[ $r == "ERR EPERM"* ]] && pass "G a handle by id on the agent's program $PROG refused in the gap ($r)" || bad "G program $PROG in the gap: $r"
    fi
    r=$(sudo $PROBE load-kprobe-write-user --name k302_gap)
    [[ $r == "ERR EPERM"* ]] && pass "G a kprobe load refused in the gap ($r)" || bad "G a kprobe load in the gap: $r"
    sudo systemctl start northnarrow-agent; sleep 3; sudo systemctl start northnarrow-watchdog; sleep 15
    A=$(agent_pid)
    hooks=$(event "$A" INFO "anti-tamper: all LSM hooks attached" | tail -1 | grep -oE 'deny_attached=[0-9]+ deny_expected=[0-9]+')
    [[ -n $A ]] && systemctl is-active --quiet northnarrow-agent && [[ -n $hooks ]] \
        && pass "G the agent started through the pinned guard ($A, $hooks), $(mode_of "$A")" \
        || bad "G after the gap: agent ${A:-none} $(systemctl is-active northnarrow-agent), hooks [${hooks}]"
fi

echo "== T the rounds' cost"
summaries | while read -r l; do
    echo "  $(echo "$l" | grep -oE '(rounds|all_seen|child_cpu_us_max|checks_us_max|latency_ms_max|deny_all_refused|deny_attempted_max)=[0-9]+' | tr '\n' ' ')"
done
cpu=$(summaries | grep -oE 'child_cpu_us_max=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
chk=$(summaries | grep -oE 'checks_us_max=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
over=$(since "$AUDIT" "$A0" | grep -a "round's cost" | wc -l)
if [ -n "$cpu" ] && [ $(( ${cpu:-0} + ${chk:-0} )) -le 50000 ] && [ "$over" = 0 ]; then
    pass "T the round within its budget: child and target CPU max ${cpu} us + the agent's checks max ${chk} us <= 50000 us"
elif [ -z "$cpu" ]; then
    measure "T no summary this agent (fewer than 10 rounds since its start); over-budget rows $over"
    [ "$over" = 0 ] || bad "T over-budget rows $over"
else
    bad "T cost child ${cpu:-?} us, checks ${chk:-?} us, over-budget rows $over"
fi

if (( SET )) && [[ ${KEEP_ENFORCE:-0} != 1 ]]; then
    sudo systemctl unset-environment NN_BPF_DEFENSE_ENFORCE; restart_agent
    echo "guard back in the lab build's mode: $(mode_of "$(agent_pid)")"
fi
sudo rm -f /run/northnarrow/debug-deny-detach /run/northnarrow/debug-deny-budget-spent
(( fail == 0 )) && echo "DENY-SELFTEST-CHECK PASS" || echo "DENY-SELFTEST-CHECK FAIL"
exit $fail
