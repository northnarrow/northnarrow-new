#!/usr/bin/env bash
# Lot 280c — the sensor self-test (`nn-lab.sh selftest-check`; run by the lab
# user from the synced tree, sudo inside, the lab key; a debug-trigger build:
# `nn-lab.sh install`). On a LAB GUEST ONLY: T3 drops one ring's events for a
# few minutes.
#
#  T0  the manifest settled: every source has the self-test's word — `seen`,
#      its evidence `probe` (a live event) or `attach_check` — or `not
#      exercised` with why; none missed;
#  T1  ROUNDS rounds (default 10) all seen: the journal's summary line (every
#      10 rounds) counts them, and no `sensor_selftest` row was signed;
#  T2  the self-test's events reached no rule, no posture and no signed log:
#      the posture observing, no detection of the probe child, no netflow,
#      listener or drift row of it since the start (its DNS datagram used to
#      leave one a minute), the drains' skipped rows counted;
#  T3  one sensor blinded (`/run/northnarrow/debug-ring-drop` names a ring
#      pump read through `run_ring`, `BLIND`, default bpf_syscall): the
#      next round signs
#      `subsystem_degraded` (source sensor_selftest, the sensor and the step)
#      and the manifest says `unknown` / `missed`; the round after it signs
#      `sensor_selftest_alert`, the manifest `attached, not invoked` / `gap`;
#      the file removed, `sensor_selftest_restored` and the degradation
#      withdrawn;
#  T4  the round's cost: the summary's child CPU, the agent's checks and the
#      slowest event, against the budget.
set -u
PATH=$PATH:/usr/sbin:/sbin
ROUNDS=${ROUNDS:-10}
BLIND=${BLIND:-bpf_syscall}
AUDIT=/etc/northnarrow/audit.log
DET=/var/lib/northnarrow/detections/detections.jsonl
NETFLOW=/var/lib/northnarrow/netflow.jsonl
LISTEN=/var/lib/northnarrow/netflow_listeners.jsonl
DRIFT=/var/lib/northnarrow/fim_drift.jsonl
DROP=/run/northnarrow/debug-ring-drop
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
T=$(mktemp -d)
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null; }
caps() { sudo "$NNADMIN" capabilities --key "$KEY" --json > "$T/caps.json" 2>/dev/null; }
# a source's state, word and evidence in the newest manifest
src() { python3 -I -c 'import json, sys
m = json.load(open(sys.argv[1]))["manifest"]
for s in m["sources"]:
    if s["source"] == sys.argv[2]:
        print(s["state"], s.get("probe"), s.get("evidence"))' "$T/caps.json" "$1"; }
journal() { sudo journalctl --namespace=northnarrow -u northnarrow-agent --since "@$START" --no-pager -o cat 2>/dev/null; }
# the audit rows of `op` (or the sensor_selftest degradations) since line $2
audit_op() { since "$AUDIT" "$2" | grep -a "\"op\":\"$1\""; }
degraded() { since "$AUDIT" "$1" | grep -a '"kind":"subsystem_degraded"' | grep -a '"source":"sensor_selftest"'; }
# wait up to $2 s for `cmd $1` to print something
wait_for() { local end=$((SECONDS + $2)) out; while ((SECONDS < end)); do out=$($1 "${@:3}"); [ -n "$out" ] && { echo "$out"; return 0; }; sleep 5; done; return 1; }

sudo systemctl is-active --quiet northnarrow-agent || { echo "the agent is not active"; exit 1; }
[ -n "$KEY" ] || { echo "no lab admin key"; exit 1; }
START=$(date -d "$(systemctl show -p ActiveEnterTimestamp --value northnarrow-agent)" +%s)
A0=$(lines "$AUDIT"); D0=$(lines "$DET"); N0=$(lines "$NETFLOW"); L0=$(lines "$LISTEN"); F0=$(lines "$DRIFT")
echo "agent $(sudo "$NNADMIN" --version 2>/dev/null | head -1); kernel $(uname -r); active since $(date -d "@$START" -u +%T)Z"
sudo rm -f "$DROP"

echo "== T0 the manifest settled, every source's word"
settled=0
for _ in $(seq 1 30); do
    caps && python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["manifest"]["settled"] else 1)' "$T/caps.json" && { settled=1; break; }
    sleep 5
done
[ "$settled" = 1 ] || bad "T0 the manifest did not settle within 150 s"
python3 -I - "$T/caps.json" > "$T/t0.txt" <<'EOF'
import json, sys
m = json.load(open(sys.argv[1]))["manifest"]
bad = 0
for s in m["sources"]:
    w, ev = s.get("probe"), s.get("evidence")
    note = ""
    if w is None and s["state"] == "standby":
        note = "  (standby: the word is the source's it stands in for)"
    elif w in ("missed", "gap", "stale", "pending", None):
        bad += 1; note = "  <-- " + "; ".join(s.get("why", []))[:200]
    elif w == "not_exercised":
        note = "  (" + "; ".join(x for x in s.get("why", []) if "self-test" in x)[:160] + ")"
    print("  %-14s %-22s word %-14s evidence %s%s" % (s["source"], s["state"], w, ev, note))
print("BAD", bad)
EOF
sed '$d' "$T/t0.txt"
if [ "$(tail -1 "$T/t0.txt")" = "BAD 0" ]; then pass "T0 every source has the self-test's word, none missed"; else bad "T0 $(tail -1 "$T/t0.txt") source(s) without a good word"; fi

echo "== T1 $ROUNDS rounds all seen (the journal's summary every 10 rounds)"
summary() { journal | grep -a "the rounds' cost" | tail -1; }
want=$(( (ROUNDS + 9) / 10 ))
end=$((SECONDS + ROUNDS * 80 + 120))
got=0
while ((SECONDS < end)); do
    got=$(journal | grep -ac "the rounds' cost")
    ((got >= want)) && break
    sleep 15
done
journal | grep -a "the rounds' cost" | sed 's/^/  /' | cut -c1-400
rounds=$(journal | grep -a "the rounds' cost" | grep -oE ' rounds=[0-9]+' | awk -F= '{s += $2} END {print s + 0}')
allseen=$(journal | grep -a "the rounds' cost" | grep -oE ' all_seen=[0-9]+' | awk -F= '{s += $2} END {print s + 0}')
if ((got >= want)) && [ "$rounds" = "$allseen" ] && [ -z "$(degraded "$A0")" ] && [ -z "$(audit_op sensor_selftest_alert "$A0")" ]; then
    pass "T1 $rounds rounds, $allseen with every sensor seen, no sensor_selftest row signed"
else
    bad "T1 summaries $got/$want, rounds $rounds, all seen $allseen; degradations: $(degraded "$A0" | wc -l), alerts: $(audit_op sensor_selftest_alert "$A0" | wc -l)"
    degraded "$A0" | grep -o '"detail":"[^"]*"' | head -5 | sed 's/^/    /'
    journal | grep -aE "SELF-TEST|cannot run here" | cut -c1-300 | sort | uniq -c | head -10 | sed 's/^/    /'
fi
journal | grep -a "cannot run here" | cut -c1-300 | sort -u | sed 's/^/  not exercised: /'

echo "== T2 no rule, no posture, no signed row of the probe child"
posture=$(sudo "$NNADMIN" status --key "$KEY" 2>/dev/null | grep -im1 posture | tr -s ' ')
det=$(since "$DET" "$D0" | grep -ac '"northnarrow-age')
nf=$(since "$NETFLOW" "$N0" | grep -a '"comm":"northnarrow-age' | grep -ac '127.0.0.1')
li=$(since "$LISTEN" "$L0" | grep -a '"comm":"northnarrow-age' | grep -ac '127.0.0.1')
dr=$(since "$DRIFT" "$F0" | grep -ac '/run/northnarrow/probe')
skipped=$(summary | grep -oE 'rows_skipped=[0-9]+' | cut -d= -f2)
late=$(summary | grep -oE 'late_taken=[0-9]+' | cut -d= -f2)
echo "  $posture; since the start: detections of the agent's binary $det, loopback netflow rows $nf, listener rows $li, probe-dir drift rows $dr; rows skipped by the drains ${skipped:-?}, late events taken ${late:-?}"
if echo "$posture" | grep -qi observing && [ "$det" = 0 ] && [ "$nf" = 0 ] && [ "$li" = 0 ] && [ "$dr" = 0 ] && [ "${skipped:-0}" -gt 0 ]; then
    pass "T2 the self-test's events reached no rule, no posture, no signed log (skipped ${skipped})"
else
    bad "T2 the self-test's events reached a judge or a signed log"
    since "$NETFLOW" "$N0" | grep -a '"comm":"northnarrow-age' | head -3 | cut -c1-300 | sed 's/^/    /'
fi

echo "== T3 $BLIND blinded (its ring's events dropped)"
A1=$(lines "$AUDIT")
echo "$BLIND" | sudo tee "$DROP" > /dev/null
t3=$(date +%s)
if row=$(wait_for degraded 150 "$A1"); then
    secs=$(( $(date +%s) - t3 ))
    caps; s1=$(src "$BLIND")
    pass "T3a the signed degradation within ${secs} s: $(echo "$row" | head -1 | grep -o '"detail":"[^"]*"' | cut -c1-220); manifest $BLIND: $s1"
    [[ $s1 == unknown* && $s1 == *missed* ]] || bad "T3a the manifest says $s1, not unknown/missed"
else
    bad "T3a no sensor_selftest degradation within 150 s"
fi
if row=$(wait_for audit_op 150 sensor_selftest_alert "$A1"); then
    secs=$(( $(date +%s) - t3 ))
    sleep 6; caps; s2=$(src "$BLIND")
    pass "T3b the alert within ${secs} s: $(echo "$row" | head -1 | grep -oE '"(sensor|rounds_missed|step)":[^,]*' | tr '\n' ' '); manifest $BLIND: $s2"
    [[ $s2 == attached_not_invoked* && $s2 == *gap* ]] || bad "T3b the manifest says $s2, not attached_not_invoked/gap"
    journal | grep -a "SENSOR SELF-TEST" | tail -2 | cut -c1-260 | sed 's/^/    /'
else
    bad "T3b no sensor_selftest_alert within 150 s"
fi
sudo rm -f "$DROP"
if row=$(wait_for audit_op 150 sensor_selftest_restored "$A1"); then
    sleep 6; caps; s3=$(src "$BLIND")
    # the open degradations (the manifest's `degradations`), not the status's
    # "changed since" lines, which name the withdrawal itself
    left=$(python3 -I -c 'import json, sys
m = json.load(open(sys.argv[1]))["manifest"]
print(sum("sensor_selftest" in d for d in m.get("degradations", [])))' "$T/caps.json")
    sudo "$NNADMIN" status --key "$KEY" 2>/dev/null | grep -aE '^degradations|sensor_selftest' | cut -c1-200 | sed 's/^/    status: /'
    pass "T3c restored: $(echo "$row" | head -1 | grep -oE '"(sensor|rounds_missed)":[^,]*' | tr '\n' ' '); manifest $BLIND: $s3; open sensor_selftest degradations in the manifest: $left"
    [[ $s3 == ok* && $s3 == *seen* && $left == 0 ]] || bad "T3c the manifest says $s3, $left degradation line(s) left"
else
    bad "T3c no sensor_selftest_restored within 150 s"
fi

echo "== T4 the round's cost"
journal | grep -a "the rounds' cost" | while read -r l; do
    echo "  $(echo "$l" | grep -oE '(rounds|all_seen|child_cpu_us_max|checks_us_max|latency_ms_max|budget_us)=[0-9]+' | tr '\n' ' ')"
done
cpu=$(journal | grep -a "the rounds' cost" | grep -oE 'child_cpu_us_max=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
chk=$(journal | grep -a "the rounds' cost" | grep -oE 'checks_us_max=[0-9]+' | cut -d= -f2 | sort -n | tail -1)
over=$(since "$AUDIT" "$A0" | grep -a "round's cost" | wc -l)
if [ -n "$cpu" ] && [ $(( ${cpu:-0} + ${chk:-0} )) -le 50000 ] && [ "$over" = 0 ]; then
    pass "T4 the round within its budget: child CPU max ${cpu} us + the agent's checks max ${chk} us <= 50000 us"
else
    bad "T4 cost child ${cpu:-?} us, checks ${chk:-?} us, over-budget rows $over"
fi
rm -rf "$T"
[ "$fail" = 0 ] && echo "SELFTEST-CHECK PASS" || echo "SELFTEST-CHECK FAIL"
exit "$fail"
