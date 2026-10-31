#!/usr/bin/env bash
# EXP-13r (R12c, lab PR 270): the response dispatcher under a burst of
# responses, and an agent killed between an action's intent and its outcome.
# On an nn-lab guest only (the provisioning marker), as root.
#
# The burst: --kills N processes of the lab user exec, at once, copies of
# /bin/sleep from a fresh directory in /tmp (NN-L-R001: KillProcessTree
# each), and --flows N connect to 192.0.2.1:80 (TEST-NET-1, RFC 5737, in
# the shipped netflow blocklist: NN-L-NET-001 kills each; nothing leaves the
# guest) — every one benign, each a response the dispatcher runs. Through
# it, --load-secs S of a steady exec load of the lab user (/usr/bin/true,
# judged on P1, no rule) so the decision's delay per class is measured while
# the responses run. After --settle seconds: which of the burst's processes
# still run (each one left is killed here and counted), the agent's signed
# status before and after (stages 5, 6 and 7), and the rows the `actions`
# chain gained: every intent paired with its outcome (`unanswered` must be
# 0), the outcomes by result, the overflow rows (an agent older than R12c
# has no chain: the rows are null).
#
# --crash: the lab build's `debug-crash-mid-action` (next to the admin
# socket): the agent aborts after its next action, before that action's
# outcome row — then one R001 exec. The script waits for the watchdog's
# restart (a new MainPID, at most --restart-wait seconds) and reads what
# the new run signed: the `interrupted` row answering the old run's intent
# in the actions chain, and the `response_interrupted` row of the audit log
# (from the files: the signed rows, never journal text).
#
# Output (DIR, default /var/lib/nn-exp13r/<UTC stamp>): status-before.json,
# status-after.json, actions-new.jsonl, audit-new.jsonl, summary.json.
# Exit: 0 measured, 1 a check failed, 2 usage or not a lab guest.
set -u -o pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL=C

OUT= KILLS=200 FLOWS=200 LOAD_SECS=30 SETTLE=20 CRASH=0 RESTART_WAIT=180 KEY=
ACTIONS=/var/lib/northnarrow/detections/actions.jsonl
AUDIT=/etc/northnarrow/audit.log
RUNDIR=/run/northnarrow
MARKER=/var/lib/nn-lab-provisioned

die() { echo "exp13r: $*" >&2; exit 2; }
while (($#)); do
    case "$1" in
        --out) OUT=${2:?}; shift 2 ;;
        --kills) KILLS=${2:?}; shift 2 ;;
        --flows) FLOWS=${2:?}; shift 2 ;;
        --load-secs) LOAD_SECS=${2:?}; shift 2 ;;
        --settle) SETTLE=${2:?}; shift 2 ;;
        --crash) CRASH=1; shift ;;
        --restart-wait) RESTART_WAIT=${2:?}; shift 2 ;;
        --key) KEY=${2:?}; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
for v in KILLS FLOWS LOAD_SECS SETTLE RESTART_WAIT; do
    [[ ${!v} =~ ^[0-9]+$ ]] || die "--${v,,} takes a whole number: ${!v}"
done
(($(id -u) == 0)) || die "run as root"
[[ -e $MARKER || ${NN_TEST_DISPOSABLE_HOST:-} == 1 ]] || die "not an nn-lab guest ($MARKER missing)"
for b in python3 systemd-run systemctl runuser; do
    command -v "$b" >/dev/null 2>&1 || die "missing: $b"
done
if [[ -z $KEY ]]; then
    for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do
        [[ -r $k ]] && { KEY=$k; break; }
    done
fi
[[ -n $KEY ]] || die "no admin key (--key, /root/northnarrow-admin.key)"
systemctl is-active --quiet northnarrow-agent || die "the agent is not running"
AGENT_EXE=$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)
NNADMIN=$(dirname "${AGENT_EXE:-/usr/local/bin/northnarrow-agent}")/nn-admin
[[ -x $NNADMIN ]] || die "no nn-admin next to the agent ($NNADMIN)"
USER_NAME=${SUDO_USER:-nn}
id "$USER_NAME" >/dev/null 2>&1 || die "no user $USER_NAME"
OUT=${OUT:-/var/lib/nn-exp13r/$(date -u +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"

size() { stat -c %s "$1" 2>/dev/null || echo 0; }
status() { "$NNADMIN" status --json --key "$KEY" > "$1" 2>"$1.err" || true; }
pid_of_agent() { systemctl show -p MainPID --value northnarrow-agent; }

A0=$(size "$ACTIONS") U0=$(size "$AUDIT")
status "$OUT/status-before.json"
AGENT0=$(pid_of_agent)

STAGE=$(mktemp -d /tmp/nn-exp13r.XXXXXX) || die "mktemp"
chmod 0755 "$STAGE"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

# The steady load the decision judges while the responses run.
if ((LOAD_SECS > 0)); then
    systemd-run --quiet --collect --unit "nn-exp13r-load-$$" --uid "$USER_NAME" \
        /bin/bash -c "end=\$((SECONDS+$LOAD_SECS)); while ((SECONDS<end)); do /usr/bin/true; done" \
        || die "the load did not start"
fi

PIDS="$OUT/pids.txt"
: > "$PIDS"
if ((CRASH)); then
    : > "$RUNDIR/debug-crash-mid-action"
    sleep 7   # the event loop reads its triggers every 5 s
    cp /bin/sleep "$STAGE/nn-exp13r-crash"
    chmod 0755 "$STAGE/nn-exp13r-crash"
    runuser -u "$USER_NAME" -- "$STAGE/nn-exp13r-crash" 300 &
    echo "crash $!" >> "$PIDS"
    sleep 1
else
    # the burst: the R001 execs and the NET-001 connects, at once
    for i in $(seq 1 "$KILLS"); do
        cp /bin/sleep "$STAGE/nn-exp13r-k$i"
    done
    chmod 0755 "$STAGE"/nn-exp13r-k*
    for i in $(seq 1 "$KILLS"); do
        runuser -u "$USER_NAME" -- "$STAGE/nn-exp13r-k$i" 300 &
        echo "kill $!" >> "$PIDS"
    done
    for i in $(seq 1 "$FLOWS"); do
        runuser -u "$USER_NAME" -- python3 -I -c '
import socket, time
s = socket.socket(); s.settimeout(30)
try: s.connect(("192.0.2.1", 80))
except OSError: pass
time.sleep(300)' &
        echo "flow $!" >> "$PIDS"
    done
fi

if ((CRASH)); then
    # the watchdog's restart: a new MainPID
    end=$((SECONDS + RESTART_WAIT)); AGENT1=$AGENT0
    while ((SECONDS < end)); do
        AGENT1=$(pid_of_agent)
        [[ -n $AGENT1 && $AGENT1 != 0 && $AGENT1 != "$AGENT0" ]] && systemctl is-active --quiet northnarrow-agent && break
        sleep 2
    done
    sleep "$SETTLE"
else
    sleep "$SETTLE"
    AGENT1=$(pid_of_agent)
fi

# which of the burst's processes still run (left ones killed and counted)
left=0
while read -r kind pid; do
    if kill -0 "$pid" 2>/dev/null; then
        left=$((left + 1)); echo "$kind $pid left" >> "$OUT/left.txt"; kill -9 "$pid" 2>/dev/null
    fi
done < "$PIDS"
wait 2>/dev/null
status "$OUT/status-after.json"
tail -c +"$((A0 + 1))" "$ACTIONS" > "$OUT/actions-new.jsonl" 2>/dev/null || : > "$OUT/actions-new.jsonl"
tail -c +"$((U0 + 1))" "$AUDIT" > "$OUT/audit-new.jsonl" 2>/dev/null || : > "$OUT/audit-new.jsonl"
[[ -e $ACTIONS ]] && ACTIONS_EXISTS=1 || ACTIONS_EXISTS=0

python3 -I - "$OUT" "$KILLS" "$FLOWS" "$left" "$CRASH" "$AGENT0" "$AGENT1" "$ACTIONS_EXISTS" <<'PY'
import collections, json, os, sys
out, kills, flows, left, crash, agent0, agent1, exists = sys.argv[1:9]
kills, flows, left, crash, exists = int(kills), int(flows), int(left), int(crash), int(exists)

def rows(name):
    r = []
    try:
        with open(os.path.join(out, name), "rb") as f:
            for line in f:
                try:
                    r.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return r

def status(name):
    try:
        with open(os.path.join(out, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

actions = [r for r in rows("actions-new.jsonl") if "row" in r]
audit = rows("audit-new.jsonl")
intents = {(r["run"], r["action"]): r for r in actions if r["row"] == "intent"}
answers = {(r["run"], r["action"]): r for r in actions if r["row"] in ("outcome", "interrupted")}
unanswered = [k for k in intents if k not in answers]
results = collections.Counter(
    (r["row"], (r.get("outcome") or {}).get("result")) for r in actions if r["row"] in ("outcome", "interrupted"))
overflow = [r["overflow"] for r in actions if r["row"] == "overflow"]
before, after = status("status-before.json"), status("status-after.json")

def delay(s):
    d = (s or {}).get("event_bus_decision") or {}
    return {q["priority"]: {"timed": q["timed"], "p99_us": q["delay_p99_us"],
                            "max_us": q["delay_max_us"], "over_budget": q["over_budget"]}
            for q in d.get("queues", [])}

def stages(s):
    b = (s or {}).get("event_bus") or {}
    return {str(st["stage"]): st["total"] for st in b.get("stages", [])}

summary = {
    "burst": {"kills": kills, "flows": flows, "left_running": left},
    "agent": {"before": agent0, "after": agent1, "restarted": agent0 != agent1},
    "actions_chain": bool(exists),
    "intents": len(intents),
    "answered": len([k for k in intents if k in answers]),
    "unanswered": len(unanswered),
    "results": {f"{k[0]}:{k[1]}": n for k, n in sorted(results.items())},
    "by_response": dict(collections.Counter(i["intent"]["response"] for i in intents.values())),
    "overflow_rows": overflow,
    "interrupted_audit_rows": [a.get("extra") for a in audit if a.get("op") == "response_interrupted"],
    "decision_delay_before": delay(before),
    "decision_delay_after": delay(after),
    "stages_after": stages(after),
    "dispatch_after": (after or {}).get("response_dispatch"),
}
with open(os.path.join(out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1, sort_keys=True)
print(json.dumps({k: summary[k] for k in ("burst", "agent", "intents", "answered", "unanswered", "results", "by_response")}, sort_keys=True))
ok = True
if exists and not crash and summary["unanswered"]:
    ok = False; print("FAIL: intents without an outcome", unanswered[:8])
if crash:
    interrupted = [r for r in actions if r["row"] == "interrupted"]
    print("crash:", "restarted" if summary["agent"]["restarted"] else "NOT restarted",
          len(interrupted), "interrupted row(s),", len(summary["interrupted_audit_rows"]), "audit row(s)")
    if exists and (not interrupted or not summary["interrupted_audit_rows"]):
        ok = False; print("FAIL: the interrupted intent is not reported")
sys.exit(0 if ok else 1)
PY
