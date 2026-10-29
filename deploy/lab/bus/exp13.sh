#!/usr/bin/env bash
# EXP-13 (lab PR 267, R12a; plan §3.4, R12): a flood of file opens in a test
# cgroup and, at the same time, bursts of tamper attempts on the agent's
# protected files. Before R12a every source shared one queue: the opens
# filled it, the fs_protect pump waited behind them and its ring dropped
# the tamper records, or they reached the rules seconds late. With the
# priority bus the tamper class (P0) is taken first and its pump never
# waits on the opens (P2).
#
# Runs ON a lab guest, as root, against the installed agent (`nn-lab.sh
# ssh 'sudo bash ~/northnarrow/deploy/lab/bus/exp13.sh'`). Benign: the flood
# is the lab user's read-only opens of world-readable files the file-open
# sensor reports (/etc/passwd, /etc/login.defs), each from a new thread (the
# kernel drops a task's repeated read within a second, review 75), in a
# transient unit of its own (its cgroup, CPUQuota); the tamper attempts are
# chmod()s of /etc/northnarrow/admin.pub to the mode it already has, which
# the deny hook refuses (and which change nothing if it did not). The
# anti-tamper denials put the agent in a locked COMBAT (kernel-adjudicated):
# the run unlocks it at the end with the lab's admin key, as the operator
# would.
#
# Usage: exp13.sh [--out DIR] [--flood-secs S] [--flood-procs P]
#   [--threads T] [--bursts B] [--burst-size K] [--burst-gap-ms G]
#   [--settle S] [--key FILE] [--stall-secs N]
# --flood-secs 0: no flood. --stall-secs N (a lab build: debug-trigger): the
# event loop is first made to stand still N seconds
# (/run/northnarrow/debug-stall-loop, lab PR 216), and the bursts start when
# it does — the tamper queue fills and its sender waits, then drops: the
# drop's WARN, count and signed `event_bus_drop` row (the P0 path EXP-13
# itself never reaches).
# Output (DIR, default /var/lib/nn-exp13/<UTC stamp>): status-before.json,
# status-after.json (`nn-admin status --json --key`), tamper.txt (one line
# per burst), flood.txt, detections.jsonl (the new detection records),
# audit.jsonl (the new audit rows), summary.json and summary.txt.
# Exit: 0 measured, 1 a measurement is missing, 2 usage or not a lab guest.
set -u -o pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL=C

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT= FLOOD_SECS=40 FLOOD_PROCS=4 THREADS=32 BURSTS=8 BURST_SIZE=1500 BURST_GAP_MS=3000
SETTLE=75 KEY= STALL=0
DET=/var/lib/northnarrow/detections/detections.jsonl
AUDIT=/etc/northnarrow/audit.log
TARGET=/etc/northnarrow/admin.pub
MARKER=/var/lib/nn-lab-provisioned
LIBEXEC=/usr/local/libexec/nn-lab/exp13

die() { echo "exp13: $*" >&2; exit 2; }
while (($#)); do
    case "$1" in
        --out) OUT=${2:?}; shift 2 ;;
        --flood-secs) FLOOD_SECS=${2:?}; shift 2 ;;
        --flood-procs) FLOOD_PROCS=${2:?}; shift 2 ;;
        --threads) THREADS=${2:?}; shift 2 ;;
        --bursts) BURSTS=${2:?}; shift 2 ;;
        --burst-size) BURST_SIZE=${2:?}; shift 2 ;;
        --burst-gap-ms) BURST_GAP_MS=${2:?}; shift 2 ;;
        --settle) SETTLE=${2:?}; shift 2 ;;
        --key) KEY=${2:?}; shift 2 ;;
        --stall-secs) STALL=${2:?}; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
for v in FLOOD_SECS FLOOD_PROCS THREADS BURSTS BURST_SIZE BURST_GAP_MS SETTLE STALL; do
    [[ ${!v} =~ ^[0-9]+$ ]] || die "--${v,,} takes a whole number: ${!v}"
done
(($(id -u) == 0)) || die "run as root"
[[ -e $MARKER || ${NN_TEST_DISPOSABLE_HOST:-} == 1 ]] || die "not an nn-lab guest ($MARKER missing)"
for b in cc python3 systemd-run systemctl runuser; do
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
[[ -e $TARGET ]] || die "no $TARGET"
USER_NAME=${SUDO_USER:-nn}
id "$USER_NAME" >/dev/null 2>&1 || die "no user $USER_NAME for the flood"
OUT=${OUT:-/var/lib/nn-exp13/$(date -u +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"

# The helpers: root-owned, outside any user-writable or staging directory
# (R001/R009 would kill a root exec from one); two names, one per role.
install -d -m 0755 "$LIBEXEC"
cc -O2 -pthread -o "$LIBEXEC/nn-exp13-flood" "$SCRIPT_DIR/nn-exp13.c" || die "cc failed"
install -m 0755 "$LIBEXEC/nn-exp13-flood" "$LIBEXEC/nn-exp13-tamper"

status() { "$NNADMIN" status --json --key "$KEY" > "$1" 2> "$1.err" || echo "exp13: status read failed ($1.err)" >&2; }

echo "exp13: agent $AGENT_EXE ($(sha256sum "$AGENT_EXE" | cut -c1-16)), $(nproc) cpus, flood ${FLOOD_PROCS}x${THREADS} threads ${FLOOD_SECS}s, ${BURSTS} bursts of ${BURST_SIZE} every ${BURST_GAP_MS} ms" | tee "$OUT/summary.txt"
det0=$(stat -c %s "$DET" 2>/dev/null || echo 0)
aud0=$(stat -c %s "$AUDIT" 2>/dev/null || echo 0)
status "$OUT/status-before.json"
t_start=$(date +%s%N)

# The flood, in a transient unit of its own: its cgroup, at most 3 CPUs.
: > "$OUT/flood.txt"
if ((FLOOD_SECS > 0)); then
    systemctl stop nn-exp13-flood.service 2>/dev/null
    systemctl reset-failed nn-exp13-flood.service 2>/dev/null
    systemd-run --quiet --unit=nn-exp13-flood --uid="$USER_NAME" -p CPUQuota=300% \
        -p StandardOutput="file:$OUT/flood.txt" -p StandardError="file:$OUT/flood.err" \
        /bin/bash -c "for i in \$(seq 1 $FLOOD_PROCS); do $LIBEXEC/nn-exp13-flood flood $FLOOD_SECS $THREADS /etc/passwd /etc/login.defs & done; wait" \
        || die "the flood unit did not start"
    sleep 5
fi
# A lab build's stalled loop: the trigger is read at the loop's next 5 s
# check, which removes it and stands still.
if ((STALL > 0)); then
    echo "$STALL" > /run/northnarrow/debug-stall-loop || die "cannot write the stall trigger"
    for _ in $(seq 1 100); do [[ -e /run/northnarrow/debug-stall-loop ]] || break; sleep 0.1; done
    [[ -e /run/northnarrow/debug-stall-loop ]] && { rm -f /run/northnarrow/debug-stall-loop; die "the trigger was not taken (not a debug-trigger build?)"; }
fi
# The tamper bursts, in the flood.
"$LIBEXEC/nn-exp13-tamper" tamper "$BURSTS" "$BURST_SIZE" "$BURST_GAP_MS" "$TARGET" > "$OUT/tamper.txt" 2> "$OUT/tamper.err"
tamper_rc=$?
# The flood's end, then the detection budget's reporter (60 s windows).
while systemctl is-active --quiet nn-exp13-flood.service; do sleep 1; done
t_flood_end=$(date +%s%N)
sleep "$SETTLE"
status "$OUT/status-after.json"
t_end=$(date +%s%N)
tail -c +"$((det0 + 1))" "$DET" > "$OUT/detections.jsonl" 2>/dev/null
tail -c +"$((aud0 + 1))" "$AUDIT" > "$OUT/audit.jsonl" 2>/dev/null
journalctl --namespace=northnarrow -u northnarrow-agent --since "@$((t_start / 1000000000))" --no-pager -o cat > "$OUT/journal.txt" 2>/dev/null \
    || journalctl -u northnarrow-agent --since "@$((t_start / 1000000000))" --no-pager -o cat > "$OUT/journal.txt" 2>/dev/null

# Leave the host as the run found it: the COMBAT the denials raised is
# released the operator's way.
"$NNADMIN" unlock --key "$KEY" > "$OUT/unlock.txt" 2>&1 || true

python3 -I - "$OUT" "$t_start" "$t_flood_end" "$t_end" "$tamper_rc" <<'PY' | tee -a "$OUT/summary.txt"
import json, sys, calendar, time
out, t_start, t_flood_end, t_end, tamper_rc = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])

def load(p):
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return None

def ts_ns(ts):
    if not isinstance(ts, str) or not ts.endswith("Z"):
        return None
    base, _, frac = ts[:-1].partition(".")
    try:
        t = time.strptime(base, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    return calendar.timegm(t) * 1_000_000_000 + int((frac + "000000000")[:9] or 0)

before, after = load(out + "/status-before.json"), load(out + "/status-after.json")
def drops(s, ring):
    return None if s is None else int((s.get("ringbuf_drops") or {}).get(ring, 0))
def delta(ring):
    a, b = drops(before, ring), drops(after, ring)
    return None if a is None or b is None else b - a

bursts = []
for line in open(out + "/tamper.txt"):
    f = line.split()
    if len(f) == 6 and f[0] == "burst":
        bursts.append({"n": int(f[1]), "t0": int(f[2]), "t1": int(f[3]), "refused": int(f[4]), "allowed": int(f[5])})
attempts = sum(b["refused"] for b in bursts)
allowed = sum(b["allowed"] for b in bursts)

recs, suppressed = [], 0
for line in open(out + "/detections.jsonl", errors="replace"):
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if not isinstance(r, dict) or not str(r.get("rule_id", "")).startswith("NN-L-AT-001"):
        continue
    t = ts_ns(r.get("ts"))
    if t is None or t < t_start:
        continue
    recs.append(t)
    suppressed += int(r.get("suppressed_before") or 0)
recs.sort()

held, bus_rows, ring_rows = 0, [], []
for line in open(out + "/audit.jsonl", errors="replace"):
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if not isinstance(r, dict):
        continue
    e = r.get("entry", r)
    op, extra = e.get("op"), e.get("extra") or {}
    if op == "detections_held":
        for h in extra.get("held", []) if isinstance(extra.get("held"), list) else [extra]:
            if str(h.get("rule", "")).startswith("NN-L-AT-001"):
                held += int(h.get("count") or 0)
    elif op == "event_bus_drop":
        bus_rows.append(extra)
    elif op == "ringbuf_drop":
        ring_rows.append(extra)

# Each burst's first record: how long the first refused attempt waited to
# be judged and recorded behind the flood.
lat = []
for b in bursts:
    first = next((t for t in recs if t >= b["t0"]), None)
    lat.append(None if first is None else round((first - b["t0"]) / 1e6, 3))

def bus(s):
    q = ((s or {}).get("event_bus") or {}).get("queues") or []
    return {x["priority"]: x for x in q}
bb, ba = bus(before), bus(after)
def qd(p, k):
    if p not in ba:
        return None
    return ba[p][k] - (bb.get(p, {}).get(k, 0) if k in ("enqueued", "dropped", "waited", "aged", "decided") else 0)

summary = {
    "attempts_refused": attempts, "attempts_allowed": allowed, "tamper_rc": tamper_rc,
    "at001_records": len(recs), "at001_suppressed_before": suppressed, "at001_held_reported": held,
    "at001_accounted": len(recs) + held,
    "ring_drops_delta": {r: delta(r) for r in ("fs_protect", "open_sensor", "task_denial_rate", "exec", "fim")},
    "first_record_latency_ms": lat,
    "event_bus": None if not ba else {p: {k: qd(p, k) for k in ("enqueued", "dropped", "waited", "aged", "decided", "max_depth", "max_wait_us", "latency_p50_us", "latency_p99_us", "latency_max_us")} for p in sorted(ba)},
    "event_bus_drop_rows": bus_rows, "ringbuf_drop_rows": ring_rows,
    "flood": open(out + "/flood.txt").read().split("\n") if True else None,
    "flood_secs_measured": round((t_flood_end - t_start) / 1e9, 1),
}
json.dump(summary, open(out + "/summary.json", "w"), indent=1)
print("refused attempts   :", attempts, "(allowed:", allowed, ")")
print("AT-001 recorded    :", len(recs), "records +", held, "held (budget, signed detections_held) =", len(recs) + held)
print("ring drops (delta) :", summary["ring_drops_delta"])
print("first record (ms)  :", lat)
if summary["event_bus"]:
    for p, v in summary["event_bus"].items():
        print("bus", p, ":", v)
else:
    print("bus                : (this agent has no event bus)")
print("event_bus_drop rows:", len(bus_rows), "ringbuf_drop rows:", len(ring_rows))
print("flood              :", " | ".join(x for x in summary["flood"] if x))
PY
echo "exp13: results in $OUT"
