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
#   [--net-rate R] [--dns-rate D] [--net-port P] [--probes N]
#   [--stage-read] [--bpf-flood-procs N] [--denial-flood-procs N]
# --flood-secs 0: no flood. --stall-secs N (a lab build: debug-trigger): the
# event loop is first made to stand still N seconds
# (/run/northnarrow/debug-stall-loop, lab PR 216), and the bursts start when
# it does — the tamper queue fills and its sender waits, then drops: the
# drop's WARN, count and signed `event_bus_drop` row (the P0 path EXP-13
# itself never reaches).
# EXP-13c (review #471 A2: a lower class starved under a higher one's
# flood): --net-rate R connects a second to a listener of the lab user's on
# 127.0.0.1:P (--net-port, 18099) and --dns-rate D DNS queries a second for
# names under .example to 127.0.0.1:53 (nothing leaves the guest), in a
# unit of their own, through
# the flood; --probes N then, spread over it, N probes of each kind, each a
# new process of the lab user's in a unit of its own: a connect to
# 192.0.2.1:80 (TEST-NET-1, RFC 5737, in the shipped netflow blocklist:
# NN-L-NET-001 kills it) and a connect to the listener from a copy of the
# helper in /var/tmp (a staging directory: NN-L-CHAIN-002 / NN-L-NET-008).
# The summary counts each probe's record and its latency.
# Second review of #471: --stage-read makes the staging probe read a decoy
# GPG private key of the lab user's first (FIM credential-read rules: one
# process of the three classes — exec, file, network); --bpf-flood-procs N
# (EXP-13d) runs N loops of fork() + bpf(BPF_MAP_CREATE) as the lab user,
# --denial-flood-procs N (EXP-13e) N loops of fork() + a refused chmod of
# the target as root, through the flood's time, each in a unit of its own;
# --flood-procs 0 keeps the open flood off. The agent's threads' CPU time
# and the host's CPU pressure (/proc/pressure/cpu) are read before and
# after (cpu-before.txt, cpu-after.txt).
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
SETTLE=75 KEY= STALL=0 NET_RATE=0 DNS_RATE=0 NET_PORT=18099 PROBES=0
STAGE_READ=0 BPF_PROCS=0 DENIAL_PROCS=0
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
        --net-rate) NET_RATE=${2:?}; shift 2 ;;
        --dns-rate) DNS_RATE=${2:?}; shift 2 ;;
        --net-port) NET_PORT=${2:?}; shift 2 ;;
        --probes) PROBES=${2:?}; shift 2 ;;
        --stage-read) STAGE_READ=1; shift ;;
        --bpf-flood-procs) BPF_PROCS=${2:?}; shift 2 ;;
        --denial-flood-procs) DENIAL_PROCS=${2:?}; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
for v in FLOOD_SECS FLOOD_PROCS THREADS BURSTS BURST_SIZE BURST_GAP_MS SETTLE STALL NET_RATE DNS_RATE NET_PORT PROBES BPF_PROCS DENIAL_PROCS; do
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
install -m 0755 "$LIBEXEC/nn-exp13-flood" "$LIBEXEC/nn-exp13-net"
install -m 0755 "$LIBEXEC/nn-exp13-flood" "$LIBEXEC/nn-exp13-probe"
STAGE=
if ((PROBES > 0)); then
    STAGE=$(mktemp -d /var/tmp/nn-exp13c.XXXXXX) || die "mktemp"
    chmod 0755 "$STAGE"
    install -m 0755 "$LIBEXEC/nn-exp13-flood" "$STAGE/nn-exp13-stage"
fi

status() { "$NNADMIN" status --json --key "$KEY" > "$1" 2> "$1.err" || echo "exp13: status read failed ($1.err)" >&2; }

echo "exp13: agent $AGENT_EXE ($(sha256sum "$AGENT_EXE" | cut -c1-16)), $(nproc) cpus, flood ${FLOOD_PROCS}x${THREADS} threads ${FLOOD_SECS}s, ${BURSTS} bursts of ${BURST_SIZE} every ${BURST_GAP_MS} ms, net ${NET_RATE}/s dns ${DNS_RATE}/s probes ${PROBES}" | tee "$OUT/summary.txt"
det0=$(stat -c %s "$DET" 2>/dev/null || echo 0)
aud0=$(stat -c %s "$AUDIT" 2>/dev/null || echo 0)
# The agent's threads' CPU time (utime + stime, clock ticks) and the CPU
# pressure, for the attribution of a ring that falls behind.
cpu() {
    local pid
    pid=$(systemctl show -p MainPID --value northnarrow-agent)
    { echo "ticks $(getconf CLK_TCK) uptime $(cut -d' ' -f1 /proc/uptime)"
      cat /proc/pressure/cpu 2>/dev/null | sed 's/^/psi /'
      for t in /proc/"$pid"/task/*; do
          [[ -r $t/stat ]] || continue
          printf 'thread %s %s\n' "$(cat "$t/comm" 2>/dev/null | tr ' ' '_')" "$(awk '{print $14 + $15}' "$t/stat" 2>/dev/null)"
      done; } > "$1" 2>/dev/null
}
DECOY=
if ((STAGE_READ)); then
    home=$(getent passwd "$USER_NAME" | cut -d: -f6)
    DECOY=$home/.gnupg/private-keys-v1.d/nn-exp13-decoy.key
    runuser -u "$USER_NAME" -- mkdir -p -m 0700 "$(dirname "$DECOY")"
    runuser -u "$USER_NAME" -- bash -c "printf '(private-key (nn-exp13 decoy))\n' > '$DECOY'"
fi
status "$OUT/status-before.json"
cpu "$OUT/cpu-before.txt"
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
# EXP-13c: the network load and the probes, each in a unit of its own (a
# probe's kill ends its process, never this script).
: > "$OUT/net.txt"
: > "$OUT/probes-net001.txt"
: > "$OUT/probes-stage.txt"
units=(nn-exp13-flood.service)
if ((NET_RATE > 0 || DNS_RATE > 0)); then
    systemctl stop nn-exp13-net.service 2>/dev/null
    systemctl reset-failed nn-exp13-net.service 2>/dev/null
    systemd-run --quiet --unit=nn-exp13-net --uid="$USER_NAME" \
        -p StandardOutput="file:$OUT/net.txt" -p StandardError="file:$OUT/net.err" \
        "$LIBEXEC/nn-exp13-net" net "$((FLOOD_SECS > 0 ? FLOOD_SECS : 30))" "$NET_RATE" "$NET_PORT" "$DNS_RATE" \
        || die "the network unit did not start"
    units+=(nn-exp13-net.service)
    sleep 1
fi
if ((PROBES > 0)); then
    gap=$(( (FLOOD_SECS > 0 ? FLOOD_SECS : 30) * 700 / PROBES ))
    gap_s=$(printf '%d.%03d' $((gap / 1000)) $((gap % 1000)))
    for kind in net001 stage; do
        if [[ $kind == net001 ]]; then
            cmd="$LIBEXEC/nn-exp13-probe connect 192.0.2.1 80"
        else
            cmd="$STAGE/nn-exp13-stage connect 127.0.0.1 $NET_PORT"
            ((STAGE_READ)) && cmd="$STAGE/nn-exp13-stage readconnect $DECOY 127.0.0.1 $NET_PORT"
        fi
        systemctl stop "nn-exp13-probe-$kind.service" 2>/dev/null
        systemctl reset-failed "nn-exp13-probe-$kind.service" 2>/dev/null
        systemd-run --quiet --unit="nn-exp13-probe-$kind" --uid="$USER_NAME" \
            -p StandardOutput="file:$OUT/probes-$kind.txt" -p StandardError="file:$OUT/probes-$kind.err" \
            /bin/bash -c "for i in \$(seq 1 $PROBES); do $cmd; sleep $gap_s; done" \
            || die "the $kind probes did not start"
        units+=("nn-exp13-probe-$kind.service")
    done
fi
# EXP-13d / EXP-13e: the tamper floods P0 can be kept full with.
: > "$OUT/bpfflood.txt"
: > "$OUT/denialflood.txt"
dur=$((FLOOD_SECS > 0 ? FLOOD_SECS : 30))
if ((BPF_PROCS > 0)); then
    systemctl stop nn-exp13-bpfflood.service 2>/dev/null
    systemctl reset-failed nn-exp13-bpfflood.service 2>/dev/null
    systemd-run --quiet --unit=nn-exp13-bpfflood --uid="$USER_NAME" \
        -p StandardOutput="file:$OUT/bpfflood.txt" -p StandardError="file:$OUT/bpfflood.err" \
        "$LIBEXEC/nn-exp13-flood" bpfflood "$dur" "$BPF_PROCS" || die "the bpf flood did not start"
    units+=(nn-exp13-bpfflood.service)
fi
if ((DENIAL_PROCS > 0)); then
    systemctl stop nn-exp13-denialflood.service 2>/dev/null
    systemctl reset-failed nn-exp13-denialflood.service 2>/dev/null
    systemd-run --quiet --unit=nn-exp13-denialflood \
        -p StandardOutput="file:$OUT/denialflood.txt" -p StandardError="file:$OUT/denialflood.err" \
        "$LIBEXEC/nn-exp13-tamper" denialflood "$dur" "$DENIAL_PROCS" "$TARGET" || die "the denial flood did not start"
    units+=(nn-exp13-denialflood.service)
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
# The flood's end (and the network load's and the probes'), then the
# detection budget's reporter (60 s windows).
for u in "${units[@]}"; do
    while systemctl is-active --quiet "$u"; do sleep 1; done
done
t_flood_end=$(date +%s%N)
cpu "$OUT/cpu-flood-end.txt"
sleep "$SETTLE"
status "$OUT/status-after.json"
cpu "$OUT/cpu-after.txt"
t_end=$(date +%s%N)
tail -c +"$((det0 + 1))" "$DET" > "$OUT/detections.jsonl" 2>/dev/null
tail -c +"$((aud0 + 1))" "$AUDIT" > "$OUT/audit.jsonl" 2>/dev/null
journalctl --namespace=northnarrow -u northnarrow-agent --since "@$((t_start / 1000000000))" --no-pager -o cat > "$OUT/journal.txt" 2>/dev/null \
    || journalctl -u northnarrow-agent --since "@$((t_start / 1000000000))" --no-pager -o cat > "$OUT/journal.txt" 2>/dev/null

# Leave the host as the run found it: the COMBAT the denials raised is
# released the operator's way.
"$NNADMIN" unlock --key "$KEY" > "$OUT/unlock.txt" 2>&1 || true
[[ -n $STAGE ]] && rm -rf "$STAGE"
[[ -n $DECOY ]] && rm -f "$DECOY"

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

held, bus_rows, ring_rows, coalesced = 0, [], [], 0
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
    elif op == "event_bus_coalesced":
        coalesced += int(extra.get("repeats_since_last_row") or 0)
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
    # "aged" before review #471, "ahead" after it: a key the build lacks is None
    if p not in ba or ba[p].get(k) is None:
        return None
    return ba[p][k] - (bb.get(p, {}).get(k, 0) if k in ("enqueued", "dropped", "waited", "aged", "ahead", "decided") else 0)

def lines_of(name):
    try:
        return [l.split() for l in open(out + "/" + name, errors="replace")]
    except OSError:
        return []
recs_by_pid = {}
for line in open(out + "/detections.jsonl", errors="replace"):
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if not isinstance(r, dict):
        continue
    pid = (r.get("principal") or {}).get("pid")
    t = ts_ns(r.get("ts"))
    names = [str(r.get("rule_id", ""))] + [str(m.get("rule", "")) for m in (r.get("matches") or []) if isinstance(m, dict)]
    recs_by_pid.setdefault(pid, []).append((t, names, r.get("verdict")))
def probes(kind, rules):
    out_p = []
    for f in lines_of("probes-%s.txt" % kind):
        if len(f) in (3, 4) and f[0] == "connect":
            t0, pid = int(f[1]), int(f[2])
            hits = [(t, v) for t, names, v in recs_by_pid.get(pid, []) if any(n.startswith(rules) for n in names)]
            first = min((t for t, _ in hits if t is not None), default=None)
            out_p.append({"pid": pid, "records": len(hits),
                          "latency_ms": None if first is None else round((first - t0) / 1e6, 1)})
    killed = sum(1 for l in lines_of("probes-%s.err" % kind) if "Killed" in l)
    return {"sent": len(out_p), "judged": sum(1 for p in out_p if p["records"]), "killed_while_connecting": killed, "probes": out_p}
net_line = next((f for f in lines_of("net.txt") if len(f) == 4 and f[0] == "net"), None)

def per_class(kind, classes):
    """For each probe of `kind`, which classes of its events were judged."""
    out_c = {c: 0 for c in classes}
    sent = 0
    for f in lines_of("probes-%s.txt" % kind):
        if len(f) in (3, 4) and f[0] == "connect":
            sent += 1
            names = [n for _, ns, _ in recs_by_pid.get(int(f[2]), []) for n in ns]
            for c, prefixes in classes.items():
                if any(n.startswith(prefixes) for n in names):
                    out_c[c] += 1
    return {"sent": sent, "judged": out_c}

def cpu_read(name):
    th, psi, ticks = {}, {}, 100
    for f in lines_of(name):
        if f and f[0] == "ticks":
            ticks = int(f[1])
        elif f and f[0] == "thread" and len(f) == 3:
            th[f[1]] = th.get(f[1], 0) + int(f[2])
        elif f and f[0] == "psi" and len(f) >= 6:
            psi[f[1]] = {k: float(v) for k, v in (x.split("=") for x in f[2:])}
    return th, psi, ticks

def cpu_delta(a, b):
    ta, pa, ticks = cpu_read(a)
    tb, pb, _ = cpu_read(b)
    threads = {k: round((tb.get(k, 0) - ta.get(k, 0)) / ticks, 2) for k in set(ta) | set(tb)}
    threads = dict(sorted(((k, v) for k, v in threads.items() if v > 0), key=lambda kv: -kv[1]))
    psi = {k: {"total_ms": round((pb[k]["total"] - pa.get(k, {}).get("total", 0)) / 1000), "avg10_after": pb[k].get("avg10")} for k in pb}
    return {"agent_cpu_s_by_thread": threads, "agent_cpu_s": round(sum(threads.values()), 2), "cpu_pressure": psi}

def helper_line(name, tag):
    f = next((f for f in lines_of(name) if f and f[0] == tag), None)
    return None if f is None else [int(x) for x in f[1:]]
ring_names = sorted(set((before or {}).get("ringbuf_drops") or {}) | set((after or {}).get("ringbuf_drops") or {}))

summary = {
    "net_load": None if net_line is None else {"connected": int(net_line[1]), "failed": int(net_line[2]), "dns_sent": int(net_line[3])},
    "probes_net001": probes("net001", ("NN-L-NET-001",)),
    "probes_stage": probes("stage", ("NN-L-CHAIN-002", "NN-L-NET-008")),
    "probes_stage_by_class": per_class("stage", {"exec": ("R00",), "file": ("NN-L-FIM-",), "net": ("NN-L-CHAIN-", "NN-L-NET-008")}),
    "bpfflood": helper_line("bpfflood.txt", "bpfflood"),
    "denialflood": helper_line("denialflood.txt", "denialflood"),
    "cpu_flood": cpu_delta("cpu-before.txt", "cpu-flood-end.txt"),
    "ring_drops_delta_all": {r: delta(r) for r in ring_names},
    "attempts_refused": attempts, "attempts_allowed": allowed, "tamper_rc": tamper_rc,
    "at001_records": len(recs), "at001_suppressed_before": suppressed, "at001_held_reported": held,
    "at001_coalesced": coalesced,
    "at001_accounted": len(recs) + held + coalesced,
    "ring_drops_delta": {r: delta(r) for r in ("fs_protect", "open_sensor", "task_denial_rate", "exec", "fim")},
    "first_record_latency_ms": lat,
    "event_bus": None if not ba else {p: {k: qd(p, k) for k in ("enqueued", "dropped", "waited", "aged", "ahead", "decided", "max_depth", "max_wait_us", "recent_max_wait_us", "send_wait_max_us", "latency_p50_us", "latency_p99_us", "latency_max_us")} for p in sorted(ba)},
    "event_bus_drop_rows": bus_rows, "ringbuf_drop_rows": ring_rows,
    "flood": open(out + "/flood.txt").read().split("\n") if True else None,
    "flood_secs_measured": round((t_flood_end - t_start) / 1e9, 1),
}
json.dump(summary, open(out + "/summary.json", "w"), indent=1)
print("refused attempts   :", attempts, "(allowed:", allowed, ")")
print("AT-001 recorded    :", len(recs), "records +", held, "held (budget, signed detections_held) +", coalesced, "coalesced (signed event_bus_coalesced) =", len(recs) + held + coalesced)
print("ring drops (delta) :", summary["ring_drops_delta"])
print("first record (ms)  :", lat)
if summary["event_bus"]:
    for p, v in summary["event_bus"].items():
        print("bus", p, ":", v)
else:
    print("bus                : (this agent has no event bus)")
print("event_bus_drop rows:", len(bus_rows), "ringbuf_drop rows:", len(ring_rows))
print("flood              :", " | ".join(x for x in summary["flood"] if x))
if summary["net_load"] or summary["probes_net001"]["sent"]:
    print("net load           :", summary["net_load"])
    for k in ("probes_net001", "probes_stage"):
        v = summary[k]
        print(k.ljust(19) + ":", v["judged"], "of", v["sent"], "judged,", v["killed_while_connecting"], "killed while connecting; latency ms", [p["latency_ms"] for p in v["probes"]])
    print("ring drops (all)   :", summary["ring_drops_delta_all"])
    print("stage by class     :", summary["probes_stage_by_class"])
if summary["bpfflood"] or summary["denialflood"]:
    print("bpf flood          :", summary["bpfflood"], "(children, refused, allowed, other)")
    print("denial flood       :", summary["denialflood"], "(children, refused, allowed, other)")
print("agent CPU (flood)  :", summary["cpu_flood"]["agent_cpu_s"], "s;", list(summary["cpu_flood"]["agent_cpu_s_by_thread"].items())[:6])
print("CPU pressure       :", summary["cpu_flood"]["cpu_pressure"])
PY
echo "exp13: results in $OUT"
