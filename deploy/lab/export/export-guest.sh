#!/usr/bin/env bash
# Lot 276: the export on an nn-lab guest — run as root ON THE GUEST against
# the installed agent, a local syslog-over-TLS receiver (the lab's own,
# crates/nn-export/examples/syslog_receiver.rs, built in the guest's tree).
# Our own lab guests only.
#
# usage: export-guest.sh <out-dir> <phase>...  (setup arrive outage hostile slow stall rotate rewritten protected outcome shrink cost off)
#
#   setup   — a lab CA and a receiver certificate (receiver.lab, 127.0.0.1),
#             the receiver up (honest), the signed export.local (both sinks,
#             the five chains, start = oldest), the agent restarted in a
#             trusted-installer window; the worker as the kernel sees it
#             (its account, no capability, its seccomp, its Landlock rules,
#             the port pinned where the kernel's ABI handles TCP).
#   arrive  — events (execs from /tmp, connects, a canary-free host); once
#             the export caught up: every record of the capture and of the
#             JSONL file verifies with the agent's public key
#             (`nn-admin export verify`), and every data row of the five
#             chains (archives included) is in both, none that is not.
#   outage  — the receiver killed while rows flow, events with it down (the
#             syslog sink down, the file sink up, the agent's detections
#             unaffected), the receiver back: every row arrives, the
#             duplicates counted (at least once).
#   hostile — receivers that stay silent, answer garbage, send data: in
#             each, a burst of execs is detected as with an honest one,
#             the decision's delay (stage 5) does not move, the worker is
#             not killed as hung; the sink's fault named; then honest
#             again: no row lost.
#   slow, stall — a receiver that reads 512 bytes a second, one that takes
#             the TLS session and never reads: the same checks; then it
#             dies. What its kernel acknowledged and it had not read is
#             lost — RFC 5425 has no application acknowledgement
#             (EXPORT.md §8): the loss is measured, and must be rows
#             written while that receiver held the connection only.
#   cost    — the export's own CPU (its worker, the core's nn-export thread)
#             over a flow-heavy minute, and the rows a second it delivered.
#   off     — the overlay removed, the agent restarted: no export worker.
# Each check prints PASS or FAIL into <out-dir>/steps.tsv; the exit status
# is the number of FAILs.
set -u
OUT=${1:?out dir}
shift
mkdir -p "$OUT"
TREE=${TREE:-/home/nn/northnarrow}
KEY=/root/northnarrow-admin.key
NNADMIN=/usr/local/bin/nn-admin
LAB=/var/lib/nn-export-lab
PKI=$LAB/pki
CAP=$LAB/capture.log
RECV_SRC=$TREE/target/release/examples/syslog_receiver
# run from a root-owned path, not the lab user's tree
RECV_BIN=/usr/local/libexec/nn-lab/syslog_receiver
PORT=${PORT:-6514}
EXPORT_DIR=/var/log/northnarrow/export
STATE=/var/lib/northnarrow
fails=0
TSV=$OUT/steps.tsv
[ -f "$TSV" ] || printf 'phase\tstep\tat\tresult\n' > "$TSV"
PHASE=-
note() { printf '%s\t%s\t%s\t%s\n' "$PHASE" "$1" "$(date -u +%FT%T.%3NZ)" "$2" >> "$TSV"; }
pass() { echo "PASS $1: $2"; note "$1" "ok: $2"; }
fail() { echo "FAIL $1: $2"; note "$1" "FAIL: $2"; fails=$((fails + 1)); }
check() { local n=$1 w=$2; shift 2; if "$@"; then pass "$n" "$w"; else fail "$n" "$w"; fi; }

agent_pid() { cat /run/northnarrow/agent.pid 2>/dev/null; }
# the export worker: the agent's child named nn-worker-exp (never a match by
# a command line: the workers run the agent's binary)
worker_pid() { ps --ppid "$(agent_pid)" -o pid=,comm= 2>/dev/null | awk '$2 == "nn-worker-exp" {print $1; exit}'; }
status_json() { "$NNADMIN" export status --json --key "$KEY" 2>/dev/null; }
# the agent's own journal (its namespace) and systemd's lines about its unit
agent_journal() { journalctl --namespace=northnarrow --no-pager "$@" 2>/dev/null; }
bus_json() { "$NNADMIN" status --json --key "$KEY" 2>/dev/null; }

# the agent restarted inside a trusted-installer window (its unit refuses a
# manual stop), and settled
restart_agent() {
    local old new
    old=$(agent_pid)
    "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 60 >/dev/null 2>&1
    systemctl kill -s SIGTERM northnarrow-agent
    for _ in $(seq 1 90); do
        sleep 1
        new=$(agent_pid)
        [[ -n $new && $new != "$old" ]] && kill -0 "$new" 2>/dev/null && break
    done
    systemctl is-active --quiet northnarrow-agent || { systemctl reset-failed northnarrow-agent; systemctl start northnarrow-agent; }
    for _ in $(seq 1 60); do
        "$NNADMIN" status >/dev/null 2>&1 && break
        sleep 1
    done
    sleep 15
    echo "agent $old -> $(agent_pid)"
}

receiver() {   # <mode>
    systemctl stop nn-export-recv 2>/dev/null
    systemctl reset-failed nn-export-recv 2>/dev/null
    systemd-run --quiet --unit nn-export-recv --collect -p StandardError=append:"$OUT/receiver.log" \
        "$RECV_BIN" --listen "127.0.0.1:$PORT" --cert "$PKI/srv.pem" --key "$PKI/srv.key" \
        --out "$CAP" --mode "$1"
    sleep 1
}

# every data row of the five chains (archives too), by entry_hash
chain_rows() {
    python3 -I - "$STATE" <<'PY'
import glob, json, os, re, sys
st = sys.argv[1]
chains = {
    "detections": st + "/detections/detections.jsonl",
    "actions": st + "/detections/actions.jsonl",
    "fim_drift": st + "/fim_drift.jsonl",
    "netflow": st + "/netflow.jsonl",
    "canary_access": st + "/canary_access.jsonl",
}
out = {}
for c, active in chains.items():
    files = sorted(f for f in glob.glob(active + ".*") if re.search(r"\.\d{6,}$", f))
    files.append(active)
    hs = set()
    for f in files:
        try:
            for l in open(f, "rb"):
                l = l.rstrip(b"\n")
                if not l or l.startswith(b'{"rotate":') or l.startswith(b'{"manifest":'):
                    continue
                m = re.search(rb',"entry_hash":"([0-9a-f]{64})","agent_sig":"[^"]*"}$', l)
                if m:
                    hs.add(m.group(1).decode())
        except FileNotFoundError:
            pass
    out[c] = sorted(hs)
json.dump(out, sys.stdout)
PY
}

# the rows of a set of records (capture lines, JSONL lines), by chain
record_rows() {   # <file>...
    python3 -I - "$@" <<'PY'
import json, sys, re
out = {}
dup = 0
seen = set()
for f in sys.argv[1:]:
    for line in open(f, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        i = line.find("{")
        if i < 0:
            continue
        try:
            v = json.loads(line[i:])
        except Exception:
            continue
        r = v.get("unmapped", {}).get("northnarrow", {}).get("row", {})
        c, h = r.get("chain"), r.get("entry_hash")
        if not c or not h:
            continue
        uid = v.get("metadata", {}).get("uid")
        if uid in seen:
            dup += 1
        seen.add(uid)
        out.setdefault(c, set()).add(h)
json.dump({"rows": {c: sorted(s) for c, s in out.items()}, "duplicates": dup}, sys.stdout)
PY
}

# chain rows missing from the records, and records of no chain row
compare() {   # <label> <records json>
    python3 -I - "$1" "$2" "$OUT/chains.json" <<'PY'
import json, sys
label, recs, chains = sys.argv[1], json.load(open(sys.argv[2])), json.load(open(sys.argv[3]))
rows = recs["rows"]
missing = extra = total = 0
for c, hs in chains.items():
    got = set(rows.get(c, []))
    want = set(hs)
    total += len(want)
    missing += len(want - got)
    extra += len(got - want)
    print(f"{label} {c}: chain {len(want)} rows, records of {len(got)}, missing {len(want - got)}, extra {len(got - want)}")
print(f"{label} total: chain {total} rows, missing {missing}, extra {extra}, duplicate records {recs['duplicates']}")
sys.exit(0 if missing == 0 and extra == 0 else 1)
PY
}

# the export caught up: every chain of both sinks 0 bytes behind, nothing in flight
caught_up() {   # <secs>
    local n=$1
    for _ in $(seq 1 "$n"); do
        if status_json | python3 -I -c '
import json,sys
e = json.load(sys.stdin)["export"]
ok = e and all(k["state"] == "up" and all(c["behind_bytes"] == 0 and c["in_flight"] == 0 for c in k["chains"]) for k in e["sinks"])
sys.exit(0 if ok else 1)'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# <execs from /tmp> <loopback connects> [benign execs]: detections (a few:
# the posture is not driven to COMBAT, whose isolation would cut the lab's
# ssh), flows, and decisions the decision thread judges
events() {
    local i
    cp /bin/true /tmp/nn-export-lab-x
    for i in $(seq 1 "$1"); do /tmp/nn-export-lab-x 2>/dev/null; sleep 0.2; done
    for i in $(seq 1 "$2"); do (exec 3<>/dev/tcp/127.0.0.1/22 && exec 3>&-) 2>/dev/null; done
    for i in $(seq 1 "${3:-0}"); do /usr/bin/true; done
    rm -f /tmp/nn-export-lab-x
}

stage5() { bus_json | python3 -I -c '
import json,sys
s = json.load(sys.stdin)
print(sum(q.get("over_budget", 0) for q in (s.get("event_bus_decision") or {}).get("queues", [])))'; }

detections_rows() { cat "$STATE"/detections/detections.jsonl "$STATE"/detections/detections.jsonl.[0-9]* 2>/dev/null | grep -c '"rule_id"'; }

verify() {   # <name> <file>
    "$NNADMIN" export verify --agent-pubkey-file /etc/northnarrow/agent.sig.pub --file "$2" > "$OUT/verify-$1.txt" 2>&1
    local rc=$?
    tail -1 "$OUT/verify-$1.txt"
    return $rc
}

phase_setup() {
    mkdir -p "$PKI"
    : > "$CAP"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$PKI/ca.key" 2>/dev/null
    openssl req -x509 -key "$PKI/ca.key" -out "$PKI/ca.pem" -days 30 -subj "/CN=nn-export lab CA" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$PKI/srv.key" 2>/dev/null
    openssl req -new -key "$PKI/srv.key" -out "$PKI/srv.csr" -subj "/CN=receiver.lab" 2>/dev/null
    printf 'subjectAltName=DNS:receiver.lab,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n' > "$PKI/ext.cnf"
    openssl x509 -req -in "$PKI/srv.csr" -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" -CAcreateserial \
        -out "$PKI/srv.pem" -days 30 -extfile "$PKI/ext.cnf" 2>/dev/null
    check pki "a lab CA and receiver.lab's certificate" test -s "$PKI/srv.pem"
    check receiver-built "the lab receiver is built" test -x "$RECV_SRC"
    install -D -m 0755 -o root -g root "$RECV_SRC" "$RECV_BIN"
    receiver honest
    check receiver-up "the receiver listens on 127.0.0.1:$PORT" bash -c "ss -ltn | grep -q '127.0.0.1:$PORT'"
    # /etc/northnarrow is the agent's: its CA goes in inside a window
    "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 60 >/dev/null 2>&1
    install -m 0644 "$PKI/ca.pem" /etc/northnarrow/export-ca.pem
    check ca-installed "the CA in /etc/northnarrow, inside a window" cmp -s "$PKI/ca.pem" /etc/northnarrow/export-ca.pem
    local sha
    sha=$(sha256sum /etc/northnarrow/export-ca.pem | cut -d' ' -f1)
    cat > "$LAB/export.local" <<EOF
# lot 276 lab
enabled = true
# the five, each named: flows, file drift and canary reads are opt-in
chain = detections
chain = actions
chain = fim_drift
chain = netflow
chain = canary_access
start = oldest
file = on
file_max_bytes = 64MiB
file_max_files = 8
syslog = 127.0.0.1:$PORT
syslog_server_name = receiver.lab
syslog_ca = /etc/northnarrow/export-ca.pem
syslog_ca_sha256 = $sha
EOF
    "$NNADMIN" config overlay set export --file "$LAB/export.local" --key "$KEY" > "$OUT/overlay-set.txt" 2>&1
    check overlay-set "the signed export.local stored by the agent" grep -q . /etc/northnarrow/export.local.sig
    restart_agent > "$OUT/restart.txt" 2>&1
    sleep 5
    status_json > "$OUT/status-setup.json"
    check export-on "the export is on, its worker ready" python3 -I -c '
import json,sys
e = json.load(open(sys.argv[1]))["export"]
sys.exit(0 if e["state"] == "on" and e["worker"] == "ready" else 1)' "$OUT/status-setup.json"
    local w
    w=$(worker_pid)
    check worker-process "an nn-worker-exp process, child of the agent" test -n "$w"
    if [ -n "$w" ]; then
        grep -E '^(Uid|Gid|Groups|NoNewPrivs|Seccomp|CapInh|CapPrm|CapEff|CapAmb):' "/proc/$w/status" > "$OUT/worker-status.txt"
        check worker-account "the worker runs as northnarrow-export (its own account)" bash -c "[ \"\$(stat -c %U /proc/$w)\" = northnarrow-export ]"
        check export-dir "the export directory is the export account's alone to write" bash -c "[ \"\$(stat -c %U:%a $EXPORT_DIR)\" = northnarrow-export:755 ]"
        check worker-nnp "no_new_privs, seccomp filter, no capability" bash -c "grep -q 'NoNewPrivs:.1' '$OUT/worker-status.txt' && grep -q 'Seccomp:.2' '$OUT/worker-status.txt' && grep -q 'CapEff:.0000000000000000' '$OUT/worker-status.txt'"
        check worker-parent "its parent is the agent" bash -c "[ \"\$(ps -o ppid= -p $w | tr -d ' ')\" = \"$(agent_pid)\" ]"
        ls -l "/proc/$w/fd" > "$OUT/worker-fds.txt" 2>&1
    fi
    "$NNADMIN" capabilities --json --key "$KEY" > "$OUT/capabilities.json" 2>&1
    local abi
    abi=$(python3 -I -c '
import json,sys
m = json.load(open(sys.argv[1]))["manifest"]
w = [x for x in m.get("workers", []) if x["kind"] == "export"]
print(w[0]["kernel_landlock_abi"] if w else -1)' "$OUT/capabilities.json")
    echo "kernel landlock abi: $abi" | tee "$OUT/landlock-abi.txt"
    check manifest-export "the manifest's export entry and the worker's directory rule" python3 -I -c '
import json,sys
m = json.load(open(sys.argv[1]))["manifest"]
e = m.get("export") or {}
w = [x for x in m.get("workers", []) if x["kind"] == "export"]
rules = (w[0].get("sandbox") or {}).get("fs_rules", []) if w else []
abi = w[0]["kernel_landlock_abi"] if w else 0
ok = e.get("state") == "on" and e.get("ocsf_version") == "1.9.0" and (abi == 0 or rules == ["/var/log/northnarrow/export: read, write, create, remove, truncate"])
pin = e.get("port_pinned")
ok = ok and (pin is True if abi >= 4 else pin is False)
print("export", e, "rules", rules, "abi", abi)
sys.exit(0 if ok else 1)' "$OUT/capabilities.json"
}

phase_arrive() {
    events 5 40
    sleep 3
    # start = oldest: the chains' whole history first
    check caught-up "both sinks caught up within 600 s" caught_up 600
    status_json > "$OUT/status-arrive.json"
    chain_rows > "$OUT/chains.json"
    check verify-capture "every received record verifies (agent key, chain continuity)" verify capture "$CAP"
    cat "$EXPORT_DIR"/export.jsonl.[0-9]* "$EXPORT_DIR"/export.jsonl 2>/dev/null > "$OUT/jsonl-all.txt"
    check verify-file "every JSONL record verifies" verify file "$OUT/jsonl-all.txt"
    record_rows "$CAP" > "$OUT/recs-capture.json"
    record_rows "$OUT/jsonl-all.txt" > "$OUT/recs-file.json"
    compare capture "$OUT/recs-capture.json" > "$OUT/compare-arrive-capture.txt"
    check rows-capture "every chain row arrived at the receiver, none other" test $? -eq 0
    compare file "$OUT/recs-file.json" > "$OUT/compare-arrive-file.txt"
    check rows-file "every chain row is in the JSONL files, none other" test $? -eq 0
    cat "$OUT/compare-arrive-capture.txt" "$OUT/compare-arrive-file.txt"
}

phase_outage() {
    local before
    before=$(detections_rows)
    ( events 5 60 ) &
    local gen=$!
    sleep 1
    systemctl kill -s SIGKILL nn-export-recv 2>/dev/null
    wait $gen
    events 3 20
    sleep 4
    status_json > "$OUT/status-outage.json"
    check outage-down "the syslog sink is down, the file sink up" python3 -I -c '
import json,sys
e = json.load(open(sys.argv[1]))["export"]
s = {k["sink"]: k for k in e["sinks"]}
sys.exit(0 if s["syslog"]["state"] in ("down", "connecting") and s["file"]["state"] == "up" else 1)' "$OUT/status-outage.json"
    check outage-detects "the agent detected the execs during the outage" bash -c "[ $(detections_rows) -gt $before ]"
    sleep 20
    receiver honest
    check outage-caught-up "both sinks caught up within 180 s of the receiver's return" caught_up 180
    status_json > "$OUT/status-after-outage.json"
    chain_rows > "$OUT/chains.json"
    check verify-capture-outage "every received record verifies after the outage" verify capture-outage "$CAP"
    record_rows "$CAP" > "$OUT/recs-capture-outage.json"
    compare capture-after-outage "$OUT/recs-capture-outage.json" > "$OUT/compare-outage.txt"
    check outage-no-loss "no row lost through the outage (duplicates counted)" test $? -eq 0
    cat "$OUT/compare-outage.txt"
}

phase_hostile() { hostile_modes silent garbage chatty; }

hostile_modes() {
    local m before after s5a s5b
    for m in "$@"; do
        receiver "$m"
        sleep 2
        before=$(detections_rows)
        s5a=$(stage5)
        local t0 t1
        t0=$(date +%s%N)
        events 4 40 300
        t1=$(date +%s%N)
        sleep 8
        after=$(detections_rows)
        s5b=$(stage5)
        status_json > "$OUT/status-hostile-$m.json"
        check "hostile-$m-detects" "receiver $m: the execs detected ($before -> $after), the burst took $(( (t1 - t0) / 1000000 )) ms" bash -c "[ $after -ge $((before + 4)) ]"
        check "hostile-$m-decision" "receiver $m: stage 5 over-budget $s5a -> $s5b" bash -c "[ ${s5b:-0} -le $(( ${s5a:-0} + 2 )) ]"
        check "hostile-$m-worker" "receiver $m: the worker still ready (not killed as hung)" python3 -I -c '
import json,sys
e = json.load(open(sys.argv[1]))["export"]
print(e["worker"], [(k["sink"], k["state"], k["fault"]) for k in e["sinks"]])
sys.exit(0 if e["worker"] == "ready" else 1)' "$OUT/status-hostile-$m.json"
    done
    receiver honest
    check hostile-caught-up "honest again: caught up within 240 s" caught_up 240
    chain_rows > "$OUT/chains.json"
    record_rows "$CAP" > "$OUT/recs-capture-hostile.json"
    compare capture-after-hostile "$OUT/recs-capture-hostile.json" > "$OUT/compare-hostile.txt"
    check hostile-no-loss "no row lost through the hostile receivers" test $? -eq 0
    cat "$OUT/compare-hostile.txt"
    check verify-capture-hostile "the capture still verifies" verify capture-hostile "$CAP"
}

phase_slow() { bounded_loss slow; }
phase_stall() { bounded_loss stall; }

bounded_loss() {   # <mode>
    local m=$1 before after s5a s5b
    # caught up first: what is lost after this is this receiver's alone
    check "$m-ready" "caught up before the $m receiver" caught_up 240
    chain_rows > "$OUT/chains-before-$m.json"
    record_rows "$CAP" > "$OUT/recs-before-$m.json"
    receiver "$m"
    sleep 2
    before=$(detections_rows)
    s5a=$(stage5)
    events 4 40 300
    sleep 8
    after=$(detections_rows)
    s5b=$(stage5)
    status_json > "$OUT/status-$m.json"
    check "$m-detects" "receiver $m: the execs detected ($before -> $after)" bash -c "[ $after -ge $((before + 4)) ]"
    check "$m-decision" "receiver $m: stage 5 over-budget $s5a -> $s5b" bash -c "[ ${s5b:-0} -le $(( ${s5a:-0} + 2 )) ]"
    check "$m-worker" "receiver $m: the worker still ready" python3 -I -c '
import json,sys
e = json.load(open(sys.argv[1]))["export"]
print(e["worker"], [(k["sink"], k["state"], k["fault"]) for k in e["sinks"]])
sys.exit(0 if e["worker"] == "ready" else 1)' "$OUT/status-$m.json"
    chain_rows > "$OUT/chains-$m.json"
    # the receiver dies with what it had not read
    receiver honest
    check "$m-caught-up" "honest again: caught up within 240 s" caught_up 240
    chain_rows > "$OUT/chains.json"
    record_rows "$CAP" > "$OUT/recs-capture-$m.json"
    python3 -I - "$m" "$OUT/chains-before-$m.json" "$OUT/chains-$m.json" "$OUT/chains.json" \
        "$OUT/recs-capture-$m.json" "$OUT/recs-before-$m.json" > "$OUT/compare-$m.txt" <<'PY'
import json, sys
mode = sys.argv[1]
before, during, now, recs, recs0 = (json.load(open(f)) for f in sys.argv[2:7])
rows = recs["rows"]
lost = window = 0
outside = []
for c, hs in now.items():
    # what this receiver lost: missing now, and not missing already before it
    earlier = set(before.get(c, [])) - set(recs0["rows"].get(c, []))
    missing = set(hs) - set(rows.get(c, [])) - earlier
    held = set(during.get(c, [])) - set(before.get(c, []))
    lost += len(missing)
    window += len(held)
    outside += [(c, h) for h in missing - held]
print(f"{mode}: {window} row(s) written while it held the connection, {lost} lost, {len(outside)} lost outside it")
sys.exit(0 if not outside else 1)
PY
    check "$m-loss-bounded" "the rows lost are rows written while the $m receiver held the connection" test $? -eq 0
    cat "$OUT/compare-$m.txt"
}

# The review of #499 (X1): a chain rotated while the export reads it — the
# netflow chain (its file 16 MiB) driven past a rotation by connects, both
# sinks caught up; every row across it arrived, no "cursor ahead".
phase_rotate() {
    local n0 n1 s
    n0=$(ls "$STATE"/netflow.jsonl.[0-9]* 2>/dev/null | wc -l)
    s=$(date +%s)
    while [ "$(ls "$STATE"/netflow.jsonl.[0-9]* 2>/dev/null | wc -l)" -le "$n0" ] && [ $(( $(date +%s) - s )) -lt 240 ]; do
        events 0 200 0
    done
    n1=$(ls "$STATE"/netflow.jsonl.[0-9]* 2>/dev/null | wc -l)
    check rotate-happened "the netflow chain rotated while exported ($n0 -> $n1 archives, $(( $(date +%s) - s )) s)" test "$n1" -gt "$n0"
    check rotate-caught-up "both sinks caught up after the rotation" caught_up 300
    chain_rows > "$OUT/chains.json"
    record_rows "$CAP" > "$OUT/recs-capture-rotate.json"
    compare capture-after-rotate "$OUT/recs-capture-rotate.json" > "$OUT/compare-rotate.txt"
    check rotate-no-loss "every row across the rotation arrived, none other" test $? -eq 0
    cat "$OUT/compare-rotate.txt"
    check verify-capture-rotate "the capture verifies across the rotation" verify capture-rotate "$CAP"
    # the agent logs in its journal namespace (`LogNamespace=northnarrow`):
    # `journalctl -u northnarrow-agent` alone reads systemd's lines only
    # (rounds 5 to 10 counted there: no note could be seen)
    agent_journal --since "-10min" | grep -ciE 'cursorahead|cursor_ahead' > "$OUT/cursor-ahead.txt"
    check rotate-no-cursor-ahead "no read went ahead of the chain (cursor_ahead notes: $(cat "$OUT/cursor-ahead.txt"))" bash -c "[ \"\$(cat '$OUT/cursor-ahead.txt')\" = 0 ]"
    # the second review of #499 (R1): the rotation's second window (the
    # archive renamed, the new file not made yet) is no eviction either
    agent_journal --since "-10min" | grep -ciE 'Evicted [{]|active file is missing' > "$OUT/evicted.txt"
    check rotate-no-eviction "no file taken for evicted or missing across the rotation (notes: $(cat "$OUT/evicted.txt"))" bash -c "[ \"\$(cat '$OUT/evicted.txt')\" = 0 ]"
}

# The review of #499 (D1, D2): what verify refuses — a record whose OCSF
# fields were rewritten (its row genuine), a rotation's terminator stripped
# with the file's last row dropped.
phase_rewritten() {
    python3 -I - "$CAP" "$OUT" <<'PY'
import json, sys
cap, out = sys.argv[1], sys.argv[2]
recs = []
for line in open(cap, encoding="utf-8", errors="replace"):
    i = line.find("{")
    if i >= 0:
        try:
            recs.append(json.loads(line[i:]))
        except Exception:
            pass
det = [r for r in recs if r.get("unmapped", {}).get("northnarrow", {}).get("row", {}).get("chain") == "detections"]
v = dict(det[0])
v["severity_id"] = 1
v["finding_info"] = {"title": "benign", "uid": "x"}
open(out + "/rewritten.jsonl", "w").write(json.dumps(v) + "\n")
# a rotation: the first row of a file after 1 with its terminator, the row before it
by = {}
for r in recs:
    row = r["unmapped"]["northnarrow"]["row"]
    by.setdefault(row["chain"], {})[(row["file"], row["line"])] = r
cut = None
for c, rows in by.items():
    for (f, l), r in sorted(rows.items()):
        if l == 1 and f > 1 and r["unmapped"]["northnarrow"]["row"].get("rotate"):
            prev = [k for k in rows if k[0] == f - 1]
            if len(prev) >= 2:
                last = max(prev)
                keep = [rows[k] for k in sorted(prev) if k != last]
                nxt = json.loads(json.dumps(r))
                del nxt["unmapped"]["northnarrow"]["row"]["rotate"]
                cut = keep + [nxt]
                break
    if cut:
        break
with open(out + "/cut.jsonl", "w") as f:
    for r in cut or []:
        f.write(json.dumps(r) + "\n")
print("rewritten 1 record; cut:", len(cut or []), "records")
PY
    "$NNADMIN" export verify --agent-pubkey-file /etc/northnarrow/agent.sig.pub --file "$OUT/rewritten.jsonl" > "$OUT/verify-rewritten.txt" 2>&1
    local rc=$?
    check rewritten-tampered "a record with its fields rewritten: TAMPERED, exit 13 (got $rc)" test "$rc" -eq 13
    if [ -s "$OUT/cut.jsonl" ]; then
        "$NNADMIN" export verify --agent-pubkey-file /etc/northnarrow/agent.sig.pub --file "$OUT/cut.jsonl" > "$OUT/verify-cut.txt" 2>&1
        rc=$?
        check cut-broken "a file's tail cut, its terminator stripped: BROKEN, exit 11 (got $rc)" test "$rc" -eq 11
    else
        fail cut-broken "no rotation in the capture to cut (run phase rotate first)"
    fi
    : > "$OUT/empty.jsonl"
    "$NNADMIN" export verify --agent-pubkey-file /etc/northnarrow/agent.sig.pub --file "$OUT/empty.jsonl" > "$OUT/verify-empty.txt" 2>&1
    rc=$?
    check empty-not-ok "an empty capture: EMPTY, exit 2 (got $rc)" test "$rc" -eq 2
}

# The export worker's protection, as the kernel and the agent hold it.
# Lot 276's rounds 5 to 7 ran a phase that killed the worker from this
# script, as root, until the supervisor disabled it (the review of #499,
# D4): that kill is a tamper attempt — `task_kill` refuses it (the worker's
# pid is protected, as the agent's), NN-L-AT-001 signs it and the COMBAT
# ladder ends the sender (round 7: this script, `KillProcessTree`; nothing
# measured after it). What the lab checks from outside is that protection:
# one root `kill -9`, sent from a transient unit of its own, which the
# ladder ends instead of this script. The degraded state (D4) is the unit
# tests' (`agent::export`, the controller's and the beat's).
phase_protected() {
    local w w2 sender
    w=$(worker_pid)
    rm -f "$OUT/tamper.txt"
    # systemd expands `$` in a command line itself: `$$` passes one on
    # (round 8 read `sender=$`)
    systemd-run --unit=nn-k276-tamper --collect --wait --quiet \
        -p StandardOutput="file:$OUT/tamper.txt" -p StandardError="append:$OUT/tamper.txt" \
        /bin/bash -c "echo sender=\$\$\$\$; kill -9 $w; echo kill-rc=\$\$?; sleep 10; echo sender-alive" >/dev/null 2>&1
    sleep 3
    w2=$(worker_pid)
    sender=$(sed -n 's/^sender=//p' "$OUT/tamper.txt" | head -1)
    check protected-refused "a root kill -9 of the export worker (pid ${w:-none}) refused" \
        grep -q 'kill-rc=1' "$OUT/tamper.txt"
    check protected-worker "the worker untouched (pid ${w:-none}, now ${w2:-none})" \
        bash -c "[ -n '$w' ] && [ '$w' = '$w2' ]"
    check protected-on "the export still on, its worker ready" python3 -I -c '
import json,sys
e = json.load(sys.stdin)["export"]
print(e["state"], e["worker"])
sys.exit(0 if e["state"] == "on" and e["worker"] == "ready" else 1)' < <(status_json)
    check protected-recorded "the attempt signed: NN-L-AT-001 for the sender (pid ${sender:-none})" python3 -I -c '
import json,sys
pid = int(sys.argv[2] or 0)
for l in open(sys.argv[1], errors="replace"):
    if "NN-L-AT-001" not in l:
        continue
    r = json.loads(l)
    if (r.get("principal") or {}).get("pid") == pid:
        print(r.get("ts"), r.get("severity"), r.get("posture_at"))
        sys.exit(0)
sys.exit(1)' "$STATE/detections/detections.jsonl" "$sender"
    check protected-answered "the sender ended by the response ladder, not by itself" bash -c "
        ! grep -q sender-alive '$OUT/tamper.txt' &&
        grep -q 'Killed { pid: $sender }' '$STATE/detections/actions.jsonl'"
}

# The third check of #499: an action's outcome record carries its intent's
# signed row (`intent_raw`), and `export verify` checks every record on its
# own — the actions of a capture whole: OK; the outcome moved before its
# intent with the intent's facts rewritten: TAMPERED (13); the capture's
# head cut after the intent: the records left OK on their own, the outcome
# rewritten TAMPERED. And what the row costs: an outcome's record with and
# without it. The actions come from the `protected` phase (the COMBAT
# ladder's intents and outcomes): run it first.
phase_outcome() {
    local rc
    check outcome-caught-up "both sinks caught up with the actions" caught_up 300
    python3 -I - "$CAP" "$OUT" <<'PY'
import json, re, sys
cap, out = sys.argv[1], sys.argv[2]
recs = []
for l in open(cap, errors="replace"):
    m = re.search(r"(\{.*\})\s*$", l)
    if not m:
        continue
    try:
        recs.append(json.loads(m.group(1)))
    except ValueError:
        pass
def nn(v):
    return (v.get("unmapped") or {}).get("northnarrow") or {}
def place(v):
    r = nn(v)["row"]
    return (r["file"], r["line"])
acts = sorted({place(v): v for v in recs if nn(v).get("row", {}).get("chain") == "actions"}.values(), key=place)
outs = [v for v in acts if nn(v).get("kind") == "outcome" and nn(v).get("intent_raw")]
def dump(name, vs):
    with open(f"{out}/{name}", "w") as f:
        for v in vs:
            f.write(json.dumps(v, separators=(",", ":")) + "\n")
if not outs:
    print("no outcome with its intent row in the capture")
    sys.exit(0)
o = outs[-1]
ir = nn(o)["intent_row"]
intent = [v for v in acts if place(v) == (ir["file"], ir["line"])]
dump("outcome-whole.jsonl", acts)
bent = json.loads(json.dumps(o))
bent["severity_id"] = 1
bent["severity"] = "Informational"
bent["message"] = "benign"
if "process" in bent:
    bent["process"] = {"pid": 1}
others = [v for v in acts if v is not o]
dump("outcome-reordered-bent.jsonl", [bent] + others)
after = [v for v in acts if place(v) > (ir["file"], ir["line"])]
dump("outcome-head-cut.jsonl", after)
dump("outcome-head-cut-bent.jsonl", [bent if v is o else v for v in after])
line = lambda v: len(json.dumps(v, separators=(",", ":")))
bare = json.loads(json.dumps(o))
bare["unmapped"]["northnarrow"].pop("intent_raw")
with open(f"{out}/outcome-cost.txt", "w") as f:
    f.write(f"outcome {place(o)} class {o['class_uid']}: {line(o)} bytes with its intent row, "
            f"{line(bare)} without it (+{line(o) - line(bare)}); its intent's row {len(nn(o)['intent_raw'])} bytes; "
            f"outcomes with the row in the capture: {len(outs)}, sizes {sorted(line(v) for v in outs)}\n")
print(open(f"{out}/outcome-cost.txt").read().strip())
print(f"actions records {len(acts)}, after the intent {len(after)}, its intent's record {len(intent)}")
PY
    if [ -s "$OUT/outcome-whole.jsonl" ]; then
        verify outcome-whole "$OUT/outcome-whole.jsonl"
        rc=$?
        check outcome-whole-ok "the actions whole: OK, exit 0 (got $rc)" test "$rc" -eq 0
        verify outcome-reordered-bent "$OUT/outcome-reordered-bent.jsonl"
        rc=$?
        check outcome-reordered-bent "the outcome before its intent, the intent's facts rewritten: TAMPERED, exit 13 (got $rc)" test "$rc" -eq 13
        verify outcome-head-cut "$OUT/outcome-head-cut.jsonl"
        rc=$?
        check outcome-head-cut "the head cut after the intent: the records left OK on their own, exit 0 (got $rc)" test "$rc" -eq 0
        verify outcome-head-cut-bent "$OUT/outcome-head-cut-bent.jsonl"
        rc=$?
        check outcome-head-cut-bent "the head cut, the outcome rewritten: TAMPERED, exit 13 (got $rc)" test "$rc" -eq 13
    else
        fail outcome-intent-row "no action outcome with its intent row in the capture (run the protected phase first)"
    fi
}

# The signed text of the `shrink` phase: the JSONL files' count $1, 1 MiB
# each; set, and the agent started again.
shrink_overlay() {   # <files>
    local sha
    sha=$(sha256sum /etc/northnarrow/export-ca.pem | cut -d' ' -f1)
    printf '%s\n' "# lot 276 lab: the JSONL files' count" "enabled = true" \
        "chain = detections" "chain = actions" "chain = netflow" "start = end" \
        "file = on" "file_max_bytes = 1MiB" "file_max_files = $1" \
        "syslog = 127.0.0.1:$PORT" "syslog_server_name = receiver.lab" \
        "syslog_ca = /etc/northnarrow/export-ca.pem" "syslog_ca_sha256 = $sha" \
        > "$LAB/export-shrink.local"
    "$NNADMIN" config overlay set export --file "$LAB/export-shrink.local" --key "$KEY" >> "$OUT/overlay-shrink.txt" 2>&1
    restart_agent >> "$OUT/restart-shrink.txt" 2>&1
    sleep 5
}

# The second review of #499 (R3): a signed configuration with fewer JSONL
# files, the agent started again — the sink's open removes what the earlier
# one left past the new count, and the core does not take it for the
# worker's: the worker not killed, the file sink up, no `directory_over`.
phase_shrink() {
    local w0 w1 s t0
    t0=$(date +%s)
    # 8 files of 1 MiB, filled past four
    shrink_overlay 8
    s=$(date +%s)
    while [ ! -e "$EXPORT_DIR/export.jsonl.4" ] && [ $(( $(date +%s) - s )) -lt 300 ]; do
        events 0 200 0
    done
    ls -l "$EXPORT_DIR" > "$OUT/shrink-before.txt"
    check shrink-filled "the JSONL files past four (export.jsonl.4 there, $(( $(date +%s) - s )) s)" test -e "$EXPORT_DIR/export.jsonl.4"
    check shrink-caught-up "both sinks caught up" caught_up 300
    # the next start, signed with 2
    shrink_overlay 2
    w0=$(worker_pid)
    sleep 10
    w1=$(worker_pid)
    ls -l "$EXPORT_DIR" > "$OUT/shrink-after.txt"
    status_json > "$OUT/status-shrink.json"
    check shrink-cleared "the files past the new count removed at the sink's open (left: $(ls "$EXPORT_DIR" | tr '\n' ' '))" bash -c "[ -z \"\$(ls '$EXPORT_DIR' | grep -vxE 'export\.jsonl(\.1)?')\" ]"
    check shrink-worker "the worker not killed (pid ${w0:-none}, 10 s later ${w1:-none})" bash -c "[ -n '$w0' ] && [ '$w0' = '$w1' ]"
    check shrink-file-up "the export on, its worker ready, the file sink up, no fault" python3 -I -c '
import json,sys
e = json.load(open(sys.argv[1]))["export"]
f = [k for k in e["sinks"] if k["sink"] == "file"][0]
print(e["state"], e["worker"], f["state"], f["faults"], f.get("fault"))
sys.exit(0 if e["state"] == "on" and e["worker"] == "ready" and f["state"] == "up" and f["faults"] == 0 else 1)' "$OUT/status-shrink.json"
    agent_journal --since "@$t0" | grep -iE 'past its bound|directory_over' > "$OUT/shrink-over.txt"
    check shrink-not-over "the worker never killed for its directory, at 1 MiB from 64 MiB nor at 2 files from 8 ($(wc -l < "$OUT/shrink-over.txt") note(s))" bash -c "[ ! -s '$OUT/shrink-over.txt' ]"
    events 0 50 0
    check shrink-writes "the sinks catch up after the start" caught_up 120
}

ticks() { awk '{print $14 + $15}' "$1" 2>/dev/null; }

phase_cost() {
    local w tid a w0 w1 t0 t1 rows0 rows1 hz
    hz=$(getconf CLK_TCK)
    a=$(agent_pid)
    w=$(worker_pid)
    tid=$(grep -l '^nn-export$' /proc/"$a"/task/*/comm 2>/dev/null | head -1 | cut -d/ -f5)
    rows0=$(status_json | python3 -I -c 'import json,sys; print(sum(k["rows"] for k in json.load(sys.stdin)["export"]["sinks"]))')
    w0=$(ticks "/proc/$w/stat"); t0=$(ticks "/proc/$a/task/$tid/stat")
    local s=$(date +%s)
    while [ $(( $(date +%s) - s )) -lt 60 ]; do events 0 50 20; done
    caught_up 120
    local secs=$(( $(date +%s) - s ))
    w1=$(ticks "/proc/$w/stat"); t1=$(ticks "/proc/$a/task/$tid/stat")
    rows1=$(status_json | python3 -I -c 'import json,sys; print(sum(k["rows"] for k in json.load(sys.stdin)["export"]["sinks"]))')
    {
        echo "window ${secs} s; rows delivered (both sinks) $((rows1 - rows0))"
        echo "export worker CPU: $(( (w1 - w0) * 1000 / hz )) ms ($(python3 -I -c "print(round(100*($w1-$w0)/$hz/$secs,2))") % of a CPU)"
        echo "core nn-export thread CPU: $(( (t1 - t0) * 1000 / hz )) ms ($(python3 -I -c "print(round(100*($t1-$t0)/$hz/$secs,2))") % of a CPU)"
        echo "worker RSS: $(grep VmRSS /proc/$w/status)"
    } | tee "$OUT/cost.txt"
    check cost-measured "the export's cost measured" test -s "$OUT/cost.txt"
}

phase_off() {
    printf 'enabled = false\n' > "$LAB/export-off.local"
    "$NNADMIN" config overlay set export --file "$LAB/export-off.local" --key "$KEY" > "$OUT/overlay-off.txt" 2>&1
    restart_agent > "$OUT/restart-off.txt" 2>&1
    check off-no-worker "enabled = false: no export worker" bash -c '[ -z "$(ps --ppid "$(cat /run/northnarrow/agent.pid)" -o comm= | grep -x nn-worker-exp)" ]'
    check off-status "export status: off" bash -c "$NNADMIN export status --key $KEY | grep -q 'export: off'"
    systemctl stop nn-export-recv 2>/dev/null
    # leave the guest clean: no overlay for the next lot's agent (inside a
    # window: the overlays are protected files), no CA, no lab files
    "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 60 >/dev/null 2>&1
    rm -f /etc/northnarrow/export.local /etc/northnarrow/export.local.sig /etc/northnarrow/export-ca.pem \
        "$STATE"/detections/export-cursors.json
    check off-clean "the overlay and the CA removed" bash -c '[ ! -e /etc/northnarrow/export.local ] && [ ! -e /etc/northnarrow/export-ca.pem ]'
    restart_agent > "$OUT/restart-clean.txt" 2>&1
    check off-none "export status: none" bash -c "$NNADMIN export status --key $KEY | grep -q 'export: none'"
    rm -rf "$LAB" "$EXPORT_DIR"/export.jsonl* "$RECV_BIN"
}

for p in "$@"; do
    PHASE=$p
    echo "=== $p $(date -u +%FT%TZ)"
    "phase_$p"
    # the later phases measure an export that is on: not after a setup
    # that failed (lot 276's first lab ran them, 18 FAILs of one cause)
    if [ "$p" = setup ] && [ "$fails" -gt 0 ]; then
        echo "setup failed ($fails): the later phases are not run"
        break
    fi
done
echo "fails: $fails"
exit "$fails"
