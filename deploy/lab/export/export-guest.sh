#!/usr/bin/env bash
# Lot 276: the export on an nn-lab guest — run as root ON THE GUEST against
# the installed agent, a local syslog-over-TLS receiver (the lab's own,
# crates/nn-export/examples/syslog_receiver.rs, built in the guest's tree).
# Our own lab guests only.
#
# usage: export-guest.sh <out-dir> <phase>...  (setup arrive outage hostile slow stall cost off)
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
        check worker-account "the worker runs as northnarrow-worker" bash -c "[ \"\$(stat -c %U /proc/$w)\" = northnarrow-worker ]"
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
