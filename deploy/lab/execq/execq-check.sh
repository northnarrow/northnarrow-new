#!/bin/bash
# Lab PR 223 (EXPERIMENTAL) — the exec quarantine at first sight, end to end
# on a lab guest (`nn-lab.sh execq-check`; docs/design/EXEC_QUARANTINE.md
# §11). Run as the lab user with sudo, with the agent installed by this tree's
# install.sh (it creates the `northnarrow-scan` account and installs the
# scanner) and running on LSM (`lsm=…,bpf`).
#
# The check turns the guard on (a unit drop-in, inside a signed
# trusted-installer window), stores a lab-only signed block list holding the
# SHA-256 of a harmless test binary it builds here, and runs:
#   1. a copy of /usr/bin/true in /tmp and in the home, each with its own
#      content (random bytes appended: a digest already judged clean resumes
#      without a record): held before its first instruction, scanned clean,
#      recorded; the second run is not held;
#   2. the block-listed test binary: killed before its first instruction (no
#      marker file), its file quarantined;
#   3. a UPX-packed copy of ls (when upx can be installed): a heuristic hit;
#   4. package-managed binaries: never held;
#   5. the exec time of new binaries, first sight and cached, with the guard
#      on, and with it off;
#   6. the scanner stopped (SIGSTOP) during a decision: the budget runs out,
#      the default policy resumes, signed; the scanner killed (SIGKILL)
#      during a scan: a signed degradation and a decision.
# Then it puts the guest back (drop-in and list removed, agent restarted).
# Verdicts come from the signed detection chain, the signed audit log and
# the signed status (`nn-admin status --key`), never from journal text.
# Exit: 0 PASS, 1 FAIL, 2 refused (not a lab guest).
set -u

NN_LAB_GUEST_MARKER=/var/lib/nn-lab-provisioned
if ! [[ -e $NN_LAB_GUEST_MARKER || ${NN_TEST_DISPOSABLE_HOST:-} == 1 ]]; then
    echo "execq check: refusing to run: not an nn-lab guest ($NN_LAB_GUEST_MARKER missing) and NN_TEST_DISPOSABLE_HOST=1 not set — it changes the agent's unit and its signed configuration" >&2
    exit 2
fi

HERE=$(cd "$(dirname "$0")" && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
AUD=/etc/northnarrow/audit.log
RULE=NN-L-EXECQ-001_FirstSightQuarantine
BIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")
NNADMIN=$BIN/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
DROPIN_DIR=/etc/systemd/system/northnarrow-agent.service.d
DROPIN=$DROPIN_DIR/nn-lab-execq.conf
HASHES=/etc/northnarrow/execq-hashes.local
BUDGET_MS=${NN_EXECQ_BUDGET_MS:-2000}
ROUNDS=${NN_EXECQ_LAT_ROUNDS:-20}
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
skip() { printf 'SKIP  %s\n' "$*"; }
info() { printf 'INFO  %s\n' "$*"; }

[[ -n $KEY ]] || { echo "execq check: no admin key (/root/northnarrow-admin.key, /etc/northnarrow/admin.key)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "execq check: python3 is needed to read the records" >&2; exit 1; }
WORK=$(mktemp -d "$HOME/nn-execq.XXXXXXXX") || exit 1
TMPX=$(mktemp /tmp/nn-x.XXXXXXXX) || exit 1
GUARD_ON=0

grant() { sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 300 >/dev/null 2>&1; }

# The unit refuses `systemctl restart` (external audit EBPF-001): a signed
# trusted-installer window, SIGTERM, and the watchdog starts it again.
restart_agent() {
    local old new i
    old=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
    grant
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 40); do
        sleep 1
        new=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
        if [[ -n $new && $new != "$old" ]] && sudo kill -0 "$new" 2>/dev/null \
            && sudo "$NNADMIN" status >/dev/null 2>&1; then
            sleep 2
            return 0
        fi
    done
    sudo systemctl start northnarrow-agent
    sleep 6
}

det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }

# The exec quarantine records written after line $1, one TSV line each:
# exe, verdict, decision, held, response, basis, reasons, held_ms.
execq_since() {
    sudo tail -n "+$(($1 + 1))" "$DET" 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if r.get("rule_id") != sys.argv[1]:
        continue
    e = r.get("execq") or {}
    print("\t".join([r.get("exe") or "", e.get("verdict", ""), e.get("decision", ""),
                     str(e.get("held")), r.get("response", ""), e.get("basis", ""),
                     " | ".join(e.get("reasons", [])), str(e.get("held_ms", ""))]))
' "$RULE"
}
# records for exe $2 since line $1
recs_for() { execq_since "$1" | awk -F'\t' -v x="$2" '$1 == x'; }
field() { printf '%s' "$1" | head -1 | cut -f"$2"; }

# One field of the signed status's exec quarantine object.
execq_status() {
    sudo "$NNADMIN" status --key "$KEY" --json 2>/dev/null | python3 -c '
import json, sys
try:
    v = (json.load(sys.stdin).get("execq") or {}).get(sys.argv[1])
except ValueError:
    v = None
print("" if v is None else v)
' "$1"
}

audit_since() { sudo tail -n "+$(($1 + 1))" "$AUD" 2>/dev/null; }
audit_count() { sudo cat "$AUD" 2>/dev/null | wc -l; }

median() { sort -n | awk '{a[NR]=$1} END {if (NR) print a[int((NR+1)/2)]; else print 0}'; }

# The running scanner's pid: its user and its exact command line (the agent
# runs `$BIN/northnarrow-scan --fd 3`). Not `pgrep -x`: the name has 16
# characters, the kernel keeps 15, and older procps matches -x on those.
scanner_pid() { pgrep -u northnarrow-scan -f "^$BIN/northnarrow-scan( |\$)" | head -1; }

# newbin <path>: a copy of /usr/bin/true with 32 random bytes appended, so its
# SHA-256 is new to the guard (a digest already judged clean resumes without a
# record, and every case needs its own first sight).
newbin() { { cat /usr/bin/true; head -c 32 /dev/urandom; } > "$1" && chmod 0755 "$1"; }

guard_off() {
    ((GUARD_ON)) || return 0
    grant
    sudo rm -f "$DROPIN"
    sudo systemctl daemon-reload
    restart_agent
    GUARD_ON=0
}

cleanup() {
    guard_off
    grant
    if [[ -e $WORK/hashes.saved ]]; then
        sudo install -m 0644 -o root -g root "$WORK/hashes.saved" "$HASHES"
        [[ -e $WORK/hashes.sig.saved ]] && sudo install -m 0644 -o root -g root "$WORK/hashes.sig.saved" "$HASHES.sig"
    else
        sudo rm -f "$HASHES" "$HASHES.sig"
    fi
    rm -rf "$WORK"
    rm -f "$TMPX"
}

# ── setup ─────────────────────────────────────────────────────────────
getent passwd northnarrow-scan >/dev/null || { bad "no northnarrow-scan account (this tree's install.sh creates it)"; exit 1; }
[[ -x $BIN/northnarrow-scan ]] || { bad "no $BIN/northnarrow-scan (install this tree)"; exit 1; }
command -v cc >/dev/null || sudo apt-get install -y gcc >/dev/null 2>&1 || sudo dnf install -y gcc >/dev/null 2>&1
cc -O2 -o "$WORK/nn-execq-marker" "$HERE/nn-execq-marker.c" || { bad "cannot build the test binary"; exit 1; }
MARK_SHA=$(sha256sum "$WORK/nn-execq-marker" | cut -d' ' -f1)
printf '# lab only — deploy/lab/execq/execq-check.sh\nblock %s nn-lab-execq-marker\n' "$MARK_SHA" > "$WORK/hashes"
if sudo test -e "$HASHES"; then
    sudo cp "$HASHES" "$WORK/hashes.saved" && sudo chown "$(id -u)" "$WORK/hashes.saved"
    sudo test -e "$HASHES.sig" && sudo cp "$HASHES.sig" "$WORK/hashes.sig.saved" && sudo chown "$(id -u)" "$WORK/hashes.sig.saved"
fi
trap cleanup EXIT
sudo "$NNADMIN" config overlay set execq-hashes --file "$WORK/hashes" --key "$KEY" >/dev/null \
    || { bad "storing the signed lab block list failed"; exit 1; }
grant
sudo install -d -m 0755 "$DROPIN_DIR"
printf '[Service]\nEnvironment=NN_EXEC_QUARANTINE=enforce\nEnvironment=NN_EXEC_QUARANTINE_BUDGET_MS=%s\n' "$BUDGET_MS" \
    | sudo tee "$DROPIN" >/dev/null
sudo systemctl daemon-reload
GUARD_ON=1
restart_agent
state=$(execq_status state)
if [[ $state == enforce ]]; then
    pass "guard on: signed status says execq state enforce (budget ${BUDGET_MS} ms, test binary sha256 ${MARK_SHA:0:16}…)"
else
    bad "guard not on: execq state '${state}' (a degraded state names why)"
    exit 1
fi

# ── 1. a new binary: held, scanned clean, recorded; the second run not held
newbin "$TMPX"
b=$(det_count); ki0=$(execq_status known_identity)
"$TMPX"; rc=$?; sleep 2
r=$(recs_for "$b" "$TMPX")
if [[ $(field "$r" 2) == clean && $(field "$r" 4) == True ]]; then
    pass "1  $TMPX (a copy of true): held before its first instruction, scanned clean, recorded (response: $(field "$r" 5); rc $rc — R001 kills a /tmp binary as before, now on a held process)"
else
    bad "1  $TMPX: no held clean record (rc $rc): ${r:-none}"
fi
b=$(det_count)
"$TMPX"; sleep 2
n=$(recs_for "$b" "$TMPX" | grep -c .); ki1=$(execq_status known_identity)
if [[ $n -eq 0 && ${ki1:-0} -gt ${ki0:-0} ]]; then
    pass "1  second run of $TMPX not held: known identity ($ki0 → $ki1), no new record"
else
    bad "1  second run of $TMPX: $n new record(s), known identity $ki0 → $ki1"
fi
X=$WORK/nn-x
newbin "$X"
b=$(det_count)
"$X"; rc=$?; sleep 2
r=$(recs_for "$b" "$X")
if [[ $rc -eq 0 && $(field "$r" 2) == clean && $(field "$r" 5) == resumed ]]; then
    pass "1  $X (home): held, scanned clean, resumed (held $(field "$r" 8) ms), exit 0"
else
    bad "1  $X: rc $rc, record: ${r:-none}"
fi
b=$(det_count)
"$X"; rc=$?; sleep 2
n=$(recs_for "$b" "$X" | grep -c .)
[[ $rc -eq 0 && $n -eq 0 ]] && pass "1  second run of $X: not held, no record" || bad "1  second run of $X: rc $rc, $n record(s)"

# ── 2. the block-listed test binary: killed before its first instruction
M=$WORK/nn-execq-marker
b=$(det_count); q0=$(execq_status quarantined)
"$M" "$WORK/ran"; rc=$?; sleep 2
r=$(recs_for "$b" "$M"); q1=$(execq_status quarantined)
if [[ $(field "$r" 2) == malicious && $(field "$r" 3) == kill ]] && [[ ! -e $WORK/ran ]] \
    && [[ $(field "$r" 5) == *"quarantined (vault "* ]] && [[ ! -e $M ]] && [[ $rc -eq 137 ]]; then
    pass "2  block-listed test binary killed while held (no marker: no instruction ran), quarantined ($q0 → $q1): $(field "$r" 5)"
else
    bad "2  block-listed test binary: rc $rc, marker $([[ -e $WORK/ran ]] && echo present || echo absent), file $([[ -e $M ]] && echo present || echo gone), record: ${r:-none}"
fi

# ── 3. a UPX-packed copy of a harmless binary: a heuristic hit
command -v upx >/dev/null || sudo apt-get install -y upx-ucl >/dev/null 2>&1 || sudo dnf install -y upx >/dev/null 2>&1
if command -v upx >/dev/null; then
    U=$WORK/nn-upx
    cp /usr/bin/ls "$U" && upx -qq "$U" >/dev/null 2>&1
    b=$(det_count)
    "$U" --version >/dev/null; rc=$?; sleep 2
    r=$(recs_for "$b" "$U")
    if [[ $(field "$r" 2) == suspicious && $(field "$r" 7) == *elf.upx_marker* && $rc -eq 0 ]]; then
        pass "3  UPX-packed ls: suspicious ($(field "$r" 7 | cut -c1-160)…), resumed by the default policy"
    else
        bad "3  UPX-packed ls: rc $rc, record: ${r:-none}"
    fi
else
    skip "3  upx not installable here"
fi

# ── 4. package-managed binaries: never held
owner=$( (dpkg -S /usr/bin/true || rpm -qf /usr/bin/true) 2>/dev/null | head -1)
h0=$(execq_status held); b=$(det_count)
/usr/bin/true; /usr/bin/ls / >/dev/null; /usr/bin/env true; sleep 2
h1=$(execq_status held); n=$(execq_since "$b" | awk -F'\t' '$1 ~ /^\/usr\//' | grep -c .)
[[ $n -eq 0 && $h1 == "$h0" ]] && pass "4  package-managed binaries not held ($owner; held stays $h0)" \
    || bad "4  package-managed binaries: $n record(s), held $h0 → $h1"

# ── 6a. the scanner stopped during a decision: budget expiry, default policy
spid=$(scanner_pid)
S=$WORK/nn-stall
{ cat /usr/bin/true; head -c 32 /dev/urandom; } > "$S" && chmod 0755 "$S"
a0=$(audit_count); b=$(det_count)
if [[ -n $spid ]]; then
    sudo kill -STOP "$spid"
    t0=$(date +%s%N); "$S"; rc=$?; t1=$(date +%s%N)
    # the hung scanner is killed 5 s after its last word (HUNG_AFTER)
    ms=$(((t1 - t0) / 1000000)); sleep 6
    r=$(recs_for "$b" "$S")
    deg=$(audit_since "$a0" | grep -a '"subsystem_degraded"' | grep -ac 'no verdict within the decision budget')
    npid=$(scanner_pid)
    if [[ $rc -eq 0 && $(field "$r" 6) == *"decision budget expired"* && $(field "$r" 5) == resumed \
        && $ms -ge $((BUDGET_MS * 9 / 10)) && $deg -ge 1 && -n $npid && $npid != "$spid" ]]; then
        pass "6  scanner stopped: held ${ms} ms, budget expired, default policy resumed (signed record), hung scanner killed and restarted (pid $spid → $npid, signed degradation)"
    else
        bad "6  scanner stopped: rc $rc, ${ms} ms, degradations $deg, scanner $spid → ${npid:-none}, record: ${r:-none}"
    fi
    sudo kill -CONT "$spid" 2>/dev/null
else
    bad "6  no running scanner to stop"
fi

# ── 6b. the scanner killed during a scan
B=$WORK/nn-big
{ cat /usr/bin/true; head -c $((512 * 1024 * 1024)) /dev/urandom; } > "$B" && chmod 0755 "$B"
sleep 3
a0=$(audit_count); b=$(det_count)
("$B"; echo $? > "$WORK/big.rc") &
sleep 0.3
spid=$(scanner_pid)
[[ -n $spid ]] && sudo kill -KILL "$spid"
wait
sleep 3
r=$(recs_for "$b" "$B")
deg=$(audit_since "$a0" | grep -a '"subsystem_degraded"' | grep -ac 'scanner.*killed by signal 9')
if [[ -n $spid && $deg -ge 1 && -n $r && $(cat "$WORK/big.rc" 2>/dev/null) == 0 ]]; then
    pass "6  scanner killed mid-scan: signed degradation, then $(field "$r" 2) / $(field "$r" 6) (held $(field "$r" 8) ms)"
else
    bad "6  scanner killed mid-scan: scanner ${spid:-none}, degradations $deg, rc $(cat "$WORK/big.rc" 2>/dev/null), record: ${r:-none}"
fi
rm -f "$B"

# ── 5. latency: first sight and cached with the guard on, then off
lat() {   # <tag> → microseconds per exec, one per line
    local i f t0 t1
    for i in $(seq 1 "$ROUNDS"); do
        f=$WORK/lat-$1-$i
        [[ -e $f ]] || { { cat /usr/bin/true; head -c 16 /dev/urandom; } > "$f"; chmod 0755 "$f"; }
        t0=$(date +%s%N); "$f"; t1=$(date +%s%N)
        echo $(((t1 - t0) / 1000))
    done
}
first=$(lat on | median); cached=$(lat on | median)
guard_off
off=$(lat off | median)
info "5  exec of a new 40 KB binary from the home, median of $ROUNDS: guard on first sight ${first} µs, guard on cached ${cached} µs, guard off ${off} µs (first sight adds ~$((first - off)) µs)"
((first < BUDGET_MS * 1000 / 2)) && pass "5  first sight decided well inside the budget (${first} µs < $((BUDGET_MS / 2)) ms)" \
    || bad "5  first sight ${first} µs: the budget, not a decision?"

echo
if ((fail)); then echo "execq check: FAIL"; else echo "execq check: PASS"; fi
exit "$fail"
