#!/usr/bin/env bash
# The re-check of #482: one canary trip on an nn-lab guest (our own guests
# only; the provisioning marker), as root, to run under thread-caps.sh's
# trace — the trip's access row and registry mark are the writer's
# (nn-canary-log), the trip event is the decision's, and the decision's
# filter must refuse it nothing (thread-caps.sh's decision-refused.tsv).
#
#   1. the lab key given canary-manage if it lacks it (a signed
#      trusted-installer window, the agent started again — as
#      deploy/lab/cow/cow-check.sh grants response-manage);
#   2. a File canary deployed at /srv/nn-canary-trip/decoy.txt;
#   3. a disposable reader (a child shell of its own, never this script)
#      opens it;
#   4. the canary listed tripped (its access row written, its registry
#      marked: the writer's work), within 20 s;
#   5. the canary burnt, its directory removed.
#
# Exit: 0 tripped and recorded, 1 not, 2 not run (a prerequisite missing).
set -u
export LC_ALL=C
ETC=/etc/northnarrow
MARKER=/var/lib/nn-lab-provisioned
DIR=/srv/nn-canary-trip
say() { printf 'canary-trip: %s\n' "$*"; }
fail() { say "FAIL — $*"; cleanup; exit 1; }
notrun() { say "NOT RUN — $*"; exit 2; }
[[ $(id -u) == 0 ]] || notrun "run as root (sudo)"
[[ -e $MARKER ]] || notrun "not an nn-lab guest ($MARKER missing)"

NN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
[[ -x $NN ]] || NN=/usr/local/bin/nn-admin
KEY=$(for k in /root/northnarrow-admin.key $ETC/admin.key; do test -r "$k" && { echo "$k"; break; }; done)
[[ -n $KEY ]] || notrun "no lab admin key (/root/northnarrow-admin.key)"
A=(--key "$KEY")

agent_pid() { cat /run/northnarrow/agent.pid 2>/dev/null; }
window() { "$NN" trusted-installer-grant "${A[@]}" --window-secs "${1:-120}" >/dev/null 2>&1; }
restart_agent() {
    local old new i
    old=$(agent_pid)
    window 120
    systemctl daemon-reload
    systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 30); do
        sleep 1
        new=$(agent_pid)
        [[ -n $new && $new != "$old" ]] && kill -0 "$new" 2>/dev/null && { sleep 5; return 0; }
    done
    systemctl start northnarrow-agent
    sleep 5
}
ensure_role() {
    grep -q "$1" $ETC/admin.pub && return 0
    say "granting $1 to the lab key"
    window 120
    sed -i -E "/$1/! s/^([0-9a-fA-F]{64})[[:space:]]+([a-z,-]+)\$/\\1 \\2,$1/" $ETC/admin.pub
    restart_agent
}
ID=
cleanup() {
    [[ -n $ID ]] && "$NN" canary burn --canary-id "$ID" "${A[@]}" >/dev/null 2>&1
    rm -rf "$DIR"
}
tripped() { # the canary's entry in `canary list` (JSONL) says tripped
    "$NN" canary list "${A[@]}" 2>/dev/null | python3 -I -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    e = json.loads(line)
    if sys.argv[1] in (e.get("canary_id"), e.get("id")):
        sys.exit(0 if e.get("tripped") else 1)
sys.exit(1)' "$ID"
}

ensure_role canary-manage
ensure_role canary-read
mkdir -p "$DIR"
out=$("$NN" canary deploy --name nn-lab-trip "${A[@]}" file --path "$DIR/decoy.txt" 2>&1) \
    || fail "deploy refused: $out"
ID=$(grep -oE '[0-9a-f]{32}' <<<"$out" | head -1)
[[ -n $ID ]] || fail "no canary id in: $out"
say "deployed $ID at $DIR/decoy.txt"
sleep 3
tripped && fail "tripped before any read"
# the reader: a child of its own (the agent may answer it)
bash -c "cat '$DIR/decoy.txt' > /dev/null" 2>/dev/null
say "read by a disposable child"
for _ in $(seq 1 20); do
    sleep 1
    if tripped; then
        say "tripped and recorded (the access row and the registry mark: the writer's)"
        "$NN" canary list "${A[@]}" 2>/dev/null | grep -F "$ID"
        cleanup
        say "PASS"
        exit 0
    fi
done
"$NN" canary list "${A[@]}" 2>&1 | grep -F "$ID"
fail "not listed tripped within 20 s"
