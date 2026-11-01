#!/usr/bin/env bash
# R12c-2 (lab PR 270; report 06 INI-14, EXP-33): the heartbeat's external
# verifier run on the HOST against an nn-lab guest — normal beats, then a
# replayed export, a tampered beat, the agent frozen, the network cut and the
# agent stopped, each of which must alert; the time to each alert measured.
# Our own lab guests only (nn-lab.sh's), the agent installed from the tree.
#
# usage: watch-lab.sh <out-dir> [nn-admin]   (from the tree's root, with
#        NN_LAB_DISTRO naming the guest; nn-admin: a host build of this
#        tree's, default target/release/nn-admin)
#
# The verifier (`nn-admin heartbeat watch --every 5`) runs here in the
# background; its source is a wrapper (`fetch.sh`) that pulls the newest
# beats over the lab's SSH (`sudo -n nn-admin heartbeat export`) or, by a
# mode file, serves an old export (the replay) or the live one with one beat
# altered (the tamper) — the channel or the host lying. The guest's actions:
# `systemctl freeze`/`thaw` of the agent's unit (frozen), SSH dropped in the
# guest's firewall for 150 s with the removal scheduled inside it (the
# network cut), SIGTERM to the watchdog and the agent through a trusted-
# installer window (the stop: its signed stop beat), and their start again.
# Output: watch.log (every line the verifier printed, UTC-stamped),
# scenarios.tsv (scenario, start, first expected alert, seconds), and
# summary.txt. Exit 0 when every scenario alerted as expected.
set -u -o pipefail
OUT=${1:?out dir}
NNADMIN=${2:-target/release/nn-admin}
LAB=./deploy/lab/nn-lab.sh
[[ -x $LAB && -x $NNADMIN ]] || { echo "run from the tree's root, with $NNADMIN built" >&2; exit 2; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
NNADMIN=$(cd "$(dirname "$NNADMIN")" && pwd)/$(basename "$NNADMIN")
D=${NN_LAB_DISTRO:-ubuntu2404}
ROOT=${NN_LAB_DIR:-$HOME/.cache/nn-lab}
if [[ $D == ubuntu2404 ]]; then DIR=$ROOT; else DIR=$ROOT/$D; fi
PORT=$(cat "$DIR/ssh_port")
g() { "$LAB" ssh "$@"; }

# the agent's public key, from the guest
g 'cat /etc/northnarrow/agent.sig.pub' > "$OUT/agent.pub" || { echo "no agent.sig.pub" >&2; exit 1; }
MODE=$OUT/mode; echo live > "$MODE"
cat > "$OUT/fetch.sh" <<EOF
#!/usr/bin/env bash
# the verifier's source: the guest's export over SSH, or what the mode says
live() { ssh -i "$ROOT/id_ed25519" -p $PORT -o BatchMode=yes -o ConnectTimeout=5 \\
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$DIR/known_hosts" \\
  -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=nn-lab-$D -o HostKeyAlgorithms=ssh-ed25519 \\
  -o CheckHostIP=no -o LogLevel=ERROR \\
  nn@127.0.0.1 'sudo -n /usr/local/bin/nn-admin heartbeat export --count 64'; }
case \$(cat "$MODE") in
  replay) cat "$OUT/old-export.jsonl" ;;
  tamper) live | python3 -I -c 'import sys
lines = sys.stdin.read().splitlines()
for i in range(len(lines) - 1, -1, -1):
    if "\"kind\":\"beat\"" in lines[i] or "\"kind\":\"start\"" in lines[i]:
        lines[i] = lines[i].replace("\"posture\":\"", "\"posture\":\"x", 1); break
print("\n".join(lines))' ;;
  *) live ;;
esac
EOF
chmod +x "$OUT/fetch.sh"
"$OUT/fetch.sh" > "$OUT/old-export.jsonl" || { echo "the first fetch failed" >&2; exit 1; }

STATE=$OUT/state.json; rm -f "$STATE"
"$NNADMIN" heartbeat watch --agent-pubkey-file "$OUT/agent.pub" --from-cmd "$OUT/fetch.sh" \
  --state "$STATE" --every 5 > "$OUT/watch.log" 2>&1 &
WPID=$!
trap 'kill "$WPID" 2>/dev/null' EXIT
now() { date -u +%FT%T.%6NZ; }
TSV=$OUT/scenarios.tsv; printf 'scenario\tstart\talert\tseconds\n' > "$TSV"
# the first ALERT of kind $2 at or after $1 within $3 s: its line's time
wait_alert() {
  local since=$1 kind=$2 within=$3 end=$((SECONDS + within)) t
  while ((SECONDS < end)); do
    t=$(awk -v s="$since" -v k="ALERT $kind" '$1 >= s && index($0, k) {print $1; exit}' "$OUT/watch.log")
    [[ -n $t ]] && { echo "$t"; return 0; }
    sleep 1
  done
  return 1
}
wait_ok() {
  local since=$1 within=$2 end=$((SECONDS + within))
  while ((SECONDS < end)); do
    awk -v s="$since" '$1 >= s && $2 == "OK" {f=1} END {exit !f}' "$OUT/watch.log" && return 0
    sleep 1
  done
  return 1
}
secs() { python3 -I -c 'import sys,datetime as d
p=lambda s: d.datetime.strptime(s[:26], "%Y-%m-%dT%H:%M:%S.%f")
print(round((p(sys.argv[2]) - p(sys.argv[1])).total_seconds(), 1))' "$1" "$2"; }
fails=0
scenario() { # name kind within action...
  local name=$1 kind=$2 within=$3; shift 3
  local t0 t
  t0=$(now)
  "$@"
  if t=$(wait_alert "$t0" "$kind" "$within"); then
    printf '%s\t%s\t%s\t%s\n' "$name" "$t0" "$t" "$(secs "$t0" "$t")" >> "$TSV"
  else
    printf '%s\t%s\t-\tNO ALERT within %s s\n' "$name" "$t0" "$within" >> "$TSV"
    fails=$((fails + 1))
  fi
}

# 0. normal beats: anchored, then OK only, for 70 s (two beats at 30 s)
t0=$(now); sleep 70
if awk -v s="$t0" '$1 >= s && $2 == "ALERT"' "$OUT/watch.log" | grep -q .; then
  printf 'normal\t%s\t-\tALERT while normal\n' "$t0" >> "$TSV"; fails=$((fails + 1))
else
  printf 'normal\t%s\t-\tOK (%s checks)\n' "$t0" "$(awk -v s="$t0" '$1 >= s && $2 == "OK"' "$OUT/watch.log" | wc -l)" >> "$TSV"
fi
# 1. a replayed (older) export
scenario replay REPLAY 30 sh -c "echo replay > '$MODE'"
echo live > "$MODE"; wait_ok "$(now)" 30 || true
# 2. a beat altered on the way
scenario tamper TAMPERED 30 sh -c "echo tamper > '$MODE'"
echo live > "$MODE"; wait_ok "$(now)" 30 || true
# 3. the agent frozen (its cgroup), thawed after the alert
scenario freeze SILENT 180 g 'sudo systemctl freeze northnarrow-agent'
g 'sudo systemctl thaw northnarrow-agent'; wait_ok "$(now)" 120 || true
# 4. the network cut: SSH dropped in the guest for 150 s
scenario netcut SILENT 180 g 'sudo systemd-run --quiet --on-active=150 iptables -D INPUT -p tcp --dport 22 -j DROP && sudo iptables -I INPUT -p tcp --dport 22 -j DROP'
wait_ok "$(now)" 240 || true
# 5. the agent stopped (SIGTERM through a trusted-installer window): its
#    signed stop beat; then started again (a start beat, a new run)
scenario stop STOPPED 60 g 'k=$(for f in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r $f && { echo $f; break; }; done); sudo /usr/local/bin/nn-admin trusted-installer-grant --key $k --window-secs 120 >/dev/null && sudo systemctl kill -s SIGTERM northnarrow-watchdog && sleep 1 && sudo systemctl kill -s SIGTERM northnarrow-agent'
g 'sudo systemctl start northnarrow-agent northnarrow-watchdog'; wait_ok "$(now)" 120 || true
sleep 10
kill "$WPID" 2>/dev/null; trap - EXIT
{
  echo "heartbeat watch lab on $D: $fails scenario(s) without their alert"
  column -t -s $'\t' "$TSV"
} > "$OUT/summary.txt"
cat "$OUT/summary.txt"
exit $((fails > 0))
