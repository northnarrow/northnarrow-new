#!/usr/bin/env bash
# R12c-2 (lab PR 270; review of #478): the heartbeat verifier on the HOST
# against an nn-lab guest — the guest's clock ahead, then back, a restart
# with the clock behind (the RTC after a reboot), and the actions chain's
# newest archive removed while the agent runs. Our own lab guests only
# (nn-lab.sh's), the agent installed from the tree.
#
# usage: clock-lab.sh <out-dir> [nn-admin]   (from the tree's root, with
#        NN_LAB_DISTRO naming the guest; nn-admin: a host build of this
#        tree's)
#
# Expected: clock ahead DEGRADED ("ahead of the verifier's"), clock back
# DEGRADED ("clock went back"), restart with the clock behind STOPPED then
# DEGRADED and never REPLAY, the archive removed REPLAY ("no longer holds
# the head"). The actions chain rotates at 1 MiB for the run (the systemd
# manager's environment, `NN_ACTIONS_CAP_BYTES`, removed at the end — the
# self-integrity check reports it as a weakening meanwhile: a DEGRADED
# beside). Output: watch.log, scenarios.tsv (scenario, start, alert,
# seconds, and whether a REPLAY or TAMPERED came, which none should but
# the archive's), summary.txt.
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
GRANT='k=$(for f in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r $f && { echo $f; break; }; done); sudo /usr/local/bin/nn-admin trusted-installer-grant --key $k --window-secs 120 >/dev/null'
STOP="$GRANT && sudo systemctl kill -s SIGTERM northnarrow-watchdog && sleep 1 && sudo systemctl kill -s SIGTERM northnarrow-agent && sleep 3"
START='sudo systemctl start northnarrow-agent northnarrow-watchdog'
ACT=/var/lib/northnarrow/detections/actions.jsonl

g 'cat /etc/northnarrow/agent.sig.pub' > "$OUT/agent.pub" || { echo "no agent.sig.pub" >&2; exit 1; }
cat > "$OUT/fetch.sh" <<EOF
#!/usr/bin/env bash
exec ssh -i "$ROOT/id_ed25519" -p $PORT -o BatchMode=yes -o ConnectTimeout=5 \\
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$DIR/known_hosts" \\
  -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=nn-lab-$D -o HostKeyAlgorithms=ssh-ed25519 \\
  -o CheckHostIP=no -o LogLevel=ERROR \\
  nn@127.0.0.1 'sudo -n /usr/local/bin/nn-admin heartbeat export --count 64'
EOF
chmod +x "$OUT/fetch.sh"

# the actions chain at 1 MiB for the run, and filled near it
g "sudo timedatectl set-ntp false; sudo systemctl set-environment NN_ACTIONS_CAP_BYTES=1048576; $STOP; $START" > "$OUT/setup.log" 2>&1
sleep 20
g 'mkdir -p ~/exp13' >> "$OUT/setup.log" 2>&1
g 'cat > ~/exp13/responses.sh' < ./deploy/lab/bus/responses.sh
for i in 1 2 3; do
  g "sudo bash ~/exp13/responses.sh --out /var/lib/nn-exp13r/clock-fill-$i --kills 400 --flows 0 --load-secs 0 --settle 10" >> "$OUT/setup.log" 2>&1
done
g "sudo ls -l $ACT* | cat" >> "$OUT/setup.log" 2>&1
sleep "${NN_HB_SETTLE:-60}"

STATE=$OUT/state.json; rm -f "$STATE"
"$NNADMIN" heartbeat watch --agent-pubkey-file "$OUT/agent.pub" --from-cmd "$OUT/fetch.sh" \
  --state "$STATE" --every 5 > "$OUT/watch.log" 2>&1 &
WPID=$!
trap 'kill "$WPID" 2>/dev/null; g "sudo systemctl unset-environment NN_ACTIONS_CAP_BYTES; sudo timedatectl set-ntp true" >/dev/null 2>&1' EXIT
now() { date -u +%FT%T.%6NZ; }
TSV=$OUT/scenarios.tsv; printf 'scenario\tstart\talert\tseconds\tgrave alerts\n' > "$TSV"
wait_alert() {
  local since=$1 pat=$2 within=$3 t
  local end=$((SECONDS + within))
  while ((SECONDS < end)); do
    t=$(awk -v s="$since" -v k="$pat" '$1 >= s && $0 ~ k {print $1; exit}' "$OUT/watch.log")
    [[ -n $t ]] && { echo "$t"; return 0; }
    sleep 1
  done
  return 1
}
secs() { python3 -I -c 'import sys,datetime as d
p=lambda s: d.datetime.strptime(s[:26], "%Y-%m-%dT%H:%M:%S.%f")
print(round((p(sys.argv[2]) - p(sys.argv[1])).total_seconds(), 1))' "$1" "$2"; }
fails=0
scenario() { # name pattern within action...
  local name=$1 pat=$2 within=$3; shift 3
  local t0 t grave
  t0=$(now)
  "$@"
  if t=$(wait_alert "$t0" "$pat" "$within"); then
    grave=$(awk -v s="$t0" '$1 >= s && / ALERT (REPLAY|TAMPERED) /' "$OUT/watch.log" | wc -l)
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$t0" "$t" "$(secs "$t0" "$t")" "$grave" >> "$TSV"
  else
    printf '%s\t%s\t-\tNO ALERT within %s s\t-\n' "$name" "$t0" "$within" >> "$TSV"
    fails=$((fails + 1))
  fi
  sleep 40
}
sleep 20
# 1. the guest's clock 40 s ahead
scenario clock-ahead 'ALERT DEGRADED .*ahead of the verifier' 90 g 'sudo date -s "+40 seconds" >/dev/null'
# 2. back by 40 s: the next beat stamped before the last
scenario clock-back 'ALERT DEGRADED .*clock went back' 90 g 'sudo date -s "-40 seconds" >/dev/null'
# 3. a clean stop, the clock 40 s behind, the start (an RTC behind after a
#    reboot): STOPPED, then DEGRADED, never REPLAY
scenario restart-behind 'ALERT DEGRADED .*clock went back' 120 g "$STOP; sudo date -s '-40 seconds' >/dev/null; $START"
g 'sudo date -s "+40 seconds" >/dev/null'
sleep 40
# 4. the actions chain's newest archive removed while the agent runs: right
#    after a beat, a burst that rotates the chain, the archive removed
#    before the next beat
t0=$(now)
last=$(awk '$2 == "OK" {print $3}' "$OUT/watch.log" | tail -1)
while [[ $(awk '$2 == "OK" {print $3}' "$OUT/watch.log" | tail -1) == "$last" ]]; do sleep 1; done
before=$(g "ls $ACT.* 2>/dev/null | grep -c '\.[0-9]*$' || true" 2>/dev/null | tr -d '\r')
g "sudo bash ~/exp13/responses.sh --out /var/lib/nn-exp13r/clock-rot --kills 800 --flows 0 --load-secs 0 --settle 3" >> "$OUT/setup.log" 2>&1
g "n=\$(sudo ls $ACT.* 2>/dev/null | grep -E '\\.[0-9]+\$' | sort -t. -k3 -n | tail -1); echo removing \$n; $GRANT && sudo rm -f \$n" >> "$OUT/setup.log" 2>&1
if t=$(wait_alert "$t0" 'ALERT REPLAY .*no longer holds' 90); then
  printf 'archive-removed\t%s\t%s\t%s\t-\n' "$t0" "$t" "$(secs "$t0" "$t")" >> "$TSV"
else
  printf 'archive-removed\t%s\t-\tNO ALERT within 90 s (archives before: %s)\t-\n' "$t0" "$before" >> "$TSV"
  fails=$((fails + 1))
fi
sleep 10
kill "$WPID" 2>/dev/null; trap - EXIT
g "sudo systemctl unset-environment NN_ACTIONS_CAP_BYTES; sudo timedatectl set-ntp true; $STOP; $START" >> "$OUT/setup.log" 2>&1
{
  echo "heartbeat clock lab on $D: $fails scenario(s) without their alert"
  column -t -s $'\t' "$TSV"
} > "$OUT/summary.txt"
cat "$OUT/summary.txt"
exit $((fails > 0))
