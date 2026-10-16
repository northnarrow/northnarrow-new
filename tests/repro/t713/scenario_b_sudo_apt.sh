#!/bin/bash
# T7.13 Scenario B — sudo subprocess mass-write cascade.
# Exercises the `confirmed_intrusion` mass-write arm via the new
# auth-lineage exemption (T7.13 PRIMARY AMPLIFIER -> COMBAT).
#
# Stimulus: `sudo apt-get -qq update` (or `dnf -q makecache`), best
#            effort, then ALWAYS 30 deterministic writes by a sudo
#            subprocess, counted before the verdict.
# Mechanism: apt's PID is a child of sudo. apt does >=20 write-opens
#            within 60 s while refreshing /var/cache/apt and
#            /var/lib/apt/lists. Pre-fix this trips
#            `confirmed_intrusion` mass-write arm with
#            target_level=Combat. Combined with the ALERTED already
#            raised by sudo's shadow read, the rank-by-target_level
#            sort in PostureMachine::observe collapses the cascade
#            into a single OBSERVING -> COMBAT hop.
#
# Pre-fix observable timeline:
#   t≈0.5s   POSTURE TRANSITION state=ALERTED  (sudo shadow read)
#   t≈30-60s POSTURE TRANSITION state=COMBAT   (mass-write hits 20)
#   t+1s     NORTHNARROW_COMBAT chain installed
#   t+1s     non-loopback traffic dropped; SSH may die
#   t+1s     nn-admin status: posture=Combat, isolation=true
#
# Post-fix observable timeline:
#   t≈0.2s   ProcessSpawn{pid=sudo, exe=/usr/bin/sudo} ingested
#   t≈0.3s   ProcessSpawn{pid=apt,  ppid=sudo}        ingested
#   t≈0.3s   /etc/shadow open suppressed (auth-mediated)
#   t≈0.3s+ apt write-open events: mass-write arm queries
#            is_auth_mediated(apt.pid) -> true -> returns false
#   no transition; posture stays Observing
#
# WARNING: If pre-fix COMBAT engages, external network is blocked.
#          Recovery from another local console: run.sh's reset_agent
#          (trusted-installer window + SIGTERM; `systemctl restart` is
#          refused since EBPF-001). The agent's reconcile-stale-chain
#          logic tears down the orphaned chain at boot.
#
# Runtime: ~90 s
#
# Exit status (external audit NN-AUD-221): 0 PASS, 1 bug reproduced or
# unexpected posture, 2 inconclusive (the 30 deterministic writes did not
# all land, so a quiet posture would prove nothing).

set -u
# Kill only a journal tail this script started: with JCTL unset the old
# `kill ${JCTL:-0}` signalled the whole process group (run.sh included).
JCTL=""
WDIR=""
trap '[ -n "$JCTL" ] && { kill "$JCTL" 2>/dev/null; wait "$JCTL" 2>/dev/null; }; [ -n "$WDIR" ] && sudo rm -rf "$WDIR"; true' EXIT

LOG=$(mktemp -t t713-B.XXXX.log)
echo "Tailing journal -> $LOG"

sudo journalctl --namespace=northnarrow -fu northnarrow-agent --since "now" > "$LOG" &
JCTL=$!
sleep 1

# The package manager is the realistic stimulus, but it needs a network
# (an isolated range has none) and a refresh with nothing new may write
# little. It is best-effort; the deterministic stimulus below always runs
# and is counted, so the verdict never rests on writes that did not happen.
echo "[t=0] sudo-subprocess workload"
if command -v apt-get >/dev/null; then
  echo "  best-effort: sudo apt-get -qq update"
  sudo apt-get -qq update || echo "  (apt-get update failed — offline range?)"
elif command -v dnf >/dev/null; then
  echo "  best-effort: sudo dnf -q makecache"
  sudo dnf -q makecache || echo "  (dnf makecache failed — offline range?)"
fi
WDIR=$(sudo mktemp -d /tmp/t713-B.XXXXXX) || { echo "RESULT: INCONCLUSIVE (mktemp failed)"; exit 2; }
echo "  deterministic: sudo bash -c '30 writes into $WDIR'"
sudo bash -c 'for i in $(seq 1 30); do echo "$i" > "$1/f_$i"; done' t713-B "$WDIR"
WRITES=$(sudo find "$WDIR" -maxdepth 1 -type f -name 'f_*' | wc -l)
echo "  files written: $WRITES/30"
if [[ "$WRITES" -ne 30 ]]; then
  echo; echo "RESULT: INCONCLUSIVE (only $WRITES of the 30 writes landed — writer killed?)"
  exit 2
fi

echo "[t=2s] waiting 65 s for mass-write window to populate"
sleep 65
sleep 5   # observation buffer

kill "$JCTL" 2>/dev/null; wait "$JCTL" 2>/dev/null

echo; echo "=== Posture transitions observed ==="
grep -E 'POSTURE TRANSITION|ConfirmedIntrusion|SensitiveFileAccess' "$LOG" || echo "(none)"

echo; echo "=== NORTHNARROW_COMBAT chain ==="
sudo iptables -L NORTHNARROW_COMBAT -n 2>&1 | head -5 || echo "(chain absent)"

echo; echo "=== nn-admin status ==="
sudo nn-admin status --json 2>/dev/null \
  | jq -r '"posture=" + .posture + "  isolation=" + (.network_isolation_engaged|tostring)'

# Assertion (the workdir goes with the EXIT trap)
POSTURE=$(sudo nn-admin status --json 2>/dev/null | jq -r '.posture // empty')
if [[ "$POSTURE" == "Observing" ]]; then
  echo; echo "RESULT: PASS (post-fix — sudo cascade fully suppressed)"; rc=0
elif [[ "$POSTURE" == "Combat" ]]; then
  echo; echo "RESULT: PRE-FIX BUG REPRODUCED (posture=Combat — SSH may have died)"; rc=1
else
  echo; echo "RESULT: UNEXPECTED (posture=${POSTURE:-unreadable})"; rc=1
fi

echo; echo "--- log saved at $LOG ---"
exit "$rc"
