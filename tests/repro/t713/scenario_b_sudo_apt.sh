#!/bin/bash
# T7.13 Scenario B — sudo subprocess mass-write cascade.
# Exercises the `confirmed_intrusion` mass-write arm via the new
# auth-lineage exemption (T7.13 PRIMARY AMPLIFIER -> COMBAT).
#
# Stimulus: `sudo apt-get -qq update` (or `dnf -q makecache`, or a
#            deterministic shell-loop fallback).
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
#          Recovery from another local console:
#            sudo systemctl restart northnarrow-agent
#          The agent's reconcile-stale-chain logic (main.rs:872+)
#          tears down the orphaned chain at boot.
#
# Runtime: ~90 s

set -u
trap 'kill ${JCTL:-0} 2>/dev/null; wait ${JCTL:-0} 2>/dev/null || true' EXIT

LOG=$(mktemp -t t713-B.XXXX.log)
echo "Tailing journal -> $LOG"

sudo journalctl --namespace=northnarrow -fu northnarrow-agent --since "now" > "$LOG" &
JCTL=$!
sleep 1

echo "[t=0] choosing sudo-subprocess workload"
if command -v apt-get >/dev/null; then
  echo "  using: sudo apt-get -qq update  (>50 writes via sudo subprocess)"
  sudo apt-get -qq update
elif command -v dnf >/dev/null; then
  echo "  using: sudo dnf -q makecache    (>50 writes via sudo subprocess)"
  sudo dnf -q makecache
else
  echo "  fallback: sudo bash -c '30 writes'"
  sudo bash -c 'mkdir -p /tmp/t713-B && for i in {1..30}; do echo $i > /tmp/t713-B/f_$i; done'
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

# Cleanup fallback workdir
sudo rm -rf /tmp/t713-B 2>/dev/null

# Assertion
POSTURE=$(sudo nn-admin status --json 2>/dev/null | jq -r '.posture // empty')
if [[ "$POSTURE" == "Observing" ]]; then
  echo; echo "RESULT: PASS (post-fix — sudo cascade fully suppressed)"
elif [[ "$POSTURE" == "Combat" ]]; then
  echo; echo "RESULT: PRE-FIX BUG REPRODUCED (posture=Combat — SSH may have died)"
else
  echo; echo "RESULT: UNEXPECTED (posture=$POSTURE)"
fi

echo; echo "--- log saved at $LOG ---"
