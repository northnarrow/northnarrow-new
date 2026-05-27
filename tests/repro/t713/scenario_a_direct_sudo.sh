#!/bin/bash
# T7.13 Scenario A — direct sudo /etc/shadow read.
# Exercises the `sensitive_file_access` trigger surface (T7.13 PRIMARY).
#
# Stimulus: `sudo cat /etc/shadow > /dev/null`
# Mechanism: sudo's PAM auth chain opens /etc/shadow while the kernel
#            is still at the caller's uid=1000 (LSM file_open hook
#            fires BEFORE the setuid transition completes). Pre-fix
#            this trips `sensitive_file_access` -> SensitiveFileAccess
#            -> OBSERVING -> ALERTED.
#
# This scenario alone does NOT reach COMBAT (target_level=Alerted).
# Scenario B exercises the full cascade.
#
# Pre-fix observable timeline (within ~3 s of sudo invocation):
#   t≈0.2s  sudo opens /etc/shadow (uid=1000)
#   t≈0.5s  "POSTURE TRANSITION state=ALERTED" in journal
#   t≈0.5s  nn-admin status: posture=Alerted
#           NORTHNARROW_COMBAT chain: absent (Alerted doesn't engage)
#
# Post-fix observable timeline:
#   t≈0.2s  sudo opens /etc/shadow (uid=1000, exe=/usr/bin/sudo)
#   t≈0.2s  AuthSessionTracker.is_auth_mediated(sudo.pid) -> true
#   t≈0.2s  sensitive_file_access returns false; NO trigger
#   no transition; posture stays Observing
#
# Runtime: ~10 s

set -u
trap 'kill ${JCTL:-0} 2>/dev/null; wait ${JCTL:-0} 2>/dev/null || true' EXIT

LOG=$(mktemp -t t713-A.XXXX.log)
echo "Tailing journal -> $LOG"

sudo journalctl -fu northnarrow-agent --since "now" > "$LOG" &
JCTL=$!
sleep 1

echo "[t=0] firing: sudo cat /etc/shadow > /dev/null"
sudo cat /etc/shadow > /dev/null

# Per-event posture evaluation is async (mpsc + tokio); 5 s is generous.
sleep 5

kill "$JCTL" 2>/dev/null; wait "$JCTL" 2>/dev/null

echo; echo "=== Posture transitions observed ==="
grep -E 'POSTURE TRANSITION|SensitiveFileAccess' "$LOG" || echo "(none)"

echo; echo "=== NORTHNARROW_COMBAT chain ==="
sudo iptables -L NORTHNARROW_COMBAT -n 2>&1 | head -5 || echo "(chain absent)"

echo; echo "=== nn-admin status ==="
sudo nn-admin status --json 2>/dev/null \
  | jq -r '"posture=" + .posture + "  isolation=" + (.network_isolation_engaged|tostring)'

# Assertion
POSTURE=$(sudo nn-admin status --json 2>/dev/null | jq -r '.posture // empty')
if [[ "$POSTURE" == "Observing" ]]; then
  echo; echo "RESULT: PASS (post-fix — posture remained Observing)"
elif [[ "$POSTURE" == "Alerted" ]]; then
  echo; echo "RESULT: PRE-FIX BUG REPRODUCED (posture=Alerted)"
else
  echo; echo "RESULT: UNEXPECTED (posture=$POSTURE)"
fi

echo; echo "--- log saved at $LOG ---"
