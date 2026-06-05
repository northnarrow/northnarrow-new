#!/bin/bash
# T7.13 Scenario C — NEGATIVE CONTROL: ransomware shape from /tmp.
# Verifies the fix does NOT suppress legitimate ConfirmedIntrusion.
#
# Stimulus: copy /bin/sh to /tmp/payload (no sudo — uid=1000 owns /tmp),
#           then exec it to do 30 file writes.
# Mechanism: exec from /tmp/ trips `confirmed_intrusion`'s exec-from-
#            /tmp arm IMMEDIATELY on ProcessSpawn (single-event COMBAT).
#            The lineage gate ONLY suppresses sensitive_file_access and
#            the mass-write arm; the exec-from-/tmp arm,
#            FsProtectDenial, persistence_mechanism, lateral_movement,
#            exploit_attempt, lolbas_pattern and exfiltration_pattern
#            are UNAFFECTED — same logic.
#
# Pre-fix AND post-fix expected timeline (identical — this is the
# regression guard):
#   t≈0.2s  ProcessSpawn{filename=/tmp/payload-<pid>} ingested
#   t≈0.3s  confirmed_intrusion exec-from-/tmp arm fires; target=Combat
#   t≈0.5s  POSTURE TRANSITION state=COMBAT
#   t≈0.5s  NORTHNARROW_COMBAT chain installed
#
# A post-fix observation that COMBAT did NOT engage here means the
# lineage gate is too broad (regression — fix exempts /tmp execs by
# mistake).
#
# Runtime: ~10 s

set -u
trap 'kill ${JCTL:-0} 2>/dev/null; wait ${JCTL:-0} 2>/dev/null || true' EXIT

LOG=$(mktemp -t t713-C.XXXX.log)
echo "Tailing journal -> $LOG"

sudo journalctl --namespace=northnarrow -fu northnarrow-agent --since "now" > "$LOG" &
JCTL=$!
sleep 1

PAYLOAD=/tmp/t713-payload-$$
WORKDIR=/tmp/t713-C-$$
cp /bin/sh "$PAYLOAD"
chmod +x "$PAYLOAD"
mkdir -p "$WORKDIR"

echo "[t=0] exec'ing $PAYLOAD (uid=$UID, no sudo, no auth ancestor)"
"$PAYLOAD" -c "for i in \$(seq 1 30); do echo \$i > $WORKDIR/f_\$i; done"

sleep 5

kill "$JCTL" 2>/dev/null; wait "$JCTL" 2>/dev/null

echo; echo "=== Posture transitions observed ==="
grep -E 'POSTURE TRANSITION|ConfirmedIntrusion' "$LOG" || echo "(none)"

echo; echo "=== NORTHNARROW_COMBAT chain ==="
sudo iptables -L NORTHNARROW_COMBAT -n 2>&1 | head -5 || echo "(chain absent)"

echo; echo "=== nn-admin status ==="
sudo nn-admin status --json 2>/dev/null \
  | jq -r '"posture=" + .posture + "  isolation=" + (.network_isolation_engaged|tostring)'

# Cleanup
rm -f "$PAYLOAD"
rm -rf "$WORKDIR"

# Assertion — MUST be Combat for both pre and post fix
POSTURE=$(sudo nn-admin status --json 2>/dev/null | jq -r '.posture // empty')
if [[ "$POSTURE" == "Combat" ]]; then
  echo; echo "RESULT: PASS (negative control held — /tmp exec still drives COMBAT)"
else
  echo; echo "RESULT: REGRESSION (posture=$POSTURE; expected Combat). Lineage gate is too broad."
fi

echo; echo "--- log saved at $LOG ---"
echo "--- NOTE: Posture is now Combat (expected). Reset before next test:"
echo "          sudo systemctl restart northnarrow-agent"
