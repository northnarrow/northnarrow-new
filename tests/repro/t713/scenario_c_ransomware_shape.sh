#!/bin/bash
# T7.13 Scenario C — NEGATIVE CONTROL: ransomware shape from /tmp.
# Verifies the fix does NOT suppress the response to a /tmp exec.
#
# Stimulus: copy /bin/sh to /tmp/payload (no sudo — uid=1000 owns /tmp),
#           then exec it to do 30 file writes.
# Mechanism (since external audit POS-015, lab PR 141, and POS-001): an
#            exec from /tmp is a `StagingExec` trigger — ENGAGED, not a
#            COMBAT on its own — and R001 kills it at once; COMBAT needs a
#            second class of evidence. The lineage gate that the T7.13 fix
#            added suppresses only sensitive_file_access and the mass-write
#            arm for sudo/apt lineages; this exec has no such lineage.
#
# Expected (pre-fix and post-fix — this is the regression guard): an R001
# verdict for the payload and the posture out of Observing (ENGAGED, or
# COMBAT if other evidence joined). Still Observing, or no R001 verdict,
# means the lineage gate exempted a /tmp exec: a regression.
#
# Runtime: ~10 s
#
# Exit status (external audit NN-AUD-221): 0 PASS (Combat), 1 regression,
# 2 inconclusive (the payload could not be staged in /tmp).

set -u
# Kill only a journal tail this script started: with JCTL unset the old
# `kill ${JCTL:-0}` signalled the whole process group (run.sh included).
JCTL=""
trap '[ -n "$JCTL" ] && { kill "$JCTL" 2>/dev/null; wait "$JCTL" 2>/dev/null; }; true' EXIT

LOG=$(mktemp -t t713-C.XXXX.log)
echo "Tailing journal -> $LOG"

sudo journalctl --namespace=northnarrow -fu northnarrow-agent --since "now" > "$LOG" &
JCTL=$!
sleep 1

PAYLOAD=/tmp/t713-payload-$$
WORKDIR=/tmp/t713-C-$$
if ! { cp /bin/sh "$PAYLOAD" && chmod +x "$PAYLOAD" && mkdir -p "$WORKDIR"; }; then
  echo; echo "RESULT: INCONCLUSIVE (could not stage $PAYLOAD)"
  rm -f "$PAYLOAD"; rm -rf "$WORKDIR"
  exit 2
fi

# The agent may kill the payload on exec (that is the point): its own
# exit status says nothing, the posture below does.
echo "[t=0] exec'ing $PAYLOAD (uid=$UID, no sudo, no auth ancestor)"
"$PAYLOAD" -c "for i in \$(seq 1 30); do echo \$i > $WORKDIR/f_\$i; done"

sleep 5

kill "$JCTL" 2>/dev/null; wait "$JCTL" 2>/dev/null

echo; echo "=== Posture transitions observed ==="
grep -E 'POSTURE TRANSITION|ConfirmedIntrusion|StagingExec|R001_ExecFromTmp' "$LOG" || echo "(none)"

echo; echo "=== NORTHNARROW_COMBAT chain ==="
sudo iptables -L NORTHNARROW_COMBAT -n 2>&1 | head -5 || echo "(chain absent)"

echo; echo "=== nn-admin status ==="
sudo nn-admin status --json 2>/dev/null \
  | jq -r '"posture=" + .posture + "  isolation=" + (.network_isolation_engaged|tostring)'

# Cleanup
rm -f "$PAYLOAD"
rm -rf "$WORKDIR"

# Assertion (external audit NN-AUD-221: this check can fail)
POSTURE=$(sudo nn-admin status --json 2>/dev/null | jq -r '.posture // empty')
R001=$(grep -c "R001_ExecFromTmp.*t713-payload-$$" "$LOG" || true)
if [[ "$POSTURE" == "Engaged" || "$POSTURE" == "Combat" ]] && [[ "${R001:-0}" -ge 1 ]]; then
  echo; echo "RESULT: PASS (negative control held — the /tmp exec drew R001 and moved the posture to $POSTURE)"; rc=0
elif [[ -z "$POSTURE" ]]; then
  echo; echo "RESULT: INCONCLUSIVE (posture unreadable)"; rc=2
else
  echo; echo "RESULT: REGRESSION (posture=$POSTURE, R001 verdicts for the payload: ${R001:-0}; expected Engaged or Combat and one). Lineage gate is too broad."; rc=1
fi

echo; echo "--- log saved at $LOG ---"
echo "--- NOTE: the posture is no longer Observing (expected). Reset before the next test:"
echo "          run.sh resets it (trusted-installer window + SIGTERM; systemctl restart is refused)"
exit "$rc"
