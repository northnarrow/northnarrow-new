#!/bin/bash
# T7.13 master driver. Runs preconditions + A + B + C in sequence with
# agent restarts between scenarios so each starts from Observing and an
# empty iptables chain.
#
# Total runtime: ~3 minutes
#   - preconditions:        ~5 s
#   - reset_agent (x4):    ~20 s  (restart + 3 s settle)
#   - Scenario A:          ~10 s
#   - Scenario B:          ~90 s  (60 s mass-write window + buffers)
#   - Scenario C:          ~10 s
#
# Usage:  bash run.sh           # full sequence
#         bash run.sh A         # only Scenario A
#         bash run.sh B         # only Scenario B
#         bash run.sh C         # only Scenario C

set -uo pipefail
SD="$(dirname "$(readlink -f "$0")")"

reset_agent() {
  echo; echo ">>> resetting agent (posture -> Observing)"
  sudo systemctl restart northnarrow-agent
  sleep 3
  if sudo iptables -L NORTHNARROW_COMBAT >/dev/null 2>&1; then
    echo "FAIL: stale chain survived restart — manual cleanup needed"
    exit 1
  fi
}

WHICH=${1:-ALL}

bash "$SD/pre.sh" || exit 1
reset_agent

if [[ "$WHICH" == "ALL" || "$WHICH" == "A" ]]; then
  echo; echo "##### SCENARIO A: direct sudo /etc/shadow #####"
  bash "$SD/scenario_a_direct_sudo.sh"
  reset_agent
fi

if [[ "$WHICH" == "ALL" || "$WHICH" == "B" ]]; then
  echo; echo "##### SCENARIO B: sudo subprocess mass-write #####"
  bash "$SD/scenario_b_sudo_apt.sh"
  reset_agent
fi

if [[ "$WHICH" == "ALL" || "$WHICH" == "C" ]]; then
  echo; echo "##### SCENARIO C: ransomware-shape (NEGATIVE CONTROL) #####"
  bash "$SD/scenario_c_ransomware_shape.sh"
  reset_agent
fi

echo; echo "##### DONE — see individual scenario RESULT lines. #####"
