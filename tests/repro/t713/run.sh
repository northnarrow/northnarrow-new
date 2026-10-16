#!/bin/bash
# T7.13 master driver. Runs preconditions + A + B + C in sequence with
# agent restarts between scenarios so each starts from Observing and an
# empty iptables chain.
#
# Total runtime: ~4 minutes
#   - preconditions:        ~5 s
#   - reset_agent (x4):    ~40 s  (window + SIGTERM + watchdog respawn)
#   - Scenario A:          ~10 s
#   - Scenario B:          ~90 s  (60 s mass-write window + buffers)
#   - Scenario C:          ~10 s
#
# Usage:  bash run.sh           # full sequence
#         bash run.sh A         # only Scenario A
#         bash run.sh B         # only Scenario B
#         bash run.sh C         # only Scenario C
#
# Exit status (external audit NN-AUD-221): 0 only when every scenario run
# reported PASS; 1 when one reproduced the bug, regressed or saw something
# unexpected; 2 when one could not conclude (stimulus not produced) and
# nothing failed. The scenarios use the same codes.

set -uo pipefail
SD="$(dirname "$(readlink -f "$0")")"

# External audit EBPF-001: the agent unit refuses `systemctl restart`
# (RefuseManualStop) and PID 1 relays signals to it only inside a signed
# trusted-installer window. Reset the way the lab's anti-tamper suite
# does (deploy/lab/adversarial/anti-tamper.sh restart_agent): open the
# window with the lab key, SIGTERM the agent, wait for the watchdog to
# bring up a new pid (start the unit by hand after 30 s). The new agent
# boots in Observing and its reconciler drops a stale COMBAT chain.
nn_admin() {
  local exe
  exe=$(systemctl show -p ExecStart --value northnarrow-agent 2>/dev/null \
        | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)
  echo "$(dirname "${exe:-/usr/local/bin/northnarrow-agent}")/nn-admin"
}
admin_key() {
  local k
  for k in "${NN_ADMIN_KEY:-}" /root/northnarrow-admin.key /etc/northnarrow/admin.key; do
    [[ -n "$k" ]] && sudo test -r "$k" && { echo "$k"; return 0; }
  done
  return 1
}
reset_agent() {
  local old new key i
  echo; echo ">>> resetting agent (posture -> Observing)"
  key=$(admin_key) || { echo "FAIL: no admin key for the trusted-installer window"; exit 1; }
  old=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
  sudo "$(nn_admin)" trusted-installer-grant --key "$key" --window-secs 120 >/dev/null \
    || { echo "FAIL: trusted-installer grant refused ($key)"; exit 1; }
  sudo systemctl kill --signal=SIGTERM northnarrow-agent
  new=""
  for i in $(seq 1 30); do
    sleep 1
    new=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
    [[ -n "$new" && "$new" != "$old" ]] && sudo kill -0 "$new" 2>/dev/null && break
    new=""
  done
  if [[ -z "$new" ]]; then
    sudo systemctl start northnarrow-agent
    new=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
  fi
  [[ -n "$new" && "$new" != "$old" ]] || { echo "FAIL: the agent did not come back with a new pid"; exit 1; }
  sleep 3
  if sudo iptables -L NORTHNARROW_COMBAT >/dev/null 2>&1; then
    echo "FAIL: stale chain survived restart — manual cleanup needed"
    exit 1
  fi
  echo ">>> agent pid $old -> $new"
}

WHICH=${1:-ALL}
case "$WHICH" in ALL|A|B|C) ;; *) echo "usage: bash run.sh [A|B|C]"; exit 2 ;; esac

bash "$SD/pre.sh" || exit 1
reset_agent

declare -A RC
run_scenario() { # letter script title
  echo; echo "##### SCENARIO $1: $3 #####"
  bash "$SD/$2"
  RC[$1]=$?
  reset_agent
}

[[ "$WHICH" == ALL || "$WHICH" == A ]] && run_scenario A scenario_a_direct_sudo.sh "direct sudo /etc/shadow"
[[ "$WHICH" == ALL || "$WHICH" == B ]] && run_scenario B scenario_b_sudo_apt.sh "sudo subprocess mass-write"
[[ "$WHICH" == ALL || "$WHICH" == C ]] && run_scenario C scenario_c_ransomware_shape.sh "ransomware-shape (NEGATIVE CONTROL)"

rc=0
echo; echo "##### SUMMARY #####"
for s in A B C; do
  [[ -n "${RC[$s]:-}" ]] || continue
  case "${RC[$s]}" in
    0) st=PASS ;;
    2) st="INCONCLUSIVE (stimulus not produced)"; (( rc == 0 )) && rc=2 ;;
    *) st="FAIL (rc=${RC[$s]})"; rc=1 ;;
  esac
  echo "  scenario $s: $st"
done
echo "##### DONE — rc=$rc #####"
exit "$rc"
