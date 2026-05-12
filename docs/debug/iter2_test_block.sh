#!/bin/bash
# Tappa 7 task 5 — iteration 2 diagnostic. (v2: prebuilt binary + jq install + dir targets)
#
# Run:  bash /home/forty/dev/northnarrow-new/iter2_test_block.sh
# Read: cat /tmp/iter2_results.txt
#
# Bugs fixed from v1:
#   1. v1 used `sudo cargo` which loses user PATH on this host. Now uses
#      the prebuilt binary at target/release/northnarrow-agent with the
#      --no-ade flag.
#   2. v1 needed jq which is not installed. Now apt-installs jq at start.
#   3. v1 attacked /var/lib/northnarrow/state.json (does not exist).
#      The PROTECTED_INODES entry is the DIRECTORY /var/lib/northnarrow.
#      Attacks now target the directory itself + a canary file inside it.

set +e

RESULT_FILE=/tmp/iter2_results.txt
AGENT_LOG=/tmp/nn-agent.log
TRACE_LOG=/tmp/trace.log

# Everything below goes into the result file (and only the result file —
# no tee, no process-substitution, no chance of partial paste issues).
exec >"$RESULT_FILE" 2>&1

cd /home/forty/dev/northnarrow-new || { echo "FATAL: cannot cd to repo"; exit 1; }

PROTECTED_DIR=/var/lib/northnarrow
CANARY=$PROTECTED_DIR/canary
HOOKS='security_inode_unlink|security_inode_rmdir|security_inode_rename|security_inode_setattr|security_file_ioctl'

echo '====================================================================='
echo '== Tappa 7 task 5 — iteration 2 diagnostic (v2)                    =='
echo '====================================================================='
echo "date:    $(date -Iseconds)"
echo "kernel:  $(uname -r)"
echo "cwd:     $(pwd)"
echo "head:    $(git log --oneline -1 2>/dev/null)"
echo "output:  $RESULT_FILE"
echo

# -- 0. ensure jq is available --
echo '--- ensure jq is installed ---'
if ! command -v jq >/dev/null; then
  sudo apt-get install -y jq 2>&1 | tail -5
fi
if command -v jq >/dev/null; then
  echo "jq: $(command -v jq) ($(jq --version))"
else
  echo "WARNING: jq still missing — Part B JSON parsing will degrade."
fi

# -- 1. detach prior LSM links (so we can kill prior agent) --
echo
echo '--- detach prior LSM links (force-clear stale state) ---'
if command -v jq >/dev/null; then
  LINK_IDS=$(sudo bpftool link show -j 2>/dev/null | jq -r '.[] | select(.type=="lsm") | .id')
else
  LINK_IDS=$(sudo bpftool link show 2>/dev/null | awk -F: '/lsm/{print $1}')
fi
if [ -n "$LINK_IDS" ]; then
  for lid in $LINK_IDS; do
    echo "  detaching lsm link id=$lid"
    sudo bpftool link detach id "$lid" 2>&1
  done
else
  echo "  (no prior lsm links)"
fi

# -- 2. pkill prior agent + drain trace --
echo
echo '--- cleanup prior agent (best effort) ---'
sudo pkill -TERM -f 'northnarrow-agent' 2>/dev/null
sleep 2
sudo bash -c 'echo > /sys/kernel/debug/tracing/trace' 2>/dev/null

# -- 3. verify agent binary exists --
AGENT_BIN=./target/release/northnarrow-agent
if [ ! -x "$AGENT_BIN" ]; then
  echo "FATAL: $AGENT_BIN not found or not executable"
  echo "Build with: cargo build --release -p northnarrow-agent"
  exit 1
fi
echo
echo "agent binary: $AGENT_BIN ($(stat -c %s "$AGENT_BIN") bytes)"

# -- 4. launch fresh agent via prebuilt binary --
echo
echo "--- launching: sudo nohup $AGENT_BIN --no-ade ---"
sudo nohup "$AGENT_BIN" --no-ade </dev/null >"$AGENT_LOG" 2>&1 &
sleep 1
echo "launched; log: $AGENT_LOG"

# Wait up to 30s for 7 LSM progs to be visible to bpftool
LSM_COUNT=0
for i in $(seq 1 30); do
  sleep 1
  LSM_COUNT=$(sudo bpftool prog show 2>/dev/null | grep -c '^[0-9]\+: lsm')
  echo "  t+${i}s: lsm prog count = $LSM_COUNT"
  [ "$LSM_COUNT" -ge 7 ] && break
done
echo "FINAL lsm prog count = $LSM_COUNT (need 7)"

# -- 5. start trace_pipe capture --
sudo cat /sys/kernel/debug/tracing/trace_pipe >"$TRACE_LOG" 2>/dev/null &
TRACE_PID=$!
sleep 1

# -- 6. PART B: per-id bpftool prog show -j --
echo
echo '====================================================================='
echo '== PART B: loaded LSM programs (key field: attach_btf_id)          =='
echo '====================================================================='
echo
if command -v jq >/dev/null; then
  echo '--- one-line summary ---'
  sudo bpftool prog show -j 2>/dev/null \
    | jq -r '.[] | select(.type=="lsm") | "id=\(.id)\tname=\(.name)\tattach_btf_id=\(.attach_btf_id // "?")\tattach_btf_obj_id=\(.attach_btf_obj_id // "?")\trun_cnt=\(.run_cnt // 0)"'
  echo
  echo '--- per-id full JSON ---'
  for id in $(sudo bpftool prog show -j 2>/dev/null | jq -r '.[] | select(.type=="lsm") | .id'); do
    echo "--- bpftool prog show id $id -j ---"
    sudo bpftool prog show id "$id" -j | jq .
  done
else
  echo '--- raw bpftool prog show (no jq fallback) ---'
  sudo bpftool prog show 2>&1
  echo
  echo '--- per-id raw text ---'
  for id in $(sudo bpftool prog show 2>/dev/null | awk -F: '/lsm/{print $1}'); do
    echo "--- bpftool prog show id $id (text) ---"
    sudo bpftool prog show id "$id" 2>&1
  done
fi

# -- 7. PART C: vmlinux BTF ids for the five FS hook names --
echo
echo '====================================================================='
echo '== PART C: vmlinux BTF ids for our hook names                      =='
echo '== (bpftool btf dump is large; allow ~10-20 seconds)               =='
echo '====================================================================='
echo
echo '--- raw FUNC lines matching our hook names ---'
sudo bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null \
  | grep -E "FUNC '(${HOOKS})'"
echo
echo '--- parsed (name -> vmlinux btf_id) ---'
sudo bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null \
  | grep -E "FUNC '(${HOOKS})'" \
  | sed -E "s/.*\[([0-9]+)\] FUNC '([^']+)'.*/btf_id=\1\tname=\2/"

# -- 8. attack matrix --
echo
echo '====================================================================='
echo '== ATTACK MATRIX                                                   =='
echo '====================================================================='
echo "protected dir: $PROTECTED_DIR"
echo "canary file:   $CANARY"
echo -n "dir exists pre-attack: "; [ -d "$PROTECTED_DIR" ] && echo yes || echo no
sudo ls -lid "$PROTECTED_DIR" 2>/dev/null
echo

# chattr / mv / chmod target the directory itself (it's the protected inode).
# touch creates a fresh canary inside (tests inode_unlink path's parent-dir check).
# rm deletes the canary.
echo "--- chattr -i $PROTECTED_DIR ---"
sudo chattr -i  "$PROTECTED_DIR"        2>&1; echo "rc=$?"

echo "--- mv $PROTECTED_DIR ${PROTECTED_DIR}.attk ---"
sudo mv         "$PROTECTED_DIR" "${PROTECTED_DIR}.attk" 2>&1; echo "rc=$?"

echo "--- touch $CANARY ---"
sudo touch      "$CANARY"               2>&1; echo "rc=$?"

echo "--- chmod 600 $PROTECTED_DIR ---"
sudo chmod 600  "$PROTECTED_DIR"        2>&1; echo "rc=$?"

echo "--- rm -f $CANARY ---"
sudo rm -f      "$CANARY"               2>&1; echo "rc=$?"
sleep 2

sudo kill "$TRACE_PID" 2>/dev/null
wait "$TRACE_PID" 2>/dev/null

# -- 9. PART D: marker counts --
echo
echo '====================================================================='
echo '== PART D: nn-diag marker counts from trace_pipe                   =='
echo '====================================================================='
TOTAL=$(grep -cE 'nn-diag' "$TRACE_LOG" 2>/dev/null)
echo "total nn-diag lines: $TOTAL"
echo
echo '--- counts per marker (desc) ---'
grep -oE 'nn-diag[A-Za-z0-9_-]*' "$TRACE_LOG" 2>/dev/null \
  | sort | uniq -c | sort -rn
echo
echo '--- first 40 raw nn-diag trace lines ---'
grep -E 'nn-diag' "$TRACE_LOG" 2>/dev/null | head -40

# -- 10. PART E: agent log tail --
echo
echo '====================================================================='
echo '== PART E: agent log tail (attach-success / errors per hook)       =='
echo '====================================================================='
tail -100 "$AGENT_LOG"

# -- 11. PART F: post-attack run_cnt per LSM prog --
echo
echo '====================================================================='
echo '== PART F: post-attack run_cnt per LSM prog                        =='
echo '====================================================================='
if command -v jq >/dev/null; then
  sudo bpftool prog show -j 2>/dev/null \
    | jq -r '.[] | select(.type=="lsm") | "id=\(.id)\tname=\(.name)\tattach_btf_id=\(.attach_btf_id // "?")\trun_cnt=\(.run_cnt // 0)\trun_time_ns=\(.run_time_ns // 0)"'
else
  sudo bpftool prog show 2>&1 | grep -B0 -A2 lsm
fi

echo
echo "== done. Full transcript at $RESULT_FILE =="
