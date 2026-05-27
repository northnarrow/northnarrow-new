#!/bin/bash
# T7.13 reproducer preconditions.
#
# Runs every check needed before scenarios A/B/C; exits 1 on any
# failure so the operator is never left guessing whether the harness
# or the agent is at fault. Idempotent; safe to re-run.
#
# Required state on this host:
#   - Linux kernel >=5.7 with CONFIG_BPF_LSM=y, `bpf` in active lsm chain
#   - /sys/fs/bpf mounted (bpffs)
#   - northnarrow-agent service active
#   - iptables available
#   - sudo callable (Phase 3.5 unblocker — depends on this VM's
#     kernel-level sudo segfault recovery completing first)
#   - posture currently == Observing and NORTHNARROW_COMBAT chain absent
#   - test user runs at uid >= 1000

set -uo pipefail
echo "=== T7.13 PRECONDITIONS ==="

# 1. BPF-LSM in active lsm chain
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "FAIL: BPF-LSM not in /sys/kernel/security/lsm"
  exit 1
fi
echo "OK:   BPF-LSM enabled"

# 2. bpffs mounted (agent pins anti-tamper maps + LSM links there)
if ! mount | grep -q 'type bpf'; then
  echo "FAIL: bpffs not mounted (expected /sys/fs/bpf)"
  exit 1
fi
echo "OK:   bpffs mounted"

# 3. Agent running
if ! systemctl is-active --quiet northnarrow-agent; then
  echo "FAIL: northnarrow-agent service not active"
  exit 1
fi
echo "OK:   northnarrow-agent active"

# 4. Posture is Observing (admin socket via nn-admin).
#    The agent's status JSON shape is:
#      {"posture":"Observing","network_isolation_engaged":false,
#       "last_admin_action_secs_ago":null}
#    .posture is Debug-formatted (matches PostureKind variant name).
POSTURE=$(sudo nn-admin status --json 2>/dev/null | jq -r '.posture // empty')
if [[ "$POSTURE" != "Observing" ]]; then
  echo "FAIL: posture=$POSTURE (expected Observing)."
  echo "      Try: sudo systemctl restart northnarrow-agent"
  exit 1
fi
echo "OK:   posture == Observing"

# 5. No stale NORTHNARROW_COMBAT chain. The agent's boot-time
#    reconciler tears down orphaned chains at start (main.rs:872+).
if sudo iptables -L NORTHNARROW_COMBAT >/dev/null 2>&1; then
  echo "FAIL: stale NORTHNARROW_COMBAT chain (restart should reconcile)"
  exit 1
fi
echo "OK:   NORTHNARROW_COMBAT chain absent"

# 6. Regular user (uid >= 1000)
if [[ $UID -lt 1000 ]]; then
  echo "FAIL: must run as regular user; got uid=$UID"
  exit 1
fi
echo "OK:   test user uid=$UID"

# 7. Sudo callable (this VM's Phase 3.5 blocker)
if ! sudo -n true 2>/dev/null && ! sudo true 2>/dev/null; then
  echo "FAIL: sudo not callable — Phase 3.5 still gated by VM recovery"
  exit 1
fi
echo "OK:   sudo callable"

echo "=== PRECONDITIONS PASS ==="
