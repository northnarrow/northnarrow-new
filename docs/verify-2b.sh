#!/usr/bin/env bash
# verify-2b.sh — Tappa 7 task 6 #2b verification harness.
#
# Proves the agent-side #2b mechanism end-to-end on a real BPF-LSM
# kernel: all 7 LSM hooks pin a program (prog_<hook>) AND a link
# (link_<hook>); a restarted agent REUSES them; and the pinned hook
# keeps FIRING during the agent death→respawn gap (no agent alive).
#
# This is the behavioural + log-path companion to the deterministic
# kernel-object-id stability proof in
# `agent/tests/privileged_map_pin.rs` (run that too — see runbook).
#
# ── Requirements (Hetzner verify box only) ──────────────────────────
#   root; /sys/fs/bpf is bpffs; CONFIG_BPF_LSM=y with `bpf` in the
#   boot lsm= chain; bpftool on PATH; eBPF object built
#   (`cargo xtask build-ebpf`); agent built
#   (`cargo build -p northnarrow-agent --release`).
#
# ── DESTRUCTIVE ─────────────────────────────────────────────────────
#   Recursively purges /sys/fs/bpf/northnarrow at start. Do NOT run
#   on a host with a live production agent. Run deliberately on the
#   isolated, post-reboot verify box.
#
# ── Agent stop signal (source-verified) ─────────────────────────────
#   SIGKILL and SIGTERM are *blocked by the LSM hook under test* — the
#   protected agent cannot be stopped with either. Of the deliverable
#   signals (agent/src/main.rs:306-338): SIGINT drives the tokio
#   graceful-shutdown arm (works, but runs full eBPF/ADE teardown, so
#   termination latency is unbounded); SIGHUP is documented as
#   unreliably delivered; SIGQUIT has *no handler* ⇒ kernel default
#   action = immediate terminate, and is not hook-blocked. SIGQUIT is
#   therefore the deterministic, immediate stop and is exactly what
#   the proven AgentGuard pattern in privileged_map_pin.rs uses. It is
#   also the semantically stronger test: 2b's pin-survival defends
#   against an attacker *abruptly* killing the agent, so verifying the
#   gap under an abrupt SIGQUIT models the real threat better than a
#   graceful SIGINT would. We send SIGQUIT, poll liveness with
#   `sudo kill -0`, and on timeout dump process diagnostics — a
#   SIGQUIT that "fails" means the resolved PID is wrong (it cannot
#   mean SIGQUIT was ineffective), which the diagnostics expose.
set -u

ROOT=/sys/fs/bpf/northnarrow
PIN=$ROOT/PROTECTED_PIDS
AGENT_BIN=${AGENT_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/northnarrow-agent}
RULES_SRC=${RULES_SRC:-$(cd "$(dirname "$0")/.." && pwd)/configs/combat-rules.v4}
EXPECTED_HOOKS=7
ATTACH_TIMEOUT=20      # seconds
STOP_TIMEOUT=30        # seconds (safety margin; SIGQUIT is immediate)
WORK=$(mktemp -d)

PASS=0
FAIL=0
SENTINELS=()
AGENTS=()

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
ok()    { green "PASS: $*"; PASS=$((PASS + 1)); }
bad()   { red   "FAIL: $*"; FAIL=$((FAIL + 1)); }
# `printf '---- …'` makes bash's printf parse the leading dashes as
# options ("printf: --: invalid option"); echo of a dash-prefixed
# string containing spaces/letters is printed literally and is safe.
note()  { echo "---- $*"; }

# ── bash-bug fix #1: `grep -c X f || echo 0` emits "0\n0" and breaks
# arithmetic. `grep -c` already prints a lone count (0 when none) and
# exits 1 on no-match; `|| true` only stops `set -e` (we don't use it
# but keep the idiom robust). Result is a single integer.
count_in() { # count_in <pattern> <file>
  local n
  n=$(grep -c -- "$1" "$2" 2>/dev/null || true)
  printf '%s' "${n:-0}"
}

# ── bash-bug fix #3: `kill -0 PID` as non-root on a root-owned PID
# returns EPERM (looks dead). The agent runs as root; always probe
# liveness through sudo.
alive() { sudo kill -0 "$1" 2>/dev/null; }

# ── bash-bug fix #2: `sudo kill … | tee` captures tee's rc, not
# kill's. Always capture $? directly, never across a pipe.
# Usage: try_kill9 <pid> <errfile> ; echo $RC_KILL
try_kill9() {
  local p=$1 errf=$2
  sudo kill -9 "$p" 2>"$errf"
  RC_KILL=$?
}

cleanup() {
  set +u
  for s in "${SENTINELS[@]}"; do
    [ -n "$s" ] || continue
    # Remove from the protected map FIRST (a still-protected PID
    # would have its own cleanup kill denied), then SIGINT (passes
    # the hook), then reap.
    le_key "$s"
    sudo bpftool map delete pinned "$PIN" key $LE_KEY >/dev/null 2>&1
    kill -INT "$s" >/dev/null 2>&1
    wait "$s" 2>/dev/null
  done
  for a in "${AGENTS[@]}"; do
    [ -n "$a" ] || continue
    # SIGQUIT: deterministic best-effort reap (SIGINT can hang on
    # the agent's graceful-shutdown teardown; cleanup must not block).
    alive "$a" && sudo kill -QUIT "$a" >/dev/null 2>&1
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# Little-endian 4-byte key for a u32 PID, as the space-separated
# decimal byte tokens `bpftool map (update|delete) … key` expects
# (PROTECTED_PIDS is HashMap<u32,u8>). Sets $LE_KEY.
le_key() {
  local p=$1
  LE_KEY="$((p & 255)) $((p >> 8 & 255)) $((p >> 16 & 255)) $((p >> 24 & 255))"
}

require() {
  command -v bpftool >/dev/null 2>&1 || { red "bpftool not on PATH"; exit 2; }
  [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null || {
    red "must run as root (or have passwordless sudo)"; exit 2; }
  mount | grep -q '/sys/fs/bpf .*type bpf' || {
    red "/sys/fs/bpf is not a bpffs mount"; exit 2; }
  grep -q bpf /sys/kernel/security/lsm 2>/dev/null || {
    red "bpf not in kernel lsm= chain (CONFIG_BPF_LSM / boot param)"; exit 2; }
  [ -x "$AGENT_BIN" ] || { red "agent binary missing: $AGENT_BIN"; exit 2; }
  [ -f "$RULES_SRC" ] || { red "combat rules missing: $RULES_SRC"; exit 2; }
}

# Count loaded `type lsm` programs (prog show reliably tags LSM
# programs `lsm`). Stdout = integer.
lsm_prog_count() {
  sudo bpftool prog show 2>/dev/null \
    | awk '/^[0-9]+: lsm /{n++} END{print n+0}'
}

# Spawn an agent with a per-instance tempdir; echoes its PID.
spawn_agent() { # spawn_agent <tag>
  local tag=$1 td="$WORK/$1"
  mkdir -p "$td"
  cp "$RULES_SRC" "$td/combat-rules.v4"
  sudo "$AGENT_BIN" \
    --combat-rules "$td/combat-rules.v4" \
    --admin-pub "$td/admin.pub" \
    --admin-socket "$td/admin.sock" \
    --no-ade >"$td/agent.log" 2>&1 &
  local shpid=$!   # PID of the `sudo` wrapper, not the agent
  # The agent is sudo's child. Primary: child of sudo whose cmdline
  # matches the binary. Fallback: any direct child of sudo (the agent
  # is sudo's only child) — NOT `pgrep -f` (sudo's own argv contains
  # the binary path, so an unscoped match also hits the wrapper).
  sleep 0.3
  local apid
  apid=$(pgrep -P "$shpid" -f "$AGENT_BIN" | head -1)
  [ -n "$apid" ] || apid=$(pgrep -P "$shpid" | head -1)
  # Runtime diagnostic to stderr (NOT stdout — stdout is captured as
  # the PID by `$(spawn_agent …)`). Confirms apid is the agent, not
  # the sudo wrapper, before stop_agent depends on it.
  {
    note "spawn_agent[$tag]: shpid=$shpid apid=$apid cmdline='$(
      sudo cat /proc/"$apid"/cmdline 2>/dev/null | tr '\0' ' ')'"
  } >&2
  # NB: caller must `AGENTS+=("$pid")` — doing it here would mutate a
  # command-substitution subshell, leaving the trap's array empty.
  echo "$apid"
}

wait_for_full_attach() { # wait_for_full_attach <agent.log>
  local log=$1 deadline=$((SECONDS + ATTACH_TIMEOUT))
  # Strict gate: each hook runs load → attach → pin_prog → pin_link
  # sequentially, so prog/link PIN FILES lag the kernel program by a
  # ~200ms window. Waiting only on `lsm_prog_count` lets the caller
  # sample pin counts mid-window and see 6/7. Require all three —
  # 7 progs loaded AND 7 prog_ pins AND 7 link_ pins — to close the
  # race (same load-vs-pin race the Rust test's
  # `wait_for_full_lsm_attach` already guards).
  while [ $SECONDS -lt $deadline ]; do
    if sudo test -e "$PIN" \
       && [ "$(lsm_prog_count)" -ge "$EXPECTED_HOOKS" ] \
       && [ "$(count_pins prog_)" -ge "$EXPECTED_HOOKS" ] \
       && [ "$(count_pins link_)" -ge "$EXPECTED_HOOKS" ]; then
      return 0
    fi
    sleep 0.2
  done
  red "timeout: full LSM attach not reached in ${ATTACH_TIMEOUT}s"
  note "state: progs=$(lsm_prog_count) prog_pins=$(count_pins prog_) link_pins=$(count_pins link_)"
  note "agent.log tail:"; tail -15 "$log"
  return 1
}

stop_agent() { # stop_agent <pid>
  # SIGQUIT primary: no handler ⇒ kernel default action terminates
  # immediately, not hook-blocked — matches the proven AgentGuard
  # pattern and models abrupt-kill (the threat 2b defends). A
  # SIGQUIT that doesn't land in STOP_TIMEOUT means the PID is wrong,
  # not that SIGQUIT failed — so we dump diagnostics instead of
  # escalating to SIGKILL/SIGTERM (both hook-blocked anyway).
  local p=$1 deadline=$((SECONDS + STOP_TIMEOUT))
  sudo kill -QUIT "$p" 2>/dev/null
  while [ $SECONDS -lt $deadline ]; do
    alive "$p" || return 0
    sleep 0.2
  done
  note "SIGQUIT did not stop $p in ${STOP_TIMEOUT}s"
  note "process state: $(sudo grep -E '^(Name|State|PPid):' /proc/"$p"/status 2>/dev/null | tr '\n' ' ')"
  note "cmdline: $(sudo cat /proc/"$p"/cmdline 2>/dev/null | tr '\0' ' ')"
  red "agent $p will not die"
  return 1
}

count_pins() { # count_pins <prefix>
  sudo ls "$ROOT" 2>/dev/null | grep -c "^$1" || true
}

# ───────────────────────── run ──────────────────────────────────────
require
note "purging $ROOT (destructive, clean-slate)"
sudo rm -rf "$ROOT"

# ===== Boot 1 — FRESH attach path ==================================
note "Boot 1: spawn agent (expect fresh attach + pin of 7 progs/links)"
A1=$(spawn_agent boot1); AGENTS+=("$A1")
A1_LOG="$WORK/boot1/agent.log"
wait_for_full_attach "$A1_LOG" || exit 1

mp=$(count_pins ''); pp=$(count_pins prog_); lp=$(count_pins link_)
[ "$pp" -ge "$EXPECTED_HOOKS" ] && ok "boot1: $pp prog_ pins" \
  || bad "boot1: prog_ pins=$pp (<$EXPECTED_HOOKS)"
[ "$lp" -ge "$EXPECTED_HOOKS" ] && ok "boot1: $lp link_ pins" \
  || bad "boot1: link_ pins=$lp (<$EXPECTED_HOOKS)"
[ "$mp" -ge 20 ] && ok "boot1: $mp total pins (>=6 maps +7 prog +7 link)" \
  || bad "boot1: total pins=$mp (<20)"

fresh=$(count_in 'LSM hook freshly attached + pinned' "$A1_LOG")
reuse=$(count_in 'reused pinned LSM link' "$A1_LOG")
[ "$fresh" -eq "$EXPECTED_HOOKS" ] \
  && ok "boot1: $fresh 'freshly attached + pinned' log lines" \
  || bad "boot1: 'freshly attached' lines=$fresh (expected $EXPECTED_HOOKS)"
[ "$reuse" -eq 0 ] && ok "boot1: 0 'reused' log lines (correct: nothing to reuse)" \
  || bad "boot1: unexpected 'reused' lines=$reuse"

# ===== Stop boot 1 → enter the GAP =================================
note "Stopping boot 1 (SIGQUIT — immediate, models abrupt kill) → GAP open"
stop_agent "$A1" || exit 1

# ----- structural gap proof: kernel objects survive with NO agent --
pp=$(count_pins prog_); lp=$(count_pins link_)
[ "$pp" -ge "$EXPECTED_HOOKS" ] && [ "$lp" -ge "$EXPECTED_HOOKS" ] \
  && ok "gap: prog_/link_ pins persist with no agent alive ($pp/$lp)" \
  || bad "gap: pins vanished on agent exit (prog_=$pp link_=$lp)"
[ "$(lsm_prog_count)" -ge "$EXPECTED_HOOKS" ] \
  && ok "gap: $(lsm_prog_count) LSM progs still loaded in kernel" \
  || bad "gap: LSM progs gone after agent exit ($(lsm_prog_count))"

# ----- negative control: kill -9 an UNPROTECTED process succeeds ----
sleep 600 & CTRL=$!
SENTINELS+=("$CTRL")
try_kill9 "$CTRL" "$WORK/ctrl.err"
if [ "$RC_KILL" -eq 0 ]; then
  ok "gap: kill -9 on unprotected pid succeeds (hook is selective)"
else
  bad "gap: kill -9 on unprotected pid failed rc=$RC_KILL — hook over-blocks or kill broken"
fi
wait "$CTRL" 2>/dev/null

# ----- behavioural gap proof: protected sentinel, NO agent alive ----
sleep 600 & SENT=$!
SENTINELS+=("$SENT")
le_key "$SENT"
sudo bpftool map update pinned "$PIN" key $LE_KEY value 1 >/dev/null 2>&1 \
  && note "sentinel pid $SENT injected into pinned PROTECTED_PIDS" \
  || bad "could not inject sentinel into $PIN (map missing?)"

try_kill9 "$SENT" "$WORK/sent.err"
if [ "$RC_KILL" -ne 0 ] && grep -qi 'not permitted' "$WORK/sent.err"; then
  ok "GAP BEHAVIOURAL: kill -9 sentinel DENIED (EPERM) with NO agent alive — hook still firing"
else
  bad "GAP BEHAVIOURAL: kill -9 sentinel rc=$RC_KILL err='$(cat "$WORK/sent.err")' — hook NOT firing in the gap"
fi
# cleanup order: unprotect FIRST, then SIGINT (passes hook), then reap
sudo bpftool map delete pinned "$PIN" key $LE_KEY >/dev/null 2>&1
kill -INT "$SENT" 2>/dev/null
wait "$SENT" 2>/dev/null

# ===== Boot 2 — REUSE path =========================================
note "Boot 2: spawn agent (expect REUSE of all 7 pinned links)"
A2=$(spawn_agent boot2); AGENTS+=("$A2")
A2_LOG="$WORK/boot2/agent.log"
wait_for_full_attach "$A2_LOG" || exit 1

reuse=$(count_in 'reused pinned LSM link' "$A2_LOG")
fresh=$(count_in 'LSM hook freshly attached + pinned' "$A2_LOG")
[ "$reuse" -eq "$EXPECTED_HOOKS" ] \
  && ok "boot2: $reuse 'reused pinned LSM link' log lines (reuse path works)" \
  || bad "boot2: 'reused' lines=$reuse (expected $EXPECTED_HOOKS)"
[ "$fresh" -eq 0 ] \
  && ok "boot2: 0 'freshly attached' lines (correct: all reused)" \
  || bad "boot2: $fresh hooks re-attached instead of reused — #2b reuse broken"

pp=$(count_pins prog_); lp=$(count_pins link_)
[ "$pp" -ge "$EXPECTED_HOOKS" ] && [ "$lp" -ge "$EXPECTED_HOOKS" ] \
  && ok "boot2: pin set intact ($pp prog_/$lp link_)" \
  || bad "boot2: pin set changed (prog_=$pp link_=$lp)"

# ----- steady-state self-protection (existing #1 invariant) --------
try_kill9 "$A2" "$WORK/a2.err"
if [ "$RC_KILL" -ne 0 ] && grep -qi 'not permitted' "$WORK/a2.err"; then
  ok "steady-state: kill -9 against live agent2 DENIED (EPERM)"
else
  bad "steady-state: kill -9 agent2 rc=$RC_KILL err='$(cat "$WORK/a2.err")'"
fi
note "stopping boot 2 (SIGQUIT)"
stop_agent "$A2" || true

# ===== DEFERRED: stale-pin recovery path ===========================
# The third disposition — "purged stale pin and freshly attached" —
# requires a pin file that EXISTS but whose BPF_OBJ_GET fails
# (corrupt / dangling kernel object). bpffs does not allow writing
# arbitrary bytes into a pinned-object inode, so this state cannot be
# induced reliably from a shell without extra tooling. Per the 2b
# plan this is FLAGGED and DEFERRED to a dedicated hardening-test
# commit (a Rust harness that pins a *map* fd at a link_<hook> path
# can force the from_pin failure deterministically). The two paths
# that occur in normal operation — fresh (boot 1) and reuse
# (boot 2) — are fully verified above.
note "stale-pin recovery path: DEFERRED to hardening commit (see comment)"

# ───────────────────────── verdict ─────────────────────────────────
echo
note "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && { green "2b-verify GREEN"; exit 0; }
red "2b-verify RED"; exit 1
