#!/usr/bin/env bash
# verify-2b.sh — Tappa 7 task 6 #2b verification harness.
#
# Proves the agent-side #2b mechanism end-to-end on a real BPF-LSM
# kernel: every LSM hook pins a program (prog_<hook>) AND a link
# (link_<hook>); a restarted agent REUSES them; and the pinned hook
# keeps FIRING during the agent death→respawn gap (no agent alive).
#
# Behavioural + log-path companion to the deterministic kernel-object
# -id stability proof in `agent/tests/privileged_map_pin.rs` (run that
# too — see docs/integration-test-runbook.md).
#
# ════════════════════════════════════════════════════════════════════
# AGENT STOP SIGNAL — SOURCE-VERIFIED TRUTH (read before editing)
# ════════════════════════════════════════════════════════════════════
# A long bug history accreted a FALSE folk-explanation ("the LSM
# task_kill hook blocks SIGQUIT"). It does not. The truth, verified
# against the agent + eBPF source on 2026-05-17:
#
#  1. agent-ebpf/src/task_kill.rs:101-104 — the task_kill LSM hook
#     denies ONLY SIGKILL(9) and SIGTERM(15) for a PROTECTED_PIDS
#     entry. SIGQUIT(3) and SIGINT(2) hit `return 0` (ALLOWED). The
#     hook is signal-selective by design and never sees SIGQUIT.
#
#  2. agent/src/main.rs:295-308 — the agent pre-registers tokio
#     Signal streams for SIGINT, SIGTERM, SIGHUP only. There is NO
#     SIGQUIT handler; SIGQUIT keeps whatever disposition it
#     INHERITED.
#
#  3. This harness launches the agent as `sudo "$AGENT_BIN" … &` —
#     an asynchronous job in a NON-interactive shell. POSIX
#     (Shell&Utilities §2.11) requires such a shell to set the
#     child's SIGINT and SIGQUIT disposition to SIG_IGN so stray
#     terminal ^C/^\ cannot fell a background job. SIG_IGN survives
#     exec. The agent RE-ARMS SIGINT (overriding the inherited
#     ignore) but NEVER re-arms SIGQUIT ⇒ under THIS launch method
#     SIGQUIT remains SIG_IGN ⇒ `kill -QUIT <agent>` is silently
#     swallowed. The agent's own comment at main.rs:297-301 calls
#     out this exact "SIG_IGN inherited from `bash &`" hazard.
#
#  4. agent/tests/privileged_map_pin.rs:156-168 spawns the agent via
#     std::process::Command (NOT a shell `&`), which does NOT set
#     SIG_IGN, so SIGQUIT works THERE by kernel default action. That
#     is the *only* reason the Rust AgentGuard's SIGQUIT-on-drop
#     works — it is a property of Command::spawn, not of the kernel.
#     Do not copy that pattern into a shell harness.
#
#  CONSEQUENCE — the only signal that reliably stops a fully-attached
#  self-protected agent from THIS harness is **SIGINT**: not
#  hook-blocked AND explicitly re-armed by the agent → drives the
#  tokio graceful-shutdown arm. With --no-ade the teardown is fast.
#  Pins SURVIVE graceful shutdown by design (anti_tamper/mod.rs
#  :432-442,508-513 — links are take_link'd then bpffs-pinned; only
#  the agent's dup fds close), so SIGINT does NOT weaken the gap or
#  reuse proof.
#
#  HARD-KILL RECOVERY (no reboot): the agent inserts its own PID into
#  PROTECTED_PIDS exactly once at startup (main.rs:137-142) with no
#  watchdog/re-assert loop. So deleting that PID key from the pinned
#  PROTECTED_PIDS map makes the hook return 0 for it, after which
#  SIGKILL is permitted and immediate. kill_agent_safe() uses this as
#  the documented fallback, ELIMINATING the "stale unkillable agent
#  needs a reboot" failure class.
#
#  FORWARD (Tappa 8): KILL_OVERRIDE/PTRACE_OVERRIDE/FS_PROTECT_OVERRIDE
#  are shipped empty today (task_kill.rs:68-79) but Tappa 8 will write
#  an Ed25519 capability token to KILL_OVERRIDE slot 0 at runtime —
#  at which point a `kill -9` on a protected PID may SUCCEED. The
#  kill-denied assertions below snapshot these maps into the verdict
#  and SKIP (not FAIL) if an override is active. If a future
#  hardening tappe makes the hook also deny SIGINT, this harness will
#  need the nn-admin Ed25519 unlock path before it can stop the agent
#  (see docs/integration-test-runbook.md).
#
# ── Requirements (Hetzner verify box only) ──────────────────────────
#   root; /sys/fs/bpf is bpffs; CONFIG_BPF_LSM=y with `bpf` in the
#   boot lsm= chain; bpftool on PATH; eBPF object built
#   (`cargo xtask build-ebpf`); agent built
#   (`cargo build -p northnarrow-agent --release`).
#
# ── DESTRUCTIVE ─────────────────────────────────────────────────────
#   Recursively purges /sys/fs/bpf/northnarrow at start (AFTER a
#   pre-flight that kills any stale agent still holding those
#   objects). Do NOT run on a host with a live production agent. Run
#   deliberately on the isolated, post-reboot verify box.
#
# ── Exit codes ──────────────────────────────────────────────────────
#   0  GREEN — every assertion passed
#   1  RED   — an assertion failed / attach timed out
#   2  RED   — environment precondition unmet (require())
#   3  RED   — an agent could not be stopped even by unprotect+SIGKILL
#              (genuine kernel-stuck state — needs admin unlock or
#              reboot). The verdict file is still written.
#
# Every run — success OR failure, every exit path — writes a JSON
# verdict to /tmp/2b_verdict.json and prints `VERDICT: <path>` as the
# final stdout line.
set -u

# LC_ALL=C: stabilise grep/awk/sort collation and bpftool/ls number
# formatting so output parsing is locale-independent (audit: a de_DE
# box would otherwise thousands-separate counts and break `-eq`).
export LC_ALL=C

# ── configuration ───────────────────────────────────────────────────
ROOT=/sys/fs/bpf/northnarrow
PIN=$ROOT/PROTECTED_PIDS
AGENT_BIN=${AGENT_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/northnarrow-agent}
RULES_SRC=${RULES_SRC:-$(cd "$(dirname "$0")/.." && pwd)/configs/combat-rules.v4}
# Sanity floor only. The REAL expected hook count is DISCOVERED at
# runtime from the agent's own disposition log lines (see
# wait_for_attached) so this harness still holds when Tappa 10.5
# Battle-Time Defense Synthesis grows the hook set past 7.
MIN_HOOKS=7
# Pinned anti-tamper maps the eBPF object always creates (PROTECTED_PIDS,
# KILL_OVERRIDE, PTRACE_OVERRIDE, PROTECTED_INODES, FS_PROTECT_OVERRIDE,
# FS_PROTECT_EVENTS). Used only for the "total pins" sanity floor.
PINNED_MAPS=6
ATTACH_TIMEOUT=${ATTACH_TIMEOUT:-30}   # s; generous for Tappa 10 rule-sandbox startup growth
STOP_GRACE=${STOP_GRACE:-15}           # s; SIGINT graceful-shutdown budget (--no-ade ⇒ fast)
HARDKILL_GRACE=${HARDKILL_GRACE:-5}    # s; post unprotect+SIGKILL budget
POLL=0.2                               # s; generic poll interval

VERDICT=/tmp/2b_verdict.json
HARNESS_OUT=/tmp/2b_harness.out
HARNESS_ERR=/tmp/2b_harness.err
: >"$HARNESS_OUT" 2>/dev/null || true
: >"$HARNESS_ERR" 2>/dev/null || true

WORK=$(mktemp -d)

PASS=0
FAIL=0
SKIP=0
CLEANED=0          # cleanup() idempotency guard
EXPECTED_HOOKS=0   # discovered at boot1 attach; 0 until then

SENTINELS=()       # helper PIDs (sleep) to reap
AGENTS=()          # agent PIDs to stop on exit

# Verdict accumulators (parallel arrays — bash has no struct).
A_NAME=(); A_STAT=(); A_EVID=(); A_DUR=()
S_SIG=(); S_PID=(); S_RC=(); S_OUT=()
declare -A BPFFS_SNAP=()
declare -A LSM_SNAP=()

# ── output: deterministic dual-sink (console + on-disk transcript) ───
# Audit: process-substitution `tee` loses tail output when the script
# exit()s before tee drains. Every emitter instead appends explicitly
# and synchronously to the transcript files, so log_paths in the
# verdict are always complete regardless of exit path.
emit()  { printf '%s\n' "$*"; printf '%s\n' "$*" >>"$HARNESS_OUT" 2>/dev/null || true; }
emitc() { # emitc <ansi> <text>
  printf '\033[%sm%s\033[0m\n' "$1" "$2"
  printf '%s\n' "$2" >>"$HARNESS_OUT" 2>/dev/null || true
}
note()  { printf '%s\n' "---- $*" >&2; printf '%s\n' "---- $*" >>"$HARNESS_ERR" 2>/dev/null || true; }
green() { emitc 32 "$*"; }
red()   { emitc 31 "$*"; }

now_ms()  { date +%s%3N 2>/dev/null || echo 0; }
now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# JSON string escaper. Order matters: backslash FIRST, then quote,
# then collapse the structural whitespace, then strip any remaining
# C0 control bytes. Evidence strings are short and harness-generated.
jstr() {
  local s=${1-}
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/ }
  s=${s//$'\r'/}
  s=${s//$'\t'/ }
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037' 2>/dev/null || printf '%s' "$s")
  printf '%s' "$s"
}

# record_assertion <name> <PASS|FAIL|SKIP> <evidence> [start_ms]
record_assertion() {
  local name=$1 stat=$2 evid=$3 start=${4:-} dur=0
  [ -n "$start" ] && dur=$(( $(now_ms) - start ))
  A_NAME+=("$name"); A_STAT+=("$stat"); A_EVID+=("$evid"); A_DUR+=("$dur")
  case $stat in
    PASS) green "PASS: $name — $evid"; PASS=$((PASS+1)) ;;
    FAIL) red   "FAIL: $name — $evid"; FAIL=$((FAIL+1)) ;;
    SKIP) emit  "SKIP: $name — $evid"; SKIP=$((SKIP+1)) ;;
  esac
}
ok()   { record_assertion "$1" PASS "$2" "${3:-}"; }
bad()  { record_assertion "$1" FAIL "$2" "${3:-}"; }
skip() { record_assertion "$1" SKIP "$2" "${3:-}"; }

# record_signal <signal> <pid> <rc> <outcome>
record_signal() { S_SIG+=("$1"); S_PID+=("$2"); S_RC+=("$3"); S_OUT+=("$4"); }

# ── primitives ──────────────────────────────────────────────────────

# Audit: `kill -0 PID` as non-root on a root-owned PID returns EPERM
# and looks dead. The agent runs as root → always probe via sudo.
alive() { sudo kill -0 "$1" 2>/dev/null; }

# Audit: $? must be captured directly off `kill`, never across a pipe
# (a pipe yields the LAST element's status). Sets RC_KILL.
try_kill9() { # try_kill9 <pid> <errfile>
  sudo kill -9 "$1" 2>"$2"; RC_KILL=$?
}

# wait_for_dead <pid> <seconds> → 0 if it died within budget else 1.
wait_for_dead() {
  local p=$1 deadline=$(( SECONDS + $2 ))
  while [ "$SECONDS" -lt "$deadline" ]; do
    alive "$p" || return 0
    sleep "$POLL"
  done
  return 1
}

# Little-endian 4-byte u32 key as the decimal byte tokens bpftool's
# `map (update|delete) … key` expects (PROTECTED_PIDS is
# HashMap<u32,u8>; value is a single byte). Sets LE_KEY.
le_key() { local p=$1
  LE_KEY="$((p & 255)) $((p >> 8 & 255)) $((p >> 16 & 255)) $((p >> 24 & 255))"
}

# Remove a PID from the pinned PROTECTED_PIDS map (best effort). Used
# both for sentinel teardown and for the hard-kill recovery path.
unprotect_pid() { # unprotect_pid <pid>
  [ -n "${1:-}" ] || return 0
  sudo test -e "$PIN" 2>/dev/null || return 0
  le_key "$1"
  # shellcheck disable=SC2086  # LE_KEY is 4 deliberate arg tokens
  sudo bpftool map delete pinned "$PIN" key $LE_KEY >/dev/null 2>&1 || true
}

# count_in <pattern> <file> → lone integer, 0 on no-match/missing.
# Audit: `grep -c X f || echo 0` prints "0\n0" and breaks arithmetic;
# grep -c already prints a single 0 on no match, so swallow only the
# exit status.
count_in() {
  local n
  n=$(grep -c -F -- "$1" "$2" 2>/dev/null) || n=0
  printf '%s' "${n:-0}"
}

# count_pins <prefix> → number of pin entries whose name starts with
# <prefix>. `ls -1` (one per line, no colour, locale-stable).
count_pins() { # count_pins <prefix>
  local n
  n=$(sudo ls -1 "$ROOT" 2>/dev/null | grep -c -- "^$1") || n=0
  printf '%s' "${n:-0}"
}

# lsm_prog_count → count of loaded `lsm`-type BPF programs.
# Audit: prefer `bpftool -j` (column-/locale-independent JSON); fall
# back to text with id+type anchored so a future bpftool column
# reorder cannot inflate the count.
lsm_prog_count() {
  local j n
  if j=$(sudo bpftool -j prog show 2>/dev/null) && [ -n "$j" ]; then
    n=$(grep -o '"type":"lsm"' <<<"$j" | grep -c . ) || n=0
    printf '%s' "${n:-0}"; return 0
  fi
  sudo bpftool prog show 2>/dev/null \
    | awk '/^[0-9]+:[[:space:]]+lsm[[:space:]]/{n++} END{print n+0}'
}

# snapshot_bpffs <label> — comma-joined sorted pin listing, stashed
# for the verdict and echoed to the transcript.
snapshot_bpffs() { local label=$1 s
  s=$(sudo ls -1 "$ROOT" 2>/dev/null | sort | tr '\n' ',' )
  s=${s%,}
  BPFFS_SNAP[$label]=$s
  note "bpffs[$label] ($(count_pins '')): ${s:-<empty>}"
}
snapshot_lsm() { local label=$1 n; n=$(lsm_prog_count)
  LSM_SNAP[$label]=$n
  note "lsm_progs[$label]: $n"
}

# The kernel stamps comm at TASK_COMM_LEN-1 = 15 chars; pgrep -x
# matches comm and SILENTLY returns nothing for a >15-char pattern
# (it also warns). Derive the truncated comm from the actual binary
# name so a future rename (nn-agent, northnarrowd, …) cannot
# re-introduce bug #4.
agent_comm15() { local b; b=$(basename "$AGENT_BIN"); printf '%s' "${b:0:15}"; }

# Defensive process diagnostic. Audit/bug #6: `cat /proc/$pid/<x>`
# with empty/garbage pid silently falls back to /proc/cmdline (kernel
# boot params). Require: non-empty, all-digits, and /proc/<pid> dir
# present, before ANY read.
proc_diag() { # proc_diag <pid> <tag>
  local p=${1:-} tag=${2:-proc}
  case $p in ''|*[!0-9]*) note "$tag: no resolvable PID (got '${p}')"; return 0 ;; esac
  if ! sudo test -d "/proc/$p" 2>/dev/null; then
    note "$tag: /proc/$p absent (already gone or never existed)"; return 0
  fi
  note "$tag pid=$p status: $(sudo grep -E '^(Name|State|PPid|SigBlk|SigIgn|SigCgt):' \
        "/proc/$p/status" 2>/dev/null | tr '\n' ' ')"
  note "$tag pid=$p cmdline: $(sudo tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)"
}

# realpath of the agent binary, for /proc/<pid>/exe cross-checks.
AGENT_REAL=$(readlink -f "$AGENT_BIN" 2>/dev/null || printf '%s' "$AGENT_BIN")

# resolve_agent_pids → newline-separated PIDs whose /proc/<pid>/exe
# realpath IS the agent binary. Audit/forward (Tappa 9.5 deception):
# pgrep -x by comm could collide with a future honeypot sharing the
# truncated comm "northnarrow-age"; the exe-realpath identity check is
# authoritative and impostor-proof.
#
# Perf: pgrep -x (truncated comm) is the FAST path and the common
# case post bug-#4 fix — exe-verify only its 1-2 hits. The full
# /proc/*/exe sweep (one sudo readlink per process) is the FALLBACK,
# entered only when pgrep finds nothing (binary renamed in place or
# comm masked via prctl(PR_SET_NAME)); without this split a busy box
# would issue thousands of sudo execs per spawn poll and blow the
# resolve budget.
resolve_agent_pids() {
  local comm15 hits pid exe
  comm15=$(agent_comm15)
  hits=$(pgrep -x "$comm15" 2>/dev/null || true)
  if [ -z "$hits" ]; then
    hits=$(for d in /proc/[0-9]*; do printf '%s\n' "${d#/proc/}"; done)
  fi
  # shellcheck disable=SC2086  # word-split the PID list deliberately
  printf '%s\n' $hits | grep -E '^[0-9]+$' | sort -un | while read -r pid; do
    exe=$(sudo readlink -f "/proc/$pid/exe" 2>/dev/null) || continue
    [ "$exe" = "$AGENT_REAL" ] && printf '%s\n' "$pid"
  done
}

# ── stop / cleanup ──────────────────────────────────────────────────

# kill_agent_safe <pid> [tag] → 0 stopped, 3 unkillable.
#
# Strategy (see the SOURCE-VERIFIED TRUTH block at the top):
#   1. SIGINT  — the only hook-passing, agent-re-armed stop. Graceful;
#                pins survive by design. Budget: STOP_GRACE.
#   2. unprotect (delete the agent's own PID key from the pinned
#      PROTECTED_PIDS map) + SIGKILL — race-free hard kill (agent
#      registers self once, no re-assert). Abrupt; pins still survive
#      (links are take_link'd+pinned). Budget: HARDKILL_GRACE.
#   3. give up → rc 3. Genuinely kernel-stuck; needs admin unlock or
#      reboot. NEVER loops forever.
# Deliberately never sends SIGTERM/SIGKILL to a still-protected agent
# (hook-denied — wasted) and never sends SIGQUIT (SIG_IGN-inherited
# under `bash &`; a no-op that historically masked the real PID bug).
kill_agent_safe() {
  local p=${1:-} tag=${2:-agent} rc
  case $p in ''|*[!0-9]*) note "kill_agent_safe: bogus pid '${p}'"; return 0 ;; esac
  alive "$p" || { record_signal NONE "$p" 0 "already dead"; return 0; }

  sudo kill -INT "$p" 2>/dev/null; rc=$?
  if wait_for_dead "$p" "$STOP_GRACE"; then
    record_signal SIGINT "$p" "$rc" "graceful stop within ${STOP_GRACE}s"
    note "$tag $p stopped via SIGINT"
    return 0
  fi
  record_signal SIGINT "$p" "$rc" "no exit in ${STOP_GRACE}s — escalating"
  note "$tag $p ignored SIGINT for ${STOP_GRACE}s; unprotect+SIGKILL"
  proc_diag "$p" "$tag"

  unprotect_pid "$p"
  sudo kill -9 "$p" 2>/dev/null; rc=$?
  if wait_for_dead "$p" "$HARDKILL_GRACE"; then
    record_signal SIGKILL "$p" "$rc" "hard kill after unprotect within ${HARDKILL_GRACE}s"
    note "$tag $p hard-killed (unprotect+SIGKILL)"
    return 0
  fi
  record_signal SIGKILL "$p" "$rc" "SURVIVED unprotect+SIGKILL — kernel-stuck"
  proc_diag "$p" "$tag"
  red "$tag $p unkillable even after unprotect+SIGKILL — needs admin unlock or reboot"
  return 3
}

# Reap a non-protected helper PID (sentinel). Unprotect first in case
# it was injected into PROTECTED_PIDS, then SIGINT (hook-passing),
# then SIGKILL as last resort (sentinels are plain `sleep`, killable).
reap_sentinel() { local s=${1:-}
  case $s in ''|*[!0-9]*) return 0 ;; esac
  unprotect_pid "$s"
  kill -INT "$s" 2>/dev/null || true
  wait_for_dead "$s" 3 || sudo kill -9 "$s" 2>/dev/null || true
  wait "$s" 2>/dev/null || true
}

# purge_bpffs_safe — destructive clean slate; FAILs loudly if the
# tree survives (would mean an agent is still holding it — pre-flight
# should have prevented that).
purge_bpffs_safe() {
  sudo rm -rf "$ROOT" 2>/dev/null || true
  if sudo test -e "$ROOT" 2>/dev/null; then
    return 1
  fi
  return 0
}

write_verdict() { # write_verdict <exit_code>
  local rc=$1 fv i sep f
  [ "$rc" -eq 0 ] && [ "$FAIL" -eq 0 ] && fv=GREEN || fv=RED

  local host kern lsm distro gsha gbr gdirty gmsg bsz bsha bprof
  host=$(uname -n 2>/dev/null)
  kern=$(uname -r 2>/dev/null)
  lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)
  distro=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}")
  gsha=$(git -C "$(dirname "$0")" rev-parse HEAD 2>/dev/null)
  gbr=$(git -C "$(dirname "$0")" rev-parse --abbrev-ref HEAD 2>/dev/null)
  git -C "$(dirname "$0")" diff --quiet HEAD 2>/dev/null && gdirty=false || gdirty=true
  gmsg=$(git -C "$(dirname "$0")" log -1 --pretty=%s 2>/dev/null)
  bsz=$(stat -c %s "$AGENT_BIN" 2>/dev/null || echo 0)
  bsha=$(sha256sum "$AGENT_BIN" 2>/dev/null | awk '{print $1}')
  case $AGENT_BIN in */release/*) bprof=release ;; */debug/*) bprof=debug ;; *) bprof=unknown ;; esac

  {
    printf '{\n'
    printf '  "timestamp": "%s",\n' "$(now_iso)"
    printf '  "host": {"hostname":"%s","kernel_version":"%s","lsm_chain":"%s","distro":"%s"},\n' \
      "$(jstr "$host")" "$(jstr "$kern")" "$(jstr "$lsm")" "$(jstr "$distro")"
    printf '  "git": {"sha":"%s","branch":"%s","dirty":%s,"message":"%s"},\n' \
      "$(jstr "$gsha")" "$(jstr "$gbr")" "$gdirty" "$(jstr "$gmsg")"
    printf '  "agent_binary": {"path":"%s","size_bytes":%s,"sha256":"%s","build_profile":"%s"},\n' \
      "$(jstr "$AGENT_BIN")" "${bsz:-0}" "$(jstr "$bsha")" "$bprof"
    printf '  "configuration": {"bpffs_root":"%s","attach_timeout":%s,"stop_grace":%s,"hardkill_grace":%s,"expected_hooks":%s,"min_hooks":%s},\n' \
      "$(jstr "$ROOT")" "$ATTACH_TIMEOUT" "$STOP_GRACE" "$HARDKILL_GRACE" "$EXPECTED_HOOKS" "$MIN_HOOKS"

    printf '  "assertions": ['
    sep=''
    for i in "${!A_NAME[@]}"; do
      printf '%s\n    {"name":"%s","status":"%s","evidence":"%s","duration_ms":%s}' \
        "$sep" "$(jstr "${A_NAME[$i]}")" "${A_STAT[$i]}" "$(jstr "${A_EVID[$i]}")" "${A_DUR[$i]}"
      sep=','
    done
    [ -n "$sep" ] && printf '\n  ' ; printf '],\n'

    printf '  "signals_attempted": ['
    sep=''
    for i in "${!S_SIG[@]}"; do
      printf '%s\n    {"signal":"%s","pid":%s,"rc":%s,"outcome":"%s"}' \
        "$sep" "${S_SIG[$i]}" "${S_PID[$i]:-0}" "${S_RC[$i]:-0}" "$(jstr "${S_OUT[$i]}")"
      sep=','
    done
    [ -n "$sep" ] && printf '\n  ' ; printf '],\n'

    printf '  "log_paths": {"boot1_agent_log":"%s","boot2_agent_log":"%s","harness_stdout":"%s","harness_stderr":"%s"},\n' \
      "$(jstr "$WORK/boot1/agent.log")" "$(jstr "$WORK/boot2/agent.log")" \
      "$(jstr "$HARNESS_OUT")" "$(jstr "$HARNESS_ERR")"

    printf '  "bpffs_snapshots": {'
    sep=''
    for f in at_start post_boot1 post_stop post_boot2 at_end; do
      printf '%s"%s":"%s"' "$sep" "$f" "$(jstr "${BPFFS_SNAP[$f]:-}")"; sep=','
    done
    printf '},\n'

    printf '  "lsm_kernel_state": {'
    sep=''
    for f in at_start post_boot1 post_stop post_boot2 at_end; do
      printf '%s"%s":%s' "$sep" "$f" "${LSM_SNAP[$f]:-0}"; sep=','
    done
    printf '},\n'

    printf '  "summary": {"pass":%s,"fail":%s,"skip":%s},\n' "$PASS" "$FAIL" "$SKIP"
    printf '  "final_verdict": "%s",\n' "$fv"
    printf '  "exit_code": %s\n' "$rc"
    printf '}\n'
  } >"$VERDICT" 2>/dev/null || true
  sync 2>/dev/null || true
}

cleanup() {
  local rc=$?
  set +u
  [ "$CLEANED" -eq 1 ] && return
  CLEANED=1

  # Stop any still-tracked agents (best effort; rc already decided).
  if [ "${#AGENTS[@]}" -gt 0 ]; then
    for a in "${AGENTS[@]}"; do
      [ -n "$a" ] || continue
      alive "$a" 2>/dev/null && kill_agent_safe "$a" "cleanup-agent" >/dev/null 2>&1
    done
  fi
  if [ "${#SENTINELS[@]}" -gt 0 ]; then
    for s in "${SENTINELS[@]}"; do reap_sentinel "$s"; done
  fi

  snapshot_bpffs at_end 2>/dev/null
  snapshot_lsm   at_end 2>/dev/null
  rm -rf "$WORK" 2>/dev/null

  write_verdict "$rc"
  echo
  emit "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
  if [ "$rc" -eq 0 ] && [ "$FAIL" -eq 0 ]; then
    green "2b-verify GREEN"
  else
    red "2b-verify RED (exit $rc)"
  fi
  # MUST be the final stdout line.
  echo "VERDICT: $VERDICT"
}
trap cleanup EXIT

die() { # die <exit_code> <message>
  red "$2"
  exit "$1"
}

# ── require ─────────────────────────────────────────────────────────
# Audit: every check is loud (records a FAIL assertion) before the
# non-zero exit, so the verdict explains *why* the box was rejected.
require() {
  local s=$(now_ms)
  command -v bpftool >/dev/null 2>&1 \
    || { bad "require:bpftool" "bpftool not on PATH" "$s"; die 2 "bpftool not on PATH"; }
  command -v pgrep >/dev/null 2>&1 \
    || { bad "require:pgrep" "pgrep not on PATH" "$s"; die 2 "pgrep not on PATH"; }
  if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then
    bad "require:root" "not root and no passwordless sudo" "$s"
    die 2 "must run as root (or have passwordless sudo)"
  fi
  if command -v findmnt >/dev/null 2>&1; then
    findmnt -n -t bpf /sys/fs/bpf >/dev/null 2>&1 \
      || { bad "require:bpffs" "/sys/fs/bpf is not a bpffs mount" "$s"; die 2 "/sys/fs/bpf not bpffs"; }
  else
    mount 2>/dev/null | grep -Eq '(^| )/sys/fs/bpf .*type bpf|bpf on /sys/fs/bpf type bpf' \
      || { bad "require:bpffs" "/sys/fs/bpf is not a bpffs mount" "$s"; die 2 "/sys/fs/bpf not bpffs"; }
  fi
  grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
    || { bad "require:lsm" "bpf not in kernel lsm= chain" "$s"; die 2 "bpf not in lsm= chain"; }
  [ -x "$AGENT_BIN" ] \
    || { bad "require:agent-bin" "agent binary missing/not executable: $AGENT_BIN" "$s"; die 2 "agent binary missing"; }
  [ -f "$RULES_SRC" ] \
    || { bad "require:rules" "combat rules missing: $RULES_SRC" "$s"; die 2 "combat rules missing"; }
  ok "require" "env OK (root, bpffs, bpf-lsm, agent+rules present)" "$s"
}

# ── pre-flight: kill stale agents BEFORE the destructive purge ──────
# Audit/bug #5+#8: `rm -rf $ROOT` unlinks pin FILES but kernel objects
# survive while a stale agent (from a prior failed run) still holds
# refs — its 7 hooks then pollute every subsequent lsm_prog_count.
# This must run BEFORE the purge so the pinned PROTECTED_PIDS map is
# still present for the unprotect+SIGKILL recovery path. exe-verified
# PIDs only — a Tappa-9.5 honeypot sharing the comm is NOT killed
# (and is reported).
pre_flight_cleanup() {
  local s=$(now_ms) pids p comm15 imposters="" stuck=0
  snapshot_bpffs at_start
  snapshot_lsm   at_start

  comm15=$(agent_comm15)
  imposters=$(pgrep -x "$comm15" 2>/dev/null | while read -r p; do
    [ "$(sudo readlink -f "/proc/$p/exe" 2>/dev/null)" = "$AGENT_REAL" ] || printf '%s ' "$p"
  done)
  [ -n "$imposters" ] && note "pre-flight: comm '$comm15' matched non-agent PID(s): $imposters (NOT killed — possible deception/impostor)"

  pids=$(resolve_agent_pids)
  if [ -z "$pids" ]; then
    ok "pre-flight" "no stale agent processes" "$s"
    return 0
  fi
  note "pre-flight: stale agent PID(s) from a prior run: $(echo "$pids" | tr '\n' ' ')"
  while read -r p; do
    [ -n "$p" ] || continue
    kill_agent_safe "$p" "stale-agent" || stuck=1
  done <<<"$pids"

  # Re-resolve; anything still standing is genuinely unkillable.
  pids=$(resolve_agent_pids)
  if [ -n "$pids" ] || [ "$stuck" -ne 0 ]; then
    bad "pre-flight" "stale agent survived unprotect+SIGKILL: $(echo "$pids" | tr '\n' ' ')" "$s"
    die 3 "pre-flight could not clear stale agent(s) — reboot the verify box"
  fi
  ok "pre-flight" "cleared stale agent(s); kernel hook state purgeable" "$s"
}

# ── spawn ───────────────────────────────────────────────────────────
# Audit/bugs #3,#4: never PID-resolve via the sudo wrapper. We diff
# the exe-verified PID set before/after spawn and take the NEW member
# — impervious to comm truncation, the sudo double-fork, binary
# rename, and Tappa-9.5 honeypot comm collisions.
spawn_agent() { # spawn_agent <tag> ; echoes PID on stdout
  local tag=$1 td="$WORK/$1" before after newpid deadline
  mkdir -p "$td"
  cp "$RULES_SRC" "$td/combat-rules.v4"
  before=$(resolve_agent_pids | tr '\n' '|')
  sudo "$AGENT_BIN" \
    --combat-rules "$td/combat-rules.v4" \
    --admin-pub   "$td/admin.pub" \
    --admin-socket "$td/admin.sock" \
    --no-ade >"$td/agent.log" 2>&1 &
  local shpid=$!   # the `sudo` wrapper PID, never the agent
  deadline=$(( SECONDS + 10 ))
  newpid=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    while read -r cand; do
      [ -n "$cand" ] || continue
      case "|$before|" in *"|$cand|"*) : ;; *) newpid=$cand ;; esac
    done < <(resolve_agent_pids)
    [ -n "$newpid" ] && break
    # Fail fast if the sudo wrapper already died (bad flags, EACCES).
    kill -0 "$shpid" 2>/dev/null || { [ -n "$newpid" ] || break; }
    sleep "$POLL"
  done
  {
    note "spawn_agent[$tag]: shpid=$shpid agent_pid=${newpid:-<unresolved>}"
    proc_diag "$newpid" "spawn_agent[$tag]"
    [ -z "$newpid" ] && note "spawn_agent[$tag]: agent.log tail:" \
      && tail -n 15 "$td/agent.log" >&2 2>/dev/null
  } >&2
  printf '%s' "$newpid"   # caller MUST AGENTS+=("$pid") (subshell-safe)
}

# ── attach gate ─────────────────────────────────────────────────────
# Audit (fixes two un-listed races found in Phase 2):
#  L3 fresh-log lag — fresh_attach_and_pin pins, THEN logs; gating on
#     pin-count alone can sample 7 pins but only 6 flushed log lines.
#  L4 boot2 stale-state — boot1's pins+progs PERSIST into boot2, so a
#     pin/prog-count gate is satisfied by leftovers BEFORE the boot2
#     agent has reused anything; the reuse assertion then reads 0.
#  Fix: gate on the agent's own post-attach sync line "decision engine
#  ready" (main.rs:150-156, emitted strictly AFTER attach() returns ⇒
#  all per-hook disposition lines already flushed), in THIS boot's
#  fresh per-instance log file. EXPECTED_HOOKS is then DISCOVERED as
#  the disposition-line total (fresh+reuse+purged) — dynamic, so this
#  still holds when Tappa 10.5 grows the hook set.
disposition_total() { # disposition_total <log>
  local a b c
  a=$(count_in 'LSM hook freshly attached + pinned' "$1")
  b=$(count_in 'reused pinned LSM link' "$1")
  c=$(count_in 'purged stale pin and freshly attached' "$1")
  printf '%s' $(( a + b + c ))
}
wait_for_attached() { # wait_for_attached <tag> <log> ; sets DISCOVERED_HOOKS
  local tag=$1 log=$2 deadline=$(( SECONDS + ATTACH_TIMEOUT )) d
  DISCOVERED_HOOKS=0
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(count_in 'decision engine ready' "$log")" -ge 1 ] \
       && sudo test -e "$PIN" 2>/dev/null; then
      d=$(disposition_total "$log")
      if [ "$d" -ge "$MIN_HOOKS" ] \
         && [ "$(count_pins prog_)" -ge "$d" ] \
         && [ "$(count_pins link_)" -ge "$d" ] \
         && [ "$(lsm_prog_count)" -ge "$d" ]; then
        DISCOVERED_HOOKS=$d
        return 0
      fi
    fi
    sleep "$POLL"
  done
  d=$(disposition_total "$log")
  note "[$tag] attach timeout ${ATTACH_TIMEOUT}s: dispositions=$d engine_ready=$(count_in 'decision engine ready' "$log") prog_pins=$(count_pins prog_) link_pins=$(count_pins link_) lsm_progs=$(lsm_prog_count)"
  note "[$tag] agent.log tail:"; tail -n 20 "$log" >&2 2>/dev/null
  return 1
}

# ════════════════════════════ run ══════════════════════════════════
require
pre_flight_cleanup

note "purging $ROOT (destructive, clean-slate)"
purge_bpffs_safe || die 1 "could not purge $ROOT — an agent is still holding it"

# ===== Boot 1 — FRESH attach path ==================================
note "Boot 1: spawn agent (expect fresh attach + pin of all hooks)"
A1=$(spawn_agent boot1); AGENTS+=("$A1")
A1_LOG="$WORK/boot1/agent.log"
[ -n "$A1" ] || die 1 "boot1: could not resolve agent PID (see $A1_LOG)"
ts=$(now_ms)
if wait_for_attached boot1 "$A1_LOG"; then
  EXPECTED_HOOKS=$DISCOVERED_HOOKS
  ok "boot1:attach" "agent fully attached; discovered $EXPECTED_HOOKS hooks" "$ts"
else
  bad "boot1:attach" "full LSM attach not reached in ${ATTACH_TIMEOUT}s" "$ts"
  die 1 "boot1 attach timeout"
fi
snapshot_bpffs post_boot1
snapshot_lsm   post_boot1

mp=$(count_pins ''); pp=$(count_pins prog_); lp=$(count_pins link_)
[ "$pp" -ge "$EXPECTED_HOOKS" ] \
  && ok  "boot1:prog-pins" "$pp prog_ pins (>= $EXPECTED_HOOKS)" \
  || bad "boot1:prog-pins" "prog_ pins=$pp (< $EXPECTED_HOOKS)"
[ "$lp" -ge "$EXPECTED_HOOKS" ] \
  && ok  "boot1:link-pins" "$lp link_ pins (>= $EXPECTED_HOOKS)" \
  || bad "boot1:link-pins" "link_ pins=$lp (< $EXPECTED_HOOKS)"
floor=$(( 2 * EXPECTED_HOOKS + PINNED_MAPS ))
[ "$mp" -ge "$floor" ] \
  && ok  "boot1:total-pins" "$mp total pins (>= ${floor} = 2*$EXPECTED_HOOKS + $PINNED_MAPS maps)" \
  || bad "boot1:total-pins" "total pins=$mp (< $floor)"

fresh=$(count_in 'LSM hook freshly attached + pinned' "$A1_LOG")
reuse=$(count_in 'reused pinned LSM link' "$A1_LOG")
[ "$fresh" -eq "$EXPECTED_HOOKS" ] \
  && ok  "boot1:fresh-log" "$fresh 'freshly attached + pinned' lines = discovered hooks" \
  || bad "boot1:fresh-log" "fresh lines=$fresh (expected $EXPECTED_HOOKS)"
[ "$reuse" -eq 0 ] \
  && ok  "boot1:no-reuse" "0 'reused' lines (correct: nothing to reuse on fresh boot)" \
  || bad "boot1:no-reuse" "unexpected reuse lines=$reuse on fresh boot"

# ===== Stop boot 1 → enter the GAP =================================
note "Stopping boot 1 (SIGINT — the only hook-passing, agent-re-armed stop) → GAP open"
ts=$(now_ms)
kill_agent_safe "$A1" boot1; krc=$?
if [ "$krc" -eq 0 ]; then
  ok "boot1:stop" "agent stopped (pins expected to persist by design)" "$ts"
else
  bad "boot1:stop" "agent unkillable (rc=$krc)" "$ts"
  die 3 "boot1 agent could not be stopped — needs admin unlock or reboot"
fi
snapshot_bpffs post_stop
snapshot_lsm   post_stop

# ----- structural gap proof: kernel objects survive with NO agent --
pp=$(count_pins prog_); lp=$(count_pins link_); lk=$(lsm_prog_count)
{ [ "$pp" -ge "$EXPECTED_HOOKS" ] && [ "$lp" -ge "$EXPECTED_HOOKS" ]; } \
  && ok  "gap:pins-persist" "prog_/link_ pins persist with no agent alive ($pp/$lp)" \
  || bad "gap:pins-persist" "pins vanished on agent exit (prog_=$pp link_=$lp)"
[ "$lk" -ge "$EXPECTED_HOOKS" ] \
  && ok  "gap:progs-loaded" "$lk LSM progs still loaded in kernel with no agent" \
  || bad "gap:progs-loaded" "LSM progs gone after agent exit ($lk)"

# ----- negative control: kill -9 an UNPROTECTED process succeeds ----
sleep 600 & CTRL=$!; SENTINELS+=("$CTRL")
ts=$(now_ms)
try_kill9 "$CTRL" "$WORK/ctrl.err"
if [ "$RC_KILL" -eq 0 ]; then
  ok  "gap:neg-control" "kill -9 on unprotected pid succeeds (hook is selective)" "$ts"
else
  bad "gap:neg-control" "kill -9 unprotected pid failed rc=$RC_KILL — hook over-blocks or kill broken" "$ts"
fi
wait "$CTRL" 2>/dev/null || true

# ----- behavioural gap proof: protected sentinel, NO agent alive ----
# Audit: verify the map write actually landed (Tappa 8 may change the
# map's occupancy/semantics). If it cannot be confirmed, SKIP rather
# than emit a false FAIL.
sleep 600 & SENT=$!; SENTINELS+=("$SENT")
ts=$(now_ms)
le_key "$SENT"
# shellcheck disable=SC2086  # LE_KEY is 4 deliberate arg tokens
if sudo bpftool map update pinned "$PIN" key $LE_KEY value 1 >/dev/null 2>&1 \
   && sudo bpftool map lookup pinned "$PIN" key $LE_KEY >/dev/null 2>&1; then
  try_kill9 "$SENT" "$WORK/sent.err"
  if [ "$RC_KILL" -ne 0 ] && grep -qi 'not permitted' "$WORK/sent.err"; then
    ok  "gap:behavioural" "kill -9 protected sentinel DENIED (EPERM) with NO agent alive — hook still firing in the gap" "$ts"
  else
    bad "gap:behavioural" "kill -9 sentinel rc=$RC_KILL err='$(cat "$WORK/sent.err" 2>/dev/null)' — hook NOT firing in the gap" "$ts"
  fi
else
  skip "gap:behavioural" "could not inject/confirm sentinel in PROTECTED_PIDS (map schema changed?)" "$ts"
fi
reap_sentinel "$SENT"

# ===== Boot 2 — REUSE path =========================================
note "Boot 2: spawn agent (expect REUSE of every pinned link)"
A2=$(spawn_agent boot2); AGENTS+=("$A2")
A2_LOG="$WORK/boot2/agent.log"
[ -n "$A2" ] || die 1 "boot2: could not resolve agent PID (see $A2_LOG)"
ts=$(now_ms)
if wait_for_attached boot2 "$A2_LOG"; then
  ok "boot2:attach" "agent re-attached; $DISCOVERED_HOOKS dispositions logged" "$ts"
else
  bad "boot2:attach" "boot2 attach not reached in ${ATTACH_TIMEOUT}s" "$ts"
  die 1 "boot2 attach timeout"
fi
snapshot_bpffs post_boot2
snapshot_lsm   post_boot2

reuse=$(count_in 'reused pinned LSM link' "$A2_LOG")
fresh=$(count_in 'LSM hook freshly attached + pinned' "$A2_LOG")
purged=$(count_in 'purged stale pin and freshly attached' "$A2_LOG")
[ "$reuse" -eq "$EXPECTED_HOOKS" ] \
  && ok  "boot2:reuse-log" "$reuse 'reused pinned LSM link' lines = discovered hooks (reuse path works)" \
  || bad "boot2:reuse-log" "reuse lines=$reuse (expected $EXPECTED_HOOKS)"
[ "$fresh" -eq 0 ] && [ "$purged" -eq 0 ] \
  && ok  "boot2:all-reused" "0 fresh, 0 purged (correct: all $EXPECTED_HOOKS reused)" \
  || bad "boot2:all-reused" "$fresh re-attached / $purged purged instead of reused — #2b reuse broken"

pp=$(count_pins prog_); lp=$(count_pins link_)
{ [ "$pp" -ge "$EXPECTED_HOOKS" ] && [ "$lp" -ge "$EXPECTED_HOOKS" ]; } \
  && ok  "boot2:pins-intact" "pin set intact across reuse ($pp prog_/$lp link_)" \
  || bad "boot2:pins-intact" "pin set changed across reuse (prog_=$pp link_=$lp)"

# ----- steady-state self-protection (the #1 invariant) -------------
ts=$(now_ms)
try_kill9 "$A2" "$WORK/a2.err"
if [ "$RC_KILL" -ne 0 ] && grep -qi 'not permitted' "$WORK/a2.err"; then
  ok  "steady:self-protect" "kill -9 against live agent2 DENIED (EPERM)" "$ts"
else
  bad "steady:self-protect" "kill -9 agent2 rc=$RC_KILL err='$(cat "$WORK/a2.err" 2>/dev/null)'" "$ts"
fi

note "stopping boot 2 (SIGINT)"
ts=$(now_ms)
kill_agent_safe "$A2" boot2; krc=$?
[ "$krc" -eq 0 ] \
  && ok  "boot2:stop" "agent2 stopped cleanly" "$ts" \
  || bad "boot2:stop" "agent2 unkillable (rc=$krc)" "$ts"

# ===== DEFERRED: stale-pin recovery path ===========================
# The third disposition — "purged stale pin and freshly attached" —
# needs a pin file that EXISTS but whose BPF_OBJ_GET fails (corrupt /
# dangling). bpffs forbids writing arbitrary bytes into a pinned-object
# inode, so this cannot be induced from a shell. Per the 2b plan it is
# DEFERRED to a dedicated Rust hardening harness (pin a *map* fd at a
# link_<hook> path → deterministic from_pin failure). The two paths
# that occur in normal operation — fresh (boot1) and reuse (boot2) —
# are fully verified above.
skip "stale-pin-recovery" "DEFERRED to Rust hardening commit (cannot induce corrupt pin from shell)"

# Verdict + final VERDICT line are emitted by the EXIT trap for ALL
# paths. The process exit code MUST reflect assertion outcomes so an
# automated runner can branch on it without parsing the verdict.
[ "$FAIL" -eq 0 ] && exit 0
exit 1
