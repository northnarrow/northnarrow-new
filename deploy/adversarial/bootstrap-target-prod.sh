#!/usr/bin/env bash
# Tappa 10.7 V1 — bootstrap northnarrowdev into PRODUCTION mode.
#
# RUNS ON: inside the target guest (northnarrowdev), as root.
# Design ref: TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md §5, §10.2.
# Operator context + the host-side dance: RANGE_SETUP.md.
#
# WHAT THIS DOES (and why it is more than `install.sh`):
# the target is currently a DEV/SMOKE box — an agent built and reinstalled
# many times in-session, a 1.8 GB legacy drift log, a dev-era FIM baseline,
# and (critically) the STALE BUG-042 unit whose CapabilityBoundingSet still
# carries near-root CAP_SYS_ADMIN and is missing CAP_PERFMON /
# CAP_LINUX_IMMUTABLE / CAP_SYS_PTRACE. This script lands a CLEAN production
# state — not dev-state-with-a-fresh-agent-on-top:
#
#   1. stop the dev agent + watchdog
#   2. scrub dev/smoke RUNTIME state  (keeps /etc config + the admin keypair
#      — regenerating it would break BUG-013's single-key posture)
#   3. rebuild the SHIPPED binary  (cargo xtask build --release, NO
#      test-privileged feature; xtask, NOT bare cargo — eBPF freshness gate)
#   4. install via the real path  (install.sh lands the BUG-042 unit +
#      re-applies +i; it does NOT enable, so we do)
#   5. enable + start the real units
#   6. fresh FIM baseline  (so the baseline reflects prod, not the dev box)
#   7. deploy canaries     (signed; skipped if the admin key is absent)
#   8. HEALTH CHECK — fail loud unless production mode is genuinely live
#
# Idempotent: safe to re-run. Re-running re-scrubs runtime state and
# rebuilds/reinstalls; it never touches /etc config or the admin keypair.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00_config.sh"

require_root "real systemd + LSM attach + chattr"
require_cmd systemctl
require_cmd bpftool
require_cmd capsh
[ -d "$NN_REPO_DIR" ] || die "repo not found at $NN_REPO_DIR"
cd "$NN_REPO_DIR"

# The build runs as the invoking (non-root) user: cargo/rustup live in that
# user's home, target/ is owned by them, and root's secure PATH has no
# cargo (the established flow is build-as-user, install-as-root). install.sh
# only copies the prebuilt binary, so it still runs as root.
BUILD_USER="${BUILD_USER:-${SUDO_USER:-$(stat -c %U "$NN_REPO_DIR")}}"
[ "$BUILD_USER" = root ] && die "refusing to build as root — set BUILD_USER to the repo owner"
as_build_user() { sudo -u "$BUILD_USER" -H bash -lc "$1"; }
as_build_user 'command -v cargo >/dev/null' \
    || die "cargo not found for build user '$BUILD_USER' (rustup not installed for them?)"

# Containment guard — never run a state-mutating bootstrap while the box is
# wired to the outside world for a C2 run (see RANGE_SETUP.md §containment).
if ip route get 1.1.1.1 >/dev/null 2>&1 && [ "${ALLOW_NAT:-0}" != 1 ]; then
    warn "a default/NAT route to the internet is present."
    warn "bootstrap is fine WITH NAT (it needs to build); but the sweep MUST"
    warn "run with NAT + Tailscale detached. This only gates accidental runs"
    warn "during an armed campaign. Set ALLOW_NAT=1 to silence."
fi

# ── 1. stop the dev agent + watchdog ─────────────────────────────────
# Safe without reboot: the task_kill LSM hook has a PID-1 carve-out armed
# at boot and the watchdog is disabled for stop. (northnarrow-vm-ops memo.)
log "Stopping dev agent + watchdog..."
systemctl stop "$NN_AGENT_UNIT" "$NN_WATCHDOG_UNIT" 2>/dev/null || true

# ── 2. scrub dev/smoke RUNTIME state (NOT config, NOT honeypot baits) ─
# /var/lib/northnarrow carries +i on the DIRECTORY; drop it to mutate, then
# install.sh re-applies it. We delete only regenerable runtime telemetry:
#   - fim_drift.jsonl*       dev drift incl. the 1.8 GB legacy-pre-bug026 file
#   - fim_baseline.jsonl     dev baseline — re-seeded fresh in step 6
#   - combat-audit.jsonl     dev COMBAT history
#   - netflow*.jsonl         dev netflow capture
#   - canar*.jsonl           dev canary registry/access (re-deployed in step 7)
# We KEEP /etc/northnarrow entirely: admin.key/admin.pub (BUG-013 single
# key), agent_id, the *.v1/*.local rule config, and the 10 honeypot BAITS
# (agent.dev.lock, kill_switch.conf, maintenance.mode, … — these are
# install.sh-managed deception artefacts, NOT dev cruft. Do not delete.)
log "Scrubbing dev/smoke runtime state (BEST-EFFORT — config + baits preserved)..."
# IMPORTANT: on a box that has run a dev agent, the anti-tamper BPF-LSM deny
# hooks stay PINNED in bpffs (/sys/fs/bpf/northnarrow/link_*) and keep
# ENFORCING after the agent process stops, so rm/chattr here are denied at
# the KERNEL level (EPERM) until a reboot — there is no sanctioned operator
# verb to lift fs-protect (the anti-tamper-trust-gap). That is the
# anti-tamper working AS DESIGNED: it resists a root-level scrub. We do NOT
# tear out the pinned hooks (that would script-defeat the product's own
# protection). This scrub is therefore best-effort: it clears what it can
# (e.g. right after a fresh boot) and no-ops with a warning on a pinned host.
# Detection is still clean — step 6 re-seeds a FRESH FIM baseline; residual
# dev append-logs (drift/netflow/combat-audit) + the legacy file are
# historical noise, separated from sweep evidence by timestamp and the
# rotated journal namespace below.
if [ -d "$NN_STATE_DIR" ]; then
    chattr -i "$NN_STATE_DIR" 2>/dev/null || true
    chattr -i "$NN_STATE_DIR"/fim_drift.jsonl* \
              "$NN_STATE_DIR"/fim_baseline.jsonl \
              "$NN_STATE_DIR"/combat-audit.jsonl \
              "$NN_STATE_DIR"/netflow*.jsonl \
              "$NN_STATE_DIR"/canar*.jsonl 2>/dev/null || true
    if rm -f "$NN_STATE_DIR"/fim_drift.jsonl* \
             "$NN_STATE_DIR"/fim_baseline.jsonl \
             "$NN_STATE_DIR"/combat-audit.jsonl \
             "$NN_STATE_DIR"/netflow*.jsonl \
             "$NN_STATE_DIR"/canar*.jsonl 2>/dev/null; then
        log "  dev runtime state cleared"
    else
        warn "  scrub blocked by pinned anti-tamper (expected without a reboot) —"
        warn "  continuing; the new agent re-seeds a fresh FIM baseline (step 6)."
    fi
fi
# Rotate the dedicated journal namespace so evidence windows start clean.
journalctl --namespace="$NN_JOURNAL_NS" --rotate 2>/dev/null || true
journalctl --namespace="$NN_JOURNAL_NS" --vacuum-time=1s 2>/dev/null || true

# ── 3. rebuild the SHIPPED binary (no test-privileged; xtask) ────────
# `test-privileged` is a CARGO FEATURE, not an install flag. A plain build
# omits it, which is what we want. We MUST go through xtask: a bare
# `cargo build` cannot produce an installable agent — agent/build.rs refuses
# a stale/unstamped eBPF object (the eBPF freshness gate).
log "Building shipped binary as '$BUILD_USER': cargo xtask build --release (NO test-privileged)..."
as_build_user "cd '$NN_REPO_DIR' && cargo xtask build --release"
# Defence in depth: refuse to ship a binary that carries the test feature.
if strings -n 8 target/release/northnarrow-agent | grep -q 'test-privileged'; then
    die "release binary contains test-privileged markers — refusing to ship"
fi

# ── 4. install via the real path (lands the BUG-042 unit) ────────────
# install.sh copies deploy/systemd/*.service → /etc/systemd/system (this is
# how the BUG-042 capability set is deployed — no manual unit copy needed),
# re-creates the state dir at 0700, refreshes baits skip-if-identical, and
# re-applies +i. It deliberately does NOT enable the units.
log "Installing via deploy/install.sh..."
[ -f deploy/install.sh ] || die "deploy/install.sh missing"
# install.sh copies binaries + units FIRST, then refreshes the 10 honeypot
# control-surface baits in /var/lib/northnarrow. On a pinned host, refreshing
# a bait whose content CHANGED EPERMs (the pinned inode_unlink hook denies the
# atomic replace — BUG-020 residual; only a reboot fully clears it). That is
# NON-FATAL: the load-bearing artifacts (binaries + both units) are already in
# place. So tolerate install.sh's exit and verify what actually matters.
if ! bash deploy/install.sh; then
    warn "install.sh exited non-zero — verifying load-bearing artifacts landed..."
    { [ -x "$NN_BIN_DIR/northnarrow-agent" ] && [ -x "$NN_BIN_DIR/northnarrow-watchdog" ] \
      && [ -f "/etc/systemd/system/$NN_AGENT_UNIT" ] \
      && [ -f "/etc/systemd/system/$NN_WATCHDOG_UNIT" ]; } \
      || die "install.sh failed AND binaries/units are missing — genuine install failure"
    warn "binaries + units ARE installed; failure was a pinned-host bait refresh"
    warn "(BUG-020 residual). Continuing — reboot + re-run to refresh stale baits."
fi

# ── 5. enable + start the real units ─────────────────────────────────
log "Enabling + starting $NN_AGENT_UNIT and $NN_WATCHDOG_UNIT..."
systemctl daemon-reload
systemctl enable --now "$NN_AGENT_UNIT" "$NN_WATCHDOG_UNIT"

# Wait for the agent to load rules + attach every LSM hook. Scope to the
# CURRENT MainPID — a box cycled in-session has multiple "decision engine
# ready" lines this boot, so an unscoped `-b` grep matches a STALE instance
# and races ahead of the new agent's LSM attach. Gate on BOTH the new PID's
# ready line AND the LSM progs actually being visible.
READY_PID=$(systemctl show -p MainPID --value "$NN_AGENT_UNIT" 2>/dev/null || echo 0)
log "Waiting for agent (PID $READY_PID) to reach readiness + LSM attach..."
for _ in $(seq 1 30); do
    # grep -c (NOT grep -q): grep -q closes the pipe on its first match, so under
    # the script's `set -o pipefail` the upstream journalctl/bpftool dies with
    # SIGPIPE (141) and pipefail promotes it — a false negative once the box has
    # enough log lines / BPF programs loaded. grep -c reads all input → no close.
    ready=$(journalctl --namespace="$NN_JOURNAL_NS" _PID="$READY_PID" 2>/dev/null \
            | grep -c "decision engine ready" || true)
    lsm=$(bpftool prog show 2>/dev/null \
            | grep -cE 'lsm.*(task_kill|inode_|fim_|ptrace_access)' || true)
    if [ "${ready:-0}" -gt 0 ] && [ "${lsm:-0}" -gt 0 ]; then
        break
    fi
    sleep 1
done

# ── 6. fresh FIM baseline (reflects prod, not the dev box) ───────────
if [ -f "$NN_ETC_DIR/admin.key" ]; then
    log "Re-seeding FIM baseline (signed, fim-manage role)..."
    "$NN_BIN_DIR/nn-admin" fim baseline --key "$NN_ETC_DIR/admin.key" 2>/dev/null \
        || warn "fim baseline re-seed failed — verify manually (nn-admin fim baseline)"
else
    warn "no admin.key — skipping FIM baseline re-seed (deploy it offline per BUG-013)"
fi

# ── 7. deploy canaries (signed; skippable) ───────────────────────────
# Canary deploy is an authenticated op (--key). It needs the single admin
# key; on a clean range this is acceptable, but we skip rather than fail if
# the key has been moved offline.
if [ -f "$NN_ETC_DIR/admin.key" ] && [ "${DEPLOY_CANARIES:-1}" = 1 ]; then
    log "Deploying baseline canaries..."
    "$NN_BIN_DIR/nn-admin" canary deploy --name range-aws-creds \
        --key "$NN_ETC_DIR/admin.key" credential \
        --path /home/forty/.aws/credentials.bak --cred-family aws 2>/dev/null \
        || warn "canary deploy failed — deploy manually (nn-admin canary deploy ...)"
else
    warn "skipping canary deploy (no admin.key or DEPLOY_CANARIES=0)"
fi

# ── 8. HEALTH CHECK — fail loud ──────────────────────────────────────
# Each probe was dry-run against the live agent on 2026-06-02. The CapEff
# decode is the master signal: it proves the BUG-042 unit landed, which in
# turn is what authorises lineage/quarantine /proc/<pid>/exe reads
# (CAP_SYS_PTRACE), +i re-arm (CAP_LINUX_IMMUTABLE) and the minimal BPF
# attach path (CAP_PERFMON, not CAP_SYS_ADMIN).
log "── HEALTH CHECK ──────────────────────────────────────────────"
fail=0
check() { if eval "$2"; then log "  PASS: $1"; else warn "  FAIL: $1"; fail=1; fi; }

# (a) units active
check "$NN_AGENT_UNIT active"    "systemctl is-active --quiet '$NN_AGENT_UNIT'"
check "$NN_WATCHDOG_UNIT active" "systemctl is-active --quiet '$NN_WATCHDOG_UNIT'"

MAINPID=$(systemctl show -p MainPID --value "$NN_AGENT_UNIT" 2>/dev/null || echo 0)

# (b) rule count == EXPECTED_RULE_COUNT (69) — engine's own load is truth
RULES=$(journalctl --namespace="$NN_JOURNAL_NS" -u "$NN_AGENT_UNIT" -b 2>/dev/null \
        | grep -v 'event=ProcessSpawn' \
        | grep -oE 'decision engine ready.*rules=[0-9]+' \
        | grep -oE 'rules=[0-9]+' | tail -1 | cut -d= -f2 || true)
check "engine loaded $EXPECTED_RULE_COUNT rules (got '${RULES:-none}')" \
      "[ \"\${RULES:-0}\" = \"$EXPECTED_RULE_COUNT\" ]"

# (c) LSM attached: bpf in the kernel chain AND NN LSM progs loaded
check "bpf in kernel LSM chain" "grep -q bpf /sys/kernel/security/lsm"
# grep -c (NOT grep -q) — same SIGPIPE-under-pipefail trap as the wait-loop:
# grep -q closes the pipe on its first match and bpftool dies SIGPIPE (141),
# which pipefail promotes to a false FAIL once enough BPF progs are loaded
# (this probe passed at boot-time counts, then false-FAILed at 41 progs).
# grep -c reads all input. Ground-truth cross-check: bpftool link show | grep lsm_mac.
check "NN BPF-LSM programs attached" \
      "[ \"\$(bpftool prog show 2>/dev/null | grep -cE 'lsm.*(task_kill|inode_|fim_|ptrace_access)')\" -gt 0 ]"

# (d) MASTER PROBE — CapEff carries the BUG-042 set, and NOT CAP_SYS_ADMIN
CAPEFF_HEX=$(awk '/CapEff/{print $2}' "/proc/$MAINPID/status" 2>/dev/null || echo 0)
CAP_DECODED=$(capsh --decode=0x"$CAPEFF_HEX" 2>/dev/null || echo "")
for c in $REQUIRED_CAPS; do
    check "CapEff has $c" "grep -qw '$c' <<<'$CAP_DECODED'"
done
for c in $FORBIDDEN_CAPS; do
    check "CapEff does NOT have $c (BUG-042 regression guard)" \
          "! grep -qw '$c' <<<'$CAP_DECODED'"
done

# (e) COMBAT absent at rest — authoritative posture probe + chain check
ISO=$("$NN_BIN_DIR/nn-admin" status --json 2>/dev/null \
      | grep -oE '"network_isolation_engaged":(true|false)' | cut -d: -f2 || true)
check "network isolation NOT engaged at rest (got '${ISO:-?}')" "[ \"\${ISO:-true}\" = false ]"
check "no NorthNarrow COMBAT iptables chain at rest" \
      "! iptables -S 2>/dev/null | grep -qi northnarrow"

# (f) +i applied on the state dir
check "+i set on $NN_STATE_DIR" "lsattr -d '$NN_STATE_DIR' 2>/dev/null | awk '{print \$1}' | grep -q i"

# (g) admin surface live
check "admin socket present" "[ -S '$NN_RUN_DIR/admin.sock' ]"
check "pid file present"     "[ -f '$NN_RUN_DIR/agent.pid' ]"

if [ "$fail" -ne 0 ]; then
    die "HEALTH CHECK FAILED — target is NOT in a clean production state. See FAILs above."
fi
log "── HEALTH CHECK PASSED — production mode is live ─────────────"
log "Next (on the VirtualBox host): detach NAT + Tailscale, run isolation"
log "verify, then snapshot the target as '$TARGET_SNAPSHOT'. See RANGE_SETUP.md."
