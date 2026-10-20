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
#   0. check the tree before anything else  (clean, at NN_EXPECT_COMMIT
#      when set, owned and writable by the build user only; external audit
#      LAB-027) — a refusal leaves the box as it was
#   1. stop the dev agent + watchdog  (through a signed trusted-installer
#      window: the units refuse `systemctl stop`, external audit EBPF-001)
#      and drop the bpffs pin root so the deny hooks detach
#   2. scrub dev/smoke RUNTIME state  (keeps /etc config + the admin keypair
#      — regenerating it would break BUG-013's single-key posture)
#   3. rebuild the SHIPPED binary  (cargo xtask build --release, NO
#      test-privileged feature; xtask, NOT bare cargo — eBPF freshness gate)
#      and refuse it unless it reports no lab feature (--build-features)
#   4. install via the real path  (install.sh lands the BUG-042 unit +
#      re-applies +i; it does NOT enable, so we do), then record what was
#      installed from what in $RANGE_PROVENANCE (commit, tree state, the
#      three binaries' sha256, checked equal to the build)
#   5. enable + start the real units
#   6. fresh FIM baseline  (so the baseline reflects prod, not the dev box)
#   7. deploy canaries     (signed; skipped if the admin key is absent)
#   8. HEALTH CHECK — fail loud unless production mode is genuinely live
#
# Step 1 needs the admin key (/root/northnarrow-admin.key,
# $NN_ETC_DIR/admin.key or NN_ADMIN_KEY) with the trusted-installer role
# when the agent is running, and stops the bootstrap on any failure.
#
# Idempotent: safe to re-run. Re-running re-scrubs runtime state and
# rebuilds/reinstalls; it never touches /etc config or the admin keypair.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00_config.sh"

require_root "real systemd + LSM attach + chattr"
require_cmd systemctl
require_cmd bpftool
require_cmd capsh
# install.sh refuses a host without nft (the per-process outbound block,
# lab PR 165); said here, before step 1 stops anything.
command -v nft >/dev/null 2>&1 || die "nft not found — install nftables first (apt-get install nftables)"
[ -d "$NN_REPO_DIR" ] || die "repo not found at $NN_REPO_DIR"
cd "$NN_REPO_DIR"

# The build runs as the invoking (non-root) user: cargo/rustup live in that
# user's home, target/ is owned by them, and root's secure PATH has no
# cargo (the established flow is build-as-user, install-as-root). install.sh
# only copies the prebuilt binary, so it still runs as root.
BUILD_USER="${BUILD_USER:-${SUDO_USER:-$(stat -c %U "$NN_REPO_DIR")}}"
[ "$BUILD_USER" = root ] && die "refusing to build as root — set BUILD_USER to the repo owner"
BUILD_HOME=$(getent passwd "$BUILD_USER" | cut -d: -f6)
[ -n "$BUILD_HOME" ] && [ -d "$BUILD_HOME" ] || die "build user '$BUILD_USER' has no home directory"
# External audit LAB-027 (NN-AUD-417, lab PR 211): `bash -lc` ran the build
# user's login profiles before a build that root then installs. Now a clean
# environment and an explicit PATH (BUILD_PATH to change it), no profile.
BUILD_PATH=${BUILD_PATH:-$BUILD_HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin}
as_build_user() {
    sudo -u "$BUILD_USER" -H env -i HOME="$BUILD_HOME" USER="$BUILD_USER" LOGNAME="$BUILD_USER" \
        PATH="$BUILD_PATH" LANG=C.UTF-8 bash -c "$1"
}
as_build_user 'command -v cargo >/dev/null' \
    || die "cargo not found for build user '$BUILD_USER' on $BUILD_PATH (rustup not installed for them? BUILD_PATH)"

# >>> range-tree (xtask/tests/lab_host_safety.rs runs this block)
# External audit LAB-027 (NN-AUD-417, lab PR 211): the build of whatever
# the tree held — a work in progress, a file anyone could change — was
# installed as root, with no record of what it was. Before anything is
# stopped or built, the tree must be:
#   - clean: `git status --porcelain` empty (an untracked file counts), and
#     no cargo configuration git ignores (an untracked `.cargo/*` in the
#     tree, a `.cargo/config*` in a parent directory: cargo reads both);
#   - at NN_EXPECT_COMMIT when it is set;
#   - the build user's: every file and directory owned by them (or root),
#     none writable by others, none writable by a group other than the
#     build user's own private group (or root's), and the same for each
#     parent directory up to / (others-writable only with the sticky bit).
# NN_ALLOW_DIRTY_TREE=1 lets a dirty tree through (only that check), and
# the provenance file says so. git runs as the build user, never as root
# in a tree root does not own.
TREE_STATE=
TREE_HEAD=
range_private_group() {   # <user>: their primary group, when it is theirs alone
    local gid gname members
    gid=$(id -g "$1") || return 1
    gname=$(getent group "$gid" | cut -d: -f1)
    members=$(getent group "$gid" | cut -d: -f4)
    [ "$gname" = "$1" ] || return 1
    case ",$members," in ",,"|",$1,") printf '%s\n' "$gid" ;; *) return 1 ;; esac
}
range_unsafe_mode() {   # <path> <user> <private gid or empty>: why the path is unsafe, or nothing
    local owner mode gid
    read -r owner mode gid < <(stat -c '%U %a %g' -- "$1") || { echo "cannot stat"; return; }
    case "$owner" in "$2" | root) ;; *) echo "owned by $owner"; return ;; esac
    mode=$((8#$mode))
    if (( mode & 2 )) && ! (( mode & 01000 )); then echo "writable by others"; return; fi
    if (( mode & 020 )) && [ "$gid" != 0 ] && [ "$gid" != "${3:-x}" ]; then echo "writable by group $gid"; fi
}
range_tree_check() {   # <repo> <build user>
    local repo=$1 user=$2 pgid d f why bad q status head want ign
    pgid=$(range_private_group "$user" || true)
    q=$(printf '%q' "$repo")
    # ownership and modes, the tree (target/ included) and its parents
    bad=$(find "$repo" \( ! -user "$user" ! -user root \) -print -quit 2>/dev/null)
    [ -z "$bad" ] || { warn "$bad is owned by $(stat -c %U -- "$bad"), not $user"; return 1; }
    if [ -n "$pgid" ]; then
        bad=$(find "$repo" ! -type l \( -perm -0002 -o \( -perm -0020 ! -gid "$pgid" ! -gid 0 \) \) -print -quit 2>/dev/null)
    else
        bad=$(find "$repo" ! -type l \( -perm -0002 -o \( -perm -0020 ! -gid 0 \) \) -print -quit 2>/dev/null)
    fi
    [ -z "$bad" ] || { warn "$bad is writable by others or by a group not $user's own ($(stat -c '%a %G' -- "$bad"))"; return 1; }
    d=$repo
    while [ "$d" != / ]; do
        d=$(dirname "$d")
        why=$(range_unsafe_mode "$d" "$user" "$pgid")
        [ -z "$why" ] || { warn "parent directory $d is $why: the tree can be swapped under the build"; return 1; }
        for f in "${d%/}/.cargo/config" "${d%/}/.cargo/config.toml"; do
            if [ -e "$f" ]; then warn "$f exists: cargo would read it in the build"; return 1; fi
        done
    done
    # git state, as the build user
    status=$(as_build_user "git -C $q status --porcelain=v1 --untracked-files=normal") \
        || { warn "git status failed in $repo (as $user)"; return 1; }
    ign=$(as_build_user "git -C $q ls-files --others --ignored --exclude-standard --directory" | grep -E '(^|/)\.cargo/' || true)
    [ -z "$ign" ] || { warn "cargo configuration git ignores: $(head -3 <<<"$ign" | tr '\n' ' ')"; return 1; }
    head=$(as_build_user "git -C $q rev-parse --verify HEAD^{commit}") || { warn "no HEAD commit in $repo"; return 1; }
    if [ -n "${NN_EXPECT_COMMIT:-}" ]; then
        want=$(as_build_user "git -C $q rev-parse --verify $(printf '%q' "$NN_EXPECT_COMMIT^{commit}")" 2>/dev/null) \
            || { warn "NN_EXPECT_COMMIT=$NN_EXPECT_COMMIT names no commit in $repo"; return 1; }
        [ "$head" = "$want" ] || { warn "HEAD is $head, NN_EXPECT_COMMIT is $want"; return 1; }
    fi
    if [ -n "$status" ]; then
        warn "the tree has $(wc -l <<<"$status") uncommitted path(s): $(head -5 <<<"$status" | tr '\n' ';')"
        if [ "${NN_ALLOW_DIRTY_TREE:-0}" != 1 ]; then
            warn "commit them (or NN_ALLOW_DIRTY_TREE=1, recorded in the provenance file)"
            return 1
        fi
        TREE_STATE="dirty, allowed by NN_ALLOW_DIRTY_TREE=1 ($(wc -l <<<"$status") paths)"
    else
        TREE_STATE=clean
    fi
    TREE_HEAD=$head
}
# <<< range-tree
range_tree_check "$NN_REPO_DIR" "$BUILD_USER" \
    || die "refusing to build and install from $NN_REPO_DIR (external audit LAB-027): nothing was stopped or changed"
log "Tree: $NN_REPO_DIR at $TREE_HEAD ($TREE_STATE)"

# Containment guard — never run a state-mutating bootstrap while the box is
# wired to the outside world for a C2 run (see RANGE_SETUP.md §containment).
if ip route get 1.1.1.1 >/dev/null 2>&1 && [ "${ALLOW_NAT:-0}" != 1 ]; then
    warn "a default/NAT route to the internet is present."
    warn "bootstrap is fine WITH NAT (it needs to build); but the sweep MUST"
    warn "run with NAT + Tailscale detached. This only gates accidental runs"
    warn "during an armed campaign. Set ALLOW_NAT=1 to silence."
fi

# The admin key, if it is still on the range host: install.sh writes it to
# /root/northnarrow-admin.key since external audit DEP-001 (the agent reports
# it there, as intended on a range). Needed from step 1 on.
ADMIN_KEY=${NN_ADMIN_KEY:-}
for k in /root/northnarrow-admin.key "$NN_ETC_DIR/admin.key"; do
    if [ -z "$ADMIN_KEY" ] && [ -f "$k" ]; then ADMIN_KEY=$k; fi
done
# The health check compares what steps 6 and 7 leave behind with this.
BOOTSTRAP_START=$(date +%s)

# ── 1. stop the dev agent + watchdog (trusted-installer window) ──────
# External audit EBPF-001: the units refuse `systemctl stop`
# (RefuseManualStop) and PID 1 relays signals to them only inside a signed
# trusted-installer window; the old `systemctl stop … || true` was refused
# without a word and install.sh then refused the running install. Same path
# as install.sh --upgrade (stop_nn_unit) and the lab's anti-tamper suite:
# open the window with the admin key, SIGTERM the watchdog first (it would
# respawn the agent), then the agent, SIGKILL what outlives 10 s, then drop
# the bpffs pin root so the deny hooks detach. Any failure stops here.
unit_has_procs() {
    local cg
    cg=$(systemctl show -p ControlGroup --value "$1" 2>/dev/null || true)
    [ -n "$(cat "/sys/fs/cgroup${cg:-/system.slice/$1}/cgroup.procs" 2>/dev/null)" ]
}
units_present=0
for u in "$NN_WATCHDOG_UNIT" "$NN_AGENT_UNIT"; do
    st=$(systemctl is-active "$u" 2>/dev/null || true)
    if [ "${st:-inactive}" != inactive ]; then units_present=1; fi
done
if [ "$units_present" = 1 ] || [ -d /sys/fs/bpf/northnarrow ]; then
    log "Stopping the installed agent + watchdog (trusted-installer window)..."
    if systemctl is-active --quiet "$NN_AGENT_UNIT"; then
        [ -n "$ADMIN_KEY" ] \
            || die "the agent is running and no admin key was found (/root/northnarrow-admin.key, $NN_ETC_DIR/admin.key or NN_ADMIN_KEY): the units refuse a manual stop (EBPF-001)"
        "$NN_BIN_DIR/nn-admin" trusted-installer-grant --key "$ADMIN_KEY" --window-secs 600 >/dev/null \
            || die "trusted-installer grant refused — $ADMIN_KEY needs the trusted-installer role on its admin.pub line"
    fi
    for u in "$NN_WATCHDOG_UNIT" "$NN_AGENT_UNIT"; do
        systemctl kill --signal=SIGTERM "$u" 2>/dev/null || true
        for _ in $(seq 1 20); do
            unit_has_procs "$u" || break
            sleep 0.5
        done
        if unit_has_procs "$u"; then
            systemctl kill --signal=SIGKILL "$u" 2>/dev/null || true
            sleep 1
        fi
        ! unit_has_procs "$u" || die "$u still runs after SIGTERM and SIGKILL — is the window open?"
        systemctl reset-failed "$u" 2>/dev/null || true
    done
    rm -rf /sys/fs/bpf/northnarrow 2>/dev/null || true
    [ ! -d /sys/fs/bpf/northnarrow ] \
        || die "/sys/fs/bpf/northnarrow is still protected (no window: the agent was not running) — reboot the target (bpffs does not survive it) and re-run"
    n=0
    for _ in $(seq 1 30); do
        progs=$(bpftool prog show 2>/dev/null) || die "bpftool prog show failed"
        n=$(grep -c ' lsm ' <<<"$progs" || true)
        [ "${n:-0}" = 0 ] && break
        sleep 1
    done
    [ "${n:-0}" = 0 ] || die "$n LSM program(s) still loaded 30 s after the stop — another NorthNarrow process holds them"
    log "  units stopped, pin root dropped, no LSM program left"
fi

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
log "Scrubbing dev/smoke runtime state (config + baits preserved)..."
# Step 1 dropped the pin root, so the deny hooks are detached and root may
# clear +i and delete (before EBPF-001 the stop was refused and this scrub
# hit EPERM on every pinned host). A failure now means something else holds
# these files: stop rather than seed a "clean" range over the dev history.
if [ -d "$NN_STATE_DIR" ]; then
    chattr -i "$NN_STATE_DIR" 2>/dev/null || true
    chattr -i "$NN_STATE_DIR"/fim_drift.jsonl* \
              "$NN_STATE_DIR"/fim_baseline.jsonl \
              "$NN_STATE_DIR"/combat-audit.jsonl \
              "$NN_STATE_DIR"/netflow*.jsonl \
              "$NN_STATE_DIR"/canar*.jsonl 2>/dev/null || true
    rm -f "$NN_STATE_DIR"/fim_drift.jsonl* \
          "$NN_STATE_DIR"/fim_baseline.jsonl \
          "$NN_STATE_DIR"/combat-audit.jsonl \
          "$NN_STATE_DIR"/netflow*.jsonl \
          "$NN_STATE_DIR"/canar*.jsonl \
        || die "scrub of $NN_STATE_DIR failed with the deny hooks detached — inspect lsattr/lsof there"
    log "  dev runtime state cleared"
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
as_build_user "cd $(printf '%q' "$NN_REPO_DIR") && cargo xtask build --release"
# Defence in depth: refuse to ship a binary built with a test or debug
# feature (debug-trigger also puts the BPF guard in observe mode). The
# positive marker is the binary's own answer: `--build-features` prints
# exactly `none` for a release build; anything else, or a binary that
# cannot answer, is refused. External audit NN-AUD-211: the old
# `strings | grep -q test-privileged` matched every correct build (the
# release binary names the feature in an error message) and only the
# SIGPIPE that pipefail turned into a false condition kept it quiet.
feat=$(target/release/northnarrow-agent --build-features 2>&1) \
    || die "target/release/northnarrow-agent cannot report its build features (${feat:-no output}) — refusing to ship"
[ "$feat" = none ] || die "release binary built with lab features ($feat) — refusing to ship"
log "  build features: none"

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
# --source-tree: a build from source has no MANIFEST.sha256 (external audit DEP-007).
if ! bash deploy/install.sh --source-tree; then
    warn "install.sh exited non-zero — verifying load-bearing artifacts landed..."
    { [ -x "$NN_BIN_DIR/northnarrow-agent" ] && [ -x "$NN_BIN_DIR/northnarrow-watchdog" ] \
      && [ -f "/etc/systemd/system/$NN_AGENT_UNIT" ] \
      && [ -f "/etc/systemd/system/$NN_WATCHDOG_UNIT" ]; } \
      || die "install.sh failed AND binaries/units are missing — genuine install failure"
    warn "binaries + units ARE installed; failure was a pinned-host bait refresh"
    warn "(BUG-020 residual). Continuing — reboot + re-run to refresh stale baits."
fi

# External audit LAB-027 (NN-AUD-417, lab PR 211): what was installed, from
# what. The three installed binaries must be the ones just built; their
# digests, the commit and the tree's state go to $RANGE_PROVENANCE (root's,
# 0644; kept with each run's evidence, RANGE_SETUP.md §7). The digest lines
# are sha256sum's: `grep /usr/local/bin range-provenance.txt | sha256sum -c`.
prov_tmp=$(mktemp)
{
    echo "# $(date -u +%FT%TZ) deploy/adversarial/bootstrap-target-prod.sh on $(hostname)"
    echo "repo: $NN_REPO_DIR"
    echo "commit: $TREE_HEAD"
    echo "describe: $(as_build_user "git -C $(printf '%q' "$NN_REPO_DIR") describe --always --tags --dirty" 2>/dev/null || echo '?')"
    echo "tree: $TREE_STATE"
    echo "expected_commit: ${NN_EXPECT_COMMIT:-unset}"
    echo "build_user: $BUILD_USER"
    echo "build_path: $BUILD_PATH"
    echo "build_features: $feat"
    for b in northnarrow-agent northnarrow-watchdog nn-admin; do
        built=$(sha256sum < "target/release/$b" | cut -d' ' -f1) || die "target/release/$b: cannot read it"
        inst=$(sha256sum < "$NN_BIN_DIR/$b" | cut -d' ' -f1) || die "$NN_BIN_DIR/$b: not installed"
        [ "$built" = "$inst" ] || die "$NN_BIN_DIR/$b is not the binary built from $TREE_HEAD (sha256 $inst, built $built)"
        echo "$inst  $NN_BIN_DIR/$b"
    done
} > "$prov_tmp"
install -m 0644 -o root -g root "$prov_tmp" "$RANGE_PROVENANCE"
rm -f "$prov_tmp"
log "Provenance written to $RANGE_PROVENANCE:"
sed 's/^/  /' "$RANGE_PROVENANCE"

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
# External audit NN-AUD-223: a failure stops the bootstrap (it used to be a
# warning, and the health check passed without a baseline). The request is
# queued in the agent; the health check waits for the file it writes.
[ -n "$ADMIN_KEY" ] \
    || die "no admin key — the FIM baseline cannot be re-seeded (a key with the fim-manage role at /root/northnarrow-admin.key, or NN_ADMIN_KEY)"
log "Re-seeding FIM baseline (signed, fim-manage role)..."
"$NN_BIN_DIR/nn-admin" fim baseline --key "$ADMIN_KEY" \
    || die "fim baseline re-seed failed (does $ADMIN_KEY carry the fim-manage role on its admin.pub line?)"

# ── 7. deploy canaries (signed) ──────────────────────────────────────
# canary-manage role. A failure stops the bootstrap; DEPLOY_CANARIES=0 skips
# the deploy on purpose and the health check then fails.
CANARY_AWS_PATH=${CANARY_AWS_PATH:-$(getent passwd "$BUILD_USER" | cut -d: -f6)/.aws/credentials.bak}
if [ "${DEPLOY_CANARIES:-1}" = 1 ]; then
    log "Deploying baseline canaries ($CANARY_AWS_PATH)..."
    "$NN_BIN_DIR/nn-admin" canary deploy --name range-aws-creds \
        --key "$ADMIN_KEY" credential \
        --path "$CANARY_AWS_PATH" --cred-family aws \
        || die "canary deploy failed (does $ADMIN_KEY carry the canary-manage role?)"
else
    warn "DEPLOY_CANARIES=0: canary deploy skipped — the health check will fail"
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

# (b) rule count == EXPECTED_RULE_COUNT (the frozen V2 registry's engine
#     rows, 00_config.sh) — engine's own load is truth
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

# (d) MASTER PROBE — CapEff carries the BUG-042 set, and NOT CAP_SYS_ADMIN.
#     External audit NN-AUD-223: decoded only from the agent's own process
#     (MainPID > 1, comm checked) and a well-formed hex mask; when it cannot
#     be decoded every capability probe fails (the "does NOT have" ones used
#     to pass on an empty decode).
CAP_DECODED=
if [[ "$MAINPID" =~ ^[0-9]+$ ]] && [ "$MAINPID" -gt 1 ] \
        && [ "$(cat "/proc/$MAINPID/comm" 2>/dev/null)" = northnarrow-age ]; then
    CAPEFF_HEX=$(awk '/^CapEff:/{print $2}' "/proc/$MAINPID/status" 2>/dev/null || true)
    if [[ "$CAPEFF_HEX" =~ ^[0-9a-fA-F]{16}$ ]]; then
        CAP_DECODED=$(capsh --decode=0x"$CAPEFF_HEX" 2>/dev/null || true)
    fi
fi
check "agent MainPID $MAINPID is northnarrow-agent and its CapEff decodes" "[ -n \"\$CAP_DECODED\" ]"
for c in $REQUIRED_CAPS; do
    check "CapEff has $c" "[ -n \"\$CAP_DECODED\" ] && grep -qw '$c' <<<\"\$CAP_DECODED\""
done
for c in $FORBIDDEN_CAPS; do
    check "CapEff does NOT have $c (BUG-042 regression guard)" \
          "[ -n \"\$CAP_DECODED\" ] && ! grep -qw '$c' <<<\"\$CAP_DECODED\""
done

# (e) COMBAT absent at rest — authoritative posture probe + chain check
ISO=$("$NN_BIN_DIR/nn-admin" status --json 2>/dev/null \
      | grep -oE '"network_isolation_engaged":(true|false)' | cut -d: -f2 || true)
check "network isolation NOT engaged at rest (got '${ISO:-?}')" "[ \"\${ISO:-true}\" = false ]"
# captured first: a failed listing is a FAIL, not an empty "no chain"
IPT=$(iptables -S 2>&1) && IPT_OK=1 || IPT_OK=0
check "iptables readable (iptables -S)" "[ $IPT_OK = 1 ]"
check "no NorthNarrow COMBAT iptables chain at rest" \
      "[ $IPT_OK = 1 ] && ! grep -qi northnarrow <<<\"\$IPT\""

# (f) +i applied on the state dir
ATTRS=$(lsattr -d "$NN_STATE_DIR" 2>/dev/null | awk '{print $1}' || true)
check "+i set on $NN_STATE_DIR (got '${ATTRS:-unreadable}')" "[[ \"\$ATTRS\" == *i* ]]"

# (g) admin surface live
check "admin socket present" "[ -S '$NN_RUN_DIR/admin.sock' ]"
check "pid file present"     "[ -f '$NN_RUN_DIR/agent.pid' ]"

# (h) External audit NN-AUD-223: a FIM baseline written by this bootstrap
#     (step 6 queues it; the agent writes it within a minute)
BASELINE="$NN_STATE_DIR/fim_baseline.jsonl"
for _ in $(seq 1 60); do
    [ -s "$BASELINE" ] && [ "$(stat -c %Y "$BASELINE" 2>/dev/null || echo 0)" -ge "$BOOTSTRAP_START" ] && break
    sleep 1
done
check "FIM baseline non-empty and newer than this bootstrap ($BASELINE)" \
      "[ -s '$BASELINE' ] && [ \"\$(stat -c %Y '$BASELINE')\" -ge $BOOTSTRAP_START ]"

# (i) the range's canary is deployed (canary-read role)
CANARIES=$("$NN_BIN_DIR/nn-admin" canary list --key "$ADMIN_KEY" 2>&1 || true)
check "canary range-aws-creds deployed" "grep -q 'range-aws-creds' <<<\"\$CANARIES\""

# (j) no passwordless sudo for the build user or any login user (uid >= 1000)
NOPASSWD_USERS=
while IFS=: read -r user _ uid _ _ _ shell; do
    [ "$uid" -ge 1000 ] 2>/dev/null || [ "$user" = "$BUILD_USER" ] || continue
    case "$shell" in */nologin|*/false) [ "$user" = "$BUILD_USER" ] || continue ;; esac
    # captured, then matched: grep -q on the pipe would close it early and
    # pipefail would turn sudo's SIGPIPE into a silent miss
    rules=$(sudo -l -U "$user" 2>/dev/null || true)
    if grep -qE 'NOPASSWD|!authenticate' <<<"$rules"; then
        NOPASSWD_USERS="$NOPASSWD_USERS $user"
    fi
done < /etc/passwd
check "no NOPASSWD sudo rule for login users (found:${NOPASSWD_USERS:- none})" "[ -z \"\$NOPASSWD_USERS\" ]"

if [ "$fail" -ne 0 ]; then
    die "HEALTH CHECK FAILED — target is NOT in a clean production state. See FAILs above."
fi
log "── HEALTH CHECK PASSED — production mode is live ─────────────"
log "Next (on the VirtualBox host): detach NAT + Tailscale, run isolation"
log "verify, then snapshot the target as '$TARGET_SNAPSHOT'. See RANGE_SETUP.md."
