#!/usr/bin/env bash
# NorthNarrow XDR install skeleton (Tappa 7 task 6 Watchdog W7).
#
# Copies the release-mode agent + watchdog binaries to
# /usr/local/bin/ and the two systemd unit files to
# /etc/systemd/system/, then `daemon-reload`s. Does NOT enable
# or start the units — operators run that explicitly after
# inspecting the install layout.
#
# Usage:
#   sudo ./deploy/install.sh
#
# Assumes `cargo xtask build --release` has already run and produced
# ./target/release/{northnarrow-agent,northnarrow-watchdog,nn-admin}.
# Use xtask, NOT a bare `cargo build`: xtask compiles the eBPF object
# (separate nightly/bpfel toolchain) and the userland in one step, and
# stamps the object so agent/build.rs can prove it is fresh. A plain
# `cargo build` does NOT rebuild the eBPF object and cannot produce an
# installable agent — the build fails on a stale/unstamped object.
# Pre-flights every step (including eBPF object freshness, see
# require_fresh_ebpf) so an incomplete or stale invocation surfaces an
# actionable error instead of leaving a half-installed / silently-stale
# system.
#
# Tappa 10.6 (D8) deploy-surface verification — NO install change needed:
#   - D1 grew ProcessSpawnRaw by strict APPEND. The kernel↔userland wire
#     is bytemuck Pod and the eBPF object is embedded in + rebuilt
#     atomically with the agent binary this script installs — and that
#     atomicity is now ENFORCED, not assumed: `cargo xtask build` stamps
#     the eBPF object with a source-closure hash, `agent/build.rs`
#     refuses to embed a stale/unstamped object (fail-loud at build), the
#     agent refuses to start on a placeholder (boot preflight), and
#     require_fresh_ebpf below refuses to install an agent older than its
#     object. So there is no on-disk wire-format compatibility step AND
#     no way for a stale object to reach a running host. (A bytemuck size
#     check alone could not catch the dangerous case — a new field carved
#     from reclaimed padding keeps the size identical; the provenance
#     stamp is what closes it. See ebpf-guard/ + docs/design.)
#   - D2 added kernel reads (argv via mm->arg_start, parent context) to
#     the EXISTING `sched_process_exec` tracepoint — no new BPF program,
#     map, pin, or LSM hook, so the bpffs / `lsm=…,bpf` prerequisites
#     (steps 3-4 below) are unchanged.
#   - D3-D7 are userland-only (correlation store, CHAIN-004..008, the
#     ADE process_template). They add NO new config file: R011-R017 reuse
#     `process-comm-allowlist.v1` and the chain rules need none.
#   Engine grew 62 → 67 rules; that is internal to the agent binary and
#   needs no operator action.

set -euo pipefail

# ── configuration ───────────────────────────────────────────────────
REPO_ROOT=${REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
TARGET_DIR=${TARGET_DIR:-"$REPO_ROOT/target/release"}
BIN_DIR=${BIN_DIR:-/usr/local/bin}
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}
ETC_DIR=${ETC_DIR:-/etc/northnarrow}
STATE_DIR=${STATE_DIR:-/var/lib/northnarrow}

AGENT_BIN="$TARGET_DIR/northnarrow-agent"
WATCHDOG_BIN="$TARGET_DIR/northnarrow-watchdog"
# Beta Step 4c: nn-admin is the operator's COMBAT-release / admin tool.
# It must be on-host so an operator can unlock COMBAT, and install.sh
# uses it below to bootstrap admin.pub on a fresh install (issue #124).
NN_ADMIN_BIN="$TARGET_DIR/nn-admin"
AGENT_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-agent.service"
WATCHDOG_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-watchdog.service"

# Cluster-15 eBPF staleness guard (install-time half). The compiled
# eBPF object is built by `cargo xtask` and its provenance stamp
# (`.buildhash`) is written alongside it. `require_fresh_ebpf` (below)
# uses these to refuse installing an agent binary that predates the
# current eBPF object. Paths MUST match ebpf-guard's ARTIFACT_RELPATH /
# STAMP_RELPATH (ebpf-guard/src/lib.rs).
EBPF_ARTIFACT="$REPO_ROOT/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf"
EBPF_STAMP="$EBPF_ARTIFACT.buildhash"

# Tappa 9 C7: default FIM watched-paths list. install.sh drops this
# at /etc/northnarrow/fim-paths.v1 if missing; the agent loads it at
# boot and merges any operator overlay at /etc/northnarrow/fim-paths.local.
FIM_PATHS_V1_SRC="$REPO_ROOT/configs/fim-paths.v1"

# Tappa 9.5 K7: canary content templates the K4 renderer reads at
# `canary deploy` time. install.sh drops the 5 .tmpl files into
# /etc/northnarrow/canary-templates/. PROTECTED_INODES covers each
# individual .tmpl file (see ETC_PROTECTED_TEMPLATES in
# agent/src/anti_tamper/filesystem.rs) — tamper would silently
# widen / narrow what bytes get written onto the host when an
# operator deploys a credential canary.
CANARY_TEMPLATES_SRC_DIR="$REPO_ROOT/configs/canary-templates"

# Tappa 9.5.1: anti-tamper control-surface bait files (NN-L-FIM-024).
# install.sh writes the 10 inert control files; the agent re-verifies +
# recreates any missing one from the same embedded content at every boot
# (HoneypotIntegrityCheck), which also covers the tmpfs /run/northnarrow
# pair after a reboot. Same bytes either way (configs/honeypot-baits is
# include_str!'d into the agent).
HONEYPOT_BAITS_SRC_DIR="$REPO_ROOT/configs/honeypot-baits"

# Tappa 10 N8: default NetFlow blocklists consumed by NN-L-NET-001
# (IP / CIDR) + NN-L-NET-003 (JA3 fingerprint). install.sh drops
# these at /etc/northnarrow/netflow-blocklist.v1 +
# /etc/northnarrow/netflow-ja3-blocklist.v1 if missing; operators
# extend / narrow via the matching `.local` overlays. ETC_PROTECTED_FILES
# (agent/src/anti_tamper/filesystem.rs) widens to cover the four
# blocklist filenames so PROTECTED_INODES defends them against
# tamper — the same lock-in as fim-paths.v1 / .local.
NETFLOW_BLOCKLIST_V1_SRC="$REPO_ROOT/configs/netflow-blocklist.v1"
NETFLOW_JA3_BLOCKLIST_V1_SRC="$REPO_ROOT/configs/netflow-ja3-blocklist.v1"

# Tappa 10.5 D1: default per-family comm allowlists. process-comm
# exempts trusted actors from the process detection rules (R011..);
# netflow-comm is the trusted-actor set the network rules suppress on
# (seeded from the inline const sets formerly in net.rs). install.sh
# drops both .v1 files if missing; operators tune via the matching
# `.local` overlays. ETC_PROTECTED_FILES widens to cover all four
# filenames so PROTECTED_INODES defends them against tamper — the
# same lock-in as fim-paths.v1 / netflow-blocklist.v1.
PROCESS_COMM_ALLOWLIST_V1_SRC="$REPO_ROOT/configs/process-comm-allowlist.v1"
# Beta Step 3: opt-in overlay template (container-runtime exemptions,
# off by default). Shipped as a `.example` an operator copies to the
# live `.local` to activate — the v1 default stays conservative so R013
# escape-to-host detection is preserved on non-container hosts.
PROCESS_COMM_ALLOWLIST_EXAMPLE_SRC="$REPO_ROOT/configs/process-comm-allowlist.local.example"
NETFLOW_COMM_ALLOWLIST_V1_SRC="$REPO_ROOT/configs/netflow-comm-allowlist.v1"
# Beta Step 4b: empty-by-default COMBAT management carve-out CIDR list.
COMBAT_ALLOW_CIDRS_SRC="$REPO_ROOT/configs/combat-allow.cidrs"

# ── pre-flight ──────────────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "install.sh: must run as root (use sudo)" >&2
        exit 1
    fi
}

require_file() {
    local path=$1
    local hint=$2
    if [[ ! -f "$path" ]]; then
        echo "install.sh: required file missing: $path" >&2
        echo "install.sh: $hint" >&2
        exit 1
    fi
}

# Cluster-15 staleness guard, install-time half. The eBPF object is
# compiled by `cargo xtask` and EMBEDDED into the agent binary at build
# time; `agent/build.rs` refuses to embed a stale or unstamped object,
# and the agent refuses to start on the empty placeholder. This check is
# the belt-and-suspenders: it refuses to install an agent binary that is
# OLDER than the current eBPF object/stamp (the eBPF was rebuilt but the
# agent was not, so the binary may still embed a previous object), and
# requires the xtask provenance stamp to exist at all (a plain
# `cargo build` does not build the eBPF object and leaves no stamp).
# Together with the build + startup guards this makes "the eBPF object is
# rebuilt atomically with the agent" an enforced fact, not a comment.
require_fresh_ebpf() {
    if [[ ! -f "$EBPF_STAMP" ]]; then
        echo "install.sh: eBPF provenance stamp missing: $EBPF_STAMP" >&2
        echo "install.sh: the eBPF object was not built via xtask (a plain \`cargo build\` does NOT build it)." >&2
        echo "install.sh: rebuild the eBPF object + agent atomically:  cargo xtask build --release" >&2
        exit 1
    fi
    if [[ "$EBPF_ARTIFACT" -nt "$AGENT_BIN" ]]; then
        echo "install.sh: STALE agent binary — $AGENT_BIN is older than the eBPF object:" >&2
        echo "install.sh:   $EBPF_ARTIFACT" >&2
        echo "install.sh: the eBPF object was rebuilt after the agent; the binary may embed a previous object." >&2
        echo "install.sh: rebuild atomically:  cargo xtask build --release" >&2
        exit 1
    fi
    if [[ "$EBPF_STAMP" -nt "$AGENT_BIN" ]]; then
        echo "install.sh: STALE agent binary — $AGENT_BIN is older than the eBPF build stamp:" >&2
        echo "install.sh:   $EBPF_STAMP" >&2
        echo "install.sh: rebuild atomically:  cargo xtask build --release" >&2
        exit 1
    fi
    echo "install.sh: eBPF object freshness OK (agent binary is no older than the stamped object)"
}

require_root
require_file "$AGENT_BIN"    "run \`cargo xtask build --release\` first (xtask builds the eBPF object + userland atomically; a plain \`cargo build\` cannot produce an installable agent — agent/build.rs refuses a stale/unstamped eBPF object)"
require_file "$WATCHDOG_BIN" "run \`cargo xtask build --release\` first (or \`cargo build --release -p northnarrow-watchdog\`)"
require_file "$NN_ADMIN_BIN" "run \`cargo xtask build --release\` first (or \`cargo build --release -p northnarrow-agent --bin nn-admin\`)"
# Refuse a stale agent binary BEFORE we touch the live system.
require_fresh_ebpf
require_file "$AGENT_UNIT_SRC"    "expected at $AGENT_UNIT_SRC (this script's sibling deploy/systemd/)"
require_file "$WATCHDOG_UNIT_SRC" "expected at $WATCHDOG_UNIT_SRC"
require_file "$FIM_PATHS_V1_SRC"  "expected at $FIM_PATHS_V1_SRC (Tappa 9 C7 default FIM watched-paths list)"
require_file "$NETFLOW_BLOCKLIST_V1_SRC"     "expected at $NETFLOW_BLOCKLIST_V1_SRC (Tappa 10 N8 default NetFlow IP/CIDR blocklist)"
require_file "$NETFLOW_JA3_BLOCKLIST_V1_SRC" "expected at $NETFLOW_JA3_BLOCKLIST_V1_SRC (Tappa 10 N8 default NetFlow JA3 blocklist)"

require_dir() {
    local path=$1
    local hint=$2
    if [[ ! -d "$path" ]]; then
        echo "install.sh: required directory missing: $path" >&2
        echo "install.sh: $hint" >&2
        exit 1
    fi
}

require_dir "$CANARY_TEMPLATES_SRC_DIR" "expected at $CANARY_TEMPLATES_SRC_DIR (Tappa 9.5 K7 canary content templates)"
for tmpl in aws.tmpl azure.tmpl docker.tmpl gcp.tmpl generic.tmpl; do
    require_file "$CANARY_TEMPLATES_SRC_DIR/$tmpl" "expected at $CANARY_TEMPLATES_SRC_DIR/$tmpl (Tappa 9.5 K4 canary template)"
done

require_dir "$HONEYPOT_BAITS_SRC_DIR" "expected at $HONEYPOT_BAITS_SRC_DIR (Tappa 9.5.1 NN-L-FIM-024 control-surface files)"
for bait in agent.dev.lock kill_switch.conf maintenance.mode debug_disable.flag agent.legacy.conf shutdown.signal disable.token override.config pause.flag unload.signal; do
    require_file "$HONEYPOT_BAITS_SRC_DIR/$bait" "expected at $HONEYPOT_BAITS_SRC_DIR/$bait (Tappa 9.5.1 control-surface file)"
done

# ── install ─────────────────────────────────────────────────────────
echo "install.sh: copying binaries to $BIN_DIR/"
install -m 755 -o root -g root "$AGENT_BIN"    "$BIN_DIR/northnarrow-agent"
install -m 755 -o root -g root "$WATCHDOG_BIN" "$BIN_DIR/northnarrow-watchdog"
install -m 755 -o root -g root "$NN_ADMIN_BIN" "$BIN_DIR/nn-admin"

echo "install.sh: copying systemd unit files to $UNIT_DIR/"
install -m 644 -o root -g root "$AGENT_UNIT_SRC"    "$UNIT_DIR/northnarrow-agent.service"
install -m 644 -o root -g root "$WATCHDOG_UNIT_SRC" "$UNIT_DIR/northnarrow-watchdog.service"

# Tappa 9 C7: ensure /etc/northnarrow/ exists and ship the default
# FIM watched-paths list. Idempotent: if the operator has already
# customised /etc/northnarrow/fim-paths.v1, we leave it alone (the
# v1 file is operator-configuration once installed; v2 of the list
# would ship at /etc/northnarrow/fim-paths.v2 when the schema bumps).
echo "install.sh: ensuring $ETC_DIR (mode 0755, root:root)"
install -d -m 0755 -o root -g root "$ETC_DIR"

if [[ -f "$ETC_DIR/fim-paths.v1" ]]; then
    echo "install.sh: $ETC_DIR/fim-paths.v1 already present — leaving operator copy untouched"
else
    echo "install.sh: copying default FIM watched-paths list to $ETC_DIR/fim-paths.v1"
    install -m 0644 -o root -g root "$FIM_PATHS_V1_SRC" "$ETC_DIR/fim-paths.v1"
fi

# Tappa 10 N8: ship the default NetFlow IP/CIDR + JA3 blocklists.
# Same idempotency contract as fim-paths.v1 — existing operator
# copies (likely customised from the threat-intel feed of choice)
# are left untouched; only fresh installs receive the seed file.
# The matching `.local` overlays are NOT shipped by install.sh
# (operator-curated, deploy via configuration management).
if [[ -f "$ETC_DIR/netflow-blocklist.v1" ]]; then
    echo "install.sh: $ETC_DIR/netflow-blocklist.v1 already present — leaving operator copy untouched"
else
    echo "install.sh: copying default NetFlow IP/CIDR blocklist to $ETC_DIR/netflow-blocklist.v1"
    install -m 0644 -o root -g root "$NETFLOW_BLOCKLIST_V1_SRC" "$ETC_DIR/netflow-blocklist.v1"
fi

if [[ -f "$ETC_DIR/netflow-ja3-blocklist.v1" ]]; then
    echo "install.sh: $ETC_DIR/netflow-ja3-blocklist.v1 already present — leaving operator copy untouched"
else
    echo "install.sh: copying default NetFlow JA3 blocklist to $ETC_DIR/netflow-ja3-blocklist.v1"
    install -m 0644 -o root -g root "$NETFLOW_JA3_BLOCKLIST_V1_SRC" "$ETC_DIR/netflow-ja3-blocklist.v1"
fi

# Tappa 10.5 D1: ship the default per-family comm allowlists. Same
# idempotency contract as fim-paths.v1 — existing operator copies are
# left untouched; only fresh installs receive the seed file. The
# matching `.local` overlays are NOT shipped (operator-curated, deploy
# via configuration management).
if [[ -f "$ETC_DIR/process-comm-allowlist.v1" ]]; then
    echo "install.sh: $ETC_DIR/process-comm-allowlist.v1 already present — leaving operator copy untouched"
else
    echo "install.sh: copying default process comm allowlist to $ETC_DIR/process-comm-allowlist.v1"
    install -m 0644 -o root -g root "$PROCESS_COMM_ALLOWLIST_V1_SRC" "$ETC_DIR/process-comm-allowlist.v1"
fi

# Beta Step 3: refresh the opt-in overlay TEMPLATE (container-runtime
# exemptions, off by default). This is a `.example`, never the live
# `.local`, so it is safe to overwrite on every install — it documents
# the current set of recommended container-runtime comms. Container
# hosts activate it with:
#   cp $ETC_DIR/process-comm-allowlist.local.example \
#      $ETC_DIR/process-comm-allowlist.local
# See docs/operator/CONTAINER_HOST_DEPLOY.md for the security tradeoff.
if [[ -f "$PROCESS_COMM_ALLOWLIST_EXAMPLE_SRC" ]]; then
    echo "install.sh: refreshing overlay template $ETC_DIR/process-comm-allowlist.local.example"
    install -m 0644 -o root -g root "$PROCESS_COMM_ALLOWLIST_EXAMPLE_SRC" "$ETC_DIR/process-comm-allowlist.local.example"
fi

if [[ -f "$ETC_DIR/netflow-comm-allowlist.v1" ]]; then
    echo "install.sh: $ETC_DIR/netflow-comm-allowlist.v1 already present — leaving operator copy untouched"
else
    echo "install.sh: copying default NetFlow comm allowlist to $ETC_DIR/netflow-comm-allowlist.v1"
    install -m 0644 -o root -g root "$NETFLOW_COMM_ALLOWLIST_V1_SRC" "$ETC_DIR/netflow-comm-allowlist.v1"
fi

# Beta Step 4b: COMBAT management carve-out CIDR list. Empty default =
# full isolation (no regression). Operator-editable (NOT in the FIM
# deny-zone) so an emergency CIDR can be added from a local console
# mid-COMBAT. Left untouched if the operator already has one.
if [[ -f "$ETC_DIR/combat-allow.cidrs" ]]; then
    echo "install.sh: $ETC_DIR/combat-allow.cidrs already present — leaving operator copy untouched"
else
    echo "install.sh: seeding empty COMBAT carve-out list at $ETC_DIR/combat-allow.cidrs"
    install -m 0644 -o root -g root "$COMBAT_ALLOW_CIDRS_SRC" "$ETC_DIR/combat-allow.cidrs"
fi

# Beta Step 4c (issue #124): bootstrap an admin keypair on a FRESH
# install so COMBAT is recoverable. Without admin.pub the agent still
# runs and still enters COMBAT on intrusion, but there is NO way to
# release it short of a reboot. Generate one ONLY when admin.pub is
# absent (never overwrite operator-managed keys). The private half is
# written to the host and MUST be moved offline — see the warning.
if [[ -f "$ETC_DIR/admin.pub" ]]; then
    echo "install.sh: $ETC_DIR/admin.pub already present — leaving admin keys untouched"
else
    echo "install.sh: no admin.pub found — bootstrapping an Ed25519 admin keypair (nn-admin init)"
    if "$BIN_DIR/nn-admin" init --priv-out "$ETC_DIR/admin.key" --pub-append "$ETC_DIR/admin.pub"; then
        chmod 0600 "$ETC_DIR/admin.key" 2>/dev/null || true
        echo ""
        echo "  ##########################################################################"
        echo "  #  SECURITY — an admin PRIVATE key was just written to this host:         #"
        echo "  #      $ETC_DIR/admin.key  (mode 0600)"
        echo "  #                                                                        #"
        echo "  #  This key RELEASES COMBAT isolation. Anyone holding it — or with root   #"
        echo "  #  on THIS host — can unlock the host. MOVE IT OFF THIS HOST NOW and      #"
        echo "  #  store it offline, e.g.:                                                #"
        echo "  #      mv $ETC_DIR/admin.key  <secure-offline-location>"
        echo "  #  Keep ONLY the public half ($ETC_DIR/admin.pub) on the host.            #"
        echo "  #  Recovery procedure: docs/operator/COMBAT_RECOVERY.md                   #"
        echo "  ##########################################################################"
        echo ""
    else
        echo "install.sh: WARNING — nn-admin init failed; admin.pub was NOT created." >&2
        echo "install.sh: COMBAT will be UNRECOVERABLE without an admin key. Generate one manually:" >&2
        echo "install.sh:   nn-admin init --priv-out <offline-path> --pub-append $ETC_DIR/admin.pub" >&2
    fi
fi

# Tappa 9 C7: ensure /var/lib/northnarrow/ exists at mode 0700
# (matches STATE_DIR_MODE in agent/src/anti_tamper/filesystem.rs)
# and pre-touch the two chained FIM logs so PROTECTED_INODES has
# inodes to register at the agent's very first attach. The agent
# also bootstraps these (bootstrap_fim_log) but doing it here
# closes a brief race window on first boot.
echo "install.sh: ensuring $STATE_DIR (mode 0700, root:root)"
install -d -m 0700 -o root -g root "$STATE_DIR"

for fim_log in fim_baseline.jsonl fim_drift.jsonl; do
    if [[ -f "$STATE_DIR/$fim_log" ]]; then
        echo "install.sh: $STATE_DIR/$fim_log already present — leaving chain intact"
    else
        echo "install.sh: bootstrapping $STATE_DIR/$fim_log (zero-byte placeholder)"
        install -m 0644 -o root -g root /dev/null "$STATE_DIR/$fim_log"
    fi
done

# Tappa 9.5.1: anti-tamper control-surface bait files (NN-L-FIM-024).
# 10 inert files across /etc, /var/lib and /run; mode 0644 root:root so a
# tamper is observable. We (re)write them to the canonical content on
# every install — they are NN-managed, not operator configuration. The
# tmpfs /run/northnarrow pair vanishes on reboot; the agent's boot
# HoneypotIntegrityCheck recreates it (and any deleted persistent bait)
# from the same embedded bytes.
RUN_DIR="/run/northnarrow"
echo "install.sh: ensuring $RUN_DIR (mode 0755, root:root)"
install -d -m 0755 -o root -g root "$RUN_DIR"
declare -A HONEYPOT_BAIT_DIRS=(
    [agent.dev.lock]="$ETC_DIR"
    [kill_switch.conf]="$ETC_DIR"
    [maintenance.mode]="$ETC_DIR"
    [debug_disable.flag]="$ETC_DIR"
    [agent.legacy.conf]="$ETC_DIR"
    [shutdown.signal]="$STATE_DIR"
    [disable.token]="$STATE_DIR"
    [override.config]="$STATE_DIR"
    [pause.flag]="$RUN_DIR"
    [unload.signal]="$RUN_DIR"
)
for bait in "${!HONEYPOT_BAIT_DIRS[@]}"; do
    dst_dir="${HONEYPOT_BAIT_DIRS[$bait]}"
    echo "install.sh: writing control-surface file $dst_dir/$bait"
    install -m 0644 -o root -g root "$HONEYPOT_BAITS_SRC_DIR/$bait" "$dst_dir/$bait"
done

# Tappa 9.5 K7: pre-touch the two canary chain files for the same
# reason as the FIM logs — STATE_PROTECTED_FILES needs an inode to
# register against before LSM hooks come up. Existing chains are
# preserved (we MUST NOT silently erase a prior canary registry or
# access log on upgrade).
for canary_log in canaries.jsonl canary_access.jsonl; do
    if [[ -f "$STATE_DIR/$canary_log" ]]; then
        echo "install.sh: $STATE_DIR/$canary_log already present — leaving chain intact"
    else
        echo "install.sh: bootstrapping $STATE_DIR/$canary_log (zero-byte placeholder)"
        install -m 0644 -o root -g root /dev/null "$STATE_DIR/$canary_log"
    fi
done

# Tappa 10 N8: pre-touch the NetFlow chain log for the same reason
# as the FIM + canary logs — STATE_PROTECTED_FILES (now five
# entries) needs an inode to register against before LSM hooks
# come up. The agent's bootstrap_netflow_log helper also handles
# this at boot, but doing it here closes the brief race window on
# first start (same lock-in as fim_baseline.jsonl).
if [[ -f "$STATE_DIR/netflow.jsonl" ]]; then
    echo "install.sh: $STATE_DIR/netflow.jsonl already present — leaving chain intact"
else
    echo "install.sh: bootstrapping $STATE_DIR/netflow.jsonl (zero-byte placeholder)"
    install -m 0644 -o root -g root /dev/null "$STATE_DIR/netflow.jsonl"
fi

# Tappa 9.5 K7: install the 5 canary content templates into
# /etc/northnarrow/canary-templates/. Templates are read by the
# K4 renderer at `nn-admin canary deploy` time; PROTECTED_INODES
# covers each individual .tmpl per ETC_PROTECTED_TEMPLATES.
# Idempotent per file: an existing operator-customised template
# is left untouched (the source-of-truth for any one family is
# the file on the operator host once installed; the next agent
# upgrade ships fresh templates only when the family didn't
# already exist on the host).
echo "install.sh: ensuring $ETC_DIR/canary-templates (mode 0755, root:root)"
install -d -m 0755 -o root -g root "$ETC_DIR/canary-templates"

for tmpl in aws.tmpl azure.tmpl docker.tmpl gcp.tmpl generic.tmpl; do
    if [[ -f "$ETC_DIR/canary-templates/$tmpl" ]]; then
        echo "install.sh: $ETC_DIR/canary-templates/$tmpl already present — leaving operator copy untouched"
    else
        echo "install.sh: copying canary template $tmpl"
        install -m 0644 -o root -g root "$CANARY_TEMPLATES_SRC_DIR/$tmpl" "$ETC_DIR/canary-templates/$tmpl"
    fi
done

# Tappa 9 §13 Q5 TOFU baseline marker: a missing fim_baseline.jsonl
# (or one that contains only a stray comment / no chain entries) is
# the agent's signal at boot to run a first-boot baseline pass
# (RecomputeReason::FirstBootTofu). install.sh does NOT trigger the
# baseline itself — it can only bootstrap the empty file; the
# agent's main.rs decides whether to run TOFU based on the file's
# emptiness at attach time. Documented in:
#   docs/operator/TAPPA9_FIM_TRUST_MODEL.md

echo "install.sh: reloading systemd unit catalogue"
systemctl daemon-reload

echo ""
echo "install.sh: install complete."
echo ""
echo "Next steps (operator runs explicitly — install.sh does NOT auto-start):"
echo ""
echo "  1. Verify the install layout:"
echo "       systemctl status northnarrow-agent.service"
echo "       systemctl status northnarrow-watchdog.service"
echo ""
echo "  2. Confirm /etc/northnarrow/ has admin.pub + admin.key +"
echo "     combat-rules.v4 + combat-allow.cidrs + agent_id +"
echo "     fim-paths.v1 + canary-templates/ +"
echo "     netflow-blocklist.v1 + netflow-ja3-blocklist.v1 +"
echo "     process-comm-allowlist.v1 + netflow-comm-allowlist.v1 (the"
echo "     agent bootstraps agent_id on first start; admin.pub + admin.key"
echo "     were auto-generated above IF admin.pub was absent — MOVE"
echo "     admin.key OFFLINE now (see docs/operator/COMBAT_RECOVERY.md);"
echo "     combat-rules.v4 is operator-provided; combat-allow.cidrs +"
echo "     fim-paths.v1 + canary-templates/ + netflow-{,ja3-}blocklist.v1 +"
echo "     {process,netflow}-comm-allowlist.v1 were just installed above)."
echo "     Optional: add management CIDRs to combat-allow.cidrs to keep an"
echo "     SSH path open during COMBAT (anti-lockout — empty by default;"
echo "     see docs/operator/COMBAT_RECOVERY.md §2)."
echo "     Optional: drop /etc/northnarrow/fim-paths.local to customise"
echo "     the FIM watched-paths set (\`+/path\` add, \`-/path\` disable —"
echo "     see docs/operator/TAPPA9_FIM_TRUST_MODEL.md §13 Q7)."
echo "     Optional: drop /etc/northnarrow/netflow-blocklist.local +"
echo "     /etc/northnarrow/netflow-ja3-blocklist.local to extend the"
echo "     NetFlow blocklists from a threat-intel feed (\`+entry\` add,"
echo "     \`-entry\` disable — same schema as fim-paths.local; see"
echo "     docs/design/TAPPA10_NETWORK_OBSERVABILITY_DESIGN.md §10 + §13 Q5)."
echo "     Optional: drop /etc/northnarrow/process-comm-allowlist.local +"
echo "     /etc/northnarrow/netflow-comm-allowlist.local to tune the"
echo "     Tappa 10.5 detection-rule comm exemptions (\`+comm\` add,"
echo "     \`-comm\` re-enable detection on a default — same schema; see"
echo "     docs/design/TAPPA10_5_DETECTION_RULES_AT_SCALE_DESIGN.md §13 Q3)."
echo "     CONTAINER HOSTS: cp process-comm-allowlist.local.example to"
echo "     .local to exempt container-runtime comms (\`runc\` etc.). This"
echo "     weakens R013 escape-to-host detection — read the security note"
echo "     in docs/operator/CONTAINER_HOST_DEPLOY.md before enabling."
echo "     Deploy canaries with \`nn-admin canary deploy <type> --path ...\`"
echo "     (Tappa 9.5 §12 Q1 EXPLICIT-PER-HOST: no default canaries —"
echo "     placement is operator-curated)."
echo ""
echo "  3. Confirm bpffs is mounted at /sys/fs/bpf:"
echo "       mount | grep ' /sys/fs/bpf'"
echo "     If absent: mount -t bpf bpf /sys/fs/bpf"
echo ""
echo "  4. Confirm the 'bpf' LSM is in the kernel's lsm= chain:"
echo "       cat /sys/kernel/security/lsm"
echo "     If absent: edit /etc/default/grub to add 'lsm=…,bpf' then"
echo "       update-grub && reboot. (See docs/TAPPA7_PREREQ.md.)"
echo ""
echo "  5. Enable + start:"
echo "       systemctl enable --now northnarrow-agent.service"
echo "       systemctl enable --now northnarrow-watchdog.service"
echo ""
echo "  6. Follow logs:"
echo "       journalctl -u northnarrow-agent.service -f"
echo "       journalctl -u northnarrow-watchdog.service -f"
