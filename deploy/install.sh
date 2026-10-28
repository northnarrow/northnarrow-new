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
# ./target/release/{northnarrow-agent,northnarrow-watchdog,nn-admin,northnarrow-scan}.
# Use xtask, NOT a bare `cargo build`: xtask compiles the eBPF object
# (separate nightly/bpfel toolchain) and the userland in one step, and
# stamps the object so crates/nn-linux/build.rs can prove it is fresh. A plain
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
#     the eBPF object with a source-closure hash, `crates/nn-linux/build.rs`
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
#     LLM advisor's process_template, removed in Wave 4). They add NO new
#     config file: R011-R017 reuse
#     `process-comm-allowlist.v1` and the chain rules need none.
#   Engine grew 62 → 67 rules; that is internal to the agent binary and
#   needs no operator action.

set -euo pipefail

# ── configuration ───────────────────────────────────────────────────
REPO_ROOT=${REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
TARGET_DIR=${TARGET_DIR:-"$REPO_ROOT/target/release"}
BIN_DIR=${BIN_DIR:-/usr/local/bin}
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}
# Operator drop-ins always live in /etc, whatever directory holds the unit
# files themselves (a package ships them in /usr/lib/systemd/system).
DROPIN_ROOT=${DROPIN_ROOT:-/etc/systemd/system}
ETC_DIR=${ETC_DIR:-/etc/northnarrow}
STATE_DIR=${STATE_DIR:-/var/lib/northnarrow}
# The agent's bpffs pin root (the same override as uninstall.sh).
BPFFS_ROOT=${BPFFS_ROOT:-/sys/fs/bpf/northnarrow}
# The agent's runtime directory (the units' RuntimeDirectory=northnarrow) and
# the journald namespace config the units' LogNamespace= reads.
RUN_DIR=${RUN_DIR:-/run/northnarrow}
JOURNALD_NS_CONF=${JOURNALD_NS_CONF:-/etc/systemd/journald@northnarrow.conf}
# Lab PR 220: the transactional upgrade ("upgrade transaction" below). The
# copies of every file a run replaces live here until the run is over —
# outside the agent's own directories, which its hooks protect.
UPGRADE_TXN_ROOT=${UPGRADE_TXN_ROOT:-/var/lib/northnarrow-upgrade}
# How long the restarted units have to prove their health (upgrade_health_check).
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-60}
# What a rolled-back upgrade leaves for the restored agent to sign
# (agent/src/upgrade_rollback.rs, DEFAULT_MARKER_PATH).
ROLLBACK_MARKER=${ROLLBACK_MARKER:-$RUN_DIR/upgrade-rolled-back.json}

AGENT_BIN="$TARGET_DIR/northnarrow-agent"
WATCHDOG_BIN="$TARGET_DIR/northnarrow-watchdog"

# ── arguments ─────────────────────────────────────────────────────────
# --upgrade: the host already runs NorthNarrow. With the units active the
# anti-tamper layer denies every write this script makes (PROTECTED_INODES
# covers the binaries, the units and /etc/northnarrow; task_kill denies
# signals), so an in-place upgrade must: stop the watchdog FIRST (or it
# respawns the agent), stop the agent, drop the bpffs pin root so the LSM
# programs detach, wait until the agent's own programs are unloaded
# (wait_own_programs_unloaded), install, then start the units that were
# running. Keys, agent_id, the audit chain
# and every chain log are preserved — install.sh never touches them.
# Lab PR 220: the upgrade is a transaction ("upgrade transaction" below):
# every file it replaces is copied first, binaries and units are switched by
# rename, the restarted units must pass a health check
# (upgrade_health_check), and any failure after the stop restores the
# copies and starts the previous units again.
UPGRADE=0
GRANT_KEY=
# External audit DEP-001: where a fresh install writes the private half of
# the bootstrap admin key. Never under /etc/northnarrow or the state dir:
# those are the product's own trees (backed up, kept in etckeeper, read by
# tooling that would pick a key up from there), and the key must leave the
# host anyway — the agent reports it for as long as it stays.
ADMIN_KEY_OUT=/root/northnarrow-admin.key
# Package maintainer scripts (deploy/release/mk-packages.sh) drive this
# script in two halves around the package manager's own file copy:
#   --package-stop       before unpack/removal: stop the units, drop the pin
#                        root, remember which units ran (/run/northnarrow-pkg-restart)
#   --package-configure  after unpack: configure the host, restart them and
#                        check their health (lab PR 220; --defer-health-check
#                        leaves the check to the rpm %posttrans)
#   --package-verify     rpm %posttrans: that health check, once the whole
#                        transaction is over
# All three run with BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system and
# REPO_ROOT=/usr/share/northnarrow (the package's data tree).
MODE=full
PKG_RESTART_FILE=${PKG_RESTART_FILE:-/run/northnarrow-pkg-restart}
DEFER_HEALTH=0
VERIFY=1
# Lab PR 220: a release tree installs only at "attested" — the default, so
# REQUIRE_ATTESTATION starts at 1 and only --allow-unverified (or
# --allow-manifest-only) or --no-verify clears it. --require-attestation is
# accepted (the default) and makes a contradiction with them a usage error.
REQUIRE_ATTESTATION=1
REQUIRE_ATTESTATION_FLAG=0
# External audit DEP-007: the release checks no longer step down on their
# own. A tree without MANIFEST.sha256 is refused unless --source-tree says it
# is one. Lab PR 220 (static review of baf4c25 P0 C-45 / G-07): a release
# tree installs only when its SLSA provenance attestation verifies — an
# unsigned SHA256SUMS next to the tarball, or the tree's own MANIFEST.sha256,
# proves nothing about where it was built. --allow-unverified accepts less
# (and a source tree); --allow-manifest-only is its former, narrower name.
# The flag that accepted the lower level is logged (stderr and the system
# log, auth.warning), recorded in the install manifest (verify_override) and
# reported by `nn-admin host-check`.
SOURCE_TREE=0
ALLOW_UNVERIFIED=0
UNVERIFIED_FLAG=""
VERIFY_OVERRIDE=""
ATTEST_FAILURE=""
TARBALL=""
SUMS=""
ATTEST_BUNDLE=""
# Lab follow-up (lab PR 165): a host without nftables is refused unless
# --without-nftables; the flag is recorded in the install manifest
# (prerequisite_overrides) and reported by `nn-admin host-check`.
WITHOUT_NFT=0
PREREQ_OVERRIDES=()
# External audit EVD-019 (NN-AUD-281): the group that may read the audit log
# and the head anchor besides root — a log shipper's. Empty: each file keeps
# the group it has (root on a default install); every upgrade keeps it.
AUDIT_GROUP=${NN_AUDIT_GROUP:-}
# Lab PR 222: the copy-on-first-write guard's drop-in (CAP_SYS_ADMIN for its
# fanotify permission events). keep = leave an installed one in place
# (refreshed), 1 = install it, 0 = remove it.
COW_GUARD=keep
while [[ $# -gt 0 ]]; do
    case "$1" in
        --upgrade) UPGRADE=1 ;;
        --grant-key) GRANT_KEY=$2; shift ;;
        --admin-key-out) ADMIN_KEY_OUT=$2; shift ;;
        --package-stop) MODE=stop ;;
        --package-configure) MODE=configure ;;
        --package-verify) MODE=verify ;;
        --defer-health-check) DEFER_HEALTH=1 ;;
        --tarball) TARBALL=$2; shift ;;
        --sums) SUMS=$2; shift ;;
        --attestation) ATTEST_BUNDLE=$2; shift ;;
        --require-attestation) REQUIRE_ATTESTATION_FLAG=1 ;;
        --source-tree) SOURCE_TREE=1 ;;
        --allow-unverified) ALLOW_UNVERIFIED=1; UNVERIFIED_FLAG=--allow-unverified ;;
        --allow-manifest-only) ALLOW_UNVERIFIED=1; UNVERIFIED_FLAG=${UNVERIFIED_FLAG:---allow-manifest-only} ;;
        --no-verify) VERIFY=0 ;;
        --without-nftables) WITHOUT_NFT=1 ;;
        --audit-group) AUDIT_GROUP=$2; shift ;;
        --cow-guard) COW_GUARD=1 ;;
        --no-cow-guard) COW_GUARD=0 ;;
        -h|--help)
            echo "usage: sudo $0 [--upgrade --grant-key KEY] [--tarball FILE] [--sums FILE] [--attestation BUNDLE]"
            echo "                 [--source-tree | --allow-unverified | --no-verify] [--without-nftables]"
            echo "  --upgrade              stop the running units, replace binaries/units/configs, restart them and"
            echo "                         check their health; on any failure the previous files are restored and the"
            echo "                         previous units started again (exit 3; 4 when that could not be completed)"
            echo "  --grant-key KEY        admin key with the trusted-installer role (opens the window an upgrade needs,"
            echo "                         and the new agent's window for a rollback): required by --upgrade"
            echo "  --admin-key-out PATH   fresh install: where to write the bootstrap admin PRIVATE key"
            echo "                         (default /root/northnarrow-admin.key; never under $ETC_DIR) — move it offline"
            echo "  --tarball FILE         the release tarball this tree was extracted from (default: ../<tree>.tar.gz)"
            echo "  --sums FILE            SHA256SUMS of the release (default: next to the tarball)"
            echo "  --attestation BUNDLE   offline Sigstore bundle for the tarball (gh attestation download)"
            echo "  A release tree installs only when the tarball's SLSA provenance attestation verifies (gh 2.49+,"
            echo "  or cosign with --attestation) and the tree is the tarball's (--require-attestation: the default)."
            echo "  --allow-unverified     install a tree whose attestation did not verify, or a build from source"
            echo "                         (lab, development): logged, recorded as 'checksums', 'manifest' or"
            echo "                         'source-tree' with the flag (--allow-manifest-only: its former name)"
            echo "  --source-tree          the tree is a build from source (cargo xtask build --release), not a"
            echo "                         release: install it without MANIFEST.sha256 (recorded as 'source-tree')"
            echo "  --no-verify            skip every release check (dev only; recorded as 'unverified')"
            echo "  --cow-guard            add the copy-on-first-write drop-in (CAP_SYS_ADMIN, CAP_CHOWN, CAP_FOWNER;"
            echo "                         EXPERIMENTAL; the guard stays off without a signed cow-guard.local)"
            echo "  --no-cow-guard         remove that drop-in"
            echo "  --audit-group GROUP    existing group that may read $ETC_DIR/audit.log and chain_heads.json"
            echo "                         besides root (a log shipper; NN_AUDIT_GROUP too). Kept by later upgrades"
            echo "  The flag that accepted a level below 'attested' is logged (auth.warning), recorded in the"
            echo "  install manifest and reported by nn-admin host-check."
            echo "  --without-nftables     install on a host without nft (nftables): the agent's per-process"
            echo "                         outbound block then cannot work (recorded in the install manifest)"
            exit 0 ;;
        *) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
if (( REQUIRE_ATTESTATION_FLAG )) && { (( ALLOW_UNVERIFIED )) || (( ! VERIFY )); }; then
    echo "install.sh: --require-attestation contradicts ${UNVERIFIED_FLAG:---no-verify}" >&2
    exit 2
fi
if (( ALLOW_UNVERIFIED )) || (( ! VERIFY )); then
    REQUIRE_ATTESTATION=0
fi
if (( DEFER_HEALTH )) && [[ $MODE != configure ]]; then
    echo "install.sh: --defer-health-check goes with --package-configure only" >&2
    exit 2
fi
if [[ -n "$AUDIT_GROUP" ]]; then
    if [[ ! "$AUDIT_GROUP" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || ! getent group "$AUDIT_GROUP" >/dev/null; then
        echo "install.sh: --audit-group $AUDIT_GROUP: no such group — create it first (groupadd --system <name>)" >&2
        exit 2
    fi
fi
if [[ $MODE != full ]]; then
    # The package manager verified and placed the files; there is no tree
    # to verify and nothing to copy. The trusted-installer key comes from
    # --grant-key or NN_GRANT_KEY only, or the operator opens the window
    # before the package command. External audit DEP-001: a bootstrap key
    # left on the host is never picked up on its own — that made every
    # package upgrade suspend the anti-tamper with whatever key root could
    # read.
    VERIFY=0
    GRANT_KEY=${GRANT_KEY:-${NN_GRANT_KEY:-}}
fi
case "$ADMIN_KEY_OUT" in
    "$ETC_DIR"|"$ETC_DIR"/*|"$STATE_DIR"|"$STATE_DIR"/*|/etc/northnarrow/*|/var/lib/northnarrow/*)
        echo "install.sh: --admin-key-out $ADMIN_KEY_OUT is inside NorthNarrow's own directories — refused" >&2
        echo "install.sh: (external audit DEP-001): write the private key elsewhere and move it offline." >&2
        exit 2 ;;
esac
# Beta Step 4c: nn-admin is the operator's COMBAT-release / admin tool.
# It must be on-host so an operator can unlock COMBAT, and install.sh
# uses it below to bootstrap admin.pub on a fresh install (issue #124).
NN_ADMIN_BIN="$TARGET_DIR/nn-admin"
# Lab PR 223 (EXPERIMENTAL): the exec quarantine's confined scanner, which
# the agent spawns as the `northnarrow-scan` account (created below). Off
# unless the agent runs with --exec-quarantine.
SCAN_BIN="$TARGET_DIR/northnarrow-scan"
SCAN_USER=northnarrow-scan
AGENT_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-agent.service"
WATCHDOG_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-watchdog.service"
# Lab PR 216: the watchdog unit's OnFailure= handler (records that systemd
# gave up on the watchdog; not enabled, started only by OnFailure=).
WATCHDOG_FAILED_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-watchdog-failed.service"
# Dedicated journal-namespace config (activated by LogNamespace=northnarrow
# in both units). Capped, isolated journald instance → no /var/log/syslog
# amplification, hard SystemMaxUse ceiling, zero customer config.
JOURNALD_NS_CONF_SRC="$REPO_ROOT/deploy/systemd/journald@northnarrow.conf"

# Cluster-15 eBPF staleness guard (install-time half). The compiled
# eBPF object is built by `cargo xtask` and its provenance stamp
# (`.buildhash`) is written alongside it. `require_fresh_ebpf` (below)
# uses these to refuse installing an agent binary that predates the
# current eBPF object. Paths MUST match ebpf-guard's ARTIFACT_RELPATH /
# STAMP_RELPATH (ebpf-guard/src/lib.rs).
EBPF_ARTIFACT="$REPO_ROOT/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf"
EBPF_STAMP="$EBPF_ARTIFACT.buildhash"

# Tappa 9 C7: default FIM watched-paths list. install.sh installs this
# at /etc/northnarrow/fim-paths.v1 (install_shipped_v1); the agent loads it
# at boot and merges any operator overlay at /etc/northnarrow/fim-paths.local.
FIM_PATHS_V1_SRC="$REPO_ROOT/configs/fim-paths.v1"

# Tappa 9.5 K7: canary content templates the K4 renderer reads at
# `canary deploy` time. install.sh drops the 5 .tmpl files into
# /etc/northnarrow/canary-templates/. PROTECTED_INODES covers each
# individual .tmpl file (see ETC_PROTECTED_TEMPLATES in
# crates/nn-linux/src/anti_tamper/filesystem.rs) — tamper would silently
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
# (IP / CIDR) + NN-L-NET-003 (JA3 fingerprint). install.sh installs
# these at /etc/northnarrow/netflow-blocklist.v1 +
# /etc/northnarrow/netflow-ja3-blocklist.v1 (install_shipped_v1); operators
# extend / narrow via the matching `.local` overlays. ETC_PROTECTED_FILES
# (crates/nn-linux/src/anti_tamper/filesystem.rs) widens to cover the four
# blocklist filenames so PROTECTED_INODES defends them against
# tamper — the same lock-in as fim-paths.v1 / .local.
NETFLOW_BLOCKLIST_V1_SRC="$REPO_ROOT/configs/netflow-blocklist.v1"
NETFLOW_JA3_BLOCKLIST_V1_SRC="$REPO_ROOT/configs/netflow-ja3-blocklist.v1"

# Tappa 10.5 D1: default per-family comm allowlists. process-comm
# exempts trusted actors from the process detection rules (R011..);
# netflow-comm is the trusted-actor set the network rules suppress on
# (seeded from the inline const sets formerly in net.rs). install.sh
# installs both .v1 files (install_shipped_v1); operators tune via the
# matching `.local` overlays. ETC_PROTECTED_FILES widens to cover all four
# filenames so PROTECTED_INODES defends them against tamper — the
# same lock-in as fim-paths.v1 / netflow-blocklist.v1.
PROCESS_COMM_ALLOWLIST_V1_SRC="$REPO_ROOT/configs/process-comm-allowlist.v1"
# Beta Step 3: opt-in overlay template (container-runtime exemptions,
# off by default). Shipped as a `.example` an operator copies to the
# live `.local` to activate — the v1 default stays conservative so R013
# escape-to-host detection is preserved on non-container hosts.
PROCESS_COMM_ALLOWLIST_EXAMPLE_SRC="$REPO_ROOT/configs/process-comm-allowlist.local.example"
NETFLOW_COMM_ALLOWLIST_V1_SRC="$REPO_ROOT/configs/netflow-comm-allowlist.v1"
# Lab PR 225: the security tools whose disabling NN-L-EVA-001..004 detect.
# Shipped content like the other .v1 lists (install_shipped_v1); protected
# by PROTECTED_INODES; no overlay yet.
SECURITY_TOOLS_V1_SRC="$REPO_ROOT/configs/security-tools.v1"
# Beta Step 4b: empty-by-default COMBAT management carve-out CIDR list.
COMBAT_ALLOW_CIDRS_SRC="$REPO_ROOT/configs/combat-allow.cidrs"

# ── pre-flight ──────────────────────────────────────────────────────
# ── release verification (supply chain, install-time half) ───────────
# What the operator downloaded must be what CI built and attested:
#   1. MANIFEST.sha256 inside the tree (every file hashed by mk-tarball)
#      — catches a corrupted or edited tree;
#   2. SHA256SUMS of the release against the tarball — catches a
#      swapped tarball;
#   3. the tree is the tarball's: its MANIFEST.sha256 is the one inside the
#      tarball (lab PR 220) — catches an edited tree, manifest rewritten,
#      next to a genuine tarball;
#   4. the SLSA provenance attestation of the tarball, verified with
#      `gh attestation verify` (online or with an offline --attestation
#      bundle) or cosign, bound to THIS repository's release workflow run
#      for a v* tag — catches a tarball built elsewhere, or by a dispatch
#      run on a branch.
# The strongest level reached is recorded in the install manifest and
# the agent re-checks the installed hashes at every boot. A source tree
# (no MANIFEST.sha256: the lab, a developer build) is "source-tree" and
# needs --source-tree or --allow-unverified; a release tree below
# "attested" needs --allow-unverified (external audit DEP-007, lab PR 220:
# require_provenance_floor).
REPO_SLUG="northnarrow/northnarrow-new"
SIGNER_WORKFLOW="$REPO_SLUG/.github/workflows/release.yml"
# External audit SUP-001: the certificate identity must be the release
# workflow at a v* tag. --signer-workflow accepted any ref, so the artefacts
# of a workflow_dispatch run on a branch verified as well.
SIGNER_IDENTITY_REGEX='^https://github\.com/northnarrow/northnarrow-new/\.github/workflows/release\.yml@refs/tags/v'
PROVENANCE="source-tree"
TARBALL_SHA256=""
ATTEST_METHOD="none"
ATTEST_VERIFIED=0
# >>> sums_expected (run by xtask/tests/install_scripts.rs)
# External audit DEP-016 (NN-AUD-388): the checksum SHA256SUMS lists for a
# file NAME. The name used to be pasted into a `grep -E` pattern: its dots
# matched any character, so a line for another file (`…-1X2.3-…`) listed
# first was taken for it (a spurious REFUSED), and a name with a `+` was
# never found. The name is now compared as a string with the second field,
# a leading `*` (binary mode) removed. Prints the checksum; exit 1 when no
# line names the file, 3 when lines name it with different checksums (the
# first one is no longer picked), awk's own status (2) when FILE cannot be
# read.
sums_expected() {
    NN_SUMS_NAME=$1 awk '
        { n = $2; sub(/^\*/, "", n) }
        NF == 2 && n == ENVIRON["NN_SUMS_NAME"] {
            h = tolower($1)
            if (!(h in seen)) { seen[h] = 1; distinct++; found = h }
        }
        END {
            if (distinct == 0) exit 1
            if (distinct > 1) exit 3
            print found
        }' "$2"
}
# <<< sums_expected
# Lab PR 220: an accepted lower level is not only a line on the terminal —
# the system log (auth.warning, tag northnarrow-install) has it too, next to
# the install manifest's verify_override and `nn-admin host-check`.
log_override() {
    echo "install.sh: WARNING: $1" >&2
    logger -p auth.warning -t northnarrow-install -- "$1" 2>/dev/null || true
}
# Lab PR 220 (G-36): the checks of the tarball vouch for the tarball, and the
# tree is what gets installed — with a MANIFEST.sha256 that travels inside the
# tree it vouches for. The tree is the tarball's when its MANIFEST.sha256 is
# the one the tarball holds (its one top-level directory's), byte for byte;
# `sha256sum -c` then binds every file of the tree to it. Exit 0 the same, 1
# different, 2 no single MANIFEST.sha256 in the tarball (or it is unreadable).
tarball_manifest_matches() {   # <tarball> <the tree's MANIFEST.sha256>
    local member
    member=$(tar -tzf "$1" 2>/dev/null | awk -F/ 'NF == 2 && $1 != "." && $2 == "MANIFEST.sha256"') || return 2
    [[ -n "$member" && "$member" != *$'\n'* ]] || return 2
    tar -xzOf "$1" "$member" 2>/dev/null | cmp -s - "$2"
}
verify_release() {
    if (( ! VERIFY )); then
        PROVENANCE="unverified"
        VERIFY_OVERRIDE="--no-verify"
        log_override "--no-verify — release checks skipped, provenance recorded as 'unverified'"
        return 0
    fi
    if [[ -f "$REPO_ROOT/MANIFEST.sha256" ]]; then
        (( SOURCE_TREE )) && echo "install.sh: --source-tree ignored — the tree carries MANIFEST.sha256 and is verified as a release" >&2
        echo "install.sh: verifying the extracted tree against MANIFEST.sha256"
        if ! (cd "$REPO_ROOT" && sha256sum -c --quiet MANIFEST.sha256); then
            echo "install.sh: REFUSED — the extracted tree does not match MANIFEST.sha256 (corrupted or edited release)" >&2
            exit 1
        fi
        PROVENANCE="manifest"
    else
        # External audit DEP-007: removing this one file used to turn every
        # check below off ("source tree"). Every release tree ships it
        # (mk-tarball.sh), so its absence is a refusal unless the operator
        # says the tree is a build from source.
        if (( ! SOURCE_TREE && ! ALLOW_UNVERIFIED )); then
            echo "install.sh: REFUSED — no MANIFEST.sha256 in $REPO_ROOT. A release tree always carries one:" >&2
            echo "install.sh: this one was altered, or it is a build from source. For a source build" >&2
            echo "install.sh: (cargo xtask build --release) re-run with --source-tree or --allow-unverified" >&2
            echo "install.sh: (recorded as 'source-tree')." >&2
            exit 1
        fi
        VERIFY_OVERRIDE=$( (( SOURCE_TREE )) && echo --source-tree || echo "$UNVERIFIED_FLAG")
        log_override "$VERIFY_OVERRIDE — no MANIFEST.sha256: a build from source, release checks not applicable (provenance: source-tree)"
        return 0
    fi
    local tree_name tgz sums out=""
    tree_name=$(basename "$REPO_ROOT")
    tgz=${TARBALL:-"$REPO_ROOT/../$tree_name.tar.gz"}
    if [[ ! -f "$tgz" ]]; then
        ATTEST_FAILURE="no tarball next to the tree"
        echo "install.sh: tarball not found ($tgz) — the attestation is the tarball's: pass --tarball (and --sums)" >&2
        return 0
    fi
    TARBALL_SHA256=$(sha256sum "$tgz" | cut -d' ' -f1)
    local rc=0
    tarball_manifest_matches "$tgz" "$REPO_ROOT/MANIFEST.sha256" || rc=$?
    case $rc in
        0) echo "install.sh: the tree is the tarball's (its MANIFEST.sha256 is the one in $(basename "$tgz"))" ;;
        1) echo "install.sh: REFUSED — the tree's MANIFEST.sha256 is not the one in $(basename "$tgz"): the tree was" >&2
           echo "install.sh: not extracted from this tarball, or it was edited and its manifest rewritten" >&2
           exit 1 ;;
        *) echo "install.sh: REFUSED — $(basename "$tgz") holds no single <tree>/MANIFEST.sha256 (or cannot be read)" >&2
           exit 1 ;;
    esac
    sums=${SUMS:-"$(dirname "$tgz")/SHA256SUMS"}
    if [[ -f "$sums" ]]; then
        local expected
        rc=0
        expected=$(sums_expected "$(basename "$tgz")" "$sums") || rc=$?
        case $rc in
            0) ;;
            1) echo "install.sh: REFUSED — $(basename "$tgz") is not listed in $sums" >&2
               exit 1 ;;
            3) echo "install.sh: REFUSED — $sums lists $(basename "$tgz") more than once, with different checksums" >&2
               exit 1 ;;
            *) echo "install.sh: REFUSED — $sums could not be read (awk exit $rc)" >&2
               exit 1 ;;
        esac
        if [[ "$expected" != "$TARBALL_SHA256" ]]; then
            echo "install.sh: REFUSED — tarball sha256 $TARBALL_SHA256 does not match SHA256SUMS ($expected)" >&2
            exit 1
        fi
        echo "install.sh: tarball matches SHA256SUMS ($TARBALL_SHA256)"
        PROVENANCE="checksums"
    else
        echo "install.sh: SHA256SUMS not found next to the tarball — pass --sums to verify it" >&2
    fi
    # attestation: gh (2.49+) online or with an offline bundle, else cosign.
    # Lab PR 220: a failure is no longer a line and a lower level — it is a
    # refusal (require_provenance_floor), with what the verifier said.
    if command -v gh >/dev/null 2>&1 && gh attestation --help >/dev/null 2>&1; then
        local -a args=(attestation verify "$tgz" --repo "$REPO_SLUG" --cert-identity-regex "$SIGNER_IDENTITY_REGEX" --deny-self-hosted-runners)
        [[ -n "$ATTEST_BUNDLE" ]] && args+=(--bundle "$ATTEST_BUNDLE")
        ATTEST_METHOD=$([[ -n "$ATTEST_BUNDLE" ]] && echo gh-bundle || echo gh)
        if out=$(gh "${args[@]}" 2>&1); then
            ATTEST_VERIFIED=1
        else
            ATTEST_FAILURE="gh attestation verify failed"
            echo "install.sh: gh attestation verify FAILED for $(basename "$tgz") (signer $SIGNER_WORKFLOW):" >&2
            printf '%s\n' "$out" | tail -n 5 | sed 's/^/install.sh:   /' >&2
        fi
    elif command -v cosign >/dev/null 2>&1 && [[ -n "$ATTEST_BUNDLE" ]]; then
        ATTEST_METHOD=cosign
        if out=$(cosign verify-blob-attestation --bundle "$ATTEST_BUNDLE" --new-bundle-format \
            --certificate-identity-regexp "$SIGNER_IDENTITY_REGEX" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com "$tgz" 2>&1); then
            ATTEST_VERIFIED=1
        else
            ATTEST_FAILURE="cosign verify-blob-attestation failed"
            echo "install.sh: cosign attestation verification FAILED for $(basename "$tgz"):" >&2
            printf '%s\n' "$out" | tail -n 5 | sed 's/^/install.sh:   /' >&2
        fi
    else
        ATTEST_FAILURE="no attestation verifier (gh 2.49+, or cosign with --attestation)"
        echo "install.sh: no attestation verifier available (gh ≥ 2.49, or cosign + --attestation bundle)" >&2
    fi
    if (( ATTEST_VERIFIED )); then
        echo "install.sh: SLSA provenance attestation verified ($ATTEST_METHOD, signer $SIGNER_WORKFLOW)"
        PROVENANCE="attested"
    fi
}

# External audit DEP-007: MANIFEST.sha256 travels inside the tree it vouches
# for — whoever edits the tree can rewrite it. Lab PR 220 (static review of
# baf4c25 P0 C-45 / G-07): so does an unsigned SHA256SUMS next to the
# tarball — whoever swaps the tarball swaps it too. A release tree installs
# at "attested" only; "checksums" and "manifest" need --allow-unverified,
# which is logged and recorded. Separate from verify_release so the verifier
# itself stays a verifier.
require_provenance_floor() {
    case $PROVENANCE in
        checksums|manifest) ;;
        *) return 0 ;;
    esac
    if (( REQUIRE_ATTESTATION )); then
        echo "install.sh: REFUSED — the release's SLSA provenance attestation did not verify ($ATTEST_FAILURE)." >&2
        echo "install.sh: $([[ $PROVENANCE == checksums ]] && echo "SHA256SUMS is not signed: it proves the tarball is the one it lists, not" || echo "Only the tree's own MANIFEST.sha256 was checked: it proves nothing about") where the release was built." >&2
        echo "install.sh: Keep the tarball next to the tree (or --tarball FILE), with gh 2.49+ (online) or an offline" >&2
        echo "install.sh: bundle (gh attestation download <tarball> --repo $REPO_SLUG; --attestation FILE, gh or" >&2
        echo "install.sh: cosign), see docs/operator/INSTALL_UPGRADE_UNINSTALL.md §5.1 — or re-run with" >&2
        echo "install.sh: --allow-unverified (logged, recorded as '$PROVENANCE')." >&2
        exit 1
    fi
    VERIFY_OVERRIDE=$UNVERIFIED_FLAG
    log_override "$UNVERIFIED_FLAG — the release's provenance attestation did not verify ($ATTEST_FAILURE): installed at provenance '$PROVENANCE'"
}

# Record what was installed: provenance level + sha256 of every installed
# binary and of the eBPF object. The agent compares its own binary, the
# watchdog, nn-admin and the embedded object hash against this file at
# every boot (agent/src/install_manifest.rs) and refuses to start on a
# mismatch; the file sits under the inode_protect hook with the rest of
# /etc/northnarrow.
write_install_manifest() {
    local manifest="$ETC_DIR/install-manifest.json" version
    version=$("$BIN_DIR/northnarrow-agent" --version 2>/dev/null | awk '{print $NF}')
    local sha_agent sha_wd sha_admin sha_scan sha_ebpf
    sha_agent=$(sha256sum "$BIN_DIR/northnarrow-agent" | cut -d' ' -f1)
    sha_wd=$(sha256sum "$BIN_DIR/northnarrow-watchdog" | cut -d' ' -f1)
    sha_admin=$(sha256sum "$BIN_DIR/nn-admin" | cut -d' ' -f1)
    sha_scan=$(sha256sum "$BIN_DIR/northnarrow-scan" | cut -d' ' -f1)
    sha_ebpf=$(sha256sum "$EBPF_ARTIFACT" | cut -d' ' -f1)
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<EOT
{
  "version": "${version:-unknown}",
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "provenance": "$PROVENANCE",
  "verify_override": $([[ -n "$VERIFY_OVERRIDE" ]] && echo "\"$VERIFY_OVERRIDE\"" || echo null),
  "prerequisite_overrides": $(prereq_overrides_json),
  "bin_dir": "$BIN_DIR",
  "files": {
    "northnarrow-agent": "$sha_agent",
    "northnarrow-watchdog": "$sha_wd",
    "nn-admin": "$sha_admin",
    "northnarrow-scan": "$sha_scan",
    "ebpf_object": "$sha_ebpf"
  },
  "tarball_sha256": $([[ -n "$TARBALL_SHA256" ]] && echo "\"$TARBALL_SHA256\"" || echo null),
  "attestation": {"verified": $([[ $ATTEST_VERIFIED == 1 ]] && echo true || echo false), "method": "$ATTEST_METHOD", "signer_workflow": "$SIGNER_WORKFLOW", "failure": $([[ -n "$ATTEST_FAILURE" ]] && echo "\"$ATTEST_FAILURE\"" || echo null)}
}
EOT
    # Lab PR 220: next to the old one, then rename(2) over it — the agent
    # reads the old manifest or the new one, never half of it.
    install -m 0644 -o root -g root "$tmp" "$manifest.nn-new"
    mv -fT "$manifest.nn-new" "$manifest"
    rm -f "$tmp"
    echo "install.sh: install manifest written to $manifest (provenance: $PROVENANCE)"
}

# The flags that accepted a missing prerequisite, as a JSON array.
prereq_overrides_json() {
    local out="" o
    for o in ${PREREQ_OVERRIDES[@]+"${PREREQ_OVERRIDES[@]}"}; do
        out+="${out:+, }\"$o\""
    done
    echo "[$out]"
}

# Lab follow-up (lab PR 165): the agent's per-process outbound block (a
# BlockOutbound verdict, the COMBAT soft egress block during INVESTIGATE) is
# an nftables rule applied with `nft -f -`. Without `nft` the agent runs but
# cannot drop an offender's traffic; Debian 12's cloud image ships without
# it. install.sh installs no system package: it refuses and names the
# command, or goes on with --without-nftables (recorded). The packages
# depend on nftables, so in --package-configure a missing `nft` (a forced
# install) is a warning: a failing post-unpack hook would leave the package
# half-configured. NFT_DIRS are the directories the agent looks in
# (external audit ATP-014, crates/nn-linux/src/trusted_bin.rs): the system ones, never
# /usr/local, and only a root-owned file nobody else can write.
NFT_DIRS=${NFT_DIRS:-"/usr/sbin /usr/bin /sbin /bin"}
find_nft() {
    local d real
    for d in $NFT_DIRS; do
        real=$(readlink -f "$d/nft" 2>/dev/null) || continue
        if [[ -f "$real" && -x "$real" ]] && [[ $(stat -c '%u' "$real") == 0 ]] &&
            (( (8#$(stat -c '%a' "$real") & 8#022) == 0 )); then
            echo "$d/nft"
            return 0
        fi
    done
    return 1
}
nft_install_hint() {
    if command -v apt-get >/dev/null 2>&1; then echo "apt-get install nftables"
    elif command -v dnf >/dev/null 2>&1; then echo "dnf install nftables"
    elif command -v yum >/dev/null 2>&1; then echo "yum install nftables"
    elif command -v zypper >/dev/null 2>&1; then echo "zypper install nftables"
    else echo "install the distribution's nftables package"
    fi
}
require_nft() {
    local nft
    if nft=$(find_nft); then
        echo "install.sh: nftables present ($nft)"
        return 0
    fi
    if [[ $MODE == configure ]]; then
        echo "install.sh: WARNING: nft (nftables) not found although the package depends on it (a forced install?):" >&2
        echo "install.sh: the agent's per-process outbound block will not work — $(nft_install_hint)" >&2
        return 0
    fi
    if (( WITHOUT_NFT )); then
        PREREQ_OVERRIDES+=("--without-nftables")
        echo "install.sh: WARNING: --without-nftables — no nft on this host: a BlockOutbound verdict and the COMBAT" >&2
        echo "install.sh: soft egress block will not drop an offender's traffic (recorded in the install manifest)" >&2
        return 0
    fi
    echo "install.sh: REFUSED — nft (nftables) not found in: $NFT_DIRS" >&2
    echo "install.sh: the agent's per-process outbound block (a BlockOutbound verdict, the COMBAT soft egress" >&2
    echo "install.sh: block during INVESTIGATE) is an nftables rule: without nft it cannot contain an offender." >&2
    echo "install.sh: install it first:  sudo $(nft_install_hint)" >&2
    echo "install.sh: or re-run with --without-nftables (recorded in the install manifest, reported by nn-admin host-check)." >&2
    exit 1
}

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
# time; `crates/nn-linux/build.rs` refuses to embed a stale or unstamped object,
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

# ── upgrade health check (rollback.sh carries a copy: txn_write_resume) ──
# Lab PR 220 (static review of baf4c25 P0 C-45 / TD-09): an upgrade used to
# be over when `systemctl start` returned. It is over when what now runs
# shows that it protects the host:
#   - every unit that ran before is active (both are Type=notify: active is
#     the READY=1 each sends once it is wired up);
#   - the agent's own event "anti-tamper: all LSM hooks attached" with
#     deny_attached equal to deny_expected — or the observe-hook shortfall,
#     every deny hook attached and only telemetry missing (a WARNING) — as an
#     event of the unit's main process: _SYSTEMD_UNIT, _PID and _TRANSPORT
#     are fields journald sets, not the writer; one event is one stdout line,
#     and a value another user names (a file name) is a field after an
#     event's message, never at its start (lab PR 167, 206), so the whole
#     line is matched;
#   - the pid file names that process, and it answers `nn-admin status` on
#     its admin socket;
#   - the watchdog's own event "watchdog PID registered in PROTECTED_PIDS"
#     with its main pid: the pid the task_kill hook now protects (the agent
#     registers itself before its hooks attach: its health line says so).
# Polled for HEALTH_TIMEOUT seconds; HEALTH_FAILURE names what is missing,
# HEALTH_NOTE a weakness that does not fail the check.
ADMIN_SOCKET=${ADMIN_SOCKET:-$RUN_DIR/admin.sock}
NN_TS_RE='[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})'
HEALTH_FAILURE=""
HEALTH_NOTE=""
unit_main_pid() {
    local p
    p=$(systemctl show -p MainPID --value "$1.service" 2>/dev/null) || return 1
    [[ "$p" =~ ^[1-9][0-9]*$ ]] || return 1
    echo "$p"
}
# The stdout events of unit $1 written by process $2, one per line.
own_events() {
    journalctl --namespace=northnarrow "_SYSTEMD_UNIT=$1.service" "_PID=$2" _TRANSPORT=stdout -o cat --no-pager 2>/dev/null || true
}
# "<deny_attached> <deny_expected> <all|observe-shortfall|deny-shortfall>"
# from the anti-tamper health event of agent pid $1 (NN_TS_RE holds two
# groups: the counts are groups 3 and 4).
agent_deny_hooks() {
    local line kind all obs deny
    all="^$NN_TS_RE +INFO anti-tamper: all LSM hooks attached deny_attached=([0-9]+) deny_expected=([0-9]+)\$"
    obs="^$NN_TS_RE +WARN anti-tamper: OBSERVE HOOK SHORTFALL .* deny_attached=([0-9]+) deny_expected=([0-9]+) observe_failed=.*\$"
    deny="^$NN_TS_RE +ERROR anti-tamper: DENY HOOK SHORTFALL .* deny_attached=([0-9]+) deny_expected=([0-9]+) .*\$"
    while IFS= read -r line; do
        if [[ "$line" =~ $all ]]; then kind=all
        elif [[ "$line" =~ $obs ]]; then kind=observe-shortfall
        elif [[ "$line" =~ $deny ]]; then kind=deny-shortfall
        else continue
        fi
        echo "${BASH_REMATCH[3]} ${BASH_REMATCH[4]} $kind"
        return 0
    done < <(own_events northnarrow-agent "$1")
    return 1
}
watchdog_registered() {   # <pid>
    local line re="^$NN_TS_RE +INFO watchdog: watchdog PID registered in PROTECTED_PIDS pid=$1( .*)?\$"
    while IFS= read -r line; do
        [[ "$line" =~ $re ]] && return 0
    done < <(own_events northnarrow-watchdog "$1")
    return 1
}
health_once() {   # <unit>...
    local u state pid hooks da de kind
    HEALTH_FAILURE=""
    HEALTH_NOTE=""
    # Every unit that is not active is named: the watchdog waits for the
    # agent it supervises, so a new agent that does not start leaves the
    # watchdog "activating" too, and naming only the first unit checked
    # pointed at the watchdog (lab, 21/10, debian12).
    for u in "$@"; do
        state=$(systemctl is-active "$u.service" 2>/dev/null) || true
        if [[ "$state" != active ]]; then
            HEALTH_FAILURE="${HEALTH_FAILURE:+$HEALTH_FAILURE; }$u.service is ${state:-unknown}"
        fi
    done
    [[ -z "$HEALTH_FAILURE" ]] || return 1
    for u in "$@"; do
        case $u in
            northnarrow-agent)
                if ! pid=$(unit_main_pid northnarrow-agent); then
                    HEALTH_FAILURE="northnarrow-agent.service has no main process"
                    return 1
                fi
                if [[ "$(cat "$RUN_DIR/agent.pid" 2>/dev/null)" != "$pid" ]]; then
                    HEALTH_FAILURE="$RUN_DIR/agent.pid does not name the agent's main process ($pid)"
                    return 1
                fi
                if ! hooks=$(agent_deny_hooks "$pid"); then
                    HEALTH_FAILURE="the agent (pid $pid) logged no 'anti-tamper: all LSM hooks attached'"
                    return 1
                fi
                read -r da de kind <<<"$hooks"
                if [[ $kind == deny-shortfall ]] || (( da != de || de == 0 )); then
                    HEALTH_FAILURE="the agent (pid $pid) runs with $da of $de deny hooks attached (DENY HOOK SHORTFALL)"
                    return 1
                fi
                if [[ $kind == observe-shortfall ]]; then
                    HEALTH_NOTE="the agent (pid $pid) attached every deny hook ($de) but not every observe hook: some telemetry is missing (its signed subsystem_degraded names it)"
                fi
                if ! "$BIN_DIR/nn-admin" status --socket "$ADMIN_SOCKET" --json >/dev/null 2>&1; then
                    HEALTH_FAILURE="the agent (pid $pid) does not answer nn-admin status on $ADMIN_SOCKET"
                    return 1
                fi
                ;;
            northnarrow-watchdog)
                if ! pid=$(unit_main_pid northnarrow-watchdog); then
                    HEALTH_FAILURE="northnarrow-watchdog.service has no main process"
                    return 1
                fi
                if ! watchdog_registered "$pid"; then
                    HEALTH_FAILURE="the watchdog (pid $pid) logged no 'watchdog PID registered in PROTECTED_PIDS'"
                    return 1
                fi
                ;;
        esac
    done
    return 0
}
upgrade_health_check() {   # <unit>...
    local i
    for ((i = 0; ; i++)); do
        health_once "$@" && return 0
        (( i < HEALTH_TIMEOUT )) || return 1
        sleep 1
    done
}
# The package hooks' side of the health check (lab PR 220): pass, or name
# what is missing on the terminal and in the system log (auth.err, tag
# northnarrow-pkg) and fail the hook, so the package manager reports the
# operation as failed. The restart list stays: `dpkg --configure -a` (or the
# next attempt) starts and checks the units again.
pkg_health_or_fail() {   # <unit>...
    local msg
    if upgrade_health_check "$@"; then
        if [[ -n "$HEALTH_NOTE" ]]; then echo "install.sh: WARNING: $HEALTH_NOTE" >&2; fi
        echo "install.sh: health check passed ($*)"
        rm -f "$PKG_RESTART_FILE"
        return 0
    fi
    msg="the upgraded NorthNarrow did not pass its health check: $HEALTH_FAILURE"
    echo "install.sh: $msg" >&2
    echo "install.sh: at this point the package manager does not restore the previous version (what each one" >&2
    echo "install.sh: can roll back: docs/operator/INSTALL_UPGRADE_UNINSTALL.md §6.2). Find the cause (systemctl" >&2
    echo "install.sh: status <unit>; journalctl --namespace=northnarrow -u <unit>), then run the configure step" >&2
    echo "install.sh: again, or install the previous package with NN_GRANT_KEY set." >&2
    logger -p auth.err -t northnarrow-pkg -- "$msg" 2>/dev/null || true
    return 1
}

# >>> rollback_marker (agent/src/upgrade_rollback.rs reads what it writes; its test runs this block)
# Lab PR 220: what a rolled-back upgrade leaves for the restored agent, which
# signs it at its boot as one `upgrade_rolled_back` row of the audit chain and
# removes it. One JSON object of strings, control characters dropped, each
# value cut at 200 bytes; written beside the path, then renamed over it.
json_str() {
    printf '"%s"' "$(printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177' | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -b1-200)"
}
write_rollback_marker() {   # <stage> <reason> <failed version> <restored version> <transaction>
    local tmp="$ROLLBACK_MARKER.tmp"
    mkdir -p -m 0700 "$(dirname "$ROLLBACK_MARKER")" && rm -f "$tmp" || return 1
    (umask 077 && printf '{"format":1,"stage":%s,"reason":%s,"failed_version":%s,"restored_version":%s,"txn":%s,"at":%s}\n' \
        "$(json_str "$1")" "$(json_str "$2")" "$(json_str "$3")" "$(json_str "$4")" "$(json_str "$5")" \
        "$(json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" > "$tmp") && mv -fT "$tmp" "$ROLLBACK_MARKER"
}
# <<< rollback_marker

# ── upgrade transaction (rollback.sh carries a copy: txn_write_resume) ──
# Lab PR 220 (static review of baf4c25 P0 C-45 / G-07 / TD-09): `--upgrade`
# stopped the units, dropped the pins and overwrote binaries, units and
# configuration with no copy, no trap and no way back — a failure halfway
# (the binaries replaced and not the units, a new agent that does not start)
# left the host without a working agent. Now, before anything is stopped,
# every file the run may create or replace is copied (cp -a: bytes, mode,
# owner, times, extended attributes) into a transaction directory under
# $UPGRADE_TXN_ROOT, and the ones that do not exist yet are listed; the
# binaries and units are staged next to the installed ones and switched by
# rename(2); and an EXIT trap turns any failure after the stop into a
# rollback: the new units stopped through their own trusted-installer window
# (the same --grant-key), the copies renamed back over the targets, the new
# files removed, the previous units started again and checked, and a marker
# left for the previous agent to sign (`upgrade_rolled_back`). The evidence
# is not rolled back: the audit chain, its head anchor and the chain logs
# keep what the new agent appended. Exit 3: rolled back, the previous version
# runs (or, nothing having run, its files are back); 4: the rollback could not
# finish — the new hooks still protect the files ($TXN_DIR/rollback.sh does
# the rest once nothing protects them), a restored file is not the one backed
# up, or the restored version fails its own health check (no rollback.sh: the
# files are back, the previous units are not healthy).
# Stages: prepared, stop, switch, start, health_check, committed. start_units
# does not fail on a unit that does not start: the health check finds it, so
# such a failure is reported at health_check.
TXN=0
TXN_DIR=""
TXN_T0=""
TXN_PHASE=""        # prepared, stop, switch, start, health_check, committed
TXN_REASON=""
TXN_SUMS=""         # the SHA-256 of every backed-up regular file, kept in memory too
UNITS_TO_RESTART=()
old_ver=unknown
new_ver=unknown
# Every path a run may create or replace, one per line. A file install.sh
# creates only when it is missing (admin.pub and the bootstrap key, the
# COMBAT rulesets and carve-out list) is listed only when it is missing.
txn_targets() {
    local f
    for f in northnarrow-agent northnarrow-watchdog nn-admin northnarrow-scan; do echo "$BIN_DIR/$f"; done
    for f in northnarrow-agent northnarrow-watchdog northnarrow-watchdog-failed; do echo "$UNIT_DIR/$f.service"; done
    echo "$DROPIN_ROOT/northnarrow-agent.service.d/10-debian-perf-paranoid.conf"
    # lab PR 222: the copy-on-first-write drop-in (--cow-guard)
    echo "$DROPIN_ROOT/northnarrow-agent.service.d/20-cow-guard.conf"
    echo "$JOURNALD_NS_CONF"
    echo "$ETC_DIR/install-manifest.json"
    for f in fim-paths netflow-blocklist netflow-ja3-blocklist process-comm-allowlist netflow-comm-allowlist \
             security-tools; do
        echo "$ETC_DIR/$f.v1"
    done
    echo "$ETC_DIR/process-comm-allowlist.local.example"
    for f in "$ETC_DIR/admin.pub" "$ADMIN_KEY_OUT" "$ETC_DIR/combat-rules.v4" "$ETC_DIR/combat-rules.v6" \
             "$ETC_DIR/combat-allow.cidrs"; do
        [[ -e "$f" || -L "$f" ]] || echo "$f"
    done
    # the control-surface files (install_bait) and the canary templates
    for f in agent.dev.lock kill_switch.conf maintenance.mode debug_disable.flag agent.legacy.conf; do
        echo "$ETC_DIR/$f"
    done
    for f in shutdown.signal disable.token override.config; do echo "$STATE_DIR/$f"; done
    for f in pause.flag unload.signal; do echo "$RUN_DIR/$f"; done
    for f in aws azure docker gcp generic; do echo "$ETC_DIR/canary-templates/$f.tmpl"; done
    # the signature `nn-admin config overlay sign` writes when the run adopts an overlay
    for f in "$ETC_DIR/combat-rules.v4" "$ETC_DIR/combat-rules.v6" "$ETC_DIR/combat-allow.cidrs"; do
        echo "$f.sig"
    done
    for f in "$ETC_DIR"/*.local; do
        if [[ -e "$f" ]]; then echo "$f.sig"; fi
    done
    return 0
}
# Copy each existing target under $TXN_DIR/backup and hash it (sums); list
# the missing ones (absent) and the missing directories they would be
# created in (absent-dirs); the edited `.v1` lists already kept as
# `<list>.v1.operator*` (operator-before).
txn_backup() {
    local p d
    : > "$TXN_DIR/absent"
    : > "$TXN_DIR/absent-dirs"
    : > "$TXN_DIR/sums"
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        if [[ -e "$p" || -L "$p" ]]; then
            mkdir -p "$TXN_DIR/backup$(dirname "$p")" && cp -a "$p" "$TXN_DIR/backup$p" || return 1
            if [[ -f "$p" && ! -L "$p" ]]; then sha256sum "$p" >> "$TXN_DIR/sums" || return 1; fi
        else
            echo "$p" >> "$TXN_DIR/absent"
            d=$(dirname "$p")
            if [[ ! -d "$d" ]]; then echo "$d" >> "$TXN_DIR/absent-dirs"; fi
        fi
    done < "$TXN_DIR/targets"
    for p in "$ETC_DIR"/*.v1.operator*; do
        if [[ -e "$p" ]]; then echo "$p"; fi
    done > "$TXN_DIR/operator-before"
}
# Put every target back as the backup holds it — a copy beside it, then
# rename(2) over it, so a target is the old file or the new one and never
# half of either — and remove what the run created. Non-zero when any path
# could not be restored (each one named).
txn_restore() {
    local p bad=0
    # The new agent, when it started, set chattr +i on $STATE_DIR again (as
    # every agent does at boot); stopped, it leaves the flag, and the
    # control-surface files kept there could not be put back (lab, 21/10: a
    # new watchdog that does not start beside a healthy new agent ended in
    # exit 4, "Operation not permitted"). Lifted as the forward path does;
    # the restored agent sets it again at its start.
    if command -v lsattr >/dev/null 2>&1 && lsattr -d "$STATE_DIR" 2>/dev/null | awk '{print $1}' | grep -q i; then
        echo "$NN_SELF: $STATE_DIR is immutable (set by the new agent) — lifting it for the restore" >&2
        chattr -i "$STATE_DIR" || bad=1
    fi
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        rm -f "$p.nn-new"
        [[ -e "$TXN_DIR/backup$p" || -L "$TXN_DIR/backup$p" ]] || continue
        rm -f "$p.nn-rollback"
        if ! { mkdir -p "$(dirname "$p")" && cp -a "$TXN_DIR/backup$p" "$p.nn-rollback" && mv -fT "$p.nn-rollback" "$p"; }; then
            echo "$NN_SELF: could not restore $p from $TXN_DIR/backup$p" >&2
            bad=1
        fi
    done < "$TXN_DIR/targets"
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        if [[ -e "$p" || -L "$p" ]] && ! rm -f "$p"; then
            echo "$NN_SELF: could not remove $p (the upgrade created it)" >&2
            bad=1
        fi
    done < "$TXN_DIR/absent"
    # a copy of an edited list the run kept: the restored list holds the same lines
    for p in "$ETC_DIR"/*.v1.operator*; do
        [[ -e "$p" ]] || continue
        grep -qxF -- "$p" "$TXN_DIR/operator-before" || rm -f "$p" || bad=1
    done
    while IFS= read -r p; do
        [[ -n "$p" ]] && rmdir "$p" 2>/dev/null
    done < <(sort -r "$TXN_DIR/absent-dirs")
    # The bytes now in place are the ones hashed before the stop — against
    # the hashes this run holds in memory (a copy changed under it since is
    # caught); rollback.sh, a later process, has the file only. A restored
    # agent whose files were changed would also fail its own install
    # manifest check at boot.
    if [[ -s "$TXN_DIR/sums" ]] && ! sha256sum -c --quiet --strict <(printf '%s\n' "${TXN_SUMS:-$(cat "$TXN_DIR/sums")}") >&2; then
        echo "$NN_SELF: a restored file is not the one backed up (named above)" >&2
        bad=1
    fi
    return "$bad"
}
txn_begin() {
    local d u
    for d in "$UPGRADE_TXN_ROOT"/*/; do
        if [[ -e "${d}rollback.sh" ]]; then
            echo "install.sh: WARNING: the rollback of an earlier upgrade is still pending: ${d}rollback.sh (its header says" >&2
            echo "install.sh: how to finish it); this run backs up the files as they are now" >&2
        fi
    done
    old_ver=$("$BIN_DIR/northnarrow-agent" --version 2>/dev/null | head -1) || true
    old_ver=${old_ver:-unknown}
    new_ver=$("$AGENT_BIN" --version 2>/dev/null | head -1) || true
    new_ver=${new_ver:-unknown}
    TXN_T0=$(date '+%F %T')
    TXN_DIR="$UPGRADE_TXN_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-$$"
    if ! { install -d -m 0700 -o root -g root "$UPGRADE_TXN_ROOT" && chmod 0700 "$UPGRADE_TXN_ROOT" \
           && install -d -m 0700 -o root -g root "$TXN_DIR" \
           && txn_targets > "$TXN_DIR/targets" && txn_backup && TXN_SUMS=$(cat "$TXN_DIR/sums"); }; then
        echo "install.sh: REFUSED — the installed files could not be backed up into $TXN_DIR (disk space?):" >&2
        echo "install.sh: nothing was changed" >&2
        rm -rf "$TXN_DIR"
        exit 1
    fi
    for u in northnarrow-agent northnarrow-watchdog; do
        if systemctl is-enabled --quiet "$u.service" 2>/dev/null; then echo "$u.service"; fi
    done > "$TXN_DIR/enabled"
    TXN=1
    TXN_PHASE=prepared
    trap txn_on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    echo "install.sh: upgrade transaction $TXN_DIR: $(find "$TXN_DIR/backup" \( -type f -o -type l \) 2>/dev/null | wc -l) installed file(s) backed up, $(grep -c . "$TXN_DIR/absent" || true) to be created"
}
txn_commit() {
    (( TXN )) || return 0
    TXN_PHASE=committed
    trap - EXIT INT TERM HUP
    rm -rf "$TXN_DIR"
}
txn_on_exit() {
    local rc=$?
    set +e
    trap - EXIT
    if (( rc == 0 )) || [[ $TXN_PHASE == committed || $TXN_PHASE == prepared ]]; then
        trap - INT TERM HUP
        # done, or refused before anything was stopped or changed: only the copies go
        rm -rf "$TXN_DIR"
        exit "$rc"
    fi
    # a second Ctrl-C must not leave the restore half done
    trap '' INT TERM HUP
    txn_rollback "$rc"
}
# The new units down, through the new agent's own window: the files are
# its protected inodes until its hooks are gone.
txn_take_down_new() {
    local ids u
    ids=$(read_own_prog_ids)
    if systemctl is-active --quiet northnarrow-agent.service; then
        open_trusted_installer_window "$GRANT_KEY" || return 1
    elif [[ -d "$BPFFS_ROOT" ]]; then
        rm -rf "$BPFFS_ROOT" 2>/dev/null || true
        if [[ -d "$BPFFS_ROOT" ]]; then
            # its pins outlive it (DEP-020): the installed (new) agent once more, for its window
            if ! { start_agent_for_window && open_trusted_installer_window "$GRANT_KEY"; }; then
                return 1
            fi
            ids=$(read_own_prog_ids)
        fi
    fi
    for u in northnarrow-watchdog northnarrow-agent; do
        if nn_unit_has_procs "$u"; then
            echo "install.sh: stopping the new $u"
            stop_nn_unit "$u"
        fi
    done
    purge_pin_root || return 1
    wait_own_programs_unloaded "$ids" || return 1
    ! nn_unit_has_procs northnarrow-agent && ! nn_unit_has_procs northnarrow-watchdog
}
# A pending rollback: this file's functions and the transaction's values in
# $TXN_DIR/rollback.sh, to run once nothing protects the files any more —
# both units disabled and the host rebooted (bpffs does not survive it).
txn_write_resume() {   # <stage> <reason>
    local f="$TXN_DIR/rollback.sh"
    printf '%s\n' ${UNITS_TO_RESTART[@]+"${UNITS_TO_RESTART[@]}"} > "$TXN_DIR/units"
    {
        echo '#!/usr/bin/env bash'
        echo "# install.sh, $(date -u +%Y-%m-%dT%H:%M:%SZ): the upgrade $old_ver -> $new_ver failed ($1)"
        echo "# and its rollback could not finish. Once neither NorthNarrow unit runs and $BPFFS_ROOT is gone:"
        echo "#   systemctl disable northnarrow-agent northnarrow-watchdog; reboot; sudo bash $f"
        echo "# It restores the previous files, enables and starts the previous units and checks them."
        echo 'set -uo pipefail'
        declare -p TXN_DIR BIN_DIR UNIT_DIR ETC_DIR RUN_DIR STATE_DIR BPFFS_ROOT ADMIN_SOCKET ROLLBACK_MARKER HEALTH_TIMEOUT NN_TS_RE NN_SELF
        declare -f txn_restore json_str write_rollback_marker unit_main_pid own_events agent_deny_hooks \
            watchdog_registered health_once upgrade_health_check nn_rollback_resume
        printf 'nn_rollback_resume %q %q %q %q\n' "$1" "$2" "$new_ver" "$old_ver"
    } > "$f" && chmod 0700 "$f"
}
nn_rollback_resume() {   # (rollback.sh) <stage> <reason> <failed version> <restored version>
    local u
    local -a units=()
    if [[ $EUID != 0 ]]; then
        echo "rollback.sh: must run as root" >&2
        return 1
    fi
    for u in northnarrow-agent northnarrow-watchdog; do
        if systemctl is-active --quiet "$u.service"; then
            echo "rollback.sh: $u is running and its hooks protect the files: systemctl disable" >&2
            echo "rollback.sh: northnarrow-agent northnarrow-watchdog, reboot, then run this again" >&2
            return 1
        fi
    done
    if [[ -d "$BPFFS_ROOT" ]]; then
        echo "rollback.sh: $BPFFS_ROOT is still there (pinned hooks): disable both units, reboot, run this again" >&2
        return 1
    fi
    if ! txn_restore; then
        echo "rollback.sh: some files could not be restored (above); $TXN_DIR keeps the copies" >&2
        return 1
    fi
    systemctl daemon-reload
    while IFS= read -r u; do
        if [[ -n "$u" ]]; then systemctl enable "$u"; fi
    done < "$TXN_DIR/enabled"
    mapfile -t units < "$TXN_DIR/units"
    if (( ${#units[@]} )); then
        write_rollback_marker "$1" "$2" "$3" "$4" "$(basename "$TXN_DIR")" || echo "rollback.sh: WARNING: $ROLLBACK_MARKER not written" >&2
        for u in northnarrow-agent northnarrow-watchdog; do
            if grep -qx "$u" "$TXN_DIR/units"; then
                echo "rollback.sh: starting $u"
                systemctl start "$u.service"
                if [[ $u == northnarrow-agent ]]; then sleep 3; fi
            fi
        done
        if ! upgrade_health_check "${units[@]}"; then
            echo "rollback.sh: the previous version ($4) is back but does not pass the health check: $HEALTH_FAILURE" >&2
            return 1
        fi
    fi
    echo "rollback.sh: rolled back to $4${units[*]:+ (${units[*]} healthy)}; remove $TXN_DIR"
}
txn_stuck() {   # <stage> <reason> <why>
    local st
    txn_write_resume "$1" "$2"
    st="northnarrow-agent $(systemctl is-active northnarrow-agent.service 2>/dev/null), northnarrow-watchdog $(systemctl is-active northnarrow-watchdog.service 2>/dev/null)"
    echo "" >&2
    echo "install.sh: ROLLBACK INCOMPLETE — $3." >&2
    echo "install.sh: the upgrade $old_ver -> $new_ver failed ($1: $2), and the previous files are not all" >&2
    echo "install.sh: back ($st): this host may be without a working NorthNarrow agent. To finish:" >&2
    echo "install.sh:   systemctl disable northnarrow-agent northnarrow-watchdog; reboot (bpffs does not survive it);" >&2
    echo "install.sh:   sudo bash $TXN_DIR/rollback.sh — it restores the previous files from $TXN_DIR," >&2
    echo "install.sh:   enables and starts the previous units and checks them" >&2
    echo "install.sh: (docs/operator/INSTALL_UPGRADE_UNINSTALL.md §2)." >&2
    logger -p auth.crit -t northnarrow-install -- "upgrade rollback incomplete ($3): disable both units, reboot, run $TXN_DIR/rollback.sh" 2>/dev/null || true
    exit 4
}
txn_rollback() {   # <exit status of the failure>
    local stage=$TXN_PHASE reason=${TXN_REASON:-"a step failed (exit status $1; its message is above)"}
    local n_restored n_removed audit_before=0 agent_was_up=0 record
    echo "" >&2
    echo "install.sh: UPGRADE FAILED — $stage: $reason" >&2
    echo "install.sh: rolling back to $old_ver from $TXN_DIR" >&2
    logger -p auth.err -t northnarrow-install -- "upgrade $old_ver -> $new_ver failed ($stage: $reason): rolling back" 2>/dev/null || true
    case $stage in
        start|health_check)
            txn_take_down_new || txn_stuck "$stage" "$reason" "the new agent's hooks still protect the files and its window could not be opened"
            ;;
    esac
    txn_restore || txn_stuck "$stage" "$reason" "some files could not be restored (named above)"
    n_restored=$(find "$TXN_DIR/backup" \( -type f -o -type l \) 2>/dev/null | wc -l)
    n_removed=$(grep -c . "$TXN_DIR/absent")
    systemctl daemon-reload
    systemctl restart systemd-journald@northnarrow.service 2>/dev/null
    echo "install.sh: restored $n_restored file(s) byte for byte; the $n_removed the upgrade would have created are gone"
    record="none: nothing was running before the upgrade, nothing was started"
    if (( ${#UNITS_TO_RESTART[@]} )); then
        if systemctl is-active --quiet northnarrow-agent.service; then agent_was_up=1; fi
        audit_before=$(wc -l < "$ETC_DIR/audit.log" 2>/dev/null) || audit_before=0
        if (( ! agent_was_up )); then
            write_rollback_marker "$stage" "$reason" "$new_ver" "$old_ver" "$(basename "$TXN_DIR")" ||
                echo "install.sh: WARNING: $ROLLBACK_MARKER not written: the restored agent has nothing to sign" >&2
        fi
        start_units "${UNITS_TO_RESTART[@]}"
        if ! upgrade_health_check "${UNITS_TO_RESTART[@]}"; then
            echo "" >&2
            echo "install.sh: ROLLBACK INCOMPLETE — the previous files are back, but $old_ver does not pass the health" >&2
            echo "install.sh: check: $HEALTH_FAILURE. This host may be without a working NorthNarrow agent: find the" >&2
            echo "install.sh: cause (systemctl status northnarrow-agent; journalctl --namespace=northnarrow -u" >&2
            echo "install.sh: northnarrow-agent --since \"$TXN_T0\"). The copies stay in $TXN_DIR." >&2
            logger -p auth.crit -t northnarrow-install -- "upgrade rolled back, but $old_ver does not pass the health check: $HEALTH_FAILURE" 2>/dev/null || true
            exit 4
        fi
        if (( agent_was_up )); then
            record="none: the previous agent never stopped (the stop did not complete); it signs the marker only at a boot"
        elif tail -n "+$((audit_before + 1))" "$ETC_DIR/audit.log" 2>/dev/null | grep -q '"op": *"upgrade_rolled_back"'; then
            record="upgrade_rolled_back, signed by the restored agent in $ETC_DIR/audit.log"
        else
            rm -f "$ROLLBACK_MARKER"
            record="none: the restored agent does not read $ROLLBACK_MARKER (older than lab PR 220); this message and the system log line are the record"
        fi
    fi
    rm -rf "$TXN_DIR"
    echo "" >&2
    echo "install.sh: UPGRADE ROLLED BACK — $new_ver failed ($stage: $reason)." >&2
    if (( ${#UNITS_TO_RESTART[@]} )); then
        echo "install.sh:   running again: $old_ver (${UNITS_TO_RESTART[*]}: health check passed)" >&2
        if [[ -n "$HEALTH_NOTE" ]]; then echo "install.sh:   WARNING: $HEALTH_NOTE" >&2; fi
    else
        echo "install.sh:   the previous files are back: $old_ver" >&2
    fi
    echo "install.sh:   signed record: $record" >&2
    echo "install.sh:   kept: what the new agent appended to the audit chain and the chain logs (nn-admin audit verify)" >&2
    echo "install.sh:   what failed: journalctl --namespace=northnarrow -u northnarrow-agent -u northnarrow-watchdog --since \"$TXN_T0\"" >&2
    logger -p auth.err -t northnarrow-install -- "upgrade $old_ver -> $new_ver rolled back ($stage: $reason); signed record: ${record%%:*}" 2>/dev/null || true
    exit 3
}
# Agent first (it pins the maps the watchdog registers into), then the
# watchdog — the same order the operator uses on a fresh install. A start
# that fails is named; the health check says what it left.
start_units() {   # <unit>...
    local u w
    for u in northnarrow-agent northnarrow-watchdog; do
        for w in "$@"; do
            [[ "$w" == "$u" ]] || continue
            echo "install.sh: starting $u"
            systemctl start "$u.service" || echo "install.sh: systemctl start $u.service failed" >&2
            if [[ "$u" == northnarrow-agent ]]; then sleep 3; fi
        done
    done
    return 0
}

require_root
if [[ $MODE == verify ]]; then
    # Lab PR 220: the rpm %posttrans, after the whole transaction (the old
    # package's scriptlets included): the health of the units the configure
    # step restarted, listed in the restart list it kept for this check.
    # Nothing to check on a first install (nothing was restarted).
    [[ -s "$PKG_RESTART_FILE" ]] || exit 0
    mapfile -t UNITS_TO_RESTART < "$PKG_RESTART_FILE"
    pkg_health_or_fail "${UNITS_TO_RESTART[@]}" || exit 1
    exit 0
fi
if [[ $MODE != full ]]; then
    # External audit DEP-008: no check here can tell where the package came
    # from — these are the package's own scripts, and a swapped package
    # brings its own. The origin is checked before the package command:
    # dnf/yum with gpgcheck=1 or `rpm -K` (the .rpm is signed), the
    # tag-bound attestation for the .deb.
    PROVENANCE="package"
    if [[ $MODE == configure ]]; then
        echo "install.sh: package install — the package's origin is not verified by install.sh; check it before installing (rpm: signature, deb: attestation; docs/operator/INSTALL_UPGRADE_UNINSTALL.md §6.1)"
    fi
else
verify_release
require_provenance_floor
require_file "$AGENT_BIN"    "run \`cargo xtask build --release\` first (xtask builds the eBPF object + userland atomically; a plain \`cargo build\` cannot produce an installable agent — agent/build.rs refuses a stale/unstamped eBPF object)"
require_file "$WATCHDOG_BIN" "run \`cargo xtask build --release\` first (or \`cargo build --release -p northnarrow-watchdog\`)"
require_file "$NN_ADMIN_BIN" "run \`cargo xtask build --release\` first (or \`cargo build --release -p northnarrow-agent --bin nn-admin\`)"
require_file "$SCAN_BIN"     "run \`cargo xtask build --release\` first (or \`cargo build --release -p northnarrow-scan\`)"
# Refuse a stale agent binary BEFORE we touch the live system.
require_fresh_ebpf
fi
# --package-stop runs from the package's pre-unpack hook, before any file of
# the new package exists (on a first install not even the data tree): it
# needs nothing but the installed nn-admin, so it skips the tree checks.
if [[ $MODE != stop ]]; then
require_file "$AGENT_UNIT_SRC"    "expected at $AGENT_UNIT_SRC (this script's sibling deploy/systemd/)"
require_file "$WATCHDOG_UNIT_SRC" "expected at $WATCHDOG_UNIT_SRC"
require_file "$WATCHDOG_FAILED_UNIT_SRC" "expected at $WATCHDOG_FAILED_UNIT_SRC (lab PR 216: the watchdog's OnFailure= handler)"
require_file "$JOURNALD_NS_CONF_SRC" "expected at $JOURNALD_NS_CONF_SRC (NN journal-namespace cap; the LogNamespace=northnarrow journald config)"
require_file "$FIM_PATHS_V1_SRC"  "expected at $FIM_PATHS_V1_SRC (Tappa 9 C7 default FIM watched-paths list)"
require_file "$NETFLOW_BLOCKLIST_V1_SRC"     "expected at $NETFLOW_BLOCKLIST_V1_SRC (Tappa 10 N8 default NetFlow IP/CIDR blocklist)"
require_file "$NETFLOW_JA3_BLOCKLIST_V1_SRC" "expected at $NETFLOW_JA3_BLOCKLIST_V1_SRC (Tappa 10 N8 default NetFlow JA3 blocklist)"
require_file "$PROCESS_COMM_ALLOWLIST_V1_SRC" "expected at $PROCESS_COMM_ALLOWLIST_V1_SRC (Tappa 10.5 D1 default process comm allowlist)"
require_file "$NETFLOW_COMM_ALLOWLIST_V1_SRC" "expected at $NETFLOW_COMM_ALLOWLIST_V1_SRC (Tappa 10.5 D1 default NetFlow comm allowlist)"

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
# Before anything on the host changes, a running install's stop included.
require_nft
fi

# Lab PR 220: replacing an install is a transaction ("upgrade transaction" above):
# the copies are taken now, before anything is stopped or changed.
if [[ $MODE == full ]] && [[ -e "$BIN_DIR/northnarrow-agent" || -e "$UNIT_DIR/northnarrow-agent.service" ]]; then
    txn_begin
fi

# ── install ─────────────────────────────────────────────────────────
# ── running install? ──────────────────────────────────────────────────
# A unit counts as "running" in ANY state but inactive: `activating`
# (the watchdog restart loop after a failed agent boot) and `failed`
# still own or re-create the LSM pins, and an agent respawned mid-copy
# re-protects /usr/local/bin — the first verified-upgrade test hit
# exactly that (`install: cannot remove '/usr/local/bin/northnarrow-agent':
# Operation not permitted`). Those units are stopped, reset and, after
# the upgrade, restarted like active ones.

# ── pin root purge under the anti-tamper (review entry 39) ─────────────────
# /sys/fs/bpf/northnarrow holds the pinned maps, LSM programs and links; the
# running agent registers it in its protected-inode set, so `rm -rf` by root
# is denied unless a trusted-installer window is open. The window is opened
# through the agent's admin socket with a key carrying the `trusted-installer`
# role (the key install.sh bootstraps has it) and survives the agent's stop
# long enough for the purge (the override lives in a pinned map).
# External audit EBPF-001: the units refuse a manual stop
# (RefuseManualStop=yes) and their processes take systemd's signals only
# inside the trusted-installer window: stop by signal, SIGTERM first (the
# agent writes agent_stop), SIGKILL only if a process outlives 10 s.
stop_nn_unit() {
    local u=$1 i
    systemctl kill --signal=SIGTERM "$u.service" 2>/dev/null || true
    for ((i = 0; i < 20; i++)); do
        nn_unit_has_procs "$u" || break
        sleep 0.5
    done
    if nn_unit_has_procs "$u"; then
        systemctl kill --signal=SIGKILL "$u.service" 2>/dev/null || true
        sleep 1
    fi
    systemctl reset-failed "$u.service" 2>/dev/null || true
}
nn_unit_has_procs() {
    local cg
    cg=$(systemctl show -p ControlGroup --value "$1.service" 2>/dev/null)
    cg=${cg:-/system.slice/$1.service}
    [[ -n "$(cat "/sys/fs/cgroup$cg/cgroup.procs" 2>/dev/null)" ]]
}

# External audit DEP-006: the drain gate used to wait for "no LSM program on
# the host", a count that includes every other product's BPF-LSM programs
# (Cilium, Tetragon, another EDR): on such a host it never reached 0 and the
# upgrade aborted with the units already stopped. The agent now lists the ids
# of its own loaded programs in $OWN_IDS_FILE (anti_tamper/bpf_defense.rs,
# next to its pid file); they are read before the stop and waited for one by
# one. The ids come from the agent, not from the pins: in enforce mode a
# foreign handle on a pinned link is refused.
OWN_IDS_FILE=${OWN_IDS_FILE:-/run/northnarrow/bpf-own-ids}
LSM_DRAIN_TIMEOUT=${LSM_DRAIN_TIMEOUT:-30}
# Numeric first fields only: the list goes to bpftool as arguments.
read_own_prog_ids() {
    [[ -r "$OWN_IDS_FILE" ]] || return 0
    awk '$1 ~ /^[0-9]+$/ {print $1}' "$OWN_IDS_FILE" | sort -un | tr '\n' ' '
}
# The ids among $1 still loaded. Only "No such file or directory" counts as
# unloaded; any other bpftool error keeps the id on the list.
own_progs_loaded() {
    local id out left=()
    for id in $1; do
        if out=$(LC_ALL=C bpftool prog show id "$id" 2>&1); then
            left+=("$id")
        elif [[ "$out" != *"No such file or directory"* ]]; then
            left+=("$id")
        fi
    done
    echo "${left[*]:-}"
}
# Wait until NorthNarrow's programs are gone: the ids in $1, or — for an
# agent that predates the list — every LSM program on the host, as before,
# naming what is left. Without bpftool: the units' processes and the pin root
# are the only holders; both are checked, and the unload itself is not.
wait_own_programs_unloaded() {
    local ids=$1 i left=$1 n=0
    if ! command -v bpftool >/dev/null 2>&1; then
        for ((i = 0; i < LSM_DRAIN_TIMEOUT; i++)); do
            nn_unit_has_procs northnarrow-agent || nn_unit_has_procs northnarrow-watchdog || break
            sleep 1
        done
        if nn_unit_has_procs northnarrow-agent || nn_unit_has_procs northnarrow-watchdog \
           || [[ -d "$BPFFS_ROOT" ]]; then
            echo "install.sh: a NorthNarrow unit still has processes, or the pin root is still there — stop them and re-run" >&2
            return 1
        fi
        echo "install.sh: bpftool not found — the agent and watchdog exited and the pin root is gone (the only holders"
        echo "install.sh: of the LSM programs); the unload itself cannot be confirmed"
        return 0
    fi
    if [[ -n "$ids" ]]; then
        echo "install.sh: waiting for NorthNarrow's BPF programs to unload (ids: $ids)"
        for ((i = 0; i < LSM_DRAIN_TIMEOUT; i++)); do
            left=$(own_progs_loaded "$ids")
            [[ -z "$left" ]] && return 0
            sleep 1
        done
        echo "install.sh: NorthNarrow BPF program(s) still loaded after ${LSM_DRAIN_TIMEOUT}s: ids $left" >&2
        echo "install.sh: (bpftool prog show id <id>) — another NorthNarrow process holds them; stop it and re-run" >&2
        return 1
    fi
    echo "install.sh: no $OWN_IDS_FILE (an agent older than the list) — waiting for every LSM program on the host to detach"
    for ((i = 0; i < LSM_DRAIN_TIMEOUT; i++)); do
        n=$(bpftool prog show 2>/dev/null | grep -c " lsm " || true)
        [[ "$n" == 0 ]] && return 0
        (( i == 0 )) && echo "install.sh: waiting for $n LSM program(s) to detach"
        sleep 1
    done
    echo "install.sh: $n LSM program(s) still loaded after ${LSM_DRAIN_TIMEOUT}s:" >&2
    bpftool prog show 2>/dev/null | grep " lsm " | sed 's/^/install.sh:   /' >&2
    echo "install.sh: if they are NorthNarrow's, another NorthNarrow process holds them: stop it and re-run" >&2
    return 1
}

open_trusted_installer_window() {
    local key=$1
    [[ -r "$key" ]] || { echo "install.sh: --grant-key $key is not readable" >&2; return 1; }
    if ! systemctl is-active --quiet northnarrow-agent.service; then
        echo "install.sh: the agent is not running — the trusted-installer window can only be opened" >&2
        echo "install.sh: through its socket. Start it (systemctl start northnarrow-agent) and re-run." >&2
        return 1
    fi
    echo "install.sh: opening the trusted-installer window (300 s) with $key"
    if ! "$BIN_DIR/nn-admin" trusted-installer-grant --key "$key" --window-secs 300; then
        echo "install.sh: trusted-installer grant REFUSED — the key needs the trusted-installer role on its" >&2
        echo "install.sh: admin.pub line (docs/operator/COMBAT_RECOVERY.md section 1.1)." >&2
        return 1
    fi
}
purge_pin_root() {
    [[ -d "$BPFFS_ROOT" ]] || return 0
    echo "install.sh: dropping $BPFFS_ROOT so the LSM programs detach (the new agent re-pins fresh)"
    rm -rf "$BPFFS_ROOT" 2>/dev/null || true
    if [[ -d "$BPFFS_ROOT" ]]; then
        echo "install.sh: $BPFFS_ROOT is PROTECTED by the anti-tamper and no trusted-installer window" >&2
        echo "install.sh: is open (review entry 39). Re-run with --grant-key <admin.key carrying the trusted-installer" >&2
        echo "install.sh: role> (a stopped agent is started for the window), or open the window yourself while the" >&2
        echo "install.sh: agent runs: nn-admin trusted-installer-grant --key <key> --window-secs 300" >&2
        return 1
    fi
}

NN_SELF=install.sh
# >>> stale_pin_root (the same text in install.sh and uninstall.sh; xtask/tests/install_scripts.rs keeps them equal)
# External audit DEP-020 (NN-AUD-440): both units inactive and the pin root
# of an agent that is gone still there. Its deny hooks outlive it on purpose,
# so the pin root, the binaries and the units stay protected, and the
# trusted-installer window opens only through a running agent's socket: the
# branch meant for this case asked for an active agent, never true there,
# and --grant-key was ignored. With the key, the installed agent is started
# (its unit only; the watchdog stays as it was) until its admin socket is
# up; the caller opens the window, stops it again and does not restart it.
ADMIN_SOCKET=${ADMIN_SOCKET:-/run/northnarrow/admin.sock}
ADMIN_SOCKET_WAIT=${ADMIN_SOCKET_WAIT:-30}
stale_pin_root_help() {
    echo "$NN_SELF: the pin root of a stopped agent is PROTECTED by its hooks, and the trusted-installer window"
    echo "$NN_SELF: opens only through a running agent. Either:"
    echo "$NN_SELF:   - re-run with --grant-key <admin key carrying the trusted-installer role>: the installed"
    echo "$NN_SELF:     agent is started for the window, then stopped again; or"
    echo "$NN_SELF:   - systemctl disable northnarrow-agent northnarrow-watchdog, reboot (bpffs does not survive"
    echo "$NN_SELF:     a reboot), re-run, then enable the units again."
}
start_agent_for_window() {
    local i
    echo "$NN_SELF: starting the installed agent (its unit only) to open the trusted-installer window"
    if ! systemctl start northnarrow-agent.service; then
        echo "$NN_SELF: the installed agent did not start (systemctl status northnarrow-agent.service)." >&2
        stale_pin_root_help >&2
        return 1
    fi
    for ((i = 0; i < ADMIN_SOCKET_WAIT; i++)); do
        [[ -S "$ADMIN_SOCKET" ]] && return 0
        sleep 1
    done
    echo "$NN_SELF: the agent started but $ADMIN_SOCKET did not appear within ${ADMIN_SOCKET_WAIT}s;" >&2
    echo "$NN_SELF: it keeps running — re-run once nn-admin status answers." >&2
    return 1
}
# <<< stale_pin_root

UNITS_TO_RESTART=()
if [[ $MODE == configure ]]; then
    # The package's pre-unpack hook already stopped the units and dropped
    # the pins; it left the list of units to start again.
    if [[ -s "$PKG_RESTART_FILE" ]]; then
        mapfile -t UNITS_TO_RESTART < "$PKG_RESTART_FILE"
        UPGRADE=1
    fi
else
for u in northnarrow-watchdog northnarrow-agent; do
    state=$(systemctl is-active "$u.service" 2>/dev/null || true)
    if [[ -n "$state" && "$state" != inactive ]]; then
        UNITS_TO_RESTART+=("$u")
    fi
done
if [[ $MODE == stop ]]; then
    # Written before anything is stopped: if a later step fails, the
    # package's abort hook still knows what to start again.
    rm -f "$PKG_RESTART_FILE"
    if (( ${#UNITS_TO_RESTART[@]} )); then
        printf '%s\n' "${UNITS_TO_RESTART[@]}" > "$PKG_RESTART_FILE"
        UPGRADE=1
    fi
fi
# Units inactive but the previous install's hooks still pinned: they deny
# the copy below. A pin root nothing protects any more (or an open window)
# is removed here; a protected one needs the window, hence a running agent
# (external audit DEP-020, the stale_pin_root block above). The agent
# started for it is stopped on the path below and stays out of
# UNITS_TO_RESTART (and of the package's restart list): the units end as
# they were.
STARTED_FOR_WINDOW=0
if (( ! ${#UNITS_TO_RESTART[@]} )) && [[ -d "$BPFFS_ROOT" ]]; then
    echo "install.sh: units inactive but $BPFFS_ROOT exists — purging the stale pins first"
    rm -rf "$BPFFS_ROOT" 2>/dev/null || true
    if [[ -d "$BPFFS_ROOT" ]]; then
        if [[ -z "$GRANT_KEY" ]]; then
            stale_pin_root_help >&2
            exit 1
        fi
        [[ -r "$GRANT_KEY" ]] || { echo "install.sh: --grant-key $GRANT_KEY is not readable" >&2; exit 1; }
        start_agent_for_window || exit 1
        STARTED_FOR_WINDOW=1
    fi
fi
if (( ${#UNITS_TO_RESTART[@]} || STARTED_FOR_WINDOW )); then
    if (( ! UPGRADE && ! STARTED_FOR_WINDOW )); then
        echo "install.sh: NorthNarrow is RUNNING (${UNITS_TO_RESTART[*]}) — with the anti-tamper hooks" >&2
        echo "install.sh: active every write below is denied. Re-run with --upgrade to stop, replace and" >&2
        echo "install.sh: restart the units in the right order (keys, audit chain and state are kept)." >&2
        exit 1
    fi
    # Lab PR 220: the upgrade must be able to roll back, and once the new
    # agent runs only its own window (opened with the key) lets the rollback
    # stop it and put the previous files back. A window opened by hand before
    # the run covers the stop, not that.
    if [[ $MODE == full ]] && (( ${#UNITS_TO_RESTART[@]} )) && [[ -z "$GRANT_KEY" ]]; then
        echo "install.sh: REFUSED — --upgrade needs --grant-key <admin key with the trusted-installer role>: its" >&2
        echo "install.sh: window stops the running units, and a rollback needs the new agent's window too." >&2
        echo "install.sh: Nothing was changed." >&2
        exit 1
    fi
    old_ver=$("$BIN_DIR/northnarrow-agent" --version 2>/dev/null | head -1 || echo "unknown")
    if (( STARTED_FOR_WINDOW )); then
        echo "install.sh: $old_ver started only for the window — stopped again below, not restarted"
    elif [[ $MODE == full ]]; then
        new_ver=$("$AGENT_BIN" --version 2>/dev/null | head -1 || echo "unknown")
        echo "install.sh: UPGRADE — installed: $old_ver → new: $new_ver"
    else
        echo "install.sh: stopping $old_ver for the package manager"
    fi
    # The pin root is in the agent's protected-inode set (review entry 39):
    # only a protected pid or an open trusted-installer window may remove it.
    # Open the window now, while the agent still answers on its socket.
    if [[ -n "$GRANT_KEY" ]]; then
        if ! open_trusted_installer_window "$GRANT_KEY"; then
            (( STARTED_FOR_WINDOW )) &&
                echo "install.sh: the agent started for the window keeps running (its stop needs the window)" >&2
            exit 1
        fi
    fi
    # External audit DEP-006: the ids of the running agent's programs,
    # read while it still runs.
    own_ids=$(read_own_prog_ids)
    # Lab PR 220: from here on a failure rolls back (txn_on_exit).
    TXN_PHASE=stop
    # Watchdog first: stopping the agent alone makes it respawn it.
    for u in northnarrow-watchdog northnarrow-agent; do
        echo "install.sh: stopping $u ($(systemctl is-active "$u.service" 2>/dev/null | tr -d '\n'))"
        stop_nn_unit "$u"
    done
    # A unit the stop did not reach (no window: the signals are refused)
    # still holds its hooks: stop here, before its pin root goes.
    for u in northnarrow-watchdog northnarrow-agent; do
        if nn_unit_has_procs "$u"; then
            TXN_REASON="$u did not stop"
            echo "install.sh: $u still runs after the stop (its signals need the trusted-installer window)" >&2
            exit 1
        fi
    done
    purge_pin_root || { TXN_REASON="the pin root could not be removed"; exit 1; }
    wait_own_programs_unloaded "$own_ids" || { TXN_REASON="the previous BPF programs did not unload"; exit 1; }
fi
fi

if [[ $MODE == stop ]]; then
    # $PKG_RESTART_FILE hands the list to --package-configure, or to the
    # abort hook that restarts the old version if the operation fails.
    echo "install.sh: units stopped and pins dropped for the package manager${UNITS_TO_RESTART[*]:+ (to restart: ${UNITS_TO_RESTART[*]})}"
    exit 0
fi

if [[ $MODE == configure ]]; then
    # Migration from the install.sh layout: its units in /etc/systemd/system
    # would shadow the package's (review 51) and run the old binaries. The
    # pins were dropped before unpack, so nothing protects them now.
    if [[ "$BIN_DIR" != /usr/local/bin ]]; then
        was_enabled=()
        for u in northnarrow-agent northnarrow-watchdog; do
            if [[ -e "/etc/systemd/system/$u.service" ]] && systemctl is-enabled --quiet "$u.service" 2>/dev/null; then
                was_enabled+=("$u.service")
            fi
        done
        for f in /usr/local/bin/northnarrow-agent /usr/local/bin/northnarrow-watchdog /usr/local/bin/nn-admin \
                 /usr/local/bin/northnarrow-scan \
                 /etc/systemd/system/northnarrow-agent.service /etc/systemd/system/northnarrow-watchdog.service \
                 /etc/systemd/system/northnarrow-watchdog-failed.service; do
            [[ -e "$f" ]] && { echo "install.sh: removing $f (install.sh layout, replaced by the package)"; rm -f "$f"; }
        done
        if (( ${#was_enabled[@]} )); then
            # the old enablement links named the removed files: re-create them
            systemctl daemon-reload
            systemctl enable "${was_enabled[@]}" 2>/dev/null || true
            echo "install.sh: kept enabled: ${was_enabled[*]}"
        fi
    fi
else
TXN_PHASE=switch
# Lab PR 220: staged next to the installed files (same directory, same file
# system), checked, then switched by rename(2): each path is the old file or
# the new one, never a half-written copy, and binaries and units change
# together.
echo "install.sh: staging binaries in $BIN_DIR/ and systemd unit files in $UNIT_DIR/"
install -m 755 -o root -g root "$AGENT_BIN"    "$BIN_DIR/northnarrow-agent.nn-new"
install -m 755 -o root -g root "$WATCHDOG_BIN" "$BIN_DIR/northnarrow-watchdog.nn-new"
install -m 755 -o root -g root "$NN_ADMIN_BIN" "$BIN_DIR/nn-admin.nn-new"
install -m 755 -o root -g root "$SCAN_BIN"     "$BIN_DIR/northnarrow-scan.nn-new"
# Review 26: the shipped units name /usr/local/bin. With another BIN_DIR
# (a package layout uses /usr/bin) their ExecStart and the watchdog's
# --agent-bin must point at the binaries that were actually installed.
install_unit() {
    local src=$1 dst=$2 tmp
    if [[ "$BIN_DIR" == /usr/local/bin ]]; then
        install -m 644 -o root -g root "$src" "$dst"
        return
    fi
    tmp=$(mktemp)
    sed "s#/usr/local/bin/#${BIN_DIR%/}/#g" "$src" > "$tmp"
    install -m 644 -o root -g root "$tmp" "$dst"
    rm -f "$tmp"
}
install_unit "$AGENT_UNIT_SRC"    "$UNIT_DIR/northnarrow-agent.service.nn-new"
install_unit "$WATCHDOG_UNIT_SRC" "$UNIT_DIR/northnarrow-watchdog.service.nn-new"
install_unit "$WATCHDOG_FAILED_UNIT_SRC" "$UNIT_DIR/northnarrow-watchdog-failed.service.nn-new"
for staged in "$AGENT_BIN:northnarrow-agent" "$WATCHDOG_BIN:northnarrow-watchdog" "$NN_ADMIN_BIN:nn-admin" \
              "$SCAN_BIN:northnarrow-scan"; do
    if ! cmp -s "${staged%%:*}" "$BIN_DIR/${staged#*:}.nn-new"; then
        TXN_REASON="the staged $BIN_DIR/${staged#*:}.nn-new differs from ${staged%%:*}"
        echo "install.sh: $TXN_REASON" >&2
        exit 1
    fi
done
echo "install.sh: switching binaries and units (rename)"
for f in "$BIN_DIR/northnarrow-agent" "$BIN_DIR/northnarrow-watchdog" "$BIN_DIR/nn-admin" \
         "$BIN_DIR/northnarrow-scan" "$UNIT_DIR/northnarrow-agent.service" "$UNIT_DIR/northnarrow-watchdog.service" \
         "$UNIT_DIR/northnarrow-watchdog-failed.service"; do
    mv -fT "$f.nn-new" "$f"
done
fi

# Lab PR 223 (EXPERIMENTAL exec quarantine): the account the agent drops
# its scanner to — a system user with its own group, no home, no shell,
# never root. It costs nothing while the guard is off; without it the guard
# refuses to start (a signed degradation), the agent itself runs.
# >>> scan_user
ensure_scan_user() {
    if getent passwd "$SCAN_USER" >/dev/null; then
        return 0
    fi
    local nologin=/usr/sbin/nologin
    [[ -x $nologin ]] || nologin=/sbin/nologin
    if ! command -v useradd >/dev/null 2>&1; then
        echo "install.sh: WARNING: useradd not found — no $SCAN_USER account; the exec quarantine cannot start its scanner" >&2
        return 0
    fi
    if useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell "$nologin" --comment "NorthNarrow exec quarantine scanner" "$SCAN_USER"; then
        echo "install.sh: created the system account $SCAN_USER (exec quarantine scanner)"
    else
        echo "install.sh: WARNING: could not create $SCAN_USER — the exec quarantine cannot start its scanner" >&2
    fi
}
# <<< scan_user
ensure_scan_user

# Debian-family kernels carry a distro patch that makes
# kernel.perf_event_paranoid=3 (their default) require CAP_SYS_ADMIN for
# perf_event_open — CAP_PERFMON, which is all upstream (and Ubuntu's own
# patch) ask for, is refused with EACCES. Every tracepoint and kprobe
# attach goes through perf_event_open, so under the bounded unit the agent
# cannot start there. Widen the bounding set ONLY on those hosts, via a
# drop-in that the operator can see and remove (e.g. after setting
# kernel.perf_event_paranoid=2 system-wide, which also restores the
# narrower set). See docs/operator/KERNEL_COMPATIBILITY.md.
DROPIN_DIR="$DROPIN_ROOT/northnarrow-agent.service.d"
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_id=${ID:-}; os_like=${ID_LIKE:-}
else
    os_id=""; os_like=""
fi
if [[ "$os_id" == debian || ( "$os_like" == *debian* && "$os_id" != ubuntu && "$os_like" != *ubuntu* ) ]]; then
    echo "install.sh: Debian-family kernel ($os_id) — adding CAP_SYS_ADMIN drop-in for perf_event_paranoid=3 semantics"
    install -d -m 0755 -o root -g root "$DROPIN_DIR"
    # External audit DEP-002: the agent compares the drop-in with this
    # file (self-integrity) and protects it: install it, do not edit it.
    install -m 0644 -o root -g root "$REPO_ROOT/deploy/systemd/10-debian-perf-paranoid.conf" \
        "$DROPIN_DIR/10-debian-perf-paranoid.conf"
elif [[ -e "$DROPIN_DIR/10-debian-perf-paranoid.conf" ]]; then
    echo "install.sh: removing stale Debian perf drop-in (not a Debian-family host)"
    rm -f "$DROPIN_DIR/10-debian-perf-paranoid.conf"
fi
# Lab PR 222: the copy-on-first-write guard (EXPERIMENTAL) answers fanotify
# permission events, which need CAP_SYS_ADMIN; its restore sets a recreated
# file's owner and time (CAP_CHOWN, CAP_FOWNER). Only with --cow-guard; an
# upgrade keeps (and refreshes) a drop-in already there. Self-integrity
# compares it with this file, as the Debian one.
if [[ "$COW_GUARD" == 1 || ( "$COW_GUARD" == keep && -e "$DROPIN_DIR/20-cow-guard.conf" ) ]]; then
    echo "install.sh: copy-on-first-write drop-in (CAP_SYS_ADMIN CAP_CHOWN CAP_FOWNER)"
    install -d -m 0755 -o root -g root "$DROPIN_DIR"
    install -m 0644 -o root -g root "$REPO_ROOT/deploy/systemd/20-cow-guard.conf" \
        "$DROPIN_DIR/20-cow-guard.conf"
elif [[ "$COW_GUARD" == 0 && -e "$DROPIN_DIR/20-cow-guard.conf" ]]; then
    echo "install.sh: removing the copy-on-first-write drop-in"
    rm -f "$DROPIN_DIR/20-cow-guard.conf"
fi
# Journal-namespace config goes in /etc/systemd/ (read by the
# systemd-journald@northnarrow instance), NOT the unit dir. NN-managed
# (always refreshed); operators override via
# /etc/systemd/journald@northnarrow.conf.d/.
install -m 644 -o root -g root "$JOURNALD_NS_CONF_SRC" "$JOURNALD_NS_CONF"

# Tappa 9 C7: ensure /etc/northnarrow/ exists.
echo "install.sh: ensuring $ETC_DIR (mode 0755, root:root)"
install -d -m 0755 -o root -g root "$ETC_DIR"

# External audit EVD-019 (NN-AUD-281): the audit log and the head anchor were
# 0644 in this world-readable directory, and any local user read key
# fingerprints, the callers' pid/uid/comm, drift details and which sensor was
# blind. The agent creates them 0640 now (root and the file's group); an
# existing copy is closed here — the units are stopped and the pins dropped,
# nothing denies the chmod — and given --audit-group's group. A missing file
# is created empty, as the agent would, so a fresh install gets the group
# too; a link is left alone (the agent writes neither through one).
for evidence in audit.log chain_heads.json; do
    ev_path="$ETC_DIR/$evidence"
    if [[ -L "$ev_path" ]]; then
        echo "install.sh: WARNING: $ev_path is a symbolic link — left alone (external audit EVD-019)" >&2
        continue
    fi
    if [[ ! -e "$ev_path" ]]; then
        install -m 0640 -o root -g "${AUDIT_GROUP:-root}" /dev/null "$ev_path"
    elif [[ -f "$ev_path" ]]; then
        if [[ -n "$AUDIT_GROUP" ]]; then
            chown "root:$AUDIT_GROUP" "$ev_path"
        else
            chown root "$ev_path"
        fi
        chmod 0640 "$ev_path"
    fi
    echo "install.sh: $ev_path closed to other users ($(stat -c '%a %U:%G' "$ev_path"))"
done

# The shipped default lists (`.v1`): the FIM watched paths (Tappa 9 C7), the
# NetFlow IP/CIDR and JA3 blocklists (Tappa 10 N8), the process and NetFlow
# comm allowlists (Tappa 10.5 D1). External audit LLMR-015 (NN-AUD-327, lab
# PR 168): they are the product's defaults, not operator configuration — an
# operator tunes a list through its signed `.local` overlay (`nn-admin config
# overlay set <list>`; the overlays are never shipped nor touched here). An
# existing copy used to be left alone, on --upgrade too, so a host kept the
# lists of its first install (NET-011, lab PR 78, took 100.64.0.0/10 and
# 198.18.0.0/15 out of the blocklist of a KillProcessTree rule: a host
# installed before kept killing on them) and a hand edit stayed in force.
# The agent now applies the list it was built with whenever the file is not
# that list (an edit: an ERROR and a signed `default_list_modified` at every
# boot). Here: a missing, current or earlier-shipped copy is (re)installed;
# any other content is kept as `<list>.v1.operator`, the shipped list
# installed, and the difference printed with the command that moves it into
# the overlay.
# SHA-256 of the copies earlier releases shipped: the agent's
# EARLIER_*_SHA256 tables next to each built-in copy (a unit test keeps the
# two equal, config::overlay::tests::install_sh_knows_the_same_shipped_lists).
declare -A SHIPPED_V1_EARLIER=(
    [fim-paths.v1]="6baec5b5f0dfc92bdf91a0426b8d3693bd4b4a7b25df79e6ff9aa2298b906659 99e3364b81cf77ccd51cda88e80bc71a45b13e7b75c7ff480b195e157ab3011a 3fc62222695e595a26069123393850cfe917c614d863947248240a3b41810c9b"
    [netflow-blocklist.v1]="b50d821782e5ab9d8ab3e27aa7c3dfb3ea0aec87001c16b2eea758d94e8a7866"
    [netflow-ja3-blocklist.v1]="0340417224f37515e1c2a1ed24bc3f530c4bdb910f6bf65dee9793152efc6a24"
    [process-comm-allowlist.v1]="4a3a973fff7875d6050b458778031c1e69f2ed0181bbde9da52854a1f16fe730 e99ae04a743682c471899cc997e7d5da6c055c043706d398e55aa976f0669b94"
    [netflow-comm-allowlist.v1]="4fca39d4d5a35da6fb5409bf25f76ce9020f444f4ac553b3c3ecda3ad9277f10"
    [security-tools.v1]=""
)
install_shipped_v1() {
    local name=$1 src=$2 what=$3 dst="$ETC_DIR/$1" on_disk keep
    if [[ -L "$dst" || ( -e "$dst" && ! -f "$dst" ) ]]; then
        # the agent reads no list through a link, nor from a FIFO
        echo "install.sh: WARNING: $dst is not a regular file — replaced with the shipped $what" >&2
        rm -f "$dst"
    fi
    if [[ ! -e "$dst" ]]; then
        echo "install.sh: copying the shipped $what to $dst"
        install -m 0644 -o root -g root "$src" "$dst"
        return 0
    fi
    if cmp -s "$src" "$dst"; then
        echo "install.sh: $dst is the shipped $what — current"
        return 0
    fi
    on_disk=$(sha256sum "$dst" | cut -d' ' -f1)
    if [[ " ${SHIPPED_V1_EARLIER[$name]:-} " == *" $on_disk "* ]]; then
        echo "install.sh: replacing $dst — the $what an earlier release shipped"
        install -m 0644 -o root -g root "$src" "$dst"
        return 0
    fi
    keep="$dst.operator"
    if [[ -e "$keep" ]] && ! cmp -s "$dst" "$keep"; then
        keep="$dst.operator.$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    cp -p "$dst" "$keep"
    install -m 0644 -o root -g root "$src" "$dst"
    echo "install.sh: WARNING: $dst was no list NorthNarrow shipped (edited by hand?): kept as $keep," >&2
    echo "install.sh:   the shipped $what installed — the agent applies only the shipped list. Move what you" >&2
    echo "install.sh:   need into the signed overlay (+entry adds, -entry disables a shipped entry):" >&2
    echo "install.sh:     nn-admin config overlay set ${name%.v1} --file <overlay> --key <config-manage key>" >&2
    if command -v diff >/dev/null 2>&1; then
        echo "install.sh:   shipped -> yours (+ yours only, - shipped entries you removed; first 40 lines):" >&2
        diff -u "$src" "$keep" | sed -n '3,42{s/^/install.sh:     /;p}' >&2 || true
    fi
}
install_shipped_v1 fim-paths.v1 "$FIM_PATHS_V1_SRC" "FIM watched-paths list"
install_shipped_v1 netflow-blocklist.v1 "$NETFLOW_BLOCKLIST_V1_SRC" "NetFlow IP/CIDR blocklist"
install_shipped_v1 netflow-ja3-blocklist.v1 "$NETFLOW_JA3_BLOCKLIST_V1_SRC" "NetFlow JA3 blocklist"
install_shipped_v1 process-comm-allowlist.v1 "$PROCESS_COMM_ALLOWLIST_V1_SRC" "process comm allowlist"
install_shipped_v1 netflow-comm-allowlist.v1 "$NETFLOW_COMM_ALLOWLIST_V1_SRC" "NetFlow comm allowlist"
install_shipped_v1 security-tools.v1 "$SECURITY_TOOLS_V1_SRC" "list of security tools"

# COMBAT rulesets (iptables-restore bodies for the NORTHNARROW_COMBAT
# chain, v4 + v6). Load-bearing beyond isolation: without a loadable
# v4 ruleset the agent builds no NetworkIsolator, and the admin socket
# (status / unlock / detections) is NOT started at all — the watchdog's
# STATUS ping then fails every 30 s and its stuck-recovery restarts a
# healthy agent forever (seen on the lab guest, 2026-10-08). Ship the
# defaults from configs/ like every other v1 file; an operator copy is
# never overwritten.
for rules in combat-rules.v4 combat-rules.v6; do
    if [[ -f "$ETC_DIR/$rules" ]]; then
        echo "install.sh: $ETC_DIR/$rules already present — leaving operator copy untouched"
    else
        require_file "$REPO_ROOT/configs/$rules" "expected at $REPO_ROOT/configs/$rules (COMBAT ruleset)"
        echo "install.sh: copying default COMBAT ruleset to $ETC_DIR/$rules"
        install -m 0644 -o root -g root "$REPO_ROOT/configs/$rules" "$ETC_DIR/$rules"
    fi
done

# Beta Step 3: refresh the opt-in overlay TEMPLATE (container-runtime
# exemptions, off by default). This is a `.example`, never the live
# `.local`, so it is safe to overwrite on every install — it documents
# the current set of recommended container-runtime comms. Container
# hosts activate it through the agent (a new file in $ETC_DIR is refused
# outside a trusted-installer window, external audit EBPF-015):
#   nn-admin config overlay set process-comm-allowlist \
#      --file $ETC_DIR/process-comm-allowlist.local.example --key <key>
# See docs/operator/CONTAINER_HOST_DEPLOY.md for the security tradeoff.
if [[ -f "$PROCESS_COMM_ALLOWLIST_EXAMPLE_SRC" ]]; then
    echo "install.sh: refreshing overlay template $ETC_DIR/process-comm-allowlist.local.example"
    install -m 0644 -o root -g root "$PROCESS_COMM_ALLOWLIST_EXAMPLE_SRC" "$ETC_DIR/process-comm-allowlist.local.example"
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
# written to $ADMIN_KEY_OUT (external audit DEP-001: not under
# /etc/northnarrow) and MUST be moved offline — see the warning; the agent
# and `nn-admin host-check` report it while it stays on the host.
if [[ -f "$ETC_DIR/admin.pub" ]]; then
    echo "install.sh: $ETC_DIR/admin.pub already present — leaving admin keys untouched"
elif [[ -e "$ADMIN_KEY_OUT" ]]; then
    echo "install.sh: WARNING — $ADMIN_KEY_OUT already exists; not overwriting it, admin.pub was NOT created." >&2
    echo "install.sh: COMBAT will be UNRECOVERABLE without an admin key. Pick another --admin-key-out, or:" >&2
    echo "install.sh:   nn-admin init --priv-out <offline-path> --pub-append $ETC_DIR/admin.pub" >&2
else
    echo "install.sh: no admin.pub found — bootstrapping an Ed25519 admin keypair (nn-admin init)"
    mkdir -p "$(dirname "$ADMIN_KEY_OUT")"
    if (umask 077 && "$BIN_DIR/nn-admin" init --priv-out "$ADMIN_KEY_OUT" --pub-append "$ETC_DIR/admin.pub"); then
        chmod 0600 "$ADMIN_KEY_OUT" 2>/dev/null || true
        # Explicit role list: the defaults (unlock, audit-read) plus
        # trusted-installer, which `install.sh --upgrade --grant-key` and
        # `uninstall.sh --grant-key` need to purge the protected pin root.
        sed -i '$ s/[[:space:]]*$/ unlock,audit-read,trusted-installer,config-manage/' "$ETC_DIR/admin.pub"
        echo ""
        echo "  ##########################################################################"
        echo "  #  SECURITY — an admin PRIVATE key was just written to this host:         #"
        echo "  #      $ADMIN_KEY_OUT  (mode 0600)"
        echo "  #                                                                        #"
        echo "  #  This key RELEASES COMBAT isolation. Anyone holding it — or with root   #"
        echo "  #  on THIS host — can unlock the host. MOVE IT OFF THIS HOST NOW and      #"
        echo "  #  store it offline, e.g.:                                                #"
        echo "  #      mv $ADMIN_KEY_OUT  <secure-offline-location>"
        echo "  #  Keep ONLY the public half ($ETC_DIR/admin.pub) on the host.            #"
        echo "  #  Roles: unlock, audit-read, trusted-installer (what --upgrade and       #"
        echo "  #  uninstall.sh --grant-key use to purge the protected pin root) and      #"
        echo "  #  config-manage (signs *.local overlays). canary-manage / fim-manage /  #"
        echo "  #  force-posture need a role list on its admin.pub line.                  #"
        echo "  #  Until it is gone the agent records it (integrity_drift, signed) and    #"
        echo "  #  nn-admin host-check reports WARN admin_key.                            #"
        echo "  #  Recovery procedure: docs/operator/COMBAT_RECOVERY.md (section 1.1)    #"
        echo "  ##########################################################################"
        echo ""
    else
        echo "install.sh: WARNING — nn-admin init failed; admin.pub was NOT created." >&2
        echo "install.sh: COMBAT will be UNRECOVERABLE without an admin key. Generate one manually:" >&2
        echo "install.sh:   nn-admin init --priv-out <offline-path> --pub-append $ETC_DIR/admin.pub" >&2
    fi
fi

# Tappa 9 C7: ensure /var/lib/northnarrow/ exists at mode 0700
# (matches STATE_DIR_MODE in crates/nn-linux/src/anti_tamper/filesystem.rs)
# and pre-touch the two chained FIM logs so PROTECTED_INODES has
# inodes to register at the agent's very first attach. The agent
# also bootstraps these (bootstrap_fim_log) but doing it here
# closes a brief race window on first boot.
# Upgrade path: the agent applies chattr +i to $STATE_DIR at boot
# (anti_tamper/filesystem.rs, belt-and-suspenders under the LSM deny
# hooks). With the agent stopped the LSM hooks are gone but the
# immutable flag persists, and every `install` below fails with
# "Operation not permitted". Lift it here; the agent re-applies it on
# its next start. (With the agent RUNNING the LSM hooks still deny
# these writes — stop it first, or upgrade through the signed
# trusted-installer window, FS_GRANT.) Lab PR 229: before the
# `install -d` too. GNU install leaves an existing directory's owner and
# mode alone when they already match; uutils (Ubuntu 26.04) sets them
# again, which an immutable directory refuses: the upgrade failed there
# (and rolled back).
if command -v lsattr >/dev/null 2>&1 && lsattr -d "$STATE_DIR" 2>/dev/null | awk '{print $1}' | grep -q i; then
    echo "install.sh: $STATE_DIR is immutable (chattr +i from a previous agent run) — lifting for the install"
    chattr -i "$STATE_DIR"
fi
echo "install.sh: ensuring $STATE_DIR (mode 0700, root:root)"
install -d -m 0700 -o root -g root "$STATE_DIR"
# External audit EVD-019 (NN-AUD-281): earlier releases created the evidence
# logs 0644 (detections, status events, netflow and its listeners, the FIM
# baseline and drift, the canary chains, their archives and manifests). The
# directory's 0700 kept other users out; a copy that keeps the mode (cp -a, a
# backup) did not. The agent creates them 0600 now; close the existing ones.
# Only *.jsonl* at the top and in detections/: the honeypot baits keep 0644.
while IFS= read -r -d '' evidence; do
    echo "install.sh: closing $evidence to other users (mode $(stat -c %a "$evidence"))"
    chmod go-rwx "$evidence"
done < <(find "$STATE_DIR" -maxdepth 2 -xdev -type f -name '*.jsonl*' -perm /077 -print0)
# Wave 4 (lab PR 214): the on-host LLM advisor was removed, and the agent no
# longer reads $STATE_DIR/models (the GGUF model and tokenizer an operator
# installed for it). They are the operator's files, possibly several GB:
# named here, left in place.
if [[ -d "$STATE_DIR/models" ]]; then
    echo "install.sh: $STATE_DIR/models holds the model of the removed LLM advisor; the agent no longer reads it — delete it to free the space (docs/operator/UPGRADE_NOTES_WAVE4.md)"
fi

for fim_log in fim_baseline.jsonl fim_drift.jsonl; do
    if [[ -f "$STATE_DIR/$fim_log" ]]; then
        echo "install.sh: $STATE_DIR/$fim_log already present — leaving chain intact"
    else
        echo "install.sh: bootstrapping $STATE_DIR/$fim_log (zero-byte placeholder)"
        install -m 0600 -o root -g root /dev/null "$STATE_DIR/$fim_log"
    fi
done

# Tappa 9.5.1: anti-tamper control-surface bait files (NN-L-FIM-024).
# 10 inert files across /etc, /var/lib and /run; mode 0644 root:root so a
# tamper is observable. We (re)write them to the canonical content on
# every install — they are NN-managed, not operator configuration. The
# tmpfs /run/northnarrow pair vanishes on reboot; the agent's boot
# HoneypotIntegrityCheck recreates it (and any deleted persistent bait)
# from the same embedded templates.
# >>> install_bait (run by xtask/tests/install_scripts.rs)
# Write control-surface file DST from template SRC. External audit FIMR-016
# (NN-AUD-290): the template's `last_modified=` line is set to the time of
# the write, UTC to the second, and the file's mtime to that same second —
# every template carried one frozen date, which a file written later
# contradicted. The agent's boot sweep writes a missing one the same way
# (fim::honeypot::render_bait).
# BUG-020 tactical (idempotent skip-if-identical). These baits are
# PROTECTED_INODES. Once the agent has pinned the anti-tamper LSM hooks,
# `install` (which REPLACES the file) is denied EPERM outside a
# trusted-installer window — and under `set -e` that aborts the whole
# reinstall before daemon-reload. A file that already holds its template,
# the date line aside, is left as it is (date and mtime kept); a missing or
# divergent one is (re)written.
install_bait() {
    local src=$1 dst=$2 epoch stamp tmp
    if [[ -f "$dst" ]] && cmp -s <(grep -v '^last_modified=' "$src") \
        <(grep -v '^last_modified=' "$dst"); then
        echo "install.sh: control-surface file $dst already matches — skip (BUG-020)"
        return 0
    fi
    echo "install.sh: writing control-surface file $dst"
    epoch=$(date -u +%s)
    stamp=$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ)
    tmp=$(mktemp)
    if ! sed "s/^last_modified=.*/last_modified=$stamp/" "$src" >"$tmp" \
        || ! install -m 0644 -o root -g root "$tmp" "$dst" \
        || ! touch -m -d "@$epoch" "$dst"; then
        rm -f "$tmp"
        echo "install.sh: could not write control-surface file $dst" >&2
        return 1
    fi
    rm -f "$tmp"
}
# <<< install_bait
# Lab PR 216 (static review C-43 / G-06): 0700, the units'
# RuntimeDirectoryMode= — it was 0755 until the agent's next start.
echo "install.sh: ensuring $RUN_DIR (mode 0700, root:root)"
install -d -m 0700 -o root -g root "$RUN_DIR"
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
    # The deny hook is pinned, so a rewrite is refused even with the agent
    # stopped (its only write-exemptions are the live agent PID and the
    # trusted-installer window): see install_bait for what is skipped.
    install_bait "$HONEYPOT_BAITS_SRC_DIR/$bait" "${HONEYPOT_BAIT_DIRS[$bait]}/$bait"
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
        install -m 0600 -o root -g root /dev/null "$STATE_DIR/$canary_log"
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
    install -m 0600 -o root -g root /dev/null "$STATE_DIR/netflow.jsonl"
fi

# Tappa 9.5 K7: install the 5 canary content templates into
# /etc/northnarrow/canary-templates/. Templates are read by the
# K4 renderer at `nn-admin canary deploy` time; PROTECTED_INODES
# covers each individual .tmpl per ETC_PROTECTED_TEMPLATES.
# An operator-customised template is left untouched. External audit
# DEC-007: the templates of earlier releases named the product ("NorthNarrow
# XDR ... DO NOT USE", northnarrow.io) in what lands in the decoy, and an
# upgrade kept them; a copy byte-identical to one of those (its SHA-256
# below, as SUPERSEDED_TEMPLATE_SHA256 in
# crates/nn-core/src/canary/templates.rs) is replaced, an edited one is
# kept and reported if it still names the product. The directory and the
# templates are closed to other users (0750 / 0640): they describe the
# decoys.
declare -A CANARY_TEMPLATE_SUPERSEDED=(
    [aws.tmpl]="cd728e77335951708ad263d4e2d52f808cd9522d1a63546f6621a8e33b15af79"
    [azure.tmpl]="1f2676fce70db95d9f2aeaf2a2c2628dd7211cf75d8464329acb208b9350ae04"
    [docker.tmpl]="c203d592a626a1ce6fa2ff74ac0935c454eda83060ba67242aa19906a662078d"
    [gcp.tmpl]="61f3817c87f6ca8892072a60f459b577ebcb98903b50aec9cdff6ec2c9e8c63a"
    [generic.tmpl]="b888d4187b100e984aac3c6f701d9ba649e67d76e55774a768d80ef4ee7be88a"
)
echo "install.sh: ensuring $ETC_DIR/canary-templates (mode 0750, root:root)"
install -d -m 0750 -o root -g root "$ETC_DIR/canary-templates"
chmod 0750 "$ETC_DIR/canary-templates"

for tmpl in aws.tmpl azure.tmpl docker.tmpl gcp.tmpl generic.tmpl; do
    src="$CANARY_TEMPLATES_SRC_DIR/$tmpl"
    dst="$ETC_DIR/canary-templates/$tmpl"
    if [[ -f "$dst" && ! -L "$dst" ]]; then
        on_disk=$(sha256sum "$dst" | cut -d' ' -f1)
        if cmp -s "$src" "$dst"; then
            echo "install.sh: $dst already current"
        elif [[ " ${CANARY_TEMPLATE_SUPERSEDED[$tmpl]} " == *" $on_disk "* ]]; then
            echo "install.sh: replacing $dst — the template an earlier release shipped (it named the product)"
            install -m 0640 -o root -g root "$src" "$dst"
        else
            echo "install.sh: $dst differs from the shipped template — leaving the operator copy untouched"
            if grep -qiE 'northnarrow|do not use|canary' "$dst"; then
                echo "install.sh: WARNING: $dst names the product or says what the file is; every decoy rendered from it does too (external audit DEC-007)" >&2
            fi
        fi
        chown root:root "$dst"
        chmod 0640 "$dst"
    else
        echo "install.sh: copying canary template $tmpl"
        install -m 0640 -o root -g root "$src" "$dst"
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
write_install_manifest
systemctl daemon-reload
# Pick up journald@northnarrow.conf on REINSTALL (on a first install the
# namespace journald socket-activates fresh on the agent's first start, so
# this is a no-op then). Best-effort — the instance may not be running yet.
systemctl restart systemd-journald@northnarrow.service 2>/dev/null || true

# Tappa 10.8 — the agent loads a *.local overlay only with a valid
# signature (<overlay>.sig, key with the config-manage role). On an upgrade
# from a release that read overlays unsigned, adopt the ones present now
# with the operator's key, while nothing protects /etc/northnarrow; an
# overlay that cannot be signed is listed, and the agent will boot on the
# shipped defaults for that list until it is signed.
if (( UPGRADE )) && [[ -s "$ETC_DIR/agent_id" ]]; then
    ovl_status() {
        "$BIN_DIR/nn-admin" config overlay status --dir "$ETC_DIR" --admin-pub "$ETC_DIR/admin.pub" \
            --agent-id-file "$ETC_DIR/agent_id" --audit-log "$ETC_DIR/audit.log" 2>/dev/null
    }
    # status exits 1 when an overlay is not loadable: not an install failure
    unsigned=$( { ovl_status || true; } | awk '/NOT LOADED/ {printf "%s ", $1}')
    # the file of an overlay kind: `<kind>.local`, except the COMBAT files
    # (external audit ATP-001 / DEP-003), which keep their own names
    ovl_file() {
        case "$1" in
            combat-rules-v4) echo "$ETC_DIR/combat-rules.v4" ;;
            combat-rules-v6) echo "$ETC_DIR/combat-rules.v6" ;;
            combat-allow) echo "$ETC_DIR/combat-allow.cidrs" ;;
            *) echo "$ETC_DIR/$1.local" ;;
        esac
    }
    if [[ -n "$unsigned" && -n "$GRANT_KEY" ]]; then
        for kind in $unsigned; do
            "$BIN_DIR/nn-admin" config overlay sign "$kind" --file "$(ovl_file "$kind")" --key "$GRANT_KEY" \
                --agent-id-file "$ETC_DIR/agent_id" >/dev/null 2>&1 || true
        done
    fi
    # what the new agent will actually load (sign does not know admin.pub roles)
    while read -r kind state rest; do
        case "$state" in
            signed) if [[ " $unsigned " == *" $kind "* ]]; then echo "install.sh: adopted overlay $(ovl_file "$kind") — signed with $GRANT_KEY"; fi ;;
            NOT) echo "install.sh: WARNING — overlay $(ovl_file "$kind") will NOT be loaded (shipped defaults for that list):${rest#*start:}" >&2
                 echo "install.sh:   sign it with a key that carries config-manage: nn-admin config overlay sign $kind --file $(ovl_file "$kind") --key <key>" >&2 ;;
        esac
    done < <(ovl_status || true)
fi

if (( UPGRADE )) && (( ${#UNITS_TO_RESTART[@]} )); then
    TXN_PHASE=start
    start_units "${UNITS_TO_RESTART[@]}"
    if [[ $MODE == configure ]]; then
        # Lab PR 220: the package hooks report an upgrade that does not pass
        # (pkg_health_or_fail); the rpm checks at the end of its transaction.
        if (( DEFER_HEALTH )); then
            echo "install.sh: units restarted; their health check runs at the end of the transaction (%posttrans)"
            exit 0
        fi
        pkg_health_or_fail "${UNITS_TO_RESTART[@]}" || exit 1
        echo ""
        echo "install.sh: UPGRADE complete — health check passed; the audit chain carries a new agent_boot entry."
        exit 0
    fi
    # Lab PR 220: the upgrade is complete when the new units prove their
    # health (upgrade_health_check); otherwise the EXIT trap rolls back.
    TXN_PHASE=health_check
    echo "install.sh: health check of ${UNITS_TO_RESTART[*]} (up to ${HEALTH_TIMEOUT}s)"
    if ! upgrade_health_check "${UNITS_TO_RESTART[@]}"; then
        TXN_REASON=$HEALTH_FAILURE
        echo "install.sh: health check FAILED: $HEALTH_FAILURE" >&2
        exit 1
    fi
    if [[ -n "$HEALTH_NOTE" ]]; then echo "install.sh: WARNING: $HEALTH_NOTE" >&2; fi
    for u in "${UNITS_TO_RESTART[@]}"; do
        echo "install.sh: $u is $(systemctl is-active "$u.service" || true)"
    done
    rm -f "$PKG_RESTART_FILE"
    txn_commit
    echo ""
    echo "install.sh: UPGRADE complete — health check passed ($new_ver); the audit chain carries a new agent_boot entry."
    exit 0
fi
txn_commit

echo ""
echo "install.sh: install complete."
echo ""
echo "Host hardening (nn-admin host-check — the anti-tamper holds only while root cannot rewrite the kernel at runtime):"
"$BIN_DIR/nn-admin" host-check 2>/dev/null | sed 's/^/  /' || true
echo ""
echo "Next steps (operator runs explicitly — install.sh does NOT auto-start):"
echo "(The docs/operator/ guides named below are in the release tree; a package"
echo " installs them in /usr/share/doc/northnarrow/operator/.)"
echo ""
echo "  1. Verify the install layout:"
echo "       systemctl status northnarrow-agent.service"
echo "       systemctl status northnarrow-watchdog.service"
echo ""
echo "  2. Confirm /etc/northnarrow/ has admin.pub +"
echo "     combat-rules.v4 + combat-rules.v6 + combat-allow.cidrs + agent_id +"
echo "     fim-paths.v1 + canary-templates/ +"
echo "     netflow-blocklist.v1 + netflow-ja3-blocklist.v1 +"
echo "     process-comm-allowlist.v1 + netflow-comm-allowlist.v1 (the"
echo "     agent bootstraps agent_id on first start; admin.pub and the"
echo "     private key $ADMIN_KEY_OUT were auto-generated above IF admin.pub"
echo "     was absent — MOVE that key OFFLINE now (docs/operator/COMBAT_RECOVERY.md);"
echo "     combat-rules.v4 + .v6 are operator-provided (configs/ has both;"
echo "     v6 preserves NDP — see its header); combat-allow.cidrs +"
echo "     fim-paths.v1 + canary-templates/ + netflow-{,ja3-}blocklist.v1 +"
echo "     {process,netflow}-comm-allowlist.v1 were just installed above)."
echo "     Optional: add management CIDRs to combat-allow.cidrs to keep an"
echo "     SSH path open during COMBAT (anti-lockout — empty by default;"
echo "     see docs/operator/COMBAT_RECOVERY.md §2)."
echo "     Overlays (*.local) are loaded only when signed by a key with the"
echo "     config-manage role: write the overlay to a file, then"
echo "       nn-admin config overlay set <kind> --file <file> --key <key>"
echo "     (stored by the running agent; applies at its next start)."
echo "     (A file dropped into /etc/northnarrow by hand is refused while the"
echo "     agent runs.) Optional: a fim-paths overlay to customise"
echo "     the FIM watched-paths set (\`+/path\` add, \`-/path\` disable —"
echo "     see docs/operator/TAPPA9_FIM_TRUST_MODEL.md §13 Q7)."
echo "     Optional: netflow-blocklist + netflow-ja3-blocklist overlays to"
echo "     extend the NetFlow blocklists from a threat-intel feed (\`+entry\` add,"
echo "     \`-entry\` disable — same schema as fim-paths.local; the entry format"
echo "     is in the header of $ETC_DIR/netflow-{,ja3-}blocklist.v1)."
echo "     Optional: process-comm-allowlist + netflow-comm-allowlist overlays"
echo "     to tune the Tappa 10.5 detection-rule comm exemptions (\`+comm\` add,"
echo "     \`-comm\` re-enable detection on a default — same schema; the format"
echo "     is in the header of $ETC_DIR/{process,netflow}-comm-allowlist.v1)."
echo "     Overlay kinds and signing: docs/operator/INSTALL_UPGRADE_UNINSTALL.md §3.6."
echo "     CONTAINER HOSTS: set process-comm-allowlist.local.example as the"
echo "     process-comm-allowlist overlay to exempt container-runtime comms (\`runc\` etc.). This"
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
echo "     Without it the agent refuses to start (exit 78; NN_ANTI_TAMPER_ALLOW_DEGRADED=1"
echo "     starts it without enforcement, trust level L0: docs/operator/BOOT_INTEGRITY.md)."
echo "     If absent: ADD 'bpf' to the list the kernel runs, then reboot. Never"
echo "     write a fixed lsm= list: it replaces the kernel's own and can switch"
echo "     SELinux or AppArmor off (update-grub on Debian/Ubuntu, grubby on the"
echo "     RHEL family: docs/operator/KERNEL_COMPATIBILITY.md, \"Enabling the bpf LSM\")."
echo ""
echo "  5. Enable + start:"
echo "       systemctl enable --now northnarrow-agent.service"
echo "       systemctl enable --now northnarrow-watchdog.service"
echo ""
echo "  6. Follow logs:"
echo "       journalctl --namespace=northnarrow -u northnarrow-agent.service -f"
echo "       journalctl --namespace=northnarrow -u northnarrow-watchdog.service -f"
echo "     (NN logs live in the 'northnarrow' journal namespace — capped 1G,"
echo "      NOT forwarded to rsyslog/syslog. The --namespace flag is required.)"
