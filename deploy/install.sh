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
# Operator drop-ins always live in /etc, whatever directory holds the unit
# files themselves (a package ships them in /usr/lib/systemd/system).
DROPIN_ROOT=${DROPIN_ROOT:-/etc/systemd/system}
ETC_DIR=${ETC_DIR:-/etc/northnarrow}
STATE_DIR=${STATE_DIR:-/var/lib/northnarrow}

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
#   --package-configure  after unpack: configure the host, restart them
# Both run with BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system and
# REPO_ROOT=/usr/share/northnarrow (the package's data tree).
MODE=full
PKG_RESTART_FILE=${PKG_RESTART_FILE:-/run/northnarrow-pkg-restart}
VERIFY=1
REQUIRE_ATTESTATION=0
# External audit DEP-007: the release checks no longer step down on their
# own. A tree without MANIFEST.sha256 is refused unless --source-tree says it
# is one; a tree vouched for only by its own MANIFEST.sha256 (no tarball +
# SHA256SUMS, no attestation) is refused unless --allow-manifest-only. The
# flag that accepted the lower level is recorded in the install manifest
# (verify_override) and reported by `nn-admin host-check`.
SOURCE_TREE=0
ALLOW_MANIFEST_ONLY=0
VERIFY_OVERRIDE=""
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
while [[ $# -gt 0 ]]; do
    case "$1" in
        --upgrade) UPGRADE=1 ;;
        --grant-key) GRANT_KEY=$2; shift ;;
        --admin-key-out) ADMIN_KEY_OUT=$2; shift ;;
        --package-stop) MODE=stop ;;
        --package-configure) MODE=configure ;;
        --tarball) TARBALL=$2; shift ;;
        --sums) SUMS=$2; shift ;;
        --attestation) ATTEST_BUNDLE=$2; shift ;;
        --require-attestation) REQUIRE_ATTESTATION=1 ;;
        --source-tree) SOURCE_TREE=1 ;;
        --allow-manifest-only) ALLOW_MANIFEST_ONLY=1 ;;
        --no-verify) VERIFY=0 ;;
        --without-nftables) WITHOUT_NFT=1 ;;
        --audit-group) AUDIT_GROUP=$2; shift ;;
        -h|--help)
            echo "usage: sudo $0 [--upgrade] [--tarball FILE] [--sums FILE] [--attestation BUNDLE] [--require-attestation]"
            echo "                 [--source-tree | --allow-manifest-only | --no-verify] [--without-nftables]"
            echo "  --upgrade              stop the running units, replace binaries/units/configs, restart them"
            echo "  --grant-key KEY        admin key with the trusted-installer role (opens the window an upgrade needs)"
            echo "  --admin-key-out PATH   fresh install: where to write the bootstrap admin PRIVATE key"
            echo "                         (default /root/northnarrow-admin.key; never under $ETC_DIR) — move it offline"
            echo "  --tarball FILE         the release tarball this tree was extracted from (default: ../<tree>.tar.gz)"
            echo "  --sums FILE            SHA256SUMS of the release (default: next to the tarball)"
            echo "  --attestation BUNDLE   offline Sigstore bundle for the tarball (gh attestation download)"
            echo "  --require-attestation  fail unless the SLSA provenance attestation verifies"
            echo "  --source-tree          the tree is a build from source (cargo xtask build --release), not a"
            echo "                         release: install it without MANIFEST.sha256 (recorded as 'source-tree')"
            echo "  --allow-manifest-only  accept a release tree checked only against its own MANIFEST.sha256"
            echo "                         (no tarball + SHA256SUMS, no attestation; recorded as 'manifest')"
            echo "  --no-verify            skip every release check (dev only; recorded as 'unverified')"
            echo "  --audit-group GROUP    existing group that may read $ETC_DIR/audit.log and chain_heads.json"
            echo "                         besides root (a log shipper; NN_AUDIT_GROUP too). Kept by later upgrades"
            echo "  The flag that accepted a level below 'checksums' is recorded in the install manifest"
            echo "  and reported by nn-admin host-check."
            echo "  --without-nftables     install on a host without nft (nftables): the agent's per-process"
            echo "                         outbound block then cannot work (recorded in the install manifest)"
            exit 0 ;;
        *) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
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
AGENT_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-agent.service"
WATCHDOG_UNIT_SRC="$REPO_ROOT/deploy/systemd/northnarrow-watchdog.service"
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
# (IP / CIDR) + NN-L-NET-003 (JA3 fingerprint). install.sh installs
# these at /etc/northnarrow/netflow-blocklist.v1 +
# /etc/northnarrow/netflow-ja3-blocklist.v1 (install_shipped_v1); operators
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
# Beta Step 4b: empty-by-default COMBAT management carve-out CIDR list.
COMBAT_ALLOW_CIDRS_SRC="$REPO_ROOT/configs/combat-allow.cidrs"

# ── pre-flight ──────────────────────────────────────────────────────
# ── release verification (supply chain, install-time half) ───────────
# What the operator downloaded must be what CI built and attested:
#   1. MANIFEST.sha256 inside the tree (every file hashed by mk-tarball)
#      — catches a corrupted or edited tree;
#   2. SHA256SUMS of the release against the tarball — catches a
#      swapped tarball;
#   3. the SLSA provenance attestation of the tarball, verified with
#      `gh attestation verify` (online or with an offline --attestation
#      bundle) or cosign, bound to THIS repository's release workflow run
#      for a v* tag — catches a tarball built elsewhere, or by a dispatch
#      run on a branch.
# The strongest level reached is recorded in the install manifest and
# the agent re-checks the installed hashes at every boot. A source tree
# (no MANIFEST.sha256: the lab, a developer build) is "source-tree" and
# needs --source-tree; a level below "checksums" needs an explicit flag
# (external audit DEP-007, require_provenance_floor).
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
verify_release() {
    if (( ! VERIFY )); then
        PROVENANCE="unverified"
        VERIFY_OVERRIDE="--no-verify"
        echo "install.sh: WARNING: --no-verify — release checks skipped, provenance recorded as 'unverified'" >&2
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
        if (( ! SOURCE_TREE )); then
            echo "install.sh: REFUSED — no MANIFEST.sha256 in $REPO_ROOT. A release tree always carries one:" >&2
            echo "install.sh: this one was altered, or it is a build from source. For a source build" >&2
            echo "install.sh: (cargo xtask build --release) re-run with --source-tree (recorded as 'source-tree')." >&2
            exit 1
        fi
        VERIFY_OVERRIDE="--source-tree"
        echo "install.sh: WARNING: --source-tree — no MANIFEST.sha256, release checks not applicable (provenance: source-tree)" >&2
        return 0
    fi
    local tree_name tgz sums
    tree_name=$(basename "$REPO_ROOT")
    tgz=${TARBALL:-"$REPO_ROOT/../$tree_name.tar.gz"}
    if [[ ! -f "$tgz" ]]; then
        echo "install.sh: tarball not found ($tgz) — pass --tarball to also verify SHA256SUMS and the attestation" >&2
        return 0
    fi
    TARBALL_SHA256=$(sha256sum "$tgz" | cut -d' ' -f1)
    sums=${SUMS:-"$(dirname "$tgz")/SHA256SUMS"}
    if [[ -f "$sums" ]]; then
        local expected
        expected=$(grep -E " \*?$(basename "$tgz")\$" "$sums" | head -1 | cut -d' ' -f1 || true)
        if [[ -z "$expected" ]]; then
            echo "install.sh: REFUSED — $(basename "$tgz") is not listed in $sums" >&2
            exit 1
        fi
        if [[ "$expected" != "$TARBALL_SHA256" ]]; then
            echo "install.sh: REFUSED — tarball sha256 $TARBALL_SHA256 does not match SHA256SUMS ($expected)" >&2
            exit 1
        fi
        echo "install.sh: tarball matches SHA256SUMS ($TARBALL_SHA256)"
        PROVENANCE="checksums"
    else
        echo "install.sh: SHA256SUMS not found next to the tarball — pass --sums to verify it" >&2
    fi
    # attestation: gh (2.49+) online or with an offline bundle, else cosign
    if command -v gh >/dev/null 2>&1 && gh attestation --help >/dev/null 2>&1; then
        local -a args=(attestation verify "$tgz" --repo "$REPO_SLUG" --cert-identity-regex "$SIGNER_IDENTITY_REGEX" --deny-self-hosted-runners)
        [[ -n "$ATTEST_BUNDLE" ]] && args+=(--bundle "$ATTEST_BUNDLE")
        if gh "${args[@]}" >/dev/null 2>&1; then
            ATTEST_VERIFIED=1; ATTEST_METHOD=$([[ -n "$ATTEST_BUNDLE" ]] && echo gh-bundle || echo gh)
        else
            echo "install.sh: gh attestation verify FAILED for $(basename "$tgz") (signer $SIGNER_WORKFLOW)" >&2
            (( REQUIRE_ATTESTATION )) && exit 1
        fi
    elif command -v cosign >/dev/null 2>&1 && [[ -n "$ATTEST_BUNDLE" ]]; then
        if cosign verify-blob-attestation --bundle "$ATTEST_BUNDLE" --new-bundle-format \
            --certificate-identity-regexp "$SIGNER_IDENTITY_REGEX" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com "$tgz" >/dev/null 2>&1; then
            ATTEST_VERIFIED=1; ATTEST_METHOD=cosign
        else
            echo "install.sh: cosign attestation verification FAILED for $(basename "$tgz")" >&2
            (( REQUIRE_ATTESTATION )) && exit 1
        fi
    else
        echo "install.sh: no attestation verifier available (gh ≥ 2.49 or cosign + --attestation bundle) — provenance stays at '$PROVENANCE'" >&2
        (( REQUIRE_ATTESTATION )) && { echo "install.sh: REFUSED — --require-attestation set" >&2; exit 1; }
    fi
    if (( ATTEST_VERIFIED )); then
        echo "install.sh: SLSA provenance attestation verified ($ATTEST_METHOD, signer $SIGNER_WORKFLOW)"
        PROVENANCE="attested"
    fi
}

# External audit DEP-007: MANIFEST.sha256 travels inside the tree it vouches
# for — whoever edits the tree can rewrite it. "manifest" (no SHA256SUMS
# check of the tarball, no attestation) is therefore accepted only on
# request. Separate from verify_release so the verifier itself is unchanged.
require_provenance_floor() {
    [[ $PROVENANCE == manifest ]] || return 0
    if (( ! ALLOW_MANIFEST_ONLY )); then
        echo "install.sh: REFUSED — only the tree's own MANIFEST.sha256 was checked, and it travels inside the" >&2
        echo "install.sh: tree it vouches for. Keep the tarball and SHA256SUMS next to the tree (or pass --tarball" >&2
        echo "install.sh: FILE --sums FILE), or re-run with --allow-manifest-only (recorded as 'manifest')." >&2
        exit 1
    fi
    VERIFY_OVERRIDE="--allow-manifest-only"
    echo "install.sh: WARNING: --allow-manifest-only — the release is vouched for only by its own MANIFEST.sha256 (provenance: manifest)" >&2
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
    local sha_agent sha_wd sha_admin sha_ebpf
    sha_agent=$(sha256sum "$BIN_DIR/northnarrow-agent" | cut -d' ' -f1)
    sha_wd=$(sha256sum "$BIN_DIR/northnarrow-watchdog" | cut -d' ' -f1)
    sha_admin=$(sha256sum "$BIN_DIR/nn-admin" | cut -d' ' -f1)
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
    "ebpf_object": "$sha_ebpf"
  },
  "tarball_sha256": $([[ -n "$TARBALL_SHA256" ]] && echo "\"$TARBALL_SHA256\"" || echo null),
  "attestation": {"verified": $([[ $ATTEST_VERIFIED == 1 ]] && echo true || echo false), "method": "$ATTEST_METHOD", "signer_workflow": "$SIGNER_WORKFLOW"}
}
EOT
    install -m 0644 -o root -g root "$tmp" "$manifest"
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
# (external audit ATP-014, agent/src/trusted_bin.rs): the system ones, never
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
# Refuse a stale agent binary BEFORE we touch the live system.
require_fresh_ebpf
fi
# --package-stop runs from the package's pre-unpack hook, before any file of
# the new package exists (on a first install not even the data tree): it
# needs nothing but the installed nn-admin, so it skips the tree checks.
if [[ $MODE != stop ]]; then
require_file "$AGENT_UNIT_SRC"    "expected at $AGENT_UNIT_SRC (this script's sibling deploy/systemd/)"
require_file "$WATCHDOG_UNIT_SRC" "expected at $WATCHDOG_UNIT_SRC"
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
           || [[ -d /sys/fs/bpf/northnarrow ]]; then
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
    [[ -d /sys/fs/bpf/northnarrow ]] || return 0
    echo "install.sh: dropping /sys/fs/bpf/northnarrow so the LSM programs detach (the new agent re-pins fresh)"
    rm -rf /sys/fs/bpf/northnarrow 2>/dev/null || true
    if [[ -d /sys/fs/bpf/northnarrow ]]; then
        echo "install.sh: /sys/fs/bpf/northnarrow is PROTECTED by the anti-tamper and no trusted-installer window" >&2
        echo "install.sh: is open (review entry 39). Start the agent again (systemctl start northnarrow-agent)" >&2
        echo "install.sh: and re-run with --grant-key <admin.key carrying the trusted-installer role>, or open" >&2
        echo "install.sh: the window yourself: nn-admin trusted-installer-grant --key <key> --window-secs 300" >&2
        return 1
    fi
}

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
if (( ${#UNITS_TO_RESTART[@]} )); then
    if (( ! UPGRADE )); then
        echo "install.sh: NorthNarrow is RUNNING (${UNITS_TO_RESTART[*]}) — with the anti-tamper hooks" >&2
        echo "install.sh: active every write below is denied. Re-run with --upgrade to stop, replace and" >&2
        echo "install.sh: restart the units in the right order (keys, audit chain and state are kept)." >&2
        exit 1
    fi
    old_ver=$("$BIN_DIR/northnarrow-agent" --version 2>/dev/null | head -1 || echo "unknown")
    if [[ $MODE == full ]]; then
        new_ver=$("$AGENT_BIN" --version 2>/dev/null | head -1 || echo "unknown")
        echo "install.sh: UPGRADE — installed: $old_ver → new: $new_ver"
    else
        echo "install.sh: stopping $old_ver for the package manager"
    fi
    # The pin root is in the agent's protected-inode set (review entry 39):
    # only a protected pid or an open trusted-installer window may remove it.
    # Open the window now, while the agent still answers on its socket.
    if [[ -n "$GRANT_KEY" ]]; then
        open_trusted_installer_window "$GRANT_KEY" || exit 1
    fi
    # External audit DEP-006: the ids of the running agent's programs,
    # read while it still runs.
    own_ids=$(read_own_prog_ids)
    # Watchdog first: stopping the agent alone makes it respawn it.
    for u in northnarrow-watchdog northnarrow-agent; do
        echo "install.sh: stopping $u ($(systemctl is-active "$u.service" 2>/dev/null | tr -d '\n'))"
        stop_nn_unit "$u"
    done
    purge_pin_root || exit 1
    wait_own_programs_unloaded "$own_ids" || exit 1
fi

if (( ! ${#UNITS_TO_RESTART[@]} )) && [[ -d /sys/fs/bpf/northnarrow ]]; then
    # Units inactive but the previous install's hooks are still pinned: they
    # deny the binary copy below. Same purge path (window needed if protected).
    echo "install.sh: units inactive but /sys/fs/bpf/northnarrow exists — purging the stale pins first"
    if [[ -n "$GRANT_KEY" ]] && systemctl is-active --quiet northnarrow-agent.service; then
        open_trusted_installer_window "$GRANT_KEY" || exit 1
    fi
    purge_pin_root || exit 1
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
                 /etc/systemd/system/northnarrow-agent.service /etc/systemd/system/northnarrow-watchdog.service; do
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
echo "install.sh: copying binaries to $BIN_DIR/"
install -m 755 -o root -g root "$AGENT_BIN"    "$BIN_DIR/northnarrow-agent"
install -m 755 -o root -g root "$WATCHDOG_BIN" "$BIN_DIR/northnarrow-watchdog"
install -m 755 -o root -g root "$NN_ADMIN_BIN" "$BIN_DIR/nn-admin"

echo "install.sh: copying systemd unit files to $UNIT_DIR/"
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
install_unit "$AGENT_UNIT_SRC"    "$UNIT_DIR/northnarrow-agent.service"
install_unit "$WATCHDOG_UNIT_SRC" "$UNIT_DIR/northnarrow-watchdog.service"
fi

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
# Journal-namespace config goes in /etc/systemd/ (read by the
# systemd-journald@northnarrow instance), NOT the unit dir. NN-managed
# (always refreshed); operators override via
# /etc/systemd/journald@northnarrow.conf.d/.
install -m 644 -o root -g root "$JOURNALD_NS_CONF_SRC" "/etc/systemd/journald@northnarrow.conf"

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
# (matches STATE_DIR_MODE in agent/src/anti_tamper/filesystem.rs)
# and pre-touch the two chained FIM logs so PROTECTED_INODES has
# inodes to register at the agent's very first attach. The agent
# also bootstraps these (bootstrap_fim_log) but doing it here
# closes a brief race window on first boot.
echo "install.sh: ensuring $STATE_DIR (mode 0700, root:root)"
install -d -m 0700 -o root -g root "$STATE_DIR"
# Upgrade path: the agent applies chattr +i to $STATE_DIR at boot
# (anti_tamper/filesystem.rs, belt-and-suspenders under the LSM deny
# hooks). With the agent stopped the LSM hooks are gone but the
# immutable flag persists, and every `install` below fails with
# "Operation not permitted". Lift it here; the agent re-applies it on
# its next start. (With the agent RUNNING the LSM hooks still deny
# these writes — stop it first, or upgrade through the signed
# trusted-installer window, FS_GRANT.)
if command -v lsattr >/dev/null 2>&1 && lsattr -d "$STATE_DIR" 2>/dev/null | awk '{print $1}' | grep -q i; then
    echo "install.sh: $STATE_DIR is immutable (chattr +i from a previous agent run) — lifting for the install"
    chattr -i "$STATE_DIR"
fi
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
    src="$HONEYPOT_BAITS_SRC_DIR/$bait"
    dst="$dst_dir/$bait"
    # BUG-020 tactical (idempotent skip-if-identical). These baits are
    # PROTECTED_INODES. Once the agent has pinned the anti-tamper LSM hooks,
    # `install` (which REPLACES the file) is denied EPERM — and under
    # `set -e` that aborts the whole reinstall before daemon-reload. The
    # deny hook is pinned, so this fires even with the agent stopped; its
    # only write-exemption is the live agent PID. The baits are
    # content-stable across installs, so if the on-disk copy already matches
    # the shipped bytes, skip the rewrite entirely. A missing or divergent
    # bait is still (re)written (fresh install; a tampered one is also
    # recreated from the same embedded bytes by the agent's boot
    # HoneypotIntegrityCheck). The STRUCTURAL fix — a key-gated trusted-local
    # installer that can suspend the pin — stays a design call (see §15.1).
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        echo "install.sh: control-surface file $dst already matches — skip (BUG-020)"
    else
        echo "install.sh: writing control-surface file $dst"
        install -m 0644 -o root -g root "$src" "$dst"
    fi
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
# below, as SUPERSEDED_TEMPLATE_SHA256 in agent/src/canary/templates.rs) is
# replaced, an edited one is kept and reported if it still names the
# product. The directory and the templates are closed to other users (0750 /
# 0640): they describe the decoys.
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
    # Agent first (it pins the maps the watchdog registers into), then the
    # watchdog — the same order the operator uses on a fresh install.
    for u in northnarrow-agent northnarrow-watchdog; do
        for w in "${UNITS_TO_RESTART[@]}"; do
            if [[ "$w" == "$u" ]]; then
                echo "install.sh: starting $u"
                systemctl start "$u.service"
                [[ "$u" == northnarrow-agent ]] && sleep 3
            fi
        done
    done
    for u in "${UNITS_TO_RESTART[@]}"; do
        echo "install.sh: $u is $(systemctl is-active "$u.service" || true)"
    done
    rm -f "$PKG_RESTART_FILE"
    echo ""
    echo "install.sh: UPGRADE complete — units restarted; the audit chain carries a new agent_boot entry."
    exit 0
fi

echo ""
echo "install.sh: install complete."
echo ""
echo "Host hardening (nn-admin host-check — the anti-tamper holds only while root cannot rewrite the kernel at runtime):"
"$BIN_DIR/nn-admin" host-check 2>/dev/null | sed 's/^/  /' || true
echo ""
echo "Next steps (operator runs explicitly — install.sh does NOT auto-start):"
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
echo "     \`-entry\` disable — same schema as fim-paths.local; see"
echo "     docs/design/TAPPA10_NETWORK_OBSERVABILITY_DESIGN.md §10 + §13 Q5)."
echo "     Optional: process-comm-allowlist + netflow-comm-allowlist overlays"
echo "     to tune the Tappa 10.5 detection-rule comm exemptions (\`+comm\` add,"
echo "     \`-comm\` re-enable detection on a default — same schema; see"
echo "     docs/design/TAPPA10_5_DETECTION_RULES_AT_SCALE_DESIGN.md §13 Q3)."
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
echo "     If absent: edit /etc/default/grub to add 'lsm=…,bpf' then"
echo "       update-grub && reboot. (See docs/TAPPA7_PREREQ.md.)"
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
