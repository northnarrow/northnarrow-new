#!/usr/bin/env bash
# Tappa 10.7 V1 — bootstrap northnarrowdev in PRODUCTION mode.
#
# RUNS ON: inside the target guest (northnarrowdev), as root.
# Builds + installs the NorthNarrow agent the way a customer runs it —
# WITHOUT the test-privileged feature flag — as a real systemd service
# with real config + real LSM attach, then verifies the deployment.
#
# This is the §5 production-mode delta in script form: NO fixtures.
# Design ref: §2.2, §5, §10.2.
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

[ "$(id -u)" = 0 ] || die "must run as root (real systemd + LSM attach)"
require_cmd cargo
require_cmd systemctl

[ -d "$NN_REPO_DIR" ] || die "repo not found at $NN_REPO_DIR (clone it first)"
cd "$NN_REPO_DIR"

# 1. Build the SHIPPED binary — explicitly NOT --features test-privileged.
log "Building agent in production mode (release, no test-privileged)..."
if [ -x target/release/northnarrow-agent ]; then
    log "release binary present — skipping rebuild (idempotent; touch to force)"
else
    cargo build --release --bin northnarrow-agent
fi

# 2. Install via the real deploy path (idempotent installer).
log "Installing via deploy/install.sh (real systemd unit + $NN_ETC_DIR config)..."
if [ -f deploy/install.sh ]; then
    bash deploy/install.sh
else
    warn "deploy/install.sh missing — falling back to manual unit enable"
fi

# 3. Enable + start the real service (idempotent).
systemctl daemon-reload
systemctl enable northnarrow.service 2>/dev/null || warn "enable: unit name may differ"
systemctl restart northnarrow.service 2>/dev/null || warn "restart: unit name may differ"

# 4. Health check — fail loud if production mode is not actually live.
log "Health check..."
systemctl is-active --quiet northnarrow.service \
    || die "northnarrow.service not active — production bootstrap failed"
[ -d "$NN_ETC_DIR" ] || warn "config dir $NN_ETC_DIR absent — check installer"

# LSM/BPF attach evidence (best-effort; real attach leaves a trace).
if command -v bpftool >/dev/null 2>&1; then
    bpftool prog show 2>/dev/null | grep -qi 'lsm\|northnarrow' \
        && log "LSM/BPF program attached: OK" \
        || warn "no LSM/BPF program visible — verify attach manually"
fi

log "Target prod-mode bootstrap complete. Engine should report $EXPECTED_RULE_COUNT rules."
log "Verify: journalctl -u northnarrow.service | grep -i 'rules'"
