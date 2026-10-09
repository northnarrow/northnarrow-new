#!/usr/bin/env bash
# Assemble the NorthNarrow release tree + tarball from a finished
# `cargo xtask build --release`.
#
# The tree reproduces exactly the paths deploy/install.sh expects
# (target/release/*, the eBPF object + provenance stamp, deploy/, configs/),
# so an operator extracts it and runs `sudo ./deploy/install.sh` — or
# `--upgrade` — unchanged, with every preflight (eBPF freshness, stamp)
# still enforced. mtimes are preserved on purpose: the staleness guard
# compares them.
#
# Usage: deploy/release/mk-tarball.sh [out-dir]        (default: dist/)
# Emits: <out>/northnarrow-<version>-<arch>-linux.tar.gz
#        <out>/northnarrow-<version>-<arch>-linux.{agent,watchdog}.sbom.cdx.json   (if cargo-cyclonedx is installed)
#        <out>/SHA256SUMS

set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$REPO_ROOT/dist"}
cd "$REPO_ROOT"

ver=$(grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)"/\1/')
arch=$(uname -m)
name="northnarrow-${ver}-${arch}-linux"
tree="$OUT/$name"

for f in target/release/northnarrow-agent target/release/northnarrow-watchdog target/release/nn-admin \
         agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf \
         agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf.buildhash; do
    [[ -f "$f" ]] || { echo "mk-tarball: missing $f — run \`cargo xtask build --release\` first" >&2; exit 1; }
done
# Same guard install.sh applies: the agent must be newer than the stamp.
[[ agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf.buildhash -nt target/release/northnarrow-agent ]] \
    && { echo "mk-tarball: agent binary older than the eBPF stamp — rebuild with \`cargo xtask build --release\`" >&2; exit 1; }

rm -rf "$tree" && mkdir -p "$tree"
install -d "$tree/target/release" "$tree/agent-ebpf/target/bpfel-unknown-none/release" "$tree/deploy" "$tree/docs/operator"
cp -p target/release/northnarrow-agent target/release/northnarrow-watchdog target/release/nn-admin "$tree/target/release/"
cp -p agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf{,.buildhash} "$tree/agent-ebpf/target/bpfel-unknown-none/release/"
cp -pr deploy/install.sh deploy/uninstall.sh deploy/systemd "$tree/deploy/"
cp -pr configs "$tree/configs"
cp -p LICENSE NOTICES.md CHANGELOG.md "$tree/"
[[ -d LICENSES ]] && cp -pr LICENSES "$tree/LICENSES"
cp -p docs/operator/*.md "$tree/docs/operator/"
cat > "$tree/README-RELEASE.md" <<EOT
NorthNarrow ${ver} (${arch}-linux)

Install:   sudo ./deploy/install.sh            then: systemctl enable --now northnarrow-agent northnarrow-watchdog
Upgrade:   sudo ./deploy/install.sh --upgrade
Uninstall: sudo ./deploy/uninstall.sh [--purge]
Docs:      docs/operator/INSTALL_UPGRADE_UNINSTALL.md, docs/operator/COMBAT_RECOVERY.md
Verify:    sha256sum -c SHA256SUMS; gh attestation verify <file> --repo northnarrow/northnarrow-new
Build:     \$(git describe --always --dirty 2>/dev/null || echo unknown) — $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOT
sed -i "s|\\\$(git describe --always --dirty 2>/dev/null \|\| echo unknown)|$(git describe --always --dirty 2>/dev/null || echo unknown)|" "$tree/README-RELEASE.md"

tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
echo "mk-tarball: $OUT/$name.tar.gz ($(du -h "$OUT/$name.tar.gz" | cut -f1))"

if cargo cyclonedx --version >/dev/null 2>&1; then
    # cargo-cyclonedx emits one <override>.json per workspace member next
    # to its manifest, whatever --manifest-path says. Keep the SBOMs of
    # the two shipped daemons (the agent crate also owns nn-admin), drop
    # the rest.
    cargo cyclonedx --format json --all --override-filename "$name.sbom" >/dev/null 2>&1
    for crate in agent watchdog; do
        mv "$crate/$name.sbom.json" "$OUT/$name.$crate.sbom.cdx.json" && echo "mk-tarball: $OUT/$name.$crate.sbom.cdx.json"
    done
    find . -maxdepth 2 -name "$name.sbom.json" -delete
else
    echo "mk-tarball: cargo-cyclonedx not installed — SBOM skipped (cargo install cargo-cyclonedx --locked)"
fi

( cd "$OUT" && sha256sum "$name.tar.gz" $(ls "$name".*.sbom.cdx.json 2>/dev/null) > SHA256SUMS && cat SHA256SUMS )
rm -rf "$tree"
