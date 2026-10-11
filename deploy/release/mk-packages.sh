#!/usr/bin/env bash
# Build the NorthNarrow distribution packages from a finished
# `cargo xtask build --release` (the same inputs as mk-tarball.sh):
#   <out>/northnarrow_<ver>-<rel>_amd64.deb     (dpkg-deb)
#   <out>/northnarrow-<ver>-<rel>.x86_64.rpm    (rpmbuild)
#
# Layout (review 26):
#   /usr/bin/{northnarrow-agent,northnarrow-watchdog,nn-admin}
#   /usr/lib/systemd/system/northnarrow-{agent,watchdog}.service  (rewritten for /usr/bin)
#   /usr/share/northnarrow/   data tree `install.sh --package-configure` reads:
#                             deploy/{install,uninstall}.sh, deploy/systemd/, configs/,
#                             and the eBPF object the install manifest hashes
#   /usr/share/doc/northnarrow/
# Nothing under /etc is owned by the package: install.sh seeds
# /etc/northnarrow on the first install and never overwrites an operator copy.
#
# The maintainer scripts (deploy/release/pkg/) drive install.sh and
# uninstall.sh in their package modes. The pre-unpack and post-removal hooks
# run when the package's own files are not on disk, so each carries an
# inlined copy of the script it needs (@INSTALL_SH@ / @UNINSTALL_SH@).
#
# Usage: deploy/release/mk-packages.sh [out-dir]       (default: dist/)
#   NN_PKG_FORMATS="deb rpm"   formats to build (rpm needs rpmbuild)
#   NN_PKG_RELEASE=1           package release number
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$REPO_ROOT/dist"}
FORMATS=${NN_PKG_FORMATS:-"deb rpm"}
REL=${NN_PKG_RELEASE:-1}
MAINTAINER="NorthNarrow <279109805+northnarrow@users.noreply.github.com>"
HOMEPAGE="https://github.com/northnarrow/northnarrow-new"
SUMMARY="NorthNarrow XDR: eBPF endpoint detection and response for Linux"
cd "$REPO_ROOT"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
ver=$(grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)"/\1/')
ebpf=agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf
for f in target/release/northnarrow-agent target/release/northnarrow-watchdog target/release/nn-admin \
         "$ebpf" "$ebpf.buildhash"; do
    [[ -f "$f" ]] || { echo "mk-packages: missing $f — run \`cargo xtask build --release\` first" >&2; exit 1; }
done
# Same guard install.sh applies to a tree: the agent must embed the stamped object.
[[ "$ebpf.buildhash" -nt target/release/northnarrow-agent ]] \
    && { echo "mk-packages: agent binary older than the eBPF stamp — rebuild with \`cargo xtask build --release\`" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/root"

# ── payload ───────────────────────────────────────────────────────────
install -d "$root/usr/bin" "$root/usr/lib/systemd/system" \
    "$root/usr/share/northnarrow/deploy/systemd" "$root/usr/share/northnarrow/$(dirname "$ebpf")" \
    "$root/usr/share/doc/northnarrow/operator"
install -m 0755 target/release/northnarrow-agent target/release/northnarrow-watchdog target/release/nn-admin \
    "$root/usr/bin/"
for u in northnarrow-agent northnarrow-watchdog; do
    sed 's#/usr/local/bin/#/usr/bin/#g' "deploy/systemd/$u.service" > "$root/usr/lib/systemd/system/$u.service"
    chmod 0644 "$root/usr/lib/systemd/system/$u.service"
done
install -m 0755 deploy/install.sh deploy/uninstall.sh "$root/usr/share/northnarrow/deploy/"
install -m 0644 deploy/systemd/* "$root/usr/share/northnarrow/deploy/systemd/"
cp -r configs "$root/usr/share/northnarrow/configs"
install -m 0644 "$ebpf" "$ebpf.buildhash" "$root/usr/share/northnarrow/$(dirname "$ebpf")/"
install -m 0644 LICENSE NOTICES.md CHANGELOG.md "$root/usr/share/doc/northnarrow/"
install -m 0644 docs/operator/*.md "$root/usr/share/doc/northnarrow/operator/"
[[ -d LICENSES ]] && cp -r LICENSES "$root/usr/share/doc/northnarrow/LICENSES"
find "$root" -type d -exec chmod 0755 {} +
find "$root/usr/share" -type f -exec chmod go-w {} +

# ── maintainer scripts ────────────────────────────────────────────────
# Inline install.sh / uninstall.sh where the template says so.
render() {
    awk -v ins=deploy/install.sh -v unins=deploy/uninstall.sh '
        /^@INSTALL_SH@$/   { while ((getline l < ins) > 0) print l; close(ins); next }
        /^@UNINSTALL_SH@$/ { while ((getline l < unins) > 0) print l; close(unins); next }
        { print }' "$1" > "$2"
    chmod 0755 "$2"
}
mkdir -p "$work/scripts"
for s in preinst postinst prerm postrm; do
    render "deploy/release/pkg/$s.sh" "$work/scripts/$s"
done

built=()
# ── .deb ──────────────────────────────────────────────────────────────
if [[ " $FORMATS " == *" deb "* ]]; then
    deb="$work/deb"
    cp -a "$root" "$deb"
    install -d -m 0755 "$deb/DEBIAN"
    for s in preinst postinst prerm postrm; do install -m 0755 "$work/scripts/$s" "$deb/DEBIAN/$s"; done
    (cd "$deb" && find usr -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum) > "$deb/DEBIAN/md5sums"
    cat > "$deb/DEBIAN/control" <<EOT
Package: northnarrow
Version: ${ver}-${REL}
Architecture: amd64
Maintainer: ${MAINTAINER}
Section: admin
Priority: optional
Depends: libc6 (>= 2.34), systemd
Installed-Size: $(du -sk "$root" | cut -f1)
Homepage: ${HOMEPAGE}
Description: ${SUMMARY}
 Rust + eBPF agent with an LSM-backed anti-tamper layer, a watchdog and the
 nn-admin operator tool. Upgrades and removal stop the running agent through
 the trusted-installer window: set NN_GRANT_KEY to a key with that role, or
 open the window with nn-admin first.
EOT
    pkg="$OUT/northnarrow_${ver}-${REL}_amd64.deb"
    dpkg-deb --root-owner-group -Zxz --build "$deb" "$pkg" >/dev/null
    built+=("$pkg")
fi

# ── .rpm ──────────────────────────────────────────────────────────────
if [[ " $FORMATS " == *" rpm "* ]]; then
    command -v rpmbuild >/dev/null || { echo "mk-packages: rpmbuild not found (apt-get install rpm / dnf install rpm-build)" >&2; exit 1; }
    top="$work/rpmbuild"
    mkdir -p "$top"/{SPECS,BUILD,RPMS,SOURCES,SRPMS}
    # scriptlet bodies go into the spec: escape rpm's macro character
    body() { sed 's/%/%%/g' "$work/scripts/$1"; }
    {
        cat <<EOT
Name:           northnarrow
Version:        ${ver}
Release:        ${REL}
Summary:        ${SUMMARY}
License:        Apache-2.0
URL:            ${HOMEPAGE}
# glibc 2.34 is the hard floor; newer symbols are weak (Rust std probes them),
# so rpm's automatic requires would over-constrain the package.
AutoReqProv:    no
Requires:       glibc >= 2.34
Requires:       systemd
%global debug_package %{nil}
%global __os_install_post %{nil}

%description
Rust + eBPF agent with an LSM-backed anti-tamper layer, a watchdog and the
nn-admin operator tool. Upgrades and removal stop the running agent through
the trusted-installer window: set NN_GRANT_KEY to a key with that role, or
open the window with nn-admin first.

%install
cp -a ${root}/. %{buildroot}/

%pre -p /bin/sh
$(body preinst)

%post -p /bin/sh
$(body postinst)

%preun -p /bin/sh
$(body prerm)

%postun -p /bin/sh
$(body postrm)

%files
%defattr(-,root,root,-)
/usr/bin/northnarrow-agent
/usr/bin/northnarrow-watchdog
/usr/bin/nn-admin
/usr/lib/systemd/system/northnarrow-agent.service
/usr/lib/systemd/system/northnarrow-watchdog.service
/usr/share/northnarrow
%doc /usr/share/doc/northnarrow
EOT
    } > "$top/SPECS/northnarrow.spec"
    rpmbuild --quiet --define "_topdir $top" -bb "$top/SPECS/northnarrow.spec"
    pkg="$OUT/northnarrow-${ver}-${REL}.x86_64.rpm"
    cp "$top/RPMS/x86_64/northnarrow-${ver}-${REL}.x86_64.rpm" "$pkg"
    built+=("$pkg")
fi

(( ${#built[@]} )) || { echo "mk-packages: nothing built (NN_PKG_FORMATS=$FORMATS)" >&2; exit 1; }
printf '%s\n' "${built[@]}"
