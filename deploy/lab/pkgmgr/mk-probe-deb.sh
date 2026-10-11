#!/usr/bin/env bash
# Builds nn-pkgprobe_1.0_all.deb: a harmless package whose files have every
# persistence shape the FIM rules watch (unit, timer, cron.d drop-in, setuid
# binary, PAM module path, kernel module path) and whose maintainer scripts do
# what real packages do (enable the unit, create a system user). Installing and
# removing it under the agent shows whether the package manager survives.
# Usage: mk-probe-deb.sh <out-dir>     (runs on a Debian-family guest)
set -euo pipefail
out=${1:?usage: mk-probe-deb.sh <out-dir>}
multiarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
install -d "$root/DEBIAN" "$root/usr/lib/systemd/system" "$root/etc/cron.d" \
    "$root/usr/lib/nn-pkgprobe" "$root/usr/lib/$multiarch/security" \
    "$root/usr/lib/modules/$(uname -r)/extra"
cat > "$root/usr/lib/systemd/system/nn-pkgprobe.service" <<'UNIT'
[Unit]
Description=NorthNarrow package-manager probe (does nothing)
[Service]
Type=oneshot
ExecStart=/bin/true
[Install]
WantedBy=multi-user.target
UNIT
cat > "$root/usr/lib/systemd/system/nn-pkgprobe.timer" <<'UNIT'
[Unit]
Description=NorthNarrow package-manager probe timer (does nothing)
[Timer]
OnCalendar=yearly
[Install]
WantedBy=timers.target
UNIT
printf '# NorthNarrow probe: never runs anything useful\n@yearly root /bin/true\n' > "$root/etc/cron.d/nn-pkgprobe"
cp /bin/true "$root/usr/lib/nn-pkgprobe/nn-pkgprobe-suid"
chmod 4755 "$root/usr/lib/nn-pkgprobe/nn-pkgprobe-suid"
printf 'not a real PAM module\n' > "$root/usr/lib/$multiarch/security/pam_nnpkgprobe.so"
printf 'not a real kernel module\n' > "$root/usr/lib/modules/$(uname -r)/extra/nn_pkgprobe.ko"
cat > "$root/DEBIAN/control" <<'CTL'
Package: nn-pkgprobe
Version: 1.0
Architecture: all
Maintainer: NorthNarrow lab <lab@invalid>
Description: NorthNarrow lab probe for package-manager false positives
CTL
cat > "$root/DEBIAN/postinst" <<'SH'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    getent passwd nn-pkgprobe >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin nn-pkgprobe
    deb-systemd-helper enable nn-pkgprobe.service nn-pkgprobe.timer >/dev/null || true
    systemctl daemon-reload || true
fi
SH
cat > "$root/DEBIAN/postrm" <<'SH'
#!/bin/sh
set -e
if [ "$1" = purge ] || [ "$1" = remove ]; then
    deb-systemd-helper purge nn-pkgprobe.service nn-pkgprobe.timer >/dev/null || true
    getent passwd nn-pkgprobe >/dev/null && userdel nn-pkgprobe || true
    systemctl daemon-reload || true
fi
SH
chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/postrm"
mkdir -p "$out"
dpkg-deb --root-owner-group --build "$root" "$out/nn-pkgprobe_1.0_all.deb" >/dev/null
echo "$out/nn-pkgprobe_1.0_all.deb"
