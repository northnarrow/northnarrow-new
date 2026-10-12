#!/usr/bin/env bash
# RPM twin of mk-probe-deb.sh: nn-pkgprobe-1.0-1.noarch.rpm with the same
# persistence shapes (unit, timer, cron.d drop-in, setuid binary, PAM module
# path, kernel module path) and scriptlets that enable the unit and create a
# system user. Needs rpmbuild (`dnf install rpm-build`).
# Usage: mk-probe-rpm.sh <out-dir>     (runs on a RHEL-family guest)
set -euo pipefail
out=${1:?usage: mk-probe-rpm.sh <out-dir>}
command -v rpmbuild >/dev/null || { echo "mk-probe-rpm: rpmbuild missing (dnf install rpm-build)" >&2; exit 1; }
top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
kver=$(uname -r)
mkdir -p "$top"/{SPECS,BUILD,RPMS,SOURCES,SRPMS,BUILDROOT}
cat > "$top/SPECS/nn-pkgprobe.spec" <<SPEC
Name:           nn-pkgprobe
Version:        1.0
Release:        1
Summary:        NorthNarrow lab probe for package-manager false positives
License:        Apache-2.0
BuildArch:      noarch
%global debug_package %{nil}
%global __brp_check_rpaths %{nil}
# The setuid probe is a copy of /bin/true (an ELF): RHEL 9's rpmbuild
# refuses arch-dependent files in a noarch package unless told not to.
%global _binaries_in_noarch_packages_terminate_build 0

%description
Harmless files in every persistence shape the FIM rules watch.

%install
install -d %{buildroot}/usr/lib/systemd/system %{buildroot}/etc/cron.d \\
    %{buildroot}/usr/lib/nn-pkgprobe %{buildroot}/usr/lib64/security \\
    %{buildroot}/usr/lib/modules/${kver}/extra
printf '[Unit]\nDescription=NorthNarrow package-manager probe (does nothing)\n[Service]\nType=oneshot\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n' > %{buildroot}/usr/lib/systemd/system/nn-pkgprobe.service
printf '[Unit]\nDescription=NorthNarrow package-manager probe timer\n[Timer]\nOnCalendar=yearly\n[Install]\nWantedBy=timers.target\n' > %{buildroot}/usr/lib/systemd/system/nn-pkgprobe.timer
printf '# NorthNarrow probe\n@yearly root /bin/true\n' > %{buildroot}/etc/cron.d/nn-pkgprobe
cp /bin/true %{buildroot}/usr/lib/nn-pkgprobe/nn-pkgprobe-suid
printf 'not a real PAM module\n' > %{buildroot}/usr/lib64/security/pam_nnpkgprobe.so
printf 'not a real kernel module\n' > %{buildroot}/usr/lib/modules/${kver}/extra/nn_pkgprobe.ko

%post
getent passwd nn-pkgprobe >/dev/null || useradd --system --no-create-home --shell /sbin/nologin nn-pkgprobe
systemctl enable nn-pkgprobe.service nn-pkgprobe.timer >/dev/null 2>&1 || :
systemctl daemon-reload || :

%postun
systemctl disable nn-pkgprobe.service nn-pkgprobe.timer >/dev/null 2>&1 || :
getent passwd nn-pkgprobe >/dev/null && userdel nn-pkgprobe || :
systemctl daemon-reload || :

%files
/usr/lib/systemd/system/nn-pkgprobe.service
/usr/lib/systemd/system/nn-pkgprobe.timer
/etc/cron.d/nn-pkgprobe
%attr(4755,root,root) /usr/lib/nn-pkgprobe/nn-pkgprobe-suid
/usr/lib64/security/pam_nnpkgprobe.so
/usr/lib/modules/${kver}/extra/nn_pkgprobe.ko
SPEC
rpmbuild --define "_topdir $top" -bb "$top/SPECS/nn-pkgprobe.spec" >/dev/null
mkdir -p "$out"
cp "$top"/RPMS/noarch/nn-pkgprobe-1.0-1.noarch.rpm "$out/"
echo "$out/nn-pkgprobe-1.0-1.noarch.rpm"
