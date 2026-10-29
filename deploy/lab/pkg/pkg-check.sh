#!/usr/bin/env bash
# Package lifecycle check (runs on the guest, from ~/northnarrow after
# `nn-lab.sh build`). Uses the host's native format: .deb with dpkg, .rpm
# with rpm. Every step prints one line; any FAIL makes the exit status 1.
#   1. install over the running install.sh layout (migration)
#   2. upgrade to a newer package release (trusted-installer window, the lab
#      key in NN_GRANT_KEY: a key left on the host is never used on its own,
#      external audit DEP-001)
#   3. upgrade with an unusable key: refused before any file changes
#   4. remove (the lab key in NN_GRANT_KEY): agent stopped, hooks detached,
#      /etc/northnarrow kept
#   5. purge (deb) / config + state cleanup (rpm)
#   6. fresh install: keys bootstrapped, nothing started; start; binary
#      integrity verified against a "package" install manifest
#   7. final cleanup so `nn-lab.sh install` can put the lab layout back
# On rpm guests, step S first checks the release signing path
# (deploy/release/sign-rpm.sh selftest). Step D checks the nftables
# dependency (lab PR 165).
set -u
cd ~/northnarrow
fail=0
log=/tmp/nn-pkg-check.log; : > "$log"
ok()   { echo "ok    $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
quiet() { "$@" >>"$log" 2>&1; }
units() { systemctl is-active northnarrow-agent northnarrow-watchdog 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }
mainpid() { systemctl show -p MainPID --value northnarrow-agent; }
lsm() { sudo bpftool prog show 2>/dev/null | grep -c " lsm " || true; }
# External audit DEP-006: the agent lists its own program ids; another
# product's LSM programs (bpftrace in the lab) are not NorthNarrow's hooks.
own_ids() { sudo awk '$1 ~ /^[0-9]+$/ {print $1}' /run/northnarrow/bpf-own-ids 2>/dev/null | tr '\n' ' '; }
own_loaded() {
    local id n=0
    [ -n "$1" ] || { lsm; return; }   # an agent older than the list: every LSM program
    for id in $1; do sudo bpftool prog show id "$id" >/dev/null 2>&1 && n=$((n + 1)); done
    echo "$n"
}
# the lab's admin key: /root/northnarrow-admin.key since external audit
# DEP-001, /etc/northnarrow/admin.key on a guest installed before
labkey() { for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; return; }; done; }

# the native format: Debian family -> .deb (even with the rpm tool installed)
if [ -e /etc/debian_version ]; then fmt=deb; else fmt=rpm; fi
if [ "$fmt" = rpm ] && ! command -v rpmbuild >/dev/null 2>&1; then
    sudo dnf install -y rpm-build >/dev/null 2>&1 || { bad "dnf install rpm-build"; exit 1; }
fi
# External audit LAB-008: the packages are installed as root from here: a
# fresh directory of the lab user's, not a fixed /tmp path another user could
# have created first to swap a package before the install.
PKGDIR=$(mktemp -d) || { bad "mktemp"; exit 1; }
trap 'rm -rf "$PKGDIR"' EXIT
# Lab PR 268: the lab build (test-privileged,debug-trigger) packed on purpose;
# mk-packages.sh refuses it otherwise.
for r in 1 2 3; do
    NN_PKG_LAB_FEATURES=1 NN_PKG_FORMATS=$fmt NN_PKG_RELEASE=$r deploy/release/mk-packages.sh "$PKGDIR" >/dev/null || { bad "build release $r"; exit 1; }
done
pkg() { ls "$PKGDIR"/* | grep -E "[-_]0?[0-9.]+-$1[._]" | head -1; }
# Lab follow-up (lab PR 165): the per-process outbound block needs nft. The
# package declares it (on the .deb a Pre-Depends: dpkg refuses before the
# pre-unpack hook stops the agent); dpkg -i and rpm -U do not fetch it, so
# the guest must have it (nn-lab.sh install provisions it).
if [ "$fmt" = deb ]; then
    check "D package pre-depends on nftables" sh -c "dpkg-deb -f '$(pkg 1)' Pre-Depends | grep -qw nftables"
else
    check "D package requires nftables" sh -c "rpm -qpR '$(pkg 1)' | grep -qx nftables"
fi
PATH="$PATH:/usr/sbin:/sbin" command -v nft >/dev/null 2>&1 \
    || { bad "  nft on the guest (dpkg -i / rpm -U refuse without it: run nn-lab.sh install first)"; exit 1; }
# External audit DEP-008: the signing path the release workflow uses on a
# tag, checked with this distribution's rpm and throwaway keys on a copy:
# signed accepted; unsigned, signed by another key, altered refused.
if [ "$fmt" = rpm ]; then
    command -v rpmsign >/dev/null 2>&1 || sudo dnf install -y rpm-sign >/dev/null 2>&1 || bad "dnf install rpm-sign"
    check "S rpm signature: signed accepted; unsigned, other key, altered refused" quiet deploy/release/sign-rpm.sh selftest "$(pkg 1)"
fi
if [ "$fmt" = deb ]; then
    # apt's timers (unattended-upgrades) take the dpkg lock now and then: a
    # purge once failed on "dpkg frontend lock was locked by another process"
    waitlock() { local i; for i in $(seq 1 120); do sudo fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1 || return 0; sleep 2; done; }
    pinstall() { waitlock; sudo env ${2:+NN_GRANT_KEY=$2} dpkg -i "$1"; }
    premove()  { waitlock; sudo env NN_GRANT_KEY="$(labkey)" dpkg -r northnarrow; }
    ppurge()   { waitlock; sudo env NN_GRANT_KEY="$(labkey)" dpkg -P northnarrow; }
    pver()     { dpkg-query -W -f='${Version}' northnarrow 2>/dev/null; }
else
    pinstall() { sudo env ${2:+NN_GRANT_KEY=$2} rpm -U --replacepkgs "$1"; }
    premove()  { sudo env NN_GRANT_KEY="$(labkey)" rpm -e northnarrow; }
    ppurge()   { sudo BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system ./deploy/uninstall.sh --package --purge --yes; }
    pver()     { rpm -q --qf '%{VERSION}-%{RELEASE}' northnarrow 2>/dev/null; }
fi

echo "== $fmt lifecycle (units before: $(units))"
before=$(units)
# External audit DEP-001: without NN_GRANT_KEY the running install cannot be
# stopped (the key on the host is not picked up on its own any more)
if pinstall "$(pkg 1)" >>"$log" 2>&1; then bad "0 install without NN_GRANT_KEY over a running install was accepted"; else ok "0 install without NN_GRANT_KEY over a running install refused"; fi
check "  units untouched ($(units))" test "$(units)" = "$before"
check "1 install release 1 over the install.sh layout" quiet pinstall "$(pkg 1)" "$(labkey)"
check "  units unchanged ($before)" test "$(units)" = "$before"
# canonical path: Debian's systemd reports the merged-/usr unit dir as /lib/systemd/system
check "  unit loaded from /usr/lib/systemd/system" test "$(readlink -f "$(systemctl show -p FragmentPath --value northnarrow-agent)")" = /usr/lib/systemd/system/northnarrow-agent.service
check "  install.sh layout removed" test ! -e /usr/local/bin/northnarrow-agent -a ! -e /etc/systemd/system/northnarrow-agent.service
check "  install manifest provenance=package" sudo grep -q '"provenance": "package"' /etc/northnarrow/install-manifest.json
[ "$(units)" = "active active" ] || { sudo systemctl start northnarrow-agent; sleep 3; sudo systemctl start northnarrow-watchdog; sleep 15; }
p1=$(mainpid)
check "2 upgrade to release 2" quiet pinstall "$(pkg 2)" "$(labkey)"
sleep 5
check "  units active after the upgrade" test "$(units)" = "active active"
check "  agent restarted (pid $p1 -> $(mainpid))" test "$(mainpid)" != "$p1"
check "  version $(pver)" test "$(pver)" = "0.0.1-2"
p2=$(mainpid)
if pinstall "$(pkg 3)" /nonexistent/key >>"$log" 2>&1; then bad "3 upgrade with an unusable key was accepted"; else ok "3 upgrade with an unusable key refused"; fi
sleep 3
check "  agent untouched (pid $(mainpid))" test "$(mainpid)" = "$p2" -a "$(units)" = "active active"
check "  version still 0.0.1-2" test "$(pver)" = "0.0.1-2"
ids=$(own_ids)
check "4 remove" quiet premove
check "  units gone ($(units))" test "$(units)" != "active active"
check "  LSM hooks detached (own ids still loaded: $(own_loaded "$ids"))" test "$(own_loaded "$ids")" = 0
check "  binaries removed" test ! -e /usr/bin/northnarrow-agent
check "  /etc/northnarrow kept" sudo test -f /etc/northnarrow/admin.pub
check "5 purge" quiet ppurge
check "  config and state removed" sudo test ! -e /etc/northnarrow -a ! -e /var/lib/northnarrow
check "6 fresh install of release 2" quiet pinstall "$(pkg 2)"
check "  admin keypair bootstrapped" sudo test -f /etc/northnarrow/admin.pub -a -s /root/northnarrow-admin.key
check "  no private key in /etc/northnarrow" sudo test ! -e /etc/northnarrow/admin.key
check "  nothing started ($(units))" test "$(units)" != "active active"
sudo systemctl start northnarrow-agent; sleep 3; sudo systemctl start northnarrow-watchdog; sleep 20
check "  units start ($(units))" test "$(units)" = "active active"
integrity() {
    sudo journalctl --namespace northnarrow -u northnarrow-agent --since '-2 min' -o cat --no-pager \
        | sed 's/\x1b\[[0-9;]*m//g' \
        | grep -q 'binary integrity verified against the install manifest provenance="package"'
}
check "  binary integrity verified (package manifest)" integrity
check "7 cleanup: remove + purge" quiet bash -c "$(declare -f waitlock labkey premove ppurge); premove && ppurge"
[ "$fail" = 0 ] && echo "pkg-check: PASS" || echo "pkg-check: FAIL (log: $log)"
exit "$fail"
