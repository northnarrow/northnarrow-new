#!/usr/bin/env bash
# The release .rpm on an RPM guest (lot 1.10; runs on the guest, from
# ~/northnarrow, driven by `nn-lab.sh rpm-release-check FROM NEW`): a signed
# released package installed the operator's way, the build under test over
# it in place, a cold boot, then remove and purge with nothing left.
#   release-rpm-check.sh install DIR   the key, the signatures, FROM installed, the units, NEW over it
#   release-rpm-check.sh boot DIR      after the host's cold boot: the units back
#   release-rpm-check.sh remove DIR    rpm -e, uninstall.sh --package --purge, the leftovers
# DIR (a fresh directory of the lab user's, LAB-008) holds from.rpm (signed),
# new.rpm (the build under test, signed or not) and RPM-GPG-KEY-northnarrow.asc;
# the host checked their checksums and the key before. The guest has no
# NorthNarrow installed when `install` starts (nn-lab.sh purges the lab's).
# Every step prints one ok/FAIL line; any FAIL makes the exit status 1.
set -u
cd ~/northnarrow || exit 1
export PATH="$PATH:/usr/sbin:/sbin"
phase=${1:?install | boot | remove}
D=${2:?the directory with from.rpm, new.rpm and the key}
fail=0
ok()    { echo "ok    $*"; }
bad()   { echo "FAIL  $*"; fail=1; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
log=$D/release-rpm-check.log
quiet() { "$@" </dev/null >>"$log" 2>&1; }
has() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }
units() { systemctl is-active northnarrow-agent northnarrow-watchdog 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }
mainpid() { systemctl show -p MainPID --value northnarrow-agent; }
pins() { sudo find /sys/fs/bpf/northnarrow -mindepth 1 -maxdepth 1 2>/dev/null </dev/null | wc -l; }
# the agent's own list of its programs (bpftool's listing is the guard's to
# refuse while the agent runs); our-lsm.sh counts them once it is gone
. deploy/lab/lib/our-lsm.sh
own_ids() { own_ids_of /run/northnarrow/bpf-own-ids; }
# shellcheck disable=SC2086 # the ids, one argument each
own_left() { our_progs_count $1; }
# deploy/install.sh's release key (the one RPM-GPG-KEY-northnarrow.asc holds)
FPR=$(sed -n 's/^RELEASE_KEY_FPR=\([0-9A-F]\{40\}\)$/\1/p' deploy/install.sh)
KEY=/root/northnarrow-admin.key
# everything named like NorthNarrow outside the homes, for the leftover check
inventory() {
    sudo find / -xdev \( -path /proc -o -path /sys -o -path /home -o -path "$D" \) -prune -o \
        \( -iname '*northnarrow*' -o -iname 'nn-admin*' \) -print 2>/dev/null </dev/null | sort
}
status_lines() {
    sudo timeout 60 /usr/bin/nn-admin status --key "$KEY" </dev/null 2>&1 \
        | grep -E '^(posture|sensors|trust level|degradations) *:|^  - [a-z_]+: ' | grep -v 'changed since' | sed "s/^/      $1: /"
}

case "$phase" in
install)
    : > "$log"
    [ -n "$FPR" ] || { bad "the release key's fingerprint (deploy/install.sh RELEASE_KEY_FPR)"; exit 1; }
    if rpm -q northnarrow >/dev/null 2>&1 || [ -e /etc/northnarrow ]; then
        bad "the guest has NorthNarrow installed: nothing to compare the leftovers with"; exit 1
    fi
    inventory > "$D/before.files"; rpm -qa --qf '%{NAME}\n' </dev/null | sort > "$D/before.rpms"
    # the audit log's length now: the AVC check reads what came after
    sudo wc -l < /var/log/audit/audit.log > "$D/audit.lines" 2>/dev/null || echo 0 > "$D/audit.lines"
    fp=$(gpg --show-keys --with-colons "$D/RPM-GPG-KEY-northnarrow.asc" </dev/null 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}')
    check "K the published key is the release key ($fp)" test "$fp" = "$FPR"
    check "  rpm --import" quiet sudo rpm --import "$D/RPM-GPG-KEY-northnarrow.asc"
    k=$(rpm -K "$D/from.rpm" </dev/null 2>&1)
    check "S the released package: ${k##*: }" has "$k" 'digests signatures OK'
    cp "$D/from.rpm" "$D/altered.rpm" \
        && printf 'X' | dd of="$D/altered.rpm" bs=1 seek=$(( $(stat -c %s "$D/from.rpm") - 4096 )) conv=notrunc status=none
    check "  an altered copy fails rpm -K" has "$(rpm -K "$D/altered.rpm" </dev/null 2>&1)" 'NOT OK'
    if quiet sudo timeout 300 dnf install -y -q --setopt=localpkg_gpgcheck=1 "$D/altered.rpm"; then
        bad "  dnf (localpkg_gpgcheck=1) installed the altered copy"
    else ok "  dnf (localpkg_gpgcheck=1) refuses the altered copy"; fi
    rm -f "$D/altered.rpm"
    k=$(rpm -K "$D/new.rpm" </dev/null 2>&1)
    case "$k" in
        *"digests signatures OK"*) ok "  the build under test is signed by the release key" ;;
        *"digests OK"*) ok "  the build under test is unsigned (digests OK; a branch build is signed on a tag only)" ;;
        *) bad "  the build under test: $k" ;;
    esac
    check "1 the released package installed (dnf, localpkg_gpgcheck=1): $(rpm -qp "$D/from.rpm" </dev/null 2>/dev/null)" \
        quiet sudo timeout 600 dnf install -y -q --setopt=localpkg_gpgcheck=1 "$D/from.rpm"
    check "  nothing started by a first install ($(units))" test "$(units)" != "active active"
    check "  admin keypair bootstrapped" sudo test -f /etc/northnarrow/admin.pub -a -s "$KEY"
    check "  install manifest provenance=package" sudo grep -q '"provenance": "package"' /etc/northnarrow/install-manifest.json
    quiet sudo systemctl enable --now northnarrow-agent; sleep 5
    quiet sudo systemctl enable --now northnarrow-watchdog; sleep 30
    check "  enabled and started: units $(units), $(pins) pins, $(echo "$(own_ids)" | wc -w) own BPF ids" test "$(units)" = "active active"
    status_lines released
    p1=$(mainpid)
    id1=$(sudo sha256sum /etc/northnarrow/agent_id /etc/northnarrow/admin.pub </dev/null | sha256sum)
    if quiet sudo timeout 300 rpm -U --replacepkgs "$D/new.rpm"; then
        bad "2 the build under test went in without NN_GRANT_KEY"
    else ok "2 without NN_GRANT_KEY the in-place upgrade is refused"; fi
    check "  agent untouched (pid $(mainpid))" test "$(mainpid)" = "$p1" -a "$(units)" = "active active"
    # the same version-release until the next release: --replacepkgs
    check "  the build under test in place (rpm -U --replacepkgs, NN_GRANT_KEY)" \
        quiet sudo timeout 900 env NN_GRANT_KEY="$KEY" rpm -U --replacepkgs "$D/new.rpm"
    sleep 20
    check "  units restarted (pid $p1 -> $(mainpid)), $(units)" test "$(mainpid)" != "$p1" -a "$(units)" = "active active"
    check "  keys and agent_id kept" test "$(sudo sha256sum /etc/northnarrow/agent_id /etc/northnarrow/admin.pub </dev/null | sha256sum)" = "$id1"
    want=$(rpm -qp --dump "$D/new.rpm" </dev/null 2>/dev/null | awk '$1 == "/usr/bin/northnarrow-agent" {print $4}')
    check "  /usr/bin/northnarrow-agent is the build under test's" test -n "$want" -a "$(sudo sha256sum /usr/bin/northnarrow-agent </dev/null | cut -d' ' -f1)" = "$want"
    check "  rpm -V northnarrow" quiet rpm -V northnarrow
    integrity() {
        sudo journalctl --namespace northnarrow -u northnarrow-agent --since '-3 min' -o cat --no-pager </dev/null 2>/dev/null \
            | sed 's/\x1b\[[0-9;]*m//g' \
            | grep -q 'binary integrity verified against the install manifest provenance="package"'
    }
    check "  binary integrity verified (package manifest)" integrity
    status_lines upgraded
    ;;
boot)
    for _ in $(seq 1 60); do systemctl is-active -q northnarrow-agent && break; sleep 2; done
    check "B after a cold boot: units $(units), $(pins) pins, $(echo "$(own_ids)" | wc -w) own BPF ids" \
        test "$(units)" = "active active" -a "$(pins)" -gt 0 -a -n "$(own_ids)"
    sleep 30
    check "  30 s later: units $(units), $(pins) pins" test "$(units)" = "active active" -a "$(pins)" -gt 0
    status_lines boot
    ;;
remove)
    ids=$(own_ids)
    if quiet sudo timeout 300 rpm -e northnarrow; then
        bad "3 rpm -e went through without NN_GRANT_KEY"
    else ok "3 without NN_GRANT_KEY rpm -e is refused"; fi
    check "  agent untouched ($(units))" test "$(units)" = "active active"
    check "  rpm -e (NN_GRANT_KEY)" quiet sudo timeout 600 env NN_GRANT_KEY="$KEY" rpm -e northnarrow
    sleep 3
    check "  units stopped ($(units))" test "$(units)" != "active active"
    check "  its BPF programs gone (left: $(own_left "$ids"))" test "$(own_left "$ids")" = 0
    check "  binaries removed" test ! -e /usr/bin/northnarrow-agent -a ! -e /usr/bin/nn-admin
    check "  /etc/northnarrow kept" sudo test -f /etc/northnarrow/admin.pub
    # the host retired: uninstall.sh's package mode, from the tree (§6 of the operator guide)
    check "4 uninstall.sh --package --purge" quiet sudo BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system ./deploy/uninstall.sh --package --purge --yes
    check "  rpm -q northnarrow: not installed" sh -c '! rpm -q northnarrow >/dev/null 2>&1'
    left=$(comm -13 "$D/before.files" <(inventory) | head -12 | tr '\n' ' ')
    check "  no file named NorthNarrow left ${left:+($left)}" test -z "$left"
    check "  no pin root" sh -c '! sudo test -e /sys/fs/bpf/northnarrow'
    check "  no BPF program of ours by name (left: $(our_progs_count))" test "$(our_progs_count)" = 0
    check "  no nft table of ours" sh -c '! sudo nft list tables 2>/dev/null </dev/null | grep -qi northnarrow'
    check "  no iptables chain of ours" sh -c '! sudo iptables-save 2>/dev/null </dev/null | grep -qiE "northnarrow|^:NN"'
    check "  no unit of ours known to systemd" sh -c '! systemctl list-unit-files --no-legend 2>/dev/null </dev/null | grep -qi northnarrow'
    echo "      packages the round added: $(comm -13 "$D/before.rpms" <(rpm -qa --qf '%{NAME}\n' </dev/null | sort) | tr '\n' ' ')(the imported key: rpm -e gpg-pubkey-$(echo "$FPR" | cut -c33- | tr 'A-F' 'a-f')-…)"
    ;;
*) echo "usage: release-rpm-check.sh install|boot|remove DIR" >&2; exit 2 ;;
esac
# SELinux (the RHEL family enforces it): no denial logged since `install` began
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != Disabled ]; then
    n0=$(cat "$D/audit.lines" 2>/dev/null || echo 0)
    avc=$(sudo tail -n "+$((n0 + 1))" /var/log/audit/audit.log </dev/null 2>/dev/null | grep 'type=AVC' || true)
    check "  SELinux $(getenforce): no AVC denial since the round began ($(grep -c . <<<"$avc"))" test -z "$avc"
    [ -z "$avc" ] || sed 's/.*avc: *//' <<<"$avc" | cut -c1-200 | sort | uniq -c | head -5 | sed 's/^/      avc: /'
fi
[ "$fail" = 0 ] && echo "release-rpm-check $phase: PASS" || echo "release-rpm-check $phase: FAIL (log: $log)"
exit "$fail"
