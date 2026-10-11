#!/usr/bin/env bash
# Release check (runs on the guest as the lab user): the SAME tarball CI built
# and attested, installed and verified on this distribution (Tappa 10.8 demo).
# Expects /tmp/nn-release/{northnarrow-<ver>-x86_64-linux.tar.gz,SHA256SUMS}
# and the lab's source install stopped (nn-lab.sh release-check does both).
set -u
fail=0
ok()  { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fail=1; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
journal() {
    sudo journalctl --namespace northnarrow -u northnarrow-agent --since "$T0" -o cat --no-pager \
        | sed 's/\x1b\[[0-9;]*m//g'
}

sudo rm -rf /opt/nn-release && sudo mkdir -p /opt/nn-release && sudo cp /tmp/nn-release/* /opt/nn-release/
cd /opt/nn-release || exit 1
tgz=$(ls northnarrow-*-x86_64-linux.tar.gz | head -1)
echo "== $tgz on $(. /etc/os-release; echo "$PRETTY_NAME") / $(uname -r)"
check "tarball matches SHA256SUMS" bash -c "sha256sum -c --ignore-missing SHA256SUMS >/dev/null"
sudo tar -xzf "$tgz" || { bad "extract"; exit 1; }
tree=/opt/nn-release/${tgz%.tar.gz}
check "release binaries run here (glibc)" "$tree/target/release/northnarrow-agent" --version
T0=$(date "+%F %T")
check "install.sh verifies and installs the tree" \
    bash -c "cd '$tree' && sudo ./deploy/install.sh --tarball '/opt/nn-release/$tgz' --sums /opt/nn-release/SHA256SUMS >/tmp/nn-release-install.log 2>&1"
check "  install manifest provenance=checksums" sudo grep -q '"provenance": "checksums"' /etc/northnarrow/install-manifest.json
sudo systemctl daemon-reload
sudo systemctl start northnarrow-agent; sleep 3; sudo systemctl start northnarrow-watchdog; sleep 25
check "units active" test "$(systemctl is-active northnarrow-agent northnarrow-watchdog | tr '\n' ' ')" = "active active "
check "binary integrity verified (checksums manifest)" bash -c "$(declare -f journal); T0='$T0'; journal | grep -q 'binary integrity verified against the install manifest provenance=\"checksums\"'"
check "every deny hook attached" bash -c "$(declare -f journal); T0='$T0'; journal | grep -q 'all LSM hooks attached deny_attached=9'"
check "telemetry probe armed" bash -c "$(declare -f journal); T0='$T0'; journal | grep -q 'telemetry probe armed'"
# a detection end to end: exec from /tmp (R001)
cp /bin/true /tmp/nn-release-probe && chmod +x /tmp/nn-release-probe
/tmp/nn-release-probe 2>/dev/null; sleep 3; rm -f /tmp/nn-release-probe
check "R001 fires on an exec from /tmp" bash -c "sudo tail -n 50 /var/lib/northnarrow/detections/detections.jsonl | grep -q 'R001_ExecFromTmp'"
[ "$fail" = 0 ] && echo "release-check: PASS" || echo "release-check: FAIL (install log: /tmp/nn-release-install.log)"
exit "$fail"
