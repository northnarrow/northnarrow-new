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
# External audit LAB-020 (NN-AUD-410, lab PR 206): an agent line counts
# only as an event of the running agent itself — its unit's stdout and pid,
# the message at the start of the line (deploy/lab/lib/lab-records.py,
# copied next to the tarball by nn-lab.sh) — never as text in another line
# (a file named like it, run from /tmp by any user, is logged in a VERDICT).
RECORDS=${NN_LAB_RECORDS:-/tmp/nn-release/lab-records.py}
agent_event() {   # <level> <message prefix>
    local pid
    pid=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null) || return 1
    sudo journalctl --namespace northnarrow -u northnarrow-agent _PID="$pid" --since "$T0" -o json --no-pager 2>/dev/null \
        | python3 -I "$RECORDS" journal northnarrow-agent.service "$pid" "$1" "$2" >/dev/null
}
[ -r "$RECORDS" ] || { bad "lab-records.py not found at $RECORDS (nn-lab.sh release-check copies it)"; exit 1; }

sudo rm -rf /opt/nn-release && sudo mkdir -p /opt/nn-release && sudo cp /tmp/nn-release/* /opt/nn-release/
cd /opt/nn-release || exit 1
tgz=$(ls northnarrow-*-x86_64-linux.tar.gz | head -1)
echo "== $tgz on $(. /etc/os-release; echo "$PRETTY_NAME") / $(uname -r)"
# External audit LAB-010: `sha256sum -c --ignore-missing` passed when ANY
# listed file matched, so the tarball itself could go unchecked, and it was
# then extracted as root with its owners and modes. Its own line now, exactly
# one, checked before anything is extracted; extracted as plain files.
sums_line=$(awk -v f="$tgz" '{ n = $2; sub(/^\*/, "", n) } NF == 2 && n == f' SHA256SUMS)
if [ -z "$sums_line" ] || [ "$(printf '%s\n' "$sums_line" | wc -l)" != 1 ]; then
    bad "tarball matches SHA256SUMS (no single line for $tgz)"; exit 1
fi
check "tarball matches SHA256SUMS" bash -c 'printf "%s\n" "$1" | sha256sum -c --strict - >/dev/null' _ "$sums_line"
[ "$fail" = 0 ] || { bad "tarball not verified: nothing extracted"; exit 1; }
sudo tar --no-same-owner --no-same-permissions -xzf "$tgz" || { bad "extract"; exit 1; }
tree=/opt/nn-release/${tgz%.tar.gz}
check "release binaries run here (glibc)" "$tree/target/release/northnarrow-agent" --version
T0=$(date "+%F %T")
check "install.sh verifies and installs the tree" \
    bash -c "cd '$tree' && sudo ./deploy/install.sh --tarball '/opt/nn-release/$tgz' --sums /opt/nn-release/SHA256SUMS >/tmp/nn-release-install.log 2>&1"
check "  install manifest provenance=checksums" sudo grep -q '"provenance": "checksums"' /etc/northnarrow/install-manifest.json
sudo systemctl daemon-reload
sudo systemctl start northnarrow-agent; sleep 3; sudo systemctl start northnarrow-watchdog; sleep 25
check "units active" test "$(systemctl is-active northnarrow-agent northnarrow-watchdog | tr '\n' ' ')" = "active active "
check "binary integrity verified (checksums manifest)" agent_event INFO 'binary integrity verified against the install manifest provenance="checksums" '
# logged only when every deny and observe hook of this kernel attached (16
# deny hooks on 5.15 and 6.1, 18 where the kernel has the ACL hooks, 6.2+)
check "every deny hook attached" agent_event INFO 'anti-tamper: all LSM hooks attached deny_attached='
check "telemetry probe armed" agent_event INFO 'telemetry probe armed'
# a detection end to end: exec from /tmp (R001)
cp /bin/true /tmp/nn-release-probe && chmod +x /tmp/nn-release-probe
/tmp/nn-release-probe 2>/dev/null; sleep 3; rm -f /tmp/nn-release-probe
check "R001 fires on an exec from /tmp" bash -c "sudo tail -n 50 /var/lib/northnarrow/detections/detections.jsonl | grep -q 'R001_ExecFromTmp'"
[ "$fail" = 0 ] && echo "release-check: PASS" || echo "release-check: FAIL (install log: /tmp/nn-release-install.log)"
exit "$fail"
