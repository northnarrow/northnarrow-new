#!/bin/bash
# Lot 275 (NN-L-NET-028, "no DNS, no connect") — false positives on real
# workloads, measured on a lab guest (`deploy/lab/nn-lab.sh ssh 'cd
# ~/northnarrow && bash deploy/lab/malsim/nodns-fp.sh'`). Run as the lab
# user with sudo, the agent installed and running with its defaults.
#
# Benign workloads only, the guest's own network (each one skipped when
# the guest is offline): every NN-L-NET-028 record written while a workload
# runs is a false positive of the rule on that workload, counted and listed
# (the program the record names, its destination). The rule only records
# (its kill is held behind the per-rule policy, off by default): nothing is
# stopped.
#
#   W1 apt         apt-get update, then a download-only install
#   W2 browser     a browser-like client: 40 parallel HTTPS fetches over
#                  12 hosts (curl --parallel), then a page with its
#                  requisites from several hosts (wget -p)
#   W3 ntp         systemd-timesyncd restarted (its servers resolved, UDP
#                  123), or chrony when it is the one installed
#   W4 mirrors     git clone over HTTPS, apt-get download from the mirror,
#                  pip download when pip is there
#   W5 containers  a container that fetches over HTTPS (podman or docker,
#                  rootful and rootless when present); skipped without one
#   W6 resolver    dig/getent against the configured resolver (the
#                  resolver itself is exempt)
#
#   bash deploy/lab/malsim/nodns-fp.sh [--only W1,W3] [--out FILE] [--with-podman]
#
#   --with-podman  install podman for W5 when no container engine is there,
#                  and purge it after (the guest left as it was)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
HELPER="$HERE/nn-ms-net.py"
py() { python3 -I "$HELPER" "$@"; }
DET=/var/lib/northnarrow/detections/detections.jsonl
RULE=NN-L-NET-028_ConnectWithoutDns
ONLY=""
OUT=""
WITH_PODMAN=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --only) ONLY=${2:-}; shift 2 ;;
        --out) OUT=${2:-}; shift 2 ;;
        --with-podman) WITH_PODMAN=1; shift ;;
        -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "nodns-fp: unknown argument $1" >&2; exit 2 ;;
    esac
done
want() { [[ -z $ONLY || ",$ONLY," == *",$1,"* ]]; }
det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }
new_records() { sudo tail -n "+$(( $1 + 1 ))" "$DET" 2>/dev/null; }
WORK=$(mktemp -d /tmp/nn-fp.XXXXXX) || exit 1
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
total=0
summary=()

# measure NAME DESCRIPTION -- COMMAND…: the rule's records while COMMAND runs
measure() {
    local name=$1 what=$2; shift 3
    local b n list
    b=$(det_count)
    "$@" >"$WORK/$name.log" 2>&1
    local rc=$?
    sleep 4
    n=$(new_records "$b" | py records count --rule "$RULE")
    list=$(new_records "$b" | python3 -I -c '
import json, sys
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if r.get("rule_id") != sys.argv[1]:
        continue
    exe = r.get("exe") or (r.get("principal") or {}).get("comm") or "?"
    print("%s %s %s" % (r.get("severity"), exe, r.get("network") or "-"))
' "$RULE" | sort | uniq -c | sort -rn | head -12)
    total=$((total + n))
    summary+=("$name|$what|rc $rc|$n")
    printf '%-4s %-60s rc=%-3s NET-028 records: %s\n' "$name" "$what" "$rc" "$n"
    [[ -n $list ]] && printf '%s\n' "$list" | sed 's/^/       /'
}

online=0
getent ahostsv4 deb.debian.org >/dev/null 2>&1 && online=1
[[ $online -eq 1 ]] || echo "INFO the guest does not resolve deb.debian.org: the online workloads are skipped"
echo "== $(uname -r); resolver: $(grep -m1 '^nameserver' /etc/resolv.conf); hosts: $(grep '^hosts:' /etc/nsswitch.conf | tr -s ' ')"

if want W1 && [[ $online -eq 1 ]]; then
    measure W1 "apt-get update + download-only install (curl jq git)" -- \
        bash -c 'sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --download-only --reinstall curl jq git'
fi

if want W2 && [[ $online -eq 1 ]]; then
    hosts=(www.debian.org www.ubuntu.com archive.ubuntu.com github.com www.wikipedia.org
           www.kernel.org www.python.org cdn.jsdelivr.net www.cloudflare.com www.google.com
           www.mozilla.org example.com)
    urls=()
    for i in $(seq 40); do urls+=("https://${hosts[$((i % ${#hosts[@]}))]}/"); done
    measure W2 "browser-like: 40 parallel HTTPS fetches over 12 hosts" -- \
        timeout 120 curl -s -o /dev/null --parallel --parallel-max 20 -m 20 "${urls[@]}"
    if command -v wget >/dev/null; then
        measure W2 "browser-like: a page and its requisites (wget -p)" -- \
            timeout 120 wget -q -p -H -P "$WORK/page" -T 20 https://www.debian.org/
    fi
fi

if want W3 && [[ $online -eq 1 ]]; then
    if systemctl list-unit-files chrony.service >/dev/null 2>&1 && systemctl is-enabled --quiet chrony 2>/dev/null; then
        measure W3 "chrony restarted, 30 s of polling" -- bash -c 'sudo systemctl restart chrony && sleep 30'
    elif systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1; then
        measure W3 "systemd-timesyncd restarted, 30 s of polling" -- \
            bash -c 'sudo systemctl restart systemd-timesyncd && sleep 30 && timedatectl timesync-status 2>/dev/null | head -3'
    else
        echo "SKIP W3 no chrony or systemd-timesyncd"
    fi
fi

if want W4 && [[ $online -eq 1 ]]; then
    measure W4 "git clone over HTTPS" -- \
        timeout 120 git clone -q --depth 1 https://github.com/octocat/Hello-World "$WORK/clone"
    measure W4 "apt-get download (the configured mirror)" -- \
        bash -c "cd $WORK && timeout 120 apt-get download -qq hello"
    if command -v pip3 >/dev/null; then
        measure W4 "pip download (PyPI and its CDN)" -- \
            timeout 120 pip3 download -q -d "$WORK/pip" six
    fi
fi

if want W5 && [[ $online -eq 1 ]]; then
    installed=0
    if [[ $WITH_PODMAN -eq 1 ]] && ! command -v podman >/dev/null && ! command -v docker >/dev/null; then
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq podman >"$WORK/podman-install.log" 2>&1; then
            installed=1
            echo "INFO podman installed for W5 ($(podman --version 2>/dev/null))"
        else
            echo "INFO podman could not be installed: W5 skipped"
        fi
    fi
    ran=0
    for eng in podman docker; do
        command -v "$eng" >/dev/null || continue
        measure W5 "$eng (rootful): a container fetches https://example.com" -- \
            timeout 180 sudo "$eng" run --rm docker.io/library/alpine:3.20 wget -q -O /dev/null https://example.com/
        ran=1
        if [[ $eng == podman ]]; then
            measure W5 "podman (rootless): a container fetches https://example.com" -- \
                timeout 180 podman run --rm docker.io/library/alpine:3.20 wget -q -O /dev/null https://example.com/
        fi
    done
    [[ $ran -eq 1 ]] || echo "SKIP W5 no podman or docker on this guest"
    if [[ $installed -eq 1 ]]; then
        podman rmi -a -f >/dev/null 2>&1; sudo podman rmi -a -f >/dev/null 2>&1
        sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq --autoremove podman >/dev/null 2>&1 \
            && echo "INFO podman purged" || echo "INFO podman purge failed"
    fi
fi

if want W6; then
    measure W6 "lookups through the configured resolver (getent, dig when present)" -- \
        bash -c 'for n in example.com www.debian.org; do getent ahosts $n; done; command -v dig >/dev/null && dig +short example.com; true'
fi

echo "== NN-L-NET-028 records over the workloads: $total"
if [[ -n $OUT ]]; then
    {
        echo "# nodns-fp $(date -u +%FT%TZ) $(uname -r)"
        printf '%s\n' "${summary[@]}"
        echo "total|$total"
    } > "$OUT"
fi
