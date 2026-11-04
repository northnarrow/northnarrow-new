#!/bin/bash
# Lot 279 (R011 judged on what a module tool's exec loads) — the benign
# corpus and the malicious shapes, measured on a lab guest
# (`deploy/lab/nn-lab.sh ssh 'cd ~/northnarrow && bash deploy/lab/malsim/kmod-check.sh'`).
# Run as the lab user with sudo, the agent installed and running with its
# defaults (it acts: a kill is a kill).
#
# For each workload: its exit status, the R011 records its execs drew
# (recorded / killed, as the primary rule or among `matches`) and R018's
# (the loads), over the detections written while it ran; the agent's
# journal lines of R011's verdicts (which tool, which modules, why).
#
# Benign (lot 279: no R011 kill expected):
#   B1 iptables-legacy  `iptables-legacy -L` with ip_tables not loaded (libxtables' modprobe)
#   B2 podman           rootful: a network created, a container on it with a published
#                       port; rootless: a container with a published port
#   B3 docker           the distribution's docker.io: the daemon's start, a container with a
#                       published port
#   B4 k3s              k3s with kube-proxy in ipvs mode, until its node is Ready
#   B5 wg-quick         a WireGuard interface up and down (wireguard-tools)
#   B6 zfs              zfsutils-linux installed (zfs-load-module: modprobe zfs)
#   B7 admin            `sudo modprobe dummy`, `sudo modprobe -r dummy`
#   B8 queries          modprobe -n / -D / -c / -R, kmod list, kmod static-nodes
# Malicious (R011 kills each; no file exists to load, so nothing reaches the
# kernel — the shapes that load are the privileged tests'
# `r011_records_a_packaged_modprobe_and_kills_an_insmod_from_tmp` and
# `r011_kills_a_module_copied_into_the_tree_and_r018_catches_what_argv_hides`,
# under a detect-only agent):
#   M1 insmod of a /tmp .ko          M2 modprobe of a /tmp .ko path
#   M3 modprobe of a name no tree resolves
#   M4 modprobe -d <a /tmp tree>      M5 modprobe -C <a /tmp configuration>
#   M6 a copy of the system's modprobe run from /tmp (a dry run)
#
#   bash deploy/lab/malsim/kmod-check.sh [--only B1,M3] [--out FILE]
#        [--with-podman] [--with-docker] [--with-k3s] [--with-zfs] [--with-wg]
#
#   --with-*  install what the workload needs when it is not there, and
#             remove it after (with its state: images, networks, its data
#             directories), the guest left as it was
set -u
DET=/var/lib/northnarrow/detections/detections.jsonl
ONLY=""
OUT=""
WITH=" "
while [[ $# -gt 0 ]]; do
    case $1 in
        --only) ONLY=${2:-}; shift 2 ;;
        --out) OUT=${2:-}; shift 2 ;;
        --with-podman|--with-docker|--with-k3s|--with-zfs|--with-wg) WITH+="${1#--with-} "; shift ;;
        -h|--help) sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "kmod-check: unknown argument $1" >&2; exit 2 ;;
    esac
done
want() { [[ -z $ONLY || ",$ONLY," == *",$1,"* ]]; }
with() { [[ $WITH == *" $1 "* ]]; }
det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }
new_records() { sudo tail -n "+$(( $1 + 1 ))" "$DET" 2>/dev/null; }
WORK=$(mktemp -d /tmp/nn-k279.XXXXXX) || exit 1
chmod 755 "$WORK"
trap 'sudo rm -rf "$WORK"' EXIT
summary=()
r011_kills=0
apt_in() { sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >"$WORK/apt.log" 2>&1; }
apt_out() { sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq --autoremove "$@" >>"$WORK/apt.log" 2>&1; }

# count: R011 and R018 records (primary or among `matches`) by action
count() {
    python3 -I -c '
import json, sys
c = {"R011_KernelModuleTooling": [0, 0], "R018_KernelModuleLoad": [0, 0]}
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    if not isinstance(r, dict) or not isinstance(r.get("rule_id"), str):
        continue
    v = r.get("verdict")
    views = [(r["rule_id"], v.get("Rule") if isinstance(v, dict) else "?")]
    for m in r.get("matches") or []:
        if isinstance(m, dict) and m.get("rule_id") != r["rule_id"]:
            views.append((m.get("rule_id"), m.get("action")))
    for rule, act in views:
        if rule in c:
            c[rule][0] += 1
            if isinstance(act, str) and act.startswith("Kill"):
                c[rule][1] += 1
print("%d %d %d %d" % (c["R011_KernelModuleTooling"][0], c["R011_KernelModuleTooling"][1],
                       c["R018_KernelModuleLoad"][0], c["R018_KernelModuleLoad"][1]))
'
}

# measure NAME EXPECT DESCRIPTION -- COMMAND…  (EXPECT: benign | kill)
measure() {
    local name=$1 expect=$2 what=$3; shift 4
    local b t0 rc n
    b=$(det_count)
    t0=$(date +%s)
    "$@" >"$WORK/$name.log" 2>&1
    rc=$?
    sleep 4
    read -r rec kill r18 r18k < <(new_records "$b" | count)
    local verdict
    if [[ $expect == benign ]]; then
        if [[ $rec -eq 0 ]]; then verdict="NONE (no module tool exec seen)"
        elif [[ $kill -eq 0 ]]; then verdict="PASS (recorded, not killed)"
        else verdict="FAIL (R011 killed)"; fi
    else
        if [[ $kill -ge 1 ]]; then verdict="PASS (killed)"; else verdict="FAIL (not killed)"; fi
    fi
    r011_kills=$((r011_kills + kill))
    summary+=("$name|$what|rc $rc|R011 $rec/$kill|R018 $r18/$r18k|$verdict")
    printf '%-3s %-62s rc=%-3s R011 rec=%s kill=%s  R018 rec=%s kill=%s  %s\n' \
        "$name" "$what" "$rc" "$rec" "$kill" "$r18" "$r18k" "$verdict"
    sudo journalctl --namespace=northnarrow -q -o cat -u northnarrow-agent --since "@$t0" 2>/dev/null |
        grep -a 'rule=R011_KernelModuleTooling' | sed 's/^.*reasoning=//' | cut -c1-300 |
        sort | uniq -c | head -8 | sed 's/^/       /'
    if [[ $rc -ne 0 ]]; then tail -3 "$WORK/$name.log" | sed 's/^/       | /'; fi
}

online=0
getent ahostsv4 deb.debian.org >/dev/null 2>&1 && online=1
echo "== $(uname -r); $(. /etc/os-release; echo "$PRETTY_NAME"); kmod $(kmod --version 2>/dev/null | head -1 | awk '{print $NF}'); sig_enforce=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null); online=$online"
sudo systemctl is-active --quiet northnarrow-agent || echo "WARN the agent is not active"

if want B1; then
    if command -v iptables-legacy >/dev/null; then
        sudo modprobe -r iptable_filter ip_tables 2>/dev/null
        if grep -qw '^ip_tables' /proc/modules; then
            echo "SKIP B1 ip_tables is loaded and in use: no modprobe to see"
        else
            measure B1 benign "iptables-legacy -L (ip_tables not loaded)" -- sudo iptables-legacy -L -n
            sudo modprobe -r iptable_filter ip_tables 2>/dev/null
        fi
    else
        echo "SKIP B1 no iptables-legacy"
    fi
fi

if want B2 && [[ $online -eq 1 ]]; then
    ours=0
    if ! command -v podman >/dev/null && with podman; then
        apt_in podman && ours=1 && echo "INFO podman installed ($(podman --version 2>/dev/null))"
    fi
    if command -v podman >/dev/null; then
        measure B2 benign "podman rootful: network create, run -p on it" -- bash -c '
            sudo podman network create nnk279 &&
            sudo timeout 180 podman run --rm --network nnk279 -p 127.0.0.1:18279:80 docker.io/library/alpine:3.20 true;
            rc=$?; sudo podman network rm -f nnk279; exit $rc'
        measure B2 benign "podman rootless: run -p" -- \
            timeout 180 podman run --rm -p 127.0.0.1:18280:80 docker.io/library/alpine:3.20 true
        if [[ $ours -eq 1 ]]; then
            podman system reset -f >/dev/null 2>&1; sudo podman system reset -f >/dev/null 2>&1
            apt_out podman && echo "INFO podman purged" || echo "INFO podman purge failed"
            sudo rm -rf /var/lib/containers /etc/containers/networks/nnk279.json
            rm -rf "$HOME/.local/share/containers" "$HOME/.config/containers"
        fi
    else
        echo "SKIP B2 no podman (--with-podman installs it)"
    fi
fi

if want B3 && [[ $online -eq 1 ]]; then
    ours=0
    if ! command -v docker >/dev/null && with docker; then
        b=$(det_count); t0=$(date +%s)
        if apt_in docker.io; then
            ours=1
            sleep 6
            read -r rec kill r18 r18k < <(new_records "$b" | count)
            echo "INFO docker.io installed and its daemon started: R011 rec=$rec kill=$kill R018 rec=$r18 kill=$r18k (the daemon's start)"
            r011_kills=$((r011_kills + kill))
            summary+=("B3|docker.io install + dockerd start|rc 0|R011 $rec/$kill|R018 $r18/$r18k|$([[ $kill -eq 0 ]] && echo PASS || echo FAIL)")
            sudo journalctl --namespace=northnarrow -q -o cat -u northnarrow-agent --since "@$t0" 2>/dev/null |
                grep -a 'rule=R011_KernelModuleTooling' | sed 's/^.*reasoning=//' | cut -c1-300 |
                sort | uniq -c | head -8 | sed 's/^/       /'
        fi
    fi
    if command -v docker >/dev/null; then
        measure B3 benign "docker: run -p" -- \
            sudo timeout 180 docker run --rm -p 127.0.0.1:18281:80 docker.io/library/alpine:3.20 true
        if [[ $ours -eq 1 ]]; then
            sudo systemctl stop docker.socket docker containerd >/dev/null 2>&1
            apt_out docker.io containerd runc && echo "INFO docker.io purged" || echo "INFO docker.io purge failed"
            sudo rm -rf /var/lib/docker /var/lib/containerd /etc/docker
            sudo ip link delete docker0 2>/dev/null
        fi
    else
        echo "SKIP B3 no docker (--with-docker installs docker.io)"
    fi
fi

if want B4 && [[ $online -eq 1 ]]; then
    if [[ -x /usr/local/bin/k3s ]]; then
        echo "SKIP B4 k3s is already installed here: not touched"
    elif with k3s; then
        measure B4 benign "k3s (kube-proxy ipvs): install, node Ready" -- bash -c '
            curl -sfL https://get.k3s.io -o /tmp/nn-k279-k3s.sh || exit 90
            sudo env INSTALL_K3S_EXEC="--kube-proxy-arg=proxy-mode=ipvs" sh /tmp/nn-k279-k3s.sh || exit 91
            for i in $(seq 1 60); do
                sudo k3s kubectl get nodes 2>/dev/null | grep -qw Ready && break; sleep 3
            done
            sudo k3s kubectl get nodes; sleep 20'
        sudo /usr/local/bin/k3s-uninstall.sh >/dev/null 2>&1 && echo "INFO k3s uninstalled" || echo "INFO k3s uninstall failed"
        sudo rm -f /tmp/nn-k279-k3s.sh
    else
        echo "SKIP B4 (--with-k3s installs k3s)"
    fi
fi

if want B5; then
    ours=0
    if ! command -v wg-quick >/dev/null && with wg && [[ $online -eq 1 ]]; then
        apt_in wireguard-tools && ours=1
    fi
    if command -v wg-quick >/dev/null; then
        sudo modprobe -r wireguard 2>/dev/null
        key=$(wg genkey)
        printf '[Interface]\nPrivateKey = %s\nAddress = 10.27.9.1/24\nListenPort = 51279\n' "$key" |
            sudo tee /etc/wireguard/nnk279.conf >/dev/null
        sudo chmod 600 /etc/wireguard/nnk279.conf
        measure B5 benign "wg-quick up / down (wireguard not loaded)" -- \
            bash -c 'sudo wg-quick up nnk279 && sudo wg-quick down nnk279'
        sudo rm -f /etc/wireguard/nnk279.conf
        sudo modprobe -r wireguard 2>/dev/null
        if [[ $ours -eq 1 ]]; then apt_out wireguard-tools; fi
    else
        echo "SKIP B5 no wg-quick (--with-wg installs wireguard-tools)"
    fi
fi

if want B6 && [[ $online -eq 1 ]]; then
    if command -v zpool >/dev/null; then
        echo "SKIP B6 zfsutils-linux is already installed here: not touched"
    elif with zfs; then
        sudo modprobe -r zfs 2>/dev/null
        measure B6 benign "zfsutils-linux install (zfs-load-module: modprobe zfs)" -- \
            bash -c 'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq zfsutils-linux && sleep 5 && systemctl is-active zfs-load-module.service; grep -qw ^zfs /proc/modules'
        apt_out zfsutils-linux && echo "INFO zfsutils-linux purged" || echo "INFO zfsutils-linux purge failed"
        sudo modprobe -r zfs 2>/dev/null
    else
        echo "SKIP B6 (--with-zfs installs zfsutils-linux)"
    fi
fi

if want B7; then
    sudo modprobe -r dummy 2>/dev/null
    measure B7 benign "sudo modprobe dummy; sudo modprobe -r dummy" -- \
        bash -c 'sudo modprobe dummy && sudo modprobe -r dummy'
fi

if want B8; then
    measure B8 benign "modprobe -n/-D/-c/-R, kmod list, kmod static-nodes" -- bash -c '
        sudo modprobe -n -v dummy && sudo modprobe -D dummy && sudo modprobe -c >/dev/null &&
        sudo modprobe -R dummy && kmod list >/dev/null &&
        sudo kmod static-nodes --format=tmpfiles --output=/dev/null'
fi

# The malicious shapes: nothing exists to load.
M=$WORK/missing
if want M1; then measure M1 kill "insmod /tmp/…/rk.ko" -- sudo insmod "$M/rk.ko"; fi
if want M2; then measure M2 kill "modprobe /tmp/…/rk.ko" -- sudo modprobe "$M/rk.ko"; fi
if want M3; then measure M3 kill "modprobe nn_k279_no_such_module" -- sudo modprobe nn_k279_no_such_module; fi
if want M4; then measure M4 kill "modprobe -d /tmp/… dummy" -- sudo modprobe -d "$M/root" dummy; fi
if want M5; then measure M5 kill "modprobe -C /tmp/….conf dummy" -- sudo modprobe -C "$M/m.conf" dummy; fi
if want M6; then
    cp "$(readlink -f "$(command -v modprobe)")" "$WORK/modprobe"
    measure M6 kill "a copy of modprobe in /tmp (modprobe -n dummy)" -- sudo "$WORK/modprobe" -n dummy
fi

echo "== R011 kills over the run: $r011_kills"
if [[ -n $OUT ]]; then
    {
        echo "# kmod-check $(date -u +%FT%TZ) $(uname -r)"
        printf '%s\n' "${summary[@]}"
        echo "r011_kills|$r011_kills"
    } > "$OUT"
fi
