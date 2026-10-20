#!/usr/bin/env bash
# NorthNarrow local lab — Ubuntu 24.04 (kernel 6.8, lsm=…,bpf) guest under
# QEMU/KVM, driven from the dev box (works inside WSL2 with nested virt).
#
# Why: WSL2's own kernel has no securityfs / BPF-LSM / bpffs, so the 56
# `#[ignore]` privileged tests, the eBPF verifier and the watchdog
# respawn can only be exercised on a real Ubuntu kernel. This script
# makes that a repeatable one-liner instead of a hand-built VM.
#
# Host prerequisites (once):
#   sudo apt install qemu-system-x86 qemu-utils cloud-image-utils gnupg gpgv
#   sudo usermod -aG kvm "$USER"      # then re-login (WSL: `wsl --shutdown`)
#   bpf-linker 0.10.3 + nightly on PATH for `cargo xtask build-ebpf`
#
# No /dev/kvm in WSL (nested virtualization not exposed — e.g. AMD hosts on
# Windows 11 26100/26200/26300.9711, KB5127648, microsoft/WSL#41918):
#   NN_LAB_ACCEL=whpx — the guest runs in QEMU for Windows on the Windows
#     hypervisor, next to WSL instead of inside it, at full speed. Needs the
#     "Windows Hypervisor Platform" feature, QEMU for Windows
#     (NN_LAB_WIN_QEMU), `sudo apt install socat` and a systemd user session.
#   NN_LAB_ACCEL=tcg — software emulation in WSL: slow, timing-sensitive
#     tests may not hold.
#   `echo whpx > ~/.cache/nn-lab/accel` makes it the default.
#
# Usage:
#   deploy/lab/nn-lab.sh up            # download image, provision, boot, wait for ssh
#   deploy/lab/nn-lab.sh check         # kernel / lsm / bpffs / iptables / cargo in the guest
#   deploy/lab/nn-lab.sh sync          # build eBPF on host, rsync repo into the guest
#   deploy/lab/nn-lab.sh build         # cargo build --release (+test-privileged,debug-trigger) in the guest
#   deploy/lab/nn-lab.sh test-e2e      # docs/integration-test-runbook.md "Run": the e2e suites, each count checked
#   deploy/lab/nn-lab.sh test-ignored  # every #[ignore] test, as root, single-threaded
#   NN_LAB_DISTRO=debian12 deploy/lab/nn-lab.sh up   # second guest (Debian 12, kernel 6.1); every
#                                                    # sub-command honours NN_LAB_DISTRO (default ubuntu2404;
#                                                    # also debian13 = 6.12, ubuntu2204 = 5.15, alma9 = 5.14 el9)
#   NN_LAB_LOCKDOWN=integrity deploy/lab/nn-lab.sh up  # a separate guest of NN_LAB_DISTRO booted with
#                                                    # lockdown=integrity (anti-tamper C27; ssh port +1000)
#   deploy/lab/nn-lab.sh upgrade-check    # install.sh --upgrade on the running install (keys/chains kept)
#   deploy/lab/nn-lab.sh uninstall-check  # uninstall.sh --purge leaves nothing, then reinstall
#   deploy/lab/nn-lab.sh tamper-check     # adversarial anti-tamper cases: outcome + chain-log evidence per case
#   deploy/lab/nn-lab.sh overhead [ROUNDS] # agent off/on throughput of the hooked operations (idle host!)
#   deploy/lab/nn-lab.sh pkgmgr-check     # dpkg/rpm survive the agent: probe package install/remove + real reinstall
#   deploy/lab/nn-lab.sh pkg-check        # our .deb/.rpm: migrate, upgrade, refused upgrade, remove, purge, fresh install
#   deploy/lab/nn-lab.sh release-check DIR # the CI release tarball (gh run download) installed and verified here
#   deploy/lab/nn-lab.sh sensor-feasibility [BASE] # Tappa 10.9 step 0: the new sensor attach points on this kernel
#   deploy/lab/nn-lab.sh verifier-check [synced] # every program of the eBPF object through this kernel's verifier
#                                      # (OK / REFUSED per program, logs of the refused ones); `synced`: the
#                                      # object `sync` copied instead of the one the agent embeds
#   deploy/lab/nn-lab.sh btrfs-check      # review 55: a watched file on a btrfs subvolume is still detected
#   deploy/lab/nn-lab.sh overlay-check    # lab PR 189: a watched file on overlayfs is detected or its boot attests it
#   deploy/lab/nn-lab.sh open-sensor-check # Tappa 10.9 step 1: the file-open sensor on LSM file_open, end to end
#   deploy/lab/nn-lab.sh exec-sensor-check # Tappa 10.9 step 2: the exec sensor on LSM bprm_check_security (review 61)
#   deploy/lab/nn-lab.sh execq-check     # lab PR 223 (EXPERIMENTAL): exec quarantine at first sight, six cases, guest put back
#   deploy/lab/nn-lab.sh malsim-exec-check # lab PR 226 (EXPERIMENTAL): exec policy and exec environment, MS-01/02/03/32 before and after, negatives, guest put back
#   deploy/lab/nn-lab.sh dns-sensor-check # Tappa 10.9 step 3: the DNS sensor on the socket buffer (reviews 66, 67)
#   deploy/lab/nn-lab.sh net-check         # lab PR 224: connect-time network verdicts, reverse shells, outbound fan-out (CM-02/03/14)
#   deploy/lab/nn-lab.sh ransom-check [--only MS23|MS25] # lab PR 225: MS-23 ransomware recorded (kill held, ENGAGED), negatives; MS-25 security tools
#   deploy/lab/nn-lab.sh fim-reuse-check  # review 57: a deleted watched file's reused inode is not attributed to it
#   deploy/lab/nn-lab.sh install       # deploy/install.sh + start both units
#   deploy/lab/nn-lab.sh respawn-check # agent death via systemd in a window, assert respawn v2 invariants
#   deploy/lab/nn-lab.sh ssh [cmd…]    # shell / command in the guest
#   deploy/lab/nn-lab.sh snapshot NAME | restore NAME   (guest must be down)
#   deploy/lab/nn-lab.sh status | down | destroy
#   deploy/lab/nn-lab.sh trust-host-key  # record the running guest's ssh host key again (a guest recreated
#                                      # by an older nn-lab.sh); `up` records it for a new guest (generated
#                                      # here, injected by cloud-init) or once for an existing disk
#   deploy/lab/nn-lab.sh verify-image  # base image vs its verified download or the vendor's signed lists
#   deploy/lab/nn-lab.sh image-info    # the base image the vendor's signed list names now: path= lab_dir=
#                                      # algo= digest= url= lines (the CI cache key); downloads the list only
#   deploy/lab/nn-lab.sh fetch-image   # the base image without a guest: downloaded against that list, or
#                                      # the one present checked (as verify-image; in CI mode replaced
#                                      # when it is not the vendor's current image); prints image-info's lines
#   deploy/lab/nn-lab.sh nightly       # unattended full run, the security checks included (tamper-check,
#                                      # pkgmgr-, open-sensor-, fim-reuse-, btrfs-, overlay-check)
#                                      # → $LAB_DIR/reports/<stamp>.md (exit 1 on any failure)
#   deploy/lab/nn-lab.sh soak start [HOURS] [INTERVAL_S] | status | stop | wait | report
#                                      # hours of synthetic load + resource samples → $LAB_DIR/reports/soak-<stamp>.md
#
# Env overrides: NN_LAB_ACCEL (kvm | whpx | tcg; default $NN_LAB_DIR/accel or kvm),
#   NN_LAB_WIN_DIR (C:\nn-lab), NN_LAB_WIN_QEMU / NN_LAB_WIN_QEMU_IMG (C:\Program Files\qemu\…),
#   NN_LAB_BOOT_TIMEOUT (900 s),
#   NN_LAB_DIR (~/.cache/nn-lab), NN_LAB_CPUS (4), NN_LAB_MEM (8192),
#   NN_LAB_SSH_PORT (2222, remembered after `up`), NN_LAB_DISK (30G), NN_LAB_LTO (thin),
#   NN_REPO (git toplevel of this script), NN_LAB_NIGHTLY_DOWN=1 (power the guest off at the end),
#   NN_LAB_NIGHTLY_SKIP (space-separated steps to skip, e.g. "test-ignored"),
#   NN_LAB_LOCKDOWN (integrity: the lockdown guest of the distro, above).
#   NN_LAB_CI=1: CI mode (.github/workflows/lab-vm.yml, lab PR 227), one KVM guest on a
#   GitHub-hosted runner. KVM only (whpx and tcg refused), every cargo build --locked (the
#   host's eBPF build, the guest's builds and test runs), ssh in batch mode with keepalives
#   (a guest that stops answering ends a call within 5 min, not at the job's timeout), a
#   boot that fails prints the tail of the guest's serial console, and `fetch-image`
#   replaces a base image that is not the vendor's current one. Unset or 0: the lab as
#   before. $CI is not read (GitHub sets it for every job).
# Exit status: 0 done; 1 a failure (the message says which); 2 a usage or configuration error.
set -euo pipefail

# cron / Task Scheduler invocations come with a minimal PATH: make sure
# cargo, bpf-linker (~/.cargo/bin) and the qemu/ss tools (/usr/sbin) are
# reachable regardless of how we were started.
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

ROOT_LAB_DIR=${NN_LAB_DIR:-"$HOME/.cache/nn-lab"}
CPUS=${NN_LAB_CPUS:-4}
# kvm (default), whpx (QEMU for Windows, see the header) or tcg.
ACCEL=${NN_LAB_ACCEL:-$(cat "${NN_LAB_DIR:-$HOME/.cache/nn-lab}/accel" 2>/dev/null || echo kvm)}
case "$ACCEL" in kvm | whpx | tcg) ;; *) echo "nn-lab: unknown NN_LAB_ACCEL=$ACCEL (kvm | whpx | tcg)" >&2; exit 2 ;; esac
# CI mode (lab PR 227; see the header). Only NN_LAB_CI turns it on: never
# $CI, which GitHub sets for every job, the xtask tests that run this script
# included. Off, nothing below changes.
CI_MODE=${NN_LAB_CI:-0}
case "$CI_MODE" in 0 | 1) ;; *) echo "nn-lab: unknown NN_LAB_CI=$CI_MODE (1, or 0 / unset)" >&2; exit 2 ;; esac
if [[ $CI_MODE == 1 && $ACCEL != kvm ]]; then
    echo "nn-lab: NN_LAB_CI=1 runs the guest under KVM only, not NN_LAB_ACCEL=$ACCEL: a hosted runner has no Windows hypervisor, and a TCG guest would not finish within a job" >&2
    exit 2
fi
# External audit SUP-016 in CI mode: the host's `cargo xtask build-ebpf` and
# every cargo build and test run in the guest are --locked, as in the other
# workflows. Empty in the lab.
LAB_CARGO_LOCKED=
if [[ $CI_MODE == 1 ]]; then LAB_CARGO_LOCKED=--locked; fi
MEM=${NN_LAB_MEM:-8192}
DISK_SIZE=${NN_LAB_DISK:-30G}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=${NN_REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}

# ── distro matrix ─────────────────────────────────────────────────────
# NN_LAB_DISTRO selects the guest. Each distro gets its own disk, seed,
# pid, serial log, ssh port and reports under $ROOT_LAB_DIR/<distro>/ —
# except ubuntu2404, the original guest, which keeps the flat layout so
# an existing lab keeps working. The ssh-key is shared.
DISTRO=${NN_LAB_DISTRO:-ubuntu2404}
case "$DISTRO" in
    ubuntu2404)
        IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
        BASE_IMG_NAME="noble-base.img"; DEFAULT_SSH_PORT=2222
        USER_DATA_TMPL="$SCRIPT_DIR/user-data.tmpl"
        LAB_DIR="$ROOT_LAB_DIR" ;;
    debian12)
        IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
        BASE_IMG_NAME="bookworm-base.qcow2"; DEFAULT_SSH_PORT=2422
        USER_DATA_TMPL="$SCRIPT_DIR/user-data.debian12.tmpl"
        LAB_DIR="$ROOT_LAB_DIR/debian12" ;;
    debian13)
        # Kernel 6.12: the lab's first guest from 6.9 on, where the
        # inode_setattr LSM hook takes `struct mnt_idmap *` first (lab PR 164).
        IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
        BASE_IMG_NAME="trixie-base.qcow2"; DEFAULT_SSH_PORT=2722
        USER_DATA_TMPL="$SCRIPT_DIR/user-data.debian13.tmpl"
        LAB_DIR="$ROOT_LAB_DIR/debian13" ;;
    ubuntu2204)
        # Kernel 5.15: the first BPF-LSM-capable LTS still in wide use
        # (same template as 24.04 — Ubuntu ships bpftool via linux-tools).
        IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
        BASE_IMG_NAME="jammy-base.img"; DEFAULT_SSH_PORT=2522
        USER_DATA_TMPL="$SCRIPT_DIR/user-data.tmpl"
        LAB_DIR="$ROOT_LAB_DIR/ubuntu2204" ;;
    alma9)
        # RHEL 9 family: kernel 5.14 + backports with native BTF (not in
        # BTFHub — only a guest can tell), SELinux enforcing, dnf.
        IMAGE_URL="https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2"
        BASE_IMG_NAME="alma9-base.qcow2"; DEFAULT_SSH_PORT=2622
        USER_DATA_TMPL="$SCRIPT_DIR/user-data.alma9.tmpl"
        LAB_DIR="$ROOT_LAB_DIR/alma9" ;;
    *) echo "nn-lab: unknown NN_LAB_DISTRO=$DISTRO (ubuntu2404 | debian12 | debian13 | ubuntu2204 | alma9)" >&2; exit 2 ;;
esac
# The base image stays with the distro: a lockdown guest is layered on it.
IMG_DIR=$LAB_DIR
# External audit LAB-024 (NN-AUD-414, lab PR 206): no guest set lockdown=,
# so the anti-tamper suite's C27 (an unsigned module refused by the kernel)
# never ran. NN_LAB_LOCKDOWN=integrity gives a separate guest of the distro
# — its own disk, seed, ssh port (the distro's + 1000) and reports under
# $ROOT_LAB_DIR/<distro>-lockdown-integrity/ — booted with
# lockdown=integrity added to the template's lsm= line (__NN_LAB_KARGS__);
# `check` fails when the running kernel is not locked down. confidentiality
# is not offered: it closes BPF reads of kernel memory, which the sensors use.
LOCKDOWN=${NN_LAB_LOCKDOWN:-}
case "$LOCKDOWN" in
    "" | none) LOCKDOWN= ;;
    integrity) ;;
    *) echo "nn-lab: unknown NN_LAB_LOCKDOWN=$LOCKDOWN (integrity, or unset)" >&2; exit 2 ;;
esac
GUEST_NAME=$DISTRO
if [[ -n $LOCKDOWN ]]; then
    GUEST_NAME="$DISTRO-lockdown-$LOCKDOWN"
    LAB_DIR="$ROOT_LAB_DIR/$GUEST_NAME"
    DEFAULT_SSH_PORT=$((DEFAULT_SSH_PORT + 1000))
fi
# The ssh port is remembered in $LAB_DIR/ssh_port after `up`, so every
# later sub-command talks to the same guest without re-exporting it.
SSH_PORT=${NN_LAB_SSH_PORT:-$(cat "$LAB_DIR/ssh_port" 2>/dev/null || echo "$DEFAULT_SSH_PORT")}

BASE_IMG="$IMG_DIR/$BASE_IMG_NAME"
DISK="$LAB_DIR/disk.qcow2"
SEED="$LAB_DIR/seed.iso"
KEY="$ROOT_LAB_DIR/id_ed25519"
PIDFILE="$LAB_DIR/qemu.pid"
SERIAL="$LAB_DIR/serial.log"
GUEST="nn@127.0.0.1"
# >>> ssh-options (xtask/tests/lab_host_safety.rs runs this block)
# External audit LAB-025 (NN-AUD-415, lab PR 211): every connection to a
# guest took any host key (StrictHostKeyChecking=no, no known_hosts), so
# whatever listened on the forwarded 127.0.0.1 port while the guest was down
# — any local user's process, another guest behind a forwarder — was taken
# for the guest: `sync` sent it the tree, the checks read its answers. Each
# guest now has its own known_hosts ($LAB_DIR/known_hosts, one line under
# the alias nn-lab-<guest>, so a changed NN_LAB_SSH_PORT keeps it), checked
# strictly from the first connection: a new guest's ed25519 host key is
# generated here at `up` and injected through cloud-init (`ssh_keys:` in the
# templates, render_user_data); a guest whose disk predates that has its key
# recorded once, by `up`, from the port only while it is served by the
# guest's own QEMU (or its whpx forwarder), and `trust-host-key` records it
# again on purpose (a guest recreated by an older nn-lab.sh). `destroy`
# removes both files. Only ed25519 is accepted; the lab key is the only one
# offered.
KNOWN_HOSTS="$LAB_DIR/known_hosts"
HOST_KEY_PUB="$LAB_DIR/ssh_host_ed25519_key.pub"
HOST_KEY_ALIAS="nn-lab-$GUEST_NAME"
case "$KEY$KNOWN_HOSTS" in
    *[\'\"]*) echo "nn-lab: NN_LAB_DIR must not contain a quote: $ROOT_LAB_DIR" >&2; exit 2 ;;
esac
SSH_COMMON=(-i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=\"$KNOWN_HOSTS\"" -o GlobalKnownHostsFile=/dev/null
    -o "HostKeyAlias=$HOST_KEY_ALIAS" -o HostKeyAlgorithms=ssh-ed25519 -o UpdateHostKeys=no
    -o CheckHostIP=no -o LogLevel=ERROR -o ConnectTimeout=5)
# CI mode (lab PR 227): never a prompt, and a guest that stops answering (a
# kernel panic, a hung QEMU) ends the call after 10 unanswered keepalives 30 s
# apart instead of at the job's timeout.
if [[ ${CI_MODE:-0} == 1 ]]; then
    SSH_COMMON+=(-o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=10)
fi
SSH_OPTS=("${SSH_COMMON[@]}" -p "$SSH_PORT")
SCP_OPTS=("${SSH_COMMON[@]}" -P "$SSH_PORT")
# rsync splits its -e string on spaces and honours quotes (not
# backslashes): every option single-quoted, so a space in a path stays.
RSYNC_RSH="ssh$(printf " '%s'" "${SSH_OPTS[@]}")"
# <<< ssh-options

log()  { printf 'nn-lab: %s\n' "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
# External audit LAB-009: a base image is downloaded only against the
# vendor's signed list, and a new guest only layered on a verified image.
# shellcheck source=deploy/lab/lib/verify-download.sh
source "$SCRIPT_DIR/lib/verify-download.sh"
# External audit NN-AUD-421: test-e2e counts each suite (nnsc_*).
# shellcheck source=deploy/lab/lib/suite-count.sh
source "$SCRIPT_DIR/lib/suite-count.sh"

# >>> render-user-data (xtask/tests/lab_scripts.rs runs this block)
# The guest's cloud-init user-data from its template: the lab key, and the
# kernel arguments added to the template's lsm= line (__NN_LAB_KARGS__:
# lockdown=, lab PR 206). A template without the placeholder would boot a
# guest that is not locked down under a lockdown guest's name: refused.
#
# The guest's ssh host key too (external audit LAB-025, lab PR 211): each
# render is a new cloud-init instance, so it gets a new ed25519 key,
# generated here, written into the user-data (__NN_LAB_HOST_KEY__, the
# private half, at that line's indentation; __NN_LAB_HOST_KEY_PUB__) and its
# public half kept next to it as ssh_host_ed25519_key.pub, from which the
# guest's known_hosts is written. The private half is only in the user-data
# (mode 0600, like the seed made from it). A template without both
# placeholders would boot a guest whose key nobody knows: refused.
render_user_data() {   # <out>
    local kargs=${LOCKDOWN:+ lockdown=$LOCKDOWN} dir hk
    grep -q 'lsm=[^"]*__NN_LAB_KARGS__"' "$USER_DATA_TMPL" || die "$USER_DATA_TMPL has no __NN_LAB_KARGS__ at the end of its lsm= line"
    grep -q '^ *__NN_LAB_HOST_KEY__$' "$USER_DATA_TMPL" && grep -q '__NN_LAB_HOST_KEY_PUB__' "$USER_DATA_TMPL" \
        || die "$USER_DATA_TMPL has no ssh_keys: entry with __NN_LAB_HOST_KEY__ and __NN_LAB_HOST_KEY_PUB__"
    dir=$(dirname "$1")
    hk=$(mktemp -d "$dir/.host-key.XXXXXX")
    if ! ssh-keygen -q -t ed25519 -N '' -C nn-lab-host -f "$hk/key" </dev/null; then
        rm -rf "$hk"; die "ssh-keygen could not make the guest's host key"
    fi
    ( umask 077
      sed -e "s|__SSH_PUBKEY__|$(cat "$KEY.pub")|" -e "s|__NN_LAB_KARGS__|$kargs|" \
          -e "s|__NN_LAB_HOST_KEY_PUB__|$(cat "$hk/key.pub")|" "$USER_DATA_TMPL" |
          awk -v kf="$hk/key" '
              /^ *__NN_LAB_HOST_KEY__$/ { ind = $0; sub(/[^ ].*/, "", ind)
                                          while ((getline l < kf) > 0) print ind l; next }
              { print }' > "$1" )
    mv -f "$hk/key.pub" "$dir/ssh_host_ed25519_key.pub"
    rm -rf "$hk"
    if grep -q '__[A-Z_]*__' "$1"; then die "$1: a template placeholder is left: $(grep -o '__[A-Z_]*__' "$1" | head -1)"; fi
    grep -q -- '-----END OPENSSH PRIVATE KEY-----' "$1" || die "$1: the host key was not written"
}
# <<< render-user-data

need_host_deps() {
    local missing=()
    for b in qemu-system-x86_64 qemu-img cloud-localds ssh ssh-keygen rsync curl; do
        command -v "$b" >/dev/null 2>&1 || missing+=("$b")
    done
    if ((${#missing[@]})); then
        die "missing on host: ${missing[*]} — run: sudo apt install qemu-system-x86 qemu-utils cloud-image-utils openssh-client rsync curl"
    fi
    if [[ $ACCEL == kvm ]]; then
        if [[ $CI_MODE == 1 && ! ( -r /dev/kvm && -w /dev/kvm ) ]]; then
            die "/dev/kvm not usable by $(id -un) (NN_LAB_CI=1): the runner must expose KVM and open it to the job's user (the udev rule of .github/workflows/lab-vm.yml)"
        fi
        [[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm not usable: enable nested virtualization and add yourself to the kvm group (sudo usermod -aG kvm \$USER, then re-login) — or NN_LAB_ACCEL=whpx (QEMU for Windows) / tcg (emulation)"
    else
        log "NN_LAB_ACCEL=tcg: software emulation, no KVM — builds and timing-sensitive tests run far slower"
    fi
}

vm_running() {
    if [[ $ACCEL == whpx ]]; then
        # The guest is up when it answers with its own host key (lab PR
        # 211): a listener on the port with another key is not the guest.
        if [[ ! -s $KNOWN_HOSTS ]]; then
            log "$(no_host_key_msg)"
            return 1
        fi
        local rc=0
        guest_probe || rc=$?
        ((rc != 2)) || log "$(host_key_mismatch_msg)"
        return "$((rc == 0 ? 0 : 1))"
    fi
    [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

# ── QEMU for Windows + WHPX (NN_LAB_ACCEL=whpx) ───────────────────────
# The guest's disks live in $NN_LAB_WIN_DIR\<distro>. QEMU forwards ssh on
# the WSL-facing host address only (not on the LAN), and a socat user unit
# (nn-fwd-<distro>) maps it to 127.0.0.1:<port> here, so every sub-command
# and lab probe talks to 127.0.0.1 as with KVM. WHPX hangs on a guest reset
# ("reboot: Restarting system"), so QEMU runs with -no-reboot: a guest
# reboot ends the process, and `up` (or the wait for ssh) starts it again.
WIN_LAB_DIR=${NN_LAB_WIN_DIR:-'C:\nn-lab'}
WIN_QEMU=${NN_LAB_WIN_QEMU:-'C:\Program Files\qemu\qemu-system-x86_64w.exe'}
WIN_QEMU_IMG=${NN_LAB_WIN_QEMU_IMG:-'C:\Program Files\qemu\qemu-img.exe'}
FWD_UNIT="nn-fwd-$GUEST_NAME"

whpx_dir_win() { printf '%s\\%s' "$WIN_LAB_DIR" "$GUEST_NAME"; }
whpx_dir() { wslpath -u "$(whpx_dir_win)"; }
# A Windows program, from a Windows working directory (a WSL one makes it
# warn about UNC paths); a user unit has no interop dirs on PATH.
win() { (cd /mnt/c && PATH="$PATH:/mnt/c/WINDOWS/system32:/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0" "$@"); }
whpx_host_ip() { ip route | awk '/default/ {print $3; exit}'; }
whpx_pid() { tr -d '\r ' < "$(whpx_dir)/qemu.pid" 2>/dev/null || true; }
whpx_qemu_running() {
    local p; p=$(whpx_pid)
    [[ -n "$p" ]] && win tasklist.exe /FI "PID eq $p" 2>/dev/null | tr -d '\r' | grep -q qemu-system
}
whpx_launch() {
    win powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(whpx_dir_win)\\start.ps1" >/dev/null
}
whpx_forward() {
    systemctl --user stop "$FWD_UNIT" 2>/dev/null || true
    systemd-run --user --collect --quiet --unit="$FWD_UNIT" \
        socat TCP-LISTEN:"$SSH_PORT",bind=127.0.0.1,fork,reuseaddr TCP:"$(whpx_host_ip)":"$SSH_PORT" ||
        die "could not start the ssh forwarder (needs a systemd user session)"
}

whpx_up() {
    local b
    for b in wslpath socat cloud-localds ssh ssh-keygen curl; do
        command -v "$b" >/dev/null 2>&1 || die "missing on host: $b — sudo apt install socat cloud-image-utils openssh-client curl"
    done
    [[ -f "$(wslpath -u "$WIN_QEMU")" ]] || die "QEMU for Windows not found at $WIN_QEMU (NN_LAB_WIN_QEMU)"
    local dir dirw
    dirw=$(whpx_dir_win)
    dir=$(whpx_dir)
    SERIAL="$dir/serial.log"
    mkdir -p "$dir" "$LAB_DIR"
    if [[ ! -f "$dir/$BASE_IMG_NAME" ]]; then
        if [[ -f "$BASE_IMG" ]]; then
            cp "$BASE_IMG" "$dir/"
            if [[ -f "$BASE_IMG.verified" ]]; then cp "$BASE_IMG.verified" "$dir/"; fi
        else
            lab_fetch_image "$dir/$BASE_IMG_NAME"
        fi
    fi
    [[ -f "$KEY" ]] || ssh-keygen -q -t ed25519 -N '' -C nn-lab -f "$KEY"
    local fresh=0
    if [[ ! -f "$dir/disk.qcow2" ]]; then
        lab_check_image "$dir/$BASE_IMG_NAME"
        win "$(wslpath -u "$WIN_QEMU_IMG")" create -q -f qcow2 -b "$dirw\\$BASE_IMG_NAME" -F qcow2 "$dirw\\disk.qcow2" "$DISK_SIZE"
        fresh=1
    fi
    if [[ ! -f "$dir/seed.iso" || $fresh == 1 ]]; then
        local ud="$LAB_DIR/user-data" md="$LAB_DIR/meta-data"
        render_user_data "$ud"
        printf 'instance-id: nn-lab-%s-%s\nlocal-hostname: nn-lab-%s\n' "$GUEST_NAME" "$(date +%s)" "$GUEST_NAME" > "$md"
        (umask 077; cloud-localds "$dir/seed.iso" "$ud" "$md")
        record_injected_host_key
    fi
    echo "$SSH_PORT" > "$LAB_DIR/ssh_port"
    local h; h=$(whpx_host_ip)
    cat > "$dir/start.ps1" <<EOF
\$a = @("-accel","whpx","-machine","q35","-cpu","max","-smp","$CPUS","-m","$MEM",
  "-drive","file=$dirw\\disk.qcow2,if=virtio,format=qcow2",
  "-drive","file=$dirw\\seed.iso,if=virtio,format=raw,readonly=on",
  "-netdev","user,id=n0,hostfwd=tcp:$h:$SSH_PORT-:22","-device","virtio-net-pci,netdev=n0",
  "-device","virtio-rng-pci","-display","none","-serial","file:$dirw\\serial.log","-monitor","none","-no-reboot")
\$p = Start-Process -FilePath "$WIN_QEMU" -ArgumentList \$a -PassThru -WindowStyle Hidden
\$p.Id | Out-File -Encoding ascii "$dirw\\qemu.pid"
EOF
    if whpx_qemu_running; then
        log "already running (QEMU for Windows pid $(whpx_pid))"
    else
        log "booting $GUEST_NAME (whpx): ${CPUS} vCPU, ${MEM} MiB, ssh → $h:$SSH_PORT → 127.0.0.1:$SSH_PORT"
        whpx_launch
    fi
    whpx_forward
    wait_ssh "${NN_LAB_BOOT_TIMEOUT:-900}"
    guest_provision_bpftool
    guest_provision_nftables
    cmd_check
}

whpx_down() {
    # The guest is powered off from inside: not without its host key, or
    # it would be killed after two minutes (lab PR 211).
    if [[ ! -s $KNOWN_HOSTS ]] && whpx_qemu_running; then die "$(no_host_key_msg); nothing stopped"; fi
    vssh 'sudo systemctl poweroff' >/dev/null 2>&1 || true
    local _
    for _ in $(seq 1 60); do whpx_qemu_running || break; sleep 2; done
    if whpx_qemu_running; then
        log "forcing QEMU exit"
        win taskkill.exe /PID "$(whpx_pid)" /F >/dev/null 2>&1 || true
    fi
    systemctl --user stop "$FWD_UNIT" 2>/dev/null || true
    log "stopped"
}

# >>> host-key (xtask/tests/lab_host_safety.rs runs this block)
# The guest's known_hosts (external audit LAB-025, lab PR 211; see SSH_OPTS).
no_host_key_msg() {
    printf '%s' "no host key recorded for guest $GUEST_NAME ($KNOWN_HOSTS): \`nn-lab.sh up\` records it" \
        " (generated at the guest's creation, or taken once from the guest's own port for a disk that predates that)," \
        " \`nn-lab.sh trust-host-key\` takes the running guest's again"
}
host_key_mismatch_msg() {
    printf '%s' "the ssh server on 127.0.0.1:$SSH_PORT does not present guest $GUEST_NAME's recorded host key" \
        " ($KNOWN_HOSTS): it is not the guest (another process on the port while the guest is down?)," \
        " or a guest recreated by an older nn-lab.sh — then \`nn-lab.sh trust-host-key\`. Nothing was sent."
}
# Without a recorded key nothing connects: the call fails as ssh does
# (255) and says why, so `|| true` callers go on and the others stop.
need_known_host() {
    [[ -s $KNOWN_HOSTS ]] && return 0
    log "$(no_host_key_msg)"
    return 255
}
vssh() { need_known_host || return; ssh "${SSH_OPTS[@]}" "$GUEST" "$@"; }
vrsync() { need_known_host || return; rsync -e "$RSYNC_RSH" "$@"; }
vscp() { need_known_host || return; scp -q "${SCP_OPTS[@]}" "$@"; }
# One batch connection: 0 the guest answered, 2 a host key that is not the
# guest's (or no ed25519 key at all), 1 anything else (not up yet).
guest_probe() {
    local err
    err=$(vssh -o BatchMode=yes true 2>&1 >/dev/null) && return 0
    if grep -qE 'Host key verification failed|no matching host key type|REMOTE HOST IDENTIFICATION HAS CHANGED' <<<"$err"; then
        return 2
    fi
    return 1
}
# The processes that may listen on the forwarded port: the guest's QEMU,
# or under whpx the socat forwarder unit (127.0.0.1 → QEMU for Windows).
lab_listener_pids() {
    if [[ $ACCEL == whpx ]]; then
        local cg
        systemctl --user show -p MainPID --value "$FWD_UNIT" 2>/dev/null || true
        cg=$(systemctl --user show -p ControlGroup --value "$FWD_UNIT" 2>/dev/null || true)
        if [[ -n $cg ]]; then cat "/sys/fs/cgroup$cg/cgroup.procs" 2>/dev/null || true; fi
    else
        cat "$PIDFILE" 2>/dev/null || true
    fi
}
# Every listener on 127.0.0.1:$SSH_PORT (any address that covers it) is
# one of lab_listener_pids. ss names the owner of the user's own sockets
# only: a listener without one is another user's.
port_is_the_guests() {
    local lines l pid pids allowed n=0
    lines=$(ss -Hltnp "sport = :$SSH_PORT" 2>/dev/null) || return 1
    [[ -n $lines ]] || return 1
    allowed=" $(lab_listener_pids | tr '\n' ' ') "
    while IFS= read -r l; do
        pids=$(grep -o 'pid=[0-9]*' <<<"$l" | cut -d= -f2 || true)
        [[ -n $pids ]] || return 1
        for pid in $pids; do [[ $allowed == *" $pid "* ]] || return 1; done
        n=$((n + 1))
    done <<<"$lines"
    ((n > 0))
}
# known_hosts from one `ssh-ed25519 <base64>` key, replaced in one rename.
write_known_hosts() {   # <type> <base64>
    [[ $1 == ssh-ed25519 && $2 =~ ^[A-Za-z0-9+/]+=*$ ]] || die "not an ed25519 public key: $1 ${2:0:20}…"
    local tmp
    tmp=$(mktemp "$KNOWN_HOSTS.XXXXXX")
    printf '%s %s %s\n' "$HOST_KEY_ALIAS" "$1" "$2" > "$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$KNOWN_HOSTS"
}
known_host_fingerprint() {
    [[ -s $KNOWN_HOSTS ]] && ssh-keygen -l -f "$KNOWN_HOSTS" 2>/dev/null | awk '{print $2; exit}'
}
# The key render_user_data generated, while the user-data it went into is
# the guest's: no connection needed.
known_host_from_seed() {
    [[ -s $HOST_KEY_PUB && -s $LAB_DIR/user-data ]] || return 1
    local type b64 _
    read -r type b64 _ < "$HOST_KEY_PUB"
    grep -qF "$b64" "$LAB_DIR/user-data" || return 1
    write_known_hosts "$type" "$b64"
    log "host key of $GUEST_NAME: $(known_host_fingerprint) (generated at its creation; $KNOWN_HOSTS)"
}
# A new seed: its key replaces whatever known_hosts said (a recreated guest).
record_injected_host_key() {
    local type b64 _
    read -r type b64 _ < "$HOST_KEY_PUB"
    write_known_hosts "$type" "$b64"
    log "host key of the new $GUEST_NAME instance: $(known_host_fingerprint) (generated here, injected by cloud-init; $KNOWN_HOSTS)"
}
# Trust on first use, for a disk that predates injected host keys: only
# while the port is served by the guest's own QEMU/forwarder, before and
# after the scan. 0 recorded, 3 the port is not the guest's, 1 no answer.
record_existing_host_key() {
    port_is_the_guests || return 3
    local scan type b64
    scan=$(ssh-keyscan -T 10 -t ed25519 -p "$SSH_PORT" 127.0.0.1 2>/dev/null || true)
    read -r type b64 < <(awk '$2 == "ssh-ed25519" && NF >= 3 { print $2, $3; exit }' <<<"$scan") || true
    [[ -n ${b64:-} ]] || return 1
    port_is_the_guests || return 3
    write_known_hosts "$type" "$b64"
    log "recorded the host key of $GUEST_NAME on first use: $(known_host_fingerprint) ($KNOWN_HOSTS)." \
        "Its disk predates host keys generated by nn-lab.sh (external audit LAB-025);" \
        "\`nn-lab.sh destroy\` + \`up\` gives a guest whose key is known before its first boot."
}
# <<< host-key
# Guest shell with rustup's env loaded: `bash -l` does NOT reach the
# `source ~/.cargo/env` line (~/.bashrc returns early when non-interactive).
# ssh joins its arguments with spaces and hands the string to the remote
# login shell, so the inner command must be re-quoted (printf %q) or the
# `bash -c "…"` boundary is lost on the way.
vcargo() {
    # Debian's non-root PATH has no sbin dirs: the privileged tests spawn
    # iptables-restore through `sudo -E env PATH=$PATH`, so add them here.
    local inner="export PATH=\$PATH:/usr/sbin:/sbin; source ~/.cargo/env 2>/dev/null; cd ~/northnarrow && $*"
    vssh "bash -c $(printf '%q' "$inner")"
}

wait_ssh() {
    local deadline=$(( $(date +%s) + ${1:-600} )) said_key=0 said_port=0
    log "waiting for ssh on 127.0.0.1:$SSH_PORT (up to ${1:-600}s; first boot reboots once)…"
    while (( $(date +%s) < deadline )); do
        if [[ $ACCEL == whpx ]] && ! whpx_qemu_running; then
            log "QEMU exited (a guest reboot: -no-reboot) — starting it again"
            whpx_launch
        fi
        # A guest without a recorded host key (its disk predates lab PR
        # 211): the key render_user_data made for it, or the one its own
        # port presents (record_existing_host_key), recorded once.
        if [[ ! -s $KNOWN_HOSTS ]] && ! known_host_from_seed; then
            local rec=0
            record_existing_host_key || rec=$?
            if ((rec == 3 && !said_port)); then
                log "127.0.0.1:$SSH_PORT is not served by $GUEST_NAME's own QEMU/forwarder (ss -ltnp): not recording a host key from it"
                said_port=1
            fi
            if ((rec != 0)); then sleep 5; continue; fi
        fi
        local probe=0
        guest_probe || probe=$?
        if ((probe == 0)); then
            # Provisioning done AND we are past the reboot (lsm=bpf active;
            # on a lockdown guest, the lockdown too: Debian's first boot
            # already lists bpf)?
            if vssh "test -f /var/lib/nn-lab-provisioned && grep -q bpf /sys/kernel/security/lsm${LOCKDOWN:+ && grep -q '\\[$LOCKDOWN\\]' /sys/kernel/security/lockdown}" 2>/dev/null; then
                log "guest is up and provisioned"
                return 0
            fi
        elif ((probe == 2 && !said_key)); then
            log "$(host_key_mismatch_msg) Still waiting."
            said_key=1
        fi
        sleep 5
    done
    if ((said_key)); then die "$(host_key_mismatch_msg)"; fi
    lab_serial_tail
    die "guest did not become reachable within ${1:-600}s; see $SERIAL"
}

# CI mode (lab PR 227): the guest's console is the only view of a boot that
# failed on a runner (the workflow uploads the whole file too).
lab_serial_tail() {
    [[ $CI_MODE == 1 && -f $SERIAL ]] || return 0
    log "last 60 lines of the guest's serial console ($SERIAL):"
    tail -n 60 "$SERIAL" | tr -d '\r' | sed 's/^/  serial| /' >&2 || true
}

cmd_up() {
    if [[ $ACCEL == whpx ]]; then
        whpx_up
        return
    fi
    need_host_deps
    mkdir -p "$LAB_DIR"
    if vm_running; then
        log "already running (pid $(cat "$PIDFILE"))"
        # A guest started before lab PR 211: record its host key now.
        [[ -s $KNOWN_HOSTS ]] || wait_ssh 120
        return 0
    fi
    if [[ ! -f "$BASE_IMG" ]]; then
        lab_fetch_image "$BASE_IMG"
    fi
    if [[ ! -f "$KEY" ]]; then
        ssh-keygen -q -t ed25519 -N '' -C nn-lab -f "$KEY"
    fi
    local fresh=0
    if [[ ! -f "$DISK" ]]; then
        lab_check_image "$BASE_IMG"
        qemu-img create -q -f qcow2 -b "$BASE_IMG" -F qcow2 "$DISK" "$DISK_SIZE"
        fresh=1
    fi
    if [[ ! -f "$SEED" || $fresh == 1 ]]; then
        local ud="$LAB_DIR/user-data" md="$LAB_DIR/meta-data"
        render_user_data "$ud"
        printf 'instance-id: nn-lab-%s-%s\nlocal-hostname: nn-lab-%s\n' "$GUEST_NAME" "$(date +%s)" "$GUEST_NAME" > "$md"
        (umask 077; cloud-localds "$SEED" "$ud" "$md")
        record_injected_host_key
    fi
    if ss -ltn 2>/dev/null | grep -qE "[:.]${SSH_PORT}\b"; then
        die "127.0.0.1:$SSH_PORT is already in use on the host — pick another: NN_LAB_SSH_PORT=2322 $0 up"
    fi
    echo "$SSH_PORT" > "$LAB_DIR/ssh_port"
    local accel_args=(-enable-kvm -machine q35,accel=kvm -cpu host)
    [[ $ACCEL == tcg ]] && accel_args=(-machine q35 -accel tcg,thread=multi,tb-size=1024 -cpu max)
    log "booting $GUEST_NAME ($ACCEL): ${CPUS} vCPU, ${MEM} MiB, ssh → 127.0.0.1:$SSH_PORT"
    qemu-system-x86_64 \
        "${accel_args[@]}" -smp "$CPUS" -m "$MEM" \
        -drive "file=$DISK,if=virtio,format=qcow2" \
        -drive "file=$SEED,if=virtio,format=raw,readonly=on" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
        -device virtio-net-pci,netdev=n0 \
        -device virtio-rng-pci \
        -display none -serial "file:$SERIAL" -monitor none \
        -daemonize -pidfile "$PIDFILE"
    wait_ssh "${NN_LAB_BOOT_TIMEOUT:-900}"
    guest_provision_bpftool
    guest_provision_nftables
    cmd_check
}

cmd_check() {
    vm_running || die "guest is not running (nn-lab.sh up)"
    vssh "NN_WANT_LOCKDOWN=$LOCKDOWN bash -s" <<'REMOTE'
set -e
export PATH="$PATH:/usr/sbin:/sbin"
echo "kernel      : $(uname -r)"
echo "lsm         : $(cat /sys/kernel/security/lsm)"
grep -q '\bbpf\b' /sys/kernel/security/lsm && echo "bpf-lsm     : OK" || { echo "bpf-lsm     : MISSING"; exit 1; }
# lab PR 206: a NN_LAB_LOCKDOWN guest that is not locked down would turn the
# anti-tamper suite's C27 into a known gap under the lockdown guest's name
ld=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "not available")
echo "lockdown    : $ld"
if [ -n "${NN_WANT_LOCKDOWN:-}" ]; then
    case "$ld" in
        *"[$NN_WANT_LOCKDOWN]"*) echo "lockdown    : OK ($NN_WANT_LOCKDOWN, NN_LAB_LOCKDOWN guest)" ;;
        *) echo "lockdown    : NOT $NN_WANT_LOCKDOWN on a NN_LAB_LOCKDOWN guest"; exit 1 ;;
    esac
fi
mount | grep -q ' /sys/fs/bpf ' && echo "bpffs       : mounted" || echo "bpffs       : NOT mounted"
command -v iptables-restore >/dev/null && echo "iptables    : $(iptables --version)" || { echo "iptables    : MISSING"; exit 1; }
command -v nft >/dev/null && echo "nft         : $(nft --version 2>/dev/null)" || echo "nft         : MISSING (install.sh refuses; nn-lab.sh install provisions it)"
# `command -v` is not enough: Ubuntu's bpftool is a wrapper that fails
# without linux-tools-$(uname -r).
if bv=$(sudo bpftool version 2>/dev/null) && [ -n "$bv" ]; then
    echo "bpftool     : $(echo "$bv" | head -1)"
else
    echo "bpftool     : missing ('bpftool version' fails; Ubuntu: linux-tools-$(uname -r))"
fi
source ~/.cargo/env 2>/dev/null && echo "cargo       : $(cargo --version)" || { echo "cargo       : MISSING"; exit 1; }
echo "mem         : $(free -g | awk '/Mem:/ {print $2}') GiB, cpus: $(nproc)"
REMOTE
}

# The privileged fixtures stop their agents by evicting them from
# PROTECTED_PIDS with bpftool. Ubuntu's /usr/sbin/bpftool (linux-tools-common)
# is only a wrapper around linux-tools-$(uname -r): without that package the
# eviction failed unnoticed on a 22.04 guest, the refused SIGQUIT sent the
# agent into COMBAT and it killed the test runner, then the next test
# binaries (lab PR 153). Installed by `up` (and again after a kernel change);
# the test suites refuse to start without a working bpftool.
guest_provision_bpftool() {
    vssh bash -s <<'REMOTE'
export PATH="$PATH:/usr/sbin:/sbin"
sudo bpftool version >/dev/null 2>&1 && exit 0
. /etc/os-release
[ "${ID:-}" = ubuntu ] || exit 0
pkg="linux-tools-$(uname -r)"
echo "nn-lab: bpftool does not run — installing $pkg" >&2
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=120 "$pkg" >/dev/null 2>&1 \
    || { sudo apt-get update -qq >/dev/null 2>&1 \
         && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=120 "$pkg" >/dev/null 2>&1; } \
    || echo "nn-lab: apt-get install $pkg failed" >&2
exit 0
REMOTE
}

# Lab follow-up (lab PR 165): install.sh refuses a host without `nft`. The
# templates install nftables on a new guest; one provisioned before gets it
# here (`up`, `install`). To check the refusal itself, remove the package
# in the guest and run install.sh by hand.
guest_provision_nftables() {
    vssh bash -s <<'REMOTE'
export PATH="$PATH:/usr/sbin:/sbin"
command -v nft >/dev/null 2>&1 && exit 0
echo "nn-lab: nft missing — installing nftables" >&2
if command -v apt-get >/dev/null 2>&1; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=120 nftables >/dev/null 2>&1 \
        || { sudo apt-get update -qq >/dev/null 2>&1 \
             && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=120 nftables >/dev/null 2>&1; } \
        || echo "nn-lab: apt-get install nftables failed" >&2
else
    sudo dnf install -y -q nftables >/dev/null 2>&1 || echo "nn-lab: dnf install nftables failed" >&2
fi
exit 0
REMOTE
}

guest_require_bpftool() {
    guest_provision_bpftool
    vssh 'export PATH="$PATH:/usr/sbin:/sbin"; sudo bpftool version >/dev/null 2>&1' \
        || die "'sudo bpftool version' fails in the guest: the privileged fixtures could not stop their agents — refusing to start (Ubuntu: sudo apt-get install linux-tools-\$(uname -r))"
}

cmd_sync() {
    vm_running || die "guest is not running"
    local obj="$REPO/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf"
    command -v bpf-linker >/dev/null 2>&1 || die "bpf-linker not on PATH (cargo install bpf-linker --version 0.10.3 --locked)"
    log "building eBPF object on host (cargo xtask build-ebpf)"
    (cd "$REPO" && cargo ${LAB_CARGO_LOCKED:+--locked} xtask build-ebpf ${LAB_CARGO_LOCKED:+--locked} >/dev/null)
    [[ -f "$obj" && -f "$obj.buildhash" ]] || die "eBPF object/stamp missing after build: $obj"
    # (target/kb, the LLM advisor's knowledge base, rode along until the
    # advisor was removed in Wave 4, lab PR 214.)
    log "rsync $REPO → guest:~/northnarrow (target/ excluded, eBPF object included)"
    # Compare by content and let changed files take the guest's clock. With
    # the host's mtimes preserved, a sync from another checkout or worktree
    # can land sources older than the guest's last build: cargo's mtime
    # fingerprint then keeps the stale crate and the build fails, or worse,
    # links the old code.
    vrsync -az --checksum --no-times --delete \
        --exclude='/fuzz/artifacts/' \
        --exclude='/fuzz/corpus/' \
        --exclude='/fuzz/target/' \
        --exclude='/target/' \
        --include='/agent-ebpf/target/' \
        --include='/agent-ebpf/target/bpfel-unknown-none/' \
        --include='/agent-ebpf/target/bpfel-unknown-none/release/' \
        --include='/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf' \
        --include='/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf.buildhash' \
        --exclude='/agent-ebpf/target/bpfel-unknown-none/release/*' \
        --exclude='/agent-ebpf/target/bpfel-unknown-none/*' \
        --exclude='/agent-ebpf/target/*' \
        --exclude='target/' --exclude='.git/' \
        "$REPO/" "$GUEST:northnarrow/"
}

cmd_build() {
    vm_running || die "guest is not running"
    # LTO "fat" (Cargo.toml release profile) can peak 6-8 GiB at link;
    # the guest has ~7 GiB, so default to thin here (NN_LAB_LTO=fat to
    # mirror production exactly on a bigger guest).
    local lto=${NN_LAB_LTO:-thin}
    # NN_LAB_CARGO_ENV: extra variables for this build, e.g. a profiling
    # build with symbols ('CARGO_PROFILE_RELEASE_STRIP=none
    # CARGO_PROFILE_RELEASE_DEBUG=line-tables-only'); perf can then name the
    # agent's functions (the release profile strips them).
    vcargo "CARGO_PROFILE_RELEASE_LTO=$lto ${NN_LAB_CARGO_ENV:-} cargo build --release $LAB_CARGO_LOCKED --features test-privileged,debug-trigger -p northnarrow-agent -p northnarrow-watchdog -p northnarrow-scan 2>&1 | grep -vE '^\s+(Compiling|Downloaded|Downloading|Locking|Adding|Updating)' | tail -40; ls -la target/release/northnarrow-agent target/release/nn-admin target/release/northnarrow-watchdog"
}

# Purge the pin root on the guest the way an operator must now do it (review
# entry 39 — the running agent protects /sys/fs/bpf/northnarrow): open the
# trusted-installer window with the lab's admin key, stop the units, remove
# the pins, wait for the LSM programs to detach. When no window can be
# opened, the guest is restarted with the units disabled (bpffs does not
# survive a reboot) and the units are enabled again. The lab never edits
# admin.pub (external audit LAB-002): install.sh gives the bootstrap key the
# roles the lab uses, and a guest installed before that (no key with
# `trusted-installer`) is refused, to be recreated.
lab_purge_pins() {
    local out
    out=$(vssh bash -s <<'REMOTE'
# Review 26: the installed layout (install.sh: /usr/local/bin; package
# layout: /usr/bin), read from the unit — an absolute path also sidesteps
# RHEL's sudo secure_path, which has no /usr/local/bin.
agent_exe=$(systemctl show -p ExecStart --value northnarrow-agent 2>/dev/null | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)
agent_exe=${agent_exe:-/usr/local/bin/northnarrow-agent}
nn_admin=$(dirname "$agent_exe")/nn-admin
if sudo test -d /sys/fs/bpf/northnarrow; then
    # The window can only be opened through a running agent. After an e2e
    # run the fixtures' pins are still there (protected) and the installed
    # agent is stopped: start it — as a protected pid it purges the stale
    # pins at boot — and open the window through it.
    if ! systemctl is-active --quiet northnarrow-agent && [ -x "$agent_exe" ] \
       && systemctl list-unit-files northnarrow-agent.service >/dev/null 2>&1; then
        sudo systemctl start northnarrow-agent 2>/dev/null && sleep 5
    fi
    # External audit DEP-001: install.sh writes the bootstrap key to
    # /root/northnarrow-admin.key; a guest installed before keeps it in
    # /etc/northnarrow.
    key=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
    if systemctl is-active --quiet northnarrow-agent && [ -n "$key" ]; then
        if ! sudo "$nn_admin" trusted-installer-grant --key "$key" --window-secs 300 >/tmp/nn-grant.log 2>&1; then
            echo "grant refused: $(tail -1 /tmp/nn-grant.log)"
        elif ! sudo grep -q "config-manage" /etc/northnarrow/admin.pub; then
            # Tappa 10.8: the lab key signs overlays too (tamper-check C24).
            # External audit LAB-002: admin.pub is not edited here.
            echo "admin.pub: no key has config-manage (installed before Tappa 10.8): recreate the guest, or tamper-check C24 fails"
        fi
    fi
    # External audit EBPF-001: the units refuse a manual stop; inside the
    # window systemd's signals are delivered — watchdog first (it would
    # respawn the agent), SIGTERM, SIGKILL for whatever outlives 10 s.
    for u in northnarrow-watchdog northnarrow-agent; do
        sudo systemctl kill --signal=SIGTERM "$u" 2>/dev/null
        for i in $(seq 1 20); do
            [ -z "$(sudo cat /sys/fs/cgroup/system.slice/$u.service/cgroup.procs 2>/dev/null)" ] && break
            sleep 0.5
        done
        sudo systemctl kill --signal=SIGKILL "$u" 2>/dev/null
        sudo systemctl reset-failed "$u" 2>/dev/null
    done
    sudo pkill -9 -f "northnarrow-agent-e2etes[t]|northnarrow-watchdog-e2etes[t]" 2>/dev/null
    sudo rm -rf /sys/fs/bpf/northnarrow 2>/dev/null
    sudo test -d /sys/fs/bpf/northnarrow && echo PINS_PROTECTED
    # tamper-check leftovers (protected while an agent ran; the window is open now)
    sudo rm -f /etc/northnarrow/zz-tamper-*.local 2>/dev/null
    sudo rm -rf /run/systemd/system.control/northnarrow-agent.service.d 2>/dev/null
    sudo rm -f /run/systemd/transient/northnarrow-agent.service 2>/dev/null
    sudo grep -q "evil-implant" /etc/northnarrow/process-comm-allowlist.local 2>/dev/null \
        && sudo rm -f /etc/northnarrow/process-comm-allowlist.local /etc/northnarrow/process-comm-allowlist.local.sig
fi
for i in $(seq 1 20); do
    n=$(sudo bpftool prog show 2>/dev/null | grep -c " lsm ")
    [ "$n" = "0" ] && break
    sleep 1
done
echo "lsm programs still loaded: $(sudo bpftool prog show 2>/dev/null | grep -c " lsm ")"
REMOTE
)
    echo "$out" | grep -vE "^PINS_PROTECTED$"
    if echo "$out" | grep -q "^PINS_PROTECTED$"; then
        # External audit LAB-002: such a guest used to be "migrated" by
        # adding roles to every key in admin.pub while nothing protected it.
        if vssh 'sudo test -f /etc/northnarrow/admin.pub && ! sudo grep -q trusted-installer /etc/northnarrow/admin.pub'; then
            die "pin root protected and no key in admin.pub has the trusted-installer role (installed before it existed); the lab does not edit admin.pub (external audit LAB-002): recreate the guest (destroy, up, sync, install)"
        fi
        echo "nn-lab: pin root protected and no trusted-installer window — restarting the guest with the units disabled"
        vssh 'sudo systemctl disable northnarrow-agent northnarrow-watchdog 2>/dev/null; true'
        cmd_down
        cmd_up
        vssh bash -s <<'REMOTE'
sudo rm -rf /sys/fs/bpf/northnarrow 2>/dev/null
sudo systemctl enable northnarrow-agent northnarrow-watchdog 2>/dev/null; true
echo "lsm programs after restart: $(sudo bpftool prog show 2>/dev/null | grep -c " lsm ")"
REMOTE
    fi
}

# External audit NN-AUD-421 (TST-015): one privileged suite, run and
# counted. `-- --list` gives the tests the suite has; the run must end with
# its one "test result: ok. N passed; 0 failed; 0 ignored; …; 0 filtered
# out" with that N (deploy/lab/lib/suite-count.sh). A test skipped, filtered
# out, ignored or compiled out fails the suite: the runbook carries no
# counts to drift. NN_LAB_E2E_TEST_ARGS: extra libtest arguments for the
# runs, not the listing (`--skip <name>` shows the check catching it).
lab_e2e_suite() {
    local label=$1 sel=$2 listf runf listed rc=0
    listf=$(mktemp) runf=$(mktemp)
    vcargo "sudo -E env \"PATH=\$PATH\" cargo test --release $LAB_CARGO_LOCKED $sel -- --list" >"$listf" || true
    listed=$(nnsc_listed "$listf")
    vcargo "sudo -E env \"PATH=\$PATH\" cargo test --release $LAB_CARGO_LOCKED $sel -- --test-threads=1 --nocapture ${NN_LAB_E2E_TEST_ARGS:-}" | tee "$runf" || rc=1
    nnsc_verdict "$label" "$listed" "$runf" >&2 || rc=1
    rm -f "$listf" "$runf"
    return "$rc"
}

cmd_test_e2e() {
    vm_running || die "guest is not running"
    # docs/integration-test-runbook.md "Run": root + single-threaded (shared iptables chain).
    # Both features: the test drives `nn-admin debug force-posture`, and
    # cargo rebuilds the CARGO_BIN_EXE_* binaries with the features of
    # THIS invocation — `test-privileged` alone yields an nn-admin without
    # the `debug` subcommand (2 of 6 tests fail with "unrecognized
    # subcommand 'debug'").
    # Two crates ship a `privileged_e2e` target; run them as separate
    # invocations (each with ITS crate's feature gate) so a failure is
    # attributable and the watchdog suite starts from a settled host.
    # The installed units must be DOWN: a running production agent sees
    # the fixtures' /tmp helpers, iptables edits and canary trips as an
    # intrusion, enters COMBAT and NEUTRALIZEs the test runner (observed:
    # `cargo test` SIGKILLed mid-suite, 2026-10-08).
    # The anti-tamper hooks outlive the agent on purpose (pinned links) and
    # the e2e fixtures' agents are foreign to a stopped enforce agent's map
    # guard: purge the pin root first, the operator way (see lab_purge_pins).
    # Every suite runs and the step fails when any of them does (the nightly
    # used to see only the last suite's status).
    guest_require_bpftool
    lab_purge_pins
    local rc=0
    lab_e2e_suite "agent privileged_e2e" "-p northnarrow-agent --features test-privileged,debug-trigger --test privileged_e2e" || rc=1
    # The FIM e2e tests are plain `#[test]` (not ignored), so neither
    # `test-ignored` nor the privileged_e2e run above covered them — the
    # lab never executed them before 2026-10-10 (review entry 33).
    log "agent privileged_e2e done — running the FIM suite"
    lab_e2e_suite "agent fim_privileged_e2e" "-p northnarrow-agent --features test-privileged,debug-trigger --test fim_privileged_e2e" || rc=1
    log "FIM suite done — running the watchdog suite"
    lab_e2e_suite "watchdog privileged_e2e" "-p northnarrow-watchdog --features test-privileged --test privileged_e2e" || rc=1
    return "$rc"
}

# One cargo run of test-ignored, framed by two lines `cargo xtask
# gate-summary` reads (lab PR 227): which run ended with which status, so a
# run that failed without a failing test (a build or cargo error) is told
# apart from one whose only failures are expected ones.
lab_ignored_run() {   # <n>/<runs> <label> <command for vcargo>
    local rc=0
    log "test-ignored run $1 start: $2"
    vcargo "$3" || rc=$?
    log "test-ignored run $1 end: $2: exit $rc"
    return "$rc"
}

cmd_test_ignored() {
    vm_running || die "guest is not running"
    guest_require_bpftool
    # Installed units hold the bpffs pins + iptables chain the tests expect
    # to own, and the enforcing agent kills `sudo cargo` (R009: root exec
    # from ~/.cargo/bin). Stop them first — watchdog first, or it respawns
    # the agent. (The nightly used to do this in its dispatcher only; a
    # stand-alone run was SIGKILLed by the agent.)
    # Purge the pins too (`lab_purge_pins` stops the units first): the
    # map-pin restart test refuses a bpffs root that still holds the
    # installed agent's pins, so with a plain stop it never ran.
    lab_purge_pins >/dev/null
    # --no-fail-fast: one failing test binary must not skip the other
    # targets (the first run stopped at 11 of 56 ignored tests).
    # $LAB_CARGO_LOCKED: --locked in CI mode (lab PR 227), empty in the lab.
    # Each of the five cargo runs is framed by lab_ignored_run's start/end
    # lines; `cargo xtask gate-summary` reads them with every `test result:`
    # line (the CI job summary; the lab can run it on a saved log).
    # NN_LAB_IGNORED_SKIP: substrings of test names to leave out (none by
    # default; the RAG release gates it skipped without target/kb left with
    # the LLM advisor in Wave 4, lab PR 214).
    local skip_args="" t
    for t in ${NN_LAB_IGNORED_SKIP-}; do skip_args+=" --skip $t"; done
    # Said once, so a saved log (and gate-summary's notes) shows what was left out.
    [[ -z $skip_args ]] || log "NN_LAB_IGNORED_SKIP: skipping the tests matching:${skip_args// --skip / }"
    # The map-pin restart test needs a pin root no earlier test agent has
    # left behind: their pins stay protected, so its own purge is refused.
    # It runs first, alone, then the pins are purged again for the rest.
    local pin_test=protected_pids_kernel_id_is_stable_across_agent_restart rc=0
    # The iptables guard's self-tests (external audit NN-AUD-232) need a
    # filter table iptables can read: the agents of the suites that follow
    # (the map-pin test's included) can leave it in a state iptables-nft
    # reports as "incompatible". They run first, on a chain of their own.
    local guard_tests="iptables::iptables_guard"
    lab_ignored_run 1/5 "fixture_selftest: the iptables guard" "sudo -E env \"PATH=\$PATH\" cargo test --release $LAB_CARGO_LOCKED -p northnarrow-agent --features test-privileged,debug-trigger --test fixture_selftest $guard_tests -- --ignored --test-threads=1" || rc=1
    lab_ignored_run 2/5 "privileged_map_pin: the restart test" "sudo -E env \"PATH=\$PATH\" cargo test --release $LAB_CARGO_LOCKED -p northnarrow-agent --features test-privileged,debug-trigger --test privileged_map_pin $pin_test -- --ignored --test-threads=1" || rc=1
    lab_purge_pins >/dev/null
    lab_ignored_run 3/5 "workspace: every #[ignore] test" "sudo -E env \"PATH=\$PATH\" cargo test --release $LAB_CARGO_LOCKED --workspace --no-fail-fast --features northnarrow-agent/test-privileged,northnarrow-agent/debug-trigger -- --ignored --test-threads=1 --skip $pin_test --skip $guard_tests$skip_args" || rc=1
    # The watchdog's privileged e2e are gated by its own feature, not by
    # #[ignore]: the run above compiled them out (0 tests), so they never
    # ran in the gate. Run them on their own, on a purged pin root.
    lab_purge_pins >/dev/null
    lab_ignored_run 4/5 "watchdog privileged_e2e" "sudo -E env \"PATH=\$PATH\" cargo test --release $LAB_CARGO_LOCKED -p northnarrow-watchdog --features test-privileged --test privileged_e2e -- --test-threads=1" || rc=1
    # The same held for the agent's FIM e2e and for six of its admin e2e
    # (force-combat/unlock, a wrong key, status, the signed shutdown, key
    # rotation, audit verify): gated by the feature, not by #[ignore], so
    # the --ignored run skipped them (found with lab PR 111). Their
    # non-ignored tests, on a purged pin root.
    lab_purge_pins >/dev/null
    lab_ignored_run 5/5 "agent fim_privileged_e2e, privileged_e2e" "sudo -E env \"PATH=\$PATH\" cargo test --release $LAB_CARGO_LOCKED -p northnarrow-agent --features test-privileged,debug-trigger --test fim_privileged_e2e --test privileged_e2e -- --test-threads=1" || rc=1
    return "$rc"
}

cmd_install() {
    vm_running || die "guest is not running"
    # `sync` rewrites the eBPF provenance stamp, so an agent binary built
    # before the last sync is "older than the stamp" and install.sh
    # (require_fresh_ebpf) refuses it. An incremental build re-runs
    # agent/build.rs and relinks the agent — seconds when nothing changed.
    cmd_build
    # Re-install on a host where an agent already ran: its binaries, unit
    # files and now the pin root itself are in PROTECTED_INODES, and the deny
    # hooks stay attached through the bpffs pins after the agent exits (by
    # design). Purge the operator way: trusted-installer window, stop, rm.
    lab_purge_pins
    guest_provision_nftables
    # External audit DEP-007: the lab installs its synced source tree (no
    # MANIFEST.sha256), which install.sh now refuses without --source-tree.
    vcargo 'sudo ./deploy/install.sh --source-tree && sudo systemctl daemon-reload && sudo systemctl start northnarrow-agent && sleep 3 && sudo systemctl start northnarrow-watchdog && systemctl --no-pager status northnarrow-agent northnarrow-watchdog | grep -E "Active|Loaded"'
}

cmd_respawn_check() {
    vm_running || die "guest is not running"
    # Design: docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md §4 — the agent must
    # come back under its OWN unit with its own caps/cgroup.
    vssh bash -s <<'REMOTE'
set -e
fail=0
old=$(sudo cat /run/northnarrow/agent.pid)
echo "agent pid before: $old"
# A plain `kill -9` from a root shell is DENIED by the task_kill LSM
# hook (the agent is in PROTECTED_PIDS — Tappa 7 working as designed).
# So is `systemctl kill` (external audit EBPF-001): PID 1 relays root's
# signal only inside a signed trusted-installer window. Open one with the
# lab key and deliver the SIGKILL through systemd: no shutdown marker is
# written (that is the signed nn-admin path only), hence the watchdog
# treats it as a crash. The respawned agent boots with the window closed.
# External audit TST-002: either refusal missing is a FAIL (it was a WARN);
# the respawn is still checked after it (the agent died either way).
if sudo kill -9 "$old" 2>/dev/null; then
    echo "FAIL: plain kill -9 from a root shell succeeded — task_kill deny hook not active, or the agent's pid not in PROTECTED_PIDS"
    fail=1
else
    echo "kill -9 from a root shell: denied (task_kill LSM hook OK)"
    nn_admin=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
    if sudo systemctl kill --kill-who=main -s SIGKILL northnarrow-agent.service 2>/dev/null; then
        echo "FAIL: systemctl kill outside a trusted-installer window succeeded — PID-1 grant not enforced"
        fail=1
    else
        echo "systemctl kill outside a window: refused — opening the window, then systemctl kill"
        key=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
        [[ -n "$key" ]] || { echo "FAIL: no lab admin key to open the window"; exit 1; }
        sudo "$nn_admin" trusted-installer-grant --key "$key" --window-secs 120 >/dev/null
        sudo systemctl kill --kill-who=main -s SIGKILL northnarrow-agent.service
    fi
fi
deadline=$(( $(date +%s) + 60 ))
new=""
while (( $(date +%s) < deadline )); do
    sleep 2
    # /run/northnarrow is 0700 root: every probe needs sudo (a plain
    # `-f` / `kill -0` from the nn user silently fails forever).
    new=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null || true)
    if [[ -n "$new" && "$new" != "$old" ]] && sudo kill -0 "$new" 2>/dev/null; then break; fi
done
[[ -n "$new" && "$new" != "$old" ]] || { echo "FAIL: no new agent pid within 60s"; sudo journalctl --namespace=northnarrow -u northnarrow-watchdog --since '-2min' --no-pager | tail -20; exit 1; }
echo "agent pid after : $new"
# The respawned agent is `activating` until it sends READY=1 (BPF load +
# attach takes a few seconds): wait for `active` instead of sampling
# once — the first nightly after #180 failed here with pid, cgroup and
# caps all correct and the unit still activating.
for i in $(seq 1 30); do
    act=$(systemctl is-active northnarrow-agent || true)
    [[ "$act" == active ]] && break
    sleep 1
done
act=$(systemctl is-active northnarrow-agent || true)
echo "unit active     : $act"
cg=$(cat /proc/$new/cgroup)
echo "cgroup          : $cg"
capeff=$(grep CapEff /proc/$new/status | awk '{print $2}')
echo "CapEff          : $capeff"
wd=$(systemctl is-active northnarrow-watchdog || true)
echo "watchdog active : $wd"
[[ "$act" == active ]] || { echo "FAIL: agent unit not active (respawned outside its unit?)"; fail=1; }
[[ "$cg" == *northnarrow-agent.service* ]] || { echo "FAIL: new agent is not in the agent unit's cgroup"; fail=1; }
(( (0x$capeff >> 5) & 1 )) || { echo "FAIL: CAP_KILL (bit 5) missing from CapEff"; fail=1; }
[[ "$wd" == active ]] || { echo "FAIL: watchdog not active after respawn"; fail=1; }
(( fail == 0 )) && echo "respawn-check: OK"
exit $fail
REMOTE
}

cmd_overhead() {
    # Tappa 10.8 — overhead of the agent on the operations it hooks. Alternates
    # agent OFF (units stopped, pin root purged: no hook attached) and agent
    # ON, ROUNDS times, runs deploy/lab/overhead/nn-bench.c on six workloads
    # (udp and dns since Tappa 10.9 step 3) and reports the medians (plus the
    # agent's own CPU time per workload).
    # Run it on an otherwise idle host: other guests' load is noise.
    vm_running || die "guest is not running"
    local rounds=${1:-3}
    local out
    out="$LAB_DIR/reports/overhead-$(date -u +%Y%m%d-%H%M%S)"
    mkdir -p "$out"
    # root-owned outside /home: as root from a user-writable path the
    # agent's R009 would kill the benchmark in the ON phase
    vssh 'cd ~/northnarrow && sudo mkdir -p /usr/local/libexec/nn-lab && sudo cc -O2 -o /usr/local/libexec/nn-lab/nn-bench deploy/lab/overhead/nn-bench.c && sudo install -m 0755 deploy/lab/overhead/run.sh /usr/local/libexec/nn-lab/nn-bench-run'
    local r phase
    for r in $(seq 1 "$rounds"); do
        for phase in off on; do
            if [[ $phase == off ]]; then
                lab_purge_pins >/dev/null
            else
                vssh 'sudo systemctl start northnarrow-agent && sleep 3 && sudo systemctl start northnarrow-watchdog && sleep 20'
            fi
            vssh 'sudo /usr/local/libexec/nn-lab/nn-bench-run /usr/local/libexec/nn-lab/nn-bench' \
                | sed "s/^/$phase $r /" | tee -a "$out/raw.txt"
        done
    done
    python3 - "$out/raw.txt" "$DISTRO" "$(vssh 'uname -r')" > "$out/overhead.md" <<'PY'
import statistics, sys
raw, distro, kernel = sys.argv[1], sys.argv[2], sys.argv[3]
rows = {}
for line in open(raw):
    phase, _round, wl, ops, cpu = line.split()
    rows.setdefault(wl, {"off": [], "on": [], "cpu": []})
    rows[wl][phase].append(float(ops))
    if phase == "on":
        rows[wl]["cpu"].append(float(cpu))
print(f"# Agent overhead — {distro} ({kernel})\n")
print("| workload | agent off (ops/s) | agent on (ops/s) | overhead | agent CPU during the run |")
print("|---|---|---|---|---|")
for wl in ("open", "wopen", "exec", "connect", "udp", "dns"):
    if wl not in rows:
        continue
    off, on = statistics.median(rows[wl]["off"]), statistics.median(rows[wl]["on"])
    cpu = statistics.median(rows[wl]["cpu"]) if rows[wl]["cpu"] else 0
    print(f"| {wl} | {off:,.0f} | {on:,.0f} | {(off - on) / off * 100:+.1f} % | {cpu:,.0f} ms |")
n = len(rows["open"]["off"])
print(f"\nMedians of {n} round{'s' if n != 1 else ''}; overhead = throughput lost with the agent running.")
PY
    cat "$out/overhead.md"
    log "overhead report: $out/overhead.md"
}

cmd_pkgmgr_check() {
    # Review 49 — the package manager must survive the agent. Installs and
    # removes a probe package carrying every persistence shape the FIM rules
    # watch (deploy/lab/pkgmgr/mk-probe-{deb,rpm}.sh), then reinstalls a
    # real package that ships a systemd unit. Pass = every transaction exits
    # 0, the package database is consistent, and no destructive verdict was
    # issued while it ran (the writes must show up as Low log-only ones).
    vm_running || die "guest is not running"
    # A gate (or an earlier check) can leave the units stopped: start them,
    # as the other checks do; an agent that does not start is not installed.
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent && sleep 4; }; sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog; systemctl is-active --quiet northnarrow-agent' \
        || die "agent not running on the guest (nn-lab.sh install)"
    vssh 'bash -s' <<'REMOTE'
set -u
fail=0
# External audit LAB-008: the probe package is built in a fresh directory
# of the lab user's, then installed as root: at a fixed /tmp path another
# user could have created the directory and swapped the package.
pd=$(mktemp -d) || exit 1
trap 'rm -rf "$pd"' EXIT
log=/tmp/nn-pkgmgr-check.log; : > "$log"
since=$(date -u +%FT%T)
step() { local what=$1; shift; if "$@" >>"$log" 2>&1; then echo "ok    $what"; else echo "FAIL  $what (rc=$?, see $log)"; fail=1; fi; }
if command -v dpkg >/dev/null 2>&1; then
    deb=$(~/northnarrow/deploy/lab/pkgmgr/mk-probe-deb.sh "$pd") || exit 1
    step "dpkg -i probe package"          sudo dpkg -i "$deb"
    step "dpkg --purge probe package"     sudo dpkg --purge nn-pkgprobe
    step "apt-get install --reinstall rsync (ships rsync.service)" \
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y rsync
    if [ -n "$(sudo dpkg --audit 2>&1)" ]; then echo "FAIL  dpkg --audit reports broken packages"; fail=1; else echo "ok    dpkg --audit clean"; fi
else
    command -v rpmbuild >/dev/null 2>&1 || step "dnf install rpm-build" sudo dnf install -y rpm-build
    rpm=$(~/northnarrow/deploy/lab/pkgmgr/mk-probe-rpm.sh "$pd") || exit 1
    step "dnf install probe package"      sudo dnf install -y "$rpm"
    step "dnf remove probe package"       sudo dnf remove -y nn-pkgprobe
    step "dnf reinstall cronie (ships crond.service)" sudo dnf reinstall -y cronie
    if sudo rpm -q nn-pkgprobe >/dev/null 2>&1; then echo "FAIL  probe package still installed"; fail=1; else echo "ok    probe package removed"; fi
fi
sleep 5
det=/var/lib/northnarrow/detections/detections.jsonl
window=$(sudo awk -v t="$since" 'index($0, "\"ts\":\"") { s = substr($0, index($0, "\"ts\":\"") + 6, 19); if (s >= t) print }' "$det")
killers=$(printf '%s\n' "$window" | grep -E '"response":"(Kill|Quarantine|Block|Full|Throttle)' || true)
if [ -n "$killers" ]; then
    echo "FAIL  destructive verdicts during the transactions:"
    printf '%s\n' "$killers" | grep -o '"rule_id":"[^"]*"\|"comm":"[^"]*"\|"response":"[^"]*"' | paste - - - | sort | uniq -c
    fail=1
else
    echo "ok    no destructive verdict"
fi
printf '%s\n' "$window" | grep '"severity":"Low"' | grep -o '"rule_id":"NN-L-FIM-[^"]*"' | sort | uniq -c | sed 's/^/      recorded: /'
[ "$fail" = 0 ] && echo "pkgmgr-check: PASS" || echo "pkgmgr-check: FAIL"
exit $fail
REMOTE
}

cmd_pkg_check() {
    # Tappa 10.8 — .deb/.rpm lifecycle in the guest's native format
    # (deploy/lab/pkg/pkg-check.sh): migration from the install.sh layout,
    # upgrade, upgrade refused without the trusted-installer key, remove,
    # purge, fresh install with a "package" install manifest. The packages
    # are built on the guest from the synced tree; the lab's install.sh
    # layout is put back at the end.
    vm_running || die "guest is not running"
    cmd_build | tail -3
    local rc=0
    vssh 'cd ~/northnarrow && bash deploy/lab/pkg/pkg-check.sh' || rc=$?
    log "restoring the lab layout (nn-lab.sh install)"
    cmd_install >/dev/null 2>&1 || { log "restore failed — run nn-lab.sh install"; rc=1; }
    return "$rc"
}

cmd_release_check() {
    # Tappa 10.8 demo — the SAME release tarball, built and attested by CI,
    # installed and verified on this guest (deploy/lab/release/release-check.sh):
    # SHA256SUMS, the binaries run on this glibc, install.sh's own tree and
    # tarball verification (provenance "checksums"), boot integrity, hooks,
    # telemetry probe, one detection end to end. DIR holds the tarball and
    # SHA256SUMS, e.g. `gh run download <release run id> -D DIR`. The lab's
    # source install is put back at the end.
    vm_running || die "guest is not running"
    local dir=${1:?usage: nn-lab.sh release-check DIR (release tarball + SHA256SUMS)}
    local tgz
    tgz=$(find "$dir" -name 'northnarrow-*-x86_64-linux.tar.gz' | head -1)
    local sums
    sums=$(find "$dir" -name SHA256SUMS | head -1)
    [[ -n "$tgz" && -n "$sums" ]] || die "no release tarball + SHA256SUMS under $dir"
    # External audit LAB-008: the tarball is extracted and installed as root
    # from here; a /tmp/nn-release another user created first is refused
    # (mkdir without -p), not reused.
    vssh 'rm -rf /tmp/nn-release && mkdir -m 0700 /tmp/nn-release'
    vrsync -a "$tgz" "$sums" "$GUEST:/tmp/nn-release/"
    # lab PR 206: release-check reads the agent's own lines through it
    vrsync -a "$REPO/deploy/lab/lib/lab-records.py" "$GUEST:/tmp/nn-release/lab-records.py"
    vrsync -a "$REPO/deploy/lab/release/release-check.sh" "$GUEST:/tmp/nn-release-check.sh"
    lab_purge_pins >/dev/null
    local rc=0
    vssh 'bash /tmp/nn-release-check.sh' || rc=$?
    log "restoring the lab's source install (nn-lab.sh install)"
    cmd_install >/dev/null 2>&1 || { log "restore failed — run nn-lab.sh install"; rc=1; }
    return "$rc"
}

cmd_verifier_check() {
    # Every program of the eBPF object through this guest's verifier, with
    # the agent's own loader setup (northnarrow-agent --verifier-check, from
    # the lab build: run `build` first). Nothing is attached. A running agent
    # is stopped first (its bpf() observer would score the loads; its pin
    # root purged, as for sensor-feasibility) and started again afterwards.
    # `synced` checks the object `sync` copied (agent-ebpf/target/…) instead
    # of the embedded one: an eBPF change without rebuilding the agent.
    # Report and the refused programs' full verifier logs: $LAB_DIR/reports.
    vm_running || die "guest is not running"
    local stamp out logs remote was_active=0 rc=0 obj_env=""
    stamp=$(date -u +%Y%m%d-%H%M%S)
    out="$LAB_DIR/reports/verifier-check-$DISTRO-$stamp.md"
    logs="$LAB_DIR/reports/verifier-check-$DISTRO-$stamp.logs"
    mkdir -p "$LAB_DIR/reports"
    case "${1:-}" in
        "") ;;
        synced) obj_env='NN_VERIFIER_CHECK_OBJECT=$HOME/northnarrow/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf ' ;;
        *) die "verifier-check: unknown argument ${1} (expected: synced)" ;;
    esac
    local only=${NN_VERIFIER_CHECK_ONLY:-}
    if vssh 'systemctl is-active --quiet northnarrow-agent'; then
        was_active=1
        lab_purge_pins >/dev/null
    fi
    vssh "sudo ${obj_env}${only:+NN_VERIFIER_CHECK_ONLY=$(printf %q "$only") }\$HOME/northnarrow/target/release/northnarrow-agent --verifier-check" | tee "$out" || rc=$?
    remote=$(sed -n 's|^verifier logs: \(/var/tmp/nn-verifier-check\.[A-Za-z0-9]*\)$|\1|p' "$out" | tail -1)
    if [[ -n $remote ]]; then
        mkdir -p "$logs"
        vssh "sudo tar -C $(printf %q "$remote") -cf - . && sudo rm -rf $(printf %q "$remote")" | tar -xf - -C "$logs" \
            && log "verifier logs: $logs"
    fi
    if [[ $was_active == 1 ]]; then
        vssh 'sudo systemctl start northnarrow-agent && sleep 3 && sudo systemctl start northnarrow-watchdog' \
            || { log "agent restart failed — run nn-lab.sh install"; rc=1; }
    fi
    log "verifier-check report: $out"
    return "$rc"
}

cmd_sensor_feasibility() {
    # Tappa 10.9 step 0 — load the throw-away probes of
    # agent-ebpf/src/sensor_probe.rs on this guest's kernel and exercise them
    # (northnarrow-agent --sensor-feasibility, from the lab build: run
    # `build` first). The installed agent is stopped and its pin root purged
    # first, then started again; the report lands under $LAB_DIR/reports.
    # BASE (a directory in the guest) runs the file checks on another
    # filesystem: the fixtures go in a fresh BASE/nn-feasibility.XXXXXX.
    vm_running || die "guest is not running"
    local base=${1:-}
    local out
    out="$LAB_DIR/reports/sensor-feasibility-$DISTRO-$(date -u +%Y%m%d-%H%M%S).md"
    mkdir -p "$LAB_DIR/reports"
    lab_purge_pins >/dev/null
    local rc=0
    # NN_FEASIBILITY_BENCH=<opens> (host env) adds the cost-per-open table.
    local bench=${NN_FEASIBILITY_BENCH:-}
    vssh "sudo ${base:+NN_FEASIBILITY_BASE=$(printf %q "$base") }${bench:+NN_FEASIBILITY_BENCH=$(printf %q "$bench") }\$HOME/northnarrow/target/release/northnarrow-agent --sensor-feasibility" | tee "$out" || rc=$?
    vssh 'sudo systemctl start northnarrow-agent && sleep 3 && sudo systemctl start northnarrow-watchdog' \
        || { log "agent restart failed — run nn-lab.sh install"; rc=1; }
    log "sensor-feasibility report: $out"
    return "$rc"
}

cmd_open_sensor_check() {
    # Tappa 10.9 step 1 (deploy/lab/open-sensor/open-sensor-check.sh): the
    # sensor is armed and the old tracepoint retired, credential stores in
    # a user's home are detected (also through io_uring), a mass write is
    # one kernel-counted event, a cron write raises PersistenceMechanism,
    # and the telemetry probe never goes silent. Needs a sync + install.
    vm_running || die "guest is not running"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; cd ~/northnarrow && bash deploy/lab/open-sensor/open-sensor-check.sh'
}

cmd_exec_sensor_check() {
    # Tappa 10.9 step 2 (deploy/lab/exec-sensor/exec-sensor-check.sh): the
    # exec sensor is armed, and R001/R004 kill what the kernel executed
    # whatever string the caller passed: a relative path, a symlink, dot
    # segments, a script, a memfd behind a symlink. Needs a sync + install.
    vm_running || die "guest is not running"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; cd ~/northnarrow && bash deploy/lab/exec-sensor/exec-sensor-check.sh'
}

cmd_execq_check() {
    # Lab PR 223 (deploy/lab/execq/execq-check.sh, EXPERIMENTAL): the exec
    # quarantine on, a lab-only signed block list; a new binary held and
    # resumed, a block-listed one killed before its first instruction and
    # quarantined, a UPX-packed one flagged, package binaries never held,
    # the latency, the scanner stopped and killed. Needs a sync + install.
    vm_running || die "guest is not running"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; cd ~/northnarrow && bash deploy/lab/execq/execq-check.sh'
}

cmd_ransom_check() {
    # Lab PR 225 (deploy/lab/malsim/ransom-check.sh): MS-23 — the benign
    # simulator (deploy/lab/malsim/ransom-sim.py, /srv/nn-malsim only) draws
    # NN-L-IMP-001, its kill held behind the per-rule response policy (off
    # by default), and the posture reaches ENGAGED; tar, rsync, git
    # checkout and an apt install draw no NN-L-IMP-001. MS-25 — stopping,
    # switching off, signalling or reconfiguring auditd and ufw leaves the
    # NN-L-EVA records (auditd must be installed in the guest). Needs a sync
    # + install.
    vm_running || die "guest is not running"
    local args
    args=$(printf '%q ' "$@")
    vssh "sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; cd ~/northnarrow && bash deploy/lab/malsim/ransom-check.sh $args"
}

cmd_malsim_exec_check() {
    # Lab PR 226 (deploy/lab/malsim/exec-check.sh, EXPERIMENTAL): the exec
    # policy off, then enforce, audit and the desktop profile (unit drop-ins
    # in a signed trusted-installer window); benign simulations MS-01
    # (/dev/shm), MS-02 (memfd), MS-03 (deleted file), MS-32 (LD_PRELOAD from
    # /tmp) from a service context, and the negatives. Needs a sync + install.
    vm_running || die "guest is not running"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; cd ~/northnarrow && bash deploy/lab/malsim/exec-check.sh'
}

cmd_dns_sensor_check() {
    # Tappa 10.9 step 3 (deploy/lab/dns-sensor/dns-sensor-check.sh): the DNS
    # sensor reads the kernel's copy of the query. NET-004 kills a sender
    # over IPv4 and IPv6, with the payload in a page not faulted in yet or a
    # zero byte inside a label, and records a query sent in pieces. Needs a
    # sync + install.
    vm_running || die "guest is not running"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; cd ~/northnarrow && bash deploy/lab/dns-sensor/dns-sensor-check.sh'
}

cmd_net_check() {
    # Lab PR 224 (deploy/lab/malsim/net-check.sh): benign loopback
    # simulations of a long-lived C2 session, a beacon, a staged binary on
    # TCP/53, reverse shells and an outbound scan / brute force; the verdicts
    # are read from the signed detections log. Needs a sync + install.
    vm_running || die "guest is not running"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; cd ~/northnarrow && bash deploy/lab/malsim/net-check.sh'
}

cmd_fim_reuse_check() {
    # Review 57 (deploy/lab/fim/inode-reuse-check.sh): a file dropped in a
    # watched directory and deleted gives its inode number back; a write to
    # the unrelated file that reuses it must not reach the FIM rules.
    vm_running || die "guest is not running"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; cd ~/northnarrow && bash deploy/lab/fim/inode-reuse-check.sh'
}

cmd_btrfs_check() {
    # Review 55 regression check (deploy/lab/btrfs/btrfs-check.sh): a watched
    # credential file on a btrfs subvolume (loop filesystem bind-mounted on
    # /root/.aws) must draw NN-L-FIM-011 when read. N/A (exit 0) on kernels
    # without btrfs, NOT RUN (exit 2) when the module does not load (it is
    # loaded with the agent stopped: R011 kills module tooling). The guest is
    # put back as it was.
    vm_running || die "guest is not running"
    vrsync -a "$REPO/deploy/lab/btrfs/btrfs-check.sh" "$GUEST:/tmp/nn-btrfs-check.sh"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog; bash /tmp/nn-btrfs-check.sh'
}

cmd_overlay_check() {
    # External audit EBPF-016 (NN-AUD-267, lab PR 189;
    # deploy/lab/overlay/overlay-check.sh): a watched credential file on an
    # overlay mount (bind-mounted on /root/.aws) must draw NN-L-FIM-011 when
    # read, or the boot must carry the signed `inode_identity_unverified`
    # record naming it. Silence fails. The guest is put back as it was.
    vm_running || die "guest is not running"
    vrsync -a "$REPO/deploy/lab/overlay/overlay-check.sh" "$GUEST:/tmp/nn-overlay-check.sh"
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog; bash /tmp/nn-overlay-check.sh'
}

cmd_tamper_check() {
    # Structured adversarial check of the anti-tamper (Tappa 10.8): every
    # documented neutralisation attempt, with expected outcome and evidence.
    vm_running || die "guest is not running"
    local rc=0
    vssh 'sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 4; }; sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog; cd ~/northnarrow && sudo bash deploy/lab/adversarial/anti-tamper.sh' || rc=$?
    # C19, C23 and C24 leave overlays in /etc/northnarrow, and C24's is
    # signed: its `+backupd` exemption stayed in force, and the e2e
    # fixtures' agents (another agent_id) logged it as an unauthorised
    # overlay, which broke audit_verify_e2e's entry count. The agent
    # protects an overlay once it has seen it, so remove them the operator
    # way: purge the pins, delete, start the units again.
    log "removing the overlays the run left in /etc/northnarrow"
    lab_purge_pins >/dev/null
    vssh 'sudo rm -f /etc/northnarrow/zz-tamper-*.local /etc/northnarrow/process-comm-allowlist.local /etc/northnarrow/process-comm-allowlist.local.sig; sudo systemctl start northnarrow-agent && sleep 3 && sudo systemctl start northnarrow-watchdog' || rc=1
    return "$rc"
}

cmd_ssh() {
    vm_running || die "guest is not running"
    vssh "$@"
}

# Record the running guest's host key again, on purpose (lab PR 211): a
# guest recreated by an nn-lab.sh older than that, or keys changed inside
# it. Same rule as at `up`: taken only from a port served by the guest's
# own QEMU (or its whpx forwarder), and checked by a strict connection.
cmd_trust_host_key() {
    if [[ $ACCEL == whpx ]]; then
        whpx_qemu_running || die "guest is not running (nn-lab.sh up)"
    else
        vm_running || die "guest is not running (nn-lab.sh up)"
    fi
    mkdir -p "$LAB_DIR"
    local old rc=0
    old=$(known_host_fingerprint || echo none)
    record_existing_host_key || rc=$?
    case $rc in
        0) ;;
        3) die "127.0.0.1:$SSH_PORT is not served by $GUEST_NAME's own QEMU/forwarder (ss -ltnp; under whpx \`nn-lab.sh up\` starts the forwarder): no host key recorded" ;;
        *) die "no ed25519 host key from 127.0.0.1:$SSH_PORT (is the guest's sshd up?)" ;;
    esac
    log "previous host key: $old"
    vssh -o BatchMode=yes true || die "a strict connection with the recorded key failed"
    log "OK: $HOST_KEY_ALIAS $(known_host_fingerprint)"
}

cmd_status() {
    echo "host key: ${HOST_KEY_ALIAS} $(known_host_fingerprint || echo "not recorded (nn-lab.sh up)") ($KNOWN_HOSTS)"
    if [[ $ACCEL == whpx ]]; then
        if whpx_qemu_running; then
            echo "running: QEMU for Windows pid $(whpx_pid), ssh -i $KEY -p $SSH_PORT $GUEST (forwarder $FWD_UNIT: $(systemctl --user is-active "$FWD_UNIT" 2>/dev/null || true))"
        else
            echo "stopped"
        fi
        return 0
    fi
    if vm_running; then
        echo "running: pid $(cat "$PIDFILE"), ssh -i $KEY -p $SSH_PORT $GUEST"
    else
        echo "stopped"
    fi
    # qemu-img refuses a locked (running) image: that is not an error here.
    [[ -f "$DISK" ]] && { qemu-img snapshot -l "$DISK" 2>/dev/null | tail -n +3 | awk 'NF {print "snapshot:", $2}' || true; }
    return 0
}

cmd_down() {
    if [[ $ACCEL == whpx ]]; then
        whpx_down
        return
    fi
    vm_running || { log "not running"; return 0; }
    [[ -s $KNOWN_HOSTS ]] || die "$(no_host_key_msg); nothing stopped"
    vssh sudo poweroff >/dev/null 2>&1 || true
    local pid; pid=$(cat "$PIDFILE")
    for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || { log "stopped"; rm -f "$PIDFILE"; return 0; }; sleep 1; done
    log "forcing qemu exit"; kill "$pid" 2>/dev/null || true; rm -f "$PIDFILE"
}

# qemu-img on the guest's disk: the Windows one under WHPX.
lab_qemu_img() {
    if [[ $ACCEL == whpx ]]; then
        win "$(wslpath -u "$WIN_QEMU_IMG")" "$@" "$(whpx_dir_win)\\disk.qcow2"
    else
        qemu-img "$@" "$DISK"
    fi
}

guest_down_or_die() {
    if [[ $ACCEL == whpx ]]; then
        whpx_qemu_running && die "stop the guest first (nn-lab.sh down)"
    else
        vm_running && die "stop the guest first (nn-lab.sh down)"
    fi
    return 0
}

cmd_snapshot() {
    guest_down_or_die
    [[ -n "${1:-}" ]] || die "snapshot NAME"
    lab_qemu_img snapshot -c "$1" && log "snapshot '$1' created"
}

cmd_restore() {
    guest_down_or_die
    [[ -n "${1:-}" ]] || die "restore NAME"
    lab_qemu_img snapshot -a "$1" && log "restored '$1'"
}

cmd_destroy() {
    cmd_down
    if [[ $ACCEL == whpx ]]; then
        rm -f "$(whpx_dir)/disk.qcow2" "$(whpx_dir)/seed.iso" "$(whpx_dir)/serial.log"
    fi
    rm -f "$DISK" "$SEED" "$LAB_DIR/user-data" "$LAB_DIR/meta-data" "$SERIAL" "$KNOWN_HOSTS" "$HOST_KEY_PUB"
    log "guest disk and its host key removed (base image + ssh key kept)"
}

# ── soak: hours of synthetic load with periodic resource samples ─────
# `soak start [HOURS] [INTERVAL_S]` installs the units if needed, ships
# deploy/lab/soak/{generate,sample}.sh to ~/soak on the guest and starts
# them detached (sampler as root, generator as nn); a timer touches
# ~/soak/stop after HOURS. `soak status` prints the last sample,
# `soak stop` ends it early, `soak wait` blocks until it ends, and
# `soak report` pulls samples.csv + logs into $LAB_DIR/reports/soak-<stamp>/
# and writes soak-<stamp>.md with the trend summary and a verdict:
# FAIL on any agent/watchdog restart, any journal ERROR, an RSS slope above
# NN_LAB_SOAK_MAX_RSS_MB_H (5 MB/h, judged only on runs ≥ 2 h) or an fd
# count that grew by more than half (and by more than 100).
SOAK_SCRIPTS="$SCRIPT_DIR/soak"
cmd_soak() {
    local sub=${1:-help}
    [ $# -gt 0 ] && shift
    case "$sub" in
        start)
            vm_running || die "guest is not running"
            local hours=${1:-24} interval=${2:-60}
            local secs
            secs=$(awk -v h="$hours" 'BEGIN{printf "%d", h*3600}')
            if ! vssh 'systemctl is-active --quiet northnarrow-agent && systemctl is-active --quiet northnarrow-watchdog'; then
                log "units not active — installing first"
                cmd_install
            fi
            if vssh 'test -f ~/soak/sample.pid && ! test -e ~/soak/stop' 2>/dev/null; then
                die "a soak is already running on the guest (nn-lab.sh soak status | stop)"
            fi
            vssh 'rm -rf ~/soak && mkdir -p ~/soak'
            vscp \
                "$SOAK_SCRIPTS/generate.sh" "$SOAK_SCRIPTS/sample.sh" "$GUEST:soak/"
            vssh "chmod +x ~/soak/*.sh; echo '$hours' > ~/soak/hours; echo '$interval' > ~/soak/interval; date -u +%s > ~/soak/start_epoch; echo \"\$(uname -r) \$(cat /etc/os-release | sed -n 's/^PRETTY_NAME=//p' | tr -d '\"')\" > ~/soak/host"
            # The sampler runs as root: it must NOT live under /home — the
            # agent's R009 (root exec from a user-writable path) would kill it
            # on the spot. Install it root-owned under /usr/local/sbin first.
            vssh "sudo install -m 0755 -o root -g root \$HOME/soak/sample.sh /usr/local/sbin/nn-soak-sample"
            # the sampler writes its pid when it starts: wait up to 15 s (2 s
            # was not enough on AlmaLinux with a freshly started agent)
            vssh "sudo nohup env SOAK_DIR=\$HOME/soak SOAK_INTERVAL=$interval setsid /usr/local/sbin/nn-soak-sample > \$HOME/soak/sample.log 2>&1 < /dev/null & disown; for i in \$(seq 1 15); do test -f ~/soak/sample.pid && break; sleep 1; done; test -f ~/soak/sample.pid && sudo kill -0 \$(cat ~/soak/sample.pid)"
            # SOAK_*_PER_S set on the host side travel to the generator, so a
            # targeted run (e.g. SOAK_DNS_PER_S=20) needs no script edit.
            local rates
            # no SOAK_*_PER_S set is the normal case: grep exits 1, and under
            # `set -o pipefail` that used to end the start before the
            # generator was launched (sampler running, generator never)
            rates=$(env | { grep -E '^SOAK_[A-Z_]+_PER_S=[0-9]+$' || true; } | tr '\n' ' ')
            vssh "nohup env SOAK_DIR=\$HOME/soak $rates setsid \$HOME/soak/generate.sh > \$HOME/soak/generate.log 2>&1 < /dev/null & disown"
            vssh "nohup setsid sh -c 'sleep $secs; touch \$HOME/soak/stop' > /dev/null 2>&1 < /dev/null & disown"
            log "soak started on $DISTRO: ${hours} h, sample every ${interval} s (nn-lab.sh soak status | wait | stop | report)"
            ;;
        status)
            vm_running || die "guest is not running"
            vssh 'cd ~/soak 2>/dev/null || { echo "no soak on this guest"; exit 0; }
                  echo "host     : $(cat host 2>/dev/null)"
                  echo "started  : $(cat start 2>/dev/null) for $(cat hours 2>/dev/null) h"
                  echo "elapsed  : $(( ($(date +%s) - $(cat start_epoch)) / 60 )) min"
                  echo "state    : $([ -e stop ] && echo stopped || echo running)"
                  echo "samples  : $(( $(wc -l < samples.csv 2>/dev/null || echo 1) - 1 ))"
                  echo "generator: $(cat generate.iter 2>/dev/null || echo 0) iterations"
                  echo "last     : $(head -1 samples.csv 2>/dev/null)"
                  echo "           $(tail -1 samples.csv 2>/dev/null)"'
            ;;
        stop)
            vm_running || die "guest is not running"
            vssh 'touch ~/soak/stop; sleep 3; pkill -f "sleep [0-9]*; touch .*soak/stop" 2>/dev/null; true'
            log "soak stopped (nn-lab.sh soak report)"
            ;;
        wait)
            vm_running || die "guest is not running"
            while ! vssh 'test -e ~/soak/stop' 2>/dev/null; do sleep 60; done
            sleep 5
            cmd_soak report
            ;;
        report)
            vm_running || die "guest is not running"
            local stamp dir report
            stamp=$(date +%Y%m%d-%H%M%S)
            dir="$LAB_DIR/reports/soak-$stamp"; report="$LAB_DIR/reports/soak-$stamp.md"
            mkdir -p "$dir"
            vscp \
                "$GUEST:soak/samples.csv" "$GUEST:soak/sample.log" "$GUEST:soak/sample.err" "$GUEST:soak/generate.log" "$GUEST:soak/host" "$GUEST:soak/hours" "$dir/" 2>/dev/null || true
            vssh 'sudo journalctl -u northnarrow-agent -u northnarrow-watchdog --since "$(cat ~/soak/start)" -p 4 --no-pager -q 2>/dev/null | tail -200' > "$dir/journal-warn-err.log" 2>/dev/null || true
            [ -s "$dir/samples.csv" ] || die "no samples.csv on the guest — was the soak started?"
            local max_rss_mb_h=${NN_LAB_SOAK_MAX_RSS_MB_H:-5}
            # External audit NN-AUD-216: ring drops fail the soak above this
            # (0 by default; raise it while review 45 is open)
            local max_drops=${NN_LAB_SOAK_MAX_DROPS:-0}
            local rc=0
            set +e
            awk -F, -v repo="$REPO" -v head="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)" -v distro="$DISTRO" \
                -v host="$(cat "$dir/host" 2>/dev/null)" -v hours="$(cat "$dir/hours" 2>/dev/null)" -v maxslope="$max_rss_mb_h" -v maxdrops="$max_drops" -v logdir="$dir" '
            NR == 1 { next }
            {
                n++; t[n]=$1; pid[n]=$2; rss[n]=$3; vsz[n]=$4; cpu[n]=$5; thr[n]=$6; fds[n]=$7; wd[n]=$8
                ar[n]=$9; wr[n]=$10; jw[n]=$11; je[n]=$12; cb[n]=$13; det[n]=$14; sts[n]=$15; aud[n]=$16; fim[n]=$17
                fs[n]=$18; us[n]=$19; fdm[n]=$20; pp[n]=$21; dr[n]=$22; gi[n]=$23
                # External audit ASK-009 (lab PR 213): an empty drop column is
                # a sample whose signed `status --key` read failed (no key)
                if ($22 == "") unread++
                # NN-AUD-216: liveness per sample (a sampler without the column
                # counts as alive when it found a pid); one dead sample is a
                # respawn gap, two in a row or the last one is a dead agent
                al[n] = (NF >= 24) ? $24 : (pid[n] != 0); wa[n] = (NF >= 25) ? $25 : 1; mp[n] = (NF >= 26) ? $26 : 0
                if (al[n] == 0) { deadrun++; if (deadrun > maxdead) maxdead = deadrun } else deadrun = 0
                if (wa[n] == 0) { wdrun++; if (wdrun > maxwd) maxwd = wdrun } else wdrun = 0
                if (mp[n] > mpmax) mpmax = mp[n]
                if (rss[n] > rssmax) rssmax = rss[n]; if (cpu[n] > cpumax) cpumax = cpu[n]; cpusum += cpu[n]
                if (fds[n] > fdsmax) fdsmax = fds[n]; if (fs[n] > fsmax) fsmax = fs[n]; if (us[n] > usmax) usmax = us[n]; if (fdm[n] > fdmmax) fdmmax = fdm[n]
                if (pid[n] != 0 && pid[n] != lastpid) { if (lastpid != 0) pidchanges++; lastpid = pid[n] }
            }
            END {
                if (n < 2) { print "not enough samples (" n ")"; exit 2 }
                dur_h = (t[n] - t[1]) / 3600.0
                # least-squares slope of RSS over time (kB/s → MB/h)
                for (i = 1; i <= n; i++) { x = t[i] - t[1]; sx += x; sy += rss[i]; sxx += x*x; sxy += x*rss[i] }
                den = n*sxx - sx*sx; slope = (den > 0) ? (n*sxy - sx*sy)/den : 0
                slope_mb_h = slope * 3600 / 1024
                fail = ""; warn = ""
                if (ar[n] - ar[1] > 0) fail = fail "; agent restarted " (ar[n]-ar[1]) "×"
                if (wr[n] - wr[1] > 0) fail = fail "; watchdog restarted " (wr[n]-wr[1]) "×"
                if (pidchanges > 0) fail = fail "; agent pid changed " pidchanges "×"
                if (je[n] > 0) fail = fail "; " je[n] " journal ERROR line(s)"
                if (dur_h >= 2 && slope_mb_h > maxslope) fail = fail "; RSS slope " sprintf("%.2f", slope_mb_h) " MB/h > " maxslope
                if (dur_h < 2 && slope_mb_h > maxslope) warn = warn "; RSS slope " sprintf("%.2f", slope_mb_h) " MB/h (run < 2 h, not judged)"
                if (fds[n] > fds[1]*1.5 && fds[n] - fds[1] > 100) fail = fail "; fds grew " fds[1] " → " fds[n]
                if (maxdead >= 2 || al[n] == 0) fail = fail "; agent down (" maxdead " consecutive sample(s) without a live agent" (al[n] == 0 ? ", down at the end" : "") ")"
                if (maxwd >= 2 || wa[n] == 0) fail = fail "; watchdog missing (" maxwd " consecutive sample(s))"
                if (mpmax >= 90) fail = fail "; a BPF map at " mpmax "% of max_entries"
                if (unread > 0) fail = fail "; ring-buffer drops not read in " unread " sample(s) (nn-admin status --key: no admin key on the guest, see sample.log / sample.err)"
                if (dr[n] - dr[1] > maxdrops) fail = fail "; ring-buffer drops +" (dr[n]-dr[1]) " > " maxdrops
                else if (dr[n] - dr[1] > 0) warn = warn "; ring-buffer drops +" (dr[n]-dr[1])
                if (cb[n] > 0) warn = warn "; " cb[n] " COMBAT journal line(s)"
                if (jw[n] > 0) warn = warn "; " jw[n] " journal WARN line(s)"
                verdict = (fail == "") ? "PASS" : "FAIL"
                printf "# nn-lab soak — %s — %s\n\n", distro, verdict
                printf "- repo: `%s` @ `%s`\n- guest: `%s`\n- planned: %s h, measured: %.2f h, %d samples, %d generator iterations\n- logs: `%s`\n\n", repo, head, host, hours, dur_h, n, gi[n], logdir
                printf "| metric | first | last | max | note |\n|---|---|---|---|---|\n"
                printf "| agent RSS (MB) | %.1f | %.1f | %.1f | slope %.2f MB/h |\n", rss[1]/1024, rss[n]/1024, rssmax/1024, slope_mb_h
                printf "| agent VSZ (MB) | %.0f | %.0f | — | |\n", vsz[1]/1024, vsz[n]/1024
                printf "| agent CPU %% (per sample) | %d | %d | %d | avg %.1f |\n", cpu[1], cpu[n], cpumax, cpusum/n
                printf "| agent threads / fds | %d / %d | %d / %d | fds max %d | |\n", thr[1], fds[1], thr[n], fds[n], fdsmax
                printf "| watchdog RSS (MB) | %.1f | %.1f | — | |\n", wd[1]/1024, wd[n]/1024
                printf "| restarts agent / watchdog | %d / %d | %d / %d | — | pid changes %d |\n", ar[1], wr[1], ar[n], wr[n], pidchanges
                printf "| journal WARN / ERROR / COMBAT lines | — | %d / %d / %d | — | since start |\n", jw[n], je[n], cb[n]
                printf "| detections.jsonl (KB) | %.0f | %.0f | — | +%.1f KB/h |\n", det[1]/1024, det[n]/1024, (det[n]-det[1])/1024/(dur_h>0?dur_h:1)
                printf "| status_events.jsonl (KB) | %.0f | %.0f | — | |\n", sts[1]/1024, sts[n]/1024
                printf "| audit.log (KB) | %.0f | %.0f | — | |\n", aud[1]/1024, aud[n]/1024
                printf "| fim_drift.jsonl (KB) | %.0f | %.0f | — | |\n", fim[1]/1024, fim[n]/1024
                printf "| map FLOW_SOCK_MAP / UDP_UNCONNECTED_SEEN / FIM_DIRTY_INODES | %d / %d / %d | %d / %d / %d | %d / %d / %d | PROTECTED_PIDS %d |\n", fs[1], us[1], fdm[1], fs[n], us[n], fdm[n], fsmax, usmax, fdmmax, pp[n]
                printf "| ring-buffer drops (cumulative) | %d | %d | — | |\n\n", dr[1], dr[n]
                if (fail != "") printf "**FAIL**: %s\n\n", substr(fail, 3)
                if (warn != "") printf "Notes: %s\n\n", substr(warn, 3)
                printf "| agent / watchdog alive (samples) | %d / %d | %d / %d | — | longest gap %d / %d, fullest map %d%% |\n", al[1], wa[1], al[n], wa[n], maxdead, maxwd, mpmax
                printf "Thresholds: 0 restarts, 0 journal ERROR, RSS slope ≤ %s MB/h on runs ≥ 2 h, fds growth < 50%%, agent and watchdog alive (one-sample gap allowed), maps < 90%%, ring drops ≤ %s.\n", maxslope, maxdrops
                exit (fail == "") ? 0 : 1
            }' "$dir/samples.csv" > "$report"
            rc=$?
            set -e
            ln -sfn "$report" "$LAB_DIR/reports/soak-latest.md"
            cat "$report"
            return $rc
            ;;
        *) die "usage: nn-lab.sh soak start [HOURS] [INTERVAL_S] | status | stop | wait | report" ;;
    esac
}

# ── nightly: the whole runbook, unattended, with a markdown report ──
#
# Every step runs even if an earlier one failed (a red test-e2e must not
# hide a red respawn-check), each step's output goes to its own log, and
# the report carries status + duration + the `test result:` lines. The
# exit code is 1 when any step failed, so a scheduler can alert on it.
cmd_upgrade_check() {
    vm_running || die "guest is not running"
    # Operator path: `install.sh --upgrade` on a host whose units are
    # ACTIVE (anti-tamper hooks up). Must stop watchdog→agent, drain the
    # LSM set, replace everything, restart, and leave keys + chains
    # intact with a fresh agent_boot audit entry.
    # The install preflights also refuse a binary older than the eBPF
    # stamp (`sync` refreshes the stamp): the step runs after `build` in
    # the nightly, and stand-alone it needs a fresh build too.
    vssh bash -s <<'REMOTE'
set -e
cd ~/northnarrow
# External audit PROC-007: R009 sanctions a root exec from a home directory
# only in an administrator's sudo session at a terminal (the lab drives the
# guest without one, and the running agent killed install.sh/uninstall.sh):
# script(1) gives sudo the pty an operator's shell would have (stdin from
# /dev/null: script forwards its stdin, the rest of this heredoc).
at_tty() { script -qec "$*" /dev/null < /dev/null; }
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 3; }
sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog
pid_before=$(sudo cat /run/northnarrow/agent.pid)
audit_before=$(sudo wc -l /etc/northnarrow/audit.log | cut -d" " -f1)
# External audit EVD-001: the signing key is closed to root; its public
# half stands for it (absent before that release: left out on both sides).
idfiles="/etc/northnarrow/admin.pub /etc/northnarrow/agent_id"
sudo test -e /etc/northnarrow/agent.sig.pub && idfiles="$idfiles /etc/northnarrow/agent.sig.pub"
fp_before=$(sudo sha256sum $idfiles | sha256sum | cut -c1-16)
echo "before: agent pid=$pid_before audit_lines=$audit_before identity=$fp_before"
# Without --upgrade the script must refuse (units active) — exit 1, no change.
# (--source-tree: the synced tree has no MANIFEST.sha256, external audit DEP-007.)
if at_tty sudo ./deploy/install.sh --source-tree >/tmp/nn-upgrade-refuse.log 2>&1; then
    echo "FAIL: install.sh without --upgrade succeeded while the units were active"; exit 1
fi
grep -q "Re-run with --upgrade" /tmp/nn-upgrade-refuse.log || { echo "FAIL: refusal message missing"; cat /tmp/nn-upgrade-refuse.log; exit 1; }
echo "install.sh without --upgrade: refused as expected"
key=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
# External audit DEP-006: the drain waits for the agent's own program ids;
# another product's LSM programs (bpftrace in the lab) are left alone.
own_before=$(sudo awk '$1 ~ /^[0-9]+$/ {print $1}' /run/northnarrow/bpf-own-ids 2>/dev/null | tr '\n' ' ')
foreign_before=$(sudo bpftool prog show 2>/dev/null | grep " lsm " | grep -vcE "^(${own_before// /|}x):" || true)
n_before=0
for id in $own_before; do sudo bpftool prog show id "$id" 2>/dev/null | grep -q " lsm " && n_before=$((n_before + 1)); done
echo "before: own program ids=[${own_before% }] own LSM programs=$n_before foreign LSM programs=$foreign_before"
# Lab PR 220: the upgrade is a transaction; a run that rolled back also
# restarts an agent (a new pid, a new agent_boot) — it must say it completed.
at_tty sudo ./deploy/install.sh --source-tree --upgrade --grant-key "$key" >/tmp/nn-upgrade.log 2>&1 || true
grep -E "UPGRADE|ROLLBACK|stopping|starting|waiting|is active|is inactive|is failed|LSM|BPF program|window|PROTECTED|grant|health check" /tmp/nn-upgrade.log | cut -c1-140
sleep 2
pid_after=$(sudo cat /run/northnarrow/agent.pid)
audit_after=$(sudo wc -l /etc/northnarrow/audit.log | cut -d" " -f1)
fp_after=$(sudo sha256sum $idfiles | sha256sum | cut -c1-16)
echo "after : agent pid=$pid_after audit_lines=$audit_after identity=$fp_after"
fail=0
grep -q "UPGRADE complete — health check passed" /tmp/nn-upgrade.log || { echo "FAIL: install.sh did not report a completed upgrade (rolled back? /tmp/nn-upgrade.log)"; fail=1; }
if sudo tail -n "+$((audit_before + 1))" /etc/northnarrow/audit.log | grep -q '"op":"upgrade_rolled_back"'; then
    echo "FAIL: an upgrade_rolled_back row was signed during the upgrade"; fail=1
fi
sudo test -z "$(sudo ls -A /var/lib/northnarrow-upgrade 2>/dev/null)" || { echo "FAIL: /var/lib/northnarrow-upgrade not empty after the upgrade"; fail=1; }
[[ "$(systemctl is-active northnarrow-agent)" == active ]] || { echo "FAIL: agent unit not active after upgrade"; fail=1; }
[[ "$(systemctl is-active northnarrow-watchdog)" == active ]] || { echo "FAIL: watchdog unit not active after upgrade"; fail=1; }
[[ "$pid_after" != "$pid_before" ]] || { echo "FAIL: agent pid unchanged — binary not restarted"; fail=1; }
(( audit_after > audit_before )) || { echo "FAIL: no new audit entry (agent_boot) after upgrade"; fail=1; }
[[ "$fp_after" == "$fp_before" ]] || { echo "FAIL: admin.pub / agent.sig.pub / agent_id changed across the upgrade"; fail=1; }
# the new agent's own LSM programs (its bpf-own-ids), not the host's
own_after=$(sudo awk '$1 ~ /^[0-9]+$/ {print $1}' /run/northnarrow/bpf-own-ids 2>/dev/null)
n=0
for id in $own_after; do sudo bpftool prog show id "$id" 2>/dev/null | grep -q " lsm " && n=$((n + 1)); done
# External audit LAB-020 (NN-AUD-410, lab PR 206): seven own LSM programs
# passed, against 16 deny hooks plus the observers. Now the new agent's own
# health line — logged only when every deny and observe hook attached —
# read from the journal's trusted fields (its unit's stdout, its pid; the
# message itself, never a field of another line: a file named like the line
# is not it, deploy/lab/lib/lab-records.py), with deny_attached equal to
# deny_expected and at least the 16 deny hooks of DENY_HOOKS
# (agent/src/anti_tamper/mod.rs; xtask/tests/lab_scripts.rs keeps the two
# equal); no fewer own LSM programs than before the upgrade (an observer
# lost fails too) nor than the deny hooks; and no anti-tamper
# `subsystem_degraded` signed at the upgraded boot (a start under
# NN_ANTI_TAMPER_ALLOW_DEGRADED=1, a missing observe hook).
deny_hooks_min=16
if [[ -n "$own_before" ]] && (( n < n_before )); then
    echo "FAIL: $n own LSM programs after the upgrade, $n_before before (a hook the new agent did not load)"; fail=1
fi
health=""
for i in $(seq 1 15); do
    health=$(sudo journalctl --namespace=northnarrow -u northnarrow-agent _PID="$pid_after" --no-pager -o json 2>/dev/null \
        | python3 -I deploy/lab/lib/lab-records.py journal northnarrow-agent.service "$pid_after" INFO "anti-tamper: all LSM hooks attached " | tail -1)
    [[ -n "$health" ]] && break
    sleep 1
done
health_re='^anti-tamper: all LSM hooks attached deny_attached=([0-9]+) deny_expected=([0-9]+)$'
if [[ "$health" =~ $health_re ]]; then
    da=${BASH_REMATCH[1]} de=${BASH_REMATCH[2]}
    (( da == de && de >= deny_hooks_min )) || { echo "FAIL: deny hooks $da of $de (at least $deny_hooks_min expected)"; fail=1; }
    (( n >= de )) || { echo "FAIL: $n own LSM programs, fewer than the $de deny hooks the agent counted"; fail=1; }
    echo "after : $health"
else
    echo "FAIL: the new agent (pid $pid_after) did not log that every LSM hook attached${health:+ (read: $health)}"; fail=1
fi
degraded=$(sudo tail -n "+$((audit_before + 1))" /etc/northnarrow/audit.log | python3 -I deploy/lab/lib/lab-records.py degraded)
while IFS= read -r l; do
    case "$l" in
        "degraded: anti-tamper"*) echo "FAIL: signed at the upgraded boot: ${l#degraded: }"; fail=1 ;;
        degraded:*) echo "note: signed at the upgraded boot: ${l#degraded: }" ;;
        unparsed=*) echo "FAIL: audit.log after the upgrade: ${l#unparsed=} line(s) not one JSON object"; fail=1 ;;
    esac
done <<<"$degraded"
for id in $own_before; do
    if sudo bpftool prog show id "$id" >/dev/null 2>&1; then echo "FAIL: old program id $id still loaded"; fail=1; fi
done
foreign_after=$(sudo bpftool prog show 2>/dev/null | grep " lsm " | grep -vcE "^($(echo $own_after | tr ' ' '|')|x):" || true)
# (an agent older than the list counted its own programs as foreign before)
if [[ -n "$own_before" ]] && (( foreign_after < foreign_before )); then
    echo "FAIL: foreign LSM programs $foreign_before -> $foreign_after"; fail=1
fi
echo "after : own LSM programs=$n (before: $n_before) foreign LSM programs=$foreign_after"
sudo ls /sys/fs/bpf/northnarrow/PROTECTED_PIDS >/dev/null || { echo "FAIL: PROTECTED_PIDS not re-pinned"; fail=1; }
# External audit DEC-007: a template an earlier release shipped named the
# product in every decoy rendered from it; the upgrade replaces it (an
# operator's edit is kept) and closes the directory to other users.
for t in aws azure docker gcp generic; do
    f=/etc/northnarrow/canary-templates/$t.tmpl
    if sudo grep -qiE 'northnarrow|do not use' "$f"; then echo "FAIL: $f still names the product"; fail=1; fi
    sudo cmp -s "$f" "configs/canary-templates/$t.tmpl" || echo "note: $f differs from the shipped template (operator copy kept)"
    m=$(sudo stat -c %a "$f"); [[ "$m" == 640 ]] || { echo "FAIL: $f mode $m (want 640)"; fail=1; }
done
m=$(sudo stat -c %a /etc/northnarrow/canary-templates); [[ "$m" == 750 ]] || { echo "FAIL: canary-templates mode $m (want 750)"; fail=1; }
# External audit LLMR-015 (lab PR 168): the shipped `.v1` lists are the
# release's after an upgrade (an edited one is kept as `.v1.operator`), and the
# new agent reported none as edited or an earlier release's.
for l in fim-paths netflow-blocklist netflow-ja3-blocklist process-comm-allowlist netflow-comm-allowlist; do
    sudo cmp -s "/etc/northnarrow/$l.v1" "configs/$l.v1" || { echo "FAIL: /etc/northnarrow/$l.v1 is not the shipped list after the upgrade"; fail=1; }
    if sudo test -e "/etc/northnarrow/$l.v1.operator"; then echo "note: /etc/northnarrow/$l.v1.operator kept (an edited list, replaced)"; fi
done
if sudo journalctl --namespace=northnarrow -u northnarrow-agent _PID="$pid_after" --no-pager -o cat 2>/dev/null \
        | sed 's/\x1b\[[0-9;]*m//g' | grep -qE 'DEFAULT LIST MODIFIED|the one an earlier release shipped'; then
    echo "FAIL: the upgraded agent found a default list edited or left over from an earlier release"; fail=1
fi
(( fail == 0 )) && echo "upgrade-check: OK"
exit $fail
REMOTE
}

cmd_uninstall_check() {
    vm_running || die "guest is not running"
    # Operator path: `uninstall.sh --purge --yes` on a running install
    # must leave NO binary, unit, pin, LSM program, config, state or bait
    # behind — then the normal install path brings the guest back so the
    # next step (and the next nightly) finds a working system.
    vssh bash -s <<'REMOTE'
set -e
cd ~/northnarrow
# External audit PROC-007: R009 sanctions a root exec from a home directory
# only in an administrator's sudo session at a terminal (the lab drives the
# guest without one, and the running agent killed install.sh/uninstall.sh):
# script(1) gives sudo the pty an operator's shell would have (stdin from
# /dev/null: script forwards its stdin, the rest of this heredoc).
at_tty() { script -qec "$*" /dev/null < /dev/null; }
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 3; }
sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog
key=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
# External audit DEP-006: the agent's own programs must go; another
# product's LSM programs (bpftrace in the lab) must stay.
own_ids=$(sudo awk '$1 ~ /^[0-9]+$/ {print $1}' /run/northnarrow/bpf-own-ids 2>/dev/null | tr '\n' ' ')
foreign_before=$(sudo bpftool prog show 2>/dev/null | grep " lsm " | grep -vcE "^(${own_ids// /|}x):" || true)
at_tty sudo ./deploy/uninstall.sh --purge --yes --grant-key "$key" 2>&1 | grep -E "uninstall.sh:|FAIL" | cut -c1-140
fail=0
for f in /usr/local/bin/northnarrow-agent /usr/local/bin/northnarrow-watchdog /usr/local/bin/nn-admin \
         /etc/systemd/system/northnarrow-agent.service /etc/systemd/system/northnarrow-watchdog.service \
         /etc/systemd/system/northnarrow-watchdog-failed.service \
         /etc/systemd/journald@northnarrow.conf /etc/northnarrow /var/lib/northnarrow /run/northnarrow /sys/fs/bpf/northnarrow \
         /root/northnarrow-admin.key; do
    if sudo test -e "$f"; then echo "FAIL: $f still present"; fail=1; fi
done
if [[ -n "$own_ids" ]]; then
    for id in $own_ids; do
        if sudo bpftool prog show id "$id" >/dev/null 2>&1; then echo "FAIL: own program id $id still loaded"; fail=1; fi
    done
    n=$(sudo bpftool prog show 2>/dev/null | grep -c " lsm " || true)
    (( n == foreign_before )) || { echo "FAIL: LSM programs $n after, $foreign_before foreign before"; fail=1; }
else
    n=$(sudo bpftool prog show 2>/dev/null | grep -c " lsm " || true)
    [[ "$n" == 0 ]] || { echo "FAIL: $n LSM programs still loaded (no bpf-own-ids: an agent older than the list)"; fail=1; }
fi
for u in northnarrow-agent northnarrow-watchdog; do
    st=$(systemctl is-active "$u" 2>/dev/null || true)
    [[ "$st" == inactive || "$st" == "" ]] || { echo "FAIL: $u is $st"; fail=1; }
done
if pgrep -f "northnarrow-(agent|watchdog)" >/dev/null; then echo "FAIL: northnarrow process still running"; fail=1; fi
(( fail == 0 )) && echo "uninstall-check: OK (host clean)"
# Bring the guest back: fresh install (new keys — the purge removed them).
sudo ./deploy/install.sh --source-tree >/tmp/nn-reinstall.log 2>&1 || { echo "FAIL: reinstall after purge failed"; tail -20 /tmp/nn-reinstall.log; exit 1; }
# External audit DEP-001: the bootstrap private key is written outside
# /etc/northnarrow
sudo test -s /root/northnarrow-admin.key || { echo "FAIL: no bootstrap key at /root/northnarrow-admin.key"; fail=1; }
if sudo test -e /etc/northnarrow/admin.key; then echo "FAIL: a private key in /etc/northnarrow"; fail=1; fi
sudo systemctl daemon-reload && sudo systemctl enable --now northnarrow-agent >/dev/null 2>&1 && sleep 3 && sudo systemctl enable --now northnarrow-watchdog >/dev/null 2>&1
echo "reinstalled: agent=$(systemctl is-active northnarrow-agent) watchdog=$(systemctl is-active northnarrow-watchdog)"
[[ "$(systemctl is-active northnarrow-agent)" == active ]] || fail=1
exit $fail
REMOTE
}

# External audit LAB-026 (NN-AUD-416, lab PR 206): the nightly ran none of
# the security checks. They run on the fresh install, before the steps that
# replace or remove it; each one starts the units it finds stopped (a gate
# leaves the agent stopped), and NN_LAB_NIGHTLY_SKIP skips any of them.
NIGHTLY_SECURITY_STEPS="tamper-check pkgmgr-check open-sensor-check fim-reuse-check btrfs-check overlay-check"
NIGHTLY_STEPS="check sync build test-e2e test-ignored install $NIGHTLY_SECURITY_STEPS respawn-check upgrade-check uninstall-check"

nightly_run_step() {
    local step=$1 logf=$2 t0 rc
    t0=$(date +%s)
    set +e
    # Subshell: a `die` inside a step must end THAT step (rc=1), not
    # the whole nightly before the report is written.
    ( case "$step" in
        check)         cmd_check ;;
        sync)          cmd_sync ;;
        build)         cmd_build ;;
        test-e2e)      cmd_test_e2e ;;
        test-ignored)  cmd_test_ignored ;;
        install)       cmd_install ;;
        tamper-check)  cmd_tamper_check ;;
        pkgmgr-check)  cmd_pkgmgr_check ;;
        open-sensor-check) cmd_open_sensor_check ;;
        fim-reuse-check) cmd_fim_reuse_check ;;
        btrfs-check)   cmd_btrfs_check ;;
        overlay-check) cmd_overlay_check ;;
        respawn-check) cmd_respawn_check ;;
        upgrade-check) cmd_upgrade_check ;;
        uninstall-check) cmd_uninstall_check ;;
        *)             echo "unknown step $step"; false ;;
    esac ) >"$logf" 2>&1
    rc=$?
    set -e
    NIGHTLY_RC[$step]=$rc
    NIGHTLY_SECS[$step]=$(( $(date +%s) - t0 ))
    return 0
}

# The lines of each step's log the report collects: test summaries and
# counts, every check's own verdict, and the anti-tamper rows that are not
# OK (a deviation, a known gap, a case not applicable here).
NIGHTLY_RESULT_LINES='^test result|panicked at|FAIL:|^FAIL |^count ok:|(respawn|upgrade|uninstall|pkgmgr)-check: |^anti-tamper check:|^\| [^|]+ \|.*\| (DEVIATION|KNOWN GAP|N/A)[^|]*\|$|^open-sensor check:|^(PASS|NOT RUN) |^(btrfs|overlay)-check: (PASS|FAIL|N/A|NOT RUN)'

# >>> nightly-status (xtask/tests/lab_scripts.rs runs this block)
# A step's status (lab PR 206): exit 0 is "ok" only for a step that ran. A
# check that says it does not apply here (btrfs-check on a kernel without
# btrfs: "btrfs-check: N/A …", exit 0) is N/A, and a NOT RUN fails whatever
# its exit status.
nightly_status() {   # <rc> <step log>
    local rc=$1 log=$2 na
    if [[ $rc == -1 ]]; then echo '⏭ skipped'; return; fi
    if grep -qE '(^|: )NOT RUN' "$log" 2>/dev/null; then echo "❌ not run (rc=$rc)"; return; fi
    if [[ $rc != 0 ]]; then echo "❌ rc=$rc"; return; fi
    na=$(grep -m1 -oE '^[a-z-]+( check)?: N/A.*' "$log" 2>/dev/null | tr '|' '/' | cut -c1-80 || true)
    if [[ -n $na ]]; then echo "➖ $na"; else echo '✅ ok'; fi
}
# <<< nightly-status

cmd_nightly() {
    local stamp report_dir report
    stamp=$(date +%Y%m%d-%H%M%S)
    report_dir="$LAB_DIR/reports/$stamp"
    mkdir -p "$report_dir"
    report="$LAB_DIR/reports/$stamp.md"
    declare -A NIGHTLY_RC NIGHTLY_SECS
    local skip=" ${NN_LAB_NIGHTLY_SKIP:-} "

    # Record the revision NOW: later steps sync the working tree as it is
    # at this moment, and HEAD may move while the run is in progress.
    local rev
    rev=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo '?')
    [[ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]] && rev="$rev+dirty"
    log "nightly $stamp @ $rev — logs in $report_dir"
    if ! vm_running || [[ ! -s $KNOWN_HOSTS ]]; then
        log "guest not running (or its host key not recorded) — bringing it up"
        if ! cmd_up >"$report_dir/up.log" 2>&1; then
            printf '# nn-lab nightly %s — FAILED at `up`\n\nSee %s/up.log\n' "$stamp" "$report_dir" > "$report"
            log "up failed; report: $report"
            return 1
        fi
    fi
    for step in $NIGHTLY_STEPS; do
        if [[ "$skip" == *" $step "* ]]; then
            NIGHTLY_RC[$step]=-1; NIGHTLY_SECS[$step]=0
            continue
        fi
        log "step: $step"
        nightly_run_step "$step" "$report_dir/$step.log"
        log "step: $step → rc=${NIGHTLY_RC[$step]} (${NIGHTLY_SECS[$step]}s)"
    done
    if [[ "${NN_LAB_NIGHTLY_DOWN:-0}" == "1" ]]; then
        cmd_down >/dev/null 2>&1 || true
    fi

    local failed=0
    {
        printf '# nn-lab nightly %s\n\n' "$stamp"
        printf -- '- repo: `%s` @ `%s`\n' "$REPO" "$rev"
        printf -- '- distro: `%s`%s\n' "$DISTRO" "${LOCKDOWN:+ (NN_LAB_LOCKDOWN=$LOCKDOWN)}"
        printf -- '- base image: %s\n' "$(lab_image_summary)"
        printf -- '- guest: `%s`\n\n' "$(vssh 'uname -r; cat /sys/kernel/security/lsm; echo; cat /sys/kernel/security/lockdown' 2>/dev/null | tr '\n' ' ')"
        printf '| step | status | seconds |\n|---|---|---|\n'
        for step in $NIGHTLY_STEPS; do
            local rc=${NIGHTLY_RC[$step]:--1} st
            st=$(nightly_status "$rc" "$report_dir/$step.log")
            [[ $st == ❌* ]] && failed=1
            printf '| %s | %s | %s |\n' "$step" "$st" "${NIGHTLY_SECS[$step]:-0}"
        done
        printf '\n## test results\n\n```\n'
        for step in $NIGHTLY_STEPS; do
            [[ -f "$report_dir/$step.log" ]] || continue
            grep -E "$NIGHTLY_RESULT_LINES" "$report_dir/$step.log" 2>/dev/null | cut -c1-160 | sed "s/^/$step: /" || true
        done
        printf '```\n\nLogs: `%s/`\n' "$report_dir"
    } > "$report"
    log "report: $report"
    cat "$report" >&2
    ln -sfn "$report" "$LAB_DIR/reports/latest.md"
    return $failed
}

# The header comment, line 2 up to the first line that is not a comment
# (external audit LAB-026: a fixed `2,36p` cut the usage block in half).
cmd_help() { awk 'NR == 1 { next } !/^#/ { exit } { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; }

case "${1:-help}" in
    up)            cmd_up ;;
    check)         cmd_check ;;
    sync)          cmd_sync ;;
    build)         cmd_build ;;
    test-e2e)      cmd_test_e2e ;;
    test-ignored)  cmd_test_ignored ;;
    install)       cmd_install ;;
    respawn-check) cmd_respawn_check ;;
    upgrade-check) cmd_upgrade_check ;;
    uninstall-check) cmd_uninstall_check ;;
    tamper-check)  cmd_tamper_check ;;
    overhead)      shift; cmd_overhead "$@" ;;
    pkgmgr-check)  cmd_pkgmgr_check ;;
    pkg-check)     cmd_pkg_check ;;
    release-check) shift; cmd_release_check "$@" ;;
    sensor-feasibility) shift; cmd_sensor_feasibility "$@" ;;
    verifier-check) shift; cmd_verifier_check "$@" ;;
    btrfs-check)   cmd_btrfs_check ;;
    overlay-check) cmd_overlay_check ;;
    open-sensor-check) cmd_open_sensor_check ;;
    exec-sensor-check) cmd_exec_sensor_check ;;
    execq-check) cmd_execq_check ;;
    net-check)     cmd_net_check ;;
    malsim-exec-check) cmd_malsim_exec_check ;;
    dns-sensor-check) cmd_dns_sensor_check ;;
    ransom-check)  shift; cmd_ransom_check "$@" ;;
    fim-reuse-check) cmd_fim_reuse_check ;;
    ssh)           shift; cmd_ssh "$@" ;;
    status)        cmd_status ;;
    trust-host-key) cmd_trust_host_key ;;
    down)          cmd_down ;;
    snapshot)      cmd_snapshot "${2:-}" ;;
    restore)       cmd_restore "${2:-}" ;;
    destroy)       cmd_destroy ;;
    verify-image)  cmd_verify_image ;;
    image-info)    cmd_image_info ;;
    fetch-image)   cmd_fetch_image ;;
    nightly)       cmd_nightly ;;
    soak)          shift; cmd_soak "$@" ;;
    help|-h|--help) cmd_help ;;
    *) die "unknown command '$1' (nn-lab.sh help)" ;;
esac
