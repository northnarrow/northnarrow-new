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
#   sudo apt install qemu-system-x86 qemu-utils cloud-image-utils
#   sudo usermod -aG kvm "$USER"      # then re-login (WSL: `wsl --shutdown`)
#   bpf-linker 0.10.3 + nightly on PATH for `cargo xtask build-ebpf`
#
# Usage:
#   deploy/lab/nn-lab.sh up            # download image, provision, boot, wait for ssh
#   deploy/lab/nn-lab.sh check         # kernel / lsm / bpffs / iptables / cargo in the guest
#   deploy/lab/nn-lab.sh sync          # build eBPF on host, rsync repo into the guest
#   deploy/lab/nn-lab.sh build         # cargo build --release (+test-privileged,debug-trigger) in the guest
#   deploy/lab/nn-lab.sh test-e2e      # docs/integration-test-runbook.md "Run" (privileged_e2e)
#   deploy/lab/nn-lab.sh test-ignored  # every #[ignore] test, as root, single-threaded
#   NN_LAB_DISTRO=debian12 deploy/lab/nn-lab.sh up   # second guest (Debian 12, kernel 6.1); every
#                                                    # sub-command honours NN_LAB_DISTRO (default ubuntu2404)
#   deploy/lab/nn-lab.sh upgrade-check    # install.sh --upgrade on the running install (keys/chains kept)
#   deploy/lab/nn-lab.sh uninstall-check  # uninstall.sh --purge leaves nothing, then reinstall
#   deploy/lab/nn-lab.sh install       # deploy/install.sh + start both units
#   deploy/lab/nn-lab.sh respawn-check # kill -9 the agent, assert respawn v2 invariants
#   deploy/lab/nn-lab.sh ssh [cmd…]    # shell / command in the guest
#   deploy/lab/nn-lab.sh snapshot NAME | restore NAME   (guest must be down)
#   deploy/lab/nn-lab.sh status | down | destroy
#   deploy/lab/nn-lab.sh nightly       # unattended full run → $LAB_DIR/reports/<stamp>.md (exit 1 on any failure)
#   deploy/lab/nn-lab.sh soak start [HOURS] [INTERVAL_S] | status | stop | wait | report
#                                      # hours of synthetic load + resource samples → $LAB_DIR/reports/soak-<stamp>.md
#
# Env overrides: NN_LAB_DIR (~/.cache/nn-lab), NN_LAB_CPUS (4), NN_LAB_MEM (8192),
#   NN_LAB_SSH_PORT (2222, remembered after `up`), NN_LAB_DISK (30G), NN_LAB_LTO (thin),
#   NN_REPO (git toplevel of this script), NN_LAB_NIGHTLY_DOWN=1 (power the guest off at the end),
#   NN_LAB_NIGHTLY_SKIP (space-separated steps to skip, e.g. "test-ignored").
set -euo pipefail

# cron / Task Scheduler invocations come with a minimal PATH: make sure
# cargo, bpf-linker (~/.cargo/bin) and the qemu/ss tools (/usr/sbin) are
# reachable regardless of how we were started.
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

ROOT_LAB_DIR=${NN_LAB_DIR:-"$HOME/.cache/nn-lab"}
CPUS=${NN_LAB_CPUS:-4}
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
    *) echo "nn-lab: unknown NN_LAB_DISTRO=$DISTRO (ubuntu2404 | debian12 | ubuntu2204 | alma9)" >&2; exit 2 ;;
esac
# The ssh port is remembered in $LAB_DIR/ssh_port after `up`, so every
# later sub-command talks to the same guest without re-exporting it.
SSH_PORT=${NN_LAB_SSH_PORT:-$(cat "$LAB_DIR/ssh_port" 2>/dev/null || echo "$DEFAULT_SSH_PORT")}

BASE_IMG="$LAB_DIR/$BASE_IMG_NAME"
DISK="$LAB_DIR/disk.qcow2"
SEED="$LAB_DIR/seed.iso"
KEY="$ROOT_LAB_DIR/id_ed25519"
PIDFILE="$LAB_DIR/qemu.pid"
SERIAL="$LAB_DIR/serial.log"
GUEST="nn@127.0.0.1"
SSH_OPTS=(-i "$KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)

log()  { printf 'nn-lab: %s\n' "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

need_host_deps() {
    local missing=()
    for b in qemu-system-x86_64 qemu-img cloud-localds ssh ssh-keygen rsync curl; do
        command -v "$b" >/dev/null 2>&1 || missing+=("$b")
    done
    if ((${#missing[@]})); then
        die "missing on host: ${missing[*]} — run: sudo apt install qemu-system-x86 qemu-utils cloud-image-utils openssh-client rsync curl"
    fi
    [[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm not usable: enable nested virtualization and add yourself to the kvm group (sudo usermod -aG kvm \$USER, then re-login)"
}

vm_running() {
    [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

vssh() { ssh "${SSH_OPTS[@]}" "$GUEST" "$@"; }
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
    local deadline=$(( $(date +%s) + ${1:-600} ))
    log "waiting for ssh on 127.0.0.1:$SSH_PORT (up to ${1:-600}s; first boot reboots once)…"
    while (( $(date +%s) < deadline )); do
        if vssh -o BatchMode=yes true 2>/dev/null; then
            # Provisioning done AND we are past the reboot (lsm=bpf active)?
            if vssh 'test -f /var/lib/nn-lab-provisioned && grep -q bpf /sys/kernel/security/lsm' 2>/dev/null; then
                log "guest is up and provisioned"
                return 0
            fi
        fi
        sleep 5
    done
    die "guest did not become reachable; see $SERIAL"
}

cmd_up() {
    need_host_deps
    mkdir -p "$LAB_DIR"
    vm_running && { log "already running (pid $(cat "$PIDFILE"))"; return 0; }
    if [[ ! -f "$BASE_IMG" ]]; then
        log "downloading $IMAGE_URL"
        curl -fL --progress-bar -o "$BASE_IMG.part" "$IMAGE_URL" && mv "$BASE_IMG.part" "$BASE_IMG"
    fi
    if [[ ! -f "$KEY" ]]; then
        ssh-keygen -q -t ed25519 -N '' -C nn-lab -f "$KEY"
    fi
    local fresh=0
    if [[ ! -f "$DISK" ]]; then
        qemu-img create -q -f qcow2 -b "$BASE_IMG" -F qcow2 "$DISK" "$DISK_SIZE"
        fresh=1
    fi
    if [[ ! -f "$SEED" || $fresh == 1 ]]; then
        local ud="$LAB_DIR/user-data" md="$LAB_DIR/meta-data"
        sed "s|__SSH_PUBKEY__|$(cat "$KEY.pub")|" "$USER_DATA_TMPL" > "$ud"
        printf 'instance-id: nn-lab-%s-%s\nlocal-hostname: nn-lab-%s\n' "$DISTRO" "$(date +%s)" "$DISTRO" > "$md"
        cloud-localds "$SEED" "$ud" "$md"
    fi
    if ss -ltn 2>/dev/null | grep -qE "[:.]${SSH_PORT}\b"; then
        die "127.0.0.1:$SSH_PORT is already in use on the host — pick another: NN_LAB_SSH_PORT=2322 $0 up"
    fi
    echo "$SSH_PORT" > "$LAB_DIR/ssh_port"
    log "booting $DISTRO: ${CPUS} vCPU, ${MEM} MiB, ssh → 127.0.0.1:$SSH_PORT"
    qemu-system-x86_64 \
        -enable-kvm -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
        -drive "file=$DISK,if=virtio,format=qcow2" \
        -drive "file=$SEED,if=virtio,format=raw,readonly=on" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
        -device virtio-net-pci,netdev=n0 \
        -device virtio-rng-pci \
        -display none -serial "file:$SERIAL" -monitor none \
        -daemonize -pidfile "$PIDFILE"
    wait_ssh 900
    cmd_check
}

cmd_check() {
    vm_running || die "guest is not running (nn-lab.sh up)"
    vssh bash -s <<'REMOTE'
set -e
export PATH="$PATH:/usr/sbin:/sbin"
echo "kernel      : $(uname -r)"
echo "lsm         : $(cat /sys/kernel/security/lsm)"
grep -q '\bbpf\b' /sys/kernel/security/lsm && echo "bpf-lsm     : OK" || { echo "bpf-lsm     : MISSING"; exit 1; }
mount | grep -q ' /sys/fs/bpf ' && echo "bpffs       : mounted" || echo "bpffs       : NOT mounted"
command -v iptables-restore >/dev/null && echo "iptables    : $(iptables --version)" || { echo "iptables    : MISSING"; exit 1; }
command -v bpftool >/dev/null && echo "bpftool     : $(bpftool version 2>/dev/null | head -1)" || echo "bpftool     : missing (linux-tools-$(uname -r)?)"
source ~/.cargo/env 2>/dev/null && echo "cargo       : $(cargo --version)" || { echo "cargo       : MISSING"; exit 1; }
echo "mem         : $(free -g | awk '/Mem:/ {print $2}') GiB, cpus: $(nproc)"
REMOTE
}

cmd_sync() {
    vm_running || die "guest is not running"
    local obj="$REPO/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf"
    command -v bpf-linker >/dev/null 2>&1 || die "bpf-linker not on PATH (cargo install bpf-linker --version 0.10.3 --locked)"
    log "building eBPF object on host (cargo xtask build-ebpf)"
    (cd "$REPO" && cargo xtask build-ebpf >/dev/null)
    [[ -f "$obj" && -f "$obj.buildhash" ]] || die "eBPF object/stamp missing after build: $obj"
    # target/kb (cargo xtask rag-kb: pinned ATT&CK + Sigma dumps) rides
    # along when present so the RAG release gates run against the real
    # corpus on the guest instead of the built-in seed.
    local kb_note="no target/kb — RAG gates will be skipped"
    ls "$REPO"/target/kb/*.jsonl >/dev/null 2>&1 && kb_note="target/kb included"
    log "rsync $REPO → guest:~/northnarrow (target/ excluded, eBPF object included, $kb_note)"
    rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
        --include='/target/' \
        --include='/target/kb/' \
        --include='/target/kb/*.jsonl' \
        --exclude='/target/kb/*' \
        --exclude='/target/*' \
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
    vcargo "CARGO_PROFILE_RELEASE_LTO=$lto cargo build --release --features test-privileged,debug-trigger -p northnarrow-agent -p northnarrow-watchdog 2>&1 | grep -vE '^\s+(Compiling|Downloaded|Downloading|Locking|Adding|Updating)' | tail -40; ls -la target/release/northnarrow-agent target/release/nn-admin target/release/northnarrow-watchdog"
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
    vssh 'sudo systemctl stop northnarrow-watchdog northnarrow-agent 2>/dev/null; true'
    vcargo 'sudo -E env "PATH=$PATH" cargo test --release -p northnarrow-agent --features test-privileged,debug-trigger --test privileged_e2e -- --test-threads=1 --nocapture'
    # The four FIM e2e tests are plain `#[test]` (not ignored), so neither
    # `test-ignored` nor the privileged_e2e run above covered them — the
    # lab never executed them before 2026-10-10 (review entry 33).
    log "agent privileged_e2e done — running the FIM suite"
    vcargo 'sudo -E env "PATH=$PATH" cargo test --release -p northnarrow-agent --features test-privileged,debug-trigger --test fim_privileged_e2e -- --test-threads=1 --nocapture'
    log "FIM suite done — running the watchdog suite"
    vcargo 'sudo -E env "PATH=$PATH" cargo test --release -p northnarrow-watchdog --features test-privileged --test privileged_e2e -- --test-threads=1 --nocapture'
}

cmd_test_ignored() {
    vm_running || die "guest is not running"
    # Installed units hold the bpffs pins + iptables chain the tests expect
    # to own, and the enforcing agent kills `sudo cargo` (R009: root exec
    # from ~/.cargo/bin). Stop them first — watchdog first, or it respawns
    # the agent. (The nightly used to do this in its dispatcher only; a
    # stand-alone run was SIGKILLed by the agent.)
    vssh 'sudo systemctl stop northnarrow-watchdog northnarrow-agent 2>/dev/null; true'
    # --no-fail-fast: one failing test binary must not skip the other
    # targets (the first run stopped at 11 of 56 ignored tests).
    # NN_LAB_IGNORED_SKIP: substrings of test names to leave out. The RAG
    # release gates (golden ≥ 90 %, latency, e2e format) need the real
    # corpus (`cargo xtask rag-kb` → target/kb, shipped by `sync`); without
    # it they used to run against the built-in seed and report a bogus
    # 36.7 % — now they fail fast, so skip them when the corpus is absent
    # and say why. Set NN_LAB_IGNORED_SKIP="" to force everything.
    local skip_args="" t default_skip=""
    if ! ls "$REPO"/target/kb/*.jsonl >/dev/null 2>&1; then
        default_skip="rag::bench"
        log "no target/kb on host — skipping the RAG release gates (run: cargo xtask rag-kb)"
    fi
    for t in ${NN_LAB_IGNORED_SKIP-$default_skip}; do skip_args+=" --skip $t"; done
    vcargo "sudo -E env \"PATH=\$PATH\" cargo test --release --workspace --no-fail-fast --features northnarrow-agent/test-privileged,northnarrow-agent/debug-trigger -- --ignored --test-threads=1$skip_args"
}

cmd_install() {
    vm_running || die "guest is not running"
    # `sync` rewrites the eBPF provenance stamp, so an agent binary built
    # before the last sync is "older than the stamp" and install.sh
    # (require_fresh_ebpf) refuses it. An incremental build re-runs
    # agent/build.rs and relinks the agent — seconds when nothing changed.
    cmd_build
    # Re-install on a host where an agent already ran: its binaries and
    # unit files are in PROTECTED_INODES and the inode_unlink/rename deny
    # hooks stay attached through the bpffs pins even after the agent
    # exits (by design — production upgrades go through the signed
    # FS_PROTECT_OVERRIDE window). The lab has no signed installer, so
    # stop the units (watchdog first) and drop the pin root: the hooks
    # detach with their links and the next agent boot re-pins fresh.
    vssh 'sudo systemctl stop northnarrow-watchdog northnarrow-agent 2>/dev/null; sudo rm -rf /sys/fs/bpf/northnarrow; true'
    # Leftover e2e agents (a test that was still tearing down) keep their
    # LSM programs attached through their own fds, and those deny the
    # unlink of the installed binary: wait for the LSM set to drain,
    # evicting + killing stragglers on the way.
    vssh bash -s <<'REMOTE'
for i in $(seq 1 20); do
    n=$(sudo bpftool prog show 2>/dev/null | grep -c " lsm ")
    [ "$n" = "0" ] && break
    sudo pkill -9 -f "northnarrow-agent-e2etes[t]|northnarrow-watchdog-e2etes[t]" 2>/dev/null
    sleep 1
done
echo "lsm programs still loaded before install: $(sudo bpftool prog show 2>/dev/null | grep -c " lsm ")"
REMOTE
    vcargo 'sudo ./deploy/install.sh && sudo systemctl daemon-reload && sudo systemctl start northnarrow-agent && sleep 3 && sudo systemctl start northnarrow-watchdog && systemctl --no-pager status northnarrow-agent northnarrow-watchdog | grep -E "Active|Loaded"'
}

cmd_respawn_check() {
    vm_running || die "guest is not running"
    # Design: docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md §4 — the agent must
    # come back under its OWN unit with its own caps/cgroup.
    vssh bash -s <<'REMOTE'
set -e
old=$(sudo cat /run/northnarrow/agent.pid)
echo "agent pid before: $old"
# A plain `kill -9` from a root shell is DENIED by the task_kill LSM
# hook (the agent is in PROTECTED_PIDS — Tappa 7 working as designed).
# systemd (PID 1) is carved out so `systemctl stop` works, so deliver
# the SIGKILL through it: no shutdown marker is written (that is the
# signed nn-admin path only), hence the watchdog treats it as a crash.
if sudo kill -9 "$old" 2>/dev/null; then
    echo "WARN: plain kill -9 from a root shell succeeded — task_kill deny hook NOT active?"
else
    echo "kill -9 from a root shell: denied (task_kill LSM hook OK) — using systemctl kill"
    sudo systemctl kill --kill-who=main  -s SIGKILL northnarrow-agent.service
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
fail=0
[[ "$act" == active ]] || { echo "FAIL: agent unit not active (respawned outside its unit?)"; fail=1; }
[[ "$cg" == *northnarrow-agent.service* ]] || { echo "FAIL: new agent is not in the agent unit's cgroup"; fail=1; }
(( (0x$capeff >> 5) & 1 )) || { echo "FAIL: CAP_KILL (bit 5) missing from CapEff"; fail=1; }
[[ "$wd" == active ]] || { echo "FAIL: watchdog not active after respawn (BindsTo regression?)"; fail=1; }
(( fail == 0 )) && echo "respawn-check: OK"
exit $fail
REMOTE
}

cmd_ssh() {
    vm_running || die "guest is not running"
    if (($#)); then vssh "$@"; else ssh "${SSH_OPTS[@]}" "$GUEST"; fi
}

cmd_status() {
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
    vm_running || { log "not running"; return 0; }
    vssh sudo poweroff >/dev/null 2>&1 || true
    local pid; pid=$(cat "$PIDFILE")
    for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || { log "stopped"; rm -f "$PIDFILE"; return 0; }; sleep 1; done
    log "forcing qemu exit"; kill "$pid" 2>/dev/null || true; rm -f "$PIDFILE"
}

cmd_snapshot() {
    vm_running && die "stop the guest first (nn-lab.sh down)"
    [[ -n "${1:-}" ]] || die "snapshot NAME"
    qemu-img snapshot -c "$1" "$DISK" && log "snapshot '$1' created"
}

cmd_restore() {
    vm_running && die "stop the guest first (nn-lab.sh down)"
    [[ -n "${1:-}" ]] || die "restore NAME"
    qemu-img snapshot -a "$1" "$DISK" && log "restored '$1'"
}

cmd_destroy() {
    cmd_down
    rm -f "$DISK" "$SEED" "$LAB_DIR/user-data" "$LAB_DIR/meta-data" "$SERIAL"
    log "guest disk removed (base image + ssh key kept in $LAB_DIR)"
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
            scp -q -i "$KEY" -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
                "$SOAK_SCRIPTS/generate.sh" "$SOAK_SCRIPTS/sample.sh" "$GUEST:soak/"
            vssh "chmod +x ~/soak/*.sh; echo '$hours' > ~/soak/hours; echo '$interval' > ~/soak/interval; date -u +%s > ~/soak/start_epoch; echo \"\$(uname -r) \$(cat /etc/os-release | sed -n 's/^PRETTY_NAME=//p' | tr -d '\"')\" > ~/soak/host"
            # The sampler runs as root: it must NOT live under /home — the
            # agent's R009 (root exec from a user-writable path) would kill it
            # on the spot. Install it root-owned under /usr/local/sbin first.
            vssh "sudo install -m 0755 -o root -g root \$HOME/soak/sample.sh /usr/local/sbin/nn-soak-sample"
            vssh "sudo nohup env SOAK_DIR=\$HOME/soak SOAK_INTERVAL=$interval setsid /usr/local/sbin/nn-soak-sample > \$HOME/soak/sample.log 2>&1 < /dev/null & disown; sleep 2; test -f ~/soak/sample.pid && sudo kill -0 \$(cat ~/soak/sample.pid)"
            vssh "nohup env SOAK_DIR=\$HOME/soak setsid \$HOME/soak/generate.sh > \$HOME/soak/generate.log 2>&1 < /dev/null & disown"
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
            scp -q -i "$KEY" -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
                "$GUEST:soak/samples.csv" "$GUEST:soak/sample.log" "$GUEST:soak/generate.log" "$GUEST:soak/host" "$GUEST:soak/hours" "$dir/" 2>/dev/null || true
            vssh 'sudo journalctl -u northnarrow-agent -u northnarrow-watchdog --since "$(cat ~/soak/start)" -p 4 --no-pager -q 2>/dev/null | tail -200' > "$dir/journal-warn-err.log" 2>/dev/null || true
            [ -s "$dir/samples.csv" ] || die "no samples.csv on the guest — was the soak started?"
            local max_rss_mb_h=${NN_LAB_SOAK_MAX_RSS_MB_H:-5}
            local rc=0
            set +e
            awk -F, -v repo="$REPO" -v head="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)" -v distro="$DISTRO" \
                -v host="$(cat "$dir/host" 2>/dev/null)" -v hours="$(cat "$dir/hours" 2>/dev/null)" -v maxslope="$max_rss_mb_h" -v logdir="$dir" '
            NR == 1 { next }
            {
                n++; t[n]=$1; pid[n]=$2; rss[n]=$3; vsz[n]=$4; cpu[n]=$5; thr[n]=$6; fds[n]=$7; wd[n]=$8
                ar[n]=$9; wr[n]=$10; jw[n]=$11; je[n]=$12; cb[n]=$13; det[n]=$14; sts[n]=$15; aud[n]=$16; fim[n]=$17
                fs[n]=$18; us[n]=$19; fdm[n]=$20; pp[n]=$21; dr[n]=$22; gi[n]=$23
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
                if (dr[n] - dr[1] > 0) warn = warn "; ring-buffer drops +" (dr[n]-dr[1])
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
                printf "Thresholds: 0 restarts, 0 journal ERROR, RSS slope ≤ %s MB/h on runs ≥ 2 h, fds growth < 50%%.\n", maxslope
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
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 3; }
sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog
pid_before=$(sudo cat /run/northnarrow/agent.pid)
audit_before=$(sudo wc -l < /etc/northnarrow/audit.log)
fp_before=$(sudo sha256sum /etc/northnarrow/admin.pub /etc/northnarrow/agent.sig.key /etc/northnarrow/agent_id | sha256sum | cut -c1-16)
echo "before: agent pid=$pid_before audit_lines=$audit_before identity=$fp_before"
# Without --upgrade the script must refuse (units active) — exit 1, no change.
if sudo ./deploy/install.sh >/tmp/nn-upgrade-refuse.log 2>&1; then
    echo "FAIL: install.sh without --upgrade succeeded while the units were active"; exit 1
fi
grep -q "Re-run with --upgrade" /tmp/nn-upgrade-refuse.log || { echo "FAIL: refusal message missing"; cat /tmp/nn-upgrade-refuse.log; exit 1; }
echo "install.sh without --upgrade: refused as expected"
sudo ./deploy/install.sh --upgrade 2>&1 | grep -E "UPGRADE|stopping|starting|waiting|is active|is inactive|is failed|LSM" | cut -c1-140
sleep 2
pid_after=$(sudo cat /run/northnarrow/agent.pid)
audit_after=$(sudo wc -l < /etc/northnarrow/audit.log)
fp_after=$(sudo sha256sum /etc/northnarrow/admin.pub /etc/northnarrow/agent.sig.key /etc/northnarrow/agent_id | sha256sum | cut -c1-16)
echo "after : agent pid=$pid_after audit_lines=$audit_after identity=$fp_after"
fail=0
[[ "$(systemctl is-active northnarrow-agent)" == active ]] || { echo "FAIL: agent unit not active after upgrade"; fail=1; }
[[ "$(systemctl is-active northnarrow-watchdog)" == active ]] || { echo "FAIL: watchdog unit not active after upgrade"; fail=1; }
[[ "$pid_after" != "$pid_before" ]] || { echo "FAIL: agent pid unchanged — binary not restarted"; fail=1; }
(( audit_after > audit_before )) || { echo "FAIL: no new audit entry (agent_boot) after upgrade"; fail=1; }
[[ "$fp_after" == "$fp_before" ]] || { echo "FAIL: admin.pub / agent.sig.key / agent_id changed across the upgrade"; fail=1; }
n=$(sudo bpftool prog show 2>/dev/null | grep -c " lsm " || true)
(( n >= 7 )) || { echo "FAIL: only $n LSM programs after upgrade"; fail=1; }
sudo ls /sys/fs/bpf/northnarrow/PROTECTED_PIDS >/dev/null || { echo "FAIL: PROTECTED_PIDS not re-pinned"; fail=1; }
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
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 3; }
sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog
sudo ./deploy/uninstall.sh --purge --yes 2>&1 | grep -E "uninstall.sh:|FAIL" | cut -c1-140
fail=0
for f in /usr/local/bin/northnarrow-agent /usr/local/bin/northnarrow-watchdog /usr/local/bin/nn-admin \
         /etc/systemd/system/northnarrow-agent.service /etc/systemd/system/northnarrow-watchdog.service \
         /etc/systemd/journald@northnarrow.conf /etc/northnarrow /var/lib/northnarrow /run/northnarrow /sys/fs/bpf/northnarrow; do
    if sudo test -e "$f"; then echo "FAIL: $f still present"; fail=1; fi
done
n=$(sudo bpftool prog show 2>/dev/null | grep -c " lsm " || true)
[[ "$n" == 0 ]] || { echo "FAIL: $n LSM programs still loaded"; fail=1; }
for u in northnarrow-agent northnarrow-watchdog; do
    st=$(systemctl is-active "$u" 2>/dev/null || true)
    [[ "$st" == inactive || "$st" == "" ]] || { echo "FAIL: $u is $st"; fail=1; }
done
if pgrep -f "northnarrow-(agent|watchdog)" >/dev/null; then echo "FAIL: northnarrow process still running"; fail=1; fi
(( fail == 0 )) && echo "uninstall-check: OK (host clean)"
# Bring the guest back: fresh install (new keys — the purge removed them).
sudo ./deploy/install.sh >/tmp/nn-reinstall.log 2>&1 || { echo "FAIL: reinstall after purge failed"; tail -20 /tmp/nn-reinstall.log; exit 1; }
sudo systemctl daemon-reload && sudo systemctl enable --now northnarrow-agent >/dev/null 2>&1 && sleep 3 && sudo systemctl enable --now northnarrow-watchdog >/dev/null 2>&1
echo "reinstalled: agent=$(systemctl is-active northnarrow-agent) watchdog=$(systemctl is-active northnarrow-watchdog)"
[[ "$(systemctl is-active northnarrow-agent)" == active ]] || fail=1
exit $fail
REMOTE
}

NIGHTLY_STEPS="check sync build test-e2e test-ignored install respawn-check upgrade-check uninstall-check"

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
    if ! vm_running; then
        log "guest not running — bringing it up"
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
        printf -- '- distro: `%s`\n' "$DISTRO"
        printf -- '- guest: `%s`\n\n' "$(vssh 'uname -r; cat /sys/kernel/security/lsm' 2>/dev/null | tr '\n' ' ')"
        printf '| step | status | seconds |\n|---|---|---|\n'
        for step in $NIGHTLY_STEPS; do
            local rc=${NIGHTLY_RC[$step]:--1} st
            case $rc in
                0)  st='✅ ok' ;;
                -1) st='⏭ skipped' ;;
                *)  st="❌ rc=$rc"; failed=1 ;;
            esac
            printf '| %s | %s | %s |\n' "$step" "$st" "${NIGHTLY_SECS[$step]:-0}"
        done
        printf '\n## test results\n\n```\n'
        grep -hE '^test result|panicked at|FAIL:|respawn-check: OK' "$report_dir"/test-e2e.log "$report_dir"/test-ignored.log "$report_dir"/respawn-check.log 2>/dev/null | cut -c1-160 || true
        printf '```\n\nLogs: `%s/`\n' "$report_dir"
    } > "$report"
    log "report: $report"
    cat "$report" >&2
    ln -sfn "$report" "$LAB_DIR/reports/latest.md"
    return $failed
}

cmd_help() { sed -n '2,36p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

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
    ssh)           shift; cmd_ssh "$@" ;;
    status)        cmd_status ;;
    down)          cmd_down ;;
    snapshot)      cmd_snapshot "${2:-}" ;;
    restore)       cmd_restore "${2:-}" ;;
    destroy)       cmd_destroy ;;
    nightly)       cmd_nightly ;;
    soak)          shift; cmd_soak "$@" ;;
    help|-h|--help) cmd_help ;;
    *) die "unknown command '$1' (nn-lab.sh help)" ;;
esac
