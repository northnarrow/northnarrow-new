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
#   deploy/lab/nn-lab.sh install       # deploy/install.sh + start both units
#   deploy/lab/nn-lab.sh respawn-check # kill -9 the agent, assert respawn v2 invariants
#   deploy/lab/nn-lab.sh ssh [cmd…]    # shell / command in the guest
#   deploy/lab/nn-lab.sh snapshot NAME | restore NAME   (guest must be down)
#   deploy/lab/nn-lab.sh status | down | destroy
#   deploy/lab/nn-lab.sh nightly       # unattended full run → $LAB_DIR/reports/<stamp>.md (exit 1 on any failure)
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

LAB_DIR=${NN_LAB_DIR:-"$HOME/.cache/nn-lab"}
CPUS=${NN_LAB_CPUS:-4}
MEM=${NN_LAB_MEM:-8192}
# The ssh port is remembered in $LAB_DIR/ssh_port after `up`, so every
# later sub-command talks to the same guest without re-exporting it.
SSH_PORT=${NN_LAB_SSH_PORT:-$(cat "${NN_LAB_DIR:-"$HOME/.cache/nn-lab"}/ssh_port" 2>/dev/null || echo 2222)}
DISK_SIZE=${NN_LAB_DISK:-30G}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=${NN_REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}

IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
BASE_IMG="$LAB_DIR/noble-base.img"
DISK="$LAB_DIR/disk.qcow2"
SEED="$LAB_DIR/seed.iso"
KEY="$LAB_DIR/id_ed25519"
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
    local inner="source ~/.cargo/env 2>/dev/null; cd ~/northnarrow && $*"
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
        sed "s|__SSH_PUBKEY__|$(cat "$KEY.pub")|" "$SCRIPT_DIR/user-data.tmpl" > "$ud"
        printf 'instance-id: nn-lab-%s\nlocal-hostname: nn-lab\n' "$(date +%s)" > "$md"
        cloud-localds "$SEED" "$ud" "$md"
    fi
    if ss -ltn 2>/dev/null | grep -qE "[:.]${SSH_PORT}\b"; then
        die "127.0.0.1:$SSH_PORT is already in use on the host — pick another: NN_LAB_SSH_PORT=2322 $0 up"
    fi
    echo "$SSH_PORT" > "$LAB_DIR/ssh_port"
    log "booting: ${CPUS} vCPU, ${MEM} MiB, ssh → 127.0.0.1:$SSH_PORT"
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
    log "agent privileged_e2e done — running the watchdog suite"
    vcargo 'sudo -E env "PATH=$PATH" cargo test --release -p northnarrow-watchdog --features test-privileged --test privileged_e2e -- --test-threads=1 --nocapture'
}

cmd_test_ignored() {
    vm_running || die "guest is not running"
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
    sudo systemctl kill --kill-whom=main -s SIGKILL northnarrow-agent.service
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

# ── nightly: the whole runbook, unattended, with a markdown report ──
#
# Every step runs even if an earlier one failed (a red test-e2e must not
# hide a red respawn-check), each step's output goes to its own log, and
# the report carries status + duration + the `test result:` lines. The
# exit code is 1 when any step failed, so a scheduler can alert on it.
NIGHTLY_STEPS="check sync build test-e2e test-ignored install respawn-check"

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
        test-ignored)
            # Installed units hold the bpffs pins + iptables chain the
            # tests expect to own: stop them first (watchdog first, or
            # it respawns the agent).
            vssh 'sudo systemctl stop northnarrow-watchdog northnarrow-agent 2>/dev/null; true'
            cmd_test_ignored ;;
        install)       cmd_install ;;
        respawn-check) cmd_respawn_check ;;
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
    ssh)           shift; cmd_ssh "$@" ;;
    status)        cmd_status ;;
    down)          cmd_down ;;
    snapshot)      cmd_snapshot "${2:-}" ;;
    restore)       cmd_restore "${2:-}" ;;
    destroy)       cmd_destroy ;;
    nightly)       cmd_nightly ;;
    help|-h|--help) cmd_help ;;
    *) die "unknown command '$1' (nn-lab.sh help)" ;;
esac
