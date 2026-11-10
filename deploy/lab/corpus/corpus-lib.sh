# shellcheck shell=bash
# Lot 283a — the benign corpus's common part, sourced by each workload script
# of this directory (docs/validation/BENIGN_CORPUS.md). Not run by itself.
#
# A workload script runs on a lab guest only (cloud-init's marker, or a host
# declared disposable with NN_TEST_DISPOSABLE_HOST=1), as the lab user over
# ssh (an authenticated session), with sudo for the root parts, and the
# agent installed and running in its default mode. It:
#   1. puts back what a run before it may have left (it is idempotent);
#   2. prepares its tools and trees — not measured;
#   3. restarts the agent inside a signed trusted-installer window and waits
#      75 s (`corpus_settle`): the posture starts from OBSERVING;
#   4. runs its steps in order, each one timed and named (`step`), the
#      posture read after each — one settle per corpus: the steps follow one
#      another as on a real host, and what one raises the next one meets;
#   5. removes everything it installed or wrote, as a measured step of its
#      own (`cleanup`);
#   6. prints the report (corpus-report.py): every kill, verdict and
#      COMBAT entry of the signed chains in its window, by step — the rule,
#      the process, the posture the agent judged it in — and, where the
#      small-file probe ran, the in-place rewrites of small files by step.
# Network: package mirrors and registries only (apt, crates.io, the npm
# registry, PyPI, Docker Hub), and get.k3s.io for the container host's k3s.
# No secret is read or written. NN_CORPUS_KEEP=<dir>: keep the raw records
# (chain slices, steps, probe output) in <dir> instead of removing them.

# Nothing here runs a program before corpus_guard has passed (the xtask
# test runs each workload on a host that is no guest, with stubs on PATH).
NN_LAB_GUEST_MARKER=/var/lib/nn-lab-provisioned
CORPUS_DIR=${BASH_SOURCE[0]%/*}
[[ $CORPUS_DIR == "${BASH_SOURCE[0]}" ]] && CORPUS_DIR=.
KEY=${NN_CORPUS_ADMIN_KEY:-/root/northnarrow-admin.key}
ACT=/var/lib/northnarrow/detections/actions.jsonl
DET=/var/lib/northnarrow/detections/detections.jsonl
AUD=/etc/northnarrow/audit.log
SF_UNIT=nn-corpus-smallfile

corpus_guard() { # <corpus>
    if [[ ! -e $NN_LAB_GUEST_MARKER && ${NN_TEST_DISPOSABLE_HOST:-} != 1 ]]; then
        echo "corpus $1: refusing to run: not an nn-lab guest ($NN_LAB_GUEST_MARKER missing) and NN_TEST_DISPOSABLE_HOST=1 not set — it installs and removes packages, services and containers" >&2
        exit 2
    fi
    if ((EUID == 0)); then
        echo "corpus $1: run it as the lab user (sudo for the root parts), not as root" >&2
        exit 2
    fi
}

corpus_init() { # <corpus>
    CORPUS=$1
    corpus_guard "$CORPUS"
    CORPUS_DIR=$(cd "$CORPUS_DIR" && pwd)
    export DEBIAN_FRONTEND=noninteractive
    export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    LABUSER=$(id -un)
    LABGROUP=$(id -gn)
    W=/srv/nn-corpus/$CORPUS
    STATE=/var/tmp/nn-corpus-$CORPUS.installed
    OUT=$(mktemp -d "/tmp/nn-corpus-$CORPUS.XXXXXX")
    STEPS=$OUT/steps.tsv
    : > "$STEPS"
    INSTALLED=""
    AG=$(sudo readlink -f /usr/local/bin/northnarrow-agent)
    ADMIN=$(dirname "$AG")/nn-admin
    sudo test -x "$ADMIN" || ADMIN=/usr/local/bin/nn-admin
    echo "== corpus $CORPUS on $(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r); agent $(sudo "$AG" --version 2>/dev/null | head -1); $(date -u +%FT%TZ)"
    systemctl is-active --quiet northnarrow-agent || { echo "corpus $CORPUS: the agent is not running: nothing is run" >&2; exit 2; }
    # a run killed half-way left its packages listed: removed first
    if [[ -s $STATE ]]; then
        INSTALLED=$(cat "$STATE")
        echo "  a run before left:$INSTALLED (removed now)"
        corpus_purge
    fi
    sudo rm -rf "$W"
    sudo mkdir -p "$W" && sudo chown "$LABUSER:$LABGROUP" "$W"
    trap corpus_on_exit EXIT
}

corpus_on_exit() {
    sudo systemctl stop "$SF_UNIT" >/dev/null 2>&1
    if [[ ${CORPUS_DONE:-0} != 1 ]]; then
        echo "  (interrupted: cleanup without measure)"
        corpus_cleanup >/dev/null 2>&1
    fi
    if [[ -n ${NN_CORPUS_KEEP:-} ]]; then
        mkdir -p "$NN_CORPUS_KEEP" && cp -a "$OUT/." "$NN_CORPUS_KEEP/" && echo "  raw records kept in $NN_CORPUS_KEEP"
    fi
    rm -rf "$OUT"
}

# packages installed now are recorded (a run killed half-way is put back by
# the next) and purged by corpus_purge
apt_need() { # <package>…
    local p
    for p in "$@"; do
        dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null | grep -q '^ii' && continue
        if sudo apt-get install -y -qq "$p" > "$OUT/apt.log" 2>&1; then
            INSTALLED="$INSTALLED $p"
            echo "$INSTALLED" > "$STATE"
        else
            echo "  apt-get install $p failed: $(tail -1 "$OUT/apt.log" | cut -c1-160)"
        fi
    done
}

corpus_purge() {
    if [[ -n ${INSTALLED// /} ]]; then
        # shellcheck disable=SC2086
        sudo apt-get purge -y -qq --autoremove $INSTALLED > "$OUT/apt.log" 2>&1 && echo "  purged:$INSTALLED"
    fi
    INSTALLED=""
    rm -f "$STATE"
}

posture() { sudo "$ADMIN" status 2>/dev/null | awk -F': *' '/^posture/ {print $2; exit}'; }
mono_ns() { python3 -I -c 'import time; print(time.monotonic_ns())'; }

# A restart of the agent inside a signed trusted-installer window, then 75 s:
# no signal of the preparation (or of a corpus before) is still counted.
corpus_settle() {
    local old new i
    sudo "$ADMIN" unlock --key "$KEY" >/dev/null 2>&1
    old=$(cat /run/northnarrow/agent.pid 2>/dev/null)
    sudo "$ADMIN" trusted-installer-grant --key "$KEY" --window-secs 60 >/dev/null 2>&1
    sudo systemctl kill -s SIGTERM northnarrow-agent
    for i in $(seq 1 60); do
        sleep 1
        new=$(cat /run/northnarrow/agent.pid 2>/dev/null)
        [[ -n $new && $new != "$old" ]] && kill -0 "$new" 2>/dev/null && break
    done
    sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl reset-failed northnarrow-agent; sudo systemctl start northnarrow-agent; }
    sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog
    sleep 75
    echo "  settled: agent $old -> $(cat /run/northnarrow/agent.pid 2>/dev/null) ($(systemctl is-active northnarrow-agent)), posture=$(posture)"
}

# The chains' lengths now: the report reads what comes after (and the
# journal's posture lines since now).
corpus_mark() {
    A0=$(sudo cat "$ACT" 2>/dev/null | wc -l)
    D0=$(sudo cat "$DET" 2>/dev/null | wc -l)
    U0=$(sudo cat "$AUD" 2>/dev/null | wc -l)
    T0=$(date +%s)
}

# The small-file probe (lot 282's backlog): every write-open of an existing
# regular file under 4 KiB, by process, from bpftrace in its own unit.
# NN_CORPUS_SMALLFILE=0 turns it off.
# Lot 290: bpftrace loads a kprobe and a perf_event program, types the
# agent refuses outside a trusted-installer window in every mode — the
# probe is the harness's instrument, not a workload: it loads inside a
# signed window of its own, and runs BEFORE corpus_settle, whose restart of
# the agent closes every window (the window ends at its deadline or at a
# restart, whichever comes first) 75 s before the measurement: no window is
# open while the steps run. No exception in the agent's code, none in the
# policy.
smallfile_start() {
    [[ ${NN_CORPUS_SMALLFILE:-1} == 1 ]] || return 0
    command -v bpftrace >/dev/null || { echo "  small-file probe: no bpftrace"; return 0; }
    sudo "$ADMIN" trusted-installer-grant --key "$KEY" --window-secs 150 >/dev/null 2>&1 ||
        { echo "  small-file probe: no window (not started)"; return 0; }
    sudo systemd-run --quiet --unit="$SF_UNIT" --collect \
        --setenv=BPFTRACE_MAP_KEYS_MAX=262144 --setenv=BPFTRACE_MAX_MAP_KEYS=262144 \
        -- bpftrace -B line -o "$OUT/smallfile.out" "$CORPUS_DIR/smallfile.bt" || { echo "  small-file probe: not started"; return 0; }
    # bpftrace compiles its program first: up to two minutes on a slow guest
    local i
    for i in $(seq 1 120); do
        sleep 1
        sudo grep -q '^SF-READY' "$OUT/smallfile.out" 2>/dev/null && break
    done
    if sudo grep -q '^SF-READY' "$OUT/smallfile.out" 2>/dev/null; then
        echo "  small-file probe: attached"
    else
        echo "  small-file probe: not attached ($(systemctl is-active "$SF_UNIT" 2>/dev/null))"
    fi
}

smallfile_stop() {
    sudo systemctl stop "$SF_UNIT" >/dev/null 2>&1
}

# step <name> <timeout-s> -- <cmd>…: rc, duration, the tail of a failure;
# begin and end (wall clock and monotonic, ns) and the posture after it
# go to the steps file the report reads. A shell function runs without the
# timeout (timeout(1) runs programs only).
step() {
    local name=$1 to=$2
    shift 3
    local t0 m0 rc t1 m1 d
    t0=$(date +%s%N)
    m0=$(mono_ns)
    if [[ $(type -t "$1") == function ]]; then
        "$@" > "$OUT/step.log" 2>&1
    else
        timeout "$to" "$@" > "$OUT/step.log" 2>&1
    fi
    rc=$?
    t1=$(date +%s%N)
    m1=$(mono_ns)
    d=$(((t1 - t0) / 100000000))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$t0" "$t1" "$m0" "$m1" "$rc" "$(posture)" >> "$STEPS"
    printf '  %-44s rc=%-3s %d.%d s\n' "$name" "$rc" $((d / 10)) $((d % 10))
    if ((rc != 0)); then
        tail -3 "$OUT/step.log" | cut -c1-200 | sed 's/^/     | /'
    fi
    return 0
}

# The context a command runs in, as a prefix in RUN: `session` — the ssh
# session (the workstation); `runner` — a session-less unit as the lab user
# (no login session, no loginuid: a CI runner); `root` — a session-less unit
# as root. Every cache goes under $W (removed by the cleanup).
runner() { # <session|runner|root>
    local env=(HOME="$HOME" PATH="$PATH" CARGO_HOME="$W/cache/cargo" GOPATH="$W/cache/gopath"
        GOCACHE="$W/cache/gocache" GOFLAGS=-modcacherw npm_config_cache="$W/cache/npm"
        PIP_CACHE_DIR="$W/cache/pip" GNUTLS_CPUID_OVERRIDE=0x1)
    local sets=() e
    for e in "${env[@]}"; do sets+=(--setenv="$e"); done
    case $1 in
        session) RUN=(env "${env[@]}") ;;
        runner) RUN=(sudo systemd-run --quiet --wait --pipe --collect --uid="$LABUSER" --gid="$LABGROUP"
            -p WorkingDirectory="$W" "${sets[@]}" --) ;;
        # root's own HOME: nothing of root's lands in the lab user's home
        root) RUN=(sudo systemd-run --quiet --wait --pipe --collect -p WorkingDirectory="$W" "${sets[@]:1}"
            --setenv=HOME=/root --) ;;
    esac
}

# The report: the chains after the mark, the steps, the probe.
corpus_report() {
    sleep 5
    sudo tail -n "+$((A0 + 1))" "$ACT" > "$OUT/actions.jsonl" 2>/dev/null
    sudo tail -n "+$((D0 + 1))" "$DET" > "$OUT/detections.jsonl" 2>/dev/null
    sudo tail -n "+$((U0 + 1))" "$AUD" > "$OUT/audit.jsonl" 2>/dev/null
    sudo journalctl --namespace=northnarrow -q -o short-unix -u northnarrow-agent --since "@$T0" 2>/dev/null |
        grep -E 'POSTURE TRANSITION|raising ConfirmedIntrusion' > "$OUT/journal.txt"
    local sf=()
    if sudo test -f "$OUT/smallfile.out"; then
        sudo chown "$LABUSER" "$OUT/smallfile.out"
        sf=(--smallfile "$OUT/smallfile.out")
    fi
    python3 -I "$CORPUS_DIR/corpus-report.py" --corpus "$CORPUS" --steps "$STEPS" \
        --actions "$OUT/actions.jsonl" --detections "$OUT/detections.jsonl" \
        --audit "$OUT/audit.jsonl" --journal "$OUT/journal.txt" "${sf[@]}"
    corpus_refusals
    echo "== done corpus $CORPUS $(date -u +%FT%TZ) posture=$(posture)"
}

# Lot 283b: the anti-tamper refusals of the run (NN-L-AT-001), each inode
# resolved to its path now — whose file the kernel refused to touch.
corpus_refusals() {
    sudo journalctl --namespace=northnarrow -q -o cat -u northnarrow-agent --since "@$T0" 2>/dev/null |
        grep -oE '`[^`]+` attempted [a-z_]+ on protected inode [0-9]+:[0-9]+' | sort | uniq -c > "$OUT/refusals.txt"
    [[ -s $OUT/refusals.txt ]] || return 0
    echo "  anti-tamper refusals (journal; each inode resolved to its path now):"
    local n who op ino path
    while read -r n who _ op _ _ _ ino; do
        path=$(sudo find / /run -xdev -inum "${ino#*:}" 2>/dev/null | head -1)
        echo "    ${n}x $who $op ${path:-inode $ino (no path now)}"
        printf 'TSV\trefusal\t%s\t%s\t%s\t%s\t%s\n' "$CORPUS" "$who" "$op" "${path:-$ino}" "$n"
    done < "$OUT/refusals.txt"
}

# The common end of a workload script: cleanup measured, then the report.
corpus_finish() {
    step cleanup 900 -- corpus_cleanup
    smallfile_stop
    CORPUS_DONE=1
    corpus_report
    sudo "$ADMIN" unlock --key "$KEY" >/dev/null 2>&1
}

# ── the builds, shared by the workstation and the CI runner ─────────────────
# Pinned versions: the same corpus on Ubuntu 22.04 (Node 12, Go 1.18) and
# 24.04. Each takes the context of runner() and a prefix for its steps' names.

# A small crate in a local repository (git clone without a forge), three
# registry dependencies, unit tests, and 120 small modules nobody formatted.
prep_crate() {
    local s=$W/src/crate
    rm -rf "$s" && mkdir -p "$s/src/m"
    cat > "$s/Cargo.toml" <<'EOF'
[package]
name = "nn-corpus-crate"
version = "0.1.0"
edition = "2021"

[dependencies]
regex = "=1.10.6"
serde = { version = "=1.0.210", features = ["derive"] }
serde_json = "=1.0.128"
EOF
    {
        echo 'pub mod m;'
        echo 'use serde::{Deserialize, Serialize};'
        echo '#[derive(Serialize, Deserialize, Debug, PartialEq)] pub struct Row { pub k: String, pub v: u32 }'
        echo 'pub fn parse(s: &str) -> Vec<Row> { let re = regex::Regex::new(r"(\w+)=(\d+)").unwrap(); re.captures_iter(s).map(|c| Row { k: c[1].to_string(), v: c[2].parse().unwrap() }).collect() }'
        echo '#[cfg(test)] mod tests { use super::*; #[test] fn parses() { let r = parse("a=1 b=2"); assert_eq!(r.len(), 2); assert_eq!(serde_json::to_string(&r[0]).unwrap(), "{\"k\":\"a\",\"v\":1}"); } }'
    } > "$s/src/lib.rs"
    local i
    : > "$s/src/m/mod.rs"
    for i in $(seq 1 120); do
        echo "pub mod f$i;" >> "$s/src/m/mod.rs"
        printf 'pub fn f%s(x:u32)->u32{let y=x+%s;if y>10{y*2}else{y+1}}\n#[cfg(test)]mod t{#[test]fn t(){assert!(super::f%s(1)>0);}}\n' "$i" "$i" "$i" > "$s/src/m/f$i.rs"
    done
    (cd "$s" && git init -q -b main && git add -A && git -c user.name=corpus -c user.email=corpus@example.invalid commit -qm crate)
    git clone -q --bare "$s" "$W/src/crate.git"
}

wl_cargo() { # <context> <prefix>
    local p=$2
    runner "$1"
    step "$p git clone (local repository)" 120 -- "${RUN[@]}" git clone -q "file://$W/src/crate.git" "$W/crate"
    step "$p cargo build" 900 -- "${RUN[@]}" bash -c "cd $W/crate && cargo build -q"
    step "$p cargo test" 900 -- "${RUN[@]}" bash -c "cd $W/crate && cargo test -q"
}

prep_go() {
    local s=$W/gomod
    rm -rf "$s" && mkdir -p "$s/calc"
    printf 'module example.invalid/nncorpus\n\ngo 1.18\n' > "$s/go.mod"
    printf 'package calc\n\nfunc Sum(xs ...int) int {\n\tt := 0\n\tfor _, x := range xs {\n\t\tt += x\n\t}\n\treturn t\n}\n' > "$s/calc/calc.go"
    printf 'package calc\n\nimport "testing"\n\nfunc TestSum(t *testing.T) {\n\tif Sum(1, 2, 3) != 6 {\n\t\tt.Fatal("sum")\n\t}\n}\n' > "$s/calc/calc_test.go"
    printf 'package main\n\nimport (\n\t"fmt"\n\n\t"example.invalid/nncorpus/calc"\n)\n\nfunc main() { fmt.Println(calc.Sum(1, 2)) }\n' > "$s/main.go"
}

wl_go() { # <context> <prefix>
    local p=$2
    runner "$1"
    step "$p go test ./..." 600 -- "${RUN[@]}" bash -c "cd $W/gomod && go test -count=1 ./..."
    step "$p go run ." 300 -- "${RUN[@]}" bash -c "cd $W/gomod && go run ."
    step "$p go build" 300 -- "${RUN[@]}" bash -c "cd $W/gomod && go build -o $W/gomod/nncorpus ."
}

# typescript 4.9.5 and prettier 2.8.8 run on Node 12 (22.04) and 18 (24.04)
prep_npm() {
    local s=$W/web
    rm -rf "$s" && mkdir -p "$s/src"
    cat > "$s/package.json" <<'EOF'
{ "name": "nn-corpus-web", "version": "1.0.0", "private": true,
  "scripts": { "build": "tsc -p ." },
  "dependencies": { "lodash": "4.17.21" },
  "devDependencies": { "typescript": "4.9.5", "prettier": "2.8.8", "@types/lodash": "4.17.0" } }
EOF
    printf '{ "compilerOptions": { "target": "es2019", "module": "commonjs", "outDir": "dist", "strict": true, "esModuleInterop": true }, "include": ["src"] }\n' > "$s/tsconfig.json"
    local i
    for i in $(seq 1 300); do
        printf 'import _ from "lodash"\nexport   function   f%s ( a : number,b:number ) : number { return _.sum( [a,b,%s] ) }\nexport const   v%s = { a:1,b : [1,2,3],   c:"x" }\n' "$i" "$i" "$i" > "$s/src/f$i.ts"
    done
}

wl_npm() { # <context> <prefix>
    local p=$2
    runner "$1"
    step "$p npm install (the lockfile)" 900 -- "${RUN[@]}" bash -c "cd $W/web && npm install --no-audit --no-fund --loglevel=error"
    step "$p npm ci" 900 -- "${RUN[@]}" bash -c "cd $W/web && npm ci --no-audit --no-fund --loglevel=error"
    step "$p npm run build (tsc)" 600 -- "${RUN[@]}" bash -c "cd $W/web && npm run -s build"
}

wl_pip() { # <context> <prefix>
    local p=$2
    runner "$1"
    step "$p python3 -m venv" 300 -- "${RUN[@]}" python3 -m venv "$W/venv"
    step "$p pip install requests rich" 600 -- "${RUN[@]}" "$W/venv/bin/pip" install -q --disable-pip-version-check requests==2.31.0 rich==13.7.1
}
