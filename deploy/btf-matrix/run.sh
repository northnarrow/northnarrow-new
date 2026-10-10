#!/usr/bin/env bash
# deploy/btf-matrix/run.sh — computed kernel-compatibility matrix over
# BTFHub (multi-kernel, level 2; docs/operator/KERNEL_COMPATIBILITY.md).
#
# For every distro/version in KERNELS the newest BTF blob of the archive
# (cloud/low-latency flavours skipped) is downloaded, and
# `northnarrow-agent --btf-check` gives the verdict without root and
# without loading any eBPF. The verdicts are compared with
# expected.tsv: a verdict WORSE than expected (SUPPORTED → DEGRADED →
# NOT_SUPPORTED) or an unreadable/unparseable BTF fails the run; a
# better one is reported so the baseline can be raised.
#
# BTFHub archives only kernels shipped WITHOUT native BTF (≤ 5.x on most
# distros). Kernels with native BTF are covered by the lab guests
# (`deploy/lab/nn-lab.sh`), and the host's own /sys/kernel/btf/vmlinux is
# added as a last row when readable.
#
#   deploy/btf-matrix/run.sh [--agent BIN] [--out matrix.md] [--cache DIR]
#
# Needs: curl, tar (xz), and `gh` or an unauthenticated GitHub API quota
# (one request per distro/version). Exit 0 = matrix matches or improves
# the baseline; 1 = regression or broken BTF; 2 = usage/tooling error.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
AGENT="$ROOT/target/release/northnarrow-agent"
OUT="$ROOT/target/btf-matrix/matrix.md"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/nn-btf-matrix"
EXPECTED="$HERE/expected.tsv"
ARCHIVE_API="repos/aquasecurity/btfhub-archive/contents"
ARCHIVE_RAW="https://github.com/aquasecurity/btfhub-archive/raw/main"

while [ $# -gt 0 ]; do
    case "$1" in
        --agent) AGENT="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --cache) CACHE="$2"; shift 2 ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -x "$AGENT" ] || { echo "agent binary not found: $AGENT (cargo build --release -p northnarrow-agent)" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl missing" >&2; exit 2; }
mkdir -p "$CACHE" "$(dirname "$OUT")"

# distro/version pairs (x86_64). Flavours matching SKIP are ignored when
# picking the newest kernel so the generic/distro kernel is tested.
KERNELS=(
    ubuntu/20.04
    ubuntu/18.04
    centos/8
    rhel/8
    ol/8
    amzn/2
    fedora/31
    sles/15.3
    centos/7
)
SKIP='azure|gcp|gke|aws|oracle|lowlatency|oem|kvm|cloud|rt\.|\.rt'

api_list() { # <distro/version> → file names, one per line
    local path="$ARCHIVE_API/$1/x86_64"
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        gh api "$path" --jq '.[].name'
    else
        curl -sSf ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
            "https://api.github.com/$path" | sed -n 's/^ *"name": *"\(.*\)",*$/\1/p'
    fi
}

verdict_rank() { # SUPPORTED=2 DEGRADED=1 NOT_SUPPORTED=0 BROKEN=-1
    case "$1" in
        SUPPORTED) echo 2 ;; DEGRADED) echo 1 ;; NOT_SUPPORTED) echo 0 ;; *) echo -1 ;;
    esac
}

declare -A EXPECT
if [ -f "$EXPECTED" ]; then
    while IFS=$'\t' read -r k v _; do
        [ -z "$k" ] || [ "${k:0:1}" = "#" ] && continue
        EXPECT["$k"]="$v"
    done < "$EXPECTED"
fi

rows=()
fail=0
improve=0
check_one() { # <label> <btf-file> <kernel>
    local label="$1" btf="$2" kernel="$3" out rc verdict detail
    set +e
    out="$("$AGENT" --btf-check "$btf" 2>&1)"
    rc=$?
    set -e
    local summary
    summary="$(printf '%s\n' "$out" | grep -m1 '^btf-check ' || true)"
    case "$rc" in
        0) if printf '%s' "$summary" | grep -q 'SUPPORTED (degraded)'; then verdict=DEGRADED; else verdict=SUPPORTED; fi ;;
        2) verdict=NOT_SUPPORTED ;;
        *) verdict=BROKEN ;;
    esac
    detail="$(printf '%s' "$summary" | sed -n 's/.*— //p' | cut -c1-110)"
    local absent
    absent="$(printf '%s\n' "$out" | awk '$1=="absent"||$1=="missing"{printf "%s%s", sep, $2; sep=", "}')"
    [ -n "$absent" ] && detail="$detail; $absent"
    local exp="${EXPECT[$label]:-}" note=""
    if [ -n "$exp" ]; then
        local ra re
        ra=$(verdict_rank "$verdict"); re=$(verdict_rank "$exp")
        if [ "$ra" -lt "$re" ]; then note="**REGRESSION** (expected $exp)"; fail=1
        elif [ "$ra" -gt "$re" ]; then note="better than expected ($exp) — raise the baseline"; improve=1
        else note="as expected"; fi
    else
        note="no baseline — add \`$label	$verdict\` to expected.tsv"
    fi
    [ "$verdict" = BROKEN ] && { fail=1; detail="exit $rc: $(printf '%s' "$out" | tail -1 | cut -c1-120)"; }
    # BPF LSM (the anti-tamper hooks) needs 5.7+: below that the verdict
    # is informational — the agent cannot run there whatever the offsets.
    local lsm="yes"
    local maj min
    maj="${kernel%%.*}"; min="${kernel#*.}"; min="${min%%.*}"
    if [[ "$maj" =~ ^[0-9]+$ && "$min" =~ ^[0-9]+$ ]] && { [ "$maj" -lt 5 ] || { [ "$maj" -eq 5 ] && [ "$min" -lt 7 ]; }; }; then
        lsm="no (needs 5.7+)"
    fi
    rows+=("| $label | $kernel | $lsm | $verdict | $detail | $note |")
    echo "btf-matrix: $label $kernel → $verdict ($note)" >&2
}

for dv in "${KERNELS[@]}"; do
    names="$(api_list "$dv" 2>/dev/null || true)"
    if [ -z "$names" ]; then
        rows+=("| $dv | — | — | BROKEN | archive listing failed | **REGRESSION** |"); fail=1
        echo "btf-matrix: $dv listing failed" >&2; continue
    fi
    file="$(printf '%s\n' "$names" | grep '\.btf\.tar\.xz$' | grep -vE "$SKIP" | sort -V | tail -1 || true)"
    if [ -z "$file" ]; then
        rows+=("| $dv | — | — | n/a | no archived BTF (kernels ship native BTF) | — |")
        echo "btf-matrix: $dv has no archived BTF" >&2; continue
    fi
    kernel="${file%.btf.tar.xz}"
    dir="$CACHE/$dv"; mkdir -p "$dir"
    btf="$dir/$kernel.btf"
    if [ ! -s "$btf" ]; then
        curl -sSfL -o "$dir/$file" "$ARCHIVE_RAW/$dv/x86_64/$file"
        tar -xJf "$dir/$file" -C "$dir"
        rm -f "$dir/$file"
    fi
    check_one "$dv" "$btf" "$kernel"
done
if [ -r /sys/kernel/btf/vmlinux ]; then
    check_one "host" /sys/kernel/btf/vmlinux "$(uname -r)"
fi

{
    echo "# Computed kernel-compatibility matrix (BTFHub)"
    echo
    echo "- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "- agent: \`$("$AGENT" --version 2>/dev/null | head -1 || echo "$AGENT")\`"
    echo "- newest non-cloud kernel per distro/version in the BTFHub archive; kernels with native BTF are covered by the lab guests"
    echo
    echo "| distro/version | kernel | BPF LSM | verdict | detail | vs baseline |"
    echo "|---|---|---|---|---|---|"
    printf '%s\n' "${rows[@]}"
} > "$OUT"
echo "btf-matrix: written $OUT" >&2
[ "$improve" = 1 ] && echo "btf-matrix: some verdicts are better than expected.tsv — raise the baseline" >&2
if [ "$fail" = 1 ]; then echo "btf-matrix: FAILED (regression or broken BTF)" >&2; exit 1; fi
exit 0
