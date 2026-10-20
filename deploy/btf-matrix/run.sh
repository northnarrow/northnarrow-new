#!/usr/bin/env bash
# deploy/btf-matrix/run.sh — computed kernel-compatibility matrix over
# BTFHub (multi-kernel, level 2; docs/operator/KERNEL_COMPATIBILITY.md).
#
# For every distro/version of expected.tsv the BTF blob pinned in
# blobs.sha256 (the newest non-cloud kernel of that distro/version at the
# archive commit pinned there) is downloaded at that commit, checked
# against its sha256, and its one member `<kernel>.btf` is read out of it;
# `northnarrow-agent --btf-check` gives the verdict without root and
# without loading any eBPF. The verdicts are compared with expected.tsv: a
# verdict WORSE than expected (SUPPORTED → DEGRADED → NOT_SUPPORTED), an
# unreadable/unparseable BTF, a blob that fails its checks, or a
# distro/version with a baseline and no blob fails the run; a better one
# is reported so the baseline can be raised.
#
# External audit SUP-014: the blobs are third-party files fed to the
# product's BTF parser, so no name and no byte comes from the archive's
# moving branch, and a cached blob is checked again at every run. A bump is
# a PR: `--refresh [COMMIT]` lists the archive at COMMIT (default: the head
# of its main branch, resolved to a commit), picks the newest non-cloud
# blob per distro/version (a name outside [A-Za-z0-9._+-] is refused),
# checks it the same way, writes the matrix of the new blobs and prints a
# new blobs.sha256 on stdout. Trade-off: kernels archived after the pin
# reach the weekly run through such a PR, not by themselves.
#
# BTFHub archives only kernels shipped WITHOUT native BTF (≤ 5.x on most
# distros). Kernels with native BTF are covered by the lab guests
# (`deploy/lab/nn-lab.sh`), and the host's own /sys/kernel/btf/vmlinux is
# added as a last row when readable (not with --no-host).
#
#   deploy/btf-matrix/run.sh [--agent BIN] [--out matrix.md] [--cache DIR]
#                            [--pins FILE] [--expected FILE] [--no-host]
#   deploy/btf-matrix/run.sh --refresh [COMMIT] [options] > blobs.sha256.new
#
# Needs: curl, tar, xz, sha256sum. Only --refresh calls the GitHub API (one
# request per distro/version, through `gh` when it is logged in, else
# curl; a GITHUB_TOKEN is sent in a header curl reads from a file
# descriptor, never on a command line — SUP-021). deploy/btf-matrix/run-test.sh
# tests this script offline. Exit 0 = matrix matches or improves the
# baseline; 1 = regression, broken BTF or a refused blob; 2 = usage/tooling
# error.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
AGENT="$ROOT/target/release/northnarrow-agent"
OUT="$ROOT/target/btf-matrix/matrix.md"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/nn-btf-matrix"
EXPECTED="$HERE/expected.tsv"
PINS="$HERE/blobs.sha256"
HOST_ROW=1
REFRESH=0
REFRESH_REF=""
ARCHIVE_REPO="aquasecurity/btfhub-archive"
ARCHIVE_RAW="https://raw.githubusercontent.com/$ARCHIVE_REPO"
# Ceilings for one download and for the BTF read out of it (the largest
# pinned archive is ~4 MB, its BTF ~50 MB).
MAX_ARCHIVE=$((64 * 1024 * 1024))
MAX_BTF=$((512 * 1024 * 1024))
# Flavours matching SKIP are ignored when picking the newest kernel, so the
# generic/distro kernel is tested.
SKIP='azure|gcp|gke|aws|oracle|lowlatency|oem|kvm|cloud|rt\.|\.rt'
NAME_RE='^[A-Za-z0-9][A-Za-z0-9._+-]*\.btf\.tar\.xz$'
LABEL_RE='^[a-z][a-z0-9_-]*/[0-9][0-9.]*$'
SHA_RE='^[0-9a-f]{64}$'
REF_RE='^[0-9a-f]{40}$'

usage_error() { echo "btf-matrix: $*" >&2; exit 2; }
need_value() { [ "$2" -ge 2 ] || usage_error "$1 needs a value"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --agent) need_value "$1" $#; AGENT="$2"; shift 2 ;;
        --out) need_value "$1" $#; OUT="$2"; shift 2 ;;
        --cache) need_value "$1" $#; CACHE="$2"; shift 2 ;;
        --pins) need_value "$1" $#; PINS="$2"; shift 2 ;;
        --expected) need_value "$1" $#; EXPECTED="$2"; shift 2 ;;
        --no-host) HOST_ROW=0; shift ;;
        --refresh)
            REFRESH=1; shift
            if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then REFRESH_REF="$1"; shift; fi ;;
        -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
        *) usage_error "unknown argument: $1" ;;
    esac
done
[ -x "$AGENT" ] || usage_error "agent binary not found: $AGENT (cargo build --release -p northnarrow-agent)"
for tool in curl tar xz sha256sum; do
    command -v "$tool" >/dev/null || usage_error "$tool missing"
done
[ -f "$EXPECTED" ] || usage_error "no baseline file: $EXPECTED"
if [ -n "$REFRESH_REF" ] && ! [[ "$REFRESH_REF" =~ $REF_RE ]]; then
    usage_error "--refresh takes a full commit id (40 hex digits), got '$REFRESH_REF'"
fi
mkdir -p "$CACHE" "$(dirname "$OUT")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Baseline and label order: expected.tsv (`<distro/version>\t<verdict>`).
declare -A EXPECT
LABELS=()
while IFS=$'\t' read -r k v _ || [ -n "$k" ]; do
    { [ -z "$k" ] || [ "${k:0:1}" = "#" ]; } && continue
    EXPECT["$k"]="$v"
    [ "$k" = host ] && continue
    [[ "$k" =~ $LABEL_RE ]] || usage_error "$EXPECTED: not a distro/version: '$k'"
    LABELS+=("$k")
done < "$EXPECTED"

# The pins: `ref <commit>` once, then `<distro/version> <file> <sha256>`.
# Any other line is an error: a pin file that does not parse checks nothing.
declare -A PIN_FILE PIN_SHA
ARCHIVE_REF=""
if [ -f "$PINS" ]; then
    n=0
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        case "$line" in ''|'#'*) continue ;; esac
        a="" b="" c="" extra=""
        read -r a b c extra <<<"$line" || true
        if [ "$a" = ref ]; then
            [[ "$b" =~ $REF_RE ]] && [ -z "$c" ] && [ -z "$ARCHIVE_REF" ] \
                || usage_error "$PINS:$n: expected one \`ref <40-hex commit>\` line"
            ARCHIVE_REF="$b"; continue
        fi
        if ! [[ "$a" =~ $LABEL_RE && "$b" =~ $NAME_RE && "$c" =~ $SHA_RE ]] || [ -n "$extra" ]; then
            usage_error "$PINS:$n: expected \`<distro/version> <name>.btf.tar.xz <sha256>\`"
        fi
        [ -z "${PIN_FILE[$a]:-}" ] || usage_error "$PINS:$n: $a is pinned twice"
        PIN_FILE["$a"]="$b"; PIN_SHA["$a"]="$c"
    done < "$PINS"
    [ -n "$ARCHIVE_REF" ] || [ "$REFRESH" = 1 ] || usage_error "$PINS: no \`ref <commit>\` line"
    while IFS= read -r a; do
        [ -z "$a" ] || [ -n "${EXPECT[$a]+x}" ] || LABELS+=("$a")
    done < <(printf '%s\n' "${!PIN_FILE[@]}" | sort)
elif [ "$REFRESH" = 0 ]; then
    usage_error "no pin file: $PINS (deploy/btf-matrix/run.sh --refresh writes one)"
fi

# --- the GitHub API (--refresh only) ---------------------------------------
# `gh` reads its token from its own config or GH_TOKEN, never from argv.
use_gh() { command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; }
api_curl() { # <path?query> <accept> → response body
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        # SUP-021: printf is a builtin; curl reads the header from /dev/fd/N,
        # so the token is in no process's argv (/proc/<pid>/cmdline).
        curl -sSf --proto '=https' -H "Accept: $2" \
            -H @<(printf 'Authorization: Bearer %s\n' "$GITHUB_TOKEN") \
            "https://api.github.com/$1"
    else
        curl -sSf --proto '=https' -H "Accept: $2" "https://api.github.com/$1"
    fi
}
api_head() { # → the commit at the head of the archive's main branch
    local path="repos/$ARCHIVE_REPO/commits/main" accept=application/vnd.github.sha
    if use_gh; then gh api -H "Accept: $accept" "$path"; else api_curl "$path" "$accept"; fi
}
api_list() { # <distro/version> → file names at $ARCHIVE_REF, one per line
    local path="repos/$ARCHIVE_REPO/contents/$1/x86_64?ref=$ARCHIVE_REF"
    if use_gh; then
        gh api "$path" --jq '.[].name'
    else
        api_curl "$path" application/vnd.github+json | sed -n 's/^ *"name": *"\([^"]*\)",*$/\1/p'
    fi
}

# --- getting and opening a blob --------------------------------------------
sha256_of() { local s _; read -r s _ < <(sha256sum -- "$1") && printf '%s' "$s"; }

download() { # <distro/version> <file> <dest>
    curl -sSfL --proto '=https' --proto-redir '=https' --max-filesize "$MAX_ARCHIVE" \
        -o "$3" "$ARCHIVE_RAW/$ARCHIVE_REF/$1/x86_64/$2"
}

# fetch_pinned <distro/version> <file> <sha256> → $BLOB, a copy in $CACHE
# whose sha256 is the pinned one. Nothing that fails the check is left in
# $CACHE: a download is checked in $WORK and moved only then, and a cached
# copy that no longer matches is deleted and downloaded again.
fetch_pinned() {
    local dv="$1" file="$2" want="$3" dir="$CACHE/$1" tmp got
    BLOB="$dir/$file"; ERR=""
    if [ -e "$BLOB" ] || [ -L "$BLOB" ]; then
        if [ -f "$BLOB" ] && [ ! -L "$BLOB" ] && got="$(sha256_of "$BLOB")" && [ "$got" = "$want" ]; then
            return 0
        fi
        echo "btf-matrix: $dv: the cached $file does not match its pin — deleted, downloading it again" >&2
        rm -f -- "$BLOB"
    fi
    tmp="$(mktemp -d "$WORK/dl.XXXXXX")"
    if ! download "$dv" "$file" "$tmp/$file"; then
        ERR="download of $file failed"; return 1
    fi
    got="$(sha256_of "$tmp/$file")"
    if [ "$got" != "$want" ]; then
        ERR="$file: sha256 $got, pinned $want — refused"; return 1
    fi
    mkdir -p "$dir"
    mv -f -- "$tmp/$file" "$BLOB"
}

# open_blob <archive> <kernel> → $BTF, the archive's only member
# `<kernel>.btf` (a regular file), read into $WORK through `tar -O`: no
# member name, owner, mode or link from the archive reaches the disk, and
# at most MAX_BTF bytes are read.
open_blob() {
    local archive="$1" kernel="$2" names verbose out
    BTF=""; ERR=""
    if ! names="$(tar -tJf "$archive" 2>/dev/null)"; then
        ERR="not an xz tar archive"; return 1
    fi
    if [ "$names" != "$kernel.btf" ] && [ "$names" != "./$kernel.btf" ]; then
        ERR="archive members [$(printf '%s' "$names" | head -5 | tr '\n' ' ' | cut -c1-100)], expected only $kernel.btf — refused"
        return 1
    fi
    verbose="$(tar -tvJf "$archive" 2>/dev/null)" || { ERR="archive listing failed"; return 1; }
    if [ "${verbose:0:1}" != "-" ]; then
        ERR="$kernel.btf is not a regular file in the archive — refused"; return 1
    fi
    out="$(mktemp -d "$WORK/btf.XXXXXX")/$kernel.btf"
    if ! tar -xJOf "$archive" -- "$names" | head -c "$((MAX_BTF + 1))" > "$out"; then
        ERR="extraction failed"; return 1
    fi
    local size
    size="$(stat -c %s -- "$out")"
    if [ "$size" -eq 0 ] || [ "$size" -gt "$MAX_BTF" ]; then
        ERR="$kernel.btf is $size bytes (1 to $MAX_BTF accepted) — refused"; return 1
    fi
    BTF="$out"
}

# --- verdicts ---------------------------------------------------------------
verdict_rank() { # SUPPORTED=2 DEGRADED=1 NOT_SUPPORTED=0 BROKEN=-1
    case "$1" in
        SUPPORTED) echo 2 ;; DEGRADED) echo 1 ;; NOT_SUPPORTED) echo 0 ;; *) echo -1 ;;
    esac
}

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

# SUP-013: a distro/version with a baseline and no blob is a regression,
# not a skipped row (a renamed archive layout or a lost pin would
# otherwise turn a checked kernel into "n/a" and the run stay green).
no_blob() { # <label> <reason>
    local exp="${EXPECT[$1]:-}"
    if [ -n "$exp" ]; then
        rows+=("| $1 | — | — | n/a | $2 | **REGRESSION** (baseline $exp, no blob found) |"); fail=1
    else
        rows+=("| $1 | — | — | n/a | $2 | — |")
    fi
    echo "btf-matrix: $1: $2" >&2
}
refused() { # <label> <kernel> <reason>
    rows+=("| $1 | $2 | — | BROKEN | $3 | **REGRESSION** |"); fail=1
    echo "btf-matrix: $1: $3" >&2
}

pins_out=()
if [ "$REFRESH" = 1 ]; then
    if [ -z "$REFRESH_REF" ]; then
        REFRESH_REF="$(api_head 2>/dev/null || true)"
        [[ "$REFRESH_REF" =~ $REF_RE ]] || usage_error "cannot resolve the head of $ARCHIVE_REPO to a commit (got '${REFRESH_REF:0:60}')"
    fi
    ARCHIVE_REF="$REFRESH_REF"
fi

for dv in "${LABELS[@]}"; do
    if [ "$REFRESH" = 1 ]; then
        if ! names="$(api_list "$dv" 2>/dev/null)" || [ -z "$names" ]; then
            rows+=("| $dv | — | — | BROKEN | archive listing failed | **REGRESSION** |"); fail=1
            pins_out+=("# $dv: archive listing failed")
            echo "btf-matrix: $dv listing failed" >&2; continue
        fi
        odd="$(printf '%s\n' "$names" | grep '\.btf\.tar\.xz$' | grep -cvE "$NAME_RE" || true)"
        [ "$odd" = 0 ] || echo "btf-matrix: $dv: $odd archive name(s) outside [A-Za-z0-9._+-] ignored" >&2
        file="$(printf '%s\n' "$names" | grep -E "$NAME_RE" | grep -vE "$SKIP" | sort -V | tail -1 || true)"
        if [ -z "$file" ]; then
            no_blob "$dv" "no archived BTF at ${ARCHIVE_REF:0:12}"
            pins_out+=("# $dv: no archived BTF"); continue
        fi
        kernel="${file%.btf.tar.xz}"
        tmp="$(mktemp -d "$WORK/dl.XXXXXX")"
        if ! download "$dv" "$file" "$tmp/$file"; then
            refused "$dv" "$kernel" "download of $file failed"
            pins_out+=("# $dv: download of $file failed"); continue
        fi
        archive="$tmp/$file"
        pin="$dv $file $(sha256_of "$archive")"
    else
        file="${PIN_FILE[$dv]:-}"
        if [ -z "$file" ]; then
            no_blob "$dv" "no blob pinned in $(basename "$PINS")"; continue
        fi
        kernel="${file%.btf.tar.xz}"
        if ! fetch_pinned "$dv" "$file" "${PIN_SHA[$dv]}"; then
            refused "$dv" "$kernel" "$ERR"; continue
        fi
        archive="$BLOB"
    fi
    if ! open_blob "$archive" "$kernel"; then
        refused "$dv" "$kernel" "$ERR"
        [ "$REFRESH" = 1 ] && pins_out+=("# $dv: $file refused: $ERR")
        continue
    fi
    [ "$REFRESH" = 1 ] && pins_out+=("$pin")
    check_one "$dv" "$BTF" "$kernel"
    rm -rf -- "$(dirname "$BTF")"
done
if [ "$HOST_ROW" = 1 ] && [ -r /sys/kernel/btf/vmlinux ]; then
    check_one "host" /sys/kernel/btf/vmlinux "$(uname -r)"
fi

{
    echo "# Computed kernel-compatibility matrix (BTFHub)"
    echo
    echo "- generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "- agent: \`$("$AGENT" --version 2>/dev/null | head -1 || echo "$AGENT")\`"
    echo "- archive: \`$ARCHIVE_REPO@$ARCHIVE_REF\`$([ "$REFRESH" = 1 ] && echo " (refresh: blobs not pinned yet)")"
    echo "- the blob pinned in deploy/btf-matrix/blobs.sha256 per distro/version (the newest non-cloud kernel at that commit); kernels with native BTF are covered by the lab guests"
    echo
    echo "| distro/version | kernel | BPF LSM | verdict | detail | vs baseline |"
    echo "|---|---|---|---|---|---|"
    printf '%s\n' "${rows[@]}"
} > "$OUT"
echo "btf-matrix: written $OUT" >&2

if [ "$REFRESH" = 1 ]; then
    cat <<EOF
# The BTFHub blobs deploy/btf-matrix/run.sh checks (external audit SUP-014).
#
#   ref <commit of $ARCHIVE_REPO the blobs are downloaded at>
#   <distro/version> <archive name> <sha256 of the archive>
#
# The newest non-cloud kernel of each distro/version of expected.tsv at
# that commit. Written by \`deploy/btf-matrix/run.sh --refresh [COMMIT]\`:
# a bump is a PR that replaces this file, and the BTF matrix workflow
# checks the new blobs on it. Never edit a digest by hand.
ref $ARCHIVE_REF
EOF
    printf '%s\n' "${pins_out[@]}"
fi
[ "$improve" = 1 ] && echo "btf-matrix: some verdicts are better than expected.tsv — raise the baseline" >&2
if [ "$fail" = 1 ]; then echo "btf-matrix: FAILED (regression, broken BTF or refused blob)" >&2; exit 1; fi
exit 0
