#!/usr/bin/env bash
# The oldest glibc a release runs on, checked on what is shipped.
#
# The release binaries are linked on the build host. Linked against a newer
# glibc than a supported distribution has, a binary that refers to a newer
# function, even weakly (Rust's standard library probes `pidfd_spawnp` and
# `pidfd_getpid`, GLIBC_2.39, that way), prints
#   weak version `GLIBC_2.39' not found (required by nn-admin)
# at every start on Ubuntu 22.04 and Debian 12; a strong reference does not
# start at all. Every ELF file shipped must need no glibc symbol version
# above GLIBC_BASELINE, weak references included, and no shared library
# beyond glibc's own and libgcc_s (any other is a runtime dependency the
# packages do not declare).
#
#   glibc-baseline.sh check [--allow-lib SONAME]... PATH...
#                                 every ELF file under each PATH (a file or a
#                                 directory, searched): its glibc version
#                                 needs (`readelf -V`, the .gnu.version_r
#                                 section: strong and weak) and its NEEDED
#                                 libraries; exit 1 on the first rule broken
#                                 by any file, after listing them all
#   glibc-baseline.sh selftest    the check against binaries built here on
#                                 purpose: a strong and a weak need of
#                                 GLIBC_2.35 and GLIBC_2.39 refused, a need
#                                 of GLIBC_2.34 accepted, an undeclared
#                                 library refused.
#                                 Needs cc and the Rust toolchain's rust-lld
#                                 (the linker of the release, which marks a
#                                 weak-only version need WEAK)
#
# The release workflow (.github/workflows/release.yml, package job) runs
# `selftest`, then `check` on the tarball's tree, the .deb's and the .rpm's
# files. Needs readelf (binutils).
set -euo pipefail

# The glibc of AlmaLinux/RHEL 9, the oldest of the supported distributions
# (docs/operator/KERNEL_COMPATIBILITY.md, "Verified matrix") and the floor
# the .deb and the .rpm declare: Ubuntu 22.04 has 2.35, Debian 12 2.36,
# Ubuntu 24.04 2.39. The release is built on Ubuntu 22.04, the oldest image
# GitHub offers; this check is what holds every need at or below 2.34.
# xtask/tests/supply_chain.rs keeps the packages' floors equal to it.
GLIBC_BASELINE=2.34
# The shared libraries a release binary may need: glibc's and libgcc_s
# (the unwinder Rust's standard library links), present on every distribution.
ALLOWED_LIBS=(libc.so.6 libm.so.6 libgcc_s.so.1 ld-linux-x86-64.so.2 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1)

die() { echo "glibc-baseline: $*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found${2:+ ($2)}"; }

# 0 when version a is above version b (dotted numbers).
above() {
    [[ "$1" != "$2" ]] && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}

is_elf() { [[ -f "$1" && ! -L "$1" ]] && [[ "$(head -c4 -- "$1" | od -An -c | tr -d ' ')" == '177ELF' ]]; }

# One ELF file: "ok …" or "FAIL …" lines; returns 1 when a rule is broken.
check_one() {
    local f=$1 bad=0 line name flags v lib max="" weak=""
    local -a allowed=("${ALLOWED_LIBS[@]}" "${EXTRA_LIBS[@]}")
    # The version needs (.gnu.version_r): "Name: GLIBC_2.39  Flags: WEAK".
    while read -r line; do
        name=$(sed -n 's/.*Name: \([^ ]*\).*/\1/p' <<<"$line")
        flags=$(sed -n 's/.*Flags: \([^ ]*\).*/\1/p' <<<"$line")
        [[ "$name" == GLIBC_* ]] || continue
        v=${name#GLIBC_}
        if [[ ! "$v" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
            echo "FAIL  $f needs $name (not a release of glibc)"; bad=1; continue
        fi
        if above "$v" "$GLIBC_BASELINE"; then
            echo "FAIL  $f needs $name (flags: ${flags:-none}) — above the baseline GLIBC_$GLIBC_BASELINE"
            bad=1
        fi
        if [[ -z "$max" ]] || above "$v" "$max"; then max=$v; weak=$flags; fi
    done < <(readelf -V -W -- "$f" 2>/dev/null | sed -n '/^Version needs section/,/^Version \(definition\|symbols\) section/p' | grep 'Name: ')
    while read -r lib; do
        [[ -n "$lib" ]] || continue
        local ok=0 a
        for a in "${allowed[@]}"; do [[ "$lib" == "$a" ]] && ok=1; done
        if (( ! ok )); then
            echo "FAIL  $f needs the shared library $lib (not glibc's nor libgcc_s: a dependency the packages do not declare)"
            bad=1
        fi
    done < <(readelf -d -W -- "$f" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
    if (( ! bad )); then
        if [[ -n "$max" ]]; then
            echo "ok    $f: highest glibc need GLIBC_$max (flags: ${weak:-none})"
        else
            echo "ok    $f: no glibc version need (static, or not linked against glibc)"
        fi
    fi
    return "$bad"
}

cmd_check() {
    EXTRA_LIBS=()
    while [[ $# -gt 0 && "$1" == --allow-lib ]]; do
        EXTRA_LIBS+=("${2:?--allow-lib needs a soname}"); shift 2
    done
    (( $# )) || die "usage: glibc-baseline.sh check [--allow-lib SONAME]... PATH..."
    need readelf "binutils"
    local p f n=0 bad=0
    for p in "$@"; do
        [[ -e "$p" ]] || die "$p: not found"
        while IFS= read -r -d '' f; do
            is_elf "$f" || continue
            n=$((n + 1))
            check_one "$f" || bad=1
        done < <(find "$p" -type f -print0 | sort -z)
    done
    (( n > 0 )) || die "no ELF file under $*"
    if (( bad )); then
        echo "glibc-baseline: FAIL — a shipped ELF file needs more than glibc $GLIBC_BASELINE (or an undeclared library); build it on the baseline (release.yml, package job)"
        return 1
    fi
    echo "glibc-baseline: $n ELF file(s), none needs more than glibc $GLIBC_BASELINE"
}

cmd_selftest() {
    need cc "a C compiler"
    need readelf "binutils"
    need rustc "the Rust toolchain"
    local gccld
    gccld="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld"
    [[ -x "$gccld/ld.lld" ]] || die "rust-lld not found under $gccld (rustup's toolchain ships it)"
    local d self
    self=$(readlink -f "$0")
    d=$(mktemp -d)
    trap 'rm -rf "$d"' RETURN
    # A library that defines a symbol at GLIBC_2.34 (the baseline), one at
    # GLIBC_2.35 (one above it) and one at GLIBC_2.39: the version names are
    # what the check reads, whatever library defines them.
    cat > "$d/v.map" <<'EOF'
GLIBC_2.34 { global: nn_ok; local: *; };
GLIBC_2.35 { global: nn_mid; } GLIBC_2.34;
GLIBC_2.39 { global: nn_new; } GLIBC_2.35;
EOF
    printf 'int nn_ok(void) { return 0; }\nint nn_mid(void) { return 0; }\nint nn_new(void) { return 1; }\n' > "$d/stub.c"
    cc -shared -fPIC -o "$d/libnnstub.so.1" -Wl,-soname,libnnstub.so.1 -Wl,--version-script="$d/v.map" "$d/stub.c"
    ln -s libnnstub.so.1 "$d/libnnstub.so"
    printf 'int nn_new(void);\nint main(void) { return nn_new(); }\n' > "$d/strong.c"
    printf 'int nn_new(void) __attribute__((weak));\nint main(void) { return nn_new ? nn_new() : 0; }\n' > "$d/weak.c"
    printf 'int nn_mid(void);\nint main(void) { return nn_mid(); }\n' > "$d/strong35.c"
    printf 'int nn_mid(void) __attribute__((weak));\nint main(void) { return nn_mid ? nn_mid() : 0; }\n' > "$d/weak35.c"
    printf 'int nn_ok(void);\nint main(void) { return nn_ok(); }\n' > "$d/ok.c"
    local p
    for p in strong weak strong35 weak35 ok; do
        mkdir "$d/$p"
        cc -B "$gccld" -fuse-ld=lld -Wl,--no-as-needed -o "$d/$p/$p" "$d/$p.c" -L"$d" -lnnstub
    done
    # The fixtures are what they claim: the weak one's need is flagged WEAK.
    readelf -V -W "$d/weak/weak" | grep -q 'Name: GLIBC_2.39 *Flags: WEAK' \
        || die "selftest: the weak fixture has no WEAK need of GLIBC_2.39 (linker?)"
    readelf -V -W "$d/strong/strong" | grep -q 'Name: GLIBC_2.39 *Flags: none' \
        || die "selftest: the strong fixture has no strong need of GLIBC_2.39"
    readelf -V -W "$d/weak35/weak35" | grep -q 'Name: GLIBC_2.35 *Flags: WEAK' \
        || die "selftest: the weak 2.35 fixture has no WEAK need of GLIBC_2.35 (linker?)"
    readelf -V -W "$d/strong35/strong35" | grep -q 'Name: GLIBC_2.35 *Flags: none' \
        || die "selftest: the strong 2.35 fixture has no strong need of GLIBC_2.35"
    readelf -V -W "$d/ok/ok" | grep -q 'Name: GLIBC_2.34 ' \
        || die "selftest: the accepted fixture has no need of GLIBC_2.34"
    local fail=0 out
    expect() {   # <want rc> <label> <args...>
        local want=$1 label=$2 rc=0; shift 2
        out=$(bash "$self" check "$@" 2>&1) || rc=$?
        if [[ "$rc" == "$want" ]]; then
            echo "selftest ok    $label (exit $rc)"
        else
            echo "selftest FAIL  $label: exit $rc, expected $want"; printf '%s\n' "$out"; fail=1
        fi
    }
    expect 1 "a strong need of GLIBC_2.39 is refused" --allow-lib libnnstub.so.1 "$d/strong"
    expect 1 "a weak need of GLIBC_2.39 is refused" --allow-lib libnnstub.so.1 "$d/weak"
    grep -q 'needs GLIBC_2.39 (flags: WEAK)' <<<"$out" || { echo "selftest FAIL  the weak need is not named WEAK"; fail=1; }
    expect 1 "a strong need of GLIBC_2.35 is refused" --allow-lib libnnstub.so.1 "$d/strong35"
    expect 1 "a weak need of GLIBC_2.35 is refused" --allow-lib libnnstub.so.1 "$d/weak35"
    grep -q 'needs GLIBC_2.35 (flags: WEAK)' <<<"$out" || { echo "selftest FAIL  the weak 2.35 need is not named WEAK"; fail=1; }
    expect 0 "a need of GLIBC_2.34 is accepted" --allow-lib libnnstub.so.1 "$d/ok"
    expect 1 "an undeclared shared library is refused" "$d/ok"
    expect 1 "one bad file among good ones fails the whole check" --allow-lib libnnstub.so.1 "$d/ok" "$d/weak"
    (( ! fail )) || { echo "glibc-baseline: selftest FAILED"; return 1; }
    echo "glibc-baseline: selftest passed"
}

case "${1:-}" in
    check) shift; cmd_check "$@" ;;
    selftest) shift; cmd_selftest "$@" ;;
    *) die "usage: glibc-baseline.sh check [--allow-lib SONAME]... PATH... | selftest" ;;
esac
