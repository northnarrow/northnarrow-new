#!/usr/bin/env bash
# Sign and verify the NorthNarrow .rpm (external audit DEP-008).
#
# An RPM signature is what dnf/yum (gpgcheck=1) and `rpm -K` check on the
# host, so a signed .rpm is authenticated before its scriptlets run. (A .deb
# has no per-package signature that dpkg or apt checks; its origin is
# checked with the release attestation, docs/operator/INSTALL_UPGRADE_UNINSTALL.md §6.1.)
#
#   sign-rpm.sh sign FPR RPM...       sign in place with the secret key FPR
#                                     from $GNUPGHOME (passphrase, if any, in
#                                     the file NN_RPM_GPG_PASSPHRASE_FILE)
#   sign-rpm.sh verify PUBKEY RPM...  exit 0 only if every RPM carries a valid
#                                     signature by PUBKEY and intact digests
#   sign-rpm.sh selftest RPM          on a copy, with throwaway keys: signed
#                                     accepted; unsigned, signed by another
#                                     key, and altered after signing refused
#
# The release workflow signs on a tag with the release key (rpm-sign job)
# and runs `selftest` on every run; the lab's pkg-check runs `selftest` on
# the rpm-based guests. Needs rpmsign, rpmkeys and gpg.
set -euo pipefail

die() { echo "sign-rpm: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found${2:+ ($2)}"; }

cmd_sign() {
    local fpr=${1:?usage: sign-rpm.sh sign FPR RPM...}; shift
    (( $# )) || die "usage: sign-rpm.sh sign FPR RPM..."
    need rpmsign "apt-get install rpm / dnf install rpm-sign"
    need gpg
    local gpg_bin; gpg_bin=$(command -v gpg)
    # Debian's rpm macros name /usr/bin/gpg2, which Ubuntu does not ship.
    local -a defs=(--define "_gpg_name $fpr" --define "__gpg $gpg_bin" --define "_gpg_digest_algo sha256")
    if [[ -n "${NN_RPM_GPG_PASSPHRASE_FILE:-}" ]]; then
        [[ -r "$NN_RPM_GPG_PASSPHRASE_FILE" ]] || die "NN_RPM_GPG_PASSPHRASE_FILE is not readable"
        defs+=(--define "_gpg_sign_cmd_extra_args --pinentry-mode loopback --passphrase-file $NN_RPM_GPG_PASSPHRASE_FILE")
    fi
    local rpm
    for rpm in "$@"; do
        [[ -f "$rpm" ]] || die "no such file: $rpm"
        GPG_TTY=${GPG_TTY:-/dev/null} rpmsign --addsign "${defs[@]}" "$rpm" >/dev/null || die "rpmsign failed for $rpm"
        echo "sign-rpm: signed $(basename "$rpm") with $fpr"
    done
}

cmd_verify() {
    local pub=${1:?usage: sign-rpm.sh verify PUBKEY RPM...}; shift
    (( $# )) || die "usage: sign-rpm.sh verify PUBKEY RPM..."
    need rpmkeys
    [[ -s "$pub" ]] || die "public key not found: $pub"
    # A database holding only this key: a key the host trusts for other
    # packages does not make a NorthNarrow package pass.
    local db rc=0 rpm out
    db=$(mktemp -d)
    rpmkeys --dbpath "$db" --import "$pub" || { rm -rf "$db"; die "cannot import $pub"; }
    for rpm in "$@"; do
        if [[ ! -f "$rpm" ]]; then
            echo "sign-rpm: REFUSED — no such file: $rpm" >&2; rc=1; continue
        fi
        # Unsigned prints "digests OK", a bad or unknown signature
        # "SIGNATURES NOT OK" (exit 1): only the full line passes.
        if out=$(rpmkeys --dbpath "$db" --checksig "$rpm" 2>&1) && [[ "$out" == *": digests signatures OK" ]]; then
            echo "sign-rpm: $(basename "$rpm"): digests signatures OK"
        else
            echo "sign-rpm: REFUSED — $(basename "$rpm"): no valid signature by $(basename "$pub") (rpmkeys: ${out##*: })" >&2
            rc=1
        fi
    done
    rm -rf "$db"
    return $rc
}

cmd_selftest() {
    local src=${1:?usage: sign-rpm.sh selftest RPM}
    [[ -f "$src" ]] || die "no such file: $src"
    need gpg
    local work fail=0 fpr_a fpr_b
    work=$(mktemp -d)
    export GNUPGHOME="$work/gnupg"
    mkdir -m 0700 "$GNUPGHOME"
    # shellcheck disable=SC2064
    trap "gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf '$work'" EXIT
    for k in a b; do
        gpg --batch --quiet --passphrase '' --quick-gen-key "sign-rpm selftest $k <selftest-$k@invalid>" rsa3072 sign 1d 2>/dev/null \
            || die "gpg could not create a throwaway key"
    done
    fpr_a=$(gpg --batch --with-colons --list-secret-keys "selftest-a@invalid" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')
    fpr_b=$(gpg --batch --with-colons --list-secret-keys "selftest-b@invalid" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')
    gpg --batch --armor --export "$fpr_a" > "$work/a.asc"
    local name; name=$(basename "$src")
    mkdir "$work/unsigned" "$work/signed" "$work/other" "$work/altered"
    cp "$src" "$work/unsigned/$name"
    expect() { # expect ok|refused WHAT RPM
        local want=$1 what=$2 rpm=$3 got
        if cmd_verify "$work/a.asc" "$rpm" >/dev/null 2>&1; then got=ok; else got=refused; fi
        if [[ $got == "$want" ]]; then echo "sign-rpm: selftest ok    $what: $got"; else echo "sign-rpm: selftest FAIL  $what: $got (expected $want)" >&2; fail=1; fi
    }
    expect refused "unsigned package" "$work/unsigned/$name"
    cp "$src" "$work/signed/$name" && cmd_sign "$fpr_a" "$work/signed/$name" >/dev/null
    expect ok "package signed by the expected key" "$work/signed/$name"
    cp "$src" "$work/other/$name" && cmd_sign "$fpr_b" "$work/other/$name" >/dev/null
    expect refused "package signed by another key" "$work/other/$name"
    # one byte of the payload (the end of the file) changed after signing
    cp "$work/signed/$name" "$work/altered/$name"
    local size; size=$(stat -c %s "$work/altered/$name")
    printf '\xff' | dd of="$work/altered/$name" bs=1 seek=$((size - 64)) conv=notrunc status=none
    cmp -s "$work/signed/$name" "$work/altered/$name" && { printf '\x00' | dd of="$work/altered/$name" bs=1 seek=$((size - 64)) conv=notrunc status=none; }
    expect refused "signed package altered after signing" "$work/altered/$name"
    (( fail == 0 )) || die "selftest failed"
    echo "sign-rpm: selftest passed"
}

case "${1:-}" in
    sign) shift; cmd_sign "$@" ;;
    verify) shift; cmd_verify "$@" ;;
    selftest) shift; cmd_selftest "$@" ;;
    *) echo "usage: sign-rpm.sh sign FPR RPM... | verify PUBKEY RPM... | selftest RPM" >&2; exit 2 ;;
esac
