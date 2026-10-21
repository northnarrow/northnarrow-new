#!/usr/bin/env bash
# Self-test of deploy/lab/lib/verify-download.sh (external audit LAB-009):
# no network, no VM. Two throwaway GnuPG keys stand for the vendor's
# (pinned) key and a foreign one; a directory stands for the mirrors
# (nnv_fetch is replaced by a copy from it).
#   bash deploy/lab/lib/verify-download-test.sh      → exit 0 when every case holds
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/lab/lib/verify-download.sh
source "$HERE/verify-download.sh"

W=$(mktemp -d)
GH="$W/gnupg"
mkdir -m 0700 "$GH"
cleanup() { gpgconf --homedir "$GH" --kill all >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT

pass=0 fail=0
ok() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "ok    $what"; pass=$((pass + 1)); else echo "FAIL  $what"; fail=$((fail + 1)); fi; }
no() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "FAIL  $what (accepted)"; fail=$((fail + 1)); else echo "ok    $what (refused)"; pass=$((pass + 1)); fi; }
flip() { printf '\x01' | dd of="$1" bs=1 seek="${2:-100}" conv=notrunc status=none; }

g() { gpg --homedir "$GH" --batch --quiet --pinentry-mode loopback --passphrase '' "$@"; }
keygen() {
    g --quick-gen-key "$1 <$1@nn-lab.invalid>" ed25519 sign never 2>/dev/null
    g --with-colons --fingerprint "$1@nn-lab.invalid" | awk -F: '$1 == "fpr" { print $10; exit }'
}
A=$(keygen vendor)
B=$(keygen foreign)
[[ ${#A} == 40 && ${#B} == 40 ]] || { echo "could not create the test keys"; exit 1; }
g --armor --export "$A" > "$W/A.asc"
g --armor --export "$B" > "$W/B.asc"
cat "$W/A.asc" "$W/B.asc" > "$W/AB.asc"
g --export "$A" "$B" > "$W/ring-AB.gpg"
sign() { rm -f "$2.sig"; g --local-user "$1" --detach-sign ${3:+--armor} -o "$2.sig" "$2"; }

echo "== signatures (nnv_check_sig)"
printf 'aaaa  one\n' > "$W/list"
sign "$A" "$W/list"
ok "good signature by the pinned key" nnv_check_sig "$W/ring-AB.gpg" "$A" "$W/list.sig" "$W/list"
cp "$W/list" "$W/list.mod" && printf 'x' >> "$W/list.mod"
no "list changed after signing" nnv_check_sig "$W/ring-AB.gpg" "$A" "$W/list.sig" "$W/list.mod"
no "signature valid but pinned fingerprint is another key" nnv_check_sig "$W/ring-AB.gpg" "$B" "$W/list.sig" "$W/list"
sign "$B" "$W/list"
no "signature by a foreign key that sits in the keyring" nnv_check_sig "$W/ring-AB.gpg" "$A" "$W/list.sig" "$W/list"
sign "$A" "$W/list" armor
ok "armored detached signature (AlmaLinux CHECKSUM.asc)" nnv_check_sig "$W/ring-AB.gpg" "$A" "$W/list.sig" "$W/list"
# gpgv exits 0 with VALIDSIG for a key that has expired since (EXPKEYSIG):
# only GOODSIG says the key is still good.
g --faked-system-time '20200101T000000!' --quick-gen-key 'expired <expired@nn-lab.invalid>' ed25519 sign 1d 2>/dev/null
E=$(g --with-colons --fingerprint expired@nn-lab.invalid | awk -F: '$1 == "fpr" { print $10; exit }')
g --export "$E" > "$W/ring-E.gpg"
rm -f "$W/list.sig"
g --faked-system-time '20200101T120000!' --local-user "$E" --detach-sign -o "$W/list.sig" "$W/list" 2>/dev/null
no "signature by the pinned key, which has expired since" nnv_check_sig "$W/ring-E.gpg" "$E" "$W/list.sig" "$W/list"

echo "== pinned key import (nnv_keyring_import)"
ok "key whose primary fingerprint is the pinned one" nnv_keyring_import "$W/A.asc" "$A" "$W/ring-A.gpg"
no "another key served for the pinned fingerprint" nnv_keyring_import "$W/B.asc" "$A" "$W/ring-x.gpg"
no "  and no keyring is left behind" test -e "$W/ring-x.gpg"
ok "a file with two keys: the pinned one only is kept" nnv_keyring_import "$W/AB.asc" "$A" "$W/ring-1.gpg"
sign "$B" "$W/list"
no "  the other key does not verify through that keyring" nnv_check_sig "$W/ring-1.gpg" "$B" "$W/list.sig" "$W/list"

echo "== lists (nnv_sum_for_name, nnv_names_for_digest)"
h1=$(printf 'image-1' | sha256sum | cut -d' ' -f1)
h2=$(printf 'image-2' | sha256sum | cut -d' ' -f1)
{
    printf '%s *noble-server-cloudimg-amd64.img\n' "$h1"
    printf '%s  x-noble-server-cloudimg-amd64.img\n' "$h2"
    printf '%s  dup.img\n%s  dup.img\n' "$h1" "$h2"
    printf 'SHA256 (AlmaLinux-9-GenericCloud-latest.x86_64.qcow2) = %s\n' "$(tr 'a-f' 'A-F' <<<"$h2")"
    printf '%s  crlf.img\r\n' "$h1"
    printf '# AlmaLinux-9-GenericCloud-latest.x86_64.qcow2: 1 bytes\n'
} > "$W/SUMS"
ok "GNU binary-mode entry" test "$(nnv_sum_for_name "$W/SUMS" noble-server-cloudimg-amd64.img)" = "$h1"
ok "BSD entry, upper-case digest" test "$(nnv_sum_for_name "$W/SUMS" AlmaLinux-9-GenericCloud-latest.x86_64.qcow2)" = "$h2"
ok "CRLF line" test "$(nnv_sum_for_name "$W/SUMS" crlf.img)" = "$h1"
no "a name listed twice" nnv_sum_for_name "$W/SUMS" dup.img
no "a name not listed" nnv_sum_for_name "$W/SUMS" missing.img
no "a suffix of a listed name" nnv_sum_for_name "$W/SUMS" server-cloudimg-amd64.img
no "a regex that would match a listed name" nnv_sum_for_name "$W/SUMS" 'noble.server-cloudimg-amd64.img'
nnv_meta debian12 https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
printf '%s  debian-12-genericcloud-amd64-20261006-2623.qcow2\n%s  debian-12-genericcloud-amd64-20261006-2623.raw\n' "$h1" "$h1" > "$W/SUMS.deb"
ok "dated Debian build found by digest" test "$(nnv_names_for_digest "$W/SUMS.deb" "$h1" "$NNV_NAME_RE")" = debian-12-genericcloud-amd64-20261006-2623.qcow2
no "digest listed only under another image type" nnv_names_for_digest "$W/SUMS.deb" "$h2" "$NNV_NAME_RE"
nnv_meta debian13 https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
ok "debian13: unsigned SHA512SUMS, history under trixie/" test "$NNV_SUMS $NNV_ALGO ${NNV_SIG:-unsigned} $NNV_HISTORY_BASE" = "SHA512SUMS sha512 unsigned https://cloud.debian.org/images/cloud/trixie/"
ok "debian13: current and dated build names" grep -qE "$NNV_NAME_RE" <<<"debian-13-genericcloud-amd64-20261015-2632.qcow2"
no "debian13: a Debian 12 image is another image" grep -qE "$NNV_NAME_RE" <<<"debian-12-genericcloud-amd64.qcow2"
no "debian13: the name pattern is literal" grep -qE "$NNV_NAME_RE" <<<"debian-13-genericcloud-amd64Xqcow2"

echo "== per-distribution settings (nnv_meta)"
nnv_meta ubuntu2404 https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
ok "ubuntu: signed SHA256SUMS, pinned UEC key, history under noble/" test "$NNV_SUMS $NNV_SIG $NNV_FPR $NNV_HISTORY_BASE" = "SHA256SUMS SHA256SUMS.gpg D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81 https://cloud-images.ubuntu.com/noble/"
ok "ubuntu: name pattern matches the image" grep -qE "$NNV_NAME_RE" <<<"noble-server-cloudimg-amd64.img"
no "ubuntu: name pattern is anchored and literal" grep -qE "$NNV_NAME_RE" <<<"nobleXserver-cloudimg-amd64.img.bad"
nnv_meta alma9 https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2
ok "alma: signed CHECKSUM, pinned AlmaLinux 9 key" test "$NNV_SUMS $NNV_SIG $NNV_FPR" = "CHECKSUM CHECKSUM.asc BF18AC2876178908D6E71267D36CB86CB86B3716"
ok "alma: dated build name" grep -qE "$NNV_NAME_RE" <<<"AlmaLinux-9-GenericCloud-9.8-20261005.x86_64.qcow2"
no "alma: the ext4 variant is another image" grep -qE "$NNV_NAME_RE" <<<"AlmaLinux-9-GenericCloud-ext4-latest.x86_64.qcow2"
no "an unknown distribution" nnv_meta gentoo https://example.invalid/x.img

echo "== image digest and record (nnv_verify_listed, nnv_record_*)"
head -c 300000 /dev/urandom > "$W/img"
printf '%s  img\n' "$(sha256sum < "$W/img" | cut -d' ' -f1)" > "$W/SUMS.img"
ok "image matches the list" nnv_verify_listed "$W/img" "$W/SUMS.img" img sha256
cp "$W/img" "$W/img.mod" && flip "$W/img.mod"
no "one byte changed" nnv_verify_listed "$W/img.mod" "$W/SUMS.img" img sha256
nnv_record_write "$W/img.verified" "$W/img" sha256 "$(nnv_digest sha256 "$W/img")" src list "$A"
ok "record check" nnv_record_check "$W/img.verified" "$W/img"
no "record check, one byte changed" nnv_record_check "$W/img.verified" "$W/img.mod"
printf 'file=img\n' > "$W/bad.verified"
no "record without a digest" nnv_record_check "$W/bad.verified" "$W/img"

echo "== nn-lab glue against a fake mirror (lab_fetch_image, lab_check_image, cmd_verify_image)"
SRV="$W/srv"
nnv_fetch() {
    local p=${1#https://}
    [[ $p == */ ]] && p+=index
    [[ -f "$SRV/$p" ]] || return 22
    cp -- "$SRV/$p" "$2"
}
log() { printf 'nn-lab: %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
ROOT_LAB_DIR="$W/lab" ACCEL=kvm
publish() {  # DIR FILE…: a list of FILEs signed by $SIGNER in mirror DIR
    local dir=$1 f
    shift
    mkdir -p "$SRV/$dir"
    : > "$SRV/$dir/$NNV_SUMS"
    for f in "$@"; do printf '%s *%s\n' "$(nnv_digest "$NNV_ALGO" "$SRV/$dir/$f")" "$f" >> "$SRV/$dir/$NNV_SUMS"; done
    if [[ -n $NNV_SIG ]]; then rm -f "$SRV/$dir/$NNV_SIG"; sign "$SIGNER" "$SRV/$dir/$NNV_SUMS" armor && mv "$SRV/$dir/$NNV_SUMS.sig" "$SRV/$dir/$NNV_SIG"; fi
}
setup_alma() {
    rm -rf "$SRV" "$ROOT_LAB_DIR"
    NNV_ALMALINUX9_FPR=$A DISTRO=alma9 BASE_IMG_NAME=alma9-base.qcow2
    IMAGE_URL=https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2
    LAB_DIR="$ROOT_LAB_DIR/alma9" BASE_IMG="$ROOT_LAB_DIR/alma9/alma9-base.qcow2"
    nnv_meta "$DISTRO" "$IMAGE_URL"
    mkdir -p "$SRV/repo.almalinux.org/almalinux/9/cloud/x86_64/images"
    cp "$W/A.asc" "$SRV/repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9"
    cp "$W/img" "$SRV/${IMAGE_URL#https://}"
    SIGNER=$A publish repo.almalinux.org/almalinux/9/cloud/x86_64/images AlmaLinux-9-GenericCloud-latest.x86_64.qcow2
}
# die() exits: each call runs in a subshell.
fetch() { (lab_fetch_image "$BASE_IMG"); }
check() { (lab_check_image "$BASE_IMG"); }
verify() { (cmd_verify_image); }
check_win() { (lab_check_image "$W/win/noble-base.img"); }
setup_alma
ok "signed list, image as listed: downloaded" fetch
ok "  image in place" cmp -s "$BASE_IMG" "$W/img"
ok "  record names the signer" grep -qx "signed_by=$A" "$LAB_DIR/alma9-base.qcow2.verified"
ok "  a new guest may be layered on it" check
flip "$BASE_IMG"
no "one byte changed in the cached image: up refuses a new guest on it" check
setup_alma
flip "$SRV/${IMAGE_URL#https://}"
no "image served differs from the signed list" fetch
no "  nothing kept (no image, no .part)" test -e "$BASE_IMG" -o -e "$BASE_IMG.part"
setup_alma
SIGNER=$B publish repo.almalinux.org/almalinux/9/cloud/x86_64/images AlmaLinux-9-GenericCloud-latest.x86_64.qcow2
no "list signed by another key" fetch
setup_alma
cp "$W/B.asc" "$SRV/repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9"
no "key server answers with another key" fetch
no "  no keyring cached" test -e "$ROOT_LAB_DIR/keys/almalinux-9.gpg"
setup_alma
rm "$SRV/repo.almalinux.org/almalinux/9/cloud/x86_64/images/CHECKSUM.asc"
no "signature missing" fetch
setup_alma
ok "the good case again, in this shell" fetch

# Debian: no signature is published; the list is taken over HTTPS.
rm -rf "$SRV" "$ROOT_LAB_DIR"
DISTRO=debian12 BASE_IMG_NAME=bookworm-base.qcow2 LAB_DIR="$ROOT_LAB_DIR/debian12"
BASE_IMG="$LAB_DIR/bookworm-base.qcow2"
IMAGE_URL=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
nnv_meta "$DISTRO" "$IMAGE_URL"
mkdir -p "$SRV/cloud.debian.org/images/cloud/bookworm/latest"
cp "$W/img" "$SRV/${IMAGE_URL#https://}"
publish cloud.debian.org/images/cloud/bookworm/latest debian-12-genericcloud-amd64.qcow2
ok "debian: unsigned list over HTTPS, image as listed" fetch
ok "  record says unsigned" grep -qx "signed_by=unsigned" "$LAB_DIR/bookworm-base.qcow2.verified"

# verify-image: an image downloaded before these checks (no record).
rm -rf "$SRV" "$ROOT_LAB_DIR"
NNV_UBUNTU_CLOUD_FPR=$A DISTRO=ubuntu2404 BASE_IMG_NAME=noble-base.img LAB_DIR="$ROOT_LAB_DIR"
BASE_IMG="$LAB_DIR/noble-base.img"
IMAGE_URL=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
nnv_meta "$DISTRO" "$IMAGE_URL"
n=cloud-images.ubuntu.com/noble
mkdir -p "$SRV/$n/current" "$SRV/$n/20260911" "$SRV/$n/20260926" "$SRV/keyserver.ubuntu.com/pks"
cp "$W/A.asc" "$SRV/${NNV_KEY_URL#https://}"
printf '<a href="20260911/">20260911/</a> <a href="20260926/">x</a> <a href="current/">current/</a> <a href="/">up</a>\n' > "$SRV/$n/index"
head -c 200000 /dev/urandom > "$SRV/$n/current/noble-server-cloudimg-amd64.img"
cp "$W/img" "$SRV/$n/20260911/noble-server-cloudimg-amd64.img"
head -c 200000 /dev/urandom > "$SRV/$n/20260926/noble-server-cloudimg-amd64.img"
for d in current 20260911 20260926; do SIGNER=$A publish "$n/$d" noble-server-cloudimg-amd64.img; done
mkdir -p "$LAB_DIR" && cp "$W/img" "$BASE_IMG"
ok "verify-image: an older build still published" verify
ok "  recorded as that build" grep -q "^source=https://$n/20260911/noble-server-cloudimg-amd64.img$" "$LAB_DIR/noble-base.img.verified"
ok "  and checked against the record next time" verify
flip "$BASE_IMG"
no "  one byte changed since: refused" verify
rm -f "$LAB_DIR/noble-base.img.verified"
no "an image in none of the published lists" verify
no "  no record written" test -e "$LAB_DIR/noble-base.img.verified"
SIGNER=$B publish "$n/20260911" noble-server-cloudimg-amd64.img
cp "$SRV/$n/20260911/noble-server-cloudimg-amd64.img" "$BASE_IMG"
no "an older build whose list is signed by another key" verify
rm -f "$BASE_IMG"
no "no image present: nothing to verify" verify

# WHPX: QEMU for Windows runs on its own copy, which carries its own record.
ACCEL=whpx
whpx_dir() { printf '%s\n' "$W/win"; }
SIGNER=$A publish "$n/20260911" noble-server-cloudimg-amd64.img
mkdir -p "$W/win"
cp "$W/img" "$BASE_IMG"
cp "$W/img" "$W/win/noble-base.img"
ok "whpx: both copies verified" verify
ok "  each with its record" test -f "$BASE_IMG.verified" -a -f "$W/win/noble-base.img.verified"
ok "  the nightly names the copy in use" grep -q '^noble-base.img sha256:' <<<"$(lab_image_summary)"
flip "$W/win/noble-base.img"
no "  the Windows copy changed: refused" verify
no "  and no new guest is layered on it" check_win
ACCEL=kvm

# CI glue (lab PR 227): the workflow keys its image cache by image-info's
# digest and checks a restored image with fetch-image. The mirror above:
# current/ lists a random image, 20260911/ lists $W/img.
echo "== CI glue (image-info, fetch-image)"
info() { (cmd_image_info); }
fetchi() { (cmd_fetch_image); }
cur_img="$SRV/$n/current/noble-server-cloudimg-amd64.img"
cur=$(nnv_digest sha256 "$cur_img")
rm -f "$BASE_IMG" "$BASE_IMG.verified"
ok "image-info: the digest the current signed list gives" grep -qx "digest=$cur" <<<"$(info 2>/dev/null)"
ok "  the KVM image's path and the guest's directory" grep -qx "path=$BASE_IMG" <<<"$(info 2>/dev/null)"
ok "  (lab_dir)" grep -qx "lab_dir=$LAB_DIR" <<<"$(info 2>/dev/null)"
no "  no image downloaded" test -e "$BASE_IMG"
CI_MODE=1
cp "$cur_img" "$BASE_IMG"
ok "ci fetch-image: a restored image that is the current one is kept" fetchi
ok "  and recorded against the list" grep -qx "sha256=$cur" "$BASE_IMG.verified"
ok "  prints the digest the cache key was made of" grep -qx "digest=$cur" <<<"$(fetchi 2>/dev/null)"
cp "$W/img" "$BASE_IMG"
rm -f "$BASE_IMG.verified"
ok "ci fetch-image: a restored older build (still published) is replaced" fetchi
ok "  by the current image" cmp -s "$BASE_IMG" "$cur_img"
flip "$BASE_IMG"
ok "ci fetch-image: a restored image changed by one byte, record and all, is replaced" fetchi
ok "  by the current image" cmp -s "$BASE_IMG" "$cur_img"
SIGNER=$B publish "$n/current" noble-server-cloudimg-amd64.img
no "ci fetch-image: the current list signed by another key" fetchi
no "ci image-info: the same list" info
SIGNER=$A publish "$n/current" noble-server-cloudimg-amd64.img
rm -f "$BASE_IMG" "$BASE_IMG.verified"
ok "ci fetch-image: no image: downloaded against the list" fetchi
ok "  the current image" cmp -s "$BASE_IMG" "$cur_img"
CI_MODE=0
cp "$W/img" "$BASE_IMG"
rm -f "$BASE_IMG.verified"
ok "lab fetch-image: an older build still published is verified" fetchi
ok "  and kept (the lab's guests are layered on it)" cmp -s "$BASE_IMG" "$W/img"
head -c 1000 /dev/urandom > "$BASE_IMG"
rm -f "$BASE_IMG.verified"
no "lab fetch-image: an image in no published list" fetchi
ok "  is not deleted" test -s "$BASE_IMG"
unset CI_MODE

echo
echo "verify-download self-test: $pass passed, $fail failed"
((fail == 0))
