# shellcheck shell=bash
# Download verification for the lab's base images (external audit LAB-009,
# NN-AUD-214). Sourced by deploy/lab/nn-lab.sh and by
# deploy/lab/lib/verify-download-test.sh; it runs nothing on its own.
#
# Trust model:
#   - Ubuntu and AlmaLinux sign their image lists (SHA256SUMS +
#     SHA256SUMS.gpg, CHECKSUM + CHECKSUM.asc). The signing keys are pinned
#     below by primary fingerprint. A key fetched from the network is kept
#     only when its primary fingerprint is the pinned one, and a list counts
#     only when gpgv reports a GOOD signature whose primary key is the
#     pinned one (a key added to the cached keyring proves nothing).
#   - Debian publishes no signature for its current cloud images (bookworm
#     and trixie alike): its SHA512SUMS is fetched over HTTPS from
#     cloud.debian.org (Debian's documented method, TLS + DNSSEC) and the
#     record says "unsigned".
#   - The image itself is checked against the list before it gets its
#     final name, and its digest is recorded next to it (<image>.verified).
#     A new guest disk is only layered on an image whose digest still
#     matches that record.
#   - An image downloaded before these checks is neither deleted nor
#     downloaded again (guests are layered on it): `nn-lab.sh verify-image`
#     looks for its digest in the lists the vendor still publishes and
#     records it when found.

# UEC Image Automatic Signing Key <cdimage@ubuntu.com>: Ubuntu cloud images.
NNV_UBUNTU_CLOUD_FPR=D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81
# AlmaLinux OS 9 <packager@almalinux.org>: AlmaLinux 9 packages and images.
NNV_ALMALINUX9_FPR=BF18AC2876178908D6E71267D36CB86CB86B3716

nnv_err() { printf 'nn-lab: %s\n' "$*" >&2; }

nnv_require_tools() {
    local t missing=()
    for t in curl gpg gpgv sha256sum sha512sum mktemp; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    ((${#missing[@]} == 0)) && return 0
    nnv_err "missing on host: ${missing[*]} (needed to verify downloads) — sudo apt install curl gnupg gpgv coreutils"
    return 1
}

# nnv_meta DISTRO IMAGE_URL: how this distribution publishes its image
# list. Sets NNV_SUMS, NNV_SIG (empty: unsigned), NNV_ALGO, NNV_KEY,
# NNV_FPR, NNV_KEY_URL, NNV_NAME_RE (names the image is published under,
# current and dated builds), NNV_HISTORY_BASE and NNV_HISTORY_RE (the
# dated build directories still published; empty: none).
nnv_meta() {
    local distro=$1 url=$2 name
    name=${url##*/}
    NNV_SIG="" NNV_KEY="" NNV_FPR="" NNV_KEY_URL="" NNV_HISTORY_BASE="" NNV_HISTORY_RE=""
    case "$distro" in
        ubuntu2404 | ubuntu2204)
            NNV_SUMS=SHA256SUMS NNV_SIG=SHA256SUMS.gpg NNV_ALGO=sha256
            NNV_KEY=ubuntu-cloud NNV_FPR=$NNV_UBUNTU_CLOUD_FPR
            NNV_KEY_URL="https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$NNV_UBUNTU_CLOUD_FPR"
            NNV_NAME_RE="^${name//./\\.}\$"
            NNV_HISTORY_BASE="${url%/current/*}/"
            NNV_HISTORY_RE='^[0-9]{8}(\.[0-9]+)?/$' ;;
        debian12 | debian13)
            NNV_SUMS=SHA512SUMS NNV_ALGO=sha512
            NNV_NAME_RE="^debian-${distro#debian}-genericcloud-amd64(-[0-9]{8}-[0-9]+)?\\.qcow2\$"
            NNV_HISTORY_BASE="${url%/latest/*}/"
            NNV_HISTORY_RE='^[0-9]{8}-[0-9]+/$' ;;
        alma9)
            # CHECKSUM lists the dated builds still on the mirror too.
            NNV_SUMS=CHECKSUM NNV_SIG=CHECKSUM.asc NNV_ALGO=sha256
            NNV_KEY=almalinux-9 NNV_FPR=$NNV_ALMALINUX9_FPR
            NNV_KEY_URL=https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9
            NNV_NAME_RE='^AlmaLinux-9-GenericCloud-(latest|9\.[0-9]+-[0-9]{8})\.x86_64\.qcow2$' ;;
        *) nnv_err "no download verification defined for $distro"; return 1 ;;
    esac
}

# nnv_fetch URL OUT [curl options…]: HTTPS only (redirects included),
# TLS 1.2 or newer.
nnv_fetch() {
    local url=$1 out=$2
    shift 2
    curl -fL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 2 "$@" -o "$out" "$url"
}

# nnv_digest ALGO FILE: the hex digest of FILE.
nnv_digest() {
    local out
    case "$1" in sha256 | sha512) ;; *) nnv_err "unknown digest $1"; return 1 ;; esac
    out=$("$1sum" < "$2") || return 1
    printf '%s\n' "${out%% *}"
}

# nnv_keyring_import ASC FPR RING: write RING with the key from ASC, only
# if ASC holds a key whose primary fingerprint is FPR (nothing else is
# exported).
nnv_keyring_import() {
    local asc=$1 fpr=$2 ring=$3 home listing got=""
    home=$(mktemp -d) || return 1
    if gpg --homedir "$home" --batch --quiet --import "$asc" >/dev/null 2>&1 &&
        listing=$(gpg --homedir "$home" --batch --with-colons --fingerprint "$fpr" 2>/dev/null); then
        got=$(awk -F: '$1 == "fpr" { print $10; exit }' <<<"$listing")
    fi
    if [[ $got == "$fpr" ]] && gpg --homedir "$home" --batch --export "$fpr" > "$ring.part" 2>/dev/null && [[ -s $ring.part ]]; then
        mv -f "$ring.part" "$ring"
        rm -rf "$home"
        return 0
    fi
    rm -f "$ring.part"
    rm -rf "$home"
    nnv_err "${asc##*/}: no key with the pinned primary fingerprint $fpr"
    return 1
}

# nnv_keyring NAME FPR URL DIR: prints DIR/NAME.gpg, fetched from URL and
# checked against FPR the first time.
nnv_keyring() {
    local name=$1 fpr=$2 url=$3 dir=$4 ring tmp rc=0
    ring="$dir/$name.gpg"
    if [[ ! -s $ring ]]; then
        mkdir -p "$dir" && chmod 0700 "$dir" || return 1
        tmp=$(mktemp -d) || return 1
        { nnv_fetch "$url" "$tmp/key.asc" -sS && nnv_keyring_import "$tmp/key.asc" "$fpr" "$ring"; } || rc=1
        rm -rf "$tmp"
        ((rc == 0)) || return 1
    fi
    printf '%s\n' "$ring"
}

# nnv_check_sig RING FPR SIG DATA: SIG is a GOOD signature over DATA whose
# primary key is FPR (VALIDSIG's last field).
nnv_check_sig() {
    local status
    status=$(gpgv --status-fd 1 --keyring "$1" "$3" "$4" 2>/dev/null) || return 1
    grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status" || return 1
    awk -v f="$2" '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && toupper($NF) == f { ok = 1 } END { exit !ok }' <<<"$status"
}

# Both list formats: GNU "<hex>  name" / "<hex> *name" and BSD
# "SHA256 (name) = <hex>". Prints "<lowercase hex> <name>" per entry.
nnv_entries() {
    awk '
        { sub(/\r$/, ""); f = ""; h = "" }
        /^[0-9A-Fa-f]+ [ *][^ ]/ { h = $1; f = substr($0, length($1) + 3) }
        /^[A-Z0-9-]+ \(.+\) = [0-9A-Fa-f]+$/ {
            h = $NF; f = $0
            sub(/^[A-Z0-9-]+ \(/, "", f); sub(/\) = [0-9A-Fa-f]+$/, "", f)
        }
        f != "" { print tolower(h), f }' "$1"
}

# nnv_sum_for_name SUMS NAME: the digest listed for exactly NAME; fails
# unless exactly one entry names it.
nnv_sum_for_name() {
    [[ -n $2 ]] || return 1
    nnv_entries "$1" | awk -v n="$2" '
        { f = substr($0, index($0, " ") + 1) }
        f == n { d = $1; c++ }
        END { if (c != 1) exit 1; print d }'
}

# nnv_names_for_digest SUMS DIGEST NAME_RE: the names listed with DIGEST
# that match NAME_RE (ERE); fails when there is none.
nnv_names_for_digest() {
    local names
    names=$(nnv_entries "$1" | awk -v d="$2" 'BEGIN { d = tolower(d) } $1 == d { print substr($0, index($0, " ") + 1) }' |
        grep -E -- "$3") || return 1
    printf '%s\n' "$names"
}

# nnv_verify_listed FILE SUMS NAME ALGO: FILE's digest is the one SUMS
# lists for NAME. Prints the digest.
nnv_verify_listed() {
    local want got
    want=$(nnv_sum_for_name "$2" "$3") || { nnv_err "$3: not listed exactly once in ${2##*/}"; return 1; }
    got=$(nnv_digest "$4" "$1") || return 1
    [[ $got == "$want" ]] || { nnv_err "$3: $4 $got is not the listed $want"; return 1; }
    printf '%s\n' "$got"
}

# nnv_record_write RECORD FILE ALGO DIGEST SOURCE LISTED_IN SIGNED_BY
nnv_record_write() {
    {
        printf 'file=%s\n' "${2##*/}"
        printf '%s=%s\n' "$3" "$4"
        printf 'source=%s\n' "$5"
        printf 'listed_in=%s\n' "$6"
        printf 'signed_by=%s\n' "$7"
        printf 'verified_at=%s\n' "$(date -u +%FT%TZ)"
    } > "$1.part" && mv -f "$1.part" "$1"
}

nnv_record_field() { awk -F= -v k="$2" '$1 == k { print substr($0, length(k) + 2); exit }' "$1"; }

# nnv_record_check RECORD FILE: FILE's digest is the recorded one.
nnv_record_check() {
    local algo want got
    algo=$(awk -F= '$1 == "sha256" || $1 == "sha512" { print $1; exit }' "$1")
    [[ -n $algo ]] && want=$(nnv_record_field "$1" "$algo")
    [[ -n ${want:-} ]] || { nnv_err "unreadable record $1"; return 1; }
    got=$(nnv_digest "$algo" "$2") || return 1
    [[ $got == "$want" ]] || { nnv_err "${2##*/}: $algo $got is not the recorded $want ($1)"; return 1; }
}

# nnv_history BASE RE MAX: the build directories listed in BASE's index
# that match RE, newest first, at most MAX.
nnv_history() {
    local idx dirs
    idx=$(mktemp) || return 1
    if ! nnv_fetch "$1" "$idx" -sS; then rm -f "$idx"; return 1; fi
    dirs=$(grep -oE 'href="[^"/]+/"' "$idx" | sed 's/^href="//; s/"$//' | grep -E -- "$2" | sort -ru | sed -n "1,${3}p") || true
    rm -f "$idx"
    printf '%s' "$dirs${dirs:+$'\n'}"
}

# ── nn-lab.sh glue: uses its DISTRO, IMAGE_URL, BASE_IMG, BASE_IMG_NAME,
# LAB_DIR, ROOT_LAB_DIR, ACCEL, CI_MODE, log, die and whpx_dir ────────────

# The record of an image lives next to it (WHPX keeps its own copy).
lab_image_record() { printf '%s.verified\n' "$1"; }
lab_image_in_use() { if [[ $ACCEL == whpx ]]; then printf '%s/%s\n' "$(whpx_dir)" "$BASE_IMG_NAME"; else printf '%s\n' "$BASE_IMG"; fi; }
lab_signer_text() { if [[ $1 == unsigned ]]; then echo "list unsigned (HTTPS only)"; else echo "list signed by $1"; fi; }

# lab_fetch_list DIR_URL TMP: the vendor's list for one build directory in
# TMP, its signature checked. Prints the signer ("unsigned" for Debian).
lab_fetch_list() {
    local dir=${1%/} tmp=$2 ring
    nnv_fetch "$dir/$NNV_SUMS" "$tmp/$NNV_SUMS" -sS || return 1
    if [[ -z $NNV_SIG ]]; then
        echo unsigned
        return 0
    fi
    nnv_fetch "$dir/$NNV_SIG" "$tmp/$NNV_SIG" -sS || return 1
    ring=$(nnv_keyring "$NNV_KEY" "$NNV_FPR" "$NNV_KEY_URL" "$ROOT_LAB_DIR/keys") || return 1
    nnv_check_sig "$ring" "$NNV_FPR" "$tmp/$NNV_SIG" "$tmp/$NNV_SUMS" ||
        { nnv_err "$dir/$NNV_SIG: no good signature by $NNV_FPR"; return 1; }
    echo "$NNV_FPR"
}

_lab_fetch_image() {
    local dest=$1 tmp=$2 name=${IMAGE_URL##*/} signer digest
    signer=$(lab_fetch_list "${IMAGE_URL%/*}" "$tmp") || return 1
    [[ $signer == unsigned ]] &&
        log "WARNING: $DISTRO publishes no signature for its cloud images: $NNV_SUMS is trusted over HTTPS only"
    nnv_sum_for_name "$tmp/$NNV_SUMS" "$name" >/dev/null ||
        { nnv_err "$name is not listed exactly once in ${IMAGE_URL%/*}/$NNV_SUMS"; return 1; }
    log "downloading $IMAGE_URL"
    # CI mode (lab PR 227): no progress bar in a job log
    local progress=--progress-bar
    if [[ ${CI_MODE:-0} == 1 ]]; then progress=-sS; fi
    nnv_fetch "$IMAGE_URL" "$dest.part" "$progress" || return 1
    digest=$(nnv_verify_listed "$dest.part" "$tmp/$NNV_SUMS" "$name" "$NNV_ALGO") || return 1
    mv -f "$dest.part" "$dest" || return 1
    nnv_record_write "$(lab_image_record "$dest")" "$dest" "$NNV_ALGO" "$digest" "$IMAGE_URL" \
        "${IMAGE_URL%/*}/$NNV_SUMS ($(nnv_digest sha256 "$tmp/$NNV_SUMS" | cut -c1-16))" "$signer" || return 1
    log "base image verified: $NNV_ALGO $digest, $(lab_signer_text "$signer")"
}

# lab_fetch_image DEST: IMAGE_URL downloaded to DEST.part and renamed to
# DEST only once its digest is the one the vendor's (signed) list gives.
lab_fetch_image() {
    local dest=$1 tmp rc=0
    nnv_require_tools || die "cannot verify the download"
    nnv_meta "$DISTRO" "$IMAGE_URL" || die "cannot verify the download"
    mkdir -p "$(dirname "$dest")"
    tmp=$(mktemp -d) || die "mktemp failed"
    (_lab_fetch_image "$dest" "$tmp") || rc=$?
    rm -rf "$tmp"
    if ((rc != 0)); then
        rm -f "$dest.part"
        die "base image refused: $IMAGE_URL did not verify (nothing kept)"
    fi
}

# lab_check_image FILE: before a new guest disk is layered on FILE.
lab_check_image() {
    local rec
    rec=$(lab_image_record "$1")
    if [[ -f $rec ]]; then
        nnv_record_check "$rec" "$1" ||
            die "base image $1 is not the one that was verified: delete it (nn-lab.sh destroy for the guests on it) and run up again for a verified download"
        log "base image matches its verification record ($rec)"
    else
        log "WARNING: $1 was downloaded before downloads were verified — nn-lab.sh verify-image checks it against the vendor's lists"
    fi
}

# lab_image_summary: one line for the nightly report.
lab_image_summary() {
    local rec algo
    rec=$(lab_image_record "$(lab_image_in_use)")
    if [[ ! -f $rec ]]; then
        echo "$BASE_IMG_NAME, unverified (nn-lab.sh verify-image)"
        return 0
    fi
    algo=$(awk -F= '$1 == "sha256" || $1 == "sha512" { print $1; exit }' "$rec")
    echo "$BASE_IMG_NAME $algo:$(nnv_record_field "$rec" "$algo" | cut -c1-16), listed in $(nnv_record_field "$rec" listed_in), signed by $(nnv_record_field "$rec" signed_by)"
}

_lab_verify_present() {
    local img=$1 tmp=$2 rec digest dir signer names hist d n=0
    local dirs=("${IMAGE_URL%/*}/")
    rec=$(lab_image_record "$img")
    log "hashing $img ($NNV_ALGO)"
    digest=$(nnv_digest "$NNV_ALGO" "$img") || return 1
    if [[ -f $rec ]]; then
        if nnv_record_check "$rec" "$img"; then
            log "OK    $img matches its verification record ($rec)"
            return 0
        fi
        log "FAIL  $img changed since it was verified ($rec): delete it (nn-lab.sh destroy for the guests on it) and run up again"
        return 1
    fi
    # The current build first, then the dated builds the vendor still lists.
    if [[ -n $NNV_HISTORY_RE ]]; then
        if hist=$(nnv_history "$NNV_HISTORY_BASE" "$NNV_HISTORY_RE" "${NN_LAB_VERIFY_BUILDS:-40}"); then
            for d in $hist; do dirs+=("$NNV_HISTORY_BASE$d"); done
        else
            log "      $NNV_HISTORY_BASE not reachable: only the current build is checked"
        fi
    fi
    for dir in "${dirs[@]}"; do
        n=$((n + 1))
        rm -f "$tmp/$NNV_SUMS" ${NNV_SIG:+"$tmp/$NNV_SIG"}
        signer=$(lab_fetch_list "$dir" "$tmp") || { log "      $dir: list not usable, skipped"; continue; }
        if names=$(nnv_names_for_digest "$tmp/$NNV_SUMS" "$digest" "$NNV_NAME_RE"); then
            nnv_record_write "$rec" "$img" "$NNV_ALGO" "$digest" "${dir%/}/${names%%$'\n'*}" \
                "${dir%/}/$NNV_SUMS ($(nnv_digest sha256 "$tmp/$NNV_SUMS" | cut -c1-16))" "$signer" || return 1
            log "OK    $img is ${dir%/}/${names%%$'\n'*} ($NNV_ALGO $digest, $(lab_signer_text "$signer")); recorded in $rec"
            return 0
        fi
    done
    log "FAIL  $img ($NNV_ALGO $digest) is in none of the $n lists $DISTRO still publishes: delete it (nn-lab.sh destroy for the guests on it) and run up again for a verified download"
    return 1
}

# nn-lab.sh verify-image: the base image(s) present for this distro,
# checked against their record or the vendor's published lists. Never
# downloads an image, never deletes one.
cmd_verify_image() {
    local imgs=() img tmp rc=0
    [[ -f $BASE_IMG ]] && imgs+=("$BASE_IMG")
    if [[ $ACCEL == whpx && -f "$(whpx_dir)/$BASE_IMG_NAME" ]]; then
        imgs+=("$(whpx_dir)/$BASE_IMG_NAME")
    fi
    ((${#imgs[@]})) || die "no $BASE_IMG_NAME for $DISTRO: nothing to verify (up downloads and verifies one)"
    nnv_require_tools || die "cannot verify"
    nnv_meta "$DISTRO" "$IMAGE_URL" || die "cannot verify"
    for img in "${imgs[@]}"; do
        tmp=$(mktemp -d) || die "mktemp failed"
        (_lab_verify_present "$img" "$tmp") || rc=1
        rm -rf "$tmp"
    done
    return "$rc"
}

# ── CI glue (lab PR 227): the base image of a GitHub-hosted runner ───────
# The workflow (.github/workflows/lab-vm.yml) keys its image cache by the
# digest the vendor's list gives now (`image-info`, which downloads the
# list, never the image), and `fetch-image` checks a restored image against
# that list before a guest is layered on it: a cache entry is never trusted
# for what it says it holds.

# _lab_current_digest TMP: the digest that the vendor's current list, its
# signature checked, gives for IMAGE_URL's image.
_lab_current_digest() {
    local tmp=$1 name=${IMAGE_URL##*/} signer
    signer=$(lab_fetch_list "${IMAGE_URL%/*}" "$tmp") || return 1
    if [[ $signer == unsigned ]]; then
        log "WARNING: $DISTRO publishes no signature for its cloud images: $NNV_SUMS is trusted over HTTPS only"
    fi
    nnv_sum_for_name "$tmp/$NNV_SUMS" "$name" ||
        { nnv_err "$name is not listed exactly once in ${IMAGE_URL%/*}/$NNV_SUMS"; return 1; }
}

# _lab_check_current IMG TMP: IMG is the image the vendor's current list
# names. 0: it is, and its record is written; 3: it is another image; 1: no
# usable list.
_lab_check_current() {
    local img=$1 tmp=$2 name=${IMAGE_URL##*/} signer want got
    signer=$(lab_fetch_list "${IMAGE_URL%/*}" "$tmp") || return 1
    want=$(nnv_sum_for_name "$tmp/$NNV_SUMS" "$name") ||
        { nnv_err "$name is not listed exactly once in ${IMAGE_URL%/*}/$NNV_SUMS"; return 1; }
    log "hashing $img ($NNV_ALGO)"
    got=$(nnv_digest "$NNV_ALGO" "$img") || return 1
    if [[ $got != "$want" ]]; then
        log "$img ($NNV_ALGO $got) is not the image ${IMAGE_URL%/*}/$NNV_SUMS lists now ($want)"
        return 3
    fi
    nnv_record_write "$(lab_image_record "$img")" "$img" "$NNV_ALGO" "$got" "$IMAGE_URL" \
        "${IMAGE_URL%/*}/$NNV_SUMS ($(nnv_digest sha256 "$tmp/$NNV_SUMS" | cut -c1-16))" "$signer" || return 1
    log "base image is the vendor's current one: $NNV_ALGO $got, $(lab_signer_text "$signer")"
}

# KEY=VALUE lines for the workflow ($GITHUB_OUTPUT): the KVM base image's
# path, the guest's directory (its serial log), the digest and its source.
lab_image_lines() {   # <algo> <digest>
    printf 'path=%s\nlab_dir=%s\nalgo=%s\ndigest=%s\nurl=%s\n' "$BASE_IMG" "$LAB_DIR" "$1" "$2" "$IMAGE_URL"
}

# nn-lab.sh image-info: the image the vendor's current list names.
cmd_image_info() {
    local tmp digest rc=0
    nnv_require_tools || die "cannot verify"
    nnv_meta "$DISTRO" "$IMAGE_URL" || die "cannot verify"
    tmp=$(mktemp -d) || die "mktemp failed"
    digest=$(_lab_current_digest "$tmp") || rc=1
    rm -rf "$tmp"
    ((rc == 0)) || die "no verified list for $IMAGE_URL: no digest to report"
    lab_image_lines "$NNV_ALGO" "$digest"
}

# nn-lab.sh fetch-image: the KVM base image, without a guest. Absent, it is
# downloaded as `up` does. Present, it is checked: in the lab as
# verify-image does (never replaced: guests are layered on it); in CI mode
# (NN_LAB_CI=1: an image restored from the workflow's cache, no guest on it)
# against the list the vendor publishes now, and downloaded again when it is
# another image. Prints image-info's lines for the image now in place.
cmd_fetch_image() {
    local tmp rc=0 rec algo
    [[ $ACCEL != whpx ]] || die "fetch-image is for a KVM host (under whpx, \`up\` copies the image to Windows)"
    nnv_require_tools || die "cannot verify"
    nnv_meta "$DISTRO" "$IMAGE_URL" || die "cannot verify"
    mkdir -p "$(dirname "$BASE_IMG")"
    if [[ ! -f $BASE_IMG ]]; then
        lab_fetch_image "$BASE_IMG"
    elif [[ ${CI_MODE:-0} == 1 ]]; then
        tmp=$(mktemp -d) || die "mktemp failed"
        (_lab_check_current "$BASE_IMG" "$tmp") || rc=$?
        rm -rf "$tmp"
        case $rc in
            0) ;;
            3)
                log "discarding it (NN_LAB_CI=1: no guest is layered on it) and downloading the current image"
                rm -f "$BASE_IMG" "$(lab_image_record "$BASE_IMG")"
                lab_fetch_image "$BASE_IMG" ;;
            *) die "the base image present could not be checked against the vendor's list: not used" ;;
        esac
    else
        cmd_verify_image || die "$BASE_IMG did not verify (see above): it is kept, the guests on it need it"
    fi
    rec=$(lab_image_record "$BASE_IMG")
    [[ -f $rec ]] || die "$BASE_IMG has no verification record"
    algo=$(awk -F= '$1 == "sha256" || $1 == "sha512" { print $1; exit }' "$rec")
    [[ -n $algo ]] || die "unreadable record $rec"
    lab_image_lines "$algo" "$(nnv_record_field "$rec" "$algo")"
}
