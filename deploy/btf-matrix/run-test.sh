#!/usr/bin/env bash
# deploy/btf-matrix/run-test.sh — offline tests of run.sh (external audit
# SUP-013, SUP-014, SUP-021). No network and no agent build: `curl` and
# `gh` are stubs first on PATH that serve a local directory standing in for
# the BTFHub archive (the API listing and the raw files), and `--agent` is a
# stub whose verdict is the first line of the BTF it is given. The stubs
# record their command lines, the headers curl reads from a file, the URLs
# asked for and the BTF the agent saw.
#
#   deploy/btf-matrix/run-test.sh            # every case; exit 1 if one fails
#   NN_BTF_RUN=/path/to/run.sh run-test.sh   # the cases against another run.sh
#
# Needs bash, tar, xz, sha256sum. xtask/tests/supply_chain.rs runs it in the
# CI test job, and the BTF matrix workflow before the matrix.
set -euo pipefail
unset GITHUB_TOKEN GH_TOKEN NN_TEST_GH_AUTH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="${NN_BTF_RUN:-$HERE/run.sh}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
REF=0123456789abcdef0123456789abcdef01234567
REF2=89abcdef0123456789abcdef0123456789abcdef
API=https://api.github.com/repos/aquasecurity/btfhub-archive
RAW=https://raw.githubusercontent.com/aquasecurity/btfhub-archive
SENTINEL=sentinel-not-a-secret

# --- stubs -----------------------------------------------------------------
mkdir -p "$T/bin"
cat > "$T/bin/curl" <<'STUB'
#!/usr/bin/env bash
# curl stand-in: serves $NN_TEST_MIRROR; records argv, headers and URLs.
set -u
log="$NN_TEST_LOG"
tr '\0' ' ' < /proc/$$/cmdline >> "$log/curl.argv"; echo >> "$log/curl.argv"
out="" url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -H) if [ "${2:0:1}" = @ ]; then cat -- "${2:1}" >> "$log/curl.headers"; else printf '%s\n' "$2" >> "$log/curl.headers"; fi; shift 2 ;;
        --proto|--proto-redir|--max-filesize|--config|-K|-d|--data) shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
printf '%s\n' "$url" >> "$log/curl.urls"
case "$url" in *..*) echo "curl stub: '..' in $url" >&2; exit 3 ;; esac
api=https://api.github.com/repos/aquasecurity/btfhub-archive
raw=https://raw.githubusercontent.com/aquasecurity/btfhub-archive
case "$url" in
    "$api/commits/main") src="$NN_TEST_MIRROR/api/commits-main" ;;
    "$api/contents/"*"?ref="*)
        p="${url#"$api/contents/"}"; src="$NN_TEST_MIRROR/api/${p#*\?ref=}/${p%%\?ref=*}.json" ;;
    "$raw/"*) src="$NN_TEST_MIRROR/raw/${url#"$raw/"}" ;;
    *) echo "curl stub: unexpected URL $url" >&2; exit 6 ;;
esac
[ -f "$src" ] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
if [ -n "$out" ]; then cat -- "$src" > "$out"; else cat -- "$src"; fi
STUB
cat > "$T/bin/gh" <<'STUB'
#!/usr/bin/env bash
# gh stand-in: logged in only when NN_TEST_GH_AUTH=1; `gh api` serves the mirror.
set -u
log="$NN_TEST_LOG"
tr '\0' ' ' < /proc/$$/cmdline >> "$log/gh.argv"; echo >> "$log/gh.argv"
[ "${1:-}" = auth ] && { [ "${NN_TEST_GH_AUTH:-0}" = 1 ]; exit; }
[ "${1:-}" = api ] || exit 1
shift
path="" jq=""
while [ $# -gt 0 ]; do
    case "$1" in
        -H) shift 2 ;;
        --jq) jq="$2"; shift 2 ;;
        *) path="$1"; shift ;;
    esac
done
prefix=repos/aquasecurity/btfhub-archive
case "$path" in
    "$prefix/commits/main") cat -- "$NN_TEST_MIRROR/api/commits-main" ;;
    "$prefix/contents/"*"?ref="*)
        p="${path#"$prefix/contents/"}"; src="$NN_TEST_MIRROR/api/${p#*\?ref=}/${p%%\?ref=*}.json"
        [ -f "$src" ] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
        [ "$jq" = '.[].name' ] || { echo "gh stub: unexpected --jq '$jq'" >&2; exit 1; }
        sed -n 's/^ *"name": *"\([^"]*\)",*$/\1/p' "$src" ;;
    *) echo "gh stub: unexpected path $path" >&2; exit 1 ;;
esac
STUB
cat > "$T/bin/agent" <<'STUB'
#!/usr/bin/env bash
# northnarrow-agent stand-in: the verdict is the first line of the BTF.
set -u
[ "${1:-}" = --version ] && { echo "northnarrow-agent 0.0.0-stub"; exit 0; }
[ "${1:-}" = --btf-check ] || exit 64
read -r s _ < <(sha256sum -- "$2")
printf '%s %s\n' "$s" "$2" >> "$NN_TEST_LOG/agent.log"
case "$(head -1 -- "$2")" in
    VERDICT=SUPPORTED) echo "btf-check $2: SUPPORTED — 0 drift"; exit 0 ;;
    VERDICT=DEGRADED) echo "btf-check $2: SUPPORTED (degraded) — 3 absent"; echo "absent iov_iter.ubuf"; exit 0 ;;
    VERDICT=NOT_SUPPORTED) echo "btf-check $2: NOT SUPPORTED — 1 missing"; echo "missing tcp_sock.bytes_sent"; exit 2 ;;
    *) echo "error: unparseable BTF"; exit 3 ;;
esac
STUB
chmod +x "$T/bin/curl" "$T/bin/gh" "$T/bin/agent"

# --- fixtures --------------------------------------------------------------
sha() { local s _; read -r s _ < <(sha256sum -- "$1"); printf '%s' "$s"; }

# blob <out.tar.xz> <kernel> <verdict>: one member, <kernel>.btf
blob() {
    local d; d="$(mktemp -d "$T/src.XXXXXX")"
    printf 'VERDICT=%s\n%s\n' "$3" "$RANDOM$RANDOM" > "$d/$2.btf"
    tar -C "$d" -cJf "$1" "$2.btf"
}
# listing <ref> <distro/version> <name>...: the API's pretty-printed JSON
listing() {
    local ref="$1" dv="$2" f; shift 2
    f="$MIRROR/api/$ref/$dv/x86_64.json"; mkdir -p "$(dirname "$f")"
    { echo "["; for n in "$@"; do printf '  {\n    "name": "%s",\n    "type": "file"\n  },\n' "$n"; done; echo "]"; } > "$f"
}
# mirror_blob <ref> <distro/version> <file> <verdict> → its sha256
mirror_blob() {
    local f="$MIRROR/raw/$1/$2/x86_64/$3"
    mkdir -p "$(dirname "$f")"; blob "$f" "${3%.btf.tar.xz}" "$4"; sha "$f"
}

# A case directory: mirror, log, cache, tmp, and the baseline
#   ubuntu/20.04 DEGRADED, centos/8 NOT_SUPPORTED, amzn/2 SUPPORTED.
new_case() {
    C="$T/case-$1"; MIRROR="$C/mirror"; LOG="$C/log"; CACHE="$C/cache"
    mkdir -p "$MIRROR/api" "$LOG" "$CACHE" "$C/tmp"
    : > "$LOG/curl.argv"; : > "$LOG/curl.headers"; : > "$LOG/curl.urls"; : > "$LOG/gh.argv"; : > "$LOG/agent.log"
    printf '# baseline\nubuntu/20.04\tDEGRADED\ncentos/8\tNOT_SUPPORTED\namzn/2\tSUPPORTED\nhost\tSUPPORTED\n' > "$C/expected.tsv"
    printf '%s\n' "$REF" > "$MIRROR/api/commits-main"
}
# The three blobs in the mirror at $REF and a pin file for them.
standard_mirror() {
    U="$(mirror_blob "$REF" ubuntu/20.04 5.8.0-63-generic.btf.tar.xz DEGRADED)"
    K="$(mirror_blob "$REF" centos/8 4.18.0-147.el8.x86_64.btf.tar.xz NOT_SUPPORTED)"
    A="$(mirror_blob "$REF" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz SUPPORTED)"
    printf '# pins\nref %s\nubuntu/20.04 5.8.0-63-generic.btf.tar.xz %s\ncentos/8 4.18.0-147.el8.x86_64.btf.tar.xz %s\namzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz %s\n' \
        "$REF" "$U" "$K" "$A" > "$C/pins"
}
# go [args...]: run.sh with the stubs and the case's files (a later --pins or
# --expected wins; $C/pins exists once standard_mirror wrote it); sets RC,
# OUT (stdout), ERRS (stderr), MD (matrix)
go() {
    set +e
    PATH="$T/bin:$PATH" TMPDIR="$C/tmp" NN_TEST_MIRROR="$MIRROR" NN_TEST_LOG="$LOG" \
        bash "$RUN" --agent "$T/bin/agent" --out "$C/matrix.md" --cache "$CACHE" \
        --expected "$C/expected.tsv" --pins "$C/pins" --no-host "$@" > "$C/stdout" 2> "$C/stderr"
    RC=$?
    set -e
    OUT="$(cat "$C/stdout")"; ERRS="$(cat "$C/stderr")"; MD="$(cat "$C/matrix.md" 2>/dev/null || true)"
}

failures=0 passed=0 CASE=""
check() { # <description> <command...>: one assertion of the current case
    local what="$1"; shift
    if "$@"; then return 0; fi
    echo "not ok - $CASE: $what (exit $RC)" >&2
    printf '%s\n' "$ERRS" | sed 's/^/    stderr: /' | tail -15 >&2
    failures=$((failures + 1)); CASE_OK=0
}
start() { CASE="$1"; CASE_OK=1; new_case "$1"; }
done_case() { if [ "$CASE_OK" = 1 ]; then echo "ok - $CASE"; passed=$((passed + 1)); fi; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks() { ! grep -qF -- "$2" <<<"$1"; }
count() { grep -cF -- "$2" <<<"$1" || true; }
no_cached_btf() { [ -z "$(find "$CACHE" -name '*.btf' -print -quit)" ]; }

# --- cases -----------------------------------------------------------------
start pinned-blobs-pass
standard_mirror
GITHUB_TOKEN="$SENTINEL" go --pins "$C/pins"
check "exit 0" [ "$RC" = 0 ]
check "three rows as expected" [ "$(count "$MD" "as expected")" = 3 ]
check "the matrix names the pinned commit" has "$MD" "aquasecurity/btfhub-archive@$REF"
check "the cache holds the pinned archive" [ "$(sha "$CACHE/centos/8/4.18.0-147.el8.x86_64.btf.tar.xz")" = "$K" ]
check "no extracted BTF in the cache" no_cached_btf
check "every download at the pinned commit" [ "$(grep -c "^$RAW/$REF/" "$LOG/curl.urls")" = 3 ]
check "nothing from a branch" lacks "$(cat "$LOG/curl.urls")" "/main/"
check "no API call without --refresh" lacks "$(cat "$LOG/curl.urls")" "api.github.com"
check "no token sent without --refresh" lacks "$(cat "$LOG/curl.headers" "$LOG/curl.argv")" "$SENTINEL"
check "the agent ran three times" [ "$(wc -l < "$LOG/agent.log")" = 3 ]
check "the temp directory is cleaned" [ -z "$(ls -A "$C/tmp")" ]
# the same cache again, with the mirror gone: nothing is downloaded
rm -rf "$MIRROR/raw"; : > "$LOG/curl.urls"
go --pins "$C/pins"
check "a verified cache is reused (exit 0)" [ "$RC" = 0 ]
check "no download from a verified cache" [ ! -s "$LOG/curl.urls" ]
done_case

start sup014-digest-mismatch-refused
standard_mirror
mirror_blob "$REF" centos/8 4.18.0-147.el8.x86_64.btf.tar.xz SUPPORTED > /dev/null   # replaced upstream
go --pins "$C/pins"
check "exit 1" [ "$RC" = 1 ]
check "a REGRESSION row naming the digest" has "$MD" "| centos/8 | 4.18.0-147.el8.x86_64 | — | BROKEN | 4.18.0-147.el8.x86_64.btf.tar.xz: sha256"
check "the row says refused" has "$MD" "refused | **REGRESSION** |"
check "nothing in the cache for it" [ -z "$(ls -A "$CACHE/centos/8" 2>/dev/null)" ]
check "no extracted BTF in the cache" no_cached_btf
check "the agent never saw it" [ "$(wc -l < "$LOG/agent.log")" = 2 ]
check "the other rows still checked" [ "$(count "$MD" "as expected")" = 2 ]
done_case

start sup014-cached-blob-checked-again
standard_mirror
go --pins "$C/pins"
check "first run exit 0" [ "$RC" = 0 ]
cached="$CACHE/ubuntu/20.04/5.8.0-63-generic.btf.tar.xz"
mkdir -p "$(dirname "$cached")"
blob "$cached" 5.8.0-63-generic SUPPORTED          # the cache restored from elsewhere
bad="$(sha "$cached")"; : > "$LOG/agent.log"
go --pins "$C/pins"
check "exit 0 (downloaded again)" [ "$RC" = 0 ]
check "the mismatch is reported" has "$ERRS" "the cached 5.8.0-63-generic.btf.tar.xz does not match its pin"
check "the cache holds the pinned archive again" [ "$(sha "$cached")" = "$U" ]
check "the tampered archive is gone" [ "$(sha "$cached")" != "$bad" ]
check "ubuntu/20.04 judged on the pinned blob" has "$MD" "| ubuntu/20.04 | 5.8.0-63-generic | yes | DEGRADED |"
done_case

start sup013-baseline-without-pin-fails
standard_mirror
grep -v '^amzn/2 ' "$C/pins" > "$C/pins.short"
go --pins "$C/pins.short"
check "exit 1" [ "$RC" = 1 ]
check "a REGRESSION row for the lost pin" has "$MD" "| amzn/2 | — | — | n/a | no blob pinned in pins.short | **REGRESSION** (baseline SUPPORTED, no blob found) |"
# a pinned distro/version without a baseline is reported, not failed
grep -v '^amzn/2' "$C/expected.tsv" > "$C/expected.short"
go --pins "$C/pins" --expected "$C/expected.short"
check "a pin without a baseline: exit 0" [ "$RC" = 0 ]
check "it asks for a baseline line" has "$MD" "no baseline — add"
done_case

start sup014-download-failure-fails
standard_mirror
rm -f "$MIRROR/raw/$REF/amzn/2/x86_64/"*
go --pins "$C/pins"
check "exit 1" [ "$RC" = 1 ]
check "a BROKEN row" has "$MD" "| amzn/2 | 4.14.355-1.amzn2.x86_64 | — | BROKEN | download of 4.14.355-1.amzn2.x86_64.btf.tar.xz failed | **REGRESSION** |"
done_case

start sup014-malformed-pins-refused
standard_mirror
bad_pins=(
    "ref $REF|ubuntu/20.04 ../5.8.0-63-generic.btf.tar.xz $U"
    "ref $REF|ubuntu/20.04 x/../../5.8.0-63-generic.btf.tar.xz $U"
    "ref $REF|ubuntu/20.04 .hidden.btf.tar.xz $U"
    "ref $REF|ubuntu/20.04 5.8.0-63-generic.btf.tar.xz ${U:0:63}"
    "ref $REF|ubuntu/20.04 5.8.0-63-generic.btf.tar.xz $U extra"
    "ref $REF|ubuntu/20.04 5.8.0-63-generic.btf.tar.xz $U|ubuntu/20.04 5.8.0-63-generic.btf.tar.xz $U"
    "ref main|ubuntu/20.04 5.8.0-63-generic.btf.tar.xz $U"
    "ubuntu/20.04 5.8.0-63-generic.btf.tar.xz $U"
    "ref $REF|../x 5.8.0-63-generic.btf.tar.xz $U"
)
i=0
for p in "${bad_pins[@]}"; do
    i=$((i + 1)); tr '|' '\n' <<<"$p" > "$C/pins.bad$i"; : > "$LOG/curl.urls"
    go --pins "$C/pins.bad$i"
    check "bad pin file $i: exit 2" [ "$RC" = 2 ]
    check "bad pin file $i: nothing downloaded" [ ! -s "$LOG/curl.urls" ]
done
done_case

start sup014-archive-members-refused
# Each archive matches its pin; the member check alone must refuse it.
evil() { # <label> <kernel> <how>
    local f="$MIRROR/raw/$REF/$1/x86_64/$2.btf.tar.xz" d
    mkdir -p "$(dirname "$f")"; d="$(mktemp -d "$T/src.XXXXXX")"
    case "$3" in
        dotdot) printf 'VERDICT=SUPPORTED\n' > "$d/$2.btf"
                tar -C "$d" -P --transform 's,^,../,' -cJf "$f" "$2.btf" 2>/dev/null ;;
        subdir) mkdir "$d/sub"; printf 'VERDICT=SUPPORTED\n' > "$d/sub/$2.btf"; tar -C "$d" -cJf "$f" "sub/$2.btf" ;;
        two) printf 'VERDICT=SUPPORTED\n' > "$d/$2.btf"; printf 'x\n' > "$d/extra"; tar -C "$d" -cJf "$f" "$2.btf" extra ;;
        symlink) ln -s /etc/hostname "$d/$2.btf"; tar -C "$d" -cJf "$f" "$2.btf" ;;
        other) printf 'VERDICT=SUPPORTED\n' > "$d/other.btf"; tar -C "$d" -cJf "$f" other.btf ;;
        notxz) printf 'not an archive\n' > "$f" ;;
        empty) : > "$d/$2.btf"; tar -C "$d" -cJf "$f" "$2.btf" ;;
    esac
    printf '%s %s %s\n' "$1" "$2.btf.tar.xz" "$(sha "$f")"
}
for how in dotdot subdir two symlink other notxz empty; do
    rm -rf "$MIRROR/raw" "$CACHE"; mkdir -p "$CACHE"; : > "$LOG/agent.log"
    { echo "ref $REF"; evil amzn/2 4.14.355-1.amzn2.x86_64 "$how"; } > "$C/pins.$how"
    printf 'amzn/2\tSUPPORTED\n' > "$C/expected.one"
    go --pins "$C/pins.$how" --expected "$C/expected.one"
    check "$how: exit 1" [ "$RC" = 1 ]
    check "$how: a BROKEN row" has "$MD" "| amzn/2 | 4.14.355-1.amzn2.x86_64 | — | BROKEN |"
    check "$how: refused" has "$MD" "**REGRESSION** |"
    case "$how" in
        symlink) why="is not a regular file in the archive" ;;
        notxz) why="not an xz tar archive" ;;
        empty) why="is 0 bytes" ;;
        *) why="expected only 4.14.355-1.amzn2.x86_64.btf" ;;
    esac
    check "$how: the reason is given" has "$MD" "$why"
    check "$how: the agent never ran" [ ! -s "$LOG/agent.log" ]
    check "$how: no member written anywhere" [ -z "$(find "$C" -name '*.btf' -print -quit)" ]
    check "$how: the temp directory is cleaned" [ -z "$(ls -A "$C/tmp")" ]
    check "$how: no extracted BTF in the cache" no_cached_btf
done
done_case

start sup013-refresh-no-blob-fails
listing "$REF" ubuntu/20.04 5.4.0-1.btf.tar.xz 5.11.0-1007-azure.btf.tar.xz 5.15.0-1-aws.btf.tar.xz \
    5.8.0-63-generic.btf.tar.xz 5.4.0-216-generic.btf.tar.xz '../9.9.9-generic.btf.tar.xz' \
    '9.9.8 x-generic.btf.tar.xz' '9.9.7$(id)-generic.btf.tar.xz' 5.11.0-22-generic.failed
listing "$REF" centos/8 4.18.0-305-azure.btf.tar.xz 4.18.0-147-azure.btf.tar.xz
listing "$REF" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz
U="$(mirror_blob "$REF" ubuntu/20.04 5.8.0-63-generic.btf.tar.xz DEGRADED)"
A="$(mirror_blob "$REF" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz SUPPORTED)"
go --refresh "$REF"
check "exit 1" [ "$RC" = 1 ]
check "a REGRESSION row for the distro/version without a blob" has "$MD" "| centos/8 | — | — | n/a | no archived BTF at ${REF:0:12} | **REGRESSION** (baseline NOT_SUPPORTED, no blob found) |"
check "the newest valid generic blob picked" has "$OUT" "ubuntu/20.04 5.8.0-63-generic.btf.tar.xz $U"
check "the other pin printed" has "$OUT" "amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz $A"
check "the missing one is a comment" has "$OUT" "# centos/8: no archived BTF"
check "the commit printed" has "$OUT" "ref $REF"
check "odd names reported" has "$ERRS" "3 archive name(s) outside [A-Za-z0-9._+-] ignored"
check "no odd name asked for" lacks "$(cat "$LOG/curl.urls")" "9.9."
check "listings at the commit" [ "$(grep -c "^$API/contents/.*?ref=$REF\$" "$LOG/curl.urls")" = 3 ]
check "downloads at the commit" [ "$(grep -c "^$RAW/$REF/" "$LOG/curl.urls")" = 2 ]
check "a refresh fills no cache" [ -z "$(ls -A "$CACHE")" ]
done_case

start refresh-round-trip
listing "$REF2" ubuntu/20.04 5.8.0-63-generic.btf.tar.xz 5.8.0-1-generic.btf.tar.xz
listing "$REF2" centos/8 4.18.0-147.el8.x86_64.btf.tar.xz
listing "$REF2" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz
mirror_blob "$REF2" ubuntu/20.04 5.8.0-63-generic.btf.tar.xz DEGRADED > /dev/null
mirror_blob "$REF2" centos/8 4.18.0-147.el8.x86_64.btf.tar.xz NOT_SUPPORTED > /dev/null
mirror_blob "$REF2" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz SUPPORTED > /dev/null
printf '%s\n' "$REF2" > "$MIRROR/api/commits-main"
go --refresh
check "refresh at the archive head: exit 0" [ "$RC" = 0 ]
check "the head resolved to its commit" has "$OUT" "ref $REF2"
printf '%s\n' "$OUT" > "$C/pins.new"
: > "$LOG/curl.urls"
go --pins "$C/pins.new"
check "the printed file is a pin file that passes: exit 0" [ "$RC" = 0 ]
check "three rows as expected" [ "$(count "$MD" "as expected")" = 3 ]
check "downloads at the new commit" [ "$(grep -c "^$RAW/$REF2/" "$LOG/curl.urls")" = 3 ]
go --refresh main
check "--refresh main (not a commit): exit 2" [ "$RC" = 2 ]
done_case

start sup021-token-not-in-argv
listing "$REF" ubuntu/20.04 5.8.0-63-generic.btf.tar.xz
listing "$REF" centos/8 4.18.0-147.el8.x86_64.btf.tar.xz
listing "$REF" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz
mirror_blob "$REF" ubuntu/20.04 5.8.0-63-generic.btf.tar.xz DEGRADED > /dev/null
mirror_blob "$REF" centos/8 4.18.0-147.el8.x86_64.btf.tar.xz NOT_SUPPORTED > /dev/null
mirror_blob "$REF" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz SUPPORTED > /dev/null
GITHUB_TOKEN="$SENTINEL" go --refresh
check "curl path: exit 0" [ "$RC" = 0 ]
check "the API was asked through curl" [ "$(grep -c "^$API/" "$LOG/curl.urls")" = 4 ]
check "the token is sent (in a header read from a file)" has "$(cat "$LOG/curl.headers")" "Authorization: Bearer $SENTINEL"
check "the token is on no curl command line" lacks "$(cat "$LOG/curl.argv")" "$SENTINEL"
check "the token goes to the API only" [ "$(count "$(cat "$LOG/curl.headers")" "Authorization")" = 4 ]
: > "$LOG/curl.urls"; : > "$LOG/curl.argv"
NN_TEST_GH_AUTH=1 GH_TOKEN="$SENTINEL" GITHUB_TOKEN="$SENTINEL" go --refresh
check "gh path: exit 0" [ "$RC" = 0 ]
check "the API was asked through gh" [ "$(grep -c "api repos/aquasecurity/btfhub-archive/contents/.*?ref=$REF --jq" "$LOG/gh.argv")" = 3 ]
check "no API call through curl" [ "$(grep -c "^$API/" "$LOG/curl.urls" || true)" = 0 ]
check "the token is on no command line" lacks "$(cat "$LOG/curl.argv" "$LOG/gh.argv")" "$SENTINEL"
done_case

start listing-failure-fails
listing "$REF" ubuntu/20.04 5.8.0-63-generic.btf.tar.xz
listing "$REF" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz
mirror_blob "$REF" ubuntu/20.04 5.8.0-63-generic.btf.tar.xz DEGRADED > /dev/null
mirror_blob "$REF" amzn/2 4.14.355-1.amzn2.x86_64.btf.tar.xz SUPPORTED > /dev/null
go --refresh "$REF"
check "exit 1" [ "$RC" = 1 ]
check "a BROKEN row" has "$MD" "| centos/8 | — | — | BROKEN | archive listing failed | **REGRESSION** |"
done_case

echo "run-test.sh: $passed case(s) passed, $failures assertion(s) failed"
[ "$failures" = 0 ]
