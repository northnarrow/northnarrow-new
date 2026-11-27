#!/usr/bin/env bash
# .github/scripts/verify-release-tag.sh — a release starts only from a tag
# signed with a key listed in .github/allowed_signers (external audit
# SUP-024). release.yml's `verify-tag` job runs `verify` before anything is
# built; `package`, and through it every later job, needs it on a tag.
#
#   verify-release-tag.sh verify <tag> <commit> [allowed_signers]
#   verify-release-tag.sh version <tag> [Cargo.toml] [CHANGELOG.md]
#   verify-release-tag.sh selftest
#
# verify, in a clone where refs/tags/<tag> is the tag as pushed, refuses
# (exit 1) unless:
#   - allowed_signers lists at least one key (none listed: every tag stops);
#   - the tag is annotated: a lightweight tag carries no signature;
#   - the tag object names itself <tag>: a signed tag of another version,
#     pushed again under a new name, is not that version;
#   - it points to <commit>, the commit the workflow builds;
#   - it carries an SSH signature (git's gpg.format=ssh) that `git
#     verify-tag` accepts with gpg.ssh.allowedSignersFile=<allowed_signers>:
#     made by a key listed there for the "git" namespace and valid at the
#     tag's date (valid-after/valid-before). An OpenPGP signature is refused:
#     the runner has no keyring to trust, and one list is the whole policy.
# The list is the one committed at the tagged commit (default:
# .github/allowed_signers next to this script): adding or rotating a key is
# a reviewed PR like any other change.
#
# version (lot 383, the alpha's version), in the checkout of the tagged
# commit, refuses (exit 1) unless:
#   - <tag> is `v` and the workspace version of Cargo.toml
#     ([workspace.package] version): `v0.1.1-alpha` for "0.1.1-alpha". The
#     artefacts are named and versioned from Cargo.toml (mk-tarball.sh,
#     mk-packages.sh), so a tag of another version would publish them under
#     a name that is not theirs (a `v0.1.0-alpha` tag once had 0.0.1 ones);
#   - CHANGELOG.md opens with that version's section, dated: its first `## `
#     heading is `## [<version>] - YYYY-MM-DD`, a real date. Not
#     `[Unreleased]` above it, not `- unreleased` for the date: the date is
#     written in the last commit before the tag (CONTRIBUTING.md,
#     "Releases"), the day of the tag.
# release.yml's `verify-tag` job runs it after `verify`.
#
# selftest runs the same checks on a scratch repository with throwaway keys
# (no network): a tag signed by the listed key passes; another key, an
# unsigned or lightweight tag, a renamed tag, a tag of another commit, an
# altered tag, an expired key, a key for another namespace and an empty list
# are refused (a key still valid at the tag's date passes); for `version`,
# a tag of another version, a CHANGELOG with `[Unreleased]` or an undated or
# impossible date on top, and a Cargo.toml without a workspace version are
# refused. xtask/tests/supply_chain.rs runs it in the CI test job.
# Needs git >= 2.34 and ssh-keygen (OpenSSH >= 8.8).
# Exit 0 = verified; 1 = refused; 2 = usage.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

refuse() { echo "::error::verify-release-tag: $*" >&2; exit 1; }

verify() { # <tag> <commit> [allowed_signers]
    local tag="$1" commit="$2" signers="${3:-$ROOT/.github/allowed_signers}" keys type name target
    [ -f "$signers" ] || refuse "no allowed-signers file at $signers"
    signers="$(cd "$(dirname "$signers")" && pwd)/$(basename "$signers")"
    keys="$(grep -cvE '^[[:space:]]*(#|$)' "$signers" || true)"
    [ "$keys" -gt 0 ] || refuse "$signers lists no key, so no tag can be verified: the maintainer adds the public half of the tag-signing key (CONTRIBUTING.md, \"Releases\")"
    type="$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" || refuse "no tag $tag in this clone"
    [ "$type" = tag ] || refuse "$tag is a lightweight tag (a $type): a release tag is annotated and signed (git tag -s)"
    name="$(git cat-file tag "refs/tags/$tag" | sed -n '/^$/q; s/^tag //p')"
    [ "$name" = "$tag" ] || refuse "the tag object under refs/tags/$tag is the tag '$name'"
    target="$(git rev-parse --verify --quiet "refs/tags/$tag^{commit}")" || refuse "$tag does not point to a commit"
    [ "$target" = "$commit" ] || refuse "$tag points to $target, the workflow builds $commit"
    git cat-file tag "refs/tags/$tag" | grep -qx -- '-----BEGIN SSH SIGNATURE-----' \
        || refuse "$tag carries no SSH signature (unsigned, or signed with OpenPGP): sign it with gpg.format=ssh and a key of $(basename "$signers")"
    git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$signers" verify-tag "refs/tags/$tag" \
        || refuse "git verify-tag refused $tag against $signers"
    echo "verify-release-tag: $tag ($commit) is signed by a key of $signers"
}

version_check() { # <tag> [Cargo.toml] [CHANGELOG.md]
    local tag="$1" cargo="${2:-$ROOT/Cargo.toml}" changelog="${3:-$ROOT/CHANGELOG.md}" ver head date
    [ -f "$cargo" ] || refuse "no $cargo"
    [ -f "$changelog" ] || refuse "no $changelog"
    ver="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version *= *"\([^"]*\)" *$/\1/p;}' "$cargo" | head -1)"
    [ -n "$ver" ] || refuse "$cargo has no [workspace.package] version"
    [ "$tag" = "v$ver" ] || refuse "the tag $tag is not v$ver: $cargo says $ver, and the artefacts are named and versioned from it"
    head="$(grep -m1 '^## ' "$changelog" || true)"
    case "$head" in
        "## [$ver] - "*) ;;
        *) refuse "$changelog opens with '${head:-no section}', not the section of $ver ('## [$ver] - YYYY-MM-DD')" ;;
    esac
    date="${head#"## [$ver] - "}"
    if ! [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || [ "$(date -u -d "$date" +%F 2>/dev/null)" != "$date" ]; then
        refuse "the section of $ver in $changelog is dated '$date', not YYYY-MM-DD: write the day of the tag in the last commit before it"
    fi
    echo "verify-release-tag: $tag is the workspace version $ver, and $(basename "$changelog") opens with its section ($date)"
}

selftest() {
    command -v ssh-keygen >/dev/null || { echo "selftest: ssh-keygen missing" >&2; exit 2; }
    local t fails=0
    t="$(mktemp -d)"
    # shellcheck disable=SC2064 # $t is fixed here
    trap "rm -rf '$t'" EXIT
    export HOME="$t/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$t/gitconfig"
    export GIT_AUTHOR_NAME=selftest GIT_AUTHOR_EMAIL=selftest@example.invalid
    export GIT_COMMITTER_NAME=selftest GIT_COMMITTER_EMAIL=selftest@example.invalid
    mkdir -p "$HOME"; : > "$GIT_CONFIG_GLOBAL"
    ssh-keygen -q -t ed25519 -N '' -C maintainer -f "$t/maintainer"
    ssh-keygen -q -t ed25519 -N '' -C other -f "$t/other"
    local pub; pub="$(cut -d' ' -f1,2 "$t/maintainer.pub")"
    printf '# throwaway\nmaintainer@example.invalid namespaces="git" %s\n' "$pub" > "$t/allowed"
    printf '# no key listed yet\n\n' > "$t/empty"
    printf 'maintainer@example.invalid namespaces="file" %s\n' "$pub" > "$t/other-namespace"
    printf 'maintainer@example.invalid namespaces="git",valid-before="20000101" %s\n' "$pub" > "$t/expired"
    printf 'maintainer@example.invalid namespaces="git",valid-before="29991231" %s\n' "$pub" > "$t/valid-until"

    git init -q "$t/repo"
    cd "$t/repo"
    git commit -q --allow-empty -m one; local c1; c1="$(git rev-parse HEAD)"
    git commit -q --allow-empty -m two; local c2; c2="$(git rev-parse HEAD)"
    local ssh=(-c gpg.format=ssh)
    git "${ssh[@]}" -c user.signingkey="$t/maintainer" tag -s v1.0.0 -m "v1.0.0" "$c2"
    git "${ssh[@]}" -c user.signingkey="$t/other" tag -s v1.0.1 -m "v1.0.1" "$c2"
    git tag -a v1.0.2 -m "v1.0.2 unsigned" "$c2"
    git tag v1.0.3 "$c2"
    git update-ref refs/tags/v2.0.0 "$(git rev-parse refs/tags/v1.0.0)"     # v1.0.0's object, renamed
    git "${ssh[@]}" -c user.signingkey="$t/maintainer" tag -s v1.0.4 -m "v1.0.4" "$c2"
    git update-ref refs/tags/v1.0.4 "$(git cat-file tag v1.0.4 | sed 's/^v1\.0\.4$/v1.0.4 altered/' | git mktag)"

    expect() { # <want exit> <what> <verify args...>
        local want="$1" what="$2" got; shift 2
        set +e; ( verify "$@" ) > "$t/out" 2>&1; got=$?; set -e
        if [ "$got" = "$want" ]; then echo "ok - $what"
        else echo "not ok - $what: exit $got, want $want"; sed 's/^/    /' "$t/out"; fails=$((fails + 1)); fi
    }
    expect 0 "a tag signed by the listed key passes" v1.0.0 "$c2" "$t/allowed"
    expect 1 "a tag of another commit is refused" v1.0.0 "$c1" "$t/allowed"
    expect 1 "a tag signed by another key is refused" v1.0.1 "$c2" "$t/allowed"
    expect 1 "an unsigned annotated tag is refused" v1.0.2 "$c2" "$t/allowed"
    expect 1 "a lightweight tag is refused" v1.0.3 "$c2" "$t/allowed"
    expect 1 "a signed tag pushed under another name is refused" v2.0.0 "$c2" "$t/allowed"
    expect 1 "a tag altered after signing is refused" v1.0.4 "$c2" "$t/allowed"
    expect 1 "a list with no key refuses every tag" v1.0.0 "$c2" "$t/empty"
    expect 1 "a key listed for another namespace is refused" v1.0.0 "$c2" "$t/other-namespace"
    expect 1 "a key expired before the tag is refused" v1.0.0 "$c2" "$t/expired"
    expect 0 "a key valid at the tag's date passes" v1.0.0 "$c2" "$t/valid-until"
    expect 1 "a missing list refuses" v1.0.0 "$c2" "$t/absent"
    expect 1 "a missing tag refuses" v9.9.9 "$c2" "$t/allowed"

    # lot 383: the tag and the version the artefacts are built as
    expect_version() { # <want exit> <what> <tag> <workspace version line> <changelog top heading> [<said>]
        local want="$1" what="$2" tag="$3" said="${6:-}" got
        printf '[package]\nname = "root"\nversion = "9.9.9"\n\n[workspace]\nmembers = []\n\n[workspace.package]\n%s\nedition = "2021"\n\n[profile.release]\nversion = "9.9.8"\n' "$4" > "$t/Cargo.toml"
        printf '# Changelog\n\nFormat: Keep a Changelog.\n\n%s\n\n### Added\n- a change\n\n## [0.0.1] - 2026-10-09\n' "$5" > "$t/CHANGELOG.md"
        set +e; ( version_check "$tag" "$t/Cargo.toml" "$t/CHANGELOG.md" ) > "$t/out" 2>&1; got=$?; set -e
        if [ -n "$said" ] && ! grep -qF -- "$said" "$t/out"; then
            echo "not ok - $what: it did not say '$said'"; sed 's/^/    /' "$t/out"; fails=$((fails + 1))
        elif [ "$got" = "$want" ]; then echo "ok - $what"
        else echo "not ok - $what: exit $got, want $want"; sed 's/^/    /' "$t/out"; fails=$((fails + 1)); fi
    }
    local v='version = "1.2.0-beta"'
    expect_version 0 "the tag of the workspace version, its dated section on top, passes" v1.2.0-beta "$v" "## [1.2.0-beta] - 2026-11-21"
    expect_version 1 "a tag of another version is refused" v1.2.0 "$v" "## [1.2.0-beta] - 2026-11-21"
    expect_version 1 "a tag without its v is refused" 1.2.0-beta "$v" "## [1.2.0-beta] - 2026-11-21"
    expect_version 1 "a version only in another section of Cargo.toml is refused" v9.9.9 "$v" "## [9.9.9] - 2026-11-21"
    expect_version 1 "a Cargo.toml without a workspace version is refused" v1.2.0-beta 'rust-version = "1.89"' "## [1.2.0-beta] - 2026-11-21"
    expect_version 1 "[Unreleased] on top is refused" v1.2.0-beta "$v" "## [Unreleased]" "not the section of 1.2.0-beta"
    expect_version 1 "another version's section on top is refused" v1.2.0-beta "$v" "## [1.1.0] - 2026-11-21" "opens with '## [1.1.0] - 2026-11-21'"
    expect_version 1 "an undated section is refused" v1.2.0-beta "$v" "## [1.2.0-beta] - unreleased" "dated 'unreleased'"
    expect_version 1 "an impossible date is refused" v1.2.0-beta "$v" "## [1.2.0-beta] - 2026-02-30"
    [ "$fails" = 0 ] || { echo "selftest: $fails case(s) failed" >&2; exit 1; }
    echo "selftest: all cases passed"
}

case "${1:-}" in
    verify) [ $# -ge 3 ] && [ $# -le 4 ] || { echo "usage: $0 verify <tag> <commit> [allowed_signers]" >&2; exit 2; }
            shift; verify "$@" ;;
    version) [ $# -ge 2 ] && [ $# -le 4 ] || { echo "usage: $0 version <tag> [Cargo.toml] [CHANGELOG.md]" >&2; exit 2; }
             shift; version_check "$@" ;;
    selftest) selftest ;;
    *) echo "usage: $0 verify <tag> <commit> [allowed_signers] | version <tag> [Cargo.toml] [CHANGELOG.md] | selftest" >&2; exit 2 ;;
esac
