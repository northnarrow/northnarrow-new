#!/usr/bin/env bash
# Drop the WORKSPACE crates' build artifacts from a restored cargo target dir,
# keeping every third-party dependency.
#
# actions/cache restores `target/` by a key made of Cargo.lock + Cargo.toml,
# which is the same for every branch that does not touch dependencies. The
# restored fingerprints can then mark a workspace crate "Fresh" although the
# branch changed its sources (seen on PR #194: `northnarrow-common` taken from
# a cache built on main, agent failed with "no variant named BpfSyscall").
# Swatinem/rust-cache strips workspace artifacts before saving for the same
# reason; this does it after restoring, without a new action in the supply
# chain. Rebuilding our own crates costs a minute; the dependencies are the
# part worth caching.
#
# External audit SUP-012: the crate list came from a process substitution,
# whose exit status nobody reads, so a failing `cargo metadata` (or python)
# gave an empty list, "(0 crates)" and exit 0 — the restored artifacts stayed.
# Each step is now checked, and an empty list or an empty name is an error.
# xtask/tests/supply_chain.rs runs this script against a stub cargo.
#
# usage: prune-workspace-cache.sh <target-dir>...
set -euo pipefail

die() { echo "prune-workspace-cache: $*" >&2; exit 1; }

meta=$(cargo metadata --no-deps --format-version 1) \
    || die "cargo metadata failed; refusing to keep a restored cache unpruned"
list=$(printf '%s' "$meta" \
    | python3 -c 'import json,sys; [print(p["name"]) for p in json.load(sys.stdin)["packages"]]') \
    || die "cannot read the workspace packages from cargo metadata"
[ -n "$list" ] || die "cargo metadata lists no workspace package"
mapfile -t names <<<"$list"
for name in "${names[@]}"; do
    [[ $name =~ ^[A-Za-z0-9_-]+$ ]] || die "unexpected package name: '$name'"
done

for target in "$@"; do
    [ -d "$target" ] || continue
    for name in "${names[@]}"; do
        under=${name//-/_}
        # <profile>/.fingerprint/<name>-<hash>, <profile>/deps/{lib,}<name>-<hash>.*,
        # <profile>/build/<name>-<hash> (build scripts), <profile>/<name> (bins),
        # <profile>/incremental/<name>-<hash>, and the same under target triples.
        find "$target" -mindepth 2 -maxdepth 4 \( \
            -path "*/.fingerprint/${name}-*" -o \
            -path "*/deps/${under}-*" -o -path "*/deps/lib${under}-*" -o \
            -path "*/build/${name}-*" -o \
            -path "*/incremental/${under}-*" -o \
            -path "*/${name}" -o -path "*/${name}.d" \) \
            -prune -exec rm -rf {} + 2>/dev/null || true
    done
    echo "pruned workspace artifacts (${#names[@]} crates) from $target"
done
