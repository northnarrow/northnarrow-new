#!/usr/bin/env bash
# Fail once a recorded RustSEC exception has expired (external audit SUP-007,
# NN-AUD-393).
#
# Every `ignore` entry of .cargo/audit.toml is preceded by its comment block,
# whose last line is `# Expires: YYYY-MM-DD` (the format is described at the
# top of that file and checked by xtask/tests/supply_chain.rs). cargo-audit
# knows nothing of the date: an exception accepted for a quarter would stay
# accepted for good. This step runs in the CI audit job, the daily schedule
# included, so an exception nobody re-checked turns the job red on the day
# after it expires: re-check it and record it again with a new date, or fix
# the dependency and drop it. An entry without a date, or with a malformed
# one, fails at once. xtask/tests/supply_chain.rs runs this script on
# fixtures with a fixed date.
#
# usage: check-audit-exceptions.sh [<audit.toml> [<today as YYYY-MM-DD>]]
set -euo pipefail

die() { echo "check-audit-exceptions: $*" >&2; exit 1; }

config=${1:-.cargo/audit.toml}
today=${2:-$(date -u +%F)}
[[ $today =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "bad date for today: '$today'"
[ -f "$config" ] || die "$config: not found"

# awk prints each accepted entry and, last, `ok <count>`; problems go to
# stderr and make it exit 1.
report=$(awk -v today="$today" '
    function flush_error(msg) { errors = errors msg "\n" }
    /^[[:space:]]*ignore[[:space:]]*=/ {
        if ($0 ~ /"/) flush_error("line " NR ": one exception per line, each after its comment block")
        else if ($0 ~ /\[[[:space:]]*\][[:space:]]*$/) inside = 0
        else if ($0 ~ /\[[[:space:]]*$/) inside = 1
        else flush_error("line " NR ": unexpected: " $0)
        next
    }
    inside && /^[[:space:]]*\]/ { inside = 0; next }
    !inside { next }
    /^[[:space:]]*#[[:space:]]*Expires:/ {
        line = $0
        sub(/^[[:space:]]*#[[:space:]]*Expires:[[:space:]]*/, "", line)
        sub(/[[:space:]]+$/, "", line)
        if (expires != "") flush_error("line " NR ": a second Expires: in one block")
        expires = line
        next
    }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*"/ {
        id = $0
        if (id !~ /^[[:space:]]*"RUSTSEC-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]",?[[:space:]]*$/) {
            flush_error("line " NR ": not one quoted RUSTSEC id: " $0)
            expires = ""
            next
        }
        gsub(/^[[:space:]]*"|"[[:space:]]*,?[[:space:]]*$/, "", id)
        count++
        if (expires == "") {
            flush_error(id ": no Expires: line in its comment block")
        } else if (expires !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
            flush_error(id ": Expires: \"" expires "\" is not YYYY-MM-DD")
        } else if (expires < today) {
            flush_error(id ": expired on " expires " (today " today "): re-check it, then record it again or drop it")
        } else {
            print "  " id ": accepted until " expires
        }
        expires = ""
        next
    }
    /[^[:space:]]/ { flush_error("line " NR ": unexpected in ignore: " $0) }
    END {
        if (inside) flush_error("ignore = [ is not closed")
        printf "%s", errors > "/dev/stderr"
        if (errors != "") exit 1
        print "ok " count + 0
    }
' "$config") || {
    [ -z "$report" ] || printf '%s\n' "$report"
    die "$config: an advisory exception has expired or has no valid Expires: date"
}
printf '%s\n' "$report" | sed '$d'
count=$(printf '%s\n' "$report" | tail -n 1)
echo "check-audit-exceptions: ${count#ok } exception(s), none expired on $today"
