#!/usr/bin/env python3
# BENIGN ransomware simulator for NorthNarrow's own lab (lab PR 222).
#
# What it does, and nothing else: for every regular file under one test
# directory (refused unless its path starts with /srv/nn-cow- and the
# directory holds the harness's marker file), it rewrites the file in place
# with random bytes of the same length (open O_WRONLY|O_TRUNC, write, fsync),
# then renames it to <name>.locked. No encryption key, no network, no
# process injection, no persistence, nothing outside the test directory.
# The original bytes exist only in the agent's copy-on-first-write journal
# (and in the harness's manifest of hashes): the point is to check that the
# agent restores them.
#
#   ransom-sim.py DIR [--rename-every N] [--tripwire] [--hold SECS]
#
# --rename-every N: rename every Nth file only (default 1: all).
# --tripwire: after the rewrites, try to open /etc/northnarrow/admin.pub
#   for appending (run as root: the agent's anti-tamper hook refuses it —
#   the decisive signal that drives COMBAT with this process as the
#   offender, the lab's usual way to get a NEUTRALIZE), then start one
#   child (/bin/true) so the ladder's spread check advances to NEUTRALIZE.
# --hold SECS: sleep afterwards (stay alive for the ladder), default 0.
import os
import sys
import time

MARKER = ".nn-cow-test-tree"


def main():
    if len(sys.argv) < 2:
        print(__doc__ or "usage: ransom-sim.py DIR", file=sys.stderr)
        return 2
    top = os.path.realpath(sys.argv[1])
    args = sys.argv[2:]
    every = 1
    tripwire = "--tripwire" in args
    hold = 0.0
    if "--rename-every" in args:
        every = max(1, int(args[args.index("--rename-every") + 1]))
    if "--hold" in args:
        hold = float(args[args.index("--hold") + 1])
    if not top.startswith("/srv/nn-cow-") or not os.path.isfile(os.path.join(top, MARKER)):
        print(f"ransom-sim: refusing {top}: not a lab test tree (no {MARKER})", file=sys.stderr)
        return 2
    targets = []
    for root, dirs, files in os.walk(top):
        dirs[:] = [d for d in dirs if not d.startswith(".northnarrow-cow")]
        for f in sorted(files):
            p = os.path.join(root, f)
            if f == MARKER or f.endswith(".locked") or os.path.islink(p) or not os.path.isfile(p):
                continue
            targets.append(p)
    t0 = time.monotonic()
    rewritten = renamed = 0
    for i, p in enumerate(sorted(targets)):
        size = os.path.getsize(p)
        fd = os.open(p, os.O_WRONLY | os.O_TRUNC)
        try:
            left = size
            while left > 0:
                n = min(left, 1 << 20)
                os.write(fd, os.urandom(n))
                left -= n
            os.fsync(fd)
        finally:
            os.close(fd)
        rewritten += 1
        if i % every == 0:
            os.rename(p, p + ".locked")
            renamed += 1
    print(f"ransom-sim: pid {os.getpid()} rewrote {rewritten} files, renamed {renamed}, "
          f"{time.monotonic() - t0:.2f}s", flush=True)
    if tripwire:
        try:
            open("/etc/northnarrow/admin.pub", "a").close()
            print("ransom-sim: tripwire open succeeded (anti-tamper NOT enforcing?)", flush=True)
        except OSError as e:
            print(f"ransom-sim: tripwire refused as expected ({e.strerror})", flush=True)
        time.sleep(0.3)
        os.spawnv(os.P_NOWAIT, "/bin/true", ["true"])
    if hold > 0:
        time.sleep(hold)
    return 0


if __name__ == "__main__":
    sys.exit(main())
