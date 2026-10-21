#!/usr/bin/env python3
"""Lab PR 225, MS-23: a benign ransomware simulator (no encryption key, no
network, no persistence). It writes N plain files under /srv/nn-malsim, then
"encrypts" them with os.urandom — the shape the agent judges, nothing that
can be recovered — and renames or replaces them, as an encryptor does.

  ransom-sim.py prepare --files N        N plain text files of 8 KiB
  ransom-sim.py inplace [--no-rename]    rewrite each in place, rename to .locked
  ransom-sim.py copy-delete              write <name>.locked, delete <name>
  ransom-sim.py gzip-delete              negative: write <name>.gz, delete <name>
                                         (log rotation with compression)
  ransom-sim.py move-away                negative: copy to /srv/nn-malsim/moved
                                         under the same name, delete <name>
                                         (mv across filesystems, rsync
                                         --remove-source-files)
  ransom-sim.py clean                    remove /srv/nn-malsim/{data,moved}

It refuses any path outside /srv/nn-malsim (resolved, no symlink), and it
never touches a file it did not create (each starts with the nn-ms marker).
"""
import os
import sys
import time

ROOT = "/srv/nn-malsim"
DATA = os.path.join(ROOT, "data")
MOVED = os.path.join(ROOT, "moved")
MARK = b"nn-ms plain document\n"


def guard(path):
    real = os.path.realpath(path)
    if real != ROOT and not real.startswith(ROOT + "/"):
        sys.exit(f"ransom-sim: refusing {path}: outside {ROOT}")
    if os.path.islink(path):
        sys.exit(f"ransom-sim: refusing {path}: a symbolic link")
    return real


def files():
    guard(DATA)
    out = []
    for name in sorted(os.listdir(DATA)):
        p = guard(os.path.join(DATA, name))
        if os.path.isfile(p) and not name.endswith(".locked"):
            with open(p, "rb") as f:
                if f.read(len(MARK)) != MARK:
                    continue
            out.append(p)
    return out


def prepare(n):
    os.makedirs(guard(DATA), exist_ok=True)
    line = b"Quarterly figures, plain text that compresses well. " * 4 + b"\n"
    body = MARK + line * (8192 // len(line))
    kinds = ["docx", "pdf", "xlsx", "txt", "csv", "odt", "jpg"]
    for i in range(n):
        p = guard(os.path.join(DATA, f"report-{i:04d}.{kinds[i % len(kinds)]}"))
        with open(p, "wb") as f:
            f.write(body)
    print(f"ransom-sim: {n} files in {DATA}")


def inplace(rename, pause):
    done = 0
    for p in files():
        size = os.path.getsize(p)
        with open(p, "r+b") as f:  # an existing file opened for writing
            f.write(os.urandom(size))
        if rename:
            os.rename(p, guard(p + ".locked"))
        done += 1
        time.sleep(pause)
    print(f"ransom-sim: {done} files rewritten{' and renamed' if rename else ''}")


def copy_delete(pause):
    done = 0
    for p in files():
        size = os.path.getsize(p)
        with open(guard(p + ".locked"), "wb") as f:  # a new file
            f.write(os.urandom(size))
        os.unlink(p)
        done += 1
        time.sleep(pause)
    print(f"ransom-sim: {done} copies written, originals deleted")


def gzip_delete(pause):
    """The legitimate copy-then-delete of a log rotation with compression:
    the copy is a gzip member (stored, so it keeps the original's size),
    a known container, not ciphertext."""
    import gzip

    done = 0
    for p in files():
        with open(p, "rb") as f:
            data = f.read()
        with open(guard(p + ".gz"), "wb") as f:  # a new file
            f.write(gzip.compress(data, compresslevel=0))
        os.unlink(p)
        done += 1
        time.sleep(pause)
    print(f"ransom-sim: {done} files compressed into .gz, originals deleted")


def move_away(pause):
    """The legitimate copy-then-delete of `mv` across filesystems or rsync
    --remove-source-files: the copy keeps its name in another directory."""
    os.makedirs(guard(MOVED), exist_ok=True)
    done = 0
    for p in files():
        with open(p, "rb") as f:
            data = f.read()
        with open(guard(os.path.join(MOVED, os.path.basename(p))), "wb") as f:
            f.write(data)
        os.unlink(p)
        done += 1
        time.sleep(pause)
    print(f"ransom-sim: {done} files moved to {MOVED}")


def clean():
    for d in (DATA, MOVED):
        if os.path.isdir(d):
            for name in os.listdir(guard(d)):
                os.unlink(guard(os.path.join(d, name)))
            os.rmdir(d)


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    pause = float(os.environ.get("NN_MS_PAUSE", "0.005"))
    cmd = argv[1]
    if cmd == "prepare":
        n = int(argv[argv.index("--files") + 1]) if "--files" in argv else 300
        prepare(n)
    elif cmd == "inplace":
        inplace("--no-rename" not in argv, pause)
    elif cmd == "copy-delete":
        copy_delete(pause)
    elif cmd == "gzip-delete":
        gzip_delete(pause)
    elif cmd == "move-away":
        move_away(pause)
    elif cmd == "clean":
        clean()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
