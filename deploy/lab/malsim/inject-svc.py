#!/usr/bin/env python3
"""Lot 281 (`inject-check.sh`): an exempt service's stand-in — started by
systemd in its unit, it waits for a line on the FIFO argv[1], then becomes
the ransomware simulator argv[2] (`inplace`, files under /srv/nn-malsim
only) by exec: the same process, so the action is its own."""
import os
import sys

fifo, sim = sys.argv[1], sys.argv[2]
with open(fifo) as f:
    f.readline()
os.execv(sys.executable, [sys.executable, "-I", sim, "inplace"])
