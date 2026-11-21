# Deploying NorthNarrow on a container host

*Beta Step 3 — process-comm-allowlist container-runtime overlay.*

NorthNarrow ships with a **security-first default**: the
`process-comm-allowlist.v1` file (installed to `/etc/northnarrow/`)
exempts only package managers and configuration-management actors. It
deliberately does **not** exempt container runtimes, because doing so
weakens a real detection (see below). On a host that legitimately runs
containers (Docker, Kubernetes, podman, containerd, CRI-O) you may need
to opt in.

## When to enable the container-runtime overlay

Enable it only if you observe **R013** false positives —
`R013_NamespaceEscapeTooling` ("Namespace/escape tooling from
non-standard path", MITRE **T1611 Escape-to-Host"). R013 fires when a
process whose `comm` is `runc` (or `nsenter` / `unshare`) execs from a
path **outside** the standard binary dirs (`/usr/bin`, `/bin`,
`/usr/sbin`, `/sbin`).

Most container runtimes install `runc` under a standard path, so they
**do not** trip R013 and need no exemption. You only need the overlay
when your runtime invokes `runc` (or a copy of it) from a non-standard
location — some bundle layouts and older runtimes do, and k3s does
(`/var/lib/rancher/k3s/data/<hash>/bin/runc`).

Since lot 283b (`RULE_POLICY.md` §1, the decision of 06/11/2026) such
a `runc` is a High record, not killed: k3s starts its pods on a default
install (before, every container start killed its `runc` and no pod ran).
The overlay below silences the record; `enforce R013` in the signed per-rule
policy gives the kill back. A copied `nsenter` or `unshare` is killed either
way.

## What needs no overlay: the runtime's own work (lot 347)

A container start runs work that is also a classic attack technique. The
agent tells the runtime's own instance of it by identity, with no overlay
and no allowlist entry, and keeps every other instance at its severity.

**runc's copy of itself (R004, fileless exec).** At every container start,
`docker exec` and build, `runc` executes itself again from a sealed memfd
copy of its own image (`runc_cloned:/proc/self/exe`, the CVE-2019-5736
defence; runc 1.1 on Debian 13). R004 has no verdict for it when every
fact holds:

- the memfd was sealed against writing, shrinking and growing when the
  kernel executed it — the exec sensor's LSM program reads its seals at the
  exec (a seal is never removed, so its bytes could not change since) —
  and it is the whole image of an installed runtime (`runc` or `crun` in
  `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` or `/usr/local/bin`, a file
  root owns that no one else can write, in directories no one else can
  write), byte for byte — the exec pump compares it right after the exec,
  when the exec's parent runs an installed runtime or its manager;
- the process that made the copy runs that same file, by the kernel's
  exec records (the device and inode of the executed file, in any mount
  namespace: rootless Podman runs runc in its own): the `runc create` that
  forked it (runc 1.2), or the process itself just before (runc 1.1's
  `runc init`);
- an installed manager started the runtime: `containerd-shim-runc-v2`,
  `containerd`, `dockerd`, `conmon` or `podman`, by the image of the
  process the kernel recorded forking it (its exec from a root-only
  directory; for conmon's monitor, a fork that never executed, the
  installed file the agent saw it run at the exec, still at its path).

Rootless Docker (its shim executed in rootlesskit's mount namespace) is not
recognised as a manager and keeps the Critical. A memfd of any other
program, a copy not sealed when it was executed (sealed later included: any
process holding a writable descriptor of the memfd — the parent of an OCI
hook that runc executes from `/proc/<pid>/fd/N` — could rewrite and seal it
after the exec), a copy of runc run from a shell (`python3` executing runc's
bytes from a memfd), a runtime outside those directories or in one a user
can write (k3s's bundled `runc`, a snap's, a link to a user's file), every
one on an agent in tracepoint mode (no seals read at the exec) and every one
on a kernel whose BTF lacks `shmem_inode_info` stay Critical.

A clone whose process exited before the agent read it (runc 1.1's
`runc init` lives a few milliseconds past its exec; under a burst of
container starts the read can come later) is read through a process still
running that very memfd: `runc init`'s two stages, children of
`runc create`, run it until the container's program starts (lot 381), or a
thread of its own process still running (its main thread exited alone).
Only when none is left, and only in runc 1.1's shape (the process
re-executed the installed runtime with no fork since, under that runtime's
process), is it "not compared (gone)" and judged like a copy past the
budget below: root's recorded High, never killed; any other uid's the
Critical kill. In any other shape (runc 1.2's, an OCI hook), under a parent
that is gone too, or a manager (which runtime it copied is not known), or
when the process runs another file by then (a runtime's copy never executes
again) or still runs with its copy unreadable, nothing is kept: Critical.

The compares have a budget of their own, per user, with a share kept for
root's starts (Docker's, rootful Podman's) that other users cannot take;
normal container starts stay well inside it. A memfd past the
budget — every fact above holds, its bytes not compared, so it may be any
program of the runtime's length — is "not compared (budget)": root's (uid 0
of the initial user namespace) is recorded High, never killed; any other
uid's stays the Critical kill, since a user can spend its own share on
purpose (decoy OCI hooks of genuine runc copies, then a sealed payload
padded to runc's length). No user's container loop can make root's Docker
starts Critical; a rootless user's container start past its own share (a
third runc 1.1 start in a second) is killed as before lot 347.

Residual, named: a root memfd past the comparison budget is recorded High, not killed — root, who needs no such route.

`nn-admin status --key` counts what the exec pump did with these clones
since the agent's start (lot 369), once one was seen: `runtime clones : N
sealed memfds kept as an installed runtime's clone (R004 has no verdict on
them), of M compared (T through a process still running the copy); U not
compared (the budget), G not compared (gone before the read, kept
unverified), L not compared (gone, replaced or unreadable: judged
fileless), R not read in time (judged fileless), F no runtime's copy
(judged fileless)` — JSON `runtime_clones` (`compared`, `kept`,
`unverified`, `not_read`, and since lot 381 `through`, `gone`,
`no_runtime`, `lost`). F counts every sealed memfd that is no runtime's
copy: under no installed runtime or manager, of no installed runtime's
length, or not sealed by the read. Every sealed memfd exec the agent saw is
in exactly one of M, U, G, L, R and F, once (lot 381: rc11 judged one
rootful runc clone in 300 fileless outside every count; a read that
finishes after the agent stopped waiting for it is counted only in R). On a
container host with runc 1.1 the kept count
grows with every container start; containers that start while it stays at
zero mean the exemption is lost and R004 judges every start (rc5's
regression: the exec pump handed only the socket programs' execs to its
reads, so no clone was compared, lot 369).

What remains possible: the kernel reads the first bytes of the file (the
binary's header) just before the LSM program reads the seals, so a writer
racing that window chooses the header of a run whose every mapped byte is
the sealed runtime's — no code of its own runs (the program headers,
segments and interpreter are read from the sealed file; a `#!` line names
an interpreter, which the process's image then is, never the copy
compared).

**containerd's and dockerd's module probes (R011, module tooling).**
containerd and dockerd run `modprobe` at their start: containerd 1.7
probes `aufs` for its snapshotter (with the `LD_LIBRARY_PATH` its `opt`
plugin sets, `/var/lib/containerd/opt/lib:` on Debian — R011's kill until
lot 347), dockerd asks for `bridge`, `br_netfilter` and `nf_conntrack`. R011
records such an exec Low when the process that forked it (the kernel's
record) runs the installed `containerd` or `dockerd` (its image's device and
inode), root runs the system's module tool by name, with no module
parameter, every module named is a container runtime's (`overlay`, `aufs`,
`erofs`, `bridge`, `br_netfilter`, `veth`, `xfrm_user`, `xfrm_algo`,
`ip_tables`, `ip6_tables`, or of the `nf_`, `nft_`, `xt_`, `iptable_`,
`ip6table_` families), and its environment holds no refused variable but
that `LD_LIBRARY_PATH`, with each entry exactly `/var/lib/containerd/opt/lib`
or `/opt/containerd/lib` (never a directory below them: a snapshot's `lib`
under `/var/lib/containerd/` is an image's content), reached through no
link, that directory and every one above it root's and writable by no one
else, and each file in it too. `ctr install <image>` (root, or containerd's
socket, which is root's equal) fills that directory with an image's
libraries, which then load into root's `modprobe`, recorded Low: a residual.
The module file is still judged at its load, by R018: a file out of the
module tree, or deeper than any module directory, is Critical with the
loader's tree killed; a file inside `/lib/modules` that no package
installed is **High, recorded only** (no kill) — the module-load judge
refuses the load outside a trusted-installer window, and lets it through
recorded under `alert`, `audit` or `off R018` or before its maps are armed
([`RULE_POLICY.md`](RULE_POLICY.md) §2.4). Any other module, a library path of the caller's,
`MODPROBE_OPTIONS`, `LD_PRELOAD`, a copy of the tool or another parent keeps
R011's verdict. `containerd.service`'s own `ExecStartPre=modprobe overlay`
(PID 1's child) was already a Low record.

**Rootless Podman's `modprobe overlay` (R011, lots 369 and 380).** Podman
run by a user asks for `overlay` as that user. R011 records the exec Low
when the process cannot load a module: no uid 0 among its ids and no
`CAP_SYS_MODULE` in PID 1's user namespace (rootless Podman's capabilities
are its own namespace's). A `modprobe` that exits before the exec pump reads
it (a module already loaded) is judged from the process that forked it, when
the kernel's record says the exec is that fork's first and the system's
tool has no set-id bit or file capability: every thread of the forker with
no uid 0 and no capability in PID 1's namespace, or in a namespace of its
own. A forker with a uid 0 or a capability keeps High. The route is bounded
so a loop of exits cannot slow the exec pump: a forker of at most 32
threads, read at most twice a second for one forker and eight times a second
for all; past a bound the forker is not read and the exec keeps R011's
earlier judgement (High for a user's), never Low.

**containerd's task bundles (the mass-write arm, lot 380).** containerd
writes and removes each task's bundle under `/run/containerd` as containers
start and stop — new files beside originals destroyed, the shape the
posture's mass-write arm counts. The shipped `daemon-data.v1` lists
`/run/containerd/` for `containerd.service` (and `/run/docker/` for
`docker.service`, beside `/var/lib/containerd/` and `/var/lib/docker/`); a
unit's directories share one tag, so a crossing whose every file lay in
them — containerd's removal of a task takes its bundle under `/run` and its
snapshot under `/var/lib` in one window — by the unit's own cgroup, raises
nothing. Another unit's burst there, or a container's (a cgroup below the
unit's), still counts; add a runtime's other directories with
`+<unit>.service <directory>/` lines in the signed
`mass-write-carveout.local`. With Docker's own `overlay2` image store,
dockerd writes each container's init files through the layer's overlay
mount, which the kernel does not place under `/var/lib/docker`: twenty or
more containers started and removed within a minute raise ENGAGED (a known
false positive; a posture change only in the observe-only profile — a CI
host running Docker builds may meet it).

**The cpuset controller on kernels before 6.5 (NN-L-AT-001 `sched`, lot
348).** At a container's start systemd, runc and containerd-shim enable the
cgroup v2 controllers for the new cgroup's ancestors (`+cpuset +cpu +io …`
written to each `cgroup.subtree_control` from the root down). The kernel
then re-homes every task of the subtree in its own cgroup, and before 6.5
the cpuset controller asks the scheduling hook of each — the agent's
threads among them, whose CPUs and memory nodes nothing changes. The agent
refused it, so on Ubuntu 22.04 (5.15) `+cpuset` was never enabled at the
root and each start was recorded three or four times as an attempt on the
agent (High, "denied in kernel"); `docker run --cpuset-cpus` had no cpuset
to set. The agent now marks the thread that writes a `cgroup.subtree_control`
for that write's length (an fentry on `cgroup_subtree_control_write`; the
mark goes at the write's end, and after five seconds at the latest) and lets
through only that thread's scheduling check. Any other process changing the
agent's affinity, policy or priority (`taskset -p`, `chrt`, `sched_setattr`,
a write of `/proc/<pid>/timerslack_ns`) is refused and signed as before, and
`cpuset.cpus`/`cpuset.mems` of the agent's unit and slice stay refused
outside a trusted-installer window (lot 273c). Where the mark cannot be
attached (a kernel whose BTF lacks the function), the controller change is
refused as before and the journal says so (`cgroup controller mark is not
attached`). From 6.5 the kernel no longer asks: nothing changes there.

## The security tradeoff (read before enabling)

R013 is the detection for the **CVE-2019-5736** class of attack: an
attacker overwrites or drops a modified `runc` binary in a writable
path and rides it to host root. Adding `+runc` to the allowlist exempts
every `runc` in a root-owned system tree (`/usr/local`, `/opt`, …) from
R013 **everywhere on that host**; a copy in a writable path is still
judged (the allowlist reads what the kernel executed, not the name).

So: enabling the overlay trades away escape-to-host detection for
`runc` in exchange for silencing the false positives. Do it only where
container activity genuinely produces them, and scope it as narrowly as
you can. The agent's own anti-tamper LSM hooks, canary detection, and
the rest of the rule engine remain in force regardless.

## How to enable

The installer drops a documented template at
`/etc/northnarrow/process-comm-allowlist.local.example`. Since the agent
loads an overlay only when a key with the `config-manage` role signed it,
edit a copy, store it signed through the agent, and restart:

```sh
cp /etc/northnarrow/process-comm-allowlist.local.example /tmp/allow
$EDITOR /tmp/allow                                         # uncomment +runc, etc.
sudo nn-admin config overlay set process-comm-allowlist --file /tmp/allow --key <config-manage key>
sudo nn-admin trusted-installer-grant --key <trusted-installer key> --window-secs 120
sudo systemctl kill -s SIGTERM northnarrow-agent          # the watchdog starts it again
sudo nn-admin config overlay status                        # process-comm-allowlist  signed
```

A file copied into `/etc/northnarrow` by hand without a signature is
ignored at the next start (the agent boots on the shipped allowlist) and
recorded as an `unauthorized_overlay` integrity finding.

Overlay entries are prefixed:

| Prefix | Meaning |
|--------|---------|
| `+name` | add a program to the allowlist (exempt from R011–R017 and the io_uring and BPF rules) |
| `-name` | re-enable detection on a program the `.v1` default allowlists |

A name is matched on what the kernel executed: the executable's
basename, or the script's an interpreter runs, and that file must lie in
a root-owned system tree (`/usr`, `/opt`, `/bin`, `/sbin`, `/lib`,
`/snap`, `/nix/store`). A process that only names itself like an entry
is not exempt. The kernel's 15-character form of a longer name still
matches it (`containerd-shim` covers `containerd-shim-runc-v2`). Of the
container-runtime names, only `runc` is an R013 target today; the others
are listed for parity / forward compatibility and are harmless but
unnecessary for silencing R013.

## How to verify it is active

The agent logs every overlay change at boot (`+`/`-` entries applied).
After a restart, check the journal:

```sh
journalctl --namespace=northnarrow -u northnarrow-agent --since "5 min ago" | grep -i allowlist
```

## Re-tightening

If the host stops running containers, store an overlay without the
entries (`nn-admin config overlay set process-comm-allowlist --file <empty
file> …`) and restart the agent. R013 escape-to-host detection on `runc`
is restored at that start.

## Related

- `configs/process-comm-allowlist.v1` — shipped conservative default.
- The allowlist overlay design (§13 Q3 of the design note, in the source
  repository, not shipped with the release):
  <https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/TAPPA10_5_DETECTION_RULES_AT_SCALE_DESIGN.md>.
- `crates/nn-core/src/decision/rules/r013_namespace_escape_tooling.rs` — the
  rule and its allowlist gate.
