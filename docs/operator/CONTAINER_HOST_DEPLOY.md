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
can write (k3s's bundled `runc`, a snap's, a link to a user's file), a clone
the agent could not compare because the process was gone, every one on an
agent in tracepoint mode (no seals read at the exec) and every one on a
kernel whose BTF lacks `shmem_inode_info` stay Critical.

The compares have a budget of their own: each user but root may spend
64 MiB a second (about two runc 1.1 starts: runc is read twice, ~30 MiB),
all of them together leave root 256 MiB of the 512 MiB a second, and root's
starts (Docker's, rootful Podman's) may spend the rest. A memfd past the
budget — every fact above holds, its bytes not compared, so it may be any
program of the runtime's length — is "not compared (budget)": root's (uid 0
of the initial user namespace) is recorded High, never killed; any other
uid's stays the Critical kill, since a user can spend its own share on
purpose (decoy OCI hooks of genuine runc copies, then a sealed payload
padded to runc's length). No user's container loop can make root's Docker
starts Critical; a rootless user's container start past its own share (a
third runc 1.1 start in a second) is killed as before lot 347.

Residual, named: root spending its own budget (512 MiB a second of
compares), then executing a memfd of its own under the runtime, is recorded
High, not killed — root, who needs no such route.

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
