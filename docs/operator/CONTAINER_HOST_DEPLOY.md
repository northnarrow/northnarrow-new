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

- the memfd, sealed against writing, shrinking and growing, is the whole
  image of an installed runtime (`runc` or `crun` in `/usr/bin`, `/usr/sbin`,
  `/bin`, `/sbin` or `/usr/local/bin`), byte for byte — the exec pump
  compares it at the exec, when the exec's parent runs an installed
  runtime or its manager;
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
program, an unsealed copy, a copy of runc run from a shell (`python3` executing runc's bytes from a memfd), a runtime outside
those directories (k3s's bundled `runc`, a snap's) and a clone the agent
could not compare (the process gone at once, more than about seventeen
container starts in a second), and every one on an agent in tracepoint mode
(no LSM identity), stay Critical. What remains possible: the
bytes are compared a few milliseconds after the exec, so a process holding
a writable descriptor of an unsealed memfd could rewrite and seal it in
between. It would have to be the installed runtime itself, started by its
manager, with code injected into it (an `LD_PRELOAD` the manager passes, a
root `ptrace`).

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
that `LD_LIBRARY_PATH` (each entry under `/var/lib/containerd/` or
`/opt/containerd/`). The module file is still judged at its load: R018
records a packaged module, and a module no package installed, or a file out
of the module tree, is Critical; the kernel's signature policy refuses an
unsigned one. Any other module, a library path of the caller's,
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
