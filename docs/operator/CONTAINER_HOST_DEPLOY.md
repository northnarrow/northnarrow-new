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
location — some bundle layouts and older runtimes do.

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
