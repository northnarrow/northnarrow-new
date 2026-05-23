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
`runc` from R013 **everywhere on that host**, including those
attacker-controlled non-standard paths.

So: enabling the overlay trades away escape-to-host detection for
`runc` in exchange for silencing the false positives. Do it only where
container activity genuinely produces them, and scope it as narrowly as
you can. The agent's own anti-tamper LSM hooks, canary detection, and
the rest of the rule engine remain in force regardless.

## How to enable

The installer drops a documented template at
`/etc/northnarrow/process-comm-allowlist.local.example`. Copy it to the
live overlay path and uncomment the runtimes you run:

```sh
sudo cp /etc/northnarrow/process-comm-allowlist.local.example \
        /etc/northnarrow/process-comm-allowlist.local
sudoedit /etc/northnarrow/process-comm-allowlist.local   # uncomment +runc, etc.
sudo systemctl restart northnarrow-agent
```

Overlay entries are prefixed:

| Prefix | Meaning |
|--------|---------|
| `+comm` | add `comm` to the allowlist (exempt from R011–R017) |
| `-comm` | re-enable detection on a `comm` the `.v1` default allowlists |

Comms are bare process names, **TASK_COMM_LEN-truncated to 15 chars**
(e.g. `containerd-shim-runc-v2` is reported by the kernel as
`containerd-shim`). Of the container-runtime comms, only `runc` is an
R013 target today; the others are listed for parity / forward
compatibility and are harmless but unnecessary for silencing R013.

## How to verify it is active

The agent logs every overlay change at boot (`+`/`-` entries applied).
After a restart, check the journal:

```sh
journalctl -u northnarrow-agent --since "5 min ago" | grep -i allowlist
```

## Re-tightening

If the host stops running containers, remove the entries from
`/etc/northnarrow/process-comm-allowlist.local` (or delete the file)
and restart the agent. R013 escape-to-host detection on `runc` is
restored immediately.

## Related

- `configs/process-comm-allowlist.v1` — shipped conservative default.
- `docs/design/TAPPA10_5_DETECTION_RULES_AT_SCALE_DESIGN.md` §13 Q3 —
  the allowlist overlay design.
- `agent/src/decision/rules/r013_namespace_escape_tooling.rs` — the
  rule and its allowlist gate.
