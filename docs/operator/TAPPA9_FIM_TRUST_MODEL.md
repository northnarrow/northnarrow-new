# NorthNarrow FIM trust model (Tappa 9 C7)

This is the operator-facing companion to
`docs/design/TAPPA9_FIM_DESIGN.md`. Read it before deploying or
customising the File Integrity Monitoring (FIM) module — two of the
design's RFC resolutions (§13 Q5 trust-on-first-use baselines and
§13 Q7 operator overlay) bake-in trust assumptions that operators
must understand to operate the agent honestly.

## TL;DR

- The agent baselines watched paths on first boot. The baseline is
  trusted **as-is** — if the host was already compromised when the
  agent was first installed, the compromise is in the baseline and
  drift detection will NOT flag the originally-bad file. Treat
  first-boot baselines as TOFU.
- Operators may extend OR narrow the curated path list via
  `/etc/northnarrow/fim-paths.local` (`+/path` add, `-/path`
  disable). Every disabled-default emits a `WARN` at every agent
  boot so the overlay can't silently hide a regression.

## First-boot baselines (§13 Q5)

When the agent starts and the file `/var/lib/northnarrow/fim_baseline.jsonl`
is empty (the `install.sh` bootstrap creates the file as a zero-byte
placeholder for `PROTECTED_INODES`; the chain stays empty until the
first recompute), the agent fires a one-shot
`RecomputeReason::FirstBootTofu` request on the in-process recompute
channel. The boot-time recompute task walks every effective watched
path, computes SHA-256 + lstat metadata, and appends one
`BaselineEntry` per path to the chained log.

**Trust assumption:** the host filesystem state at first boot is
what FIM will subsequently compare against. If the attacker is on
the box before the agent installs, the attacker's modifications
become the trusted baseline. NorthNarrow cannot detect what it
didn't observe.

**Mitigations operators have today:**

1. Install the agent as part of host provisioning (kickstart /
   cloud-init / Ansible role), before any operator workload runs.
   The provisioning timeline is the smallest TOFU window.
2. Run `nn-admin fim baseline` manually after a known-good moment
   (e.g., post-`apt upgrade && reboot` on a clean image). The
   chain APPENDS — old entries stay as audit history; the latest
   entry per path is the active baseline.
3. Cross-check the baseline against an external known-good
   manifest (a future V1.1 `seed-from-file` op will accept a
   signed SHA-256 manifest at install time; until then, operators
   can `diff` the baseline JSONL against any out-of-band source
   manually).

**What V1.0 does NOT support:** install-time baseline computation
that ships a SHA helper alongside the agent binary. Decision per
§13 Q5: the install-time path forces shipping a SHA-256 helper
without the agent + adds a 200 ms install block + STILL doesn't
solve "host might already be compromised" honestly. First-boot
TOFU + this disclosure is the deliberate tradeoff.

## Operator overlay (§13 Q7)

`/etc/northnarrow/fim-paths.local` is the **optional** operator
overlay. Since Tappa 10.8 the agent reads it (at boot and on every signed
`fim baseline`) only when `fim-paths.local.sig` proves that a key with the
`config-manage` role signed this exact content: store it with
`nn-admin config overlay set fim-paths --file <file> --key <key>`; an
unsigned or edited file is ignored (shipped watch set) and recorded as an
`unauthorized_overlay` integrity finding. Format:

```text
# Comments and blanks are ignored. Lines are absolute paths
# with a single-character directive prefix:
#   +/abs/path   → add (also the default if no prefix)
#   -/abs/path   → disable a default-list entry
+/opt/myapp/bin/myapp
+/etc/myapp/config.toml
/etc/myapp/secrets.toml     # bare path is also `add`
-/var/log/wtmp              # we rotate aggressively; skip the truncation check
-/var/log/btmp
```

The agent merges the overlay onto the default list at every boot:

1. Read `/etc/northnarrow/fim-paths.v1` (curated default, ~100
   paths shipped by `install.sh`).
2. Apply every `-` line: if the path is in the default list, drop
   it from the effective set AND emit
   `WARN fim paths-config: default path <P> disabled by operator
    config (§13 Q7)`.
3. Apply every `+` line (or bare-path line): insert into the
   effective set.

**Disabled defaults are deliberately loud.** The boot-time WARN
fires on EVERY agent restart so the operator can't silently hide a
regression: a `disable: /etc/passwd` line stays visible in the
journal forever. The `nn-admin fim status` subcommand also reports
the disabled-default count so operators can audit the current
overlay without parsing `/etc/northnarrow/fim-paths.local`
manually.

**`-` lines targeting paths not in the default list** are no-ops
+ surface a separate WARN
(`fim paths-config: operator `disable:` targets a path not in
the v1 default list — no-op (check spelling)`). Common cause: the
operator typo'd the path or is trying to disable an `+`-added
path — the disable directive is for *defaults only*.

## Writers that are recorded, not killed (reviews 49, 52 and 83)

A write that a FIM rule answers with a kill is still written: the file
changes before the writer is killed. For the writers below, the kill only
broke legitimate work, so the rule records the write instead.

| Writer | Rules | Recorded as |
|---|---|---|
| The package manager: `dpkg`, `rpm`, `apt`, `dnf`, `yum`, `snapd`, `packagekitd` and their children (kernel-resolved lineage) | system binaries, setuid binaries, kernel and PAM modules, sensitive configs, cron drop-ins, units, timers, file capabilities | Log, Low |
| An interactive administrator session: `sudo` or `su` in the lineage, a login uid and a terminal | sensitive configs (NN-L-FIM-003), cron drop-ins (-007), units (-009), timers (-023), file capabilities (-025) | Log, at the rule's severity |
| An account tool (`passwd`, `useradd`, `usermod`, `chpasswd`, `systemd-sysusers`, libuser's `l*` tools…), told by its exe | `/etc/passwd` and `/etc/shadow` (NN-L-FIM-003), `/var/log/lastlog` (-018) | Log: Low when a user other than root ran it, else the rule's severity |

Everything else keeps the rule's response. That includes:

- a service;
- a cron job;
- a command run without a terminal (`ssh host 'sudo …'`, most automation);
- a root process with no `sudo`/`su` above it;
- `doas` and `pkexec`, which replace themselves with the command and so leave no trace in the lineage.

The `ld.so.preload`, `authorized_keys`, bait and credential rules are never relaxed.

An administrator session's configuration changes still raise the posture to ENGAGED and stay in the signed detection chain. They do not corroborate each other into COMBAT: editing `sshd_config` and then adding a unit is routine work. A signal of another kind in the same login session (an offensive tool, exfiltration, an exec from `/tmp`) still takes the next one to COMBAT.

Whoever holds an administrator's session and sudo password is that administrator to these rules.

## A store's own client (review 85)

The credential rules (cloud CLIs, browsers, password managers, GnuPG) and
the login-record rules (`wtmp`, `btmp`, `lastlog`) do not act on a
store's own client, or on the login machinery. The agent tells them by
what the kernel executed, never by the name a process gives itself:

- a binary client: its exe, inside a root-owned system tree (`/usr`,
  `/opt`, `/snap`, …), named like the client (`aws`, `firefox`, `gpg`,
  `sshd-session`);
- a client written in a scripting language: the interpreter's exe and
  the script it runs, both in such a tree (`/usr/bin/python3` running
  `/usr/lib/google-cloud-sdk/lib/gcloud.py`);
- a client that bundles its runtime: its exe under that tree
  (`/opt/az/`).

An inline program (`python3 -c …`), a module run from the caller's path,
or a copy outside a system tree is not a client. A client reading another
user's credentials is acted on like any other reader.

## File capabilities (review 86)

A file capability (`security.capability`) gives whoever runs the file the
capabilities it names: `cap_setuid` on a copy of an interpreter is a root
shell for every user. The agent sees every capability set, by any route
(`setcap`, a direct `setxattr`, `cp --preserve=xattr`, `tar --xattrs`),
and NN-L-FIM-025 strips it again. It is Critical when the set holds a
root-equivalent capability, else High. A namespaced capability (one that
applies only inside a user namespace, e.g. a rootless container build) is
only recorded.

Capabilities installed by the package manager, and those an administrator
grants from an interactive sudo session, are recorded and kept. To grant
one any other way (from a script, or a configuration-management run), open
the trusted-installer window first, or expect the capability to be removed.

## What FIM does not protect against

- **Host already compromised at install time** (TOFU window —
  documented above).
- **The agent binary itself** — Tappa 7 task 5 + 7 LSM hooks
  protect `/usr/local/bin/northnarrow-agent` against in-place
  tamper. FIM observes paths that are NOT the agent binary.
- **Paths the operator removed from the overlay** — disabled
  defaults stay loud in the journal but ARE in fact unwatched.
- **Recursive directory drift** — V1.0 watches the curated ~100
  paths (no recursive subtree). V1.1 adds opt-in `recurse: true`
  per-entry. Adding `/etc/passwd` to the watch list catches
  modifications to that exact path; it does NOT catch new files
  appearing under `/etc/` more generally.

## Audit + integrity guarantees

- Every `BaselineEntry` is signed with the agent's Ed25519
  identity key (Tappa 8 B1) and chained via `prev_hash` /
  `entry_hash`. The off-host `audit verify` tooling extended in
  Tappa 9 C8 will reject a tampered baseline chain.
- The `fim_baseline.jsonl` + `fim_drift.jsonl` files are
  registered in `PROTECTED_INODES` (Tappa 9 C7 — see
  `agent/src/anti_tamper/filesystem.rs::STATE_PROTECTED_FILES`).
  An attacker with root cannot truncate, unlink, rename, or chmod
  the files; the LSM hook denies the syscall before it reaches the
  filesystem.
- The `fim-paths.v1` + `fim-paths.local` files are likewise in
  `PROTECTED_INODES` (`ETC_PROTECTED_FILES`) so an attacker can't
  silently widen or narrow the watch set between agent restarts.
  Operator changes go through `nn-admin config overlay set fim-paths`
  (signed, stored by the running agent, applied at its next start).

## See also

- Design doc: `docs/design/TAPPA9_FIM_DESIGN.md` (§5 LSM hooks,
  §6 userland, §13 RFC resolutions).
- Rule catalogue: `agent/src/fim/rules.rs` (NN-L-FIM-001..014).
- Install script: `deploy/install.sh` (Tappa 9 C7 additions —
  drops `fim-paths.v1` + bootstraps the two chained logs).
- Operator commands: `nn-admin fim baseline`, `nn-admin fim
  report`, `nn-admin fim status` (Tappa 9 C6 + C7).
