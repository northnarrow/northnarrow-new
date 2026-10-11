# Install, upgrade, uninstall

NorthNarrow's anti-tamper layer makes the host actively resist changes to
the agent: the binaries, the units and `/etc/northnarrow` are in
`PROTECTED_INODES` (write/unlink/rename denied by LSM hooks), the agent
and watchdog pids are in `PROTECTED_PIDS` (every userspace signal
denied), and `/var/lib/northnarrow` carries `chattr +i`. That is the
point of the product — and it means the three lifecycle operations must
follow a precise order. The scripts below encode it; do not improvise
with `rm -f` or `kill -9`, they are denied by design.

| Operation | Command | Keeps keys / audit chain / state |
|---|---|---|
| Fresh install | `sudo ./deploy/install.sh` then `systemctl enable --now …` | n/a (bootstraps them) |
| Upgrade in place | `sudo ./deploy/install.sh --upgrade` | **yes** |
| Uninstall | `sudo ./deploy/uninstall.sh` | **yes** (`/etc/northnarrow`, `/var/lib/northnarrow`) |
| Retire the host | `sudo ./deploy/uninstall.sh --purge` | no — everything removed |

All three assume `cargo xtask build --release` (or the release tarball)
produced `target/release/{northnarrow-agent,northnarrow-watchdog,nn-admin}`.

## 1. Fresh install

`install.sh` copies binaries, units, the journald namespace config, the
rule and allowlist files, the canary templates and the ten inert
control-surface bait files; bootstraps an admin keypair if
`admin.pub` is absent (move `admin.key` off the host — see
`COMBAT_RECOVERY.md` §1); and does **not** start anything. Enable the
agent first, then the watchdog.

If the units are already active, `install.sh` refuses with
`Re-run with --upgrade`: with the hooks up every copy below would fail
with `Operation not permitted` halfway through.

## 2. Upgrade in place

```sh
sudo ./deploy/install.sh --upgrade
```

What it does, in order:

1. records which units are active and prints installed → new version;
2. stops the **watchdog first** (stopping the agent alone makes the
   watchdog respawn it), then the agent;
3. removes `/sys/fs/bpf/northnarrow`: the LSM programs survive agent
   restarts only through their pinned links, so dropping the pin root
   detaches them; waits until `bpftool prog show` reports 0 LSM programs
   (30 s budget, fails loudly otherwise);
4. runs the normal install (binaries, units, configs; `chattr +i` on the
   state dir is lifted and re-applied by the new agent at boot);
5. starts the agent, waits 3 s, starts the watchdog, prints their state.

Preserved across the upgrade: `admin.pub`, `agent.sig.key`, `agent_id`,
`audit.log` (the new agent appends a signed `agent_boot` entry — review
it with `nn-admin audit verify`), every chain log under
`/var/lib/northnarrow`, and every `*.local` overlay. The window with no
hooks attached is the few seconds between step 3 and the new agent's
boot; it is the same window a reboot has.

The lab verifies this path on every nightly (`nn-lab.sh upgrade-check`):
refusal without the flag, pid change, new audit entry, identity files
unchanged, ≥ 7 LSM programs and `PROTECTED_PIDS` re-pinned afterwards.

## 3. Uninstall

```sh
sudo ./deploy/uninstall.sh            # keep /etc/northnarrow + /var/lib/northnarrow
sudo ./deploy/uninstall.sh --purge    # remove them too (and the namespace journal)
```

Order: disable + stop watchdog then agent → drop the pin root and wait for
the LSM set to drain → `chattr -R -i` on state and config → remove
binaries, units, `journald@northnarrow.conf`, `/run/northnarrow` and the
ten bait files → `daemon-reload`. Without `--purge` the admin key, the
signed audit chain and the chain logs stay on disk: they are evidence and
identity, and a later reinstall picks them up (`install.sh` leaves an
existing `admin.pub` untouched). `--yes` skips the confirmation prompt.

If an unrelated NorthNarrow process (an e2e test, a manual
`northnarrow-agent` run) still holds the LSM programs, the script stops
and names the condition instead of leaving a half-removed host.

The lab verifies `uninstall.sh --purge --yes` leaves no binary, unit, pin,
LSM program, config, state or bait behind, then reinstalls
(`nn-lab.sh uninstall-check`).

### 3.2 Lost events are visible (`ringbuf drops`)

Every kernel sensor hands events to the agent through a ring buffer; when
the agent falls behind the producer cannot reserve an entry and the event
is lost. Each of the eleven rings now counts its own losses; the agent
reads the counters every 10 s, logs every increase at WARN naming the
ring, and `nn-admin status` prints the running total with the per-ring
breakdown (`ringbuf drops : 0` is the healthy line). A non-zero counter
is a coverage gap, not a cosmetic number: the lab soak treats it as a
note and a production host should alert on it.

### 3.3 The agent's BPF objects are guarded (`bpf_map`)

Root with `bpftool` could rewrite the maps the anti-tamper reads
(`PROTECTED_PIDS`, the override tokens) and unprotect the agent without
touching a file. Since lab PR 28 the `bpf_map` LSM hook denies any
**write** handle on one of the agent's own maps to a process that is not
the agent or the watchdog: `bpftool map update/delete` fails with
`Operation not permitted`, and the attempt is an anti-tamper denial
(`operation=bpf_map`, map id as the target) in the audit chain and the
posture ladder, like an unlink attempt on `/etc/northnarrow`. Read-only
handles are allowed in principle, but `bpftool` opens every map read-write,
so `bpftool map dump` on the agent's maps fails too: use `nn-admin status`
and the agent's own telemetry instead. The agent's own binaries (watchdog,
`nn-admin`, matched by executable inode) are exempt. The `bpf` hook also records who
drives BPF on the host — program loads, attaches, link create/detach,
handles-by-id on the agent's maps — as `NN-L-BPF-001/002` alerts (Log).

**Operator visibility trade-off.** `bpftool` takes read-write handles even
when it only reads (`map show`, `map dump`, `map show pinned …`), so in
enforce mode `bpftool map show` fails at the first NorthNarrow map it
enumerates (bpftool stops at the first error) and each attempt is an
anti-tamper denial → posture COMBAT (INVESTIGATE stage, no isolation).
Read the agent's state with `nn-admin status` / `nn-admin host-check`;
inspect foreign maps with `bpftool map show id <n>`; for a debugging
session set `NN_BPF_DEFENSE_OBSERVE=1` (restart required).

Like every anti-tamper hook the guard is pinned and **outlives the agent**:
stopping the unit does not lift it, and a replacement agent binary (another
inode) would be denied its own registration — which is why `install.sh
--upgrade` purges the pin root and waits for the LSM programs to detach
before copying binaries. Do the same if you ever replace the binaries by
hand: `rm -rf /sys/fs/bpf/northnarrow`.

Diagnosis mode: `NN_BPF_DEFENSE_OBSERVE=1` in the unit environment turns
the guard into an observer (nothing denied, a `foreign_map_write` record
instead); test builds (`debug-trigger`) run in that mode because the e2e
fixtures unprotect pids with `bpftool`; `NN_BPF_DEFENSE_ENFORCE=1` forces
the deny in a test build (lab checks of the deny path). The guard counts in the LSM
health: if it does not attach the agent refuses to start like for any
other deny hook (`NN_ANTI_TAMPER_ALLOW_DEGRADED=1` to override).

## 4. What still needs a reboot

- Enabling the `bpf` LSM (`lsm=…,bpf` on the kernel command line) the
  first time — see `docs/TAPPA7_PREREQ.md`.
- A kernel upgrade: the agent revalidates BTF offsets at boot and refuses
  to start on a mismatch rather than run with wrong offsets; the
  supported-kernel matrix is the next item on the reliability list.

## 5. Release artefacts and how to verify them

Every tag `v*` runs `.github/workflows/release.yml`, which builds with a
locked lockfile and pinned toolchains, and attaches to the GitHub release:

| File | What it is |
|---|---|
| `northnarrow-<ver>-x86_64-linux.tar.gz` | the release tree: binaries, eBPF object + provenance stamp, `deploy/` (install/uninstall/units), `configs/`, operator docs, licences. Extract and run `sudo ./deploy/install.sh` (or `--upgrade`) unchanged — every preflight still applies. |
| `northnarrow-<ver>-x86_64-linux.{agent,watchdog}.sbom.cdx.json` | CycloneDX SBOMs of the two daemons (the agent one covers `nn-admin` too) |
| `SHA256SUMS` | checksums of the files above |

Each artefact carries a SLSA build-provenance attestation signed by
GitHub's OIDC identity for this repository and workflow. Verify before
installing:

```sh
sha256sum -c SHA256SUMS
gh attestation verify northnarrow-<ver>-x86_64-linux.tar.gz --repo northnarrow/northnarrow-new
```

The attestation binds the file digest to the exact commit, workflow and
runner that produced it; a tarball rebuilt elsewhere, or modified after
the fact, fails the check. Pull requests that touch `deploy/`, `xtask/`
or the workflow run the same job as a dry run (artefacts on the workflow
run only).

### 5.1 `install.sh` verifies the release itself

The manual commands above stay valid, but since lab PR 21 the installer
performs the checks and refuses to touch the host when one fails:

1. **Tree manifest** — the tarball ships `MANIFEST.sha256` (every file
   hashed by `mk-tarball`); `install.sh` runs `sha256sum -c` on the
   extracted tree. A corrupted or edited tree is refused.
2. **SHA256SUMS** — if the tarball is next to the tree (`../<tree>.tar.gz`,
   or `--tarball FILE`) and `SHA256SUMS` is next to it (or `--sums FILE`),
   the tarball hash is checked against it.
3. **SLSA attestation** — with `gh` 2.49+ (online, or offline with
   `--attestation BUNDLE` from `gh attestation download`) or `cosign`
   plus a bundle, the provenance is verified and bound to this
   repository's release workflow (`--signer-workflow`). Without a
   verifier the installer says so; `--require-attestation` turns that
   into a refusal.

The strongest level reached — `attested`, `checksums`, `manifest`,
`source-tree` (no `MANIFEST.sha256`: a developer tree, the lab) or
`unverified` (`--no-verify`) — is written with the SHA-256 of every
installed binary and of the eBPF object to
`/etc/northnarrow/install-manifest.json`, which the anti-tamper hook
protects like the rest of `/etc/northnarrow`.

**At every boot the agent closes the loop**: it hashes its own executable,
the watchdog and `nn-admin` under the recorded `bin_dir` and compares the
embedded eBPF object hash with the manifest. The result is written in the
signed `agent_boot` audit entry (`binary_integrity`, `install_provenance`).
A mismatch — the running file is not the one the installer verified — or
an unreadable manifest refuses the boot (exit 78); `NN_ALLOW_UNVERIFIED_BINARY=1`
turns that into a WARN on a development host. A binary started from
outside `bin_dir` (a test fixture) is not compared.

```sh
tar xzf northnarrow-<ver>-x86_64-linux.tar.gz && cd northnarrow-<ver>-x86_64-linux
sudo ./deploy/install.sh --require-attestation          # tarball + SHA256SUMS found in ..
sudo ./deploy/install.sh --upgrade --tarball /path/to/northnarrow-<ver>-x86_64-linux.tar.gz \
    --sums /path/to/SHA256SUMS --attestation /path/to/bundle.jsonl
nn-admin audit verify --from /etc/northnarrow/audit.log --agent-sig-key /etc/northnarrow/agent.sig.key
```

Known limits: one architecture (x86_64) and no `.deb`/`.rpm` yet — the
units and the anti-tamper inode list hard-code `/usr/local/bin`, which a
distribution package must not use; moving the binaries to `/usr/bin`
(and teaching the agent its own path) is the prerequisite, tracked in the
review register. The tarball itself is not byte-reproducible (file mtimes
are preserved because the staleness guard needs them); the provenance
attestation is the integrity anchor instead.

