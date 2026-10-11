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

## 3.1 Host hardening checks (`nn-admin host-check`)

The agent's anti-tamper (signals, ptrace, inode mutations denied to root
by BPF LSM) holds only while root cannot rewrite the kernel at runtime.
Those doors are closed by the host, not by the agent, so the installer,
the agent at boot and `nn-admin` read the same eight settings and say
what is missing and how to fix it:

| Check | Expected | Why |
|---|---|---|
| BPF LSM in the LSM list | `bpf` present | the deny hooks cannot attach otherwise |
| Kernel lockdown | `[integrity]` or stronger | blocks unsigned modules, kexec of unsigned kernels, `/dev/mem` |
| Unprivileged BPF | `kernel.unprivileged_bpf_disabled` = 1 or 2 | only privileged processes load BPF |
| Module signature | `module.sig_enforce` = Y | an unsigned module is the classic way to blind a kernel sensor |
| UEFI Secure Boot | enabled | anchors the boot chain; turns on lockdown and module signing on most distros |
| IMA | measurements > 0 | a replaced binary fails before it runs (appraise) or is at least measured |
| kexec | `kernel.kexec_load_disabled` = 1 | no kernel swap without a reboot |
| bpffs | mounted once at `/sys/fs/bpf` | a second bpffs can hide pinned objects from the inventory |

`install.sh` prints the table after installing; the agent logs one WARN
per missing setting at boot; `nn-admin status` shows the count and
`nn-admin host-check [--json]` the full table (exit 2 when something is
missing). A check that cannot be determined (no EFI, IMA not compiled in)
is reported as `n/a`, not as a warning. The lab guests show the expected
gaps of a cloud image (no Secure Boot, lockdown off, kexec allowed); a
production host should clear them — the Scout Tappa will automate the
fixes, this is the measurement.

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

