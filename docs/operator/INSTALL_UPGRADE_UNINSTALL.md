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
| Upgrade in place | `sudo ./deploy/install.sh --upgrade --grant-key <admin.key>` | **yes** |
| Uninstall | `sudo ./deploy/uninstall.sh` | **yes** (`/etc/northnarrow`, `/var/lib/northnarrow`) |
| Retire the host | `sudo ./deploy/uninstall.sh --purge --grant-key <admin.key>` | no — everything removed |

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
sudo ./deploy/install.sh --upgrade --grant-key /path/to/admin.key
```

The key must carry the `trusted-installer` role (the one `install.sh`
bootstraps does; see `COMBAT_RECOVERY.md` §1.1 for older keys). Without
`--grant-key` the upgrade stops at step 3 with the recovery line, because
the pin root is protected (review entry 39).

What it does, in order:

1. records which units are active and prints installed → new version;
2. opens the **trusted-installer window** (300 s) through the running
   agent's socket with `--grant-key` — a signed, audited grant that lets
   the next steps touch what the anti-tamper protects (binaries, units,
   `/etc/northnarrow`, the pin root); then stops the **watchdog first**
   (stopping the agent alone makes the watchdog respawn it), then the
   agent;
3. removes `/sys/fs/bpf/northnarrow`: the LSM programs survive agent
   restarts only through their pinned links, so dropping the pin root
   detaches them; the pin root is in the protected-inode set, so this
   needs the window of step 2 (or a reboot); waits until `bpftool prog
   show` reports 0 LSM programs (30 s budget, fails loudly otherwise);
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
sudo ./deploy/uninstall.sh --grant-key /path/to/admin.key            # keep /etc/northnarrow + /var/lib/northnarrow
sudo ./deploy/uninstall.sh --purge --grant-key /path/to/admin.key    # remove them too (and the namespace journal)
```

Order: open the trusted-installer window (`--grant-key`, same key and
role as the upgrade; without it the pin root cannot be removed and the
script stops with the recovery line) → disable + stop watchdog then agent
→ drop the pin root and wait for
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

### 3.1 Host hardening checks (`nn-admin host-check`)

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

**Links (second half).** The only object that can *detach* one of the
agent's LSM hooks is a handle to its BPF link, and there are two ways to
get one: `LINK_GET_FD_BY_ID` (`bpftool link detach id N`) and `OBJ_GET` on
the link's pin (`bpftool link detach pinned /sys/fs/bpf/northnarrow/link_*`).
In enforce mode the `bpf` hook refuses both to a foreign process
(`EPERM`, anti-tamper denial `operation=bpf_link`, link id as the target or
0 for the pinned route). The ids of maps, programs and links are kept with
their kind, since the kernel numbers the three spaces independently.
Program handles stay allowed (`bpftool prog show` keeps working; a program
fd cannot detach anything). Every `LINK_GET_FD_BY_ID` on one of our links
is refused, so `bpftool link show` stops at the first NorthNarrow link, like
`map show` above. (For the record: the kernel refuses `LINK_DETACH` on
LSM and tracepoint links anyway — `bpftool link detach` answers "Operation
not supported" — so the handle deny is defence in depth; the route that
actually dropped the hooks was the pin, below.) The pin-name check is
name-based on purpose (no path walk in the kernel): a path longer than
255 bytes or a symlink elsewhere that points at a pin is not recognised —
acceptable for a handle that cannot detach or update anything, while the
pin files themselves are protected by inode. Independently of the mode,
the agent re-checks every registered link every 10 s through its own fd or
its pin (no `CAP_SYS_ADMIN` needed, the unit does not have it) and, if one
is gone or has no program any more, logs an ERROR and appends a signed
audit entry (`op=bpf_link_missing`): a detached hook is an alert even when
the deny path is off (observe mode, tests).

**The pin root is protected (review entry 39).** The hooks survive the
agent's death only through their pins, and `systemctl stop` of both units
is allowed (the PID-1 carve-out), so `rm -rf /sys/fs/bpf/northnarrow`
afterwards used to drop every hook — the two-command disable. The agent
now registers the pin root and every pin in the protected-inode set:
unlink, rmdir, rename and setattr are denied to any process that is not
the agent or the watchdog, unless the **trusted-installer window** is open.
That window is the authorised way to purge: `nn-admin
trusted-installer-grant --key <key with the trusted-installer role>
--window-secs 300` while the agent runs (the grant is signed, single-use
and audited, and lives in a pinned map, so it outlasts the agent's stop),
then stop the units and remove the pin root. `install.sh --upgrade
--grant-key` and `uninstall.sh --grant-key` do exactly this. A reboot also
clears bpffs. The key `install.sh` bootstraps carries the role; a key
created earlier needs `trusted-installer` added to its `admin.pub` line
(the file is itself protected: edit it with the units disabled across a
reboot, or through `rotate-keys add`).

Like every anti-tamper hook the guard is pinned and **outlives the agent**:
stopping the unit does not lift it, and a replacement agent binary (another
inode) would be denied its own registration — which is why `install.sh
--upgrade` purges the pin root (inside the window) and waits for the LSM
programs to detach before copying binaries.

Diagnosis mode: `NN_BPF_DEFENSE_OBSERVE=1` in the unit environment turns
the guard into an observer (nothing denied, a `foreign_map_write` record
instead); test builds (`debug-trigger`) run in that mode because the e2e
fixtures unprotect pids with `bpftool`; `NN_BPF_DEFENSE_ENFORCE=1` forces
the deny in a test build (lab checks of the deny path). The guard counts in the LSM
health: if it does not attach the agent refuses to start like for any
other deny hook (`NN_ANTI_TAMPER_ALLOW_DEGRADED=1` to override).

### 3.4 The agent proves its own coverage (`telemetry probe`)

A sensor that stops delivering is worse than one that was never there:
the host looks quiet. Every 60 s the agent runs a child of its own binary
(`northnarrow-agent --telemetry-probe <nonce>`, hidden flag) that produces
one known, harmless event per probed sensor — the exec itself, a read of
`/run/northnarrow/probe/<nonce>` and a DNS query for
`<nonce>.probe.northnarrow.invalid` sent to `127.0.0.1:53` (the sensor
hooks the send, no resolver needed) — and checks that each one reaches
its own pipeline within 5 s. A silent sensor is a **telemetry gap**:
`ERROR TELEMETRY GAP` in the journal and a signed audit entry
(`op=telemetry_gap`, sensor and nonce in `extra`), once per gap, with
`op=telemetry_restored` when the sensor delivers again. None of the three
events trips a rule (root-owned binary from its install path, a dedicated
probe directory, a reserved `.invalid` name). `NN_TELEMETRY_PROBE_SECS`
in the unit environment changes the period; `0` disables the probe.

### 3.5 What root can still change, and how the agent proves it

Some things root can do to the agent cannot be denied without breaking
systemd: write a drop-in for the unit (`ExecStart=`, `Environment=`),
`systemctl set-property` (MemoryMax, TasksMax, CPUQuota), raise the
agent's `oom_score_adj`, bind-mount something over `/etc/northnarrow`,
mount a second bpffs, drop a `.local` overlay that exempts a comm at the
next restart, freeze the agent's cgroup. Every 30 s (±20 %) the agent
compares these with what it saw at boot and with what `install.sh` laid
down, and every new finding is an `INTEGRITY DRIFT` ERROR and a signed
audit entry:

```sh
sudo nn-admin audit verify && sudo grep '"op":"integrity_drift"' /etc/northnarrow/audit.log
```

| `kind` | Meaning |
|---|---|
| `unit_dropin` | a `.conf` drop-in for one of the two units that `install.sh` did not create (also `system.control`, `service.d`) |
| `limit_changed` | `oom_score_adj`, `memory.max`, `pids.max`, `cpu.max` or `cgroup.freeze` differs from boot |
| `mount_over_protected` | a mount over the config, state, runtime, pin, unit or binary paths (host view) |
| `bpffs_mount` | a bpffs outside `/sys/fs/bpf` (WARN: Cilium does this legitimately) |
| `config_overlay` | a `*.local` overlay in `/etc/northnarrow`, with size and hash |
| `weakening_env` | the agent started with a variable that turns a protection off (`NN_ANTI_TAMPER_ALLOW_DEGRADED`, `NN_BPF_DEFENSE_OBSERVE=1`, …) |
| `agent_stalled` | the agent did not run for more than 15 s past a check (cgroup freeze, stopped VM, starvation) |

**How the previous run ended.** Some kills cannot be refused at all: a write
to the unit's `cgroup.kill`, `systemctl kill -s KILL`, the OOM killer — and a
crash or a power loss look the same. The watchdog brings the agent back; the
evidence is in the chain: every run writes `agent_stop` (with the reason it
left its event loop: `sigterm`, `sigint`, `sighup`, `admin_shutdown`,
`sensor_pump_exited`) and every `agent_boot` carries `previous_run`:

```sh
sudo grep '"op":"agent_boot"' /etc/northnarrow/audit.log | tail -1 | grep -o '"previous_run":{[^}]*}'
# {"ended":"abrupt","booted_at":"…","last_entry_at":"…"}   ← killed, OOM, crash
```

An abrupt end is also a `PREVIOUS RUN ENDED ABRUPTLY` WARN at boot.

Refused attempts — signals to the agent or the watchdog, a ptrace attach,
writes to protected files and pins, BPF map writes and link handles — are
recorded as detection `NN-L-AT-001_AntiTamperDenial` in
`detections.jsonl`, and every ring buffer that loses events is a
`ringbuf_drop` audit entry. The lab exercises all of this with
`nn-lab.sh tamper-check`.

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

