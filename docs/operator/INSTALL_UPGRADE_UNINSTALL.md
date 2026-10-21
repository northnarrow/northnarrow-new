# Install, upgrade, uninstall

NorthNarrow's anti-tamper layer makes the host actively resist changes to
the agent: the binaries, the units and `/etc/northnarrow` are in
`PROTECTED_INODES` (write/unlink/rename and extended attributes denied by
LSM hooks, and no new file, link or directory in the agent's own
directories), the agent
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
A release tree installs only when its tarball's provenance attestation
verifies (section 5.1). A tree built from source has no `MANIFEST.sha256`:
`install.sh` installs it only with `--source-tree` (or `--allow-unverified`),
e.g. `sudo ./deploy/install.sh --source-tree --upgrade --grant-key <admin.key>`.
The `.deb` / `.rpm` packages wrap the same steps for the package manager:
see section 6.

**Prerequisites.** The host requirements of the agent itself (BTF, `bpf`
in the LSM list, bpffs, `iptables-restore`, `/usr/bin/mountpoint`) are in
[`KERNEL_COMPATIBILITY.md`](KERNEL_COMPATIBILITY.md). One more is checked
by the install paths (lab PR 165): **nftables** (`nft`). The per-process
outbound block — a BlockOutbound verdict, the COMBAT soft egress block of
INVESTIGATE — is an nftables rule, and some cloud images (Debian 12) ship
without the tool. The packages declare it (section 6). `install.sh` installs
no system package: without `nft` it refuses before it changes anything —
an `--upgrade` too, before the units are stopped — and names the command
(`apt-get install nftables`, `dnf install nftables`). `--without-nftables`
installs anyway; the flag is recorded in `install-manifest.json`
(`prerequisite_overrides`) and named by `nn-admin host-check` (§3.1), and
the agent records a signed `subsystem_degraded` at every boot while `nft`
is missing ("block_outbound unavailable: nft missing"). Installing
nftables adds the tool only: Debian's package does not enable or start
`nftables.service`, RHEL's is disabled by preset, so no ruleset is
loaded.

Upgrading across the remediation of the external audit of `16f7563`
(anything newer than `v0.0.1-tappa9.0`)? Read
[`UPGRADE_NOTES_AUDIT_16f7563.md`](UPGRADE_NOTES_AUDIT_16f7563.md) first:
the changes of behaviour and the regressions it brings, grouped by what an
operator touches, each with its finding and lab PR. Upgrading to a Wave 4
build (the on-host LLM advisor removed)? Read
[`UPGRADE_NOTES_WAVE4.md`](UPGRADE_NOTES_WAVE4.md) too.

## 1. Fresh install

`install.sh` copies binaries, units, the journald namespace config, the
rule and allowlist files, the canary templates and the ten inert
control-surface bait files; bootstraps an admin keypair if
`admin.pub` is absent — the private half goes to
`/root/northnarrow-admin.key` (`--admin-key-out PATH`; never under
`/etc/northnarrow` or `/var/lib/northnarrow`): move it off the host, see
`COMBAT_RECOVERY.md` §1 — and does **not** start anything. Enable the
agent first, then the watchdog. If a file already exists at the key path
and `admin.pub` does not, `install.sh` leaves both alone and says so
(`uninstall.sh --purge` removes the bootstrap key with the rest).

If the units are already active, `install.sh` refuses with
`Re-run with --upgrade`: with the hooks up every copy below would fail
with `Operation not permitted` halfway through.

**Both units stopped, the pin root still there** (external audit DEP-020,
lab PR 194). The deny hooks outlive the agent through their pins: after a
stop inside a window that has since closed, the binaries, the units and
`/sys/fs/bpf/northnarrow` stay protected, and the trusted-installer window
opens only through a running agent's socket. A pin root nothing protects
any more is removed. A protected one: with `--grant-key`, `install.sh`
(and `uninstall.sh`, below) starts the installed agent — its unit only,
the watchdog stays as it was — waits for its admin socket (30 s), opens
the window, stops it again and goes on; the units end as they were (not
restarted; the audit chain carries that agent's `agent_boot` and
`agent_stop`). Without a key nothing is started or changed and the script
names the two ways out: `--grant-key`, or `systemctl disable
northnarrow-agent northnarrow-watchdog`, reboot (bpffs does not survive
it), re-run, enable the units again. Before, `--grant-key` was ignored
in this state and the run ended in `PROTECTED`. An agent that does not
start, a refused grant (the agent then keeps running: its stop needs the
window) or a socket that does not come up is an explicit failure.

The five `.v1` lists (`fim-paths`, `netflow-blocklist`,
`netflow-ja3-blocklist`, `process-comm-allowlist`,
`netflow-comm-allowlist`) are the shipped defaults, not configuration:
every run of `install.sh` — fresh install, `--upgrade`, the packages'
configure step — installs the release's copy (external audit LLMR-015,
lab PR 168). Tune a list through its signed `.local` overlay (§3.6). A
`.v1` that is no list NorthNarrow shipped (edited by hand) is kept as
`<list>.v1.operator` next to it, the shipped one is installed, and
`install.sh` prints a WARNING with the difference (first 40 lines; `+`
your additions, `-` shipped entries you removed — the overlay's own
syntax) and the `nn-admin config overlay set <list>` command. The agent
applies the list it was built with in any case: one left over from an
earlier release is a WARN at boot, an edited one an ERROR and a signed
`integrity_drift` (`default_list_modified`) at every boot, and neither is
applied.

## 2. Upgrade in place

```sh
sudo ./deploy/install.sh --upgrade --grant-key /path/to/admin.key
```

From `v0.0.1-tappa9.0` or an earlier `main`, see
[`UPGRADE_NOTES_AUDIT_16f7563.md`](UPGRADE_NOTES_AUDIT_16f7563.md) for what
changes (its "Before you upgrade" list first).

The key must carry the `trusted-installer` role (the one `install.sh`
bootstraps does; see `COMBAT_RECOVERY.md` §1.1 for older keys). Over running
units `--upgrade` refuses to start without `--grant-key`, before anything is
stopped (lab PR 220): the window opened with the key stops the running
units, and a rollback needs the *new* agent's window too — a window you
opened by hand before the run covers the stop, not that.

The upgrade is a transaction (lab PR 220; static review of `baf4c25` P0
C-45 / G-07 / TD-09). It used to stop the units, drop the pins and overwrite
binaries, units and configuration with no copy and no trap: a failure
halfway — the binaries replaced and not the units, a new agent that does not
start — left the host without a working agent. What it does now, in order:

1. checks the release (§5.1), the tree and `nft` — nothing on the host has
   changed when one of them refuses;
2. **backs up** every file the run may create or replace into
   `/var/lib/northnarrow-upgrade/<time>-<pid>/` (`cp -a`: bytes, mode,
   owner, times, extended attributes; mode `0700`, outside the agent's own
   directories), and lists the ones that do not exist yet. That is the two
   binaries and `nn-admin`, the three units (the agent's, the watchdog's
   and its `OnFailure=` handler, lab PR 216), the Debian drop-in,
   `journald@northnarrow.conf`, `install-manifest.json`, the five `.v1`
   lists, the overlay template, the ten control-surface files, the five
   canary templates, the overlay signatures the run may add and, when
   missing, `admin.pub`, the bootstrap key and the COMBAT files. The eBPF
   object travels inside the agent binary; its pins are re-created by
   whichever agent starts. A backup that fails (a full disk) is a refusal,
   with nothing stopped;
3. records which units are active, prints installed → new version, opens
   the **trusted-installer window** (300 s) through the running agent's
   socket with `--grant-key` — a signed, audited grant that lets the next
   steps touch what the anti-tamper protects (binaries, units,
   `/etc/northnarrow`, the pin root); then stops the **watchdog first**
   (stopping the agent alone makes the watchdog respawn it), then the agent,
   and checks that neither still runs;
4. removes `/sys/fs/bpf/northnarrow`: the LSM programs survive agent
   restarts only through their pinned links, so dropping the pin root
   detaches them; the pin root is in the protected-inode set, so this
   needs the window of step 3 (or a reboot); waits until the agent's own
   BPF programs are unloaded (30 s budget, `LSM_DRAIN_TIMEOUT`; fails
   loudly, naming the ids, otherwise). The agent lists their ids in
   `/run/northnarrow/bpf-own-ids` at every boot and the script reads the
   file before the stop. Another product's BPF-LSM programs (Cilium,
   Tetragon, another EDR) are not waited for — the old gate counted every
   LSM program on the host and, on such a host, gave up with the units
   already stopped (external audit DEP-006). Upgrading from an agent that
   predates the list falls back to that count and names what is left;
   without `bpftool` the script checks that the units' processes and the
   pin root are gone and says the unload itself is not confirmed;
5. **switches** the binaries and units: each new file is staged next to
   the installed one (`<path>.nn-new`, same directory, same file system),
   compared with its source, then renamed over it (`rename(2)`): every path
   is the old file or the new one, never half of either, and the six
   change together. `install-manifest.json` is written the same way. Then
   the rest of the install (configs — the shipped `.v1` lists replaced by
   the release's, an edited one kept as `<list>.v1.operator` (§1);
   `chattr +i` on the state dir is lifted and re-applied by the new agent
   at boot), and the adoption of the `*.local` overlays already present:
   each one without a valid signature is signed with `--grant-key`
   (`nn-admin config overlay sign`); one that cannot be — the key lacks
   `config-manage` — is listed with the command to sign it, and the new
   agent boots on the shipped defaults for that list until it is (§3.6);
6. starts the agent, waits 3 s, starts the watchdog;
7. runs the **health check** (up to 60 s, `HEALTH_TIMEOUT`): every unit
   that ran before is `active` (both are `Type=notify`: active means the
   process sent `READY=1`); the agent's own journal event `anti-tamper: all
   LSM hooks attached` with `deny_attached` equal to `deny_expected`, read as
   an event of the unit's main process (`_SYSTEMD_UNIT`, `_PID`,
   `_TRANSPORT=stdout`, fields journald sets, and the whole line matched — a
   file named like the line, logged in another event, is not it); the pid
   file names that process and it answers `nn-admin status` on its admin
   socket; the watchdog's own event `watchdog PID registered in
   PROTECTED_PIDS` with its main pid. A deny-hook shortfall
   (`NN_ANTI_TAMPER_ALLOW_DEGRADED=1` included) fails the check; every deny
   hook with an observe hook missing passes with a WARNING (the agent signs
   the missing telemetry as `subsystem_degraded`). Passed: the backup is
   removed and the run ends `UPGRADE complete — health check passed`.

**Any failure after step 3 rolls back** (an EXIT trap; Ctrl-C included).
The new units, if they ran, are stopped through the new agent's own window
(the same key) and its pin root dropped; every backed-up file is copied
beside its path and renamed over it, so the previous files are back byte for
byte (mode, owner, times too) — checked against the SHA-256 taken before the
stop, a copy changed in the meantime is named and stops the rollback (exit
4); what the run created (a new list's
`.operator` copy, a new signature, a staged `.nn-new`) is removed; the units
that ran are started again and pass the same health check. Before that
start the script leaves `/run/northnarrow/upgrade-rolled-back.json` (what
failed, at which stage, both versions, the transaction): the restored agent
signs it at its boot as an `upgrade_rolled_back` row of the audit chain
(`extra`: `stage`, `reason`, `failed_version`, `restored_version`, `txn`,
`at`, `reported_by: install.sh` — root's installer reported it, the agent
did not see it — and `agent_version`) and removes it. A marker that is a
link, not root's, writable by others, larger than 4 KiB or not one JSON
object of strings is recorded as `failure: marker refused (…)` and removed.
The script then reads the row back and names it; an agent older than lab
PR 220 does not read the marker — the script says so and removes it. The
evidence is not rolled back: what the new agent appended to the audit chain,
its head anchor and the chain logs stays (`nn-admin audit verify`), and so
does what it migrated at its boot, if a release ever does. The run ends with
exit status **3**:

```
install.sh: UPGRADE FAILED — health_check: the agent (pid 4242) logged no 'anti-tamper: all LSM hooks attached'
install.sh: rolling back to northnarrow-agent 0.0.1 from /var/lib/northnarrow-upgrade/20261020T100000Z-1234
…
install.sh: UPGRADE ROLLED BACK — northnarrow-agent 0.0.2 failed (health_check: …).
install.sh:   running again: northnarrow-agent 0.0.1 (northnarrow-watchdog northnarrow-agent: health check passed)
install.sh:   signed record: upgrade_rolled_back, signed by the restored agent in /etc/northnarrow/audit.log
```

and the same in the system log (`auth.err`, tag `northnarrow-install`). The
stages are `stop` (step 3–4), `switch` (step 5), `start` and `health_check`
(steps 6–7). The start step does not check what it started: a unit that
does not start is found, and reported, at `health_check`.

**When the rollback cannot finish: exit 4.** A new agent that pinned its
hooks and then died (a refused boot, exit 78) or that runs without answering
on its socket keeps the files protected, and its window opens only through
that socket; the script starts it once more for the window (as in §1) and,
when that fails too, stops with `ROLLBACK INCOMPLETE` (on the terminal and
at `auth.crit`) and leaves `rollback.sh` in the transaction directory: the
copies and the functions that restore them. Then:

```sh
sudo systemctl disable northnarrow-agent northnarrow-watchdog
sudo reboot                                      # bpffs does not survive it
sudo bash /var/lib/northnarrow-upgrade/<time>-<pid>/rollback.sh
```

It refuses while a unit runs or the pin root exists, then restores the
previous files, enables the units that were enabled, starts the ones that
ran (the previous agent signs `upgrade_rolled_back`) and runs the health
check. When the new agent was refused for its install manifest (exit 78),
"Recovering from a refused boot" in §5.1 opens its window without a reboot:
start it once with the override, then re-run `install.sh --upgrade` from the
previous release's tree. Exit 4 is also the answer when the previous version, restored, does
not pass the health check itself; the copies stay for inspection. A later
`install.sh` run warns while a `rollback.sh` is pending; `uninstall.sh
--purge` removes `/var/lib/northnarrow-upgrade`.

Preserved across the upgrade: `admin.pub`, `agent.sig.key`, `agent_id`,
`audit.log` (the new agent appends a signed `agent_boot` entry — review
it with `nn-admin audit verify`), every chain log under
`/var/lib/northnarrow`, and every `*.local` overlay (the `.v1` lists are
the release's, §1). Their modes are
closed on the way (external audit EVD-019): `audit.log` and
`chain_heads.json` become `0640` (root and the file's group), the chain
logs under `/var/lib/northnarrow` `0600`. A log shipper that reads
`audit.log` without root needs a group: `--audit-group GROUP` (an
existing group; `NN_AUDIT_GROUP` too) gives both files that group, and
every later upgrade keeps it. On a package install, open a
trusted-installer window and `chgrp GROUP` the two files yourself. The window with no
hooks attached is the few seconds between step 4 and the new agent's
boot; it is the same window a reboot has.

The lab verifies this path on every nightly (`nn-lab.sh upgrade-check`):
refusal without the flag, pid change, new audit entry, identity files
unchanged, the new agent's own health line (`anti-tamper: all LSM hooks
attached`, every deny hook of the kernel — at least the 16 of every
supported kernel — read as that agent's own journal event, lab PR 206), no
fewer of its own LSM programs than before the upgrade and none of the old
ones, no anti-tamper `subsystem_degraded` signed at the upgraded boot, no
foreign LSM program lost, `PROTECTED_PIDS` re-pinned afterwards, and the
five `.v1` lists equal to the release's with no edited or left-over list
reported by the new agent. The rollback paths are exercised by
`xtask/tests/install_scripts.rs` against stub `systemctl`, journal and
agents that keep the anti-tamper's rules (a failure at each stage, a forged
health line, a deny-hook shortfall, the pinned-and-dead agent finished by
`rollback.sh`); on a guest, with a deliberately broken new build, the check
is owed (lab PR 220).

## 3. Uninstall

```sh
sudo ./deploy/uninstall.sh --grant-key /path/to/admin.key            # keep /etc/northnarrow + /var/lib/northnarrow
sudo ./deploy/uninstall.sh --purge --grant-key /path/to/admin.key    # remove them too (and the namespace journal)
```

Order: with both units stopped and a protected pin root left, start the
installed agent for the window (§1, "Both units stopped") → open the
trusted-installer window (`--grant-key`, same key and
role as the upgrade) → stop watchdog then agent, then disable both — a
unit whose stop is refused (no window on a protected host) stops the
script before anything is disabled or removed (lab PR 194; the units used
to be disabled first and left running) → drop the pin root and wait for
the agent's own BPF programs to unload (the ids in
`/run/northnarrow/bpf-own-ids`, read before the stop, as in the upgrade;
other products' LSM programs are left alone) → `chattr -R -i` on state and
config → remove
binaries, units, `journald@northnarrow.conf`, `/run/northnarrow` and the
ten bait files → `daemon-reload`. Without `--purge` the admin key, the
signed audit chain and the chain logs stay on disk: they are evidence and
identity, and a later reinstall picks them up (`install.sh` leaves an
existing `admin.pub` untouched). The summary names every private admin
key left on the host: `/root/northnarrow-admin.key`, and
`/etc/northnarrow/admin.key` that installs before external audit DEP-001
(lab PR 96) wrote (external audit DEP-012, lab PR 194); move them offline,
or `--purge` removes both. `--yes` skips the confirmation prompt.

If an unrelated NorthNarrow process (an e2e test, a manual
`northnarrow-agent` run) still holds the LSM programs, the script stops
and names the condition instead of leaving a half-removed host.

The lab verifies `uninstall.sh --purge --yes` leaves no binary, unit, pin,
NorthNarrow program, config, state or bait behind — and every foreign LSM
program in place — then reinstalls (`nn-lab.sh uninstall-check`).

### 3.1 Host hardening checks (`nn-admin host-check`)

The agent's anti-tamper (signals, ptrace, inode mutations denied to root
by BPF LSM) holds only while root cannot rewrite the kernel at runtime.
Those doors are closed by the host, not by the agent, so the installer,
the agent at boot and `nn-admin` read the same settings and say what is
missing and how to fix it:

| Check | Expected | Why |
|---|---|---|
| BPF LSM in the LSM list | `bpf` present | otherwise the deny hooks attach and never run: the agent refuses to start (exit 78) unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`, which starts it at trust level L0 (lab PR 218, `BOOT_INTEGRITY.md`) |
| Kernel lockdown | `[integrity]` or stronger | blocks unsigned modules, kexec of unsigned kernels, `/dev/mem` |
| Unprivileged BPF | `kernel.unprivileged_bpf_disabled` = 1 or 2 | only privileged processes load BPF |
| Module signature | `module.sig_enforce` = Y, or lockdown `[integrity]`/`[confidentiality]` (refuses unsigned modules whatever the parameter says) | an unsigned module is the classic way to blind a kernel sensor |
| UEFI Secure Boot | enabled | anchors the boot chain; turns on lockdown and module signing on most distros |
| IMA | measurements > 0 | a replaced binary fails before it runs (appraise) or is at least measured |
| kexec | `kernel.kexec_load_disabled` = 1 | no kernel swap without a reboot; lockdown alone still lets a signed vendor kernel in through `kexec_file_load`, with any command line (one without `bpf` in `lsm=`, for instance). Since review 82 the running agent refuses every kexec image load itself (below); the setting still covers the time before the agent starts |
| bpffs | mounted once at `/sys/fs/bpf` | a second bpffs can hide pinned objects from the inventory |
| nftables | `nft` installed in `/usr/sbin`, `/usr/bin`, `/sbin` or `/bin`, root's and writable by nobody else — the one the agent runs; a copy in `/usr/local` is not used (external audit ATP-014, lab PR 176) | a BlockOutbound verdict and the COMBAT soft egress block (INVESTIGATE) are nftables rules: without `nft` the offender is not contained while the agent analyses it — the agent records a signed `subsystem_degraded` at boot, and each episode records the failure and shortens INVESTIGATE to 10 s. Reported with `--without-nftables` when the install manifest records it (lab PR 165). A WARN like the other rows: the refusal is the installer's (Prerequisites, above) |
| Release verified at install | `provenance` `checksums` or `attested` in `install-manifest.json` | only these rest on something outside the installed tree (section 5.1); `manifest`, `source-tree`, `unverified` and `package` are reported with the flag that accepted them. The agent boots at every level, so the lab and developer hosts keep working (external audit DEP-007) |

The agent runs unchanged under `lockdown=integrity` (verified on Ubuntu
22.04 / 5.15: every deny hook attached, and `tamper-check` saw kexec and
an unsigned module refused by the kernel; the lab's lockdown guest,
`NN_LAB_LOCKDOWN=integrity nn-lab.sh up`, repeats it, lab PR 206). `confidentiality` mode is not
verified: it restricts BPF reads of kernel memory, which the sensors rely
on.

**kexec and kdump (review 82).** While it runs, the agent refuses every
kexec kernel image load (`kexec -l`, `kexec -p`, `systemctl kexec`; both
`kexec_load` and `kexec_file_load`) outside the trusted-installer window,
and records it as an anti-tamper denial (NN-L-AT-001). A loaded image let
root reboot at once into a kernel without the agent. kdump is not affected
at boot: the agent's unit starts after `kdump.service`, so the crash kernel
is already loaded. To reload it later (`kdumpctl restart`, a crashkernel
change), open the window first:

```
sudo nn-admin trusted-installer-grant --key <admin key> --window-secs 120
sudo kdumpctl restart
```

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
ring, and `nn-admin status --key <admin key>` prints the running total with
the per-ring breakdown (`ringbuf drops : 0` is the healthy line; signed
since external audit ASK-009, lab PR 213 — without a key the agent withholds
its telemetry). A non-zero counter
is a coverage gap, not a cosmetic number: the lab soak treats it as a
note and a production host should alert on it.

The same signed status prints `deny fail-open : 0` (lab PR 215): the
operations an anti-tamper deny hook let through because a kernel read it
needed failed, per hook (§3.5). `(not counted …)` there means the agent
reads no counters (an eBPF object without `DENY_FAIL_OPEN`). The two fields
are appended to the status reply: an `nn-admin` of this release cannot read
the status of an older agent (exit 5), so upgrade the binaries together, as
for the fields before them.

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
so `bpftool map dump` on the agent's maps fails too: use `nn-admin status
--key <admin key>` and the agent's own telemetry instead. Running one of the agent's binaries
is not an exemption (external audit EBPF-002: root could preload its own
library into one). Only the successor of an agent or a watchdog that
exited may take write handles before it is a protected pid — while no live
process holds that role, from its main thread, in its first minute — and
no process gets a handle on the agent's links (by id or through a pin; a
symlink to a pin still yields one, which can neither detach nor replace the
hook: since external audit EBPF-010 `BPF_LINK_DETACH` / `BPF_LINK_UPDATE` on
one of the agent's links is denied whatever the handle). `nn-admin` talks to
the agent over its socket and needs none. The `bpf` hook also records who
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
get one: `LINK_GET_FD_BY_ID` (`bpftool link show id N`, `bpftool link
detach id N`) and `OBJ_GET` on the link's pin (`bpftool link detach pinned
/sys/fs/bpf/northnarrow/link_*`). In enforce mode the `bpf` hook refuses
both to a foreign process (`EPERM`, anti-tamper denial
`operation=bpf_link`, link id as the target or 0 for the pinned route); in
observe mode it grants them and records an `NN-L-BPF-002` alert. The ids
of maps, programs and links are kept with their kind, since the kernel
numbers the three spaces independently. Program handles stay allowed
(`bpftool prog show` keeps working; a program fd cannot detach anything).
The enumeration of link ids (`LINK_GET_NEXT_ID`) gives no handle: it is
neither refused nor recorded. `bpftool link list` (`bpftool link show`
without an argument) enumerates the ids and takes a handle by id on each
link to print it, so in enforce mode it prints the host's other links and
stops at the first NorthNarrow link, with one anti-tamper denial (posture
COMBAT, INVESTIGATE stage), like `map show` above. Until lab PR 215 the
hook had its own copy of the `bpf` command numbers, with
`LINK_GET_FD_BY_ID` at 31, which is `LINK_GET_NEXT_ID`: a handle by id on
one of our links was granted and not recorded, while `bpftool link list`
printed the first NorthNarrow link and was then refused at the next
enumeration step, which was recorded as an anti-tamper denial although it
asks for no handle. The pin route and the detach/update deny (above) did
not depend on that number. The numbers now come from one module
(`common/src/bpf_cmd.rs`), checked against the uapi header and the running
kernel's BTF. (For the record: the kernel refuses `LINK_DETACH` on
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
was allowed (the PID-1 carve-out, since limited to the same window — §3.7),
so `rm -rf /sys/fs/bpf/northnarrow`
afterwards used to drop every hook — the two-command disable. The agent
now registers the pin root and every pin in the protected-inode set:
unlink, rmdir, rename and setattr — and a new pin or directory in the
root (external audit EBPF-015) — are denied to any process that is not
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
the deny in a test build (lab checks of the deny path; the privileged e2e
`bpf_guard_enforce_refuses_protected_pids_write` asserts it). The guard counts in the LSM
health: if it does not attach the agent refuses to start like for any
other deny hook (`NN_ANTI_TAMPER_ALLOW_DEGRADED=1` to override).

### 3.4 The agent proves its own coverage (`telemetry probe`)

A sensor that stops delivering is worse than one that was never there:
the host looks quiet. Every 60 s the agent runs a child of its own binary
(`northnarrow-agent --telemetry-probe <nonce>`, hidden flag) that produces
one known, harmless event per probed sensor — the exec itself, a read of
`/run/northnarrow/probe/<nonce>` and a DNS datagram naming
`<nonce>.probe.northnarrow.invalid` sent from and to loopback
(`127.0.0.1:53`; the sensor hooks the send, no resolver needed) — and
checks that each one reaches its own pipeline within 5 s. The nonce is
random, and the datagram is flagged as a DNS *response* (`QR` set, no
recursion asked): a resolver listening on `127.0.0.1:53` drops it instead
of answering or forwarding it upstream (external audit EVD-015). A silent sensor is a **telemetry gap**:
`ERROR TELEMETRY GAP` in the journal and a signed audit entry
(`op=telemetry_gap`, sensor and nonce in `extra`), once per gap, with
`op=telemetry_restored` when the sensor delivers again. None of the three
events trips a rule (root-owned binary from its install path, a dedicated
probe directory, a reserved `.invalid` name). `NN_TELEMETRY_PROBE_SECS`
in the unit environment changes the period; `0` disables the probe.

At boot the agent also proves its deny hooks run (lab PR 218): right
after they attach, a child of its binary (`--deny-self-test`, hidden flag)
signals the agent and must be refused. Every degradation of the run (a
sensor on its fallback, a hook missing, a log not persisted) is signed
within 60 s and listed by `nn-admin status --key`, with the **trust level**
(L0 no enforcement … L3 every mandatory deny hook attached and self-tested,
nothing degraded); `nn-admin capabilities --key` reads the capability
manifest the agent signs at every boot. See `BOOT_INTEGRITY.md`.

### 3.5 What root can still change, and how the agent proves it

Some things root can do to the agent cannot be denied without breaking
systemd: write a drop-in for the unit (`ExecStart=`, `Environment=`) where
the agent's drop-in directory does not exist, `systemctl set-property`
(MemoryMax, TasksMax, CPUQuota), raise the agent's `oom_score_adj`,
bind-mount something over `/etc/northnarrow`, mount a second bpffs, change
an existing `.local` overlay in place, freeze the agent's cgroup. (A new
file, link or directory in `/etc/northnarrow`, the state directory, the
pin root or the Debian drop-in directory — a new overlay, a new drop-in,
`systemctl edit` — is refused outside a trusted-installer window since
external audit EBPF-015, like an extended attribute set on a protected
file: see §3.8.) Every 30 s (±20 %) the agent
compares these with what it saw at boot and with what `install.sh` laid
down, and every new finding is an `INTEGRITY DRIFT` ERROR and a signed
audit entry:

```sh
sudo nn-admin audit verify && sudo grep '"op":"integrity_drift"' /etc/northnarrow/audit.log
```

| `kind` | Meaning |
|---|---|
| `unit_dropin` | a `.conf` drop-in for one of the units (the agent's, the watchdog's and, since lab PR 216, the watchdog's `OnFailure=` handler `northnarrow-watchdog-failed.service`) that `install.sh` did not create, in any directory of systemd's unit search path (`/etc`, `/run` and `/usr/lib/systemd/system`, `system.control`, `transient`, `system.attached`, the generator directories; also `northnarrow-.service.d` and `service.d`), or its own Debian drop-in with content other than the shipped `deploy/systemd/10-debian-perf-paranoid.conf` (lab PR 180) |
| `limit_changed` | `oom_score_adj`, `memory.max`, `pids.max`, `cpu.max` or `cgroup.freeze` differs from boot |
| `mount_over_protected` | a mount over the config, state, runtime, pin, unit or binary paths (host view), or — laid after the agent started — over a directory above them (a tmpfs over `/var/lib`, a bind over `/etc` or `/usr/local/bin`, a second bpffs on `/sys/fs/bpf`: the detail says what it hides; lab PR 180) |
| `protected_mount_gone` | a mount those paths resolved through when the agent started is no longer mounted (a lazy unmount of a separate `/var`, of `/sys/fs/bpf`): they now resolve through the mount below (lab PR 180) |
| `mountinfo_unreadable` | neither `/proc/1/mountinfo` nor the agent's own `/proc/self/mountinfo` can be read: the mount checks above are not running (lab PR 180; with only the first unreadable the agent checks its own namespace) |
| `combat_reconcile` | at start, a `NORTHNARROW_COMBAT` chain left by a run killed or crashed in COMBAT was torn down (`result` `repaired`, with `rules_torn_down`), or could not be checked or torn down (`failed`: the host may still be isolated, [COMBAT_RECOVERY.md](COMBAT_RECOVERY.md)) (lab PR 180) |
| `bpffs_mount` | a bpffs outside `/sys/fs/bpf` (WARN: Cilium does this legitimately) |
| `tracefs_mount` | a mount at `/sys/kernel/tracing` or `/sys/kernel/debug/tracing` that is not a whole tracefs, or any mount below them: the tracepoint sensors take their field offsets from there at the next start (external audit NN-AUD-098) |
| `config_overlay` | a `*.local` overlay in `/etc/northnarrow`, with size and hash |
| `weakening_env` | the agent started with a variable that turns a protection off or cuts the evidence it keeps (`NN_ANTI_TAMPER_ALLOW_DEGRADED`, `NN_BPF_DEFENSE_OBSERVE=1`, `NN_DETECT_ONLY=1/true/yes`, a `NN_TELEMETRY_PROBE_SECS` of 0 or above 60, any `NN_*_CAP_BYTES` override, …) |
| `agent_stalled` | the agent did not run for more than 15 s past a check (cgroup freeze, stopped VM, starvation) |
| `watchdog_hold` | while the agent was down the watchdog stopped respawning it: a start that brought no agent back within 30 s (the unit failed — its `ExecStartPre=/usr/bin/mountpoint -q /sys/fs/bpf` without bpffs — or was stopped or skipped; the record carries systemd's `ActiveState`/`SubState`/`Result`/`ConditionResult`/`AssertResult`), a failed `systemctl start`, or the restart ceiling. Signed at the agent's next start (external audit DEP-004). Since lab PR 216 also each bounded retry of a hold (`hold_retry`) and its end, with its length (`hold_ended`) |
| `watchdog_exit` | the watchdog exited on a failure, with its exit status and reason (§3.9); systemd restarts it, as often as it fails (one record per run). Written by the watchdog just before it exits (lab PR 216) |
| `watchdog_failed` | systemd put `northnarrow-watchdog.service` in the failed state — a start or stop job of the unit failed (a death of the process is restarted, without limit) — and no longer restarts it: the agent runs without a supervisor until the unit is started. Written by the unit's `OnFailure=` handler with systemd's `service_result`, `exit_code` and `exit_status` (lab PR 216, §3.9) |
| `watchdog_gone` | the watchdog the agent had verified no longer runs (a crash, a kill, a stop), and what the agent finds in its place. Signed by the agent itself, within 30 s (lab PR 216) |
| `stuck_recovery_failed` | the agent stopped answering (or its event loop stood still) and the watchdog's SIGINT then SIGKILL could not end it: the agent kept its `PROTECTED_PIDS` entry and its pidfile and stays supervised (lab PR 216) |
| `event_loop_stalled` | the agent's admin socket answered three STATUS pings in a row while its event loop made no round (90 s or more); the watchdog recovers it like a hang (lab PR 216) |

The memory limits are absolute (`MemoryHigh=9G`, `MemoryMax=11G`, sized
for the model of the LLM advisor, removed in Wave 4, and not re-sized yet:
[`UPGRADE_NOTES_WAVE4.md`](UPGRADE_NOTES_WAVE4.md) §2). On a host with no more memory than `MemoryMax` the cap
cannot bind, so the agent starts there with `oom_score_adj` 0 instead of
the unit's -500 — an ordinary OOM candidate, which the watchdog respawns —
and says so in a WARN (`memory cap at or above the host's memory`); 0 is
then the value the check expects (external audit DEP-005).

**How the previous run ended.** Some kills cannot be refused at all: a write
to the unit's `cgroup.kill`, the OOM killer — and a crash or a power loss look
the same. The watchdog brings the agent back; the evidence is in the chain:
every run writes `agent_stop` (with the reason it left its event loop:
`sigterm`, `system_shutdown`, `sigint`, `sighup`, `admin_shutdown`,
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
`ringbuf_drop` audit entry. A deny hook that lets an operation through
because a kernel read it needed failed (it cannot decide, and an LSM
program cannot wait or retry) is counted too, per hook, since lab PR 215:
a WARN `deny hook FAILED OPEN` per sample, a signed `deny_fail_open` audit
entry (`hook`, `fail_open_since_last_entry`, `total`; at the first one of
a hook, then at most one per hook every 10 minutes carrying every
fail-open since the previous entry), and the `deny fail-open` line of
`nn-admin status --key` (`deny_fail_open_total` and `deny_fail_open` in
`--json`). It should stay at 0; any other value names the hook to report.
The posture is not raised by it. A NULL the kernel holds where the hook
looks (the new name of a rename) is not a fail-open. The lab exercises all of this with
`nn-lab.sh tamper-check`.

### 3.6 Overlays are signed (`nn-admin config overlay`)

The `*.local` overlays in `/etc/northnarrow` change what the agent detects
— an allowlist overlay exempts a comm, a FIM overlay stops watching a
path, a posture overlay carves writers out of the mass-write arm — and
used to be read at boot as plain files: root could add `+evil-implant` and
the next restart applied it. Since Tappa 10.8 the agent loads an overlay
only if `<overlay>.sig` proves that a key with the **`config-manage`**
role signed its exact content (SHA-256 and length), for this agent
(`agent_id`), and not earlier than the last signature the audit chain
accepted for that list (no rollback to a retired exemption). Otherwise it
boots on the shipped defaults for that list, logs `UNAUTHORIZED
OVERLAY` and records a signed `integrity_drift` (`unauthorized_overlay`).

The shipped defaults are the copy built into the agent. The `.v1` file is
applied only when it is that copy byte for byte; the copy of an earlier
release gives way to it (WARN), anything else too (ERROR and a signed
`integrity_drift`, `default_list_modified`, with both SHA-256, at every
boot), and so does a `.v1` that is a symbolic link, a FIFO or larger than
4 MiB (`default_list_unavailable`). A change to a list belongs in its
`.local` overlay; `install.sh` replaces the `.v1` files (§1).

That floor is read from the chain the agent verifies at boot (links,
hashes and signatures after the last `overlay_floor_anchor`). When the
chain's history is gone — `audit.log` missing or emptied while the agent's
signing key exists, an entry edited or removed, the key unreadable — the
floor is reset: no overlay signed before that boot is loaded, then or
later, the agent logs `OVERLAY ROLLBACK FLOOR RESET` and records an
`integrity_drift` (`overlay_rollback_floor_unavailable`, the new floor in
`not_before`). Sign the overlays again (`config overlay set`, then a
restart) to bring them back. `audit.log` is evidence: do not delete or
truncate it to reclaim space. `config overlay status` shows a reset to
come (`rollback-floor`).

| Command | Use |
|---|---|
| `nn-admin config overlay set <kind> --file F --key K` | sign over the agent's challenge and store through the running agent (it writes the overlay and its `.sig`); applies at its next start |
| `nn-admin config overlay sign <kind> --file F --key K` | sign offline and write `F.sig` next to `F`, or `--out` (upgrades: install.sh runs it with the pins purged; a new `.sig` in `/etc/northnarrow` needs a trusted-installer window while hooks are attached, even with the agent stopped) |
| `nn-admin config overlay status` | which overlays are present and whether the next start loads them (exit 1 if one does not) |

Kinds: `fim-paths`, `process-comm-allowlist`, `netflow-comm-allowlist`,
`netflow-blocklist`, `netflow-ja3-blocklist`, `mass-write-carveout`,
`escalation-allow`. Content is checked with the loader's own rules before
it is signed or stored (a malformed line is refused, not silently dropped).
Every accepted new content is a `config_overlay_accepted` audit entry,
every stored one a `config_overlay_set` entry. The two posture overlays and
every `.sig` are now protected against unlink and rename like the other
overlays. Escape hatch for a migration: `NN_OVERLAY_ALLOW_UNSIGNED=1` loads
unsigned overlays and edited `.v1` lists anyway, still reported, and is
itself reported as a weakening environment variable.

### 3.7 Stopping and restarting the agent

The units refuse a manual stop (`RefuseManualStop=yes`: `systemctl stop`,
`restart`, `isolate` of the unit alone fail at once with "may be requested
by dependency only"), and the task_kill hook refuses systemd's signals to
the agent and the watchdog unless a trusted-installer window is open
(external audit EBPF-001): systemd only relays root's request, and root is
the adversary this agent is built against. Outside a window `systemctl
kill` fails with "Access denied"; the attempt is a signed detection
(NN-L-AT-001, "on behalf of a `systemctl stop` / `kill` / `restart`") and
raises the posture to ENGAGED — never COMBAT: systemd is the relay, not the
offender, and the requester is not known.

To restart, for example after `nn-admin config overlay set`:

```sh
sudo nn-admin trusted-installer-grant --key <trusted-installer key> --window-secs 120
sudo systemctl kill -s SIGTERM northnarrow-agent       # the watchdog starts it again
```

To stop for good, `nn-admin shutdown` (2-of-N quorum; the watchdog stands
down). For maintenance, the window, then `sudo systemctl kill -s SIGTERM
northnarrow-watchdog` and the same for `northnarrow-agent` (watchdog first,
or it starts the agent again). `install.sh --upgrade` and `uninstall.sh` do
exactly this.

A shutdown or reboot needs no window and waits at most the units' 5-s stop
timeout: their stop jobs end with the processes still running, the agent
keeps detecting through the rest of the shutdown, and both end with
`systemd-shutdown`'s final SIGTERM, which the hook allows only to that
program, verified by its executable (`agent_stop` reason
`system_shutdown`). The refused SIGTERM of the stop job is not reported as
an attempt while systemd reports the host as `stopping`.

### 3.8 No new entries in the agent's directories (external audit EBPF-015)

The deny hooks used to refuse removing or changing an entry of a protected
directory, not adding one. Root could drop a decoy overlay or a second key
file next to the protected ones, plant a name the agent was about to
create, add a drop-in to the agent's unit, or set extended attributes on
the agent's files. Now, outside a trusted-installer window, a process that
is neither the agent nor the watchdog gets `EPERM` for:

- a new file (`open(O_CREAT)`, `creat`), subdirectory, symlink, hard link,
  device node or FIFO in `/etc/northnarrow`, `/var/lib/northnarrow` and
  its `detections/` directory, the agent's drop-in directory
  `/etc/systemd/system/northnarrow-agent.service.d` (Debian family, where
  install.sh makes it), and the bpffs pin root — `op=create`, `mkdir`,
  `symlink`, `link`, `mknod`;
- an extended attribute set or removed on any protected inode (`setfattr`,
  `setcap`, `evmctl`, and `setfacl`, which 6.2+ kernels send through their
  own ACL hooks) — `op=xattr`. `security.selinux` is not refused:
  `restorecon` relabels the agent's files on SELinux hosts.

Each refusal is an `ANTI-TAMPER DENIAL`, an `NN-L-AT-001` detection and a
decisive tamper signal (COMBAT), like a refused unlink. What changes for an
operator: overlays go through `nn-admin config overlay set` (the agent
writes them); `systemctl edit northnarrow-agent`, `nn-admin config overlay
sign` into `/etc/northnarrow`, `nn-admin init` creating a missing
`admin.pub` and an editor's swap file need a window
(`nn-admin trusted-installer-grant`) — editing those files in place was
already refused (the rename or truncate). install.sh, the packages and
uninstall.sh are unchanged: they open the window and purge the pins
before writing.

The agent registers itself in the pinned `PROTECTED_PIDS` before its boot
creates anything, so a restarted agent is not refused the files and map
pins it recreates by its predecessor's hooks.

### 3.9 When the watchdog fails (lab PR 216)

The watchdog supervises the agent; since lab PR 216 its own failures are
visible too (capability C23; static review C-43, C-44).

**Exit statuses.** The watchdog exits 0 only for a stop it was told to
make: SIGTERM or SIGINT (a maintenance stop inside the trusted-installer
window, a shutdown) or a shutdown signed by the admin quorum. Every failure
has its own status, logged as `watchdog EXITING on a failure` on
`watchdog.tamper` and recorded for the agent to sign (`watchdog_exit`):

| status | reason |
|---|---|
| 0 | stopped (signal, or an admin-signed shutdown) |
| 1 | an error without a status of its own (none is known) |
| 2 | the command line was refused |
| 10 | process hardening (`prctl`) failed |
| 11 | no verified agent within 30 s of the start |
| 12 | the watchdog's pidfile could not be written |
| 13 | the respawn backend could not be set up |
| 14 | `READY=1` could not be sent to systemd |
| 15 | the signal handlers could not be installed |
| 20 | the wait on the agent's pidfd failed (it used to exit 0, and was never restarted) |
| 30 | `--record-unit-failure`: the record could not be written |

**Restarts.** The watchdog never stays down.
`northnarrow-watchdog.service` has `Restart=always` with
`RestartPreventExitStatus=0` and no start limit (`StartLimitIntervalSec=0`):
every failure and every death by a signal (SIGKILL, SIGHUP, an abort) is
restarted, for as long as it fails; a stop is not. The delay grows from 2 s
to 60 s and stays there (`RestartSteps=5`, `RestartMaxDelaySec=60s`;
systemd 254+, an older systemd restarts every 2 s and logs the two keys as
unknown). Each failed run is visible on its own: the watchdog's
`watchdog_exit` record (its status and why), the agent's `watchdog_gone`
(the watchdog it had verified no longer runs, whatever ended it), both
signed within about 30 s, and the unit's restart counter:

```sh
systemctl show -p NRestarts,ExecMainStatus,StatusText northnarrow-watchdog
journalctl --namespace=northnarrow -u northnarrow-watchdog -p err
sudo grep '"op":"integrity_drift"' /etc/northnarrow/audit.log | grep -E 'watchdog_(exit|gone)'
```

A watchdog that keeps failing is restarted every minute and leaves one
record per run: fix the cause the records name. `OnFailure=` still covers
what leaves the unit itself `failed` — a start or stop job systemd fails,
not a death of the process: `northnarrow-watchdog-failed.service` records
`watchdog_failed` with systemd's result, the agent signs it, and
`systemctl start northnarrow-watchdog` brings the watchdog back.

**Liveness.** The STATUS ping is answered by the agent's admin socket,
which runs beside its event loop: a loop stuck behind one event answered
every ping. Each ping now also asks for the loop's round count (`LoopProgress`,
unsigned; the loop goes round at least every 5 s). Three answers in a row with
the count unchanged since the answer before them — 90 s or more without a
round — are a stuck agent (`event_loop_stalled`, then the SIGINT / SIGKILL
recovery). An agent older than lab PR 216 closes the
connection at that request; the watchdog then counts its STATUS answer
alone, as before, and logs it once.

**A recovery that fails does not unprotect.** The watchdog evicts the
agent's pid from `PROTECTED_PIDS` only after its pidfd reports the exit.
When the SIGINT or the SIGKILL is refused, or the agent has not exited 10 s
after the SIGKILL, the agent keeps its entry and its pidfile, the watchdog
keeps watching it and tries again at the next stuck signal; the unit's
status reads `DEGRADED: agent pid … unresponsive and could not be stopped`
and the agent signs `stuck_recovery_failed`.

**The hold is bounded.** After the restart ceiling (5 restarts in 60 s) or
a respawn that brings no agent back, the watchdog still holds — alive,
protected, no respawn loop — but its `STATUS=` line says for how long and
when it retries, an ERROR repeats every 10 minutes, and it starts the agent
once more after 10 minutes, then 20, 40 and at most every hour
(`hold_retry`). Starting the agent yourself ends the hold at once, as
before (`hold_ended` records its length).

**No core dumps.** The agent and the watchdog are not dumpable
(`PR_SET_DUMPABLE` 0 at their start; the agent also sets `RLIMIT_CORE` 0)
and the units set `LimitCORE=0`: a crash writes no memory to disk, and
`/proc/<pid>/mem`, `environ` and `maps` are closed to a process without
`CAP_SYS_PTRACE`. `/run/northnarrow` is 0700 whoever creates it (both units
and the handler declare `RuntimeDirectoryMode=0700`; `install.sh` and the
watchdog create it 0700). Each unit bounds its start: `TimeoutStartSec=180s`
for the agent (its `READY=1` follows the eBPF attach and the ADE load),
`60s` for the watchdog (its own 30-s deadline for a verified agent fires
first).

## 4. What still needs a reboot

- Enabling the `bpf` LSM (`bpf` added to the kernel's `lsm=` list) the
  first time — see
  [`KERNEL_COMPATIBILITY.md`](KERNEL_COMPATIBILITY.md#enabling-the-bpf-lsm-kernel-command-line):
  the list is extended, never replaced by a fixed one.
- A kernel upgrade: the agent revalidates BTF offsets at boot and refuses
  to start on a mismatch rather than run with wrong offsets; the
  supported-kernel matrix is the next item on the reliability list. From
  6.9 the `inode_setattr` hook gained an argument; the agent reads its
  position from the running kernel (lab PR 164), and refuses to start when
  a hook argument it reads at a fixed position has moved
  (`KERNEL_COMPATIBILITY.md`, "Kernels from 6.9"). Verified on Debian 13
  (6.12) on 2026-10-16 (lab PR 164).

## 5. Release artefacts and how to verify them

Every tag `v*` runs `.github/workflows/release.yml`, which builds with a
locked lockfile and pinned toolchains, and attaches to the GitHub release:

| File | What it is |
|---|---|
| `northnarrow-<ver>-x86_64-linux.tar.gz` | the release tree: binaries, eBPF object + provenance stamp, `deploy/` (install/uninstall/units), `configs/`, operator docs, licences. Extract and run `sudo ./deploy/install.sh` (or `--upgrade`) unchanged — every preflight still applies. |
| `northnarrow_<ver>-<rel>_amd64.deb`, `northnarrow-<ver>-<rel>.x86_64.rpm` | the same binaries as distribution packages (section 6); the `.rpm` is signed (section 6.1) |
| `RPM-GPG-KEY-northnarrow.asc` | the public key the `.rpm` is signed with (a copy of `deploy/release/RPM-GPG-KEY-northnarrow.asc` at the tag) |
| `northnarrow-<ver>-x86_64-linux.{agent,watchdog}.sbom.cdx.json` | CycloneDX SBOMs of the two daemons (the agent one covers `nn-admin` too) |
| `SHA256SUMS` | checksums of the files above |

The tarball, the packages and the SBOMs carry a SLSA build-provenance
attestation signed by GitHub's OIDC identity for this repository and
workflow (`SHA256SUMS` and the key file do not: their files are listed in
`SHA256SUMS`, which itself is not signed — the attestation is what says
where a file was built). Verify before installing:

```sh
sha256sum -c SHA256SUMS
gh attestation verify northnarrow-<ver>-x86_64-linux.tar.gz --repo northnarrow/northnarrow-new \
  --cert-identity-regex '^https://github\.com/northnarrow/northnarrow-new/\.github/workflows/release\.yml@refs/tags/v' \
  --deny-self-hosted-runners
```

The attestation binds the file digest to the exact commit, workflow and
runner that produced it; a tarball rebuilt elsewhere, or modified after
the fact, fails the check. The identity regex is what makes the check
mean "a release" (external audit SUP-001): `--repo` alone, or
`--signer-workflow`, also accepts the attestation of a `workflow_dispatch`
run of the same workflow on any branch, whose certificate names that
branch instead of a `v*` tag. `--deny-self-hosted-runners` refuses an
attestation made on a runner outside GitHub's hosted fleet. With cosign
and a bundle from `gh attestation download`, use the same regex:

```sh
cosign verify-blob-attestation --new-bundle-format --bundle <bundle.jsonl> \
  --certificate-identity-regexp '^https://github\.com/northnarrow/northnarrow-new/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>
```

Pull requests that touch `deploy/`, `xtask/` or the workflow run the same
job as a dry run (artefacts on the workflow run only). Every action the
workflows use is pinned by commit SHA, and every tool installed with
`cargo install` (bpf-linker, cargo-cyclonedx, cargo-fuzz, cargo-audit,
kani) by version with `--locked` (external audit SUP-002, SUP-005).

### 5.1 `install.sh` verifies the release itself

The manual commands above stay valid, but since lab PR 21 the installer
performs the checks and refuses to touch the host when one fails — and
since lab PR 220 (static review of `baf4c25` P0 C-45 / G-07) a release
tree installs only when step 4 verifies:

1. **Tree manifest** — the tarball ships `MANIFEST.sha256` (every file
   hashed by `mk-tarball`); `install.sh` runs `sha256sum -c` on the
   extracted tree. A corrupted or edited tree is refused.
2. **SHA256SUMS** — if the tarball is next to the tree (`../<tree>.tar.gz`,
   or `--tarball FILE`) and `SHA256SUMS` is next to it (or `--sums FILE`),
   the tarball hash is checked against it. The line is found by the
   tarball's exact name (a leading `*`, binary mode, allowed); a file that
   lists the name with two different checksums is refused (external audit
   DEP-016, lab PR 194: the name used to be a regular expression, so a
   line for a look-alike name listed first was taken for it).
3. **The tree is the tarball's** (lab PR 220) — its `MANIFEST.sha256` must
   be the one inside the tarball, byte for byte (the tarball's one
   top-level directory). The checks of steps 2 and 4 vouch for the
   tarball, step 1 binds the tree to its own manifest; a tree edited after
   extraction with its manifest rewritten, next to a genuine tarball, used
   to pass both. Refused whatever the flags.
4. **SLSA attestation** — with `gh` 2.49+ (online, or offline with
   `--attestation BUNDLE` from `gh attestation download`) or `cosign`
   plus a bundle, the tarball's provenance is verified and bound to this
   repository's release workflow run for a `v*` tag (the identity regex
   above, and `--deny-self-hosted-runners` with gh). An artefact of a
   dispatch run on a branch fails this step. A failed verification, no
   tarball next to the tree, or no verifier at all is a **refusal**
   (it used to be a line and a lower level): the message says why — the
   verifier's own last lines included — and how to get there. A host
   without network access verifies offline: download the bundle on a
   machine that has it (`gh attestation download <tarball> --repo
   northnarrow/northnarrow-new`) and pass `--attestation <bundle.jsonl>`
   (gh, or cosign: cosign is used only with that bundle, and its path has
   no automated test yet). `--require-attestation` is accepted and is the
   default.

The strongest level reached — `attested`, `checksums`, `manifest`,
`source-tree` or `unverified` — is written with the SHA-256 of every
installed binary and of the eBPF object to
`/etc/northnarrow/install-manifest.json`, which the anti-tamper hook
protects like the rest of `/etc/northnarrow`.

**No silent downgrade (external audit DEP-007, lab PR 220).** The checks
used to step down on their own: a tree without `MANIFEST.sha256` installed
as a "source tree", so removing that one file from an altered release
turned every check off; and an unsigned `SHA256SUMS` next to the tarball
was enough for `checksums` — whoever swaps the tarball swaps it too. A level
below `attested` now needs an explicit flag. The flag is **logged**: a
WARNING on the terminal and a line in the system log (`auth.warning`, tag
`northnarrow-install`: `journalctl -t northnarrow-install`); it is
**recorded** in the manifest (`verify_override`, and `attestation.failure`
says why the attestation did not verify) and **reported** by `nn-admin
host-check` (§3.1: anything below `attested` is a WARN, `checksums`
included):

| Situation | Without a flag | Flag that accepts it | Recorded as |
|---|---|---|---|
| The attestation did not verify (or no verifier), the tarball matched `SHA256SUMS` | refused | `--allow-unverified` | `checksums` |
| Only the tree's own `MANIFEST.sha256` checked (no tarball next to it) — it travels inside the tree it vouches for | refused | `--allow-unverified` (`--allow-manifest-only`, its former name, still accepted) | `manifest` |
| No `MANIFEST.sha256` (a build from source, the lab, a developer) | refused | `--source-tree` or `--allow-unverified` | `source-tree` |
| Every release check skipped | — | `--no-verify` (development only) | `unverified` |

`--allow-unverified` is for the lab and for development, where nothing
attested exists: the lab installs its synced source tree with
`--source-tree` (`nn-lab.sh install`, `upgrade-check`), and its
`release-check` installs a CI run's tarball — attested, if at all, for a
branch, not a `v*` tag — with `--allow-unverified` after checking that
it is refused without. `--source-tree` only permits a missing
`MANIFEST.sha256`: on a tree that has one, it is ignored and the tree is
verified as a release. Keep the tarball next to the extracted tree (or
pass `--tarball`), with `gh` or an offline bundle, and a release installs
with no flag. `--require-attestation` with `--allow-unverified` or
`--no-verify` is a usage error (exit 2).

**At every boot the agent closes the loop**: it hashes its own executable,
the watchdog and `nn-admin` under the recorded `bin_dir` and compares the
embedded eBPF object hash with the manifest. The result is written in the
signed `agent_boot` audit entry (`binary_integrity`, `install_provenance`).
A mismatch — the running file is not the one the installer verified — or
an unreadable manifest refuses the boot (exit 78); `NN_ALLOW_UNVERIFIED_BINARY=1`
turns that into a WARN on a development host (a weakening variable: the
agent records it in the audit chain). A binary started from
outside `bin_dir` (a test fixture) is not compared.

**A removed manifest refuses the boot too (external audit DEP-009).**
`install.sh` writes the manifest on every install, source trees and
packages included, so once the signed audit chain holds an `agent_boot`
with `binary_integrity` `verified`, a missing manifest means it was removed
(in a trusted-installer window, from an offline disk) — it no longer
switches the check off. The agent refuses to start (exit 78) and records
`agent_boot` with result `refused`, `binary_integrity` `no-manifest`;
re-run `install.sh` to write it again, or set
`NN_ALLOW_UNVERIFIED_BINARY=1` on a development host. A chain that cannot
be read counts the same way. A host whose chain has no verified boot (a
developer run, an install older than the manifest) still starts, with an
INFO. A host restored from a backup without the manifest is refused until
`install.sh` runs again; `uninstall.sh --purge` resets the chain. Limit:
deleting the audit chain as well makes the install look new — that shows
as a chain restarting from genesis in `nn-admin audit verify`.

**Recovering from a refused boot** (mismatch, unreadable or removed
manifest). The refused agent has already attached and pinned its hooks, so
`/etc/northnarrow` stays protected, and a trusted-installer window needs a
running agent. Start it once with the override taken from the service
manager's environment (the agent records it as a weakening variable),
drop the override, then reinstall — `install.sh` restarts the agent
without it:

```sh
sudo systemctl set-environment NN_ALLOW_UNVERIFIED_BINARY=1
sudo systemctl start northnarrow-agent
sudo systemctl unset-environment NN_ALLOW_UNVERIFIED_BINARY
sudo ./deploy/install.sh --upgrade --grant-key /path/to/admin.key   # + --source-tree for a source build
```

```sh
tar xzf northnarrow-<ver>-x86_64-linux.tar.gz && cd northnarrow-<ver>-x86_64-linux
sudo ./deploy/install.sh                                # tarball + SHA256SUMS found in .., gh online
sudo ./deploy/install.sh --upgrade --tarball /path/to/northnarrow-<ver>-x86_64-linux.tar.gz \
    --sums /path/to/SHA256SUMS --attestation /path/to/bundle.jsonl
nn-admin audit verify --from /etc/northnarrow/audit.log --agent-sig-key /etc/northnarrow/agent.sig.key
```

Known limits: one architecture (x86_64). The tarball itself is not
byte-reproducible (file mtimes are preserved because the staleness guard
needs them); the provenance attestation is the integrity anchor instead.

### Install layout

`install.sh` defaults to the local-software layout: binaries in
`/usr/local/bin`, units in `/etc/systemd/system`. The distribution-package
layout is the same install with two overrides, and `uninstall.sh` takes
the same ones:

```sh
sudo BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system ./deploy/install.sh
sudo BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system ./deploy/uninstall.sh --grant-key <admin.key>
```

The units are rewritten for `BIN_DIR` (`ExecStart=`, the watchdog's
`--agent-bin`). Operator drop-ins, including the Debian
`perf_event_paranoid` one, always go to `/etc/systemd/system/<unit>.d/`.
The agent protects both layouts' binaries and units and finds the watchdog
next to its own executable, so neither layout needs extra flags. A copy of
a unit anywhere earlier in systemd's load path — `/etc/systemd/system`
over a package's unit, or the tmpfs `/run/systemd/transient` and
`system.control` over either — would replace it at the next
`daemon-reload`; the agent reports it as an `integrity_drift` audit entry
of kind `unit_shadowed`, `systemctl mask` included.

## 6. Distribution packages (`.deb` / `.rpm`)

The packages install the package layout: binaries in `/usr/bin`, units in
`/usr/lib/systemd/system`, and in `/usr/share/northnarrow` the data tree
`install.sh` needs (configs, unit sources, the eBPF object). Nothing under
`/etc` belongs to the package. The first install seeds `/etc/northnarrow`
exactly as `install.sh` does, and operator configuration is never
overwritten; the shipped `.v1` lists are refreshed at every configure, an
edited one kept as `<list>.v1.operator` (§1).
The package scripts run `install.sh` / `uninstall.sh` in their package
modes, so every step and every refusal is the one described above.

| Operation | Debian / Ubuntu | RHEL / AlmaLinux | Keeps keys / audit chain / state |
|---|---|---|---|
| Install | `sudo apt-get install ./northnarrow_<ver>-<rel>_amd64.deb` (or `dpkg -i` with `nftables` installed) | `sudo dnf install ./northnarrow-<ver>-<rel>.x86_64.rpm` (or `rpm -U` with `nftables` installed) | n/a (bootstraps them) |
| Upgrade | the same command with the newer package | the same | **yes** |
| Remove | `sudo dpkg -r northnarrow` | `sudo rpm -e northnarrow` | **yes** |
| Retire the host | `sudo dpkg -P northnarrow` | `rpm -e`, then `uninstall.sh --package --purge` from the tree | no |

**Dependencies (lab PR 165).** Besides libc and systemd, the packages
need `nftables` (`nft`, the per-process outbound block). The `.deb`
declares it as `Pre-Depends`, the `.rpm` as `Requires`: `apt-get` and
`dnf` install it with the package, while a bare `dpkg -i` or `rpm -U` on a
host without it refuses before any package script runs — the running
agent keeps running. A plain `Depends` would only fail after the unpack,
with the agent already stopped by the pre-unpack hook and the package left
unconfigured.

A first install starts nothing: enable the units as in section 1. An
installation made with `install.sh` is migrated when the package is
installed over it. The running units are stopped and restarted, the
`/usr/local/bin` binaries and the `/etc/systemd/system` units are
removed, and units that were enabled stay enabled. Keys, `agent_id`, the
audit chain and the chain logs are kept. The install manifest records
`"provenance": "package"`: `install.sh` runs inside the package's own
scripts and cannot tell where the package came from, so check it before
the package command (section 6.1). `dpkg --verify northnarrow` and
`rpm -V northnarrow` only compare the installed files with what the
package database recorded at install time; they say nothing about the
package's origin.

**Upgrade and removal need the trusted-installer window.** The running
agent protects its binaries, units and pin root, so the package's hooks
stop it the way `install.sh --upgrade` does. They open the window with the
key in `NN_GRANT_KEY` — never with a key they find on the host (external
audit DEP-001: a bootstrap key left there made every package operation
open the window with whatever key root could read). Without a usable key,
or a window you opened first, the operation stops before any file
changes, the running version keeps running, and the package stays at its
current version:

```sh
sudo NN_GRANT_KEY=/path/to/admin.key apt-get install ./northnarrow_<ver>-<rel>_amd64.deb
# or open the window first, then use the package manager as usual
sudo nn-admin trusted-installer-grant --key /path/to/admin.key --window-secs 600
```

This applies to unattended upgrades too: without the key they fail
cleanly and leave the agent running. Neither an attacker nor an
automatic job can replace or remove the agent through the package manager
without a key that carries the `trusted-installer` role.

**A failed operation restarts what it stopped (external audit DEP-010).**
When a `.deb` operation fails after the pre-unpack hook stopped the units
(a file conflict in the unpack, a full disk), dpkg's rollback starts them
again, agent first. A unit that is not active afterwards is named on the
terminal (`northnarrow: rollback failed: not running after the restart:
northnarrow-agent.service (failed) - this host is without NorthNarrow`)
and in the system log (`auth.err`, tag `northnarrow-pkg`), and the hook
fails: dpkg reports the rollback as failed and leaves the package
half-installed instead of "installed" with no agent running. Find the
cause (`systemctl status northnarrow-agent`), start the agent, then the
watchdog, and run the package command again. `rpm` has no rollback
scripts; what it reports instead, and what each package manager can and
cannot roll back, is in §6.2.

**An upgrade that does not pass its health check fails (lab PR 220).** The
package's configure step restarts the units the pre-unpack hook stopped and
runs `install.sh`'s health check on them (§2, step 7: active, every deny hook
attached, the admin socket answering, the watchdog registered in
`PROTECTED_PIDS`). On the `.deb` it runs in the `postinst`: an upgrade that
does not pass fails the hook — the reason on the terminal and in the system
log (`auth.err`, tag `northnarrow-pkg`) — and dpkg reports the package
half-configured instead of installed. The `.rpm` restarts the units in
`%post` and checks them in a `%posttrans` (`install.sh --package-verify`),
once its whole transaction is over, the old package's `%preun` and
`%postun` included: an upgrade that does not pass fails that scriptlet. In
both, the restart list stays in `/run/northnarrow-pkg-restart`, so running
the configure step again (`dpkg --configure -a`) starts and checks the units
again. A first install restarts and checks nothing.

### 6.1 Verify a package before installing it

The package's maintainer scripts run as root as soon as the package
manager unpacks it, so its origin is checked before the package command
(external audit DEP-008). Nothing inside the package can do it: a swapped
package brings its own scripts.

**`.rpm` (RHEL, AlmaLinux).** The release `.rpm` carries an RPM signature
made in the release workflow, on a `v*` tag only, with the key whose
public half is committed at `deploy/release/RPM-GPG-KEY-northnarrow.asc`
(also attached to each release): `NorthNarrow RPM signing`, RSA 4096,
signing only, created 2026-10-17, expires 2028-10-16, fingerprint

```
BBBB EB6F 5566 A1CE 99AE  8379 C66A E018 C172 7C8D
```

Import that key once, from the repository at the release tag, and compare
its fingerprint with the one above (the same is in the README); then let
rpm or dnf check every package:

```sh
curl -fsSLo RPM-GPG-KEY-northnarrow.asc \
  https://raw.githubusercontent.com/northnarrow/northnarrow-new/v<ver>/deploy/release/RPM-GPG-KEY-northnarrow.asc
gpg --show-keys RPM-GPG-KEY-northnarrow.asc         # compare the fingerprint
sudo rpm --import RPM-GPG-KEY-northnarrow.asc
rpm -K northnarrow-<ver>-<rel>.x86_64.rpm           # must print: digests signatures OK
sudo dnf install --setopt=localpkg_gpgcheck=1 ./northnarrow-<ver>-<rel>.x86_64.rpm
```

`rpm -K` prints `digests OK` (no `signatures`) for an unsigned package
and `NOT OK` for a package signed by another key or altered after
signing; dnf with `localpkg_gpgcheck=1`, or a repository with
`gpgcheck=1`, refuses both. `rpm -U` on its own refuses them only with
`%_pkgverify_level signature`. The tag-bound attestation (section 5)
verifies the signed `.rpm` as well.

**`.deb` (Debian, Ubuntu).** dpkg and apt do not check a signature on a
single package file; apt authenticates the signed metadata of a
repository, and NorthNarrow has no apt repository yet. Verify the
attestation, bound to a release tag, before `dpkg -i` or `apt-get
install ./…`:

```sh
gh attestation verify northnarrow_<ver>-<rel>_amd64.deb --repo northnarrow/northnarrow-new \
  --cert-identity-regex '^https://github\.com/northnarrow/northnarrow-new/\.github/workflows/release\.yml@refs/tags/v' \
  --deny-self-hosted-runners
```

A package copied through an internal mirror or a configuration-management
cache is checked the same way on the host that installs it, or the mirror
re-serves it from a repository signed with a key the hosts trust.

### 6.2 What each package manager can roll back (lab PR 220)

`install.sh --upgrade` rolls back on its own (§2): it keeps the copies. A
package manager owns the files of a package upgrade, and the package's
scripts cannot put the previous version back behind its back. What each
one does when a NorthNarrow upgrade fails:

| Failure | dpkg / apt (`.deb`) | rpm / dnf (`.rpm`) |
|---|---|---|
| No usable `NN_GRANT_KEY` (the pre-unpack hook cannot stop the agent) | refused before any file changes; the previous version keeps running | the same (`%pre` fails, the package is not installed) |
| The unpack fails (a file conflict, a full disk) | dpkg restores the previous files itself and its abort hooks start the stopped units again, failing loudly if one does not come back (DEP-010) | no rollback: check the units yourself (`systemctl is-active northnarrow-agent northnarrow-watchdog`) |
| The new units do not pass the health check | **not restored**: the new files stay, the `postinst` fails, the package is half-configured; the units are as the failed start left them | **not restored**: the new package stays installed, the `%posttrans` fails |
| Putting the previous version back | `sudo NN_GRANT_KEY=<key> dpkg -i northnarrow_<previous>_amd64.deb` (or `apt-get install northnarrow=<previous>` from a repository that has it) | `sudo NN_GRANT_KEY=<key> rpm -Uvh --oldpackage northnarrow-<previous>.x86_64.rpm`, or `dnf history undo` / `dnf downgrade northnarrow` when the previous package is still in a repository or dnf's cache |

Keep the previous release's package until the upgraded host has passed its
health check. The previous version's own scripts stop the failed one through
its window (the same key), so a downgrade is an upgrade in the other
direction. Where a host must roll back on its own, install it from the
release tarball (`install.sh`, §1) and upgrade it with `install.sh
--upgrade` (§2).
