# Known limitations of the alpha

> Draft until rc-final: the list is checked again before the v0.1.0-alpha tag.

This page is for people who test the NorthNarrow alpha. It lists what we
know does not work yet, or works only in part, so that you can tell a
known limit from a new problem. Each item says what happens and what it
means for you, with the workaround when there is one.

The alpha installs with the `alpha` profile: the agent detects, judges and
records, and it never kills, blocks or quarantines a user's program
([ALPHA_PROFILE.md](ALPHA_PROFILE.md)). In this release a false positive is
a record, not a broken program. The agent's protection of itself stays on.

Something that is not on this page is worth a report:
[ALPHA_TESTER_GUIDE.md](ALPHA_TESTER_GUIDE.md#9-report-what-you-found) says
how.

**The evidence.** Every item ends with where it was shown:

- a test, by its name (`cargo test <name>` in the source tree finds it; a
  name with a dot is a case of the `nn-admin` golden matrix, a path is a
  lab script of the source tree);
- a CHANGELOG entry, by its lot (`lot 359`: the CHANGELOG's "Lot 359"
  entry, shipped next to these guides);
- an internal check: the pre-alpha phased checks are our own lab reports
  on the release candidates, not published. They are cited by name and
  section: Phase 0 (inventory, and its numbered list of residuals),
  Phase 1 (build and supply chain), Phases
  2, 2b and 2c (install, upgrade and uninstall), Phase 3 (self-protection),
  Phases 4 and 4b (detection), Phases 8 and 8b (kernels and verifier).

## Install and upgrade

- **Hosts the installer refuses.** `install.sh` stops before it changes
  anything on a host that is not x86_64, does not run systemd, has no
  kernel BTF, runs a kernel the agent does not support or, when it is to
  start the agent, has the BPF LSM off or bpffs not mounted. Each refusal
  says what to do. *For you:* on Ubuntu, add `bpf` to the kernel's LSM list
  and reboot before you install
  ([KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md#enabling-the-bpf-lsm-kernel-command-line)).
  A distribution outside the tested list is named, not refused.
  *Evidence:* `a_host_the_release_cannot_run_on_is_refused_with_what_to_do`;
  `install_sh_refuses_a_host_without_nft_unless_told`; lot 341; internal
  check Phase 2 §4.6.
- **A host with a library preload list.** When `/etc/ld.so.preload` names
  a library that exists (a command logger, another vendor's agent), every
  program on the host loads it, and the agent and the watchdog refuse to
  start with a library the release does not link (`start_self_check`,
  `watchdog_start_refused`; exit 78 and 16). `install.sh` (a fresh
  install, a reinstall, `--upgrade`) reads the list before it changes
  anything and refuses such a host with exit status 5, naming the files;
  a list it cannot read as a regular file is refused the same way. An
  empty list, or one that loads nothing, is noted and the install goes on;
  each start still refuses a library that becomes loadable later.
  `nn-admin host-check` fails such a list (exit 3). The `.deb` and `.rpm`
  do not run this check: on such a host the agent's start is refused.
  *For you:* remove the entry or the file, or test on a host without one.
  *Evidence:* `a_preloaded_library_anywhere_is_foreign`;
  `install_refuses_a_loadable_preload_list_and_notes_an_inert_one`;
  `host_check_fails_a_loadable_preload_list`; lot 374.
- **The upgrade has a short window with partial protection.** During
  `install.sh --upgrade`, for about 6 to 15 seconds, not all of the agent's
  kernel programs are attached, and the watchdog is absent for about 18
  seconds. It happens only inside the signed trusted-installer window the
  upgrade opens with your key, the same kind of window a reboot has.
  *For you:* do not run a test you want recorded while an upgrade runs.
  *Evidence:* internal check Phase 2b §4.3 (sampled every 0.2 s, Ubuntu
  24.04 and Debian 13).
- **An upgrade needs your admin key.** Over running units, `--upgrade`
  refuses to start without `--grant-key` and a key with the
  `trusted-installer` role. The key `install.sh` writes,
  `/root/northnarrow-admin.key`, has that role. *For you:* keep it until
  you uninstall. *Evidence:* `an_upgrade_without_a_key_changes_nothing`.
- **A refused upgrade leaves its window open.** When `install.sh
  --upgrade` stops on a check after it opened the trusted-installer window
  (the host, the drop-ins of the agent's units), nothing is installed, but
  the window stays open until its deadline (300 s), and the whole host with
  it (see "Self-protection against root"). *Workaround:* end it sooner with
  a new grant of the shortest length, `sudo nn-admin
  trusted-installer-grant --key <key> --window-secs 1`. *Evidence:*
  internal check Phase 3b.
- **Tracing tools are refused unless you name them at install.** bpftrace,
  BCC tools and `bpftool feature probe` load kernel tracing programs. The
  agent refuses them under every profile; each refusal is a signed High
  record and raises the posture. *Workaround:* install the tools first,
  then do a fresh install with `install.sh --allow-bpf-tools` (or
  `--allow-bpf-loader <path>`), see [ALPHA_PROFILE.md](ALPHA_PROFILE.md)
  §1.2. A tool installed later needs a signed policy line by hand. Run
  `bpftool feature probe` inside a trusted-installer window. The opt-out
  is wide: see "Self-protection against root" below. *Evidence:*
  `the_bpf_hook_refuses_the_rootkit_grade_types_in_every_mode`; lot 345;
  internal check Phase 8 §4.6 (bpftrace with the opt-out on 5.15 and 7.0).
- **The profile is set at install.** A fresh install is `alpha`. Later runs
  of `install.sh` keep the profile they find, and `--profile` does not
  switch an installed agent. *Workaround:* a signed `profile.local` and a
  restart inside a window ([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §4).
  *Evidence:* `install_on_a_running_host_is_unchanged`;
  `the_start_signs_an_unsigned_downgrade_to_alpha`; lot 341.
- **The installer can still leave a High record.** `sudo ./deploy/install.sh`
  and `sudo ./deploy/uninstall.sh` at a terminal are recorded Low. If the
  agent loses the exec record of the sudo chain (a full event ring under
  load), the run can be recorded High (`R009_RootExecFromUserPath`).
  *For you:* harmless under `alpha`; on an idle host it is worth a report.
  *Evidence:* internal check Phase 2b §4.2 (no High from our own install,
  upgrade or uninstall in 25 fresh installs); internal check Phase 2 §7.

## Uninstall

- **Exit codes.** `uninstall.sh` exits **0** when removed and clean; **3**
  when the agent was wedged (its socket did not answer), so no window could
  open and the rest of the removal runs at the next boot (reboot to
  finish); **4** when it removed the agent but found processes the agent
  had contained (frozen, or moved into its own scopes): they were thawed
  and listed by pid and command, and now run outside any unit. *For you:*
  under `alpha` nothing is contained, so 4 is rare; if you see it, decide
  for each listed process whether to keep or kill it
  ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3).
  *Evidence:* `uninstall_help_lists_every_exit_code`; internal check Phase
  2b §4.4.
- **Two kernel modules stay loaded until the next reboot.** After
  `uninstall.sh --purge`, `nf_tables` (with `nfnetlink` and `libcrc32c`
  where nothing else had loaded them) and, on Ubuntu 26.04, `unix_diag`
  stay loaded. The kernel loaded them on demand for the agent; unloading
  one the host's firewall or a container runtime uses would break it. A
  reboot clears them. *Evidence:* lot 350; internal check Phase 2 §4.2.
- **The host's own logs keep the agent's lines.** systemd's lines about the
  units stay in the system journal (and in `/var/log/syslog` where rsyslog
  runs). `--purge` removes only the agent's own journal namespace.
  *Evidence:* internal check Phase 2 §4.2.
- **Without `--purge`, keys and evidence stay.** By design: the admin key,
  the signed audit chain and the records stay for a later reinstall. The
  summary names every private key left on the host; `--purge` removes them
  all. *Evidence:* `uninstall_names_every_private_key_it_leaves`.

## Packages and supply chain

- **The `.rpm` has not been tested in our lab.** It is built and signed in
  CI and passes the CI self-test, but our lab has no Fedora, RHEL or
  AlmaLinux guest. The `.deb` (Ubuntu 24.04, Debian 13) and the tarball
  were tested. *For you:* if you test the `.rpm`, please report what you
  see, even when it works. *Evidence:* internal check Phase 1 §7; internal
  check Phase 2b §4.5 (the Debian package).
- **The SBOMs do not cover the eBPF object.** The release has three
  CycloneDX SBOMs: the agent (which covers `nn-admin` too), the watchdog
  and the scanner. The eBPF object built into the agent is a separate crate
  with its own dependencies (`aya-ebpf` among them), and none of the three
  lists them. *Workaround:* they are pinned in that crate's own lock file,
  `agent-ebpf/Cargo.lock`, in the source tree at the release tag.
  *Evidence:* lot 354; internal check Phase 1 §4.3.
- **`gh attestation verify` needs gh 2.49 or newer.** Ubuntu 24.04 ships
  gh 2.45, which has no `gh attestation` command. *Workaround:* keep
  `SHA256SUMS` and `SHA256SUMS.asc` next to the tarball: `install.sh` then
  checks the signed checksums with `gpgv` and installs with no flag
  ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §5).
  *Evidence:* `a_release_signed_by_the_release_key_installs_and_a_bad_signature_never_does`;
  lot 354.
- **The release's provenance is proven only from the first tag.** The
  build-provenance attestation and the real `SHA256SUMS.asc` are produced
  by the tagged release; the release candidates were checked on CI builds
  of the same tree, which carry neither. *For you:* before the tag, read
  [ALPHA_TESTER_GUIDE.md](ALPHA_TESTER_GUIDE.md#before-the-release-exists)
  for what you can and cannot verify. *Evidence:* internal check Phase
  2c §7; internal check Phase 1 §7.
- **One architecture.** x86_64 only: no ARM64. *Evidence:* internal check
  Phase 0 §4.1.
- **The tarball is not byte-reproducible.** A rebuild gives a different
  file, because file times are kept on purpose (a staleness check needs
  them). The build-provenance attestation is the integrity anchor instead.
  *Evidence:* internal check Phase 1 §4.1 (the same sections, paths
  differ).

## Signed evidence

- **The signing is not forward-secure.** Every record is signed with one
  key that lives on the host for the agent's whole life. A root user who
  steals that key can rewrite the chains' past, not only add new rows: a
  history written again from its first row verifies as the original did.
  Only a head kept elsewhere (the beats an off-host verifier fetched, an
  export already sent) tells the two apart. *For you:* to keep evidence a
  compromised host cannot rewrite, export it or let an off-host verifier
  fetch the heartbeat ([EXPORT.md](EXPORT.md), [HEARTBEAT.md](HEARTBEAT.md)).
  Forward-secure signing is future work. *Evidence:*
  `a_history_rewritten_with_the_agent_key_verifies_only_a_kept_head_tells`.
- **A signature proves the key, not the host.** The agent keeps its
  signing key from readers while it runs. A root who obtains it anyway can
  write lines that verify, and forge the heartbeat. Hardware attestation
  is future work
  ([HEARTBEAT.md](HEARTBEAT.md#what-it-does-not-prove)). *Evidence:* the
  same test; internal check Phase 3 §7.2 (residual R016, of the design).
- **The evidence lives on the host.** A root who stops the agent inside a
  window, or reads the disk from another system, can remove or roll back
  its files. Verification shows a cut chain only against a head you kept
  elsewhere ([EVIDENCE_CHAINS.md](EVIDENCE_CHAINS.md)). *Workaround:*
  forward the agent's journal off the host, or turn on the export.
  *Evidence:* `forged_tail_then_cut_while_down_is_not_found_at_boot`.
- **A flood of records can push older ones off the host.** Each log keeps
  a fixed number of archives of a fixed size, whatever their age. Records
  arriving faster than that budget — a flood, an unprivileged user's
  included — remove the oldest archives from the host. Each removal is
  signed in the log's manifest, and an archive removed less than a day
  after it was sealed is a signed degradation in `nn-admin status`
  (`chain_early_eviction`), but its records are gone from the host.
  *For you:* turn on the export to keep a copy off the host
  ([EXPORT.md](EXPORT.md)). *Evidence:* `an_archive_evicted_young_is_said`;
  lot 370.
- **`nn-admin chain verify` with no chains says OK.** On a state directory
  that holds no chain (a purged host, a wrong `--state-dir`), it prints
  `OK` with 0 rows for each chain and exits 0. *For you:* read the row
  counts, not only `OK`. *Evidence:* `chain.no-audit-log`; internal check
  Phase 0 §5 (F0-3).
- **The heartbeat verifier and pre-release versions.** The off-host
  verifier (`nn-admin heartbeat watch`) says `DEGRADED`, "the sensor
  contract changed backwards", when it cannot tell that the agent's or the
  kernel's version is newer than the last one it saw: a pre-release tag
  such as this alpha's, a kernel of another flavour. *For you:* read the
  version it names; after an upgrade you made, it is not a downgrade.
  *Evidence:* `a_contract_going_backwards_is_degraded`;
  `docs/operator/SENSOR_CONTRACT.md` (§5).
- **A clock set back can hide rows from a `--since` read.** After the
  host's clock went back across a rotation of a log, a read with `--since`
  (`fim report`, `net flows`, `net listeners`, `canary list`) can leave out
  rows of the older archives without saying `truncated`; `nn-admin chain
  verify` and the files still hold them
  ([EVIDENCE_CHAINS.md](EVIDENCE_CHAINS.md)). *Evidence:*
  `a_head_before_since_with_an_older_archive_still_stops`; lot 319.

## Self-protection against root

The agent is **hardened against root, not root-proof.** Outside a signed
trusted-installer window, its kernel hooks refuse root's attempts to stop,
blind, freeze, trace or change it, and the refusals are signed
`NN-L-AT-001_AntiTamperDenial` records (rate-limited, repeats coalesced).
Some things cannot be refused
without breaking the system: for those the agent records what happened,
most within one integrity round (about 30 seconds). Below is what stays
open for the alpha, and the record it leaves. The full analysis is in the
[trust model](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/ANTITAMPER_TRUST_MODEL.md).
*For you, for this whole section:* treat any of these records that you did
not cause as an incident.

- **A trusted-installer window opens the whole host.** While a window is
  open (an upgrade, an uninstall, `nn-admin trusted-installer-grant`),
  every root process, not only the installer, may stop the agent, load
  kernel modules or BPF programs and change the agent's files. A BPF
  program loaded in the window that would be refused outside it is
  recorded High at its load (`bpf_held_load`). After the window it cannot
  be run or attached again, but what was attached inside the window keeps
  running, and each such program still loaded is recorded High. *For you:*
  keep windows short, and open one only when you need it. *Evidence:*
  `a_window_s_forbidden_load_is_signed_at_its_load`;
  `a_held_program_is_refused_at_every_run_and_attach`;
  `a_held_program_still_loaded_after_its_window_is_signed_once`; lot 356;
  internal check Phase 3 §7.1.
- **A refused use of a held program is signed once.** When a program
  held from a window is used again, the use is refused; repeats by the same
  caller are coalesced into one signed record per program and caller, so
  the count of records is not the count of attempts. In rare cases a use can get through: it is not refused and leaves no record of its own, and the program's load record and its "still
  loaded after the window" record remain. *Evidence:* internal check Phase
  3 §7.1 and §7.3 (measured on 6.8, 6.12 and 7.0); lot 356.
- **What was loaded before the agent started.** A kernel module loaded
  before the agent started is beyond its reach. BPF programs present at its start are recorded (High for the types refused outside a window, Low for the others); on kernels from 6.9 their
  later use is not judged. *For you:* install on a fresh VM. *Evidence:*
  `the_start_is_the_baseline_and_a_later_unseen_program_is_signed_once`;
  internal check Phase 3 §7.1 (residual R002).
- **Some BPF paths are not judged.** Some network program attachments and
  some map contents are not judged; their load is still recorded.
  *Evidence:* internal check Phase 3 §7.1 (residuals R002, R132); lot 356.
- **An allowed tracing tool can read everything.** With
  `--allow-bpf-tools`, any root process that runs a named program may load
  tracing programs (for BCC that is any root Python script), and a tracing
  program can read the memory of every process, the agent's keys included.
  *For you:* use the opt-out on a test VM only. *Evidence:*
  `an_allowed_loader_cannot_load_what_kills_or_blinds_the_agent` (what it
  still cannot load); lot 345.
- **A module installed by a package transaction is trusted.** A module
  file written in the running kernel's tree since boot is trusted when the
  package database or DKMS's registry vouches for its content and the
  write came from a live package transaction: the package manager's
  process held its lock, was not stopped or traced, and the writer
  descends from it with no code injected. A module written by root inside
  a package transaction it controls is trusted too. Every load the kernel
  trusted is recorded, Low, with why it was trusted. The lock is read in
  the kernel at the write, however short the transaction. A transaction that took its
  lock while the agent's lock observer was not attached — before the
  agent's first start of the boot, or in the moment of an upgrade between
  the old agent's purge and the new one's start — holds no lock the kernel
  knows: its module files are judged as written outside one (DKMS's build
  let through and recorded High, a package's file elsewhere refused) until
  the next transaction rewrites them or the next boot. If that observer
  cannot attach (a signed observe failure), the agent samples the locks
  instead, and a transaction that begins and ends between two of its
  samples is not seen. *Evidence:*
  `a_short_transactions_module_file_is_trusted_by_its_lock_at_the_write`;
  `a_module_write_is_a_transactions_only_while_it_holds_its_lock`;
  `a_trusted_load_is_recorded_low_with_why`; lot 370.
- **Unsigned kernel modules on a host without lockdown.** The module-load
  judge refuses modules the agent does not trust, but the kernel itself is
  the host's to protect: without kernel lockdown and module signing, root
  keeps ways into the kernel that no hook of the agent sees (the anti-tamper
  lab's known gap). *For you:* enable lockdown and module signing on a host
  you care about; `nn-admin host-check` reports both. *Evidence:* internal
  check Phase 3 §7.1 (C27, as declared on 4 kernels).
- **Mounts.** A mount on, over or below the agent's directories, binaries,
  units, `/proc`, `/sys`, the cgroup root or the bpffs, and an unmount or a
  move of the mounts that hold them, is refused in the host's mount
  namespace and in the agent's and the watchdog's own; so is one made
  elsewhere that would propagate into those. What is not refused is
  signed:
  - a change of a protected mount's attributes is not refused: the next
    integrity round signs it (`integrity_drift`, `mount_attrs_changed`,
    High);
  - a mount namespace of its own (a container's, one made with `unshare`)
    is judged where it reaches the host's mounts; what it changes in its
    own copies only is its own;
  - on a kernel where the mount guard is not attached, every such mount is
    a signed degradation, and the mount watch (`mount_over_protected`)
    remains;
  - the emergency remount (`SysRq-u`) is not refused: it makes every
    block-backed file system read-only and is signed High
    (`state_fs_read_only`); restrict `kernel.sysrq` if the host needs no
    emergency remount.

  *For you:* some administration needs a window: a runtime `systemd-sysext`
  or `confext` refresh, a remount of `/proc`, `/sys`, the cgroup root or the
  bpffs, a read-only remount of `/` or the agent's file systems, `systemctl
  soft-reboot`, and on Ubuntu 22.04 a `mount --move` in the host's
  namespace. Container runtimes, including Kubernetes' bidirectional
  mounts, work. A host whose `/` is a tmpfs, or an ostree host, signs its
  layout as not canonical at each start (`mount_not_canonical`).
  *Evidence:* `a_protected_mounts_attributes_changed_are_reported`;
  `a_mount_over_protected_is_signed_high`;
  `the_guard_is_not_attached_without_the_offsets_it_reads`; lot 357;
  internal check Phase 8b §7.
- **The pin directory's lock: residuals, each signed.** The directory
  that keeps the agent's kernel programs pinned is locked in place. For the
  alpha the lock does not cover every case. In each, the agent keeps its
  kernel programs attached (it holds a descriptor of every one), and an
  integrity round, about 30 seconds apart, signs what happened (High); a
  loss that comes back soon after one already signed is reported again
  later, as every drift finding is:
  - a change of the lock's own settings is not refused: the next round
    signs it (`pin_lock_changed`) and makes the lock again;
  - in some other mount namespaces the lock does not hold: the host's
    bpffs view (and, in one case, the pins) can be lost; each loss is
    signed (`protected_mount_gone`, `pin_lock_missing`);
  - the systemd units' own mount namespaces, the agent's and the
    watchdog's among them, never have the lock. That namespace's view of
    the bpffs can be lost, not the host's nor the pins; what reads the pins
    by path there fails until a restart. Signed `protected_mount_gone`.

  A hardening lot after the alpha narrows the first two. A start that finds
  no lock (a kernel without `open_tree(2)`, an error) signs a degradation
  and the round makes it. *For you:* if a `protected_mount_gone`,
  `pin_lock_missing`, `pin_lock_changed` or `bpf_pin_vanished` appears that
  you did not cause, do not restart the agent before a reboot: its
  descriptors keep its hooks while it runs. *Evidence:*
  `a_lost_or_changed_lock_is_a_finding_and_made_again`;
  `a_start_without_the_lock_is_a_degradation`;
  `a_removed_held_pin_is_a_high_pinned_again`;
  `a_mount_gone_from_under_the_agents_paths_is_reported`; lot 359;
  internal check Phase 2c §7; internal check Phase 8b §4.2.
- **The unmount guard reads a bounded part of the mount tree.** An
  unmount is judged on the part of the mount tree the guard reads. Outside
  the host's namespace some unmounts that take a host mount the agent
  relies on are not refused; the agent's hooks stay attached while it runs
  and the integrity round signs `protected_mount_gone` (High). In the
  host's namespace an unmount wider
  than the guard reads is refused even when it is harmless: use `umount
  -R`, or a window. *Evidence:* `a_mount_gone_from_under_the_agents_paths_is_reported`;
  lots 357 and 359.
- **A FUSE file system over the agent's paths.** The agent reads `/proc`,
  `/sys` and its own state beneath views it opened at its start, with
  deadlines, and refuses a mount over them (above). A FUSE mounted over
  those paths before the guard attached, or on a kernel without it, is
  signed (`mount_over_protected`); an agent stuck on one is restarted by
  the watchdog and signed (`stuck_unresponsive`, `stuck_recovery_failed`),
  and a FUSE connection holding it is aborted (`fuse_aborted`).
  *Evidence:* `a_stuck_recovery_and_a_restart_loop_are_signed`;
  `a_fuse_on_the_way_is_never_read`; lot 353; internal check Phase 3
  §7.3.
- **Run the agent and the watchdog only through their units.** The mount
  guard of the host's namespace is complete only when the agent and the
  watchdog run as their units; started by hand, outside them, the guard
  there is not supported. *For you:* start, stop and restart them only
  with `systemctl`, inside a window. *Evidence:* lot 359.
- **Changes systemd needs are recorded, not refused.** Some changes
  systemd itself needs (unit properties, drop-ins outside the directories
  the agent guards), and some changes to the agent's settings, are a
  signed `integrity_drift` at the next round, within about 30 s
  ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3.5). A
  `daemon-reload` inside a signed window applies a drop-in already on
  disk. *Evidence:* `dropins_are_read_from_every_directory_of_the_unit_search_path`;
  `a_process_without_the_unit_s_confinement_is_drift`; internal check
  Phase 3 §7.1 (residual R015).
- **A refused `set-property` stays in systemd's memory.** systemd changes
  its own copy of the property before the agent refuses the write.
  `systemctl show` then reports the new value, and the unit's next start
  would apply it. The refusal is signed. *Workaround:* run
  `sudo systemctl daemon-reload` before you restart the agent.
  *Evidence:* lot 273b; internal check Phase 3, appendix A (C100).
- **A soft-reboot leaves the units `failed`.** `systemctl soft-reboot`
  (systemd 254 and later) cannot stop the agent: it survives with its
  protection, but the new userspace's systemd marks the units `failed`
  (systemd 255, 257) or stopped (259). *Workaround:* use a full reboot.
  *Evidence:* lot 273b.
- **A stop pulled in by another unit.** When a unit that conflicts with the
  agent's unit starts, the agent refuses the signals and keeps running, but
  systemd records its unit as stopped (`systemctl status` says `inactive`).
  *For you:* `nn-admin status` tells you the agent runs; a reboot puts
  things back. *Evidence:* internal check Phase 3, appendix A (C78a,
  C78b).
- **Kills nothing can refuse.** The kernel's OOM killer, a crash or a power
  loss end the agent without asking. The watchdog brings it back, and the
  next start records how the previous run ended (`previous_run` with
  `"ended":"abrupt"` in its signed `agent_boot` entry). The agent and the
  watchdog run with `oom_score_adj` -999: the host's OOM killer picks them
  last, and their own memory cap still ends a leak with a kill and a
  restart. On a host with less memory than the agent's cap (11 GiB) the cap
  cannot bind: a leaking agent outlives every other process, the
  workload and `sshd` included, which the OOM killer picks first. A kill
  nothing can refuse can still end the agent or the watchdog, and its role
  stays vacated until a successor takes it. What is recorded then, and by
  whom (lot 374):
  - The agent's vacancy and its successor are signed by the watchdog, the
    surviving role, in a witness chain of its own: the vacancy with its
    cause as systemd records it (an OOM kill in its unit, a signal, an
    exit status; "not known" when systemd has not recorded it in time;
    after a SIGKILL, the slice's OOM kill count when it rose, the cause
    then not known: the count is the slice's, the workers' too), then the
    process that took the role — its parent, its cgroup, and whether its
    environment or its executable mappings hold anything the release does
    not start with. The watchdog's key lives in its memory for its life;
    the agent certifies its public half from the watchdog's own descriptor
    table and imports every row it can verify into its signed audit chain
    (`witness_row`, High, for a vacancy outside a signed window, a
    successor that is not its unit's clean restart, a held start or a cut
    chain). The chain is the watchdog's to write alone: the kernel refuses
    the agent's and every other process's write of it outside a
    trusted-installer window, and the watchdog checks that it still ends at
    its last row, a chain that does not is set aside and the new one says
    so (`witness_chain_cut`). A row changed, or signed by a key the agent
    never certified, is recorded as such (`witness_chain_broken`,
    `witness_row_uncertified`).
  - Before each start of the agent it makes, the watchdog compares what
    the host would give the successor before its start — a loader preload
    list and each library it names, a drop-in that changes our units'
    code, systemd's copy of the agent's unit — with what it read at its
    own start: a change holds the start (`role_respawn_held`,
    `watchdog_respawn_held`, High) until an operator acts; what was there
    before is recorded only. Inside a signed trusted-installer window
    nothing is held, and the window takes the host as it then is as the
    new reference, changes made before it included
    (`respawn_gate_reference_moved`, signed): a later start in the same
    watchdog life is judged against it. *For you:* when the agent does not
    come back, read the watchdog's journal before you open a window (a
    held start is a `role_respawn_held` row there). A successor that
    started before that judgement, outside a window, is
    recorded as the role taken by a start the watchdog did not make
    (`role_taken_by_another_start`, High), after that start.
  - A clean stop inside a signed trusted-installer window (the operator's
    restart or stop, also when cut at its deadline: exit status 75,
    `stop_deadline`) is a note (`role_released_in_window`), as is a
    shutdown the admin quorum signed (`role_released`); another exit inside
    a window stays `role_vacated`.
  - The watchdog's vacancy and its successor are signed by the live agent
    (`watchdog_gone`, then `watchdog_succession` or
    `watchdog_successor_foreign`). Each role's start judges the other
    role's process at every start: one that is not its unit's clean
    restart is signed (`…_successor_foreign`) and the agent's start does
    not register a watchdog it finds so, whatever an earlier holder
    concluded — an earlier refusal never lapses with the holder that made
    it. A verdict that the process is clean is signed only when it took
    its role while the judging role was vacant. A library replaced on
    disk since a process mapped it is judged by identity: not the judging
    role's own copy, it is signed High (`role_successor_unconfirmed`,
    `watchdog_successor_unconfirmed`) for such a successor, and the
    process keeps its registration.
  - When both roles were vacated, the next agent start signs the gap it
    finds (`roles_vacated_gap`), or a note when the operator released both
    (`roles_released`).
  - The taking is NN-L-BPF-002: High when no signed trusted-installer
    window was open, Low inside one (the installer's restart).
  Only the restart systemd makes of the role's own unit takes a vacated
  role: a child of PID 1 in that unit's own cgroup, with clean lot 277/281
  marks, in or out of a window. A process started anywhere else, a
  transient unit included, is refused the role by the kernel and is
  recorded. A unit's restart that shows something foreign holds the role
  the kernel gave it: recorded (`role_successor_foreign`,
  `watchdog_successor_foreign`), not refused, and the other role does not
  register it. The units unset the dynamic loader's and the C library's
  variables, whatever the service manager's environment holds, and deny
  memory both writable and executable; a start that finds a loader
  variable, or an executable mapping of a library the release does not
  link, refuses itself before it takes its role, signed
  (`start_self_check`, `watchdog_start_refused`). What is not yet guaranteed: a successor that runs
  code root gave it before its start, and that hides it, is not reliably
  told from its unit's clean restart; what it signs then, its import of
  the watchdog's rows included, is not evidence, and neither is the
  absence of the watchdog's rows about it. The watchdog's judgement of the
  host before a start covers the starts it makes: a start it did not make
  is recorded after it, not prevented. While the watchdog is gone too, or
  runs without its witness (`witness_unavailable`, High), the agent's
  vacancy is recorded only by the next start (`previous_run`, the
  succession record, the gap it finds). On a host without systemd (the watchdog's `exec`
  respawn backend) a vacated role is not taken again until the next boot.
  The agent judges a process that takes the watchdog's role at its next
  round, while the kernel's guard refuses one outside the unit at once.
  *Evidence:* `previous_run_none_abrupt_clean`;
  `the_agent_and_the_watchdog_are_the_oom_killer_s_last_pick`;
  `a_role_taken_after_its_holder_exited_is_high`;
  `a_role_left_by_its_holder_is_high_outside_a_window_and_low_inside`;
  `a_role_its_holder_left_outside_a_window_is_recorded_high`;
  `the_witness_signs_the_vacancy_and_the_successor_in_one_chain`;
  `witness_rows_are_imported_once_after_their_key_is_certified`;
  `the_witness_key_is_read_only_from_the_watchdog_s_own_sealed_file`;
  `a_tail_cut_while_the_watchdog_lives_is_detected_and_signed`;
  `the_witness_chain_is_the_watchdog_role_s_alone_and_never_opened_for_writing`;
  `a_preload_new_since_the_watchdog_s_start_holds_and_an_old_one_is_recorded`;
  `a_code_drop_in_new_since_the_watchdog_s_start_holds`;
  `the_gate_holds_nothing_inside_a_signed_window_and_adopts_the_host`;
  `systemd_s_copy_of_the_agent_s_unit_is_judged_before_a_start`;
  `a_library_the_preload_list_names_that_became_loadable_holds`;
  `a_succession_is_the_other_role_s_process_taken_while_this_role_was_vacant`;
  `a_successor_refused_by_an_earlier_holder_is_judged_again_at_the_next_start`;
  `a_watchdog_an_earlier_agent_refused_is_refused_again_at_the_next_agent_start`;
  `a_watchdog_successor_no_agent_judged_is_judged_at_the_next_agent_start`;
  `a_long_running_watchdog_given_at_an_agent_start_is_registered_with_nothing_signed`;
  `a_watchdog_refused_while_its_slot_was_vacated_is_judged_again_once_it_holds_the_slot`;
  `a_library_replaced_since_it_was_mapped_is_judged_by_identity`;
  `a_torn_append_of_the_watchdog_s_own_is_repaired_and_said_torn`;
  `inside_a_window_only_a_clean_stop_is_the_operator_s`;
  `a_vacancy_inside_a_signed_window_is_released_not_vacated`;
  `both_roles_released_by_the_operator_is_a_note_not_the_gap`;
  `a_watchdog_successor_is_registered_only_as_its_unit_s_clean_restart`;
  `a_foreign_successor_is_recorded_as_holding_the_role_never_as_refused`;
  `only_the_unit_s_restart_with_nothing_foreign_is_given_the_role`;
  `only_pid_1_in_the_unit_s_own_cgroup_is_its_restart`;
  `a_unit_restart_takes_the_vacated_role_under_enforce`;
  `both_roles_vacated_is_the_gap_and_nothing_else_is`;
  `every_unit_unsets_every_loader_variable`;
  `every_unit_denies_writable_and_executable_memory`;
  `memory_deny_write_execute_off_is_judged_as_systemd_parses_it`;
  `a_start_with_a_loader_variable_refuses_itself_before_the_load_and_signs_it`;
  `a_preloaded_library_anywhere_is_foreign`;
  `every_supported_library_layout_is_a_genuine_start`; internal check
  Phase 3 §7.2.
- **Weakening variables from the service manager's environment are
  ignored, not refused.** A variable that weakens the agent, set in the
  service manager's environment rather than in the agent's unit, is
  removed at the agent's start and signed as a degradation
  (`weakening_env_ignored`). The agent tells the two apart by asking the
  service manager; when it cannot ask nothing is removed, and
  the variable is honoured and signed as `weakening_env`. One set in the
  unit (or a drop-in) is honoured and signed as `weakening_env`, as before.
  *Evidence:* `a_weakening_variable_from_the_service_manager_is_ignored`;
  lot 370.
- **The agent's CPU time.** Heavy CPU load from root processes can slow the
  agent. A stall of more than 15 s is a signed `agent_stalled` record. A
  confinement of the agent to fewer CPUs is not refused: it is detected
  and signed (`cpu_confined`, High), shown in `nn-admin status` (the
  `own_cpus` degradation), and withdrawn when it ends. Some limits on the
  agent's or the watchdog's CPUs are not recorded (one made before the
  agent's first round, CPUs taken offline). *Evidence:* `a_sibling_partition_confining_the_agent_is_a_confinement`;
  `a_cpu_taken_offline_is_no_confinement`; lot 349; internal check Phase 3
  §7.1 (residual R001).
- **The journal can be emptied.** Root can empty the system journal, the
  agent's lines included (the anti-tamper lab's known gap). The signed chains are not in the journal. *Evidence:* internal
  check Phase 3 §7.1 (C57c, as declared).
- **The kernel is the host's to protect.** A root that can write kernel
  memory can defeat any defence inside the kernel. Kernel lockdown, module
  signing, Secure Boot and disabled kexec are recommended, and
  `nn-admin host-check` reports each one
  ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3.1).
  *Evidence:* internal check Phase 3 §7.1.
- **Root can read physical memory without lockdown `confidentiality`.** The
  agent keeps its signing key in a locked page that is never swapped or
  dumped, and refuses root's ptrace, `/proc/<pid>/mem`,
  `process_vm_readv` and core dumps of its processes. It cannot refuse a
  read of physical memory: without kernel lockdown at `confidentiality`,
  root can read it, the agent's signing key included; `integrity`, the
  level recommended, does not prevent it. On such a host the signing key and the
  agent's other in-memory secrets are not protected from root.
  `nn-admin host-check` warns when lockdown is off. *Evidence:* lot 367;
  internal check Phase 3b (F3b-4).
- **Reading the agent's memory on kernels from 6.16.** From 6.16 the
  kernel lets a process with `CAP_PERFMON` or `CAP_SYS_ADMIN` through its
  read-mode memory access check even when the agent's ptrace hook refuses
  it. The agent refuses the open of its memory views itself
  (`/proc/<pid>/environ`, `auxv`, `maps`, `smaps`, `smaps_rollup`,
  `numa_maps`, `pagemap`, its own or a thread's), whatever the open's
  access mode, recorded Low as
  `ptrace_read`, "denied in kernel (the open …)". The hook's other
  read-mode refusals (`exe`, `ns/*`, `fd/`) are recorded "the hook
  refused; the kernel's outcome not observed". Some memory hints on the
  agent's process are not refused: they read none of its content, but can
  reveal which address ranges are mapped. Without the kernel's proc offsets in its
  BTF the open refusal is not armed, a signed degradation. *Evidence:*
  `the_memory_views_are_refused_at_their_open_with_the_hooks_decisions`;
  lot 367; internal check Phase 3b (F3b-1).

## Detection coverage

- **A program run through the dynamic loader.** The staging rules judge a
  program the dynamic loader runs (its operand, a library it preloads) as
  if the kernel had executed it, where the agent finds the file the loader
  maps (links followed as the kernel follows them), as it reads the
  process just after the exec. A program the agent cannot place where the
  loader maps it is recorded (R001, Medium) without a response, or judged
  by its name; a descriptor's link it cannot place is judged as fileless
  code (R004). A loader that only lists or checks a program can still run
  code the program names, so the agent never takes such a listing as
  harmless: a staged program (in `/tmp`, a memfd, a FUSE file and the
  like) listed so is never recorded Low — judged as run (the kill) when
  the file the agent read names code to run, recorded Medium otherwise,
  and its record does not say that nothing ran. `--verify` and musl's
  `ldd` run nothing (Low); musl's loader runs a program it is asked only
  to list (judged as run). A library `--audit` names runs in every mode
  and is judged. *Evidence:*
  `a_program_run_through_the_dynamic_loader_is_judged_as_if_executed`;
  `a_loader_operand_through_a_proc_view_link_is_judged_as_a_direct_exec`;
  `a_loader_that_only_lists_is_recorded_low_and_one_that_runs_stays_judged`;
  `a_staged_program_glibc_lists_is_never_low_whatever_the_pump_read`;
  `a_header_with_a_wrong_program_header_size_or_count_is_not_known`;
  `no_buffer_of_the_reader_is_larger_than_its_fixed_bound`;
  `a_listed_program_s_auditing_libraries_are_read_from_the_file_it_maps`;
  `a_loader_operand_through_a_symbolic_link_is_placed_where_the_kernel_finds_it`;
  lot 370.
- **A file of the FIM watch list absent at the start.** Its creation is an
  event with its writer, judged as a change of the file would be. Some ways
  a watched file first appears are reported later with no writer, or not
  at all; from then on the file is watched.
  *Evidence:* `ld_so_preload_created_after_the_start_is_fim_022_with_its_writer`;
  `root_authorized_keys_created_after_the_start_is_fim_004`; lot 370.
- **Files written in a package manager's lineage are recorded Low.** A
  write of a watched file by a process descending from a package manager
  root ran (dpkg, rpm, dnf, apt's lineage), while that package manager
  runs or just after, is recorded Low, not killed — killing a transaction
  would leave a half-installed package — and so is an account tool's change
  to the users database inside one. Unlike a kernel module's, such a write is not checked for a live transaction: a root process in a package manager's lineage has its writes of watched files recorded Low. `/etc/ld.so.preload`, root's `authorized_keys`, the bait files and
  the credential files keep their severity. *Evidence:*
  `package_manager_writes_are_logged_not_killed`;
  `account_tools_in_a_package_transaction_are_recorded_low`.
- **No adversarial campaign yet.** The rules have unit, end-to-end and lab
  tests; on the release candidate each rule was reproduced once, as its
  "How to test" says, on 5 kernels. No independent or adversarial campaign
  has measured them, and no coverage percentage is published. ATT&CK
  coverage means "at least one rule sees the technique", not every way of
  carrying it out. *Evidence:* internal check Phase 4 §4.2 and §7;
  internal check Phase 4b §7.
- **Two exploit-guard rules are not shown on a release build.**
  NN-L-EPG-001/002 fire on a real exploit's effect only (credentials or
  namespaces changed outside the lawful paths); a release build has no
  harmless trigger. Their proof is the end-to-end tests on a debug build.
  *Evidence:* internal check Phase 4 §7.
- **Partial telemetry.** Exec events only: no fork, exit or credential
  change events. DNS is read over UDP only: no DNS over TCP, DoT or DoH.
  *Evidence:* internal check Phase 0 §4.1.
- **Some rules recognise a program by what it is.** The netcat and miner
  rules (`R005_NetcatExec`, `R007_CryptoMiner`) go by the program's name,
  and a reverse shell is recognised by the installed shell the kernel ran,
  not by behaviour. A program the agent does not know is judged only by
  the other rules (where it runs from, what it opens, where it connects).
  *Evidence:* `fires_on_each_netcat_alias`; `fires_on_known_miner_comms`;
  `a_shell_on_an_outbound_socket_is_a_critical_reverse_shell`.
- **Ransomware detection looks for shapes.** It looks for mass rewrites,
  renames to new extensions and high-entropy writes, by one process or one
  unit within a time window. Encryption that does not show those shapes
  may be seen only by weaker signals, or not at all; on its own it raises the posture to
  ENGAGED, not COMBAT. *For you:* keep backups off the host; detection
  does not replace them. *Evidence:* internal check Phase 0, residuals R024,
  R025, R026.
- **Ancestry is followed to a limit.** The agent follows a process's
  ancestors to a fixed depth; a longer chain of wrappers is judged on what
  that depth shows. *Evidence:* internal check Phase 0, residuals R027, R053.
- **Security tools switched off.** The `NN-L-EVA-*` rules recognise only
  the commands in their table. Other ways to stop a security tool may leave
  no record. *For you:* also check from each tool's own status and logs
  that it still runs. *Evidence:* internal check Phase 0, residuals R028,
  R029.
- **Not watched by file integrity.** udev rule directories and initramfs
  hook directories are not watched: a new file there leaves no file
  integrity record. What such a file runs later is judged by the process
  rules. *Evidence:* internal check Phase 0, residuals R039, R040.
- **Some exemptions are wider than they should be.** A few exemptions for
  package managers and developer tools (npm under a system prefix, go,
  database initialisation) trust the tool by identity. They are listed in
  [UPGRADE_NOTES_WAVE4.md](UPGRADE_NOTES_WAVE4.md) §34 and §39 and will be
  narrowed. *Evidence:* lots 346 and 347.
- **An AppImage's own program is judged as the image's.** The program an
  AppImage serves from its read-only mount is judged like the image file
  the user ran, so a desktop app does not draw a "run from `/tmp`" record
  at each launch. The tie is made from what the kernel shows of the mount
  and the image's daemon; a user who controls their own image's runtime
  can make files of their own be judged as the image's, which are
  programs they could run from their home anyway. What the program then
  does is judged as for any user program. *Evidence:*
  `an_appimage_program_is_its_image_s`; lot 355.
- **A file system that does not answer leaves exec facts not verified.**
  To judge a program it runs, the agent reads facts about the program's
  files, with a short deadline and fairly between users, never on the
  exec pumps themselves; a FUSE file system is never read. A fact not read
  in time is judged not verified, never trusted, and the exec sensor is
  signed degraded (`exec_reads_unanswered`; `exec_readers_held` while a
  share of the reader is held; `exec_reads_slow`, naming the user, when
  slow reads slowed the exec pump). A user's subordinate ids
  (`/etc/subuid`) count as that user. An id from 65536 up that the agent
  cannot give one known user is *unattributed*: every such id while the
  ranges are not published (before the first publish, and always with the
  file-open sensor on its tracepoint), or while `/etc/subuid` cannot be
  read; an id of a range whose owner `/etc/passwd` does not name (an sssd
  or LDAP user's), of overlapping ranges or of a gap; an id past every
  range (a range added since the agent last read the file, a domain account with a high
  uid). The unattributed ids have one share of the reader together, one
  read at a time: they can make each other's facts unverifiable, never an
  attributed user's, root's or the system accounts', and that share held
  is signed once while it lasts (`exec_readers_held`). One user cannot
  make another user's facts unverifiable; two users acting together can
  hold the users' share, and that is signed (`exec_readers_held`). *For
  you:* such a degradation in `nn-admin status` is worth a report, with
  the file systems mounted at the time
  (`findmnt -t fuse,fuseblk,nfs,nfs4,cifs`).
  *Evidence:* `one_uid_cannot_starve_root_s_reads`;
  `one_user_s_subordinate_ids_starve_no_other_user`;
  `unattributed_ids_none_published_starve_no_attributed_user`;
  `unattributed_ids_subuid_unreadable_starve_no_attributed_user`;
  `unattributed_ids_owner_not_in_passwd_starve_no_attributed_user`;
  `unattributed_ids_past_every_range_starve_no_attributed_user`;
  `the_slow_records_never_crowd_out_the_exec_signals`;
  `an_exec_step_that_never_answers_is_not_waited_for`; lot 366.
- **After a long suspend, a record can name an earlier program.** A
  process id reused after the host spent a long time suspended can be
  taken for a process that held it before the agent started (a laptop
  whose agent restarted since). The record then names that earlier
  process's program, while what ran is still judged by its own exec.
  *For you:* a record whose program does not match what you ran, on a
  host that was suspended, is worth a report. *Evidence:* lot 360.
- **Children that only fork.** A process that forks without running a new
  program is judged by its parent's image. A few fork-only children are
  judged by their path rather than their image, or on their parent's
  earlier image.
  *Evidence:* `fork_only_connects` tests (lot 360); lot 360.
- **A TLS fingerprint is not an identity.** `NN-L-NET-003_BadJa3` records a
  listed JA3 or JA4 at Medium and never acts on it. *Evidence:* internal
  check Phase 4 §4.4.
- **Prevention is experimental and off.** The exec policy, the exec
  quarantine and the copy-on-first-write guard are off by default. Under
  `alpha` they would only observe anyway. *Evidence:*
  `every_enforcing_switch_takes_the_resolved_gate`; internal check Phase 4
  §7.

## False positives you may see

Under `alpha` a false positive is only a record. Its `response` field
reads `would have: <action>` when `enforcing` would have acted. The
[rule catalogue](https://github.com/northnarrow/northnarrow-new/blob/main/docs/detection/RULE_CATALOGUE.md)
lists the known false positives of each rule.

- **Expected on a quiet host, at Low:** one `NN-L-BPF-002` at each start
  of the agent or the watchdog; records at boot for systemd's own BPF
  programs; logrotate's daily run; on Debian 13 and Ubuntu 26.04 cloud
  images, cloud-init's netcat at each boot (`R005_NetcatExec`); on Ubuntu
  26.04, systemd's own BPF feature probes, refused and recorded
  (`NN-L-AT-001`). *Evidence:* lots 340 and 344; internal check Phase 2b
  §4.2.
- **Container runtimes**: see "Containers" below.
- **Builds and tests that run from `/tmp`.** A build that runs what it
  unpacked in `/tmp` is `R001_ExecFromTmp` High (a person's; the kill held
  below COMBAT). A person's `go test` and `go run` with the packaged `go`
  (`/usr/lib/go-<version>`, `/usr/lib/go`, `/usr/local/go`, the snap) are
  recorded Low (lot 369; lot 372 for Go 1.21 and later, whose link command
  the sensor reads cut). Still High, by design:
  - a `go` outside those trees — one a `GOTOOLCHAIN` switch downloads into
    the module cache (`~/go/pkg/mod/golang.org/toolchain@…`), one unpacked
    in a home — and its build output: the agent knows the packaged
    toolchain only;
  - a link whose arguments pass 30 KiB (`go` then hands the linker a
    response file, `@file`, whose `-o` the agent does not read);
  - `go run` with `GOCACHE` under `/tmp` or `/var/tmp`: from Go 1.24 a
    program already in the build cache runs from the cache itself, not
    from the work directory, and is judged as any exec from there (with
    the default `GOCACHE`, in the home, it is no staging exec at all).
  - a CI runner account with a login shell and a regular uid counts as a person: its `go test` and `go run` are recorded Low, like a developer's.
    A service account with no login shell, and root, stay judged.
  What a person's own build flags or build cache make `go` produce is the user running their own code — Low by design, as a module of their own.
  *Evidence:* lots 346, 369 and 372.
- **npm installed with nvm or in a home directory.** It is not exempt:
  `npm ci` there can raise the posture to ENGAGED. *Evidence:* lot 346.
- **Desktop sessions.** Services started by a user's systemd manager are
  not vouched for, so a desktop draws more records than a server.
  *Evidence:* internal check Phase 0, residuals R052.
- **Heavy ordinary writes.** Database initialisation (`initdb`), container
  image unpacking (containerd, k3s), `rsync --inplace` and large builds can
  raise the posture to ENGAGED through the mass-write signal. *Evidence:*
  lots 346 and 347; internal check Phase 0, residuals R055.
- **Backups and searches.** A backup tool, `tar` or `grep -r` that reads a
  watched credential file or a canary is recorded like any other reader.
  *Evidence:* internal check Phase 0, residuals R056.
- **Admin tasks not measured yet.** `ssh-copy-id`
  (`NN-L-FIM-004_AuthorizedKeysModified`), a systemd timer installed outside
  a package (`NN-L-FIM-009_SystemdUnitDropped`), an installer run from
  `/tmp` that connects out (`NN-L-NET-008_OutboundFromTmpExec`): recorded
  High. *Evidence:* internal check Phase 0, residuals R054. A snap
  install's own units (the snap's mount and service units, written by the
  host's snapd, the process its systemd unit runs, in the unit's cgroup) are
  recorded Low. The agent trusts snapd's units as the snapd service's own,
  as it trusts a package transaction (the package-manager boundary above);
  root changing what a system service runs is the act to watch for. *Evidence:*
  `the_host_s_snapd_writing_its_own_units_is_low_and_nothing_else_is`,
  `snapds_identity_is_snapd_services_process_with_clean_marks`; lot
  367.
- **DNS resolvers outside the system trees**, or run in a unit with a name
  the agent does not know: judged as any process, so their DNS traffic can
  draw DNS records ([UPGRADE_NOTES_WAVE4.md](UPGRADE_NOTES_WAVE4.md) §34).
  *Evidence:* lot 344.
- **Purging another package that has systemd units.** The package tool
  tries to remove empty unit directories, the agent's own among them. The
  agent refuses that and records `NN-L-AT-001`. The purge completes.
  *Evidence:* internal check Phase 0, residuals R057.
- **Stopping the agent by hand.** `systemctl stop`, `kill` or `restart` of
  the agent outside a window is refused and recorded `NN-L-AT-001` High.
  Use a window ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md)
  §3.7). *Evidence:* `deploy/lab/adversarial/anti-tamper.sh` (C01).
- **The host's own boot, shutdown and package routine** (lot 373, the
  rc7 soak). Recorded Low or not at all now, each by identity:
  - the agent re-creating its `/run/northnarrow` control-surface files at
    every boot (no `NN-L-FIM-024`);
  - `sudo bpftool prog show` (or `map list`, `cgroup tree`) with the
    packaged bpftool: still refused, `NN-L-AT-001` Low, no posture; in
    observe mode, where the kernel lets the handles through, one
    `NN-L-BPF-002` Low record per bpftool process, no posture;
  - rsyslogd's last flush and `systemd-update-utmp`'s record at shutdown,
    judged by what the kernel recorded at the write;
  - a package's postinst running `setcap` with a narrow capability
    (`cap_net_raw`, `cap_net_admin`, `cap_net_bind_service`, `cap_sys_nice`,
    …: `ping`'s, `gst-ptp-helper`'s) on its own files in its transaction
    (`R012` Low);
  - systemd-timesyncd, chronyd or ntpd polling UDP 123 as their service
    account, in their unit's cgroup, started there and never injected (no
    `NN-L-NET-013`).

  Still recorded High: `sudo logrotate -f` by hand (by design, lot 340); a
  `setcap` from a session or on a file of no package; any grant in a
  package transaction beyond the narrow set — a capability equivalent to
  root (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`, …), `=ep` — on
  `R012` and on `NN-L-FIM-025` (kept, not stripped); a bpftool `map dump`,
  `update`, `pin` or `detach`, or any other program's handle on the agent's
  objects; any other program beaconing to UDP 123. chronyd and ntpd keep a netflow allowlist entry by identity: their flows are not judged as beacons, whatever the port (a residual, named). 
  Expect on the RPM family: `NN-L-FIM-025` High (Log, kept, not stripped)
  at each install or upgrade of a package that ships a root-equivalent file
  capability (`shadow-utils`' `newuidmap` with `cap_setuid`, `newgidmap`
  with `cap_setgid`): a package transaction cannot vouch for such a grant.
  A capability number the text spells with a leading `0` (octal), in hex or
  with a sign is read as libcap reads it or not at all, and is then High.

  Residuals:
  - **A package's own files.** A file is taken as a package's from the
    package database, which a package's own root scripts can change; a
    malicious package can also ship a helper of its own. A
    narrow capability on such a file is Low: the trust boundary every package
    transaction already is (root installs what it likes through the real
    package manager). The narrow set includes `cap_net_admin`
    (`gst-ptp-helper`'s, `dumpcap`'s): a malicious package's helper with it
    lets whoever runs it change the network's configuration, the host
    firewall included.
  - **The packaged `systemd-update-utmp` itself.** Root that runs the packaged binary has its appends of whole records kept. A rewrite made
    before an exec of it, through an inherited descriptor, is another
    writer's and stays High; but a rewrite in place made under the packaged binary's own identity, by code root placed in it, is not recorded by `NN-L-FIM-019` (a residual, named); the same holds for a process that takes on that identity.
  - **bpftool listings.** A listing by root that is proven the packaged
    bpftool's has its refused handles recorded Low (`NN-L-AT-001`), and in observe mode its handles by id one Low record (`NN-L-BPF-002`, which does not say which object was asked for); the proof does not cover everything such a process can do with them. In enforce mode the refusal stands, and every other operation (a detach, a dump's or an update's
    handle) keeps its own High record.
  - A bait created with no kernel record of its writer that holds the bait's
    own content is High, not Critical (no writer to act on).

  *Evidence:* lot 373;
  `the_agent_s_own_runtime_bait_is_no_creation_by_an_unknown_writer`,
  `a_root_listing_by_the_packaged_bpftool_is_told_from_a_handle_grab`,
  `a_shutdown_record_of_the_packaged_utmp_is_kept_by_the_kernel_s_facts`,
  `an_exec_between_two_writes_is_another_writer`,
  `a_postinst_setcap_of_a_root_equivalent_capability_stays_high`,
  `fim025_a_root_equivalent_grant_in_a_package_transaction_stays_high`.
- **The host's rotations, boots and package installs** (lot 376, the rc9
  soak). Judged by identity now:
  - rsyslogd's appends to a log logrotate re-created, its last flush at the
    shutdown included: the new file is measured from the size it had when
    watched (no `NN-L-FIM-005`);
  - the first `sudo` of a session after a boot: its read of
    `/etc/sudoers` at the invoking user's uid is told by the image the
    kernel recorded at the open (no ALERTED posture);
  - a packaged program the user's own service manager starts (podman's
    quadlet user generator on Debian 13, whose `systemd-user` PAM stack
    sets no login uid) reading `/etc/passwd` for a name lookup;
  - `pg_createcluster`'s free-port probe in PostgreSQL's postinst:
    `NN-L-NET-019`/`-006` Low;
  - a package transaction's unit writes: one `NN-L-FIM-009` Low record per
    package-manager process within 15 minutes, the rest counted.

  Still recorded High: `sudo logrotate -f` by hand, now on logrotate at the
  rotation (`NN-L-FIM-005`; for `wtmp`/`btmp` also `NN-L-FIM-019`, with no
  kill when the packaged logrotate runs as root with root's configuration
  only and renames the file away — the review of #583); a truncation of a
  log by any other writer, which keeps `NN-L-FIM-019`'s kill;
  `cat /etc/login.defs` from a session (ALERTED).

  Residuals:
  - **A log moved away.** A watched log moved away is recorded as moved
    (the drift row `Renamed` and a line in the journal), not as a High:
    `NN-L-FIM-005` judges modifications only. A file that appears later at
    its path is checked as a creation by an unknown writer.
  - **`NN-L-AT-001`'s boot burst.** The BPF cross-view's baseline of
    systemd's programs (~30 Low records at each boot) is signed once per
    program, a sole trace by design (lot 356); not coalesced.
  - **A listener a package's own maintainer script starts.** It is
    recorded Low (`NN-L-NET-019`/`-006`), naming the package: the agent
    trusts that script as it trusts the package. A listener started from
    an APT or dpkg hook, or from an rpm scriptlet, stays Medium.
  - **A user's service manager launching a unit with no identity.** R004
    tells an exec with no identity (the agent's start, a lost handoff) of
    `/proc/self/fd/N` as systemd's executor only for PID 1's forks, by PID
    1's own descriptor `N`; a user manager's launch in that window stays
    Critical (a user may change its own manager's child before the exec).

  *Evidence:* lot 376;
  `a_rotated_log_is_judged_on_its_renamer_and_its_new_file_from_its_own_size`,
  `sudo_s_own_read_before_its_exec_is_known_is_told_by_its_image`,
  `a_user_manager_s_packaged_generator_reading_passwd_is_no_sensitive_access`,
  `net_019_a_package_transaction_s_own_program_binding_the_wildcard_is_low`,
  `fim_009_a_package_transaction_s_unit_writes_are_one_record_per_process_and_window`,
  `a_hand_rotation_by_the_packaged_logrotate_with_root_s_configuration_is_high_never_a_kill`,
  `net_019_an_apt_hook_s_packaged_relay_listener_is_no_package_s_own`,
  `pid_1_s_executor_launch_without_an_identity_is_told_by_pid_1_s_descriptor`.
- **Package builders in a chroot** (pbuilder, mock) may draw new records:
  a recent change made the checks of sudo and su stricter. We are watching
  for them. *Evidence:* lot 351.
- **Many hashed DNS names under one domain.** A program that resolves many
  long, random-looking names under one domain in a short time (a security
  product's reputation lookups by hash, a client of many hashed
  sub-domains) draws `NN-L-NET-014_DnsTunnelEntropy` High (`would have:
  KillProcess`). *For you:* such a record for a tool you know is a known
  false positive; report the domain. *Evidence:*
  `net_014_kills_a_tunnel_of_distinct_labels_under_one_parent`; lot 291.
- **A program that runs its own file again after an upgrade.** A program
  that, in the same process, runs its own file again through
  `/proc/self/exe` after a package upgrade replaced that file runs a file
  that is no longer on disk: `R004_ExecFromProcSelfFd` Critical (`would
  have: KillProcessTree`). *For you:* such a record right after an
  upgrade of that program's package is a known false positive.
  *Evidence:* `a_dropped_binary_that_unlinks_and_reexecutes_itself_is_killed`;
  lot 310.

## Kernels and distributions

- **Tested.** Ubuntu 22.04 (5.15), Debian 12 (6.1), Ubuntu 24.04 (6.8),
  Debian 13 (6.12) and Ubuntu 26.04 (7.0)
  ([KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md), "Verified matrix").
  Ubuntu 22.04 is supported degraded: DNS names are read through one kernel
  path only. *Evidence:* internal check Phase 8 §4.1; internal check Phase
  8b §4.1.
- **The verifier margin on 5.15 and 6.1.** The kernel's verifier accepts
  every program on the five kernels, but two programs of the mount guard
  use about 92 % of the instruction budget the project allows itself on
  5.15 (91 % on 6.1). A kernel whose verifier counts differently could
  refuse one. Then the agent does not stop: it starts without that hook,
  signs a degradation (`mount guard: <n> of <m> hooks attached`, shown
  in `nn-admin status`), and the rest loads; the by-path defences and the signed mount
  watch remain. *For you:* on any kernel, a mount-guard degradation in
  `nn-admin status` is worth a report with `uname -r`. *Evidence:*
  internal check Phase 8b §4.3 and §5 (F8b-1);
  `the_guard_is_not_attached_without_the_offsets_it_reads` (a guard not
  attached is a signed degradation; a fault-injection check of the
  verifier's refusal is planned before the tag).
- **RHEL family not re-verified.** AlmaLinux 9 was verified on an older
  build and not since many recent changes; the `.rpm` is untested (above).
  *Evidence:* internal check Phase 8 §7 (residual R066).
- **Prerequisites.** Kernel BTF (`/sys/kernel/btf/vmlinux`), `bpf` in the
  active LSM list, bpffs at `/sys/fs/bpf`, systemd, `nft`. Without the BPF
  LSM the agent refuses to start. Only the override
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1` starts it then, at trust level L0 (no
  enforcement, signed): a lab mode, not supported for the alpha. *Evidence:*
  `install_sh_refuses_a_host_without_nft_unless_told`; lot 341.
- **A kernel update can stop the agent.** At each start the agent checks
  every kernel structure it reads. When a required one is missing, it
  refuses to start rather than run with wrong offsets; an optional one
  missing is a signed degradation. *For you:* after a kernel update, check
  `nn-admin status`, and report a kernel that is refused.
  `northnarrow-agent --btf-check <btf file>` gives a verdict for a
  kernel's BTF without starting anything. *Evidence:* internal check Phase
  8 §4.4 (a field removed: a signed degradation, not a wrong read).
- **Ubuntu 26.04 (7.0): degraded fallbacks see one CPU.** On that kernel a
  BPF program on a syscall tracepoint runs only for calls made on CPU 0.
  The agent's normal start does not use those tracepoints. Only the
  fallbacks do (a sensor's tracepoint mode, a start without the BPF LSM
  under the lab override above), and they then miss what runs on other
  CPUs. *Evidence:* internal check Phase 8 §7 (residual R060).
- **overlayfs, FUSE and NFS.** On these filesystems the kernel's identity of
  a file may not match what `stat()` reports, so a protected or watched
  file there may be neither protected nor watched. The agent signs a
  degradation (`inode_identity_unverified`) at each boot that has one.
  *Workaround:* keep the agent's directories and the watched files on ext4,
  xfs or btrfs. *Evidence:* `registration_on_overlay_is_attested`.

## Containers

The agent runs on the host and sees container processes through the host
kernel.

- **runc's copy of itself.** A container runtime runs itself again from a
  sealed in-memory copy at each container start. The agent recognises this
  for the runtimes it knows. It stays a Critical
  `R004_ExecFromProcSelfFd` for runtimes it does not record (k3s's bundled
  runc, a snap's Docker, rootless Docker), and on an agent in tracepoint
  mode. Under `alpha` that is a record with `would have: KillProcessTree`,
  and nothing is killed ([UPGRADE_NOTES_WAVE4.md](UPGRADE_NOTES_WAVE4.md)
  §41). *Evidence:* lot 347.
- **Many container starts in one second.** The agent compares each copy
  byte for byte with a budget per user, and a share kept for root's container starts; normal starts stay well inside it. Past it, root's copy whose every other fact holds is recorded High (`R004_ExecFromProcSelfFd`, "not compared (budget)"), never killed: its bytes were not compared. The first one of each episode names the uid whose share ran out and the second's
  biggest spender, and the spending is signed (`runtime_copy_compare`).
  Another uid's copy past its own share stays the Critical kill.
  *Evidence:* `an_uncompared_runtime_copy_is_recorded_never_killed`;
  `the_first_uncompared_copy_of_an_episode_names_who_spent_the_budget`;
  `a_spent_budget_is_one_episode_per_quiet_minute_and_names_its_spender`;
  lot 370.
- **k3s.** Its runc runs from a non-standard path: a
  `R013_NamespaceEscapeTooling` High record. Its installer writes
  `k3s.service`: an `NN-L-FIM-009_SystemdUnitDropped` High record. An
  overlay can silence the first; read its trade-off first
  ([CONTAINER_HOST_DEPLOY.md](CONTAINER_HOST_DEPLOY.md)). *Evidence:* lot
  347.
- **Docker CE** (Docker's own packages) has not been tested in our lab.
  *Evidence:* internal check Phase 0, residuals R050.
- **A container image as the root filesystem** (an overlay root) gets the
  `inode_identity_unverified` degradation at every boot (see "Kernels and
  distributions"). *Evidence:* `registration_on_overlay_is_attested`.
- **CoreDNS** is recognised as a resolver only as containerd, k3s's
  containerd or CRI-O start it. *Evidence:* lot 347.

## Performance

- **Narrow measurements.** Overhead has been measured on Ubuntu 24.04 only,
  against one committed baseline. File-open-heavy work pays most: an `open`
  microbenchmark is about 41 % slower with the agent on, `git status` about
  24 %. *Evidence:* lot 273b (both figures, on Ubuntu 24.04).
- **Network.** UDP receives are about 20 % slower, TCP sends about 10 %
  (the TLS fingerprint sensor), connects about 6 %
  ([NETWORK_TELEMETRY.md](NETWORK_TELEMETRY.md) §6). *Evidence:*
  `docs/operator/NETWORK_TELEMETRY.md` (§6); `deploy/lab/overhead/prog-cost.sh`;
  lot 275.
- **Oversized memory limits.** The agent's unit sets `MemoryHigh=9G` and
  `MemoryMax=11G`, far above what the agent uses; they have not been
  resized yet. On a VM with less memory than that the cap cannot bind, and
  the agent says so in a WARN at start. *Evidence:* internal check Phase 0
  §5 (F0-5).
- **Events can be lost under load.** Under a burst, the kernel rings and
  the agent's queues drop new events rather than slow the host. Each loss
  is counted in `nn-admin status` (`ringbuf drops`, `loss by stage`) and
  `sensors` reads `DEGRADED`. Records can be missing for such a burst.
  *Evidence:* internal check Phase 0, residuals R022.
- **Long runs.** The long-run stability of this release is still being
  measured. *Evidence:* internal check Phase 0 §7.

## Export

The export of the signed records ([EXPORT.md](EXPORT.md)) is off by
default. It was checked end to end on the release candidate: to the JSONL
files and to a syslog receiver over TLS, our own and OpenSSL's, every row
of the chains arrived, every record verified with the agent's key, and
every record passed the OCSF 1.9.0 schema. Its limits are in
[EXPORT.md](EXPORT.md) §8; the ones a tester meets first:

- the configuration takes effect at the next start of the agent (no
  reload). *Evidence:* `deploy/lab/export/export-guest.sh` (its setup phase);
- syslog delivery has no application-level acknowledgement: a receiver
  that stops reading and then dies can lose what its kernel had accepted.
  *Evidence:* `deploy/lab/export/export-guest.sh` (its slow and stall phases);
- the receiver must speak TLS 1.3 with X25519, and there is no client
  certificate (mTLS); one record can be up to 256 KiB, so a receiver that
  cuts long messages (rsyslog's default is 8 KiB) must be told the larger
  size. *Evidence:* `the_provider_is_narrowed_as_the_advisories_require`
  (TLS 1.3 and X25519 only, no client key);
  `received_records_match_the_pinned_schema` (the lab's records, through
  OpenSSL 3.0's TLS 1.3 listener);
- the TLS provider is a young library that marks itself as not for
  production. The advisories in its dependencies are recorded with why
  they are not reached ([EXPORT.md](EXPORT.md) §7). *Evidence:* internal
  check Phase 1 §4.3;
- the export's own connections are judged by the network rules: a
  receiver on your LAN draws `NN-L-NET-007` records, one at a public
  address `NN-L-NET-028` records unless you list it in the signed
  `nodns-allow.local`. *Evidence:* `deploy/lab/export/export-guest.sh`;
- the audit log, the status events, the heartbeat, the listener log and
  the file integrity baseline are not exported. *Evidence:*
  `deploy/lab/export/export-guest.sh` (its arrive phase: the five
  chains exported, none other).

## Operator tools

The `nn-admin` commands and their exit codes are in
[NN_ADMIN.md](NN_ADMIN.md).

- **The glibc baseline.** The release is built on Ubuntu 22.04 (glibc
  2.35), and the release workflow checks that no shipped file needs a glibc
  newer than 2.34 (AlmaLinux/RHEL 9, the oldest supported), weakly or not. Earlier builds, made on Ubuntu 24.04, printed
  `weak version 'GLIBC_2.39' not found` at every `nn-admin` command on
  Ubuntu 22.04 and Debian 12 (harmless); a release that still does is one of
  those. *Evidence:* lot 365, `deploy/release/glibc-baseline.sh`.
- **Use `nn-admin` from the same release as the agent.** An `nn-admin` of
  another release may not read the agent's answers correctly.
  *Evidence:* lot 354 (the protocol version).
- **The install key does not carry every role.** The key `install.sh`
  writes can unlock, read the audit log and the records, open a window and
  sign overlays. Canary commands (`canary-manage`), `fim baseline`
  (`fim-manage`) and `response release|restore` (`response-manage`) are
  refused with an authorisation error. *Workaround:* add the role, or a
  dedicated key, as [COMBAT_RECOVERY.md](COMBAT_RECOVERY.md) §1.1
  describes. *Evidence:* lot 354.
- **A Process canary does not create its decoy.** `nn-admin canary deploy`
  of a Process canary registers the path only. Place an executable there
  yourself. A Network canary opens no listener. *Evidence:* lot 354.
- **`nn-admin status` without `--key` shows the posture only.** The
  profile, sensors, records, trust level and degradations need a key with
  `audit-read` or `telemetry-read`. *Evidence:* `sock.status.observing`.
- **`nn-admin` needs root.** The admin socket and the key file are root's:
  run it with `sudo`. Without it, a command that talks to the agent fails
  with a permission error: that does not mean the agent is stopped.
  *Evidence:* lot 354.
