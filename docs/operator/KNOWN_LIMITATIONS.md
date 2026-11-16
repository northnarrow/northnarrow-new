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
- **`nn-admin chain verify` with no chains says OK.** On a state directory
  that holds no chain (a purged host, a wrong `--state-dir`), it prints
  `OK` with 0 rows for each chain and exits 0. *For you:* read the row
  counts, not only `OK`. *Evidence:* `chain.no-audit-log`; internal check
  Phase 0 §5 (F0-3).

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
  the count of records is not the count of attempts. A use that races a
  change of its descriptor can get through: it is not refused and leaves
  no record of its own, and the program's load record and its "still
  loaded after the window" record remain. *Evidence:* internal check Phase
  3 §7.1 and §7.3 (the race measured on 6.8, 6.12 and 7.0); lot 356.
- **What was loaded before the agent started.** A kernel module loaded
  before the agent started is beyond its reach. BPF programs present at its
  start are recorded (High for the risky types); on kernels from 6.9 their
  later use is not judged. *For you:* install on a fresh VM. *Evidence:*
  `the_start_is_the_baseline_and_a_later_unseen_program_is_signed_once`;
  internal check Phase 3 §7.1 (residual R002).
- **Some BPF paths are not judged.** An XDP or tc program attached through
  netlink, and the program values of some map types, are not judged; their
  load is still recorded. *Evidence:* internal check Phase 3 §7.1 (residuals
  R002, R132); lot 356.
- **An allowed tracing tool can read everything.** With
  `--allow-bpf-tools`, any root process that runs a named program may load
  tracing programs (for BCC that is any root Python script), and a tracing
  program can read the memory of every process, the agent's keys included.
  *For you:* use the opt-out on a test VM only. *Evidence:*
  `an_allowed_loader_cannot_load_what_kills_or_blinds_the_agent` (what it
  still cannot load); lot 345.
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
  - `mount_setattr(2)` (read-only, propagation) has no kernel hook: a
    change of a protected mount's attributes is a signed `integrity_drift`
    (`mount_attrs_changed`, High) within one integrity round;
  - a mount namespace of its own (a container's, one made with `unshare`)
    is judged where it reaches the host's mounts; what it changes in its
    own copies only is its own;
  - on a kernel where the mount guard is not attached, every such mount is
    a signed degradation, and the mount watch (`mount_over_protected`)
    remains;
  - the emergency remount (`SysRq-u`, which root can trigger) is not
    refused: it makes every block-backed file system read-only and is
    signed High (`state_fs_read_only`); restrict `kernel.sysrq` if the host
    needs no emergency remount.

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
- **The pin directory's lock: four residuals, each signed.** The
  directory that keeps the agent's kernel programs pinned is locked (bound
  onto itself, private and unbindable), so that an unmount of the bpffs
  cannot take it. For the alpha the lock does not cover four cases. In
  each, the agent keeps its kernel programs attached (it holds a
  descriptor of every one), and an integrity round, about 30 seconds
  apart, signs what happened (High); a loss that comes back soon after one
  already signed is reported again later, as every drift finding is:
  - a change of the lock's flags through `mount_setattr(2)`, which has no
    kernel hook, is not refused. Until the next round puts the lock back,
    the pins are protected as they were without the lock, and the agent
    keeps its programs. Signed `pin_lock_changed`;
  - a raw mount namespace's own copy of the lock is not judged as the
    host's lock. The host's bpffs view and the pins can be lost through
    it. Signed `protected_mount_gone` and `pin_lock_missing`;
  - the systemd units' own mount namespaces, the agent's and the
    watchdog's among them, never have the lock. That namespace's view of
    the bpffs can be lost, not the host's nor the pins; what reads the pins
    by path there fails until a restart. Signed `protected_mount_gone`;
  - a mount namespace that was already a peer of the host's when the lock
    was made does not hold the lock. The host's bpffs view can be lost
    through it, as before the lock. Signed `protected_mount_gone`.

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
  unmount is judged on the part of the mount tree the guard reads. In a
  namespace that is not the host's, the agent's or the watchdog's, an
  unmount can still take the host's `/sys/fs/cgroup` mount and, where the
  pin lock does not hold (above), the host's bpffs view. The agent's hooks
  stay attached while it runs; the integrity round signs
  `protected_mount_gone` (High). In the host's namespace an unmount wider
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
- **Changes systemd needs are recorded, not refused.** A drop-in in a unit
  directory the agent does not guard, `systemctl set-property`, a higher
  `oom_score_adj`, an edit in place of an existing `.local` overlay: each is
  a signed `integrity_drift` within about 30 s
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
  `"ended":"abrupt"` in its signed `agent_boot` entry). *Evidence:*
  `previous_run_none_abrupt_clean`; internal check Phase 3 §7.2.
- **The agent's CPU time.** Heavy CPU load from root processes can slow the
  agent: its unit has no raised CPU weight yet. A stall of more than 15 s is
  a signed `agent_stalled` record. A confinement of the agent to fewer CPUs
  (a sibling cpuset partition, its cgroup's CPUs, a thread's affinity) is
  not refused: it is detected and signed (`cpu_confined`, High) and shown
  in `nn-admin status` (the `own_cpus` degradation), and withdrawn when it
  ends. A confinement made before the agent's first round is not proven.
  CPUs taken offline are not recorded, and the watchdog's CPUs are not
  watched. *Evidence:* `a_sibling_partition_confining_the_agent_is_a_confinement`;
  `a_cpu_taken_offline_is_no_confinement`; lot 349; internal check Phase 3
  §7.1 (residual R001).
- **The journal can be emptied.** A root `journalctl --vacuum-*` removes
  the agent's journal lines like any other's (the anti-tamper lab's known
  gap). The signed chains are not in the journal. *Evidence:* internal
  check Phase 3 §7.1 (C57c, as declared).
- **The kernel is the host's to protect.** A root that can write kernel
  memory can defeat any defence inside the kernel. Kernel lockdown, module
  signing, Secure Boot and disabled kexec are recommended, and
  `nn-admin host-check` reports each one
  ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3.1).
  *Evidence:* internal check Phase 3 §7.1.

## Detection coverage

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
  unit within a time window. Encryption that does not show those shapes,
  or is spread thin enough over time, processes or units, may be seen only
  by weaker signals, or not at all; on its own it raises the posture to
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
- **A file system that does not answer can delay exec records.** To
  judge a program it runs, the agent reads facts about the program's file.
  A program on a file system the agent does not trust to answer (FUSE, a
  network file system) can delay that reading, and the exec records
  behind it. The sensor self-test then finds its own
  exec missing and signs a degradation (`subsystem_degraded`, source
  `sensor_selftest`). *For you:* such a degradation in `nn-admin status`
  is worth a report, with the file systems mounted at the time
  (`findmnt -t fuse,fuseblk`). *Evidence:*
  `a_sensor_whose_events_are_dropped_gives_the_signed_degradation_then_the_alert`;
  lot 355.
- **After a long suspend, a record can name an earlier program.** A
  process id reused after the host spent a long time suspended can be
  taken for a process that held it before the agent started (a laptop
  whose agent restarted since). The record then names that earlier
  process's program, while what ran is still judged by its own exec.
  *For you:* a record whose program does not match what you ran, on a
  host that was suspended, is worth a report. *Evidence:* lot 360.
- **Children that only fork.** A process that forks without running a new
  program is judged by its parent's image. A forker's own later exec read
  after the child's connection is judged on the earlier image; a fork-only
  child that sends over UDP, and the fork of a forker that already exited,
  are judged by their path, as before. A program name cut by the kernel at
  31 bytes inside a multibyte character is not tied to its image.
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
- **Builds and tests that run from `/tmp`.** `go test`, `go run`, or a
  build that runs what it unpacked in `/tmp`, are `R001_ExecFromTmp` High.
  *Evidence:* lot 346.
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
  High. *Evidence:* internal check Phase 0, residuals R054.
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
- **Package builders in a chroot** (pbuilder, mock) may draw new records:
  a recent change made the checks of sudo and su stricter. We are watching
  for them. *Evidence:* lot 351.

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
  LSM the agent does not start. *Evidence:*
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
  fallbacks of a start without the BPF LSM do, and they then miss what runs
  on other CPUs. *Evidence:* internal check Phase 8 §7 (residual R060).
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
