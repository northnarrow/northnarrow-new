# Known limitations of the alpha

> Draft until rc-final: the list is checked again before the v0.1.0-alpha tag.

This page is for people who test the NorthNarrow alpha. It lists what we
know does not work yet, or works only in part, so that you can tell a
known limit from a new problem. Each item says what happens, what it means
for you, and the workaround when there is one.

The alpha installs with the `alpha` profile: the agent detects, judges and
records, and it never kills, blocks or quarantines a user's program
([ALPHA_PROFILE.md](ALPHA_PROFILE.md)). In this release a false positive is
a record, not a broken program. The agent's protection of itself stays on.

Something that is not on this page is worth a report:
[TESTING_THE_ALPHA.md](TESTING_THE_ALPHA.md#6-reporting-a-problem) says how.

## Install and upgrade

- **Hosts the installer refuses.** `install.sh` stops before it changes
  anything on a host that is not x86_64, does not run systemd, has no
  kernel BTF, runs a kernel the agent does not support or, when it is to
  start the agent, has the BPF LSM off or bpffs not mounted. Each refusal
  says what to do. *For you:* on Ubuntu, add `bpf` to the kernel's LSM list
  and reboot before you install
  ([KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md#enabling-the-bpf-lsm-kernel-command-line)).
  A distribution outside the tested list is named, not refused.
- **The upgrade has a short window with partial protection.** During
  `install.sh --upgrade`, for about 6 to 15 seconds, not all of the agent's
  LSM programs are attached, and the watchdog is absent for about 18
  seconds (measured on Ubuntu 24.04 with kernel 6.8 and Debian 13 with
  6.12). It happens only inside the signed trusted-installer window the
  upgrade opens with your key, and it is the same kind of window a reboot
  has. *For you:* do not run a test you want recorded while an upgrade
  runs. A later release will attach the new programs before it removes the
  old ones.
- **An upgrade needs your admin key.** Over running units, `--upgrade`
  refuses to start without `--grant-key` and a key with the
  `trusted-installer` role. The key `install.sh` writes,
  `/root/northnarrow-admin.key`, has that role. *For you:* keep it until
  you uninstall.
- **Tracing tools are refused unless you name them at install.** bpftrace,
  BCC tools and `bpftool feature probe` load BPF tracing programs. The
  agent refuses them under every profile; each refusal is a signed High
  record and raises the posture. *Workaround:* install the tools first,
  then do a fresh install with `install.sh --allow-bpf-tools` (or
  `--allow-bpf-loader <path>`), see [ALPHA_PROFILE.md](ALPHA_PROFILE.md)
  §1.2. A tool installed later needs a signed policy line by hand. Run
  `bpftool feature probe` inside a trusted-installer window. The opt-out
  is wide: see "Self-protection against root" below.
- **The profile is set at install.** A fresh install is `alpha`. Later runs
  of `install.sh` keep the profile they find, and `--profile` does not
  switch an installed agent. *Workaround:* a signed `profile.local` and a
  restart inside a window ([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §4).
- **The installer can still leave a High record.** `sudo ./deploy/install.sh`
  and `sudo ./deploy/uninstall.sh` at a terminal are recorded Low. If the
  agent loses the exec record of the sudo chain (a full event ring under
  load), the run can be recorded High (`R009_RootExecFromUserPath`).
  *For you:* harmless under `alpha`. On an idle host it is worth a report.

## Uninstall

- **Exit codes.** `uninstall.sh` exits:
  - **0**: removed, clean;
  - **3**: the agent was wedged (its socket did not answer), so no window
    could open. The rest of the removal runs at the next boot: reboot to
    finish;
  - **4**: removed, but processes the agent had contained (frozen, or moved
    into its own scopes) were found. They were thawed and listed by pid and
    command, and they now run outside any unit. *For you:* under `alpha`
    nothing is contained, so 4 is rare. If you see it, look at each listed
    process and decide whether to keep or kill it.

  See [INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3.
- **Two kernel modules stay loaded until the next reboot.** After
  `uninstall.sh --purge`, `nf_tables` (and `nfnetlink` and `libcrc32c`,
  where nothing else had loaded them) and, on Ubuntu 26.04, `unix_diag`
  stay loaded. The kernel loaded them on demand for the agent. This is
  harmless: they are standard kernel modules, and unloading one that the
  host's firewall or a container runtime uses would break it. A reboot
  clears them.
- **The host's own logs keep the agent's lines.** systemd's lines about the
  units stay in the system journal (and in `/var/log/syslog` where rsyslog
  runs). `--purge` removes only the agent's own journal namespace.
- **Without `--purge`, keys and evidence stay.** This is by design: the
  admin key, the signed audit chain and the records stay for a later
  reinstall. The summary names every private key left on the host.
  `--purge` removes them all.

## Packages and supply chain

- **The `.rpm` has not been tested in our lab.** It is built and signed in
  CI and passes the CI self-test, but our lab has no Fedora, RHEL or
  AlmaLinux guest. The `.deb` (Ubuntu 24.04, Debian 13) and the tarball
  were tested. *For you:* if you test the `.rpm`, please report what you
  see, even when it works.
- **The SBOMs do not cover the eBPF object.** The release has three
  CycloneDX SBOMs: the agent (which covers `nn-admin` too), the watchdog
  and the scanner. The eBPF object built into the agent is a separate crate
  with its own dependencies (`aya-ebpf` among them), and none of the three
  lists them. *Workaround:* they are pinned in that crate's own lock file,
  `agent-ebpf/Cargo.lock`, in the source tree at the release tag.
- **`gh attestation verify` needs gh 2.49 or newer.** Ubuntu 24.04 ships
  gh 2.45, which has no `gh attestation` command. *Workaround:* keep
  `SHA256SUMS` and `SHA256SUMS.asc` next to the tarball: `install.sh` then
  checks the signed checksums with `gpgv` and installs with no flag
  ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §5).
- **One architecture.** x86_64 only: no ARM64.
- **The tarball is not byte-reproducible.** A rebuild gives a different
  file, because file times are kept on purpose (a staleness check needs
  them). The build-provenance attestation is the integrity anchor instead.

## Self-protection against root

The agent is **hardened against root, not root-proof.** Outside a signed
trusted-installer window, its kernel hooks refuse root's attempts to stop,
blind, freeze, trace or change it, and each refusal is a signed
`NN-L-AT-001_AntiTamperDenial` record. Some things cannot be refused
without breaking the system: for those the agent records what happened.
Below is what root can still do, and the record it leaves. The full
analysis is in the
[trust model](https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/ANTITAMPER_TRUST_MODEL.md).

- **A trusted-installer window opens the whole host.** While a window is
  open (an upgrade, an uninstall, `nn-admin trusted-installer-grant`),
  every root process, not only the installer, may stop the agent, load
  kernel modules or BPF programs and change the agent's files. A BPF
  program loaded in the window that would be refused outside it is
  recorded High at its load. After the window it cannot be run or attached
  again, but what was attached inside the window keeps running, and the
  agent records each such program still loaded (High). *For you:* keep
  windows short, and open one only when you need it. A later release will
  limit the window to the process that asked for it.
- **What was loaded before the agent started.** A kernel module loaded
  before the agent started is beyond its reach. BPF programs present at its
  start are recorded (High for the risky types); on kernels from 6.9 their
  later use is not judged. *For you:* install on a fresh VM.
- **Some BPF paths are not judged.** An XDP or tc program attached through
  netlink, and the program values of some map types, are not judged. In
  rare cases the use of a loaded program is not judged on its own; its
  load is still recorded High. *For you:* treat a High BPF load record you
  did not cause as an incident.
- **An allowed tracing tool can read everything.** With
  `--allow-bpf-tools`, any root process that runs a named program may load
  tracing programs (for BCC that is any root Python script), and a tracing
  program can read the memory of every process, the agent's keys included.
  *For you:* use the opt-out on a test VM only.
- **Mounts are refused in the guarded namespaces only.** A mount on, over or
  below the agent's directories, binaries, units, `/proc`, `/sys`, the
  cgroup root or the bpffs is refused in PID 1's mount namespace and in the
  agent's and the watchdog's own (lot 357, the mount guard, and the review
  of #567), and so are an unmount or a move of the mounts themselves,
  `pivot_root`, a remount of their super blocks and a read-only bind
  remount — and so is one made in another namespace that propagates into a
  guarded one (a raw `unshare(CLONE_NEWNS)`, a container's `rshared` bind
  of a host directory, an unmount of an rbind copy that the kernel carries
  onto a held mount): its peer group is one the agent follows (read every
  30 s and within a second of a propagation change made by `mount(2)` or
  `move_mount(2)`), or — a guarded mount regrouped since — the hook walks
  the group's peers and their slaves; a group wider or deeper than the 16
  mounts it reads counts as reaching a guarded namespace, and a mount there
  is then refused on, over or below a protected point only.
  `mount_setattr(2)` (read-only, propagation) has no kernel hook: it is not
  refused, it is a signed `integrity_drift` (`mount_attrs_changed`, High)
  within one integrity round (about 30 s), as is any mount on a kernel
  where the guard is not attached (a signed degradation). The watchdog's
  namespace is guarded from the agent's watchdog refresh, up to 30 s after
  the watchdog starts. The emergency remount (`SysRq-u`, a kernel thread,
  which root can trigger through `/proc/sysrq-trigger`) is not refused: it
  makes every block-backed file system read-only, signed High
  (`state_fs_read_only`); restrict `kernel.sysrq` if the host needs no
  emergency remount. *For
  you:* on Ubuntu 22.04, `mount --move` in the host's namespace is refused
  (util-linux 2.37 names the source by a string only); a runtime
  `systemd-sysext refresh` or `systemd-confext refresh`, a
  `mount -o remount` of `/proc`, `/sys`, the cgroup root or the bpffs, a
  read-only remount of `/`, `/run` or the agent's file systems and
  `systemctl soft-reboot` need a trusted-installer window; an rbind of
  `/sys` or `/` is made `rslave` before its `umount -R`; an ostree host
  (binds of `/var`) or a host whose `/` is a tmpfs signs its layout as not
  canonical at each start (`mount_not_canonical`) — a `systemd-sysext`,
  `confext` or composefs overlay merged at boot does not.
- **An unmount that races the guard's read.** The kernel calls the
  unmount hook before it takes its mount lock. A copy grafted by a slow,
  concurrent rbind after the guard has read the subtree is taken by a lazy
  unmount, in any namespace, the guarded ones included: `/sys/fs/bpf` can
  lose its last mount. The deny hooks stay attached (the agent holds their
  descriptors) and the loss is signed High, but the pins are gone: a later
  start must load again, and the watchdog's handles on pinned maps fail.
  Planned: the pin directory made its own private, unbindable mount, which
  no propagation or copy can reach (re-check 3 of #567, N4).
- **An unmount the guard cannot read whole.** A lazy unmount (`umount -l`)
  takes the whole subtree of the mount it names, and the kernel carries
  the unmount of each mount in it onto the peers and slaves of its parent:
  the guard reads that subtree, 32 mounts of it (the re-check 2 of #567).
  Two unmounts it does not refuse, root building them on purpose:
  - in a namespace that is not PID 1's, the agent's or the watchdog's (a
    raw `unshare(CLONE_NEWNS)`), a subtree whose first 32 mounts, or a
    chain of 9 levels (about 10 mounts), are all private, behind which
    lies a copy (an rbind of `/sys`) in one of
    the host's peer groups: the kernel takes the host's childless
    `/sys/fs/bpf` and `/sys/fs/cgroup`, and their copies in the agent's,
    the watchdog's and the units' namespaces (slaves of the host's). The
    bpffs then loses its last mount: no path reaches its pins any more
    (the watchdog's handles on the pinned maps fail; a later start finds
    none), while its super block, the pins in it, lives on as long as the
    agent holds a descriptor in it (its anchor of `/sys/fs/bpf`, lot 353).
    The deny hooks no longer detach: the agent holds a descriptor of every
    link and program it pins (fix round 3 of #567, `antitamper_bpf::held`),
    so the kill, ptrace, file, cgroup and BPF guards and the mount guard
    itself keep refusing for as long as the agent runs — the lab measured
    it on 5.15 and 6.8, `umount -l /sys/fs/bpf` leaving no bpffs mounted
    in any namespace. The integrity round signs `protected_mount_gone`
    (High). If the agent stops or is restarted before a reboot, its
    descriptors close: the super block goes with its pins, the hooks with
    them, and the next start, its pins gone, starts as after a reboot;
  - a peer of a held mount's parent regrouped since the agent's last
    refresh of the peer groups (a second after `mount(2)`, up to 30 s
    after `mount_setattr(2)`): one shared slave of that parent — every
    sandboxed unit's namespace is one — is enough to hide the walk's end,
    not 16 mounts. Its unmount can take the host's childless `/sys/fs/bpf`
    or `/sys/fs/cgroup`. It hides the host's mount of the pins, not the
    pins: the regroup freed the old slaves, so the agent's and the units'
    copies stay, and so does the bpffs; the integrity round signs
    `protected_mount_gone`.
  The same holds for one pin removed (inside a trusted-installer window,
  the one place root can) or hidden: the hook stays attached while the
  agent runs, the integrity round signs `bpf_pin_vanished` (High) and pins
  it again from the descriptor where its directory is still the one it was
  pinned in (never into a new bpffs, nor a mount laid over the directory),
  so the next start finds it; a pin it cannot pin again stays signed.
  *For you:* treat a `protected_mount_gone`, a `bpf_pin_vanished` or a
  missed deny hook you did not cause as an incident, and do not restart the
  agent before a reboot when its pin directory is gone. In PID 1's namespace a lazy unmount wider than
  the walk is refused even when it is harmless (an rbind of `/` made
  `rslave`): use `umount -R`, or a trusted-installer window.
- **Changes systemd needs are recorded, not refused.** A drop-in in a unit
  directory the agent does not guard, `systemctl set-property`, a higher
  `oom_score_adj`, an edit in place of an existing `.local` overlay: each is
  a signed `integrity_drift` within about 30 s
  ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3.5).
- **A refused `set-property` stays in systemd's memory.** systemd changes
  its own copy of the property before the agent refuses the write.
  `systemctl show` then reports the new value, and the unit's next start
  would apply it. The refusal is signed. *Workaround:* run
  `sudo systemctl daemon-reload` before you restart the agent.
- **A soft-reboot leaves the units `failed`.** `systemctl soft-reboot`
  (systemd 254 and later) cannot stop the agent: it survives with its
  protection, but the new userspace's systemd marks the units `failed`
  (systemd 255, 257) or stopped (259). *Workaround:* use a full reboot.
- **A stop pulled in by another unit.** When a unit that conflicts with the
  agent's unit starts, the agent refuses the signals and keeps running, but
  systemd records its unit as stopped (`systemctl status` says `inactive`).
  *For you:* `nn-admin status` tells you the agent runs. A reboot puts
  things back.
- **Kills nothing can refuse.** The kernel's OOM killer, a crash or a power
  loss end the agent without asking. The watchdog brings it back, and the
  next start records how the previous run ended (`previous_run` with
  `"ended":"abrupt"` in its signed `agent_boot` entry).
- **The agent's CPU time.** Heavy CPU load from root processes can slow the
  agent: its unit has no raised CPU weight yet. A stall of more than 15 s is
  a signed `agent_stalled` record. A confinement of the agent to fewer CPUs
  through cgroups is recorded (`cpu_confined`, High, and the `own_cpus`
  degradation in `nn-admin status`). CPUs taken offline are not recorded,
  and the watchdog's CPUs are not watched.
- **A signature proves the key, not the host.** Records are signed with a
  key stored on the host, which the agent keeps from readers while it runs.
  A root who obtains that key can write lines that verify. Hardware
  attestation is future work
  ([HEARTBEAT.md](HEARTBEAT.md#what-it-does-not-prove)).
- **The evidence lives on the host.** A root who stops the agent inside a
  window, or reads the disk from another system, can remove or roll back
  its files. Verification shows a cut chain only against a head you kept
  elsewhere ([EVIDENCE_CHAINS.md](EVIDENCE_CHAINS.md)). *Workaround:*
  forward the agent's journal off the host, or turn on the export
  ([EXPORT.md](EXPORT.md)).
- **The kernel is the host's to protect.** A root that can write kernel
  memory can defeat any defence inside the kernel. Kernel lockdown, module
  signing, Secure Boot and disabled kexec are recommended, and
  `nn-admin host-check` reports each one
  ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3.1).

## Detection coverage

- **No adversarial campaign yet.** The rules have unit, end-to-end and lab
  tests. No independent or adversarial campaign has measured them, and no
  coverage percentage is published.
- **Partial telemetry.** Exec events only: no fork, exit or credential
  change events. DNS is read over UDP only: no DNS over TCP, DoT or DoH.
- **Some rules recognise a program by what it is.** The netcat and miner
  rules (`R005_NetcatExec`, `R007_CryptoMiner`) go by the program's name.
  Reverse-shell tooling is recognised by the installed program the kernel
  ran, not by behaviour. A program the agent does not know is judged only
  by the other rules (where it runs from, what it opens, where it
  connects).
- **Ransomware detection looks for shapes.** It looks for mass rewrites,
  renames to known extensions and high-entropy writes. Encryption that
  does not show those shapes may be seen only by weaker signals, or not at
  all. *For you:* keep backups off the host; detection does not replace
  them.
- **Ancestry is followed to a limit.** The agent follows a process's
  ancestors to a fixed depth.
- **Security tools switched off.** The `NN-L-EVA-*` rules recognise only
  the commands in their table. Other ways to stop a security tool may leave
  no record. *For you:* also check from each tool's own status and logs
  that it still runs.
- **Not watched by file integrity.** udev rule directories and initramfs
  hook directories are not watched: a new file there leaves no file
  integrity record. What such a file runs later is judged by the process
  rules.
- **Some exemptions are wider than they should be.** A few exemptions for
  package managers and developer tools (npm under a system prefix, go,
  database initialisation) trust the tool by identity. They are listed in
  [UPGRADE_NOTES_WAVE4.md](UPGRADE_NOTES_WAVE4.md) §34 and §39 and will be
  narrowed.
- **A TLS fingerprint is not an identity.** `NN-L-NET-003_BadJa3` records a
  listed JA3 or JA4 at Medium and never acts on it.
- **Prevention is experimental and off.** The exec policy, the exec
  quarantine and the copy-on-first-write guard are off by default. Under
  `alpha` they would only observe anyway.

## False positives you may see

Under `alpha` a false positive is only a record. Its `response` field
reads `would have: <action>` when `enforcing` would have acted. The
[rule catalogue](https://github.com/northnarrow/northnarrow-new/blob/main/docs/detection/RULE_CATALOGUE.md)
lists the known false positives of each rule.

**Expected on a quiet host, at Low:** one `NN-L-BPF-002` at each start of
the agent or the watchdog; the BPF cross-view's records at boot for
systemd's own programs; logrotate's daily run; on Debian 13 and Ubuntu
26.04 cloud images, cloud-init's netcat at each boot (`R005_NetcatExec`);
on Ubuntu 26.04, systemd's own BPF feature probes, refused and recorded
(`NN-L-AT-001`).

**May be recorded higher:**

- **Container runtimes**: see "Containers" below.
- **Builds and tests that run from `/tmp`.** `go test`, `go run`, an
  AppImage, or a build that runs what it unpacked in `/tmp`, are
  `R001_ExecFromTmp` High.
- **npm installed with nvm or in a home directory.** It is not exempt:
  `npm ci` there can raise the posture to ENGAGED.
- **Desktop sessions.** Services started by a user's systemd manager are
  not vouched for, so a desktop draws more records than a server.
- **Heavy ordinary writes.** Database initialisation (`initdb`), container
  image unpacking (containerd, k3s), `rsync --inplace` and large builds can
  raise the posture to ENGAGED through the mass-write signal.
- **Backups and searches.** A backup tool, `tar` or `grep -r` that reads a
  watched credential file or a canary is recorded like any other reader.
- **Admin tasks not measured yet.** `ssh-copy-id`
  (`NN-L-FIM-004_AuthorizedKeysModified`), a systemd timer installed outside
  a package (`NN-L-FIM-009_SystemdUnitDropped`), an installer run from
  `/tmp` that connects out (`NN-L-NET-008_OutboundFromTmpExec`): recorded
  High.
- **DNS resolvers outside the system trees**, or run in a unit with a name
  the agent does not know: judged as any process, so their DNS traffic can
  draw DNS records ([UPGRADE_NOTES_WAVE4.md](UPGRADE_NOTES_WAVE4.md) §34).
- **Purging another package that has systemd units.** The package tool
  tries to remove empty unit directories, the agent's own among them. The
  agent refuses that and records `NN-L-AT-001`. The purge completes.
- **Stopping the agent by hand.** `systemctl stop`, `kill` or `restart` of
  the agent outside a window is refused and recorded `NN-L-AT-001` High.
  Use a window ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md)
  §3.7).
- **Package builders in a chroot** (pbuilder, mock) may draw new records:
  a recent change made the checks of sudo and su stricter. We are watching
  for them.

## Kernels and distributions

- **Tested.** Ubuntu 22.04 (5.15), Debian 12 (6.1), Ubuntu 24.04 (6.8),
  Debian 13 (6.12) and Ubuntu 26.04 (7.0)
  ([KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md), "Verified matrix").
  Ubuntu 22.04 is supported degraded: DNS names are read through one kernel
  path only.
- **RHEL family not re-verified.** AlmaLinux 9 was verified on an older
  build and not since many recent changes; the `.rpm` is untested (above).
- **Prerequisites.** Kernel BTF (`/sys/kernel/btf/vmlinux`), `bpf` in the
  active LSM list, bpffs at `/sys/fs/bpf`, systemd, `nft`. Without the BPF
  LSM the agent does not start.
- **A kernel update can stop the agent.** At each start the agent checks
  every kernel structure it reads. When one is missing, it refuses to start
  rather than run with wrong offsets. *For you:* after a kernel update,
  check `nn-admin status`, and report a kernel that is refused.
  `northnarrow-agent --btf-check <btf file>` gives a verdict for a
  kernel's BTF without starting anything.
- **Ubuntu 26.04 (7.0): degraded fallbacks see one CPU.** On that kernel a
  BPF program on a syscall tracepoint runs only for calls made on CPU 0.
  The agent's normal start does not use those tracepoints. Only the
  fallbacks of a degraded start (exec sensor in tracepoint mode, file-open
  fallback) do, and they then miss what runs on other CPUs.
- **overlayfs, FUSE and NFS.** On these filesystems the kernel's identity of
  a file may not match what `stat()` reports, so a protected or watched
  file there may be neither protected nor watched. The agent signs a
  degradation (`inode_identity_unverified`) at each boot that has one.
  *Workaround:* keep the agent's directories and the watched files on ext4,
  xfs or btrfs.

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
  §41).
- **k3s.** Its runc runs from a non-standard path: a
  `R013_NamespaceEscapeTooling` High record. Its installer writes
  `k3s.service`: an `NN-L-FIM-009_SystemdUnitDropped` High record. An
  overlay can silence the first; read its trade-off first
  ([CONTAINER_HOST_DEPLOY.md](CONTAINER_HOST_DEPLOY.md)).
- **Docker CE** (Docker's own packages) has not been tested in our lab.
- **A container image as the root filesystem** (an overlay root) gets the
  `inode_identity_unverified` degradation at every boot (see "Kernels and
  distributions").
- **CoreDNS** is recognised as a resolver only as containerd, k3s's
  containerd or CRI-O start it.

## Performance

- **Narrow measurements.** Overhead has been measured on Ubuntu 24.04 only,
  against one committed baseline. File-open-heavy work pays most: an `open`
  microbenchmark is about 41 % slower with the agent on, `git status` about
  24 %.
- **Network.** UDP receives are about 20 % slower, TCP sends about 10 %
  (the TLS fingerprint sensor), connects about 6 %
  ([NETWORK_TELEMETRY.md](NETWORK_TELEMETRY.md) §6).
- **Oversized memory limits.** The agent's unit sets `MemoryHigh=9G` and
  `MemoryMax=11G`, far above what the agent uses; they have not been
  resized yet. On a VM with less memory than that the cap cannot bind, and
  the agent says so in a WARN at start.
- **Events can be lost under load.** Under a burst, the kernel rings and
  the agent's queues drop new events rather than slow the host. Each loss
  is counted in `nn-admin status` (`ringbuf drops`, `loss by stage`) and
  `sensors` reads `DEGRADED`. Records can be missing for such a burst.
- **Long runs.** The long-run stability of this release is still being
  measured.

## Export

The export of the signed records ([EXPORT.md](EXPORT.md)) is off by
default. Its limits are in [EXPORT.md](EXPORT.md) §8; the ones a tester
meets first:

- the configuration takes effect at the next start of the agent (no
  reload);
- syslog delivery has no application-level acknowledgement: a receiver
  that stops reading and then dies can lose what its kernel had accepted;
- the receiver must speak TLS 1.3 with X25519, and there is no client
  certificate (mTLS);
- the TLS provider is a young library that marks itself as not for
  production. The advisories in its dependencies are recorded with why
  they are not reached ([EXPORT.md](EXPORT.md) §7);
- the export's own connections are judged by the network rules: a
  receiver on your LAN draws `NN-L-NET-007` records, one at a public
  address `NN-L-NET-028` records unless you list it in the signed
  `nodns-allow.local`;
- the audit log, the status events, the heartbeat, the listener log and
  the file integrity baseline are not exported.

## Operator tools

The `nn-admin` commands and their exit codes are in
[NN_ADMIN.md](NN_ADMIN.md).

- **A glibc warning on Ubuntu 22.04 and Debian 12.** Every `nn-admin`
  command prints
  `nn-admin: /lib/x86_64-linux-gnu/libc.so.6: weak version 'GLIBC_2.39' not found (required by nn-admin)`.
  It is harmless: the binaries are built on Ubuntu 24.04 and refer weakly
  to two newer glibc functions, which they do without on an older glibc.
  The hard minimum is glibc 2.34.
- **Use `nn-admin` from the same release as the agent.** An `nn-admin` of
  another release may not read the agent's answers correctly.
- **The install key does not carry every role.** The key `install.sh`
  writes can unlock, read the audit log and the records, open a window and
  sign overlays. Canary commands (`canary-manage`), `fim baseline`
  (`fim-manage`) and `response release|restore` (`response-manage`) are
  refused with an authorisation error. *Workaround:* add the role, or a
  dedicated key, as [COMBAT_RECOVERY.md](COMBAT_RECOVERY.md) §1.1
  describes.
- **A Process canary does not create its decoy.** `nn-admin canary deploy`
  of a Process canary registers the path only. Place an executable there
  yourself. A Network canary opens no listener.
- **`nn-admin status` without `--key` shows the posture only.** The
  profile, sensors, records, trust level and degradations need a key with
  `audit-read` or `telemetry-read`.
- **`nn-admin` needs root.** The admin socket and the key file are root's:
  run it with `sudo`.
