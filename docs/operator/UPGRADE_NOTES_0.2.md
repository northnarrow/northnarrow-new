# Upgrade notes: 0.2

> These notes apply from `v0.1.1-alpha` onward: it is the first tag that carries the changes below.

What changes for an operator who upgrades from `v0.1.0-alpha` to
`v0.1.1-alpha`, and to the builds of `main` after it, on the way to the
next release (0.2). It covers three self-protection and robustness fixes,
the maintenance after the alpha and stage S1 of the roadmap (the
verifier's margin, the eBPF compiler, the cross-cutting migrations). The
changes up to the alpha are in `UPGRADE_NOTES_WAVE4.md` (frozen at the
alpha) and `UPGRADE_NOTES_AUDIT_16f7563.md`. `CHANGELOG.md`, its
`[0.1.1-alpha]` section, has each change by its lot. The stage's lab
round, on six kernels:
<https://github.com/northnarrow/northnarrow-new/blob/main/docs/validation/results/stage-s1-2026-11-26.md>.

`v0.1.1-alpha` says `0.1.1-alpha` (`0.1.1~alpha` in the packages), which
dpkg and rpm sort after the first alpha's `0.1.0~alpha`: the upgrade is
`install.sh --upgrade`, or the package command with the newer package and
`NN_GRANT_KEY` (`INSTALL_UPGRADE_UNINSTALL.md` §2.2). A build of `main`
made after the tag says `0.1.1-alpha` too, until the next tag: to put one
over an installed `v0.1.1-alpha`, use `install.sh --upgrade`, or
`rpm -U --replacepkgs` for the `.rpm` (§8).

## Before you upgrade

1. Nothing in the units, the configuration or the keys has to change. The
   agent keeps its pins, chains and keys across the upgrade, as before.
2. **Building from source** needs the new toolchains (§1): Rust 1.100.0
   (the workspace's minimum is 1.98), and `nightly-2026-08-05` with
   bpf-linker 0.10.3 for the eBPF object. `rustup` takes both from the
   `rust-toolchain.toml` files.
3. **A `move_mount(2)` of a peer copy of a protected mount is refused**
   outside a trusted-installer window, in any namespace (§3). A tool that
   moves such a copy (Debian 13's `mount --move` of one, CRIU's
   `MOVE_MOUNT_SET_GROUP` from one) gets `EPERM` and a signed High.
4. **`mount --make-*` on util-linux 2.39 and later** (Debian 13's 2.41)
   goes through `mount_setattr(2)`, which is still not refused. Its change
   of propagation on a guarded mount is now counted as it happens (§3).
5. **Exec quarantine** (experimental, off by default): a stop now signs
   one or two `stopping` entries, and a WARN's text changed (§7).
6. **More FIM records:** a watched file read again after an `exec` is
   recorded again (§5).
7. **The SysRq trigger file is refused outside a trusted-installer
   window** (§9). A script that writes `/proc/sysrq-trigger` on purpose
   (a crash-dump test, an emergency reboot) gets `EPERM` and a signed
   High, unless it runs inside a window.
8. **A stop signal the agent or the watchdog did not request restarts
   the role and is signed** (§9), and the watchdog exits with a new
   status, 21. Monitoring that reads the watchdog's exit status sees it.
9. **`kernel.sysrq`:** a write that would let the keyboard signal
   processes is refused outside a window; a host whose mask already lets
   it gets the advisory `sysrq_keyboard_signals` in `nn-admin status`
   (§9). The distributions' default masks raise neither.

## 1. The toolchain and the eBPF compiler (lots 396, 397, 400a, 1.2)

- The workspace and the eBPF crate are on Rust edition 2024; the pinned
  toolchain is 1.100.0; `rust-version` (the minimum) is 1.98, which aya
  0.16 needs. No behaviour changes with them.
- User space uses aya 0.16 and aya-obj 0.6. aya 0.16 checks a pinned map
  it reuses (type, key and value size, entries, flags); the start-in-cgroup
  tracker's marks map is adopted at its pinned size after a
  `kernel.pid_max` or `kernel.threads-max` change, so a start after such a
  change keeps its marks, as with the alpha.
- The eBPF object is built with aya-ebpf 0.3 by `nightly-2026-08-05`
  (rustc 1.99, LLVM 22.1.8), with bpf-linker 0.10.3 as before. The
  verifier processes fewer instructions in all (−6.7 % on 5.15, −13.2 % on
  7.0, the lab's measure), and no program fails on the lab's six kernels
  (§11).
- CI keeps the eBPF object it tested, with its sha256, as the artefact
  `ebpf-object`; the release workflow prints the sha256 of the object it
  embeds. Comparing the two before a tag is still a maintainer's step by
  hand.
- Nothing to configure.

## 2. Time stamps: `jiff` instead of `chrono` (lot 1.6)

- Every time the agent writes (the signed chains, the protocol, the
  exports, the CLI) is the same text byte for byte; times read from text
  (`--since`, the heartbeat verifier, `net resolve`) are read with the same
  grammar as before, leap seconds included.
- `cargo audit` no longer needs the exception for `chrono`
  (RUSTSEC-2026-0543, unmaintained).
- Nothing to configure; no format changed.

## 3. The mount guard: peer copies, `mount_setattr(2)` counted at once (lot 1.1)

- **Its margin on the verifier.** `sb_mount` and `move_mount` are each an
  entry program and the stages it tail-calls. Every mount-guard program is
  below 52 % of the 900,000-instruction gate on 5.15 and 6.1 (the
  `sb_mount` program was at 92.3 % in the alpha). A stage that a kernel's
  verifier refuses leaves its hook unattached and signs the degradation,
  as a refused hook did.
- **A peer copy moved away is refused.** A `move_mount(2)` of an attached
  peer copy of `/`, `/run`, `/proc`, `/sys`, the cgroup root, the bpffs or
  another mount the agent's paths go through is refused in any namespace
  outside a trusted-installer window, and signed (`NN-L-AT-001`, "a peer
  copy of a protected mount moved away"). A move of such a copy through
  `mount(2)` (`MS_MOVE`) outside the guarded namespaces is judged by its
  target, and what follows by the unmount guard and the integrity round
  (`KNOWN_LIMITATIONS.md`, "Self-protection against root").
- **`mount_setattr(2)`.** It has no LSM hook and is still not refused. A
  change of propagation it makes on a guarded mount, a held peer group or
  the pin directory's lock is now counted as the kernel makes it (an
  `fentry` on `change_mnt_propagation`), and the guard follows it within
  a second. The signed finding is still the integrity round's (about 30 s).
  Per-mount flags (read-only, `noexec`) do not go through that function
  and stay with the round. A kernel without the function starts the agent
  with a signed degradation ("… not at once"); the six lab kernels have it
  (§11).
- **For you, on util-linux 2.39 and later** (Debian 13's 2.41; check
  `mount --version` for `fd-based-mount`): `mount --make-*` and `mount -o
  remount,bind,ro` use `mount_setattr(2)`. They succeed, and the integrity
  round signs them High. `UPGRADE_NOTES_WAVE4.md` §52.1 said `mount
  --make-rshared /` is refused: that holds for a `mount(2)` caller only.
- An agent or a watchdog run by hand in PID 1's namespace no longer takes
  PID 1's entry out of the guard when it exits. Each re-creation of the
  lock is numbered in its finding ("its re-creation N in this run"), each
  a High of its own.
- New pins under the pin root: `MOUNT_SB_STAGES`, `MOUNT_MOVE_STAGES` and
  the propagation program's link; `MOUNT_GUARD_CONF` has six entries.
- Nothing to configure.

## 4. Ubuntu 26.04 (7.0): the exec and open fallbacks see every CPU (lot 1.3)

- On 7.0 a BPF program on a syscall tracepoint runs only for the calls
  made on CPU 0 (`KERNEL_COMPATIBILITY.md`, "Syscall tracepoints on Ubuntu
  26.04's 7.0"). The default sensors (the LSM `bprm_check_security` and
  `file_open` programs) were never affected; the exec and file-open
  sensors' tracepoint modes were.
- Now, when a sensor starts in tracepoint mode, a boot self-test makes one
  harmless call on every online CPU. Where the tracepoint misses a CPU,
  the sensor moves to the raw `sys_enter` tracepoint, which runs on every
  CPU. The choice is signed: `nn-admin status` and the capability manifest
  name the fallback (`raw_tp:sys_enter (execve, user memory)`, `(openat,
  …)`), and the degradation (`exec_sensor`, `file_open_sensor`) names the
  CPUs each attach point was seen and missed on. The lab measured 10 of 10
  execs recorded on each of 4 CPUs (§11).
- Its cost: a filter on the number of every system call of the host,
  while it runs.
- The test runs once, at the boot (`SENSOR_CONTRACT.md` §5c).
- Nothing to configure.

## 5. A file read again after an exec; the DNS sensor's port filter (lot 1.4)

- **The read-repeat filter keys on the program as well as the task.** A
  read-only open of a watched file that the same process repeats within a
  second is still recorded once. A process that reads such a file, runs
  `exec`, and reads it again under the new program now gets a second
  record, its own. Expect a few more FIM records on hosts where a wrapper
  reads a credential file and then executes the real tool.
- **The DNS response program reads only port 53.** A datagram received on
  a socket connected to another port is skipped before any helper runs.
  One narrow case changes: a datagram from port 53 that a socket queued
  before it connected to another port, then received with `recvfrom`, is
  no longer read.
- Every program's deepest call chain is within 448 of the verifier's 512
  bytes.
- Nothing to configure.

## 6. A DNS answer read before its query (lot M5)

- The agent reads DNS queries and responses from two rings, in no order
  between them. A response read before its query left the question
  "asked, never answered" for 300 s, and a later connection of that
  process to an address no response named drew no NN-L-NET-028 record.
  Now a response the process received answers its question in either
  order (`NETWORK_TELEMETRY.md` §4).
- **For you:** a host may see an NN-L-NET-028 (Medium) record where the
  alpha recorded none: a connection to an address no DNS answer gave,
  after a lookup whose response the agent happened to read first.
- Nothing to configure.

## 7. The exec quarantine's release on stop and restart (lot M4)

Only for hosts that run the exec quarantine (`--exec-quarantine`,
experimental, off by default).

- **A stop during an exec burst leaves nothing stopped.** The agent's
  stop used to wait a fixed 2 s for the quarantine's controller to stop
  itself. On an rpm host (AlmaLinux 9) a controller busy with a burst's
  package lookups did not get there before the stop's deadline ended the
  agent, and the processes it held stayed in state `T` until the next
  start. Now the stop waits for the controller only within what its
  deadline leaves, then releases from the stopping thread every process
  the kernel's map still names: resumed, or killed when a kill is owed.
  The deadline's own exit releases them too (it resumes only). A process
  the agent cannot capture stays in the pinned map for the next start, as
  before.
- **The signed `exec_quarantine` entry `stopping` gains `by`:**
  `controller` for the controller's own stop; `sweep after the
  controller's stop` or `sweep: the controller did not stop in time` for
  the stop's release. The release's entry also carries `gone` (ended
  before it reached them) and `kills_left`. A stop can now sign two
  `stopping` entries, the controller's and then the release's when it
  found something left: count `resumed` across them.
- **In enforce mode, a kill verdict already known is carried out on every
  release path.** A process whose scan asks for its kill, still waiting
  for the rules' verdict, is killed (signed) by the stop's release and by
  the next start after a crash, and stays stopped at the deadline's exit,
  where it used to be resumed.
- A new WARN, `exec quarantine controller did not stop in time — the
  stop's sweep releases what the kernel holds`, replaces `… did not stop
  within 2 s — the processes it holds stay stopped …`.
- **The release signs what it has done before the stop's deadline** (lot
  M7, builds of `main` after `v0.1.1-alpha`). A release still running
  200 ms before the deadline's note signs a first `stopping` entry
  (`"part": "first"`: what it has resumed or killed, and in `unfinished`
  what it has still to release), goes on, and signs the rest at its end
  (`"part": "rest"`). A release that ends in time signs one entry, as
  before (`"part": "whole"`). Count `resumed` across every `stopping`
  entry of the stop, as before: there can now be three (the controller's,
  then the release's two parts). Before, a release the deadline cut (seen on
  ubuntu 26.04, a burst of more than 1 000 held processes on a slow guest)
  left no signed entry: every process was released, but the audit chain
  named none. A WARN says when a release signs early: `exec quarantine:
  the stop's sweep signs what it has released at the stop's signing time,
  and goes on with the rest`.
- **Not covered yet:** after the agent was killed (SIGKILL, the OOM
  killer), the next start releases what it held only when the exec
  quarantine runs again; `uninstall.sh` after such a crash removes the
  pins and leaves those processes stopped (`KNOWN_LIMITATIONS.md`,
  "Detection coverage").
- Nothing to configure.

## 8. The `.rpm` and AlmaLinux 9 (lot 1.10)

- AlmaLinux 9 (5.14 el9, SELinux enforcing) is a guest of the nightly lab
  run, and the `.rpm` is tested in the lab. Measured on AlmaLinux 9.9: the
  alpha's signed `.rpm` installed with dnf's signature check, then a build
  of `main` put over it in place (`rpm -U --replacepkgs`, refused without
  `NN_GRANT_KEY`, the keys and the agent's id kept), a cold boot with both
  units active, `rpm -e` and `uninstall.sh --package --purge` leaving
  nothing, and no SELinux denial in any phase.
- Lot R1 (2026-11-27): the published `v0.1.0-alpha` `.rpm` upgraded with
  `rpm -U` to a `.rpm` of the `v0.1.1-alpha` release branch on AlmaLinux
  9.9, and the same with the `.deb` on Ubuntu 22.04 (`INSTALL_UPGRADE_UNINSTALL.md`
  §6).
- Fedora, Rocky and RHEL itself, and an upgrade between two packages both
  built by the release workflow, are not tested (`KNOWN_LIMITATIONS.md`,
  "Kernels and distributions").
- Nothing to configure.

## 9. Self-defence: the SysRq trigger, stops not requested, the keyboard mask (lot 2.0)

- **The SysRq trigger file is refused outside a window.** A write of
  `/proc/sysrq-trigger`, at its open and on a descriptor already open, is
  refused to every caller outside the agent's family, root included,
  whatever request it carries, unless a signed trusted-installer window
  is open: `EPERM`, and a signed NN-L-AT-001 (`deny=sysrq`, High). Each
  SysRq request acts on the whole host, outside every other hook. Inside a
  window the write goes through and its open is recorded
  (`deny=sysrq_window`, Low).
- **A stop the agent did not request is not a clean stop.** A stop
  signal (SIGTERM, SIGINT, SIGHUP for the agent; SIGTERM, SIGINT for the
  watchdog) is a clean stop only in the host's shutdown or with a signed
  trusted-installer window in force at its delivery. Any other still ends
  the process, and now:
  - the agent signs an `unrequested_stop` finding (High) that names the
    signal and its sender as the kernel delivered them, stops with the
    reason `unrequested_signal` (not a clean reason, so the off-host
    verifier reports the stop), and exits with an error; the watchdog
    starts it again, as after any death;
  - the watchdog exits with the new status **21** and leaves an
    `unrequested_stop` record, which the agent signs (High); systemd
    restarts the watchdog (`Restart=always`), and its start brings the
    agent back when it is down too;
  - the finding is held in `nn-admin status` until an acknowledgement
    covers it, like a role's death.

  The stops that were requested keep their behaviour: `install.sh`,
  `uninstall.sh` and the upgrade stop the units inside their own window,
  and so does the operator's trusted-installer flow
  (`INSTALL_UPGRADE_UNINSTALL.md` §3.7); the host's shutdown; an
  admin-signed shutdown.
- **The keyboard SysRq mask cannot be widened outside a window.**
  `kernel.sysrq` is one of the guarded sysctls: a write that would let a
  keyboard signal processes is refused outside a signed window, by both
  sysctl judges, and signed (`deny=sysctl`, naming `kernel.sysrq` and the
  value). It is never opted out by the per-rule policy's `sysctl-allow`.
  A narrower mask goes through, as do the distributions' defaults
  (Ubuntu 176, Debian 438, RHEL and AlmaLinux 16).
- **The agent never rewrites the host's mask.** A mask found letting a
  keyboard signal processes (set at boot by `sysctl.d`, or inside a
  window) is the integrity round's signed advisory
  `sysrq_keyboard_signals` ("SysRq can signal processes from a
  keyboard"), listed by `nn-admin status` under the advisories while it
  holds, and ended when the mask is narrowed. No sensor is degraded by it.
- **For you:** run a script that uses the trigger file on purpose inside
  a window; narrow a `kernel.sysrq` that lets a keyboard signal
  processes if the host does not need it; acknowledge an
  `unrequested_stop` once you know who sent the signal.

## 10. Smaller changes

- **The export worker (lot 1.8).** A failing OS random generator in the
  syslog sink's TLS key exchange is now that sink's fault, with no key
  made from it, instead of a panic that ended the worker.
- **The TLS provider (lot 398).** rustls-rustcrypto 0.1.0-pre.0: the TLS
  1.3 suites, groups and signature schemes the export offers are the same
  (`EXPORT.md` §7).
- **Landlock (lot 399).** On a kernel with Landlock ABI 10 or later the
  worker declares ABI 9, the rights it asks for; before, the core would
  have refused every worker's hello there. No lab kernel has ABI 10.
- Nothing to configure.

## 11. What the stage's lab round measured

On `main` at `7f4834ce`, the eBPF object of that commit's CI run, six
kernels, 2026-11-26:

| kernel | programs loaded / not counted / failing | highest share of the 900,000 gate | deepest stack chain |
|---|---|---|---|
| 5.14 (AlmaLinux 9.9) | 128 / 2 / 0 | `execmap_check` 33.9 % | 448 |
| 5.15 (Ubuntu 22.04) | 123 / 7 / 0 | `module_read_file_observe` 53.3 % | 448 |
| 6.1 (Debian 12) | 124 / 6 / 0 | `module_read_file_observe` 53.3 % | 448 |
| 6.8 (Ubuntu 24.04) | 127 / 3 / 0 | `execmap_check` 29.1 % | 448 |
| 6.12 (Debian 13) | 126 / 4 / 0 | `execmap_check` 33.9 % | 448 |
| 7.0 (Ubuntu 26.04) | 125 / 5 / 0 | `execmap_check` 30.8 % | 448 |

"Not counted" are the documented optional programs
(`KERNEL_COMPATIBILITY.md`, "Verifier headroom"). The privileged suites
passed on 5.15 and 7.0 (186 passed, 0 failed, on each); on 7.0 the exec
fallback recorded 10 of 10 execs on each of the 4 CPUs; the `.rpm` passed
30 of 30 package steps on AlmaLinux 9. These are our own guests, not a
third party's.
