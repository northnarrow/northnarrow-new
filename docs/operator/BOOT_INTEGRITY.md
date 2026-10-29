# Boot integrity: phases, self-test, degradations, trust level

Lab PR 218 (external review G-09, G-11, G-12, AR-09, P0 C-13, P0 C-14;
capability program C01 and C23); lab PR 262 (Wave 4 restructure, R11b:
every integrity check before the load and the pin, enforced by the types;
every refused start signed, section 7); lab PR 265 (the independent review
of #466, F4-bis: the start is the agent that ran before — its directories
not mounted over, its signing key not minted again where an identity was,
section 1.1). What the agent checks before it
touches the kernel, how it proves that its deny hooks run, how it records
what it runs without, and how it says, signed, how far its protection is
measured. Code: `agent/src/boot/` (`mod.rs`, the phases, `refusal.rs`,
`deny_selftest.rs`, `trust.rs`, `manifest.rs`) and
`crates/nn-linux/src/boot/` (`mod.rs`, `checks.rs`, `lsm.rs`,
`degradation.rs`).

## 1. The start in phases

The order of the start is enforced by the code (`BootSequence`), not by
comments in `main()`. Each step is recorded in its phase; a step recorded in
another phase, a phase skipped, or a phase left with a required step
missing stops the start. The eBPF object's load (the by-name pins of its
maps are made there), every pin and every attach take an
`IntegrityVerified` (lab PR 262; lab PR 218's `AttachPermit`), and only
`BootSequence::verify_integrity`, the move from preflight to attach, hands
one out, once every preflight check has passed. The steps it requires —
the agent's directories' mounts and its signing identity (lab PR 265), the
eBPF object, the state directory, the BTF offsets, the capabilities,
the install manifest, the audit log, the BPF LSM, the deny hooks' pin root
and the kernel's BTF — are recorded only by the checks themselves
(`boot::checks`, each after it ran against the host and passed;
`BootSequence::done` refuses them): a load, pin or attach placed before a
check does not compile, a check skipped or moved after it fails every
start (and the tests `boot::tests::main_runs_the_phases_in_order` and
`boot::checks::tests`).

What the proof means (the independent review of the PR, #466 F3): a
process has one boot sequence — `BootSequence::begin`, the only public
way to one, refuses a second, and the start's preflight takes it first —
and its checks read the host's own roots (the state directory, the active
LSMs, the kernel's BTF, the running binary) and the overrides from the
process's environment; what the start gives them is the operator's
configuration (the install manifest's and the audit log's paths, the
signing key's, `--detect-only`). So the one proof of a process says that
its start ran every check against this host, under that configuration,
and was refused by none. The proof has no public field and is not
`Clone`, `Copy` nor `Default` (tests the compiler evaluates when they
build), and the object's bytes are nn-linux's alone; like any zero-sized
type it can be forged by `unsafe` code — the guarantee is safe Rust's.

| Phase | What runs | Required before the next phase |
|---|---|---|
| 1. preflight | the agent's own directories not mounted over, its signing key there or no earlier identity on record (section 1.1); the embedded eBPF object; the state directory; the BTF offsets; the chains against their heads; the identity; the demo rules' gate; the capabilities (`caps::boot_gate`); the install manifest; the audit log's writability, the agent's key and the chain, opened; the host hardening table; the BPF LSM gate (section 2); the deny hooks' pin root and the kernel's BTF | agent mounts, signing identity, eBPF object, state directory, BTF offsets, capabilities, install manifest, audit log, BPF LSM, pin root, vmlinux BTF |
| 2. attach | the eBPF object loads (and pins its maps); the sensors; the deny hooks (`anti_tamper::attach`) | sensors, deny hooks |
| 3. self-test | one deny hook exercised against the agent (section 3) | self-test |
| 4. attest | the signed audit log, opened in the preflight, takes `agent_boot`; every degradation found so far is signed (section 4) | `agent_boot`, boot degradations |
| 5. subsystems | the blocklists, the rule engine, the response executor, the posture, the FIM observers and the file-open sensor, the drains, the admin socket | — |
| 6. run | the capability manifest and the trust level are signed (sections 5 and 6); `READY=1`; the event loop | capability manifest |

A refusal in the preflight leaves the kernel as it was: nothing is loaded,
nothing pinned, no hook attached, and the start's registration in the
previous agent's pinned `PROTECTED_PIDS` (made before the state files'
bootstrap, so that the previous hooks let it reach its own files) is
withdrawn; the refusal is signed (section 7). It creates no state file
but what its signature needs (review #466 F8): when the eBPF object, the
state directory or the BTF offsets refuse, the state files are not
bootstrapped; the agent's key and identity are made when they are
missing — only when nothing says the install had them (section 1.1) —, and
the chain that takes the refusal. The capability,
install-manifest and audit writability checks used to run after the eBPF
programs were loaded, attached and pinned (until lab PR 218), and so did
the audit chain's open (until lab PR 262) and the deny hooks' pin root
and BTF (until review #466 F6).

| Check | Before the load (L) and the first pin | Refuses with |
|---|---|---|
| no mount at or under the agent's own directories but a bind of a directory onto itself; one bpffs alone at `/sys/fs/bpf`; with the previous agent's pins, the directories it protected (section 1.1) | yes, first: before anything is read or written | `agent_mounts` (unsigned) |
| with the previous agent's pins, a restart of the binary it protected keeps its key; the signing key there, or no earlier identity on record — its public half, the install's id, a written head anchor, a signed row of a chain (section 1.1) | yes, first | `signing_identity` (unsigned) |
| the embedded eBPF object (real, its hash) | yes | `ebpf_object` |
| the state directory not a link | yes | `state_dir` |
| the BTF offsets the programs read (the running kernel's BTF; arming the `BTF_OFFSETS` map needs the loaded object: after L, before any attach) | yes | `btf_offsets` |
| the demo rules' gate (a demo-tappa5 build in enforcement) | yes | `demo_rules` |
| the capability bounding set (`CAP_KILL`) | yes | `capabilities` |
| the install manifest: the binaries and the eBPF object against what `install.sh` recorded | yes | `install_manifest` |
| the audit log writable, the agent's key loaded (an absent one minted), its chain opened (a line before the end that is not a row refuses) | yes (but when the previous agent's hooks close it to this process: after the attach registers it) | `audit_log` (a key that cannot be loaded: unsigned) |
| the BPF LSM in the active LSMs | yes | `bpf_lsm` |
| the deny hooks' pin root (`/sys/fs/bpf/northnarrow`) not a symbolic link nor anything but a directory (ATP-007), unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1` | yes (after L until review #466 F6) | `deny_hooks` |
| the kernel's BTF (`/sys/kernel/btf/vmlinux`), which every deny hook resolves against (review 53: none attaches without it), unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1` | yes (likewise; a BTF that does not parse is the BTF offsets' refusal) | `deny_hooks` |
| the load itself and each mandatory sensor's attach | is L | `sensors` |
| the deny hooks' attach and pins | after L (it is the attach) | `deny_hooks` |
| the deny self-test | after the attach (it exercises an attached hook) | `deny_self_test` |
| the boot's own `agent_boot` row (a full disk is found by the write) | after the attach | `audit_log` |

The two continuity checks (section 1.1) run first and refuse at once:
before the start registers in the previous agent's `PROTECTED_PIDS`,
before any state file is bootstrapped and before the identity is read —
nothing can sign them (the key is the one hidden or absent), so the
journal holds the refusal. The preflight's next three run before the
identity is read: the first that refuses is kept and signed at the start
of the integrity checks, still before the load (on a linked state
directory, nothing under it is read or created first).

The audit log's preflight opens it for append without writing (or, when
the file does not exist yet, checks that its directory can take it): a
read-only mount, an immutable file or a missing `ReadWritePaths` refuse the
start before anything attaches, unless `NN_AUDIT_ALLOW_UNWRITABLE=1`. Then
the log is opened with the agent's key, as the attest phase opened it
(lab PR 262): its chain is read, a torn last write repaired and signed, a
line before the end that is not a row refuses the start — before the load
now, where it used to refuse once everything was loaded, pinned and
attached. The attest phase appends the boot's rows to that log, in the
same order as before. The signed `agent_boot` row after the attach still
proves the log with a write. When the previous agent's pinned hooks close
the key or the log to this process (its early registration failed), the
open is left to the attest phase, after this boot's attach registered the
process. A signing key that cannot be loaded — a file at its name that is
not a key: corrupted, empty, a bind mount of `/dev/null` or of anything
but a regular file, unreadable — or an absent one that cannot be minted
refuses the start the same way, unless `NN_AUDIT_ALLOW_UNWRITABLE=1`
(review #466 F4: it started unaudited, with one WARN, until then): no row
can be signed without it, so the journal holds that refusal alone
(section 7). An absent key is minted only at a first install: where an
earlier identity is on record the start was refused before (section 1.1).

### 1.1 The start's continuity (lab PR 265)

Since review #466 F4 a key that is there but cannot be loaded refuses the
start. An absent key was minted, as at a first boot — and root can make the
key look absent without unlinking it, which the deny hooks refuse: a bind
mount over `/etc/northnarrow` on the host (no deny hook covers `mount(2)`),
or a runtime drop-in (`BindPaths=`, `TemporaryFileSystem=` — with
`ReadWritePaths=` reset, or systemd keeps the unit's bind of the same path)
and a `cgroup.kill` of the agent's cgroup (allowed: tamper case C20). The
watchdog's respawn then minted a new key, published its public half over
the old one in the view it saw, and signed every chain under it from then
on: the signing identity reset, with one INFO line (`bootstrapped fresh
agent signing key`). Two checks now run first in the preflight, both
recorded steps the integrity proof requires. They read two kinds of proof:
the agent's own mount table, and — when the previous agent's pins are
there — the kernel's record of what that agent protected, which no view
of the filesystem can change (the independent review of the PR, #468, R2).

- **`agent_mounts`.**
  - In the agent's own mount table (`/proc/self/mountinfo`: a bind on the
    host is copied into it, a drop-in's mounts are made there; read as
    bytes, split on the ASCII space only, every `\ooo` escape turned back
    into its byte — review of #468 R1, R3: a split on every Unicode space
    shifted the fields of a path holding U+00A0, so a bind over
    `/etc/northnarrow` from such a directory went unseen, and a byte that
    is not UTF-8 in any mount made the table unreadable), every mount at or
    under the agent's directories — `/etc/northnarrow` and
    `/var/lib/northnarrow` always, and the directories of the key, the
    identity, `admin.pub`, the install manifest, the head anchor and the
    chains the command line names — must be a bind of a directory onto
    itself: the same filesystem as the mount it sits on, showing the
    directory that is there. That is what the unit's `ReadWritePaths=` (and
    `RuntimeDirectory=`) make, on any layout: `/` on ext4 or xfs, a btrfs
    subvolume as `/`, a separate `/var` (or `/var/lib`) partition. Anything
    else refuses the start: another directory or a file bound there (a bind
    of an empty directory over `/etc/northnarrow`, a directory of the same
    basename elsewhere, another key bound over `agent.sig.key`), another
    filesystem (a tmpfs, a loop device holding the same path, an overlay),
    a mount whose underlying mount is not in the table. The journal line
    names what is mounted where, and what was there. A line of the table
    not in the kernel's shape refuses only when it may be a mount over
    those directories; one about anything else never refuses. The agent's
    directories themselves must therefore not be mount points of their own
    (put `/var` or `/var/lib` on its own filesystem instead).
  - One bpffs instance at `/sys/fs/bpf`, nothing else stacked on it and
    nothing mounted over the pin root `/sys/fs/bpf/northnarrow`: those
    would hide the pins, the next proof. What counts is the instances, not
    the mounts (the re-review of #468, S3): a bind of the same bpffs (its
    `major:minor`, its root `/`) onto itself, as a node or CNI script may
    lay, shows the same pins and is accepted; another bpffs, a tmpfs or a
    directory of the bpffs bound there refuses.
  - With the previous agent's pins there (they survive a `cgroup.kill` and
    a crash, not a reboot): `/etc/northnarrow` and `/var/lib/northnarrow`
    as this start sees them must be the inodes that agent protected (its
    pinned `PROTECTED_INODES`). A copy bound over an ancestor (`/etc`,
    `/var/lib`), a directory swapped by a rename above it, another root
    (`RootDirectory=`) show other inodes and refuse. Every agent registers
    the host's directories (their paths are fixed), so an agent the
    privileged tests run, whose files are elsewhere, sees the same ones.
  - A table that cannot be read, or pins whose inode map cannot be read,
    refuse too.
- **`signing_identity`.**
  - With the previous agent's pins there, the start is that agent's
    restart, and a restart keeps its identity: its key, its id
    (`agent_id`) and its audit log must each be in a directory that agent
    protected — a drop-in redefining `ExecStart=` with them in an empty
    directory refuses — and be there (the re-review of #468, S2: the id
    and the audit log too, not only the key; the other chains moved away
    are not refused, but the head anchor beside the audit log records
    their heads, and the boot's chain check signs a chain that starts
    again). In a release build this holds whatever binary the start runs
    (the re-review's S1): a copy of the binary started by a drop-in
    (`ExecStart=` naming a copy, or `ld.so` and the binary) is judged as
    the restart it is. Before, the rule held only for the binary the
    previous agent protected, and a copy was stopped for another reason:
    the check opens the pinned inode map read-write, and the BPF guard
    still attached denies a write handle on it to a process that is
    neither protected nor running a protected binary — the map unread,
    `agent_mounts` refused. That held while the guard enforced, not with
    `NN_BPF_DEFENSE_OBSERVE=1` (a drop-in can set it, leaving one signed
    degraded boot) nor for a read-only open. Only the lab builds
    (`test-privileged`, `debug-trigger`: the privileged tests run copies
    of the binary with files of their own beside the installed agent) keep
    the copies' exemption, and a test holds that a build without those
    features has none. In the documented flows the pins go before the
    identity: an upgrade, an uninstall and a re-key remove them first
    (`install.sh --upgrade`, `uninstall.sh`; a re-key after a refusal
    reboots first, section 3.10 of `INSTALL_UPGRADE_UNINSTALL.md`), and
    while they are there the deny hooks keep the files from being removed
    outside a window.
  - When the key's name holds nothing (read without following a link or
    opening it: a key the previous agent's hooks close to this process is
    there), the start looks for an earlier identity in the paths it was
    given: the key's public half (`agent.sig.pub`) and the install's id
    (`agent_id`) — anything at their names, or a lookup that fails
    otherwise than "not found" (review of #468 R8) —; the head anchor when
    it is not empty (install.sh creates it empty); a signed first row
    (`entry_hash`, `agent_sig`) in the audit log or in one of the other
    chains (canary registry and accesses, detections, status events,
    netflow, FIM drift and baseline, listeners), their manifests and sealed
    archives, or one of them that cannot be opened otherwise than "not
    found" (a link counts). An empty chain, a directory or another non-file
    at its name, or a first line that is not a row is no evidence (the
    chain's own check judges it). Any evidence refuses the start and
    nothing is minted.
  - The key is decided once (the review of #468, R4). The check gives
    one of two tokens, which no other code can make and the boot
    sequence gives once: *key present* — loaded, never minted — or *first
    install* — the one value that lets the key be minted, taken by value.
    The start then loads the key once, right after it registered with the
    previous agent's hooks, and every chain it signs — the audit log, the
    refusals, the head anchor, the detections and status events, FIM,
    the canaries, the network logs — takes a copy of that one key: no
    phase loads a key of its own, and the chains of one boot are signed
    by exactly one key. The load of a key decided present never mints:
    a key gone between the check and the load (a mount laid during the
    start) is an error, and so is a file other than the one the check saw
    there (another device or inode: a key swapped in); the audit check
    then refuses the start (review #466 F4). The mint of a first install
    writes the key to a file of its own (`O_CREAT|O_EXCL`) and links it at
    the key's name with `link(2)`, which never replaces what is there (the
    `rename(2)` used before did): a key that appeared since the check is
    kept and the mint refused. A load the previous agent's hooks close to
    this process before it is registered keeps the decision and is read
    after the attach. Tests hold both rules: nothing in the workspace
    mints the key but that one load (the tests' door that mints without a
    decision is compiled into test builds only), and the start's phases
    read no key but the one.

Neither has an override: an environment variable a drop-in can set would
be set by the same drop-in that lays the mount. Both refuse at once,
unsigned, exit 78, the registration withdrawn (there is none yet) —
section 7. The watchdog restarts the refused agent within its ceiling and
then holds; removing the mount (or the drop-in, then `daemon-reload`) and
`systemctl start northnarrow-agent` bring the agent back with its own key.
To re-key on purpose, retire the install's identity
(`INSTALL_UPGRADE_UNINSTALL.md`, "Re-keying the agent").

What these checks close, and what they do not:

- Closed while the previous agent's pins are there (no reboot): a bind
  over the agent's directories or over an ancestor, on the host or from a
  drop-in (`BindPaths=`, `TemporaryFileSystem=`, `RootDirectory=`); a
  rename that swaps `/etc` or `/var/lib` with a copy; a drop-in redefining
  `ExecStart=` with the key's, the id's or the audit log's path elsewhere
  — for the installed binary and, in a release build, for a copy of it;
  a bpffs stacked over the pins (a bind of the same bpffs instance onto
  itself, which hides nothing, is accepted: the re-review's S3). (A view
  without `/etc/northnarrow` at all does not start the shipped unit:
  systemd cannot set up its `ReadWritePaths=`.)
- Closed by the one decision, pins or not: a key hidden, removed or
  swapped between the check and its load — never minted, never another
  file (the review of #468, R4).
- Closed after a reboot only by the evidence the start can read: a mount
  over the agent's directories themselves (the mount table), and the
  key's absence beside its own public half, id or chains.
- Still open: a reboot with a persistent mount, drop-in or generator that
  swaps both `/etc` and `/var/lib` together, or redefines `ExecStart=`
  with every identity path elsewhere (nothing on that view says an
  identity was there: it looks like a first install); the bpffs itself
  unmounted (`umount -l /sys/fs/bpf`) and a fresh one mounted in its
  place, which puts the pins out of the start's reach as a reboot does
  (no deny hook covers `mount(2)` or `umount(2)` yet: CM-12); the chains
  other than the audit log moved away on a restart (not refused: signed
  by the boot's chain check against the head anchor); the copies'
  exemption in the lab builds. An off-host record of the public key is
  what would cover the reboot.

The unit's runtime drop-in directory,
`/run/systemd/system/northnarrow-agent.service.d`, is made (empty) by the
unit before every start (`ExecStartPre=+/bin/mkdir -p …`) and registered
by the deny hooks like the persistent one (NOCREATE, external audit
EBPF-015): a new drop-in there — `systemctl edit --runtime`, the drop-in
above — is refused outside a signed trusted-installer window, and the
directory cannot be removed or renamed (`systemctl revert
northnarrow-agent` fails with `EPERM` outside a window). It is one of the
places systemd reads drop-ins from: the others are the host's
(`service.d`, the `northnarrow-.service.d` prefix, `system.control` —
`set-property` writes resource properties there, but any directive placed
there is read —, the generators', `transient`, the vendor directory). A
drop-in there is a self-integrity finding (`unit_dropin`,
`unit_shadowed`); a mount it lays on or under the agent's directories is
refused by the mount table, and one above them by the pins' proof while
they are there.
## 2. The BPF LSM gate

The deny hooks are BPF LSM programs. A kernel built with
`CONFIG_BPF_LSM=y` but without `bpf` in its active LSM list
(`/sys/kernel/security/lsm`; the default on Ubuntu) lets every one of them
attach and never runs them. The agent used to start there with one WARN,
its health line saying "all LSM hooks attached", and no self-defence.

**Decision.** Such a start is refused before anything attaches (exit 78,
`EX_CONFIG`), unless the degraded-mode opt-in the deny-hook shortfall
already uses is set: `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`. Either way the
signed chain gets a `subsystem_degraded` (`source: bpf_lsm`) with the list
the kernel runs; a refusal adds an `agent_boot` row with `result: refused`
and `refused_by: bpf_lsm`. The opt-in starts the agent at trust level L0,
and the self-integrity check reports the variable as a `weakening_env`.
Detect-only does not change the decision: it turns the response off, not
the self-defence the agent promises.

A list that cannot be read (securityfs not mounted) is not a refusal: the
self-test decides, and the gap is signed.

Alternatives not taken: keep starting with a WARN (the silent absence this
fixes); a new variable for this case alone (one more weakening switch, when
the existing one already means "start below the expected protection" and is
already watched); refuse an unreadable list too (the self-test measures the
same thing directly).

Enable `bpf` as `KERNEL_COMPATIBILITY.md` ("Enabling the bpf LSM")
describes: add it to the list the kernel runs, never write a fixed list.

## 3. The deny self-test

Right after the deny hooks attach, the agent runs a child of its own binary
(`northnarrow-agent --deny-self-test`, hidden flag). The child is not in
`PROTECTED_PIDS`; it sends `SIGURG` to its parent, the agent. `task_kill`
refuses every signal but 0 to a protected process from an unprotected one,
so the child must get `EPERM` — a root caller signalling a root process
gets no `EPERM` from the permission checks, only from an LSM, and the child
runs in the agent's own SELinux domain or AppArmor profile, which may signal
itself. `SIGURG` is ignored by default and the
agent installs no handler: when the hook does not run, the signal it lets
through changes nothing.

| Outcome | Meaning | The start |
|---|---|---|
| `denied` | the signal was refused: the deny hooks run | goes on |
| `not_denied` | the signal was delivered: the hooks are attached and not run ("attached but not executed", seen on Ubuntu) | refused, exit 78 (`refused_by: deny_self_test`, signed), unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`: then L0, signed |
| `inconclusive` | no child, no exit within 5 s, another errno | goes on, signed, L1 |

The refusal leaves a denial on the evidence ring like any attempt on the
agent. The agent takes that one record — the child's pid, `SIGURG`, the
agent's pid as the target, a kernel timestamp between the spawn and the
reap, once — before the posture and the rules see it: the self-test never
raises COMBAT nor writes an NN-L-AT-001 detection. Any other denial goes on
as before. The journal says `deny self-test: its refused signal reached the
evidence ring` when it arrives: the refusal came from the agent's own hook,
which writes that record.

What the self-test proves: the kernel runs the agent's BPF LSM programs and
one deny hook (`task_kill`) refuses. It does not exercise each of the 16
mandatory deny hooks one by one; the attach counts them (the health line),
and a per-hook self-test is a follow-up.

## 4. Degradations

A sensor on its fallback attach point, a hook that did not attach, a stream
that is not persisted: each one used to be a WARN, some of them a signed
record, none of them visible in `nn-admin status`. Every one now:

- is signed in the audit chain as a `subsystem_degraded`
  (`op: integrity_drift`, `extra.kind: subsystem_degraded`, `extra.source`
  naming the part): at once when the code that finds it holds the audit
  log, at the log's open (phase 4) for what came before it, otherwise by a
  flush every 15 s — within 60 s of the report in every case once the log
  is open (the audit log now opens before the subsystems load);
- is listed by `nn-admin status --key` (`degradations`), and counted
  against the trust level.

The sources added by this PR: `bpf_lsm`, `deny_self_test`, `exec_sensor`
(the exec sensor on `sys_enter_execve`: the path read from the caller's
memory), `file_open_sensor` (the file-open sensor on `sys_enter_openat`,
each of its four fallbacks and the tracepoint mode), `dns_sensor`
(`udp_v6_send_skb` not attached: queries to IPv6 resolvers not observed;
the `udp_sendmsg` fallback, signed since EBPF-006), `io_uring_sensor` (no
tracepoint, or no submit tracepoint), `net_sensor` (`udpv6_sendmsg` not
attached), `net_drain` (the netflow or listener log cannot be opened). The
earlier boot records (tracepoint offsets, hook arguments, capabilities,
anti-tamper observe hooks and degraded starts, JA3 without producer, no
`nft`, FIM coverage, the admin socket…) go through the same
registry and keep their shape.

An operator's choice of a weaker sensor (`--exec-sensor tracepoint`,
`--file-open-sensor tracepoint`, `--dns-sensor sendmsg`) is recorded too:
the trust level says what runs, not why.

**The network drain without its log (P0 C-14).** When the netflow log
cannot be opened, the drain used to stay off for the whole boot: TCP, UDP
and listener events reached no rule. It now runs without the log — every
flow and listener still reaches the rules, nothing is written — and the
degradation is signed (`source: net_drain`), as the listener log's already
was evaluated-not-persisted.

## 5. Trust levels

How far this run's protection is measured, from the boot's own checks:

| Level | Meaning | When |
|---|---|---|
| **L3** | enforcing and verified | `bpf` in the active LSMs, every mandatory deny hook attached and armed, the deny self-test refused its signal, the response enforcing, nothing degraded |
| **L2** | enforcing and verified, degraded | as L3, with at least one degradation recorded (section 4) or detect-only |
| **L1** | enforcement partial or not verified | a mandatory deny hook missing (a start under `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`), or the self-test inconclusive |
| **L0** | no enforcement | `bpf` not in the active LSMs, the self-test's signal delivered, or no deny hook attached |

The mandatory deny hooks are the 16 of `DENY_HOOKS` plus the optional ones
the running kernel has (`OPTIONAL_DENY_HOOKS`), as the health line counts
them. The host's own hardening (lockdown, Secure Boot, IMA, module
signatures, kexec — `nn-admin host-check`) is not part of the level: it is
listed next to it in the manifest. `nn-admin status --key` shows the level
recomputed with the degradations recorded since the boot (a sensor that
degrades later lowers it); the manifest keeps the boot's.

## 6. The capability manifest

At every boot, before `READY=1`, the agent signs what it runs with: one
`capability_manifest` row of the audit chain (the agent's key,
hash-chained: `nn-admin audit verify` checks it), whose `extra` is:

| Field | Content |
|---|---|
| `manifest_version` | 1 |
| `agent_version`, `kernel` | the agent's version, `/proc/sys/kernel/osrelease` |
| `btf`, `btf_offsets_resolved`, `btf_offsets_drifted`, `btf_offsets_absent` | `/sys/kernel/btf/vmlinux` present; the offsets resolved from it |
| `active_lsms`, `bpf_lsm` | the active LSM list; `active`, `absent` or `unknown` |
| `deny_hooks` | `expected`, `attached`, `missing` (each hook or failed step with why), `observe_missing` |
| `deny_self_test` | `denied`, `not_denied` or `inconclusive: <why>` |
| `bpf_guard` | `enforce`, or `observe` (a debug build) |
| `sensors` | each sensor and its attach point (`exec`: `lsm:bprm_check_security` or `tracepoint:syscalls/sys_enter_execve (user memory)`; `file_open`, `dns`, `process_spawn`, `tcp_connect`, `net_flows`, `io_uring`, `fim_observers`) |
| `host_hardening` | each check of `nn-admin host-check`: id, `ok`/`warn`/`unknown`, value |
| `detect_only` | the response mode |
| `degradations` | section 4, as of the boot |
| `trust_level`, `trust_reasons` | section 5, and why it is below L3 |

Read it from the running agent with `nn-admin capabilities --key <key>`
(`--json` prints `{"entry_hash": …, "manifest": {…}}`, the row's hash and
the manifest as signed). The key needs `audit-read` or `telemetry-read`:
the manifest, the trust level and the degradations are telemetry, served
by the signed status verb only (external audit ASK-009). `nn-admin status
--key` prints the trust level, its reasons and the degradations; without a
key they are withheld like the other telemetry. The status reply appends
`trust_level`, `trust_reasons`, `degradations` and `capability_manifest`
after the fields of lab PR 207 (postcard: an older `nn-admin` reads a newer
agent's reply; upgrade the agent first).

## 7. Refused starts

Every gate refuses the start the same way (lab PR 262; lab PR 218's
`record_refused_boot`) — but the two continuity checks of section 1.1,
which nothing can sign and the journal holds alone (lab PR 265): it logs
what it found, then the refusal is signed —
the rollback floor, the identity, a `subsystem_degraded` for the gates that
had one (`bpf_lsm`, `deny_self_test`), then an `agent_boot` row with
`result: refused`, `refused_by` naming the gate (the table of section 1),
`detail`, `binary_integrity` and `install_provenance` (`unchecked`/`none`
for the gates before the install manifest's check) —, the start's pid is
withdrawn from the pinned `PROTECTED_PIDS`, and the agent exits **78**
(`EX_CONFIG`). Before lab PR 262 only the install manifest's, the BPF
LSM's and the self-test's refusals were signed; the others left a journal
line, and all but the BTF offsets' exited 1. Where the rows go:

1. the audit log — the one the preflight opened, once it did;
2. when the audit log cannot take them (its own gate: not writable, its
   chain broken, its write failed), a chain of the same format signed with
   the same key, in a file of its own: `boot-refusals/refusal-<random>.jsonl`
   beside `--pid-file` (`/run/northnarrow/boot-refusals/` under the shipped
   unit). The agent creates the directory (0700) and, before it writes,
   checks it and the pid file's directory: opened without following a
   symbolic link, owned by the agent's user, closed to others, not another
   filesystem mounted over the name. The file is new (`O_CREAT|O_EXCL`,
   0600): no name another process put there is opened (review #466 F1).
   Its first row, `boot_refusal_fallback`, names the audit log and its head
   at the refusal (`audit_head`: its rows and last `entry_hash`, or `null`
   and `audit_head_unreadable` with why). Verify it with
   `sudo nn-admin audit verify --from /run/northnarrow/boot-refusals/refusal-<…>.jsonl`.
   The next start that opens the audit log reads each file once (a regular
   file of the agent's user, closed to others, one link, at most 1 MiB),
   verifies it and records it there from those same bytes (review #466
   F2) — one `boot_refusals_recovered` row per file (`result: recorded`;
   `extra`: `fallback`, the chain's id — its first row's hash —, the
   `audit_head` it named, its rows and head, the refused boot with its
   time, gate, detail, binary integrity and row hash), before the boot's
   own `agent_boot` — and removes the file. A chain is recorded only when
   its first row is a fallback chain's, every row is signed for this
   agent's id, the head it names is this audit log's row at that place, and
   the log has not recorded that chain before. Anything else — a chain
   that does not verify, a copy of one recorded before, a prefix of the
   audit log, a link, a FIFO, a file open to others or over 1 MiB — is
   recorded with why (`result: refused`, none of its content) and removed
   all the same; a directory that is not the agent's is recorded and left.
   At most 16 files per start;
3. nowhere when neither can be written (no key, no absolute `--pid-file`,
   a fallback directory that is not the agent's), and for `agent_mounts`
   and `signing_identity` (a chain opened under a mount would be in the
   view the start refuses; signing would mean minting the key the start
   refuses to mint): the journal says why, without the content of any
   file.

The fallback is on the runtime directory's tmpfs: a reboot empties it,
and root can delete a file there before the next start records it — the
journal's `refused boot recorded in the fallback chain` line, with the
chain's `entry_hash`, is then the trace. A persistent, protected place
and an anchor for its head are a follow-up (review #466 F5).

A refusal before the load leaves no BPF program, link or pin of its own: a
host whose previous agent's hooks are pinned keeps them, unchanged (they go
on protecting the agent's files), and a host without them stays without.
The gates after the load keep what attached before them pinned, as they
did. The watchdog restarts a refused agent as any other exit, within its
ceiling (5 in 60 s).

Journal lines: the gate's own ERROR (`refusing to start: …` — for the
continuity checks `refusing to start: a mount hides the agent's own files:
<mount point> (<fstype> <source>, its directory <root>): …` and `refusing
to start: the agent's signing key <path> is absent, but this install had
one: <evidence>. …` —, `binary
integrity MISMATCH …`, `audit log NOT writable …`, `audit log open failed
…`, `agent signing key cannot be loaded …`, `CAP_KILL missing …`), then
`refused boot recorded in the audit chain`
(or `refused boot recorded in the fallback chain: …`, or `could not record
the refused boot in a signed chain …`), `anti-tamper: the refused start's
pid withdrawn from the pinned PROTECTED_PIDS`, and `start refused gate=…
exit=78`. At the next start: `boot refusals the audit log could not take
are recorded in it now`, or `a fallback chain of boot refusals that does
not verify, or a file that is not one — recorded and removed`.

## 8. Journal lines

- `boot phase done phase=… next=… steps=…` at each phase change.
- `BPF LSM active — the deny hooks will run`, or the gate's ERROR.
- `deny self-test: a signal from an unprotected child was refused — the
  deny hooks run`, or the ERROR / WARN of the other outcomes.
- `capability manifest of this boot trust_level=… entry_hash=…`, and
  `trust level below L3` with the reasons when it is.
