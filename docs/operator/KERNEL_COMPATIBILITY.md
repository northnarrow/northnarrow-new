# Kernel / distribution compatibility

NorthNarrow's kernel half (eBPF LSM hooks and sensors) reads kernel
structures through byte offsets. Since multi-kernel level 1 those offsets
are **resolved at boot from the running kernel's BTF**
(`/sys/kernel/btf/vmlinux`) and handed to the eBPF programs through the
`BTF_OFFSETS` map before anything attaches; the values compiled into the
object are only the fallback for an unarmed map. Fields that moved
between kernel versions have alternative paths (`iov_iter` on ≤ 6.3 vs
6.4+), and enumerators that changed value are resolved by name too
(`ITER_UBUF`). LSM hook arguments are read by position, so the agent also
reads each hook's prototype from the BTF (lab PR 164): an argument that
moved between kernel versions is resolved there (`inode_setattr` from
6.9, the xattr hooks before 5.12), and every other one is checked where
the program reads it. The agent still **refuses to start** when a field,
an enumerator or a checked hook argument does not exist at all on the
running kernel (BUG-036 fail-closed gate, exit 78) — so the support status
stays binary and verifiable: either every read resolves, or the agent does
not run.

## Verified matrix (lab, `deploy/lab/nn-lab.sh`)

Each row is a measurement at the date in its last column: counts in a row
(offsets, programs, suites) are those of the build verified that day. The
offset table has grown since; `northnarrow-agent --btf-check` reports
today's counts on a host.

| Distribution | Kernel | BPF LSM | BTF | Status | Verified |
|---|---|---|---|---|---|
| Ubuntu 24.04 LTS | 6.8.0-142-generic | needs `lsm=…,bpf` (grub) | yes | **supported** — full nightly green (e2e, ignored suites, install, upgrade, uninstall, respawn); offsets match the build (41/41 at the date shown, 0 drift) | 2026-10-09 |
| Debian 12 (bookworm) | 6.1.0-53-cloud-amd64 | yes (default list includes `bpf`) | yes | **supported** — full suites green (e2e, detection, canary, net, honeypot, FIM, map pinning) with 20 of 42 offsets (at the date shown) resolved differently from the build, `iov_iter` via alternative paths, `ITER_UBUF` = 6, QNAME via `ITER_IOVEC`. Under the systemd unit the agent needs `CAP_SYS_ADMIN` (Debian's `perf_event_paranoid=3` patch); `install.sh` adds it through a drop-in on Debian-family hosts | 2026-10-09 |
| Ubuntu 22.04 LTS | 5.15.0-198-generic | needs `lsm=…,bpf` (grub) | yes | **supported (degraded)** — all 27 programs and the 8 FIM observe hooks load and attach after three rewrites for the older verifier (see below); 5.15 has no `ITER_UBUF` / `iov_iter.ubuf`, so the DNS QNAME is decoded through the `ITER_IOVEC` path only (`--btf-check` says `SUPPORTED (degraded)`); e2e + ignored suites green | 2026-10-10 (lab PR 17) |
| AlmaLinux 9 (RHEL / Rocky 9 family) | 5.14.0-687 el9_8 | yes (default list includes `bpf`) | yes | **supported** — e2e agent 6/6, FIM 4/4, watchdog 4/4 with SELinux **enforcing** (no AVC denial); `--btf-check` = SUPPORTED, 0 absent (RHEL backports `iov_iter.ubuf`); the vendor tracepoint header (`common_preempt_lazy_count`) is handled by resolving tracepoint field offsets from tracefs at boot (see below) | 2026-10-10 (lab PR 20) |
| Debian 13 (trixie) | 6.12 | `lsm=…,bpf` set by the lab template | yes | the first guest from 6.9: `inode_setattr`'s dentry is argument 1, read from the prototype (see "Kernels from 6.9" below); verified there: chmod, chown and touch of a protected file refused (allowed on `main`), the FIM setattr observer records; privileged suites 81 of 82 — DNS attribution fails on `main` too, the guest resolves through `nss-resolve` | 2026-10-16 (lab PR 164) |

Prerequisites common to every row: `CONFIG_DEBUG_INFO_BTF=y` (the
`/sys/kernel/btf/vmlinux` file), `bpf` in `/sys/kernel/security/lsm`,
bpffs mounted at `/sys/fs/bpf` (the unit checks it with
`/usr/bin/mountpoint`, util-linux), `iptables-restore` (nft backend is
fine), x86_64. Ubuntu needs `bpf` added to the kernel command line; see
[Enabling the `bpf` LSM](#enabling-the-bpf-lsm-kernel-command-line) below.

`nft` (the nftables CLI) is needed too, for the per-process egress block:
the `BlockOutbound` response and the COMBAT soft egress block of
INVESTIGATE are nftables rules. The lab's Debian 12 cloud image ships
without it: there the block fails, the failure is recorded, INVESTIGATE is
shortened to 10 s, and `nn-admin host-check` reports the host (external
audit CMB-014, lab PR 119). Since lab PR 165 the install paths ask for it:
the packages depend on `nftables`, `install.sh` refuses a host without
`nft` unless `--without-nftables` (recorded in the install manifest), and
the agent records a signed `subsystem_degraded` at boot when there is no
`nft` it may run ("block_outbound unavailable: nft missing"): since
external audit ATP-014 (lab PR 176) that is one in `/usr/sbin`,
`/usr/bin`, `/sbin` or `/bin`, owned by root and writable by nobody else —
never `PATH`, never `/usr/local`. The lab guests
install it. See the Prerequisites of
[`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md).

**Kernels from 6.9.** The `inode_setattr` hook gained an argument there;
since lab PR 164 the agent reads its position from the running kernel.
Verified on Debian 13 (6.12) on 2026-10-16: the setattr deny and the FIM
observer act there (`main` let chmod, chown and touch of a protected file
through). See "Kernels from 6.9:
`inode_setattr`" below.

## Enabling the `bpf` LSM (kernel command line)

The anti-tamper hooks are BPF LSM programs: `bpf` must be in
`/sys/kernel/security/lsm`. Debian 12 and AlmaLinux 9 have it in their
default list (matrix above); Ubuntu 22.04 and 24.04 do not, nor does a host
whose command line already sets an `lsm=` without it.

Without it the hooks attach and the kernel never runs them. Since lab PR
218 the agent refuses to start there (exit 78, before anything attaches,
with a signed `subsystem_degraded` and a refused `agent_boot`), unless
`NN_ANTI_TAMPER_ALLOW_DEGRADED=1`, which starts it at trust level L0 (no
enforcement). After the attach a deny self-test checks that a deny hook
really refuses; hooks attached but not run refuse the start the same way.
See `BOOT_INTEGRITY.md`.

**Add `bpf` to the list the kernel runs; never write a fixed list.** `lsm=`
replaces the kernel's built-in list (`CONFIG_LSM`) as a whole: a module it
does not name is not started (`capability` always is). A list copied from another host can therefore
switch SELinux (RHEL family) or AppArmor (Debian, Ubuntu) off at the next
boot. Two `lsm=` on one command line are no better: edit the one that is
there. Keep a console (serial console, IPMI, the cloud provider's) for the
reboot.

1. Check, and keep the current list for step 5:

   ```sh
   cat /sys/kernel/security/lsm                      # bpf listed: nothing to do
   grep CONFIG_BPF_LSM= "/boot/config-$(uname -r)"   # must be =y: no command line adds a module the kernel lacks
   cat /sys/kernel/security/lsm > ~/lsm.before
   ```

2. Build the new list from the one `lsm=` replaces: the `lsm=` the kernel
   was booted with, if there is one, otherwise `CONFIG_LSM`.
   `/sys/kernel/security/lsm` is the fallback only: it lists the modules
   that registered hooks and can miss one the kernel starts without any
   (`integrity` on Ubuntu, for example).

   ```sh
   cur=$(tr ' ' '\n' </proc/cmdline | sed -n 's/^lsm=//p' | tail -n 1)
   [ -n "$cur" ] || cur=$(sed -n 's/^CONFIG_LSM="\(.*\)"$/\1/p' "/boot/config-$(uname -r)")
   [ -n "$cur" ] || cur=$(cat /sys/kernel/security/lsm)
   new="$cur,bpf"
   echo "$new"
   # every module running now must still be in it (capability always runs)
   for m in $(tr ',' ' ' <~/lsm.before); do
       case ",$new," in *",$m,"*) ;; *) [ "$m" = capability ] || echo "MISSING $m: stop here" ;; esac
   done
   ```

   For example, Ubuntu 24.04 (`CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"`)
   gives `landlock,lockdown,yama,integrity,apparmor,bpf`.

3. Debian and Ubuntu (`update-grub`):

   ```sh
   sudo cp /etc/default/grub /etc/default/grub.bak
   grep -rn 'lsm=' /etc/default/grub /etc/default/grub.d/ 2>/dev/null
   ```

   If that finds a line, change the value of its `lsm=` to `$new` in that
   file, and add nothing. If it finds none, add a drop-in:

   ```sh
   sudo mkdir -p /etc/default/grub.d
   printf 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX lsm=%s"\n' "$new" \
       | sudo tee /etc/default/grub.d/99-northnarrow-bpf-lsm.cfg
   sudo update-grub
   grep -o 'lsm=[^ ]*' /boot/grub/grub.cfg | sort | uniq -c    # one value, $new, on every entry
   ```

4. RHEL family (AlmaLinux, Rocky, RHEL 9: `grubby`; there is no
   `update-grub`):

   ```sh
   sudo grubby --info=ALL | grep -E '^(kernel|args)='
   sudo grubby --update-kernel=ALL --args="lsm=$new"
   sudo grubby --info=ALL | grep -o 'lsm=[^ "]*' | sort | uniq -c   # one value, $new, once per entry
   grep -n 'lsm=' /etc/default/grub
   ```

   If `/etc/default/grub` names an `lsm=`, give it the same value: a later
   `grub2-mkconfig` would bring the old list back. After a kernel update,
   run the `grubby --info=ALL` check again.

5. Reboot, then check that `bpf` was added and nothing was lost:

   ```sh
   cat /sys/kernel/security/lsm                     # ends with bpf
   diff <(tr ',' '\n' <~/lsm.before | sort) <(tr ',' '\n' </sys/kernel/security/lsm | sort)   # only "> bpf"
   getenforce                                       # SELinux hosts: Enforcing, as before
   cat /sys/module/apparmor/parameters/enabled      # AppArmor hosts: Y, as before
   sudo nn-admin host-check                         # bpf_lsm: OK
   ```

To undo it: on Debian and Ubuntu, remove the drop-in (or put
`/etc/default/grub.bak` back if you edited a line), `update-grub`, reboot;
on the RHEL family, `grubby --update-kernel=ALL --remove-args="lsm=$new"`
when there was no `lsm=` before, `--args="lsm=<previous list>"` otherwise.

Status: written in lab PR 209 (external audit DEP-013), not yet run as
written on a lab guest. The lab templates set the same kind of list
(`deploy/lab/user-data*.tmpl`: a grub drop-in on Ubuntu and Debian,
`grubby` on AlmaLinux 9, SELinux enforcing). The check to run: the Ubuntu
24.04 and 22.04 guests, and an AlmaLinux 9 guest given an `lsm=` without
`bpf`; after the reboot the list keeps `apparmor` or `selinux` and adds
`bpf`, and `getenforce` still says Enforcing.

## Computed matrix (`northnarrow-agent --btf-check <btf>`)

`northnarrow-agent --btf-check <btf>` gives the compatibility verdict for
any kernel BTF (the live `/sys/kernel/btf/vmlinux`, a blob from another
host, one extracted from a kernel package, a BTFHub archive entry)
without root and without loading any eBPF program. Exit 0 = SUPPORTED
(also when degraded), 2 = NOT SUPPORTED, 3 = unreadable or unparseable.

`deploy/btf-matrix/run.sh` computes the matrix below over the BTFHub
archive (newest non-cloud kernel per distro/version) and compares it with
`deploy/btf-matrix/expected.tsv`; the `BTF matrix` workflow runs it on
every PR touching the offset tables or the resolver, weekly, and on
demand, and fails on a verdict worse than the baseline, on a BTF the
parser cannot read, or on a distro/version of the baseline left without
a blob (external audit SUP-013). The blobs are pinned (SUP-014):
`deploy/btf-matrix/blobs.sha256` names the archive commit and the sha256
of each archive; the run downloads them at that commit, refuses one that
does not match (a cached copy included) or that holds anything but
`<kernel>.btf`, and calls no GitHub API, so it needs no token (SUP-021).
The trade-off: a kernel archived after the pin reaches the weekly run
through a bump PR — `deploy/btf-matrix/run.sh --refresh` lists the
archive at its current head, checks the new blobs and prints the new
`blobs.sha256` — not by itself. The pin of 2026-10-20 is
`aquasecurity/btfhub-archive@ed9772c5dd12`, and gives the BTFHub rows
below. `deploy/btf-matrix/run-test.sh` tests the script offline. BTFHub
archives only kernels shipped **without**
native BTF, so the lab guests (table above) cover 5.14, 5.15, 6.1, 6.8
and, with the Debian 13 guest, 6.12.

| Source | Kernel | BPF LSM | Verdict | Notes |
|---|---|---|---|---|
| WSL2 (host) | 6.18 | — | SUPPORTED | 28 of 82 slots differ from the build kernel — handled at runtime, `inode_setattr`'s dentry among them (argument 1); 28 of 28 fixed hook arguments where the programs read them (lab PR 164), 29 of 29 with `file_ioctl_compat`'s (lab PR 174); the three optional deny hooks present |
| lab guest | 6.8 (Ubuntu 24.04) | yes | SUPPORTED | 0 drift (build kernel) |
| lab guest | 6.1 (Debian 12) | yes | SUPPORTED | 20 drift, `ubuf`/`count`, `ITER_UBUF` = 6, QNAME via `ITER_IOVEC` |
| lab guest | 5.15 (Ubuntu 22.04) | yes | SUPPORTED (degraded) | 20 drift, 2 absent; no `iov_iter.ubuf` and no `ITER_UBUF` enumerator (both optional) → QNAME via `ITER_IOVEC` only |
| BTFHub | 5.8 (Ubuntu 20.04) | yes | SUPPORTED (degraded) | 21 drift, 3 absent: no `iov_iter.iter_type` / `ubuf` / `ITER_UBUF` → no DNS QNAME; **the distro kernel config must enable BPF LSM — untested on a guest** |
| BTFHub | 5.4 (Ubuntu 18.04 HWE, CentOS 7 ELRepo) | no (needs 5.7+) | SUPPORTED (degraded) | same 3 absent fields; informational — no BPF LSM before 5.7 |
| BTFHub | 5.4 UEK (Oracle Linux 8) | no | SUPPORTED (degraded) | same |
| BTFHub | 5.3 (Fedora 31, SLES 15.3) | no | SUPPORTED (degraded) | same |
| BTFHub | 4.18 (RHEL / CentOS 8) | no | NOT SUPPORTED | `tcp_sock.bytes_sent` absent; no BPF LSM on 4.18 anyway |
| BTFHub | 4.14 (Amazon Linux 2) | no | NOT SUPPORTED | same field; no BPF LSM |

Reading it: every kernel from 5.3 up resolves all required fields, and
the only degradation before 6.0 is DNS QNAME decoding. The practical
floor is therefore **BPF LSM (5.7+) plus a distro kernel built with
`CONFIG_BPF_LSM`**, not the struct layout. `tcp_sock.bytes_sent` (4.18 /
4.14) could become optional too, but no 4.x kernel can run the
anti-tamper hooks, so it is not worth a variant.

## Kernels from 6.9: `inode_setattr` (lab PR 164)

An LSM program reads its hook's arguments by position, and a kernel that
inserts an argument moves every later one. From 6.9 the `inode_setattr`
hook receives `struct mnt_idmap *` first, `(idmap, dentry, attr)`, where
6.8 and older pass `(dentry, attr)`. The anti-tamper setattr deny
(`agent-ebpf/src/inode_protect.rs::try_inode_setattr`) and the FIM setattr
observer (`agent-ebpf/src/fim_watch.rs::fim_setattr_observe`) read
argument 0 as the dentry until lab PR 164: on 6.9 and later `truncate`,
`chmod` and `chown` of a protected file were not refused, and FIM did not
see them on a watched file.

The agent now reads the prototype of `bpf_lsm_inode_setattr` from the
running kernel's BTF at boot, takes the position of its only `struct
dentry *` argument (which must be followed by the `struct iattr *`), and
writes it into the `BTF_OFFSETS` map (`INODE_SETATTR_DENTRY_ARG`, slot
106) before anything attaches; both programs read the dentry at that
position. The same check found a second case: on 5.7 to 5.11 (5.10 LTS
included) `inode_setxattr` and `inode_removexattr` start with the dentry,
where the xattr deny read argument 1 (the attribute name); their
positions are resolved the same way (slots 107 and 108, the name taken
right after the dentry).

Hook prototypes per kernel, for the arguments the programs read
(`lsm_hook_defs.h` of each version; the BTF of the WSL2 6.18 host):

| Hook | 5.7–5.11 | 5.15, 6.1, 6.8 | 6.9, 6.12, 6.18 |
|---|---|---|---|
| `inode_setattr` | `(dentry, attr)` | `(dentry, attr)` | `(idmap, dentry, attr)` |
| `inode_setxattr` | `(dentry, name, …)` | `(userns or idmap, dentry, name, …)` | `(idmap, dentry, name, …)` |
| `inode_removexattr` | `(dentry, name)` | `(userns or idmap, dentry, name)` | `(idmap, dentry, name)` |
| `inode_set_acl`, `inode_remove_acl` | — | from 6.2: `(idmap, dentry, acl_name, …)` | same |
| `file_ioctl_compat` | — (5.10.210 and later: as below) | 6.8, and 5.15.149, 6.1.76 and later: `(file, cmd, arg)`, as `file_ioctl` | same |
| the other inode, file, task, module and BPF hooks | as on 5.15 for the arguments read | unchanged | unchanged (`bpf` gains a fourth argument, not read) |

What the agent does with a prototype:

- **Resolved positions** (the three hooks above): a prototype of another
  shape (no `struct dentry *`, two of them, or not followed by what the
  program reads next) is never guessed. The slot is written absent, the
  eBPF program reads nothing, and the agent does not attach the programs
  on that hook: a missing deny hook refuses the start unless
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`, the FIM observer counts as a FIM
  coverage shortfall, and a signed `subsystem_degraded` names the hook
  and what is lost. An unarmed map (no BTF) gives the programs no
  position at all: a hook argument has no compiled fallback.
- **Fixed positions** (29 pointer arguments of the other hooks,
  `HOOK_ARG_CHECKS` in `common/src/btf_offsets.rs`; 28 before lab PR 174
  added `file_ioctl_compat`'s): checked against the running kernel's
  prototypes. A moved one refuses the start (exit 78), like a missing
  field; a hook the kernel does not have (`inode_set_acl` before 6.2,
  `file_ioctl_compat` before 6.8 and its stable backports) is not
  checked, its program does not attach.

`--btf-check` reads the prototypes too: its summary counts the hook
arguments checked, a resolved position that differs from the build kernel
is a `drift` line (`INODE_SETATTR_DENTRY_ARG … compiled=0 runtime=1` on
6.9 and later), an unresolved one an `absent` line, and a moved fixed one
a `missing` line (NOT SUPPORTED). Verified on Debian 13 (6.12): `28 hook
arguments checked` and the `INODE_SETATTR_DENTRY_ARG` drift line (29 from
lab PR 174 on a kernel with `file_ioctl_compat`).

## 32-bit ioctls: `file_ioctl_compat` (lab PR 174)

Upstream commit f1bb47a31dff ("lsm: new security_file_ioctl_compat()
hook", merged for 6.8 and marked for stable) gave the compat `ioctl`
syscall — the one a 32-bit process on a 64-bit kernel calls — its own LSM
hook: `compat_sys_ioctl` (`fs/ioctl.c`) calls
`security_file_ioctl_compat(file, cmd, arg)` where it called
`security_file_ioctl`. A BPF LSM program on `file_ioctl` no longer sees
those calls. Until lab PR 174 the agent had no program on the new hook,
so on such a kernel a 32-bit `chattr` (`FS_IOC32_SETFLAGS`; or
`FS_IOC_FSSETXATTR`, the same number in 32 and 64 bits) of a protected
file was not refused, where the same `chattr` built 64-bit was.

Which kernels have the hook (`include/linux/lsm_hook_defs.h` and
`fs/ioctl.c` of each tag, git.kernel.org stable tree, read on
2026-10-16):

| Series | Without the hook | With the hook |
|---|---|---|
| mainline | 6.7 | 6.8 and later (6.9, 6.12, the WSL2 6.18 host) |
| 6.7.y | 6.7.2 | 6.7.3 |
| 6.6.y | 6.6.14 | 6.6.15 |
| 6.1.y | 6.1.75 | 6.1.76 (Debian 12 ships later 6.1 releases) |
| 5.15.y | 5.15.148 | 5.15.149 |
| 5.10.y | 5.10.209 | 5.10.210 |

A vendor kernel (Ubuntu 22.04's 5.15.0-*, RHEL 9's 5.14.0-*) has it if
its maintainers took the patch: the agent does not go by version
numbers. The hook passes the `cmd` as the caller gave it (the
`FS_IOC32_*` to `FS_IOC_*` translation comes after), with the same
prototype as `file_ioctl`, so `protected_ioctl_compat_deny`
(`agent-ebpf/src/inode_protect.rs`) is the `file_ioctl` deny on another
hook: the same three commands, the same `PROTECTED_INODES` lookup, the
same agent-family and trusted-installer-window exemptions, the same
`ANTI-TAMPER DENIAL op=ioctl` record. 411 BPF instructions in the
object, the `file_ioctl` deny's count; no loop of its own.

It is an **optional deny hook**, like the ACL hooks of 6.2: the agent
attaches it where the running kernel's BTF has
`bpf_lsm_file_ioctl_compat`, and then counts it among the expected deny
hooks — a kernel that has it but does not attach it is a deny-hook
shortfall, which refuses the start unless
`NN_ANTI_TAMPER_ALLOW_DEGRADED=1`. Where the BTF does not have it, nothing
is attached and nothing more is expected: the compat syscall still goes
through `file_ioctl` there. The healthy boot line therefore reads
`deny_attached=N deny_expected=N` with N = 16 required, plus 2 for the
ACL hooks (6.2+), plus 1 for `file_ioctl_compat`:

| Kernel | `deny_expected` |
|---|---|
| 6.8 and later (6.12), 6.7.3+, 6.6.15+ | 19 |
| 6.2 to 6.7 without it (6.6.14, 6.7.2 and older) | 18 |
| 6.1.76+, 5.15.149+ (and a vendor 5.14 / 5.15 with the patch) | 17 |
| 6.1.75 and older, 5.15.148 and older | 16 |

`--btf-check` prints one `optional` line per optional deny hook, present
or absent in the BTF given to it (`optional file_ioctl_compat … present`
on the WSL2 6.18 host, `absent` on the BTFHub Ubuntu 20.04 5.8 kernel), and
its summary counts the hook's `struct file *` argument among the hook
arguments checked where the kernel has it (29 on the 6.18 host).

## Debian-family kernels and `perf_event_paranoid`

Every tracepoint and kprobe sensor attaches through `perf_event_open`.
Upstream (and Ubuntu's own patch, default value 4) accept `CAP_PERFMON`
for that, which is what the hardened unit grants. Debian's kernel patch
makes its default `kernel.perf_event_paranoid=3` demand `CAP_SYS_ADMIN`
instead, so the bounded unit fails with `Permission denied` while the
same binary works as plain root. `install.sh` detects a Debian-family
host (`/etc/os-release`, not Ubuntu) and installs
`northnarrow-agent.service.d/10-debian-perf-paranoid.conf` adding
`CAP_SYS_ADMIN` to the bounding set; the agent's attach error names the
condition and the two remedies (drop-in, or `perf_event_paranoid=2`
system-wide plus removing the drop-in to keep the narrower set). The
agent protects the drop-in like its unit files — removing it takes a
trusted-installer window, and `install.sh` puts it back on a
Debian-family host — and reports one whose content differs from the
shipped file (`integrity_drift`, kind `unit_dropin`).

## How it works, and what still stops a kernel

1. **Resolution.** `common::btf_offsets::REVALIDATE` lists every offset as
   `(struct, field path, alternatives)`; `ENUM_VALUES` lists enumerators.
   `agent::anti_tamper::btf_revalidate::resolve_offsets` parses the live
   BTF (own parser, no `unsafe`, fail-closed on unknown BTF kinds) and
   produces `(slot, value)` pairs; drift from the compiled values is
   logged at INFO (`offset resolved … compiled=… runtime=…`).
2. **Publication.** Right after `EbpfLoader::load` and before any attach,
   the agent writes the values into `BTF_OFFSETS` and arms slot 0 with a
   magic. The eBPF programs read offsets through `off!(NAME)`.
3. **Refusal.** A field or enumerator absent on the running kernel (no
   path and no alternative resolves), or a fixed-position hook argument
   that moved → exit 78 with the field or the hook named. The fix is a
   new alternative path in `REVALIDATE`, or a runtime position in
   `HOOK_ARGS` (level 2 work), never a guess.
4. **Hook prototypes** (lab PR 164). The positions in `HOOK_ARGS` are
   published in the same map, after the tracepoint slots; the programs
   read them with `hook_arg(slot)` (`agent-ebpf/src/btf_offsets.rs`),
   which has no compiled fallback. The argument is read with
   `bpf_probe_read_kernel` from the context (a context load needs a
   constant offset), at a position bounded below 6 first.

Level 2 so far: optional fields (degrade instead of refuse), the
`--btf-check` verdict, the computed BTFHub matrix in CI with a baseline,
a third lab guest (Ubuntu 22.04 / 5.15), a fourth (AlmaLinux 9 / 5.14,
SELinux enforcing) with tracepoint layouts resolved from tracefs.

### Kernel BTF is a hard prerequisite

The BPF LSM programs (the anti-tamper deny hooks, the FIM observers), the
`tcp_close` fexit and every other BTF-typed program attach through the
**kernel's own** BTF object: the kernel resolves their `attach_btf_id`
against `btf_vmlinux`, which exists only when the kernel was built with
`CONFIG_DEBUG_INFO_BTF=y`. Without `/sys/kernel/btf/vmlinux` the agent
refuses to start (review 53). The anti-tamper attach reports it as a
deny-hook shortfall, and only `NN_ANTI_TAMPER_ALLOW_DEGRADED=1` starts a
degraded agent. A mount that hides `/sys/kernel/btf` while the agent runs
is reported as `integrity_drift` (`tamper-check` C26).

**External BTF (BTFHub) — assessed 2026-10-11, not pursued without a
decision.** A BTF file from outside the kernel can feed the userland
offset resolution (`--btf-check` already reads one), but it cannot give
the kernel a `btf_vmlinux`. On a kernel shipped without BTF, no LSM,
fentry/fexit or `tp_btf` program can load, whatever file the agent reads.
External BTF would only serve a **sensor-only** mode: tracepoint and
kprobe telemetry with userland rules, and no anti-tamper. The fail-closed
policy refuses that mode today. The kernels it would add are the BTFHub
entries, kernels shipped without BTF that are mostly older than BPF LSM
(5.7) anyway; every BPF-LSM kernel in the lab matrix ships BTF. If
telemetry from such legacy kernels is ever needed, it should be an
explicit, separately named mode with its own guarantees, not a quiet
fallback.

## btrfs: inode identity follows `stat()` (review 55)

FIM watches files and the anti-tamper protects them by `(dev, ino)`.
Userland computes the key with `stat()`, and the eBPF hooks look it up
from the kernel's inode. On every filesystem but btrfs, `stat()` reports
the superblock's `s_dev`. On btrfs it reports the device of the inode's
subvolume (`btrfs_getattr`), and inode numbers restart in every
subvolume. Until review 55 the eBPF side used `s_dev` everywhere, so on a
host whose files live on btrfs no key ever matched and nothing warned:
FIM missed every file, the deny hooks protected none, and the
executable-inode exemption of the BPF guard never applied.

The eBPF side now computes the key as `stat()` does
(`agent-ebpf/src/inode_dev.rs`). For an inode whose superblock magic is
`BTRFS_SUPER_MAGIC`, it reads `BTRFS_I(inode)->root->anon_dev`. The three
btrfs offsets (`btrfs_inode.root`, `btrfs_inode.vfs_inode`,
`btrfs_root.anon_dev`) come from vmlinux when btrfs is built in (Debian's
cloud kernel). Otherwise they come from the module's split BTF,
`/sys/kernel/btf/btrfs` (Ubuntu), which the resolver reads on top of
vmlinux. When the module is not loaded, nothing
on the host is btrfs: the offsets stay unset, and the verdict is not
degraded (`--btf-check` prints a `module` line).

`deploy/lab/nn-lab.sh btrfs-check` is the regression check. It reads a
watched credential file twice, once on the root filesystem as a control
and once on a btrfs subvolume, and requires NN-L-FIM-011 both times.
Limit: a btrfs filesystem first mounted after the agent started
(module loaded later) keeps the old keys until the agent restarts.

## overlayfs, FUSE and NFS: inode identity unverified (lab PR 189)

btrfs is the only filesystem whose `stat()` the eBPF side reproduces
(`inode_dev::stat_dev`); everywhere else it takes the superblock's `s_dev`
and `i_ino`. On three filesystems that is not known to be the pair
`stat()` gives:

- **overlayfs** (`0x794c7630`): `stat()` reports the device and inode of
  the layer that holds the file (`ovl_getattr`), the hooks see the overlay
  inode;
- **FUSE** (`0x65735546`) and **NFS** (`0x6969`): inode numbers come from
  a daemon or a server, and the file a hook sees can be another inode than
  the one `stat()` named.

A key that does not match fails silently both ways: a protected file is
not denied, a watched one draws no FIM record. The agent does not try to
prove the match in the kernel (a hook writing back what it sees costs
verifier budget on 5.15 for an informational answer). It says where it
cannot vouch: every path it keys by `(dev, ino)` — `PROTECTED_INODES`
entries, FIM watches at boot and enrolled later — is checked with
`statfs()`, and a boot that registered any on one of these filesystems
logs one WARN `inode identity unverified …` and writes one signed
`subsystem_degraded` with `reason: inode_identity_unverified`, the
filesystems, their counts and the first five paths of each (external
audit EBPF-016, NN-AUD-267). A path enrolled after that record, on a
filesystem it did not name, is a WARN. A host with an overlay root (a
container image, a live system) gets this record at every boot: put the
agent's directories and the watched files on a filesystem the hooks key
the same way (ext4, xfs, btrfs), or accept the limit.

`deploy/lab/nn-lab.sh overlay-check` is the regression check, modelled on
`btrfs-check`: a watched credential file on an overlay mount
bind-mounted on `/root/.aws`, an agent restart, one read. NN-L-FIM-011 or
the boot's signed record naming the file must be there; silence fails.

## Tracepoint layouts on vendor kernels (RHEL 9)

Tracepoint programs read their arguments at fixed byte offsets inside the
`TracePointContext`, and those offsets come from tracefs
(`/sys/kernel/tracing/events/<category>/<event>/format`), not from BTF.
The common header is not stable across vendor kernels: RHEL 9 (5.14 el9)
inserts `common_preempt_lazy_count` at offset 8, which moves
`sched_process_exec.filename` from 8 to 12 (syscall tracepoints keep their
argument offsets thanks to 8-byte alignment). With a compiled-in 8 the exec
sensor reported an **empty filename for every exec**, and R017 ("shell
from a non-standard path") killed every `sh` on AlmaLinux 9.

Since lab PR 20 the agent resolves the tracepoint fields it reads
(`TRACEPOINT_FIELDS` in `common/src/btf_offsets.rs`) from tracefs at boot
and publishes them in the same `BTF_OFFSETS` map (slots after the enum
values); drift is logged at INFO (`tracepoint field offset resolved from
tracefs — differs from the build kernel`). If tracefs is unreadable the
compiled value stays and a WARN names the field. Independently, the rules
that match on "not under a standard prefix" (R017, R013) treat an empty
filename as unknown and never fire on it.

## io_uring tracepoints per kernel

The io_uring sensor attaches `io_uring/io_uring_create` and the submit
tracepoint, whose name and layout changed across kernels — resolved at
boot like every other tracepoint field (`TRACEPOINT_FIELDS`, alternative
event name):

| Kernel | submit event | `opcode` offset | `sq_thread` offset |
|---|---|---|---|
| Ubuntu 22.04 / 5.15 | `io_uring_submit_sqe` | 24 | 45 |
| Debian 12 / 6.1 | `io_uring_submit_sqe` | 32 | 41 |
| Ubuntu 24.04 / 6.8 | `io_uring_submit_req` | 32 | 48 |
| AlmaLinux 9 / 5.14 el9 | `io_uring_submit_req` (backported) | 40 | 56 |

A kernel built without `CONFIG_IO_URING` has no such tracepoints: the
agent logs a WARN and runs without the sensor (nothing to observe there).

## Exploit post-condition guard (lab PR 219)

Lite, the default, runs on every kernel of the matrix (BPF LSM, fentry,
`tp_btf`, an LRU task map, `bpf_task_pt_regs`: 5.15 and later). Strict
needs 6.1: its task map is not preallocated, which a raw tracepoint can
use safely only with the BPF memory allocator of 6.1. Before 6.1 the
verifier refuses such a map only on a PREEMPT_RT kernel and loads it
elsewhere with a kernel `WARN`, so the agent checks the version itself:
`--exploit-guard strict` on 5.15 (or on RHEL 9's 5.14, whose backports it
does not detect) leaves the guard `unavailable` with a signed
`subsystem_degraded`; the agent starts. Design:
https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/EXPLOIT_POSTCONDITION_GUARD.md

## DNS sensor: two static kernel functions (Tappa 10.9 step 3)

The DNS sensor hooks `udp_send_skb` and `udp_v6_send_skb`, where the kernel
sends the socket buffer holding its copy of the query. Both are `static`. A
compiler may inline them, or emit a renamed copy (`.isra.0`,
`.constprop.0`) whose arguments differ, so the agent attaches only the
plain names.

Both plain names are present on 5.15, 6.1 and 6.8. To check a kernel:
`grep -E ' udp(_v6)?_send_skb$' /proc/kallsyms`.

- **No `udp_send_skb`:** the agent falls back to the `udp_sendmsg`
  program. That one reads user memory, sees IPv4 only, and is the same as
  `--dns-sensor sendmsg`. The fallback is logged at WARN.
- **No `udp_v6_send_skb`:** IPv4 stays on the socket buffer. Queries to
  IPv6 resolvers are not observed, and a WARN says so.

## Older verifiers (5.15): constructs the eBPF code avoids

The 5.15 verifier rejected the constructs below, which 6.1 and 6.8 accept. All
are now avoided everywhere, and any new eBPF program must keep to the
same rules or the 22.04 guest will refuse to load it:

1. **No BPF-to-BPF subprogram call with a ring-buffer or ctx pointer
   argument.** `core::ptr::write_bytes` on a reserved ring-buffer entry
   compiles to a `memset` subprogram; 5.15 cannot track the pointer type
   across the call and fails with `R1 type=ctx expected=fp`. Entries are
   zeroed inline (`agent-ebpf/src/zero.rs`, volatile stores,
   `#[inline(always)]`).
2. **No variable-length helper read into uninitialised stack.**
   `bpf_probe_read_kernel_buf` with a runtime length into a `MaybeUninit`
   stack buffer fails with `invalid indirect read from stack`. Such reads
   go straight into the ring-buffer entry (the `sched_process_exec`
   filename) or into stack that was zeroed first.
3. **No stack slot that may be read before it is written.** An
   `Option<struct>` argument to an inlined helper was spilled to the
   stack and its payload loads hoisted above the discriminant check;
   5.15 rejects the `None` path with `invalid read from stack` (newer
   verifiers tolerate the read for privileged loaders). `fim_rename_observe`
   now passes an always-initialised `InodeKey` (dev 0 / ino 0 = no
   destination). Prefer plain values over `Option` across inlined calls.
   A tuple of `Option`s matched at once is spilled the same way:
   `inode_dev::stat_dev` read its three btrfs offsets as one tuple, which
   the larger file-open sensor (Tappa 10.9) turned into the same error.
   Consume each optional value with its own `match` and an early return.
4. **No large stack array, even zero-initialised.** `[0u8; 256]` lowers to
   the same `memset` subprogram as rule 1 (`R1 type=ctx expected=fp` from
   a `frame1` that only stores zeroes). String scratch lives in a
   `PerCpuArray<[u8; N]>` map (no zeroing needed: only the bytes a helper
   wrote are read); a small key that must be zero is written with
   volatile stores into a `MaybeUninit` (`bpf_defense::obj_get_names_own_link`).
5. **No subtraction on a value that then indexes map memory.** `n - 32`
   with `n` from a helper gives `R4 min value is negative` even behind an
   `if n > 32` (the compiler emits a select, the verifier keeps the
   unconditional range). Index with loop counters bounded by constants and
   move the arithmetic to a user pointer (a second `bpf_probe_read_user_str`
   from `ptr + n - 32` is a plain scalar add).
6. **Mind the state budget.** A loop of 17 helper reads accumulating a
   length, followed by two 32-step loops, exceeded the 1M-instruction
   verification limit on 5.15 (`BPF program is too large`, 29k states) where
   6.8 converges; and a 256-step byte scan over a stack buffer kept the 5.15
   verifier busy for minutes (the agent looked hung at boot). Keep loops
   short, constant-bounded and few per program. Test builds write a
   rejected program's verifier log to `/run/northnarrow/verifier-<program>.log`.
   When a loop must stay, move it into a global BPF function: an
   `#[no_mangle] #[inline(never)] pub extern "C" fn` with integer
   arguments only, which bpf-linker keeps as `linkage=global` in the BTF.
   The verifier checks it once, on its own, and the caller sees one
   unknown return value. The file-open sensor's eight-level ancestor walk
   (`open_sensor::nn_open_walk`, sixteen levels since lab PR 137) took
   `fim_file_open_sensor` from over 1M instructions to loading on 5.15.
   Since lab PR 137 its write-open counts (`nn_open_count_write`) and its
   record writer (`nn_open_emit`, whose sixteen-slot path walk inline was
   verified once per state reaching it) are global functions too: 834,000
   processed instructions on 5.15 became 463,000. A global function takes
   no BTF-typed hook argument ("R4 is not a scalar"): pass a value read
   through `bpf_probe_read_kernel`. Rule 1 still applies: kernel
   addresses go in as `u64`, never as pointers.
7. **Keep map-derived and helper-derived values out of a scalar that a
   later branch tests.** On 5.15 a branch whose outcome the verifier knows
   marks the tested register precise back to its sources; a class bit
   from `DIR_CLASS` folded into the open sensor's `reason`, before a test
   of another `reason` bit, made the class bits precise and the states
   stopped merging: over 1M instructions from one line (lab PR 137). An
   unknown folded into it (a global function's result) keeps alive the
   paths that would have returned at `reason == 0`. Count such values
   elsewhere (a map, a separate record) or store them only. The budget is
   cumulative across the program and its global functions; measure it on
   the 22.04 guest with `bpftrace` on `do_check_common`
   (`((struct bpf_verifier_env *)arg0)->insn_processed` at return) —
   aya's own log stops at 16 MB, before the verdict.
8. **Bound any offset added to or subtracted from a hook argument** (all
   kernels, 6.8 included). An LSM hook's `struct inode *` argument is a
   BTF-typed pointer. `inode - off` with `off` read from `BTF_OFFSETS` (a
   full `u32`) fails with `value -4294967295 makes trusted_ptr_ pointer be
   out of bounds`. Mask the offset first (`off & 0xffff`, as
   `inode_dev::stat_dev` does for btrfs' `container_of`) or work on a
   pointer obtained through `bpf_probe_read_kernel`, which is a plain
   scalar.
9. **No BPF-to-BPF call that a precision mark can reach (5.15 and 6.1).**
   Up to 6.3 the verifier cannot follow a precision mark back across a
   subprogram call: the first branch whose outcome it knows past such a
   call marks every scalar of every state precise, and states stop
   merging. The calls nobody wrote count too. `bpf_get_current_comm()`
   zero-initialises a 16-byte stack array, which compiles to the `memset`
   subprogram: lab PR 219's exploit guard went from a few thousand
   instructions on 6.8 to the 1M-instruction limit on 6.1 that way. Read
   `comm` with `agent-ebpf/src/comm.rs` (`comm_into` writes it straight
   into a ring record zeroed before: 6.1's helper leaves the bytes after
   the name's NUL unwritten). Check an object with `llvm-objdump -dr
   --disassemble-symbols=<program>`: no `R_BPF_64_32 memset`.
10. **Fewer ways through the program (5.15 and 6.1).** Every branch the
    verifier cannot prove one-sided doubles the paths after it until they
    merge again, and these verifiers merge fewer. In the exploit guard:
    a read whose failure means 0 anyway uses the helper's own zeroing
    (`epg::peek`, no branch on its result); a task's record is looked up
    once per run, not again inside a shared helper; a finding goes
    straight into the ring record (`epg::emit_change`), with no struct
    of 160 bytes on the stack, its words copied with volatile stores (an
    assignment between two raw places compiles to rule 9's `memmove`
    subprogram): lite's `commit_creds` program was at 512 of 512 bytes
    and 802,000 instructions, 384 bytes and 5,400 after, and its use
    points took 113,000 with that `memmove`, 2,800 without; the
    allowed-transition verdict is one load from a table built
    at compile time (`epg::ALLOWED_TABLE`), not a `match` whose arms the
    verifier walked one by one. Measure with `deploy/lab/nn-lab.sh
    verifier-check` (every program through the guest's verifier with the
    agent's own loader setup: OK or REFUSED, instructions processed on
    6.1 and later, stack per frame and per call chain); keep every
    program well under the limit on 6.1, which reports the count (5.15
    does not; there, rule 7's `bpftrace` measure).

Lab notes for 22.04-era userland:

- sudo 1.9.9 does not relay a signal sent by a process in its own process
  group, so the e2e fixtures signal every pid of the sudo subtree
  themselves (`agent/tests/common/mod.rs::quit_agent`, the watchdog
  `E2eFixture`) instead of relying on the relay sudo 1.9.15 (24.04) does.
- the 5.15 bpftool (`linux-tools-$(uname -r)`) prints the 15-byte kernel
  program name (`ptrace_access_c`), not the full BTF function name; tests
  that look programs up by name accept both.
- never probe signal behaviour with `cmd &` in a non-interactive shell:
  bash starts background jobs with SIGINT and SIGQUIT ignored.
- systemd 249 (22.04) knows `systemctl kill --kill-who=`, not the newer
  `--kill-whom=` spelling; the lab uses the old one, accepted by both.
- RHEL-family sudo sets `HOME=/root` (`always_set_home`), so the root `cargo test`
  of the lab's privileged suites resolves root's own rustup and downloads a
  second toolchain on first use; harmless, just slow once.

## Adding a distro to the lab

`NN_LAB_DISTRO=<name> deploy/lab/nn-lab.sh up` boots a separate guest
(own disk, seed, ssh port, reports under `~/.cache/nn-lab/<name>/`);
every sub-command honours the variable. Each distro has a cloud-init
template (`deploy/lab/user-data.<name>.tmpl`) and an entry in the
`case "$DISTRO"` block of `nn-lab.sh` (image URL, default port). Run
`check` first: it prints kernel, LSM list, bpffs, iptables, bpftool and
cargo, and exits non-zero on a missing prerequisite.
