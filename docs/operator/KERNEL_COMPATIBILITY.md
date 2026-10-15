# Kernel / distribution compatibility

NorthNarrow's kernel half (eBPF LSM hooks and sensors) reads kernel
structures through byte offsets. Since multi-kernel level 1 those offsets
are **resolved at boot from the running kernel's BTF**
(`/sys/kernel/btf/vmlinux`) and handed to the eBPF programs through the
`BTF_OFFSETS` map before anything attaches; the values compiled into the
object are only the fallback for an unarmed map. Fields that moved
between kernel versions have alternative paths (`iov_iter` on ≤ 6.3 vs
6.4+), and enumerators that changed value are resolved by name too
(`ITER_UBUF`). The agent still **refuses to start** when a field or
enumerator does not exist at all on the running kernel (BUG-036
fail-closed gate, exit 78) — so the support status stays binary and
verifiable: either every read resolves, or the agent does not run.

## Verified matrix (lab, `deploy/lab/nn-lab.sh`)

| Distribution | Kernel | BPF LSM | BTF | Status | Verified |
|---|---|---|---|---|---|
| Ubuntu 24.04 LTS | 6.8.0-142-generic | needs `lsm=…,bpf` (grub) | yes | **supported** — full nightly green (e2e, ignored suites, install, upgrade, uninstall, respawn); offsets match the build (41/41, 0 drift) | 2026-10-09 |
| Debian 12 (bookworm) | 6.1.0-53-cloud-amd64 | yes (default list includes `bpf`) | yes | **supported** — full suites green (e2e, detection, canary, net, honeypot, FIM, map pinning) with 20 of 42 offsets resolved differently from the build, `iov_iter` via alternative paths, `ITER_UBUF` = 6, QNAME via `ITER_IOVEC`. Under the systemd unit the agent needs `CAP_SYS_ADMIN` (Debian's `perf_event_paranoid=3` patch); `install.sh` adds it through a drop-in on Debian-family hosts | 2026-10-09 |
| Ubuntu 22.04 LTS | 5.15.0-198-generic | needs `lsm=…,bpf` (grub) | yes | **supported (degraded)** — all 27 programs and the 8 FIM observe hooks load and attach after three rewrites for the older verifier (see below); 5.15 has no `ITER_UBUF` / `iov_iter.ubuf`, so the DNS QNAME is decoded through the `ITER_IOVEC` path only (`--btf-check` says `SUPPORTED (degraded)`); e2e + ignored suites green | 2026-10-10 (lab PR 17) |
| AlmaLinux 9 (RHEL / Rocky 9 family) | 5.14.0-687 el9_8 | yes (default list includes `bpf`) | yes | **supported** — e2e agent 6/6, FIM 4/4, watchdog 4/4 with SELinux **enforcing** (no AVC denial); `--btf-check` = SUPPORTED, 0 absent (RHEL backports `iov_iter.ubuf`); the vendor tracepoint header (`common_preempt_lazy_count`) is handled by resolving tracepoint field offsets from tracefs at boot (see below) | 2026-10-10 (lab PR 20) |

Prerequisites common to every row: `CONFIG_DEBUG_INFO_BTF=y` (the
`/sys/kernel/btf/vmlinux` file), `bpf` in `/sys/kernel/security/lsm`,
bpffs mounted at `/sys/fs/bpf`, `iptables-restore` (nft backend is fine),
x86_64. See `docs/TAPPA7_PREREQ.md` for the grub step.

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
demand, and fails on a verdict worse than the baseline or on a BTF the
parser cannot read. BTFHub archives only kernels shipped **without**
native BTF, so the lab guests (table above) cover 5.15, 6.1 and 6.8.

| Source | Kernel | BPF LSM | Verdict | Notes |
|---|---|---|---|---|
| WSL2 (host) | 6.18 | — | SUPPORTED | 16 of 44 slots differ from the build kernel — handled at runtime |
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
   path and no alternative resolves) → exit 78 with the field named. The
   fix is a new alternative path in `REVALIDATE` (level 2 work), never a
   guess.

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
- RHEL-family sudo sets `HOME=/root` (`always_set_home`), so `sudo -E cargo`
  resolves root's own rustup and downloads a second toolchain on first
  use; harmless, just slow once.

## Adding a distro to the lab

`NN_LAB_DISTRO=<name> deploy/lab/nn-lab.sh up` boots a separate guest
(own disk, seed, ssh port, reports under `~/.cache/nn-lab/<name>/`);
every sub-command honours the variable. Each distro has a cloud-init
template (`deploy/lab/user-data.<name>.tmpl`) and an entry in the
`case "$DISTRO"` block of `nn-lab.sh` (image URL, default port). Run
`check` first: it prints kernel, LSM list, bpffs, iptables, bpftool and
cargo, and exits non-zero on a missing prerequisite.
