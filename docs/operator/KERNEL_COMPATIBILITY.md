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
| RHEL / Alma / Rocky 9 | 5.14 + backports | needs `lsm=…,bpf` | yes | untested — same note as 22.04 | — |

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
system-wide plus removing the drop-in to keep the narrower set).

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
a third lab guest (Ubuntu 22.04 / 5.15). Still planned: external BTF for
kernels shipped without it, an Alma 9 guest.

## Older verifiers (5.15): constructs the eBPF code avoids

The 5.15 verifier rejected three constructs that 6.1 and 6.8 accept. Both
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

## Adding a distro to the lab

`NN_LAB_DISTRO=<name> deploy/lab/nn-lab.sh up` boots a separate guest
(own disk, seed, ssh port, reports under `~/.cache/nn-lab/<name>/`);
every sub-command honours the variable. Each distro has a cloud-init
template (`deploy/lab/user-data.<name>.tmpl`) and an entry in the
`case "$DISTRO"` block of `nn-lab.sh` (image URL, default port). Run
`check` first: it prints kernel, LSM list, bpffs, iptables, bpftool and
cargo, and exits non-zero on a missing prerequisite.
