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
| Ubuntu 22.04 LTS | 5.15 | needs `lsm=…,bpf` | yes | untested — expected to resolve like Debian 12 (`iov_iter` has no `ubuf` before 6.0: the DNS QNAME copy would be refused unless a third variant is added) | — |
| RHEL / Alma / Rocky 9 | 5.14 + backports | needs `lsm=…,bpf` | yes | untested — same note as 22.04 | — |

Prerequisites common to every row: `CONFIG_DEBUG_INFO_BTF=y` (the
`/sys/kernel/btf/vmlinux` file), `bpf` in `/sys/kernel/security/lsm`,
bpffs mounted at `/sys/fs/bpf`, `iptables-restore` (nft backend is fine),
x86_64. See `docs/TAPPA7_PREREQ.md` for the grub step.

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

What level 2 adds, in order: a computed matrix over BTFHub's archive of
distribution kernels in CI (which fields resolve where, before any guest
boots), further alternatives for the fields the matrix flags, external
BTF for kernels shipped without it, a third lab guest (Alma 9).

## Adding a distro to the lab

`NN_LAB_DISTRO=<name> deploy/lab/nn-lab.sh up` boots a separate guest
(own disk, seed, ssh port, reports under `~/.cache/nn-lab/<name>/`);
every sub-command honours the variable. Each distro has a cloud-init
template (`deploy/lab/user-data.<name>.tmpl`) and an entry in the
`case "$DISTRO"` block of `nn-lab.sh` (image URL, default port). Run
`check` first: it prints kernel, LSM list, bpffs, iptables, bpftool and
cargo, and exits non-zero on a missing prerequisite.
