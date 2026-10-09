# Kernel / distribution compatibility

NorthNarrow's kernel half (eBPF LSM hooks and sensors) reads kernel
structures through **fixed byte offsets** compiled into the eBPF object
(`common::btf_offsets`, 41 offsets). At boot the agent re-derives every
offset from the running kernel's BTF (`/sys/kernel/btf/vmlinux`) and
**refuses to start** on any mismatch (BUG-036 fail-closed gate, exit 78)
rather than attach hooks that read the wrong memory. That makes the
support status binary and verifiable: either every offset matches, or the
agent does not run.

## Verified matrix (lab, `deploy/lab/nn-lab.sh`)

| Distribution | Kernel | BPF LSM | BTF | Status | Verified |
|---|---|---|---|---|---|
| Ubuntu 24.04 LTS | 6.8.0-142-generic | needs `lsm=…,bpf` (grub) | yes | **supported** — full nightly green (e2e, ignored suites, install, upgrade, uninstall, respawn) | 2026-10-09 |
| Debian 12 (bookworm) | 6.1.0-53-cloud-amd64 | yes (default list includes `bpf`) | yes | **not yet** — agent refuses to start: 20 of 41 offsets differ (`task_struct`, `mm_struct`, `inode`, `file`, `tcp_sock`, `iov_iter`); the fail-closed gate works as designed, the product does not run | 2026-10-09 |
| Ubuntu 22.04 LTS | 5.15 | needs `lsm=…,bpf` | yes | untested (expected: same as Debian 12) | — |
| RHEL / Alma / Rocky 9 | 5.14 + backports | needs `lsm=…,bpf` | yes | untested (expected: same as Debian 12) | — |

Prerequisites common to every row: `CONFIG_DEBUG_INFO_BTF=y` (the
`/sys/kernel/btf/vmlinux` file), `bpf` in `/sys/kernel/security/lsm`,
bpffs mounted at `/sys/fs/bpf`, `iptables-restore` (nft backend is fine),
x86_64. See `docs/TAPPA7_PREREQ.md` for the grub step.

## Why one kernel, and the way out

aya-ebpf 0.1 emits no CO-RE field relocations, so the offsets are
constants. Two ways to support more than one kernel build:

1. **Runtime offsets (recommended).** The agent already resolves every
   offset from the live BTF to validate it; write the resolved values
   into a small BPF array map before attaching, and have the eBPF
   programs read offsets from that map instead of constants. Same
   fail-closed behaviour when a field is missing, one eBPF object for
   every kernel whose structs carry the fields, no toolchain change.
   Review entry 27 tracks this.
2. **One eBPF object per kernel family**, built against each kernel's
   BTF and selected at boot by `uname -r`. Simpler code, but every new
   distro kernel needs a build and a package update.

## Adding a distro to the lab

`NN_LAB_DISTRO=<name> deploy/lab/nn-lab.sh up` boots a separate guest
(own disk, seed, ssh port, reports under `~/.cache/nn-lab/<name>/`);
every sub-command honours the variable. Each distro has a cloud-init
template (`deploy/lab/user-data.<name>.tmpl`) and an entry in the
`case "$DISTRO"` block of `nn-lab.sh` (image URL, default port). Run
`check` first: it prints kernel, LSM list, bpffs, iptables, bpftool and
cargo, and exits non-zero on a missing prerequisite.
