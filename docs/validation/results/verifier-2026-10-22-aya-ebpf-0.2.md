# aya-ebpf 0.2.1: the eBPF object through four verifiers (lab PR 233)

Lab PR 233 (D1b of the Wave 4 phase 2 dependency plan) builds the eBPF
programs with aya-ebpf 0.2.1 instead of 0.1.1, with the same
`nightly-2025-12-01` and bpf-linker 0.10.3 (aya-build held at 0.2.0). The
source changes are mechanical, but the generated code is not the same in
48 of the 96 BPF functions. This file is the evidence that the new object
still keeps the rules of
[`KERNEL_COMPATIBILITY.md`](../../operator/KERNEL_COMPATIBILITY.md)
("Older verifiers") and still loads everywhere `main`'s does.

- **main**: `a9d65ab`, object sha256 `e5a83897…` (aya-ebpf 0.1.1).
- **branch**: `deps/w4-aya-ebpf-0.2`, object sha256 `8333a443…`
  (aya-ebpf 0.2.1), built on the host from the lot's tree.
- Lab: our own QEMU for Windows guests with WHPX, 4 vCPU, 7 GiB, on
  2026-10-22.

## Static check of the two objects

`llvm-objdump -dr` of both objects and a parse of their ELF symbols,
relocations and BTF (`FUNC` linkage, `FUNC_PROTO` parameters):

| | main | branch |
|---|---:|---:|
| BPF functions (programs) | 96 (76) | 96 (76) |
| functions whose bytes differ from main | — | 48 (36 change size) |
| static instructions | 60,997 | 60,615 (−382) |
| `R_BPF_64_32` calls to `memset` / `memmove` / `memcpy` / `memcmp` | 71 / 0 / 0 / 1 | 71 / 0 / 0 / 1 |
| programs that reach a `memset` subprogram | 42 | the same 42 |
| `memset` in an `epg_*`, `exec_check_lsm`, `fim_file_open_sensor` or `fim_rename_observe` | none | none |
| global functions (BTF `linkage=global`, outside the programs) | 16, every argument `u64` | the same 16, every argument `u64` |
| static subprograms other than `mem*` | none | none |
| CO-RE relocations (`.BTF.ext`) | none | none |
| `maps`, `license`, `.rodata` sections | — | byte-identical |

The call targets of every function (`R_BPF_64_32`) are the same in both
objects, function for function. The changed code comes from aya-ebpf
itself. `ProbeContext::arg` now reads `pt_regs` straight from the context
instead of calling `bpf_probe_read`, so the network kprobes are 31–51
instructions shorter. The changed helper signatures (`i32` return codes,
`read_at` through `bpf_probe_read_kernel`) also change the code of every
`epg_*` program, `exec_check_lsm` and `fim_file_open_sensor`.

## Method

On each guest the branch's lab build was installed (`nn-lab.sh sync` and
`install`). `nn-lab.sh verifier-check` then ran twice: once on the
embedded object (the branch's) and once on `main`'s object, copied over
the synced object (`verifier-check synced`). Both runs use the same agent
binary, so the loader setup is the same and only the object differs.
Nothing is attached.

- **Processed instructions on 5.16 and later:** `verified_insns` from
  `bpf_prog_info`.
- **Processed instructions on 5.15:** that kernel does not report them,
  so `bpftrace` hooks `do_check_common` and reads `env->insn_processed`
  at its return. Only the verifier-check process's own loads count (not
  the agent's restart after the check). Each load is counted once, at
  its largest value, which covers the program and its global functions.

The ABSENT programs are the optional `inode_set_acl` and
`inode_remove_acl` deny hooks, which kernels before 6.2 do not have.

Flags:
- ⚠ loads on `main`, not on the branch;
- ▲ processed instructions up more than 20 %;
- ● 750,000 or more processed instructions (within 25 % of the 1M limit).

## Summary

- Ubuntu 22.04 (5.15.0-198-generic): main 74 OK, 2 ABSENT; branch 74 OK, 2 ABSENT; processed in total 1,670,537 → 1,650,981 (-1.2 %); largest rise module_read_file_observe +9.3 %; flags: none
- Debian 12 (6.1.0-54-cloud-amd64): main 74 OK, 2 ABSENT; branch 74 OK, 2 ABSENT; processed in total 1,344,125 → 1,326,525 (-1.3 %); largest rise module_read_file_observe +9.3 %; flags: none
- Ubuntu 24.04 (6.8.0-147-generic): main 76 OK; branch 76 OK; processed in total 898,196 → 897,597 (-0.1 %); largest rise udpv6_sendmsg_outbound +15.8 %; flags: none
- Debian 13 (6.12.113+deb13-cloud-amd64): main 76 OK; branch 76 OK; processed in total 914,070 → 911,541 (-0.3 %); largest rise epg_sys_enter +1.7 %; flags: none

The `probe_*` programs are lab-only sensor-feasibility probes: the agent never loads them.

## Ubuntu 22.04 — kernel 5.15.0-198-generic

- main (synced, e5a83897…): 74 OK, 2 ABSENT
- branch (embedded, 8333a443…): 74 OK, 2 ABSENT
- processed, programs counted on both: main 1,670,537, branch 1,650,981 (-1.2 %)
- largest on the branch: fim_file_open_sensor 483,485, exec_check_lsm 288,811, execmap_check 240,363, probe_file_open 108,358, execpol_env_execveat 100,005
- largest rise: module_read_file_observe 12,099 → 13,220 (+9.3 %)
- flagged: none

| program | section | result main / branch | processed main / branch | Δ | stack frame/chain main → branch | flag |
|---|---|---|---:|---:|---|---|
| bpf_map_guard | lsm/bpf_map | OK / OK | 1,945 / 1,945 | +0.0 % | 72/128 → 72/128 |  |
| bpf_syscall_observe | lsm/bpf | OK / OK | 5,597 / 5,585 | -0.2 % | 40/128 → 48/128 |  |
| dns_udp_send_skb | kprobe | OK / OK | 4,357 / 4,460 | +2.4 % | 136/192 → 112/160 |  |
| dns_udp_v6_send_skb | kprobe | OK / OK | 4,357 / 4,460 | +2.4 % | 136/192 → 112/160 |  |
| epg_chroot_fs_refs | fentry/chroot_fs_refs | OK / OK | 24 / 24 | +0.0 % | 8/32 → 8/32 |  |
| epg_commit_creds | fentry/commit_creds | OK / OK | 2,308 / 2,316 | +0.3 % | 272/288 → 280/288 |  |
| epg_lite_capable | lsm/capable | OK / OK | 2,920 / 2,937 | +0.6 % | 280/288 → 280/288 |  |
| epg_lite_commit_creds | fentry/commit_creds | OK / OK | 5,654 / 5,585 | -1.2 % | 376/384 → 376/384 |  |
| epg_lite_exec | lsm/bprm_check_security | OK / OK | 2,920 / 2,937 | +0.6 % | 280/288 → 280/288 |  |
| epg_lite_file_open | lsm/file_open | OK / OK | 5,832 / 5,852 | +0.3 % | 288/288 → 288/288 |  |
| epg_lite_fork | tp_btf/sched_process_fork | OK / OK | 167 / 148 | -11.4 % | 192/192 → 168/192 |  |
| epg_lite_set_fs_root | fentry/set_fs_root | OK / OK | 2,060 / 2,061 | +0.0 % | 176/192 → 176/192 |  |
| epg_lite_switch_ns | fentry/switch_task_namespaces | OK / OK | 2,746 / 2,737 | -0.3 % | 264/288 → 272/288 |  |
| epg_lite_task_exit | tp_btf/sched_process_exit | OK / OK | 8 / 8 | +0.0 % | 8/32 → 8/32 |  |
| epg_set_fs_root | fentry/set_fs_root | OK / OK | 1,628 / 1,636 | +0.5 % | 216/224 → 216/224 |  |
| epg_switch_ns | fentry/switch_task_namespaces | OK / OK | 1,673 / 1,682 | +0.5 % | 240/256 → 240/256 |  |
| epg_sys_enter | raw_tp/sys_enter | OK / OK | 2,560 / 2,480 | -3.1 % | 344/352 → 360/384 |  |
| epg_sys_exit | raw_tp/sys_exit | OK / OK | 6,917 / 7,071 | +2.2 % | 400/416 → 392/416 |  |
| epg_task_exit | raw_tp/sched_process_exit | OK / OK | 8 / 8 | +0.0 % | 8/32 → 8/32 |  |
| exec_check_lsm | lsm/bprm_check_security | OK / OK | 288,804 / 288,811 | +0.0 % | 160/256 → 160/256 |  |
| execmap_check | lsm/mmap_file | OK / OK | 240,363 / 240,363 | +0.0 % | 112/224 → 112/224 |  |
| execpol_env_execve | tracepoint | OK / OK | 100,005 / 100,005 | +0.0 % | 88/160 → 88/160 |  |
| execpol_env_execveat | tracepoint | OK / OK | 100,005 / 100,005 | +0.0 % | 88/160 → 88/160 |  |
| file_ioctl | lsm/file_ioctl | OK / OK | 702 / 702 | +0.0 % | 80/128 → 80/128 |  |
| fim_close_emit_observe | lsm/file_free_security | OK / OK | 464 / 464 | +0.0 % | 64/64 → 64/64 |  |
| fim_create_observe | lsm/inode_create | OK / OK | 627 / 627 | +0.0 % | 56/64 → 56/64 |  |
| fim_file_cap_observe | lsm/inode_post_setxattr | OK / OK | 7,992 / 7,992 | +0.0 % | 88/160 → 88/160 |  |
| fim_file_open_observe | lsm/file_open | OK / OK | 643 / 644 | +0.2 % | 72/96 → 72/96 |  |
| fim_file_open_sensor | lsm/file_open | OK / OK | 483,599 / 483,485 | -0.0 % | 184/352 → 184/352 |  |
| fim_link_observe | lsm/inode_link | OK / OK | 944 / 944 | +0.0 % | 56/64 → 56/64 |  |
| fim_rename_observe | lsm/inode_rename | OK / OK | 65,285 / 65,286 | +0.0 % | 112/288 → 112/288 |  |
| fim_setattr_observe | lsm/inode_setattr | OK / OK | 507 / 508 | +0.2 % | 48/64 → 48/64 |  |
| fim_unlink_observe | lsm/inode_unlink | OK / OK | 8,740 / 8,740 | +0.0 % | 64/192 → 64/192 |  |
| fim_write_intent_observe | lsm/file_permission | OK / OK | 641 / 641 | +0.0 % | 88/128 → 88/128 |  |
| inet_csk_listen_start | kprobe | OK / OK | 3,683 / 3,475 | -5.6 % | 232/288 → 232/288 |  |
| inode_rename | lsm/inode_rename | OK / OK | 2,786 / 2,786 | +0.0 % | 88/128 → 88/128 |  |
| inode_rmdir | lsm/inode_rmdir | OK / OK | 1,369 / 1,369 | +0.0 % | 88/128 → 88/128 |  |
| inode_setattr | lsm/inode_setattr | OK / OK | 776 / 776 | +0.0 % | 80/128 → 80/128 |  |
| inode_unlink | lsm/inode_unlink | OK / OK | 1,369 / 1,369 | +0.0 % | 88/128 → 88/128 |  |
| io_uring_create | tracepoint | OK / OK | 2,942 / 2,942 | +0.0 % | 64/96 → 64/96 |  |
| io_uring_submit | tracepoint | OK / OK | 7,341 / 6,368 | -13.3 % | 56/96 → 56/96 |  |
| module_load_data_observe | lsm/kernel_load_data | OK / OK | 974 / 959 | -1.5 % | 48/96 → 48/96 |  |
| module_read_file_observe | lsm/kernel_read_file | OK / OK | 12,099 / 13,220 | +9.3 % | 88/128 → 88/128 |  |
| open_sensor_rmdir | lsm/inode_rmdir | OK / OK | 459 / 459 | +0.0 % | 48/64 → 48/64 |  |
| probe_bprm | lsm/bprm_check_security | OK / OK | 14,199 / 14,219 | +0.1 % | 104/160 → 112/160 |  |
| probe_fexit_ip6_make_skb | fexit/ip6_make_skb | OK / OK | 2 / 2 | +0.0 % | 0/32 → 0/32 |  |
| probe_fexit_ip_make_skb | fexit/ip_make_skb | OK / OK | 2 / 2 | +0.0 % | 0/32 → 0/32 |  |
| probe_file_open | lsm/file_open | OK / OK | 115,372 / 108,358 | -6.1 % | 96/128 → 104/160 |  |
| probe_ip6_make_skb | kretprobe | OK / OK | 947 / 949 | +0.2 % | 80/128 → 72/128 |  |
| probe_ip_make_skb | kretprobe | OK / OK | 947 / 949 | +0.2 % | 80/128 → 72/128 |  |
| probe_udp_send_skb | kprobe | OK / OK | 939 / 960 | +2.2 % | 80/128 → 64/96 |  |
| protected_create_deny | lsm/inode_create | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| protected_ioctl_compat_deny | lsm/file_ioctl_compat | OK / OK | 702 / 702 | +0.0 % | 80/128 → 80/128 |  |
| protected_link_deny | lsm/inode_link | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| protected_mkdir_deny | lsm/inode_mkdir | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| protected_mknod_deny | lsm/inode_mknod | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| protected_open_deny | lsm/file_open | OK / OK | 1,520 / 1,520 | +0.0 % | 80/128 → 80/128 |  |
| protected_remove_acl_deny | lsm/inode_remove_acl | ABSENT / ABSENT | n/a / n/a |  | - → - |  |
| protected_removexattr_deny | lsm/inode_removexattr | OK / OK | 927 / 927 | +0.0 % | 88/128 → 88/128 |  |
| protected_set_acl_deny | lsm/inode_set_acl | ABSENT / ABSENT | n/a / n/a |  | - → - |  |
| protected_setxattr_deny | lsm/inode_setxattr | OK / OK | 927 / 927 | +0.0 % | 88/128 → 88/128 |  |
| protected_symlink_deny | lsm/inode_symlink | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| ptrace_access_check | lsm/ptrace_access_check | OK / OK | 1,680 / 1,653 | -1.6 % | 96/128 → 96/128 |  |
| role_exit | raw_tp/sched_process_exit | OK / OK | 50 / 50 | +0.0 % | 4/32 → 4/32 |  |
| sched_process_exec | tracepoint | OK / OK | 5,864 / 5,887 | +0.4 % | 96/192 → 104/224 |  |
| sched_process_exec_nostdio | tracepoint | OK / OK | 3,315 / 3,338 | +0.7 % | 96/96 → 104/128 |  |
| socket_connect_deny | lsm/socket_connect | OK / OK | 602 / 436 | -27.6 % | 64/64 → 64/64 |  |
| sys_enter_execve | tracepoint | OK / OK | 970 / 944 | -2.7 % | 80/128 → 88/128 |  |
| sys_enter_openat | tracepoint | OK / OK | 584 / 558 | -4.5 % | 80/128 → 88/128 |  |
| task_kill | lsm/task_kill | OK / OK | 8,910 / 8,882 | -0.3 % | 120/192 → 120/192 |  |
| tcp_close | fexit/tcp_close | OK / OK | 10,601 / 9,501 | -10.4 % | 408/448 → 408/448 |  |
| tcp_v4_connect | kprobe | OK / OK | 853 / 451 | -47.1 % | 152/192 → 144/192 |  |
| tcp_v6_connect | kprobe | OK / OK | 905 / 495 | -45.3 % | 256/288 → 240/288 |  |
| udp_sendmsg | kprobe | OK / OK | 34,588 / 25,505 | -26.3 % | 96/128 → 104/160 |  |
| udp_sendmsg_outbound | kprobe | OK / OK | 28,382 / 27,565 | -2.9 % | 312/352 → 312/352 |  |
| udpv6_sendmsg_outbound | kprobe | OK / OK | 46,689 / 46,069 | -1.3 % | 328/384 → 312/352 |  |

## Debian 12 — kernel 6.1.0-54-cloud-amd64

- main (synced, e5a83897…): 74 OK, 2 ABSENT
- branch (embedded, 8333a443…): 74 OK, 2 ABSENT
- processed, programs counted on both: main 1,344,125, branch 1,326,525 (-1.3 %)
- largest on the branch: fim_file_open_sensor 300,387, exec_check_lsm 284,246, execmap_check 233,850, probe_file_open 84,770, fim_rename_observe 64,186
- largest rise: module_read_file_observe 12,099 → 13,220 (+9.3 %)
- flagged: none

| program | section | result main / branch | processed main / branch | Δ | stack frame/chain main → branch | flag |
|---|---|---|---:|---:|---|---|
| bpf_map_guard | lsm/bpf_map | OK / OK | 1,319 / 1,319 | +0.0 % | 72/128 → 72/128 |  |
| bpf_syscall_observe | lsm/bpf | OK / OK | 5,626 / 5,614 | -0.2 % | 40/128 → 48/128 |  |
| dns_udp_send_skb | kprobe | OK / OK | 3,885 / 3,979 | +2.4 % | 136/192 → 112/160 |  |
| dns_udp_v6_send_skb | kprobe | OK / OK | 3,885 / 3,979 | +2.4 % | 136/192 → 112/160 |  |
| epg_chroot_fs_refs | fentry/chroot_fs_refs | OK / OK | 24 / 24 | +0.0 % | 8/32 → 8/32 |  |
| epg_commit_creds | fentry/commit_creds | OK / OK | 2,308 / 2,316 | +0.3 % | 272/288 → 280/288 |  |
| epg_lite_capable | lsm/capable | OK / OK | 2,695 / 2,712 | +0.6 % | 280/288 → 280/288 |  |
| epg_lite_commit_creds | fentry/commit_creds | OK / OK | 5,440 / 5,323 | -2.2 % | 376/384 → 376/384 |  |
| epg_lite_exec | lsm/bprm_check_security | OK / OK | 2,695 / 2,712 | +0.6 % | 280/288 → 280/288 |  |
| epg_lite_file_open | lsm/file_open | OK / OK | 5,601 / 5,622 | +0.4 % | 288/288 → 288/288 |  |
| epg_lite_fork | tp_btf/sched_process_fork | OK / OK | 167 / 148 | -11.4 % | 192/192 → 168/192 |  |
| epg_lite_set_fs_root | fentry/set_fs_root | OK / OK | 2,060 / 2,061 | +0.0 % | 176/192 → 176/192 |  |
| epg_lite_switch_ns | fentry/switch_task_namespaces | OK / OK | 2,494 / 2,484 | -0.4 % | 264/288 → 272/288 |  |
| epg_lite_task_exit | tp_btf/sched_process_exit | OK / OK | 8 / 8 | +0.0 % | 8/32 → 8/32 |  |
| epg_set_fs_root | fentry/set_fs_root | OK / OK | 1,350 / 1,358 | +0.6 % | 216/224 → 216/224 |  |
| epg_switch_ns | fentry/switch_task_namespaces | OK / OK | 1,391 / 1,400 | +0.6 % | 240/256 → 240/256 |  |
| epg_sys_enter | raw_tp/sys_enter | OK / OK | 2,560 / 2,480 | -3.1 % | 344/352 → 360/384 |  |
| epg_sys_exit | raw_tp/sys_exit | OK / OK | 6,917 / 6,943 | +0.4 % | 400/416 → 392/416 |  |
| epg_task_exit | raw_tp/sched_process_exit | OK / OK | 8 / 8 | +0.0 % | 8/32 → 8/32 |  |
| exec_check_lsm | lsm/bprm_check_security | OK / OK | 284,239 / 284,246 | +0.0 % | 160/256 → 160/256 |  |
| execmap_check | lsm/mmap_file | OK / OK | 233,850 / 233,850 | +0.0 % | 112/224 → 112/224 |  |
| execpol_env_execve | tracepoint | OK / OK | 61,658 / 61,658 | +0.0 % | 88/160 → 88/160 |  |
| execpol_env_execveat | tracepoint | OK / OK | 61,658 / 61,658 | +0.0 % | 88/160 → 88/160 |  |
| file_ioctl | lsm/file_ioctl | OK / OK | 702 / 702 | +0.0 % | 80/128 → 80/128 |  |
| fim_close_emit_observe | lsm/file_free_security | OK / OK | 464 / 464 | +0.0 % | 64/64 → 64/64 |  |
| fim_create_observe | lsm/inode_create | OK / OK | 627 / 627 | +0.0 % | 56/64 → 56/64 |  |
| fim_file_cap_observe | lsm/inode_post_setxattr | OK / OK | 7,992 / 7,992 | +0.0 % | 88/160 → 88/160 |  |
| fim_file_open_observe | lsm/file_open | OK / OK | 643 / 644 | +0.2 % | 72/96 → 72/96 |  |
| fim_file_open_sensor | lsm/file_open | OK / OK | 300,702 / 300,387 | -0.1 % | 184/352 → 184/352 |  |
| fim_link_observe | lsm/inode_link | OK / OK | 895 / 895 | +0.0 % | 56/64 → 56/64 |  |
| fim_rename_observe | lsm/inode_rename | OK / OK | 64,185 / 64,186 | +0.0 % | 112/288 → 112/288 |  |
| fim_setattr_observe | lsm/inode_setattr | OK / OK | 507 / 508 | +0.2 % | 48/64 → 48/64 |  |
| fim_unlink_observe | lsm/inode_unlink | OK / OK | 8,631 / 8,631 | +0.0 % | 64/192 → 64/192 |  |
| fim_write_intent_observe | lsm/file_permission | OK / OK | 641 / 641 | +0.0 % | 88/128 → 88/128 |  |
| inet_csk_listen_start | kprobe | OK / OK | 3,683 / 3,475 | -5.6 % | 232/288 → 232/288 |  |
| inode_rename | lsm/inode_rename | OK / OK | 2,674 / 2,674 | +0.0 % | 88/128 → 88/128 |  |
| inode_rmdir | lsm/inode_rmdir | OK / OK | 1,331 / 1,331 | +0.0 % | 88/128 → 88/128 |  |
| inode_setattr | lsm/inode_setattr | OK / OK | 776 / 776 | +0.0 % | 80/128 → 80/128 |  |
| inode_unlink | lsm/inode_unlink | OK / OK | 1,331 / 1,331 | +0.0 % | 88/128 → 88/128 |  |
| io_uring_create | tracepoint | OK / OK | 2,942 / 2,942 | +0.0 % | 64/96 → 64/96 |  |
| io_uring_submit | tracepoint | OK / OK | 7,341 / 6,368 | -13.3 % | 56/96 → 56/96 |  |
| module_load_data_observe | lsm/kernel_load_data | OK / OK | 974 / 959 | -1.5 % | 48/96 → 48/96 |  |
| module_read_file_observe | lsm/kernel_read_file | OK / OK | 12,099 / 13,220 | +9.3 % | 88/128 → 88/128 |  |
| open_sensor_rmdir | lsm/inode_rmdir | OK / OK | 459 / 459 | +0.0 % | 48/64 → 48/64 |  |
| probe_bprm | lsm/bprm_check_security | OK / OK | 14,199 / 14,219 | +0.1 % | 104/160 → 112/160 |  |
| probe_fexit_ip6_make_skb | fexit/ip6_make_skb | OK / OK | 2 / 2 | +0.0 % | 0/32 → 0/32 |  |
| probe_fexit_ip_make_skb | fexit/ip_make_skb | OK / OK | 2 / 2 | +0.0 % | 0/32 → 0/32 |  |
| probe_file_open | lsm/file_open | OK / OK | 84,709 / 84,770 | +0.1 % | 96/128 → 104/160 |  |
| probe_ip6_make_skb | kretprobe | OK / OK | 947 / 949 | +0.2 % | 80/128 → 72/128 |  |
| probe_ip_make_skb | kretprobe | OK / OK | 947 / 949 | +0.2 % | 80/128 → 72/128 |  |
| probe_udp_send_skb | kprobe | OK / OK | 939 / 960 | +2.2 % | 80/128 → 64/96 |  |
| protected_create_deny | lsm/inode_create | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| protected_ioctl_compat_deny | lsm/file_ioctl_compat | OK / OK | 702 / 702 | +0.0 % | 80/128 → 80/128 |  |
| protected_link_deny | lsm/inode_link | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| protected_mkdir_deny | lsm/inode_mkdir | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| protected_mknod_deny | lsm/inode_mknod | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| protected_open_deny | lsm/file_open | OK / OK | 1,520 / 1,520 | +0.0 % | 80/128 → 80/128 |  |
| protected_remove_acl_deny | lsm/inode_remove_acl | ABSENT / ABSENT | n/a / n/a |  | - → - |  |
| protected_removexattr_deny | lsm/inode_removexattr | OK / OK | 927 / 927 | +0.0 % | 88/128 → 88/128 |  |
| protected_set_acl_deny | lsm/inode_set_acl | ABSENT / ABSENT | n/a / n/a |  | - → - |  |
| protected_setxattr_deny | lsm/inode_setxattr | OK / OK | 927 / 927 | +0.0 % | 88/128 → 88/128 |  |
| protected_symlink_deny | lsm/inode_symlink | OK / OK | 652 / 652 | +0.0 % | 80/128 → 80/128 |  |
| ptrace_access_check | lsm/ptrace_access_check | OK / OK | 1,140 / 1,126 | -1.2 % | 96/128 → 96/128 |  |
| role_exit | raw_tp/sched_process_exit | OK / OK | 50 / 50 | +0.0 % | 4/32 → 4/32 |  |
| sched_process_exec | tracepoint | OK / OK | 4,847 / 4,869 | +0.5 % | 96/192 → 104/224 |  |
| sched_process_exec_nostdio | tracepoint | OK / OK | 2,298 / 2,320 | +1.0 % | 96/96 → 104/128 |  |
| socket_connect_deny | lsm/socket_connect | OK / OK | 602 / 436 | -27.6 % | 64/64 → 64/64 |  |
| sys_enter_execve | tracepoint | OK / OK | 970 / 944 | -2.7 % | 80/128 → 88/128 |  |
| sys_enter_openat | tracepoint | OK / OK | 584 / 558 | -4.5 % | 80/128 → 88/128 |  |
| task_kill | lsm/task_kill | OK / OK | 8,421 / 8,407 | -0.2 % | 120/192 → 120/192 |  |
| tcp_close | fexit/tcp_close | OK / OK | 7,793 / 6,821 | -12.5 % | 408/448 → 408/448 |  |
| tcp_v4_connect | kprobe | OK / OK | 853 / 451 | -47.1 % | 152/192 → 144/192 |  |
| tcp_v6_connect | kprobe | OK / OK | 905 / 495 | -45.3 % | 256/288 → 240/288 |  |
| udp_sendmsg | kprobe | OK / OK | 25,935 / 17,028 | -34.3 % | 96/128 → 104/160 |  |
| udp_sendmsg_outbound | kprobe | OK / OK | 28,181 / 23,705 | -15.9 % | 312/352 → 312/352 |  |
| udpv6_sendmsg_outbound | kprobe | OK / OK | 41,028 / 39,014 | -4.9 % | 328/384 → 312/352 |  |

## Ubuntu 24.04 — kernel 6.8.0-147-generic

- main (synced, e5a83897…): 76 OK
- branch (embedded, 8333a443…): 76 OK
- processed, programs counted on both: main 898,196, branch 897,597 (-0.1 %)
- largest on the branch: execmap_check 233,791, exec_check_lsm 176,382, fim_rename_observe 127,746, fim_file_open_sensor 102,852, execpol_env_execveat 61,647
- largest rise: udpv6_sendmsg_outbound 5,702 → 6,604 (+15.8 %)
- flagged: none

| program | section | result main / branch | processed main / branch | Δ | stack frame/chain main → branch | flag |
|---|---|---|---:|---:|---|---|
| bpf_map_guard | lsm/bpf_map | OK / OK | 1,120 / 1,120 | +0.0 % | 72/128 → 72/128 |  |
| bpf_syscall_observe | lsm/bpf | OK / OK | 2,976 / 2,977 | +0.0 % | 40/128 → 48/128 |  |
| dns_udp_send_skb | kprobe | OK / OK | 1,045 / 1,045 | +0.0 % | 136/192 → 112/160 |  |
| dns_udp_v6_send_skb | kprobe | OK / OK | 1,045 / 1,045 | +0.0 % | 136/192 → 112/160 |  |
| epg_chroot_fs_refs | fentry/chroot_fs_refs | OK / OK | 24 / 24 | +0.0 % | 8/32 → 8/32 |  |
| epg_commit_creds | fentry/commit_creds | OK / OK | 1,684 / 1,698 | +0.8 % | 272/288 → 280/288 |  |
| epg_lite_capable | lsm/capable | OK / OK | 1,786 / 1,735 | -2.9 % | 280/288 → 280/288 |  |
| epg_lite_commit_creds | fentry/commit_creds | OK / OK | 2,638 / 2,511 | -4.8 % | 376/384 → 376/384 |  |
| epg_lite_exec | lsm/bprm_check_security | OK / OK | 1,786 / 1,735 | -2.9 % | 280/288 → 280/288 |  |
| epg_lite_file_open | lsm/file_open | OK / OK | 2,018 / 2,003 | -0.7 % | 288/288 → 288/288 |  |
| epg_lite_fork | tp_btf/sched_process_fork | OK / OK | 166 / 147 | -11.4 % | 192/192 → 168/192 |  |
| epg_lite_set_fs_root | fentry/set_fs_root | OK / OK | 604 / 605 | +0.2 % | 176/192 → 176/192 |  |
| epg_lite_switch_ns | fentry/switch_task_namespaces | OK / OK | 1,246 / 1,205 | -3.3 % | 264/288 → 272/288 |  |
| epg_lite_task_exit | tp_btf/sched_process_exit | OK / OK | 8 / 8 | +0.0 % | 8/32 → 8/32 |  |
| epg_set_fs_root | fentry/set_fs_root | OK / OK | 742 / 751 | +1.2 % | 216/224 → 216/224 |  |
| epg_switch_ns | fentry/switch_task_namespaces | OK / OK | 773 / 783 | +1.3 % | 240/256 → 240/256 |  |
| epg_sys_enter | raw_tp/sys_enter | OK / OK | 1,195 / 1,191 | -0.3 % | 344/352 → 360/384 |  |
| epg_sys_exit | raw_tp/sys_exit | OK / OK | 5,967 / 5,594 | -6.3 % | 400/416 → 392/416 |  |
| epg_task_exit | raw_tp/sched_process_exit | OK / OK | 8 / 8 | +0.0 % | 8/32 → 8/32 |  |
| exec_check_lsm | lsm/bprm_check_security | OK / OK | 176,347 / 176,382 | +0.0 % | 160/256 → 160/256 |  |
| execmap_check | lsm/mmap_file | OK / OK | 233,791 / 233,791 | +0.0 % | 112/224 → 112/224 |  |
| execpol_env_execve | tracepoint | OK / OK | 61,647 / 61,647 | +0.0 % | 88/160 → 88/160 |  |
| execpol_env_execveat | tracepoint | OK / OK | 61,647 / 61,647 | +0.0 % | 88/160 → 88/160 |  |
| file_ioctl | lsm/file_ioctl | OK / OK | 701 / 701 | +0.0 % | 80/128 → 80/128 |  |
| fim_close_emit_observe | lsm/file_free_security | OK / OK | 464 / 464 | +0.0 % | 64/64 → 64/64 |  |
| fim_create_observe | lsm/inode_create | OK / OK | 619 / 619 | +0.0 % | 56/64 → 56/64 |  |
| fim_file_cap_observe | lsm/inode_post_setxattr | OK / OK | 7,542 / 7,542 | +0.0 % | 88/160 → 88/160 |  |
| fim_file_open_observe | lsm/file_open | OK / OK | 606 / 607 | +0.2 % | 72/96 → 72/96 |  |
| fim_file_open_sensor | lsm/file_open | OK / OK | 102,959 / 102,852 | -0.1 % | 184/352 → 184/352 |  |
| fim_link_observe | lsm/inode_link | OK / OK | 891 / 891 | +0.0 % | 56/64 → 56/64 |  |
| fim_rename_observe | lsm/inode_rename | OK / OK | 127,223 / 127,746 | +0.4 % | 112/288 → 112/288 |  |
| fim_setattr_observe | lsm/inode_setattr | OK / OK | 507 / 508 | +0.2 % | 48/64 → 48/64 |  |
| fim_unlink_observe | lsm/inode_unlink | OK / OK | 8,056 / 8,056 | +0.0 % | 64/192 → 64/192 |  |
| fim_write_intent_observe | lsm/file_permission | OK / OK | 640 / 640 | +0.0 % | 88/128 → 88/128 |  |
| inet_csk_listen_start | kprobe | OK / OK | 1,233 / 1,155 | -6.3 % | 232/288 → 232/288 |  |
| inode_rename | lsm/inode_rename | OK / OK | 2,630 / 2,630 | +0.0 % | 88/128 → 88/128 |  |
| inode_rmdir | lsm/inode_rmdir | OK / OK | 1,315 / 1,315 | +0.0 % | 88/128 → 88/128 |  |
| inode_setattr | lsm/inode_setattr | OK / OK | 777 / 777 | +0.0 % | 80/128 → 80/128 |  |
| inode_unlink | lsm/inode_unlink | OK / OK | 1,315 / 1,315 | +0.0 % | 88/128 → 88/128 |  |
| io_uring_create | tracepoint | OK / OK | 587 / 587 | +0.0 % | 64/96 → 64/96 |  |
| io_uring_submit | tracepoint | OK / OK | 520 / 516 | -0.8 % | 56/96 → 56/96 |  |
| module_load_data_observe | lsm/kernel_load_data | OK / OK | 774 / 759 | -1.9 % | 48/96 → 48/96 |  |
| module_read_file_observe | lsm/kernel_read_file | OK / OK | 12,122 / 11,271 | -7.0 % | 88/128 → 88/128 |  |
| open_sensor_rmdir | lsm/inode_rmdir | OK / OK | 399 / 399 | +0.0 % | 48/64 → 48/64 |  |
| probe_bprm | lsm/bprm_check_security | OK / OK | 7,981 / 8,001 | +0.3 % | 104/160 → 112/160 |  |
| probe_fexit_ip6_make_skb | fexit/ip6_make_skb | OK / OK | 2 / 2 | +0.0 % | 0/32 → 0/32 |  |
| probe_fexit_ip_make_skb | fexit/ip_make_skb | OK / OK | 2 / 2 | +0.0 % | 0/32 → 0/32 |  |
| probe_file_open | lsm/file_open | OK / OK | 12,862 / 12,896 | +0.3 % | 96/128 → 104/160 |  |
| probe_ip6_make_skb | kretprobe | OK / OK | 571 / 573 | +0.4 % | 80/128 → 72/128 |  |
| probe_ip_make_skb | kretprobe | OK / OK | 571 / 573 | +0.4 % | 80/128 → 72/128 |  |
| probe_udp_send_skb | kprobe | OK / OK | 600 / 609 | +1.5 % | 80/128 → 64/96 |  |
| protected_create_deny | lsm/inode_create | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| protected_ioctl_compat_deny | lsm/file_ioctl_compat | OK / OK | 701 / 701 | +0.0 % | 80/128 → 80/128 |  |
| protected_link_deny | lsm/inode_link | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| protected_mkdir_deny | lsm/inode_mkdir | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| protected_mknod_deny | lsm/inode_mknod | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| protected_open_deny | lsm/file_open | OK / OK | 1,514 / 1,514 | +0.0 % | 80/128 → 80/128 |  |
| protected_remove_acl_deny | lsm/inode_remove_acl | OK / OK | 864 / 864 | +0.0 % | 88/128 → 88/128 |  |
| protected_removexattr_deny | lsm/inode_removexattr | OK / OK | 928 / 928 | +0.0 % | 88/128 → 88/128 |  |
| protected_set_acl_deny | lsm/inode_set_acl | OK / OK | 864 / 864 | +0.0 % | 88/128 → 88/128 |  |
| protected_setxattr_deny | lsm/inode_setxattr | OK / OK | 928 / 928 | +0.0 % | 88/128 → 88/128 |  |
| protected_symlink_deny | lsm/inode_symlink | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| ptrace_access_check | lsm/ptrace_access_check | OK / OK | 937 / 923 | -1.5 % | 96/128 → 96/128 |  |
| role_exit | raw_tp/sched_process_exit | OK / OK | 50 / 50 | +0.0 % | 4/32 → 4/32 |  |
| sched_process_exec | tracepoint | OK / OK | 3,571 / 3,592 | +0.6 % | 96/192 → 104/224 |  |
| sched_process_exec_nostdio | tracepoint | OK / OK | 2,002 / 2,023 | +1.0 % | 96/96 → 104/128 |  |
| socket_connect_deny | lsm/socket_connect | OK / OK | 369 / 349 | -5.4 % | 64/64 → 64/64 |  |
| sys_enter_execve | tracepoint | OK / OK | 917 / 889 | -3.1 % | 80/128 → 88/128 |  |
| sys_enter_openat | tracepoint | OK / OK | 537 / 509 | -5.2 % | 80/128 → 88/128 |  |
| task_kill | lsm/task_kill | OK / OK | 7,647 / 7,633 | -0.2 % | 120/192 → 120/192 |  |
| tcp_close | fexit/tcp_close | OK / OK | 5,542 / 5,324 | -3.9 % | 408/448 → 408/448 |  |
| tcp_v4_connect | kprobe | OK / OK | 759 / 404 | -46.8 % | 152/192 → 144/192 |  |
| tcp_v6_connect | kprobe | OK / OK | 720 / 379 | -47.4 % | 256/288 → 240/288 |  |
| udp_sendmsg | kprobe | OK / OK | 1,644 / 1,595 | -3.0 % | 96/128 → 104/160 |  |
| udp_sendmsg_outbound | kprobe | OK / OK | 3,983 / 4,581 | +15.0 % | 312/352 → 312/352 |  |
| udpv6_sendmsg_outbound | kprobe | OK / OK | 5,702 / 6,604 | +15.8 % | 328/384 → 312/352 |  |

## Debian 13 — kernel 6.12.113+deb13-cloud-amd64

- main (synced, e5a83897…): 76 OK
- branch (embedded, 8333a443…): 76 OK
- processed, programs counted on both: main 914,070, branch 911,541 (-0.3 %)
- largest on the branch: execmap_check 237,151, exec_check_lsm 214,811, fim_rename_observe 126,874, fim_file_open_sensor 83,582, execpol_env_execveat 61,647
- largest rise: epg_sys_enter 1,455 → 1,480 (+1.7 %)
- flagged: none

| program | section | result main / branch | processed main / branch | Δ | stack frame/chain main → branch | flag |
|---|---|---|---:|---:|---|---|
| bpf_map_guard | lsm/bpf_map | OK / OK | 1,120 / 1,120 | +0.0 % | 72/128 → 72/128 |  |
| bpf_syscall_observe | lsm/bpf | OK / OK | 2,976 / 2,977 | +0.0 % | 40/128 → 48/128 |  |
| dns_udp_send_skb | kprobe | OK / OK | 1,045 / 1,045 | +0.0 % | 136/192 → 112/160 |  |
| dns_udp_v6_send_skb | kprobe | OK / OK | 1,045 / 1,045 | +0.0 % | 136/192 → 112/160 |  |
| epg_chroot_fs_refs | fentry/chroot_fs_refs | OK / OK | 24 / 24 | +0.0 % | 8/32 → 8/32 |  |
| epg_commit_creds | fentry/commit_creds | OK / OK | 1,684 / 1,698 | +0.8 % | 272/288 → 280/288 |  |
| epg_lite_capable | lsm/capable | OK / OK | 1,786 / 1,735 | -2.9 % | 280/288 → 280/288 |  |
| epg_lite_commit_creds | fentry/commit_creds | OK / OK | 2,638 / 2,511 | -4.8 % | 376/384 → 376/384 |  |
| epg_lite_exec | lsm/bprm_check_security | OK / OK | 1,786 / 1,735 | -2.9 % | 280/288 → 280/288 |  |
| epg_lite_file_open | lsm/file_open | OK / OK | 2,018 / 2,003 | -0.7 % | 288/288 → 288/288 |  |
| epg_lite_fork | tp_btf/sched_process_fork | OK / OK | 166 / 147 | -11.4 % | 192/192 → 168/192 |  |
| epg_lite_set_fs_root | fentry/set_fs_root | OK / OK | 604 / 605 | +0.2 % | 176/192 → 176/192 |  |
| epg_lite_switch_ns | fentry/switch_task_namespaces | OK / OK | 1,246 / 1,205 | -3.3 % | 264/288 → 272/288 |  |
| epg_lite_task_exit | tp_btf/sched_process_exit | OK / OK | 8 / 8 | +0.0 % | 8/32 → 8/32 |  |
| epg_set_fs_root | fentry/set_fs_root | OK / OK | 742 / 751 | +1.2 % | 216/224 → 216/224 |  |
| epg_switch_ns | fentry/switch_task_namespaces | OK / OK | 773 / 783 | +1.3 % | 240/256 → 240/256 |  |
| epg_sys_enter | raw_tp/sys_enter | OK / OK | 1,455 / 1,480 | +1.7 % | 344/352 → 360/384 |  |
| epg_sys_exit | raw_tp/sys_exit | OK / OK | 5,963 / 5,639 | -5.4 % | 400/416 → 392/416 |  |
| epg_task_exit | raw_tp/sched_process_exit | OK / OK | 8 / 8 | +0.0 % | 8/32 → 8/32 |  |
| exec_check_lsm | lsm/bprm_check_security | OK / OK | 214,804 / 214,811 | +0.0 % | 160/256 → 160/256 |  |
| execmap_check | lsm/mmap_file | OK / OK | 237,151 / 237,151 | +0.0 % | 112/224 → 112/224 |  |
| execpol_env_execve | tracepoint | OK / OK | 61,647 / 61,647 | +0.0 % | 88/160 → 88/160 |  |
| execpol_env_execveat | tracepoint | OK / OK | 61,647 / 61,647 | +0.0 % | 88/160 → 88/160 |  |
| file_ioctl | lsm/file_ioctl | OK / OK | 701 / 701 | +0.0 % | 80/128 → 80/128 |  |
| fim_close_emit_observe | lsm/file_free_security | OK / OK | 464 / 464 | +0.0 % | 64/64 → 64/64 |  |
| fim_create_observe | lsm/inode_create | OK / OK | 619 / 619 | +0.0 % | 56/64 → 56/64 |  |
| fim_file_cap_observe | lsm/inode_post_setxattr | OK / OK | 7,946 / 7,946 | +0.0 % | 88/160 → 88/160 |  |
| fim_file_open_observe | lsm/file_open | OK / OK | 595 / 595 | +0.0 % | 72/96 → 72/96 |  |
| fim_file_open_sensor | lsm/file_open | OK / OK | 83,716 / 83,582 | -0.2 % | 184/352 → 184/352 |  |
| fim_link_observe | lsm/inode_link | OK / OK | 891 / 891 | +0.0 % | 56/64 → 56/64 |  |
| fim_rename_observe | lsm/inode_rename | OK / OK | 126,873 / 126,874 | +0.0 % | 112/288 → 112/288 |  |
| fim_setattr_observe | lsm/inode_setattr | OK / OK | 507 / 508 | +0.2 % | 48/64 → 48/64 |  |
| fim_unlink_observe | lsm/inode_unlink | OK / OK | 8,460 / 8,460 | +0.0 % | 64/192 → 64/192 |  |
| fim_write_intent_observe | lsm/file_permission | OK / OK | 640 / 640 | +0.0 % | 88/128 → 88/128 |  |
| inet_csk_listen_start | kprobe | OK / OK | 883 / 832 | -5.8 % | 232/288 → 232/288 |  |
| inode_rename | lsm/inode_rename | OK / OK | 2,630 / 2,630 | +0.0 % | 88/128 → 88/128 |  |
| inode_rmdir | lsm/inode_rmdir | OK / OK | 1,315 / 1,315 | +0.0 % | 88/128 → 88/128 |  |
| inode_setattr | lsm/inode_setattr | OK / OK | 777 / 777 | +0.0 % | 80/128 → 80/128 |  |
| inode_unlink | lsm/inode_unlink | OK / OK | 1,315 / 1,315 | +0.0 % | 88/128 → 88/128 |  |
| io_uring_create | tracepoint | OK / OK | 587 / 587 | +0.0 % | 64/96 → 64/96 |  |
| io_uring_submit | tracepoint | OK / OK | 520 / 516 | -0.8 % | 56/96 → 56/96 |  |
| module_load_data_observe | lsm/kernel_load_data | OK / OK | 774 / 759 | -1.9 % | 48/96 → 48/96 |  |
| module_read_file_observe | lsm/kernel_read_file | OK / OK | 12,122 / 11,271 | -7.0 % | 88/128 → 88/128 |  |
| open_sensor_rmdir | lsm/inode_rmdir | OK / OK | 399 / 399 | +0.0 % | 48/64 → 48/64 |  |
| probe_bprm | lsm/bprm_check_security | OK / OK | 7,980 / 8,000 | +0.3 % | 104/160 → 112/160 |  |
| probe_fexit_ip6_make_skb | fexit/ip6_make_skb | OK / OK | 2 / 2 | +0.0 % | 0/32 → 0/32 |  |
| probe_fexit_ip_make_skb | fexit/ip_make_skb | OK / OK | 2 / 2 | +0.0 % | 0/32 → 0/32 |  |
| probe_file_open | lsm/file_open | OK / OK | 12,871 / 12,905 | +0.3 % | 96/128 → 104/160 |  |
| probe_ip6_make_skb | kretprobe | OK / OK | 571 / 573 | +0.4 % | 80/128 → 72/128 |  |
| probe_ip_make_skb | kretprobe | OK / OK | 571 / 573 | +0.4 % | 80/128 → 72/128 |  |
| probe_udp_send_skb | kprobe | OK / OK | 600 / 609 | +1.5 % | 80/128 → 64/96 |  |
| protected_create_deny | lsm/inode_create | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| protected_ioctl_compat_deny | lsm/file_ioctl_compat | OK / OK | 701 / 701 | +0.0 % | 80/128 → 80/128 |  |
| protected_link_deny | lsm/inode_link | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| protected_mkdir_deny | lsm/inode_mkdir | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| protected_mknod_deny | lsm/inode_mknod | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| protected_open_deny | lsm/file_open | OK / OK | 1,514 / 1,514 | +0.0 % | 80/128 → 80/128 |  |
| protected_remove_acl_deny | lsm/inode_remove_acl | OK / OK | 864 / 864 | +0.0 % | 88/128 → 88/128 |  |
| protected_removexattr_deny | lsm/inode_removexattr | OK / OK | 928 / 928 | +0.0 % | 88/128 → 88/128 |  |
| protected_set_acl_deny | lsm/inode_set_acl | OK / OK | 864 / 864 | +0.0 % | 88/128 → 88/128 |  |
| protected_setxattr_deny | lsm/inode_setxattr | OK / OK | 928 / 928 | +0.0 % | 88/128 → 88/128 |  |
| protected_symlink_deny | lsm/inode_symlink | OK / OK | 657 / 657 | +0.0 % | 80/128 → 80/128 |  |
| ptrace_access_check | lsm/ptrace_access_check | OK / OK | 937 / 923 | -1.5 % | 96/128 → 96/128 |  |
| role_exit | raw_tp/sched_process_exit | OK / OK | 50 / 50 | +0.0 % | 4/32 → 4/32 |  |
| sched_process_exec | tracepoint | OK / OK | 3,571 / 3,592 | +0.6 % | 96/192 → 104/224 |  |
| sched_process_exec_nostdio | tracepoint | OK / OK | 2,002 / 2,023 | +1.0 % | 96/96 → 104/128 |  |
| socket_connect_deny | lsm/socket_connect | OK / OK | 369 / 371 | +0.5 % | 64/64 → 64/64 |  |
| sys_enter_execve | tracepoint | OK / OK | 917 / 889 | -3.1 % | 80/128 → 88/128 |  |
| sys_enter_openat | tracepoint | OK / OK | 483 / 455 | -5.8 % | 80/128 → 88/128 |  |
| task_kill | lsm/task_kill | OK / OK | 8,051 / 8,037 | -0.2 % | 120/192 → 120/192 |  |
| tcp_close | fexit/tcp_close | OK / OK | 1,245 / 1,200 | -3.6 % | 408/448 → 408/448 |  |
| tcp_v4_connect | kprobe | OK / OK | 759 / 404 | -46.8 % | 152/192 → 144/192 |  |
| tcp_v6_connect | kprobe | OK / OK | 720 / 379 | -47.4 % | 256/288 → 240/288 |  |
| udp_sendmsg | kprobe | OK / OK | 1,644 / 1,595 | -3.0 % | 96/128 → 104/160 |  |
| udp_sendmsg_outbound | kprobe | OK / OK | 3,280 / 3,268 | -0.4 % | 312/352 → 312/352 |  |
| udpv6_sendmsg_outbound | kprobe | OK / OK | 3,291 / 3,151 | -4.3 % | 328/384 → 312/352 |  |
