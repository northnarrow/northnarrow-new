# aya-ebpf 0.3 and rustc 1.99's LLVM 22: the eBPF object through five verifiers (lot 1.2)

Lot 1.2 (stage S1, the old 400b) builds the eBPF programs with aya-ebpf
0.3.0 (aya-ebpf-bindings 0.3, aya-ebpf-cty 0.4, aya-ebpf-macros 0.4) and
aya-build 0.2.1 instead of 0.2.1 and 0.2.0. Both need rustc 1.98, so the
eBPF crate's nightly moves from `nightly-2025-12-01` (rustc 1.93, LLVM
21.1.5) to `nightly-2026-08-05` (rustc 1.99, LLVM 22.1.8), with the same
bpf-linker 0.10.3. The source change for aya-ebpf 0.3 is one: a map key
by reference. `fork_parent.rs` also drops two `unsafe` blocks around
`ctx.arg`, which was a safe function in aya-ebpf 0.2.1 already (they were
the build's two `unused_unsafe` warnings). The code LLVM 22 generates from
the same source is not the same, and four programs no longer loaded. This
file is the evidence that the new object keeps the rules of
[`KERNEL_COMPATIBILITY.md`](../../operator/KERNEL_COMPATIBILITY.md)
("Older verifiers") and loads everywhere `main`'s does, within the
verifier budget.

- **main**: `358ecf54` (after #617), object sha256 `4be2def0…`
  (aya-ebpf 0.2.1, `nightly-2025-12-01`).
- **branch**: `deps/aya-ebpf-0.3`, object sha256 `d9f2ae7e…`
  (aya-ebpf 0.3.0, `nightly-2026-08-05`), built on the host from the lot's
  tree.
- Lab: our own QEMU for Windows guests with WHPX, on 2026-11-25.

## The compiler: LLVM 22, not LLVM 23

`nightly-2026-08-05` is the last nightly before rustc moved to LLVM 23
(rust-lang/rust#158734, merged that day). bpf-linker 0.10.3 links with
rustc's own LLVM through its `rust-llvm-22` proxy: no system LLVM on the
runners or in the lab, and the bpf-linker every workflow already pins. A
nightly with LLVM 23 needs bpf-linker 0.11 or later, built against a system
LLVM 23 (apt.llvm.org's packages on every runner, a third party in every
build), and its own round on the five kernels. LLVM 22 is the smaller step,
and the one CI reproduces with what it installs today. The fuzz job already
builds with this nightly (lot 400a): one channel, one download.

## What LLVM 22 changed, and the fixes

`main`'s source built with the new toolchain (the object `13f828ec…`,
measured in the same round as the others: `v0` below) is refused on all
five kernels, four programs each, and over the budget on 5.15. Two
functions of that source carry a back-edge the 5.15 and 6.1 verifiers
reject (the old lot 400's WIP fixed them; they are the same after #617).
`mount_guard_move_mount`, over a million on 5.15 in that WIP, is within the
budget after #617's split.

| where | kernel | the verifier's refusal | what LLVM 22 did | the fix |
|---|---|---|---|---|
| `sched_process_exec`, `sched_process_exec_nostdio` (`main.rs`) | all five | `R1 min value is outside of the allowed memory range` (a 65,535-byte read into a 256-byte field) | the clamp of the filename's length tested on the whole `__data_loc` word (`data_loc > 0x100ffff`), the size shifted out of another copy | the length through `opaque::opaque`, then the clamp: the test is on the register the size is taken from |
| `exec_check_lsm`, `execmap_check` (`execq::level_name`) | all five (`exec_check_lsm`: 5.15, 6.1) | `math between map_value pointer and register with unbounded min value` | the callers' `levels` in 2..=64 tested on a copy (`levels - 2 > 62`), and the `& 63` / `& 15` masks dropped as redundant | `level` through `opaque::opaque`: both masks stay, on the register of the slot's offset |
| `exec_check_lsm` (`exec_lsm.rs`) | 6.8, 6.12, 7.0 | `At program exit the register R0 has smax=… should have been in [-4095, 0]` | the policy's verdict folded into `-(deny & 1) & -EACCES`, which 6.12's verifier reads as any value | the verdict through `opaque::lsm_ret`: brought into `[-4095, 0]` on the register returned (0 and `-EACCES` come out as they went in), failing closed: a positive value, which no path returns, is `-EACCES` (it was 0 before the review of #618) |
| `cgroup_join_mark` (`cgroup_join::exempt_destination`) | 5.15 | 987,382 instructions, over the 900,000 budget (207,446 on `main`) | each of a byte's three ways through the path walk laid out with its own copy of the loop's bound test, the last component's lookup moved into the loop's exit | the walk is a global function, `nn_cgroup_exempt_walk` (rule 6), checked once on its own; its verdict comes back through the buffer's first 8 bytes, so a hash of 0 stays a hash |
| `common::mount_guard::allowed_kernel_mount`, `umount_below` | 5.15, 6.1 (`check_cfg`) | a fall-through back-edge (`no_function_has_a_back_edge_the_5_15_verifier_rejects`) | the loop's latch laid out above the header it fell through into | the list walked from its end, and the bound's test closing the loop: the same verdicts |

`opaque::opaque` is a volatile read of a local, as `dns_answer` and
`inode_protect` already did by hand: the value reloaded from the stack is
one the compiler knows nothing about. `xtask/tests/ebpf_barriers.rs` reads
the three sites and allows no other hand-written barrier.

Two record writers also read the task's `comm` straight into their zeroed
ring record (`comm::comm_into`) instead of `bpf_get_current_comm()`, whose
zeroed stack array is a `memset` subprogram (rule 9): `emit_module_load`
and `inode_protect::emit_denial`. `module_read_file_observe` had five
inlined copies; with LLVM 22 it went from 459,242 instructions on 5.15 to
560,828, now 509,683.

## Static check of the two objects

| | main | branch |
|---|---:|---:|
| BPF functions (programs) | 198 (128) | 199 (128) |
| static instructions | 148,229 | 141,710 (−6,519) |
| `R_BPF_64_32` calls to `memset` / `memmove` / `memcmp` | 244 / 1 / 1 | 99 / 1 / 1 |
| global functions (BTF `linkage=global`) | 57 | 58 (`nn_cgroup_exempt_walk`) |
| functions whose size changed | — | 157 of 199 |

## Method

On each guest the branch's lab build was installed (`nn-lab.sh sync` and
`build`). `nn-lab.sh verifier-check synced` then ran twice with the same
agent binary: once with `main`'s object copied over the synced one, once
with the branch's. The loader setup is the same; only the object differs.
Nothing is attached. Processed instructions: `verified_insns` from
`bpf_prog_info` from 5.16 on; on 5.15 the kprobe on
`check_max_stack_depth` (lot 332). The count covers the program and its
global functions. The budget is 900,000 of the verifier's million; the S1
gate is 80 % of it (720,000) on 5.15 and 6.1, and a stack chain of at most
448 of 512 bytes.

## Results

| kernel | programs | OK main → branch | refused main → branch | processed, all programs (main → branch) | highest (branch) | programs that grew > 1 % | largest stack chain (branch) |
|---|---:|---:|---:|---:|---|---:|---:|
| 5.15 (`5.15.0-204-generic`) | 128 | 121 → 121 | 0 → 0 | 4,396,598 → 4,103,678 (-6.7 %) | `module_read_file_observe` 509,683 (56.6 %) | 30 | 512 |
| 6.1 (`6.1.0-56-cloud-amd64`) | 128 | 122 → 122 | 0 → 0 | 3,859,741 → 3,632,774 (-5.9 %) | `module_read_file_observe` 509,683 (56.6 %) | 32 | 512 |
| 6.8 (`6.8.0-149-generic`) | 128 | 125 → 125 | 0 → 0 | 2,428,322 → 2,285,769 (-5.9 %) | `execmap_check` 261,797 (29.1 %) | 25 | 512 |
| 6.12 (`6.12.118+deb13-cloud-amd64`) | 128 | 124 → 124 | 0 → 0 | 2,675,620 → 2,429,817 (-9.2 %) | `execmap_check` 304,741 (33.9 %) | 23 | 512 |
| 7.0 (`7.0.0-43-generic`) | 128 | 123 → 123 | 0 → 0 | 3,153,510 → 2,737,328 (-13.2 %) | `fim_rename_observe` 359,387 (39.9 %) | 19 | 512 |

"OK" counts the programs that loaded; the others are absent or not counted
on that kernel (the optional `inode_set_acl` / `inode_remove_acl` hooks,
the lab-only `probe_*` sensor-feasibility programs, as on `main`). No
program loads on `main` and not on the branch, on any kernel. The highest
program is at 56.6 % of the 900k gate on 5.15 and 6.1, below the 80 % of
S1.

Before the fixes:

| kernel | refused (v0: `main`'s source, the new toolchain) | headroom |
|---|---|---|
| 5.15 | `exec_check_lsm`, `execmap_check`, `sched_process_exec`, `sched_process_exec_nostdio` | FAIL — over the budget 900000: cgroup_join_mark 987382 |
| 6.1 | `exec_check_lsm`, `execmap_check`, `sched_process_exec`, `sched_process_exec_nostdio` | OK — every program within 900000 (highest module_read_file_observe 560828 (62.3% of the 900k gate)) |
| 6.8 | `exec_check_lsm`, `execmap_check`, `sched_process_exec`, `sched_process_exec_nostdio` | OK — every program within 900000 (highest mount_guard_sb_umount 247281 (27.5% of the 900k gate)) |
| 6.12 | `exec_check_lsm`, `execmap_check`, `sched_process_exec`, `sched_process_exec_nostdio` | OK — every program within 900000 (highest fim_rename_observe 258623 (28.7% of the 900k gate)) |
| 7.0 | `exec_check_lsm`, `execmap_check`, `sched_process_exec`, `sched_process_exec_nostdio` | OK — every program within 900000 (highest fim_rename_observe 359387 (39.9% of the 900k gate)) |

## Per program

Processed instructions, `main` → branch, on each kernel (one figure where
both are the same), the branch's share of the 900k gate on 5.15 and 6.1,
and the largest stack chain over the five kernels. Sorted by the largest
count on the branch.

| program | 5.15: main → branch | 6.1: main → branch | 6.8: main → branch | 6.12: main → branch | 7.0: main → branch | of the 900k gate (5.15 / 6.1) | stack chain of 512 (main → branch) |
|---|---:|---:|---:|---:|---:|---:|---:|
| `module_read_file_observe` | 459,242 → 509,683 | 459,242 → 509,683 | 84,407 → 77,211 | 84,703 → 77,507 | 67,941 → 70,511 | 56.6 % / 56.6 % | 160 → 128 |
| `mount_guard_move_mount_point` | 459,673 → 441,309 | 437,978 → 372,416 | 137,558 → 111,027 | 179,138 → 99,243 | 180,347 → 100,993 | 49.0 % / 41.4 % | 416 |
| `mount_guard_sb_mount_point` | 428,722 → 380,618 | 416,879 → 334,375 | 90,725 → 63,222 | 146,597 → 65,976 | 145,307 → 64,015 | 42.3 % / 37.2 % | 384 |
| `fim_rename_observe` | 113,259 → 117,916 | 110,774 → 112,097 | 218,580 → 227,518 | 253,823 → 258,623 | 362,618 → 359,387 | 13.1 % / 12.5 % | 512 |
| `mount_guard_sb_umount` | 330,177 → 329,045 | 330,134 → 328,988 | 239,225 → 246,756 | 243,109 → 244,167 | 242,319 → 242,681 | 36.6 % / 36.6 % | 384 → 352 |
| `execmap_check` | 325,008 → 327,746 | 290,794 → 293,718 | 262,054 → 261,797 | 304,666 → 304,741 | 277,478 → 277,196 | 36.4 % / 32.6 % | 384 → 416 |
| `execpol_env_commit` | 323,155 → 316,015 | 318,695 → 311,741 | 273,029 → 225,174 | 274,217 → 233,115 | 335,293 → 227,378 | 35.1 % / 34.6 % | 320 |
| `fim_file_open_sensor` | 147,208 → 159,065 | 136,713 → 145,631 | 137,624 → 142,332 | 156,903 → 160,694 | 264,694 → 261,919 | 17.7 % / 16.2 % | 480 |
| `fim_unlink_observe` | 56,357 → 61,054 | 54,869 → 56,232 | 106,643 → 113,432 | 140,777 → 142,501 | 246,340 → 244,599 | 6.8 % / 6.2 % | 480 |
| `exec_env_lsm` | 292,170 → 227,623 | 287,710 → 223,337 | 268,931 → 221,182 | 269,159 → 221,130 | 330,261 → 215,515 | 25.3 % / 24.8 % | 352 |
| `mount_guard_sb_mount_propagate` | 200,149 → 206,308 | 105,838 → 112,061 | 104,702 → 111,130 | 104,734 → 110,202 | 182,237 → 169,553 | 22.9 % / 12.5 % | 288 |
| `exec_check_lsm` | 142,094 → 148,012 | 101,309 → 109,844 | 89,011 → 99,946 | 97,587 → 106,751 | 85,784 → 99,976 | 16.4 % / 12.2 % | 384 |
| `probe_file_open` | 108,344 → 120,951 | 84,759 → 77,362 | 12,895 → 12,889 | 12,904 → 12,890 | 14,199 → 14,324 | 13.4 % / 8.6 % | 160 |
| `cgroup_join_mark` | 207,446 → 72,225 | 53,553 → 42,062 | 40,778 → 41,996 | 25,555 → 36,145 | 49,426 → 42,298 | 8.0 % / 4.7 % | 128 |
| `module_write_observe` | 37,119 → 50,549 | 29,834 → 31,120 | 28,154 → 29,468 | 50,921 → 52,223 | 62,060 → 66,476 | 5.6 % / 3.5 % | 256 |
| `protected_write_deny` | 78,322 → 57,234 | 63,964 → 53,523 | 54,355 → 49,564 | 52,925 → 49,798 | 52,125 → 48,540 | 6.4 % / 5.9 % | 256 |
| `udp_sendmsg_outbound` | 33,135 → 41,183 | 23,318 → 29,540 | 3,907 → 2,985 | 2,714 → 2,190 | 2,645 → 2,084 | 4.6 % / 3.3 % | 352 |
| `dns_answer_v4_ret4` | 34,154 → 30,245 | 25,656 → 23,571 | 3,019 → 2,694 | 3,019 → 2,694 | 2,905 → 2,444 | 3.4 % / 2.6 % | 192 |
| `dns_answer_v4_ret6` | 34,154 → 30,245 | refused (does not count) | refused (does not count) | refused (does not count) | refused (does not count) | 3.4 % / 0.0 % | 192 |
| `dns_answer_v6_ret4` | 34,154 → 30,245 | 25,656 → 23,571 | 3,019 → 2,694 | 3,019 → 2,694 | 2,905 → 2,444 | 3.4 % / 2.6 % | 192 |
| `dns_answer_v6_ret6` | 34,154 → 30,245 | refused (does not count) | refused (does not count) | refused (does not count) | refused (does not count) | 3.4 % / 0.0 % | 192 |
| `bpf_syscall_observe` | 56,286 → 29,424 | 42,279 → 27,013 | 29,227 → 24,348 | 29,143 → 24,348 | 27,348 → 22,717 | 3.3 % / 3.0 % | 512 → 480 |
| `udpv6_sendmsg_outbound` | 38,673 → 28,991 | 33,565 → 28,901 | 4,844 → 4,536 | 1,991 → 2,432 | 1,848 → 2,336 | 3.2 % / 3.2 % | 352 |
| `udp_sendmsg` | 25,705 → 24,257 | 17,168 → 16,206 | 1,630 → 1,618 | 1,630 → 1,618 | 1,566 → 1,516 | 2.7 % / 1.8 % | 160 |
| `dns_answer_v4_ret5` | refused (does not count) | 25,656 → 23,571 | 3,019 → 2,694 | 3,019 → 2,694 | refused (does not count) | 0.0 % / 2.6 % | 192 |
| `dns_answer_v6_ret5` | refused (does not count) | 25,656 → 23,571 | 3,019 → 2,694 | 3,019 → 2,694 | refused (does not count) | 0.0 % / 2.6 % | 192 |
| `tcp_close` | 21,406 → 21,650 | 16,038 → 21,650 | 6,485 → 4,748 | 2,250 → 2,114 | 2,154 → 2,039 | 2.4 % / 2.4 % | 480 |
| `bpf_prog_guard` | 28,049 → 21,134 | 22,355 → 17,173 | 19,249 → 15,840 | 19,249 → 15,840 | 17,896 → 14,973 | 2.3 % / 1.9 % | 352 → 320 |
| `protected_open_deny` | 32,384 → 20,463 | 27,152 → 20,027 | 19,404 → 17,177 | 18,998 → 18,711 | 17,640 → 16,805 | 2.3 % / 2.2 % | 224 → 192 |
| `nn_sysctl_guard` | 20,715 → 19,717 | 17,587 → 16,765 | 3,769 → 3,678 | 3,617 → 3,548 | 3,603 → 3,606 | 2.2 % / 1.9 % | 160 |
| `fim_link_observe` | 16,621 → 16,860 | 16,572 → 16,811 | 8,633 → 9,291 | 8,633 → 9,291 | 6,766 → 7,024 | 1.9 % / 1.9 % | 96 → 64 |
| `probe_bprm` | 14,204 → 13,503 | 14,204 → 13,503 | 7,986 → 8,020 | 7,985 → 8,019 | 6,985 → 6,834 | 1.5 % / 1.5 % | 160 |
| `tls_client_hello` | 11,560 → 11,340 | 11,560 → 11,340 | 4,525 → 4,411 | 4,543 → 4,411 | 4,385 → 4,268 | 1.3 % / 1.3 % | 224 |
| `bpf_prog_load_guard` | absent | absent | absent | 10,370 → 10,163 | 9,902 → 9,732 | — / — | 256 |
| `mount_guard_move_mount` | 14,693 → 9,472 | 14,650 → 9,415 | 9,271 → 8,680 | 9,270 → 8,674 | 8,800 → 8,259 | 1.1 % / 1.0 % | 224 |
| `task_kill` | 10,123 → 9,391 | 9,292 → 9,191 | 8,902 → 8,145 | 8,902 → 8,145 | 7,356 → 7,341 | 1.0 % / 1.0 % | 192 → 160 |
| `fim_file_cap_observe` | 8,718 → 9,076 | 8,603 → 8,959 | 8,545 → 8,079 | 8,545 → 8,079 | 7,015 → 7,314 | 1.0 % / 1.0 % | 160 |
| `io_uring_submit` | 8,528 → 8,983 | 8,528 → 8,983 | 520 → 583 | 520 → 583 | 534 → 559 | 1.0 % / 1.0 % | 96 |
| `epg_sys_exit` | 7,071 → 6,973 | 6,943 → 6,841 | 5,594 → 5,759 | 5,639 → 5,660 | 5,933 → 5,724 | 0.8 % / 0.8 % | 416 |
| `mount_guard_sb_mount` | 6,775 → 6,781 | 6,775 → 6,781 | 6,765 → 6,771 | 6,765 → 6,771 | 6,371 | 0.8 % / 0.8 % | 160 |
| `mount_guard_sb_remount` | 5,060 → 6,451 | 5,017 → 6,394 | 4,449 → 3,914 | 4,449 → 3,914 | 3,954 → 3,464 | 0.7 % / 0.7 % | 192 → 160 |
| `sched_process_exec` | 6,500 → 6,431 | 5,398 → 5,663 | 4,052 → 3,977 | 4,052 → 3,977 | 3,761 → 3,750 | 0.7 % / 0.6 % | 224 → 192 |
| `fim_write_intent_observe` | 13,678 → 6,178 | 13,678 → 6,178 | 3,929 → 3,139 | 2,302 → 1,876 | 2,115 → 1,732 | 0.7 % / 0.7 % | 256 → 224 |
| `inet_csk_listen_start` | 3,475 → 5,960 | 3,475 → 5,960 | 1,155 → 1,070 | 832 → 804 | 826 → 753 | 0.7 % / 0.7 % | 288 |
| `bpf_map_guard` | 8,162 → 5,807 | 6,386 → 5,792 | 5,543 → 4,989 | 5,543 → 4,989 | 5,141 → 4,626 | 0.6 % / 0.6 % | 256 |
| `file_ioctl` | 7,942 → 5,788 | 6,564 → 5,776 | 5,772 → 5,200 | 5,772 → 5,200 | 5,299 → 4,739 | 0.6 % / 0.6 % | 352 |
| `protected_ioctl_compat_deny` | 7,942 → 5,788 | 6,564 → 5,776 | 5,772 → 5,200 | 5,772 → 5,200 | 5,299 → 4,739 | 0.6 % / 0.6 % | 352 |
| `inode_rename` | 9,981 → 5,331 | 7,160 → 5,219 | 5,721 → 4,406 | 5,721 → 4,406 | 5,332 → 3,952 | 0.6 % / 0.6 % | 128 → 96 |
| `epg_lite_commit_creds` | 5,585 → 5,269 | 5,323 → 5,045 | 2,511 → 2,620 | 2,511 → 2,620 | 4,261 → 4,393 | 0.6 % / 0.6 % | 384 |
| `io_uring_create` | 2,942 → 4,584 | 2,942 → 4,584 | 587 → 575 | 587 → 575 | 548 → 569 | 0.5 % / 0.5 % | 96 |
| `dns_udp_send_skb` | 4,460 → 4,383 | 3,979 → 3,907 | 1,045 → 989 | 1,045 → 989 | 1,204 → 948 | 0.5 % / 0.4 % | 160 |
| `dns_udp_v6_send_skb` | 4,460 → 4,383 | 3,979 → 3,907 | 1,045 → 989 | 1,045 → 989 | 1,204 → 948 | 0.5 % / 0.4 % | 160 |
| `epg_lite_file_open` | 5,852 → 4,295 | 5,622 → 4,068 | 2,003 → 2,142 | 2,003 → 2,142 | 1,961 → 2,119 | 0.5 % / 0.5 % | 288 |
| `bpf_write_user_guard` | 5,621 → 4,038 | 4,287 → 3,857 | 3,876 → 3,581 | 3,876 → 3,581 | 3,591 → 3,312 | 0.4 % / 0.4 % | 224 |
| `mount_guard_sb_pivotroot` | 4,523 → 3,952 | 4,480 → 3,895 | 3,903 → 3,367 | 3,903 → 3,367 | 3,417 → 2,920 | 0.4 % / 0.4 % | 192 → 160 |
| `module_load_data_observe` | 4,865 → 3,879 | 4,865 → 3,879 | 1,979 → 1,332 | 1,979 → 1,332 | 1,949 → 1,299 | 0.4 % / 0.4 % | 96 → 64 |
| `sched_process_exec_nostdio` | 3,958 → 3,858 | 2,856 → 3,069 | 2,490 → 2,434 | 2,490 → 2,434 | 2,356 → 2,328 | 0.4 % / 0.3 % | 160 → 128 |
| `epg_lite_capable` | 2,937 → 3,613 | 2,712 → 3,385 | 1,735 → 1,949 | 1,735 → 1,949 | 1,816 → 1,952 | 0.4 % / 0.4 % | 288 |
| `epg_lite_exec` | 2,937 → 3,613 | 2,712 → 3,385 | 1,735 → 1,949 | 1,735 → 1,949 | 1,816 → 1,952 | 0.4 % / 0.4 % | 288 |
| `fim_setattr_observe` | 3,573 → 3,567 | 3,573 → 3,567 | 2,602 → 2,595 | 2,602 → 2,595 | 2,342 → 2,381 | 0.4 % / 0.4 % | 192 |
| `ptrace_access_check` | 3,375 → 2,926 | 3,375 → 2,926 | 2,663 → 2,359 | 2,663 → 2,193 | 2,484 → 2,048 | 0.3 % / 0.3 % | 160 → 96 |
| `epg_lite_switch_ns` | 2,737 → 2,793 | 2,484 → 2,555 | 1,205 → 1,344 | 1,205 → 1,344 | 1,196 → 1,355 | 0.3 % / 0.3 % | 288 |
| `inbound_accept_ret2` | refused (does not count) | 3,908 → 2,752 | 1,511 → 1,416 | 1,332 → 1,246 | 1,241 → 1,148 | 0.0 % / 0.3 % | 320 |
| `inbound_accept_ret4` | 3,908 → 2,752 | 3,908 → 2,752 | 1,511 → 1,416 | refused (does not count) | refused (does not count) | 0.3 % / 0.3 % | 320 |
| `inode_rmdir` | 5,062 → 2,671 | 3,655 → 2,633 | 2,947 → 2,249 | 2,947 → 2,249 | 2,759 → 1,997 | 0.3 % / 0.3 % | 160 → 128 |
| `inode_unlink` | 4,963 → 2,651 | 3,580 → 2,613 | 2,870 → 2,226 | 2,870 → 2,226 | 2,663 → 2,000 | 0.3 % / 0.3 % | 128 → 96 |
| `epg_sys_enter` | 2,480 → 2,507 | 2,480 → 2,507 | 1,190 → 1,241 | 1,479 → 1,507 | 1,412 → 1,486 | 0.3 % / 0.3 % | 384 → 352 |
| `dns_nss_resolve` | 2,834 → 2,472 | 2,834 → 2,204 | 529 → 527 | 529 → 527 | 550 → 538 | 0.3 % / 0.2 % | 96 |
| `epg_commit_creds` | 2,316 → 2,347 | 2,316 → 2,347 | 1,698 → 1,723 | 1,698 → 1,723 | 1,676 → 1,740 | 0.3 % / 0.3 % | 288 |
| `epg_lite_set_fs_root` | 2,061 → 2,113 | 2,061 → 2,113 | 605 → 619 | 605 → 619 | 599 → 613 | 0.2 % / 0.2 % | 192 |
| `cgroup_join_fork` | 2,082 → 2,054 | 1,270 → 1,237 | 1,730 → 1,697 | 1,869 → 1,836 | 1,655 → 1,661 | 0.2 % / 0.1 % | 64 |
| `mount_guard_propagation` | 1,954 → 1,938 | 1,954 → 1,938 | 1,734 → 1,722 | 1,734 → 1,722 | 1,438 → 1,451 | 0.2 % / 0.2 % | 96 |
| `epg_switch_ns` | 1,682 → 1,680 | 1,400 → 1,398 | 783 → 780 | 783 → 780 | 750 → 747 | 0.2 % / 0.2 % | 256 |
| `protected_removexattr_deny` | 2,781 → 1,644 | 2,099 → 1,644 | 1,758 → 1,476 | 1,758 → 1,476 | 1,661 → 1,321 | 0.2 % / 0.2 % | 160 |
| `protected_setxattr_deny` | 2,781 → 1,644 | 2,099 → 1,644 | 1,758 → 1,476 | 1,758 → 1,476 | 1,661 → 1,321 | 0.2 % / 0.2 % | 160 |
| `epg_set_fs_root` | 1,636 → 1,635 | 1,358 → 1,357 | 751 → 749 | 751 → 749 | 717 → 715 | 0.2 % / 0.2 % | 224 |
| `fim_create_observe` | 1,539 | 1,539 | 963 | 963 | 848 | 0.2 % / 0.2 % | 64 |
| `inode_setattr` | 2,429 → 1,420 | 1,762 → 1,420 | 1,546 → 1,253 | 1,546 → 1,253 | 1,416 → 1,142 | 0.2 % / 0.2 % | 128 → 96 |
| `protected_remove_acl_deny` | absent | absent | 1,694 → 1,397 | 1,694 → 1,397 | 1,652 → 1,250 | — / — | 160 |
| `protected_set_acl_deny` | absent | absent | 1,694 → 1,397 | 1,694 → 1,397 | 1,652 → 1,250 | — / — | 160 |
| `protected_create_deny` | 2,439 → 1,255 | 1,770 → 1,255 | 1,419 → 1,096 | 1,419 → 1,096 | 1,322 → 980 | 0.1 % / 0.1 % | 128 → 96 |
| `protected_link_deny` | 2,439 → 1,255 | 1,770 → 1,255 | 1,419 → 1,096 | 1,419 → 1,096 | 1,322 → 980 | 0.1 % / 0.1 % | 128 → 96 |
| `protected_mkdir_deny` | 2,439 → 1,255 | 1,770 → 1,255 | 1,419 → 1,096 | 1,419 → 1,096 | 1,322 → 980 | 0.1 % / 0.1 % | 128 → 96 |
| `protected_mknod_deny` | 2,439 → 1,255 | 1,770 → 1,255 | 1,419 → 1,096 | 1,419 → 1,096 | 1,322 → 980 | 0.1 % / 0.1 % | 128 → 96 |
| `protected_symlink_deny` | 2,439 → 1,255 | 1,770 → 1,255 | 1,419 → 1,096 | 1,419 → 1,096 | 1,322 → 980 | 0.1 % / 0.1 % | 128 → 96 |
| `cgroup_join_inject` | 3,285 → 1,089 | 3,230 → 1,055 | 1,332 → 989 | 1,332 → 989 | 1,249 → 921 | 0.1 % / 0.1 % | 160 → 96 |
| `sys_enter_execve` | 944 | 944 | 889 | 889 | 879 | 0.1 % / 0.1 % | 128 |
| `probe_ip6_make_skb` | 949 → 942 | 949 → 942 | 573 → 570 | 573 → 570 | 655 → 652 | 0.1 % / 0.1 % | 128 → 96 |
| `probe_ip_make_skb` | 949 → 942 | 949 → 942 | 573 → 570 | 573 → 570 | 655 → 652 | 0.1 % / 0.1 % | 128 → 96 |
| `probe_udp_send_skb` | 960 → 908 | 960 → 908 | 609 → 582 | 609 → 582 | 728 → 703 | 0.1 % / 0.1 % | 96 |
| `task_setscheduler_deny` | 1,379 → 890 | 1,379 → 890 | 1,160 → 838 | 1,160 → 838 | 1,098 → 773 | 0.1 % / 0.1 % | 128 → 96 |
| `fim_file_open_observe` | 884 → 883 | 884 → 883 | 734 → 733 | 722 | 648 | 0.1 % / 0.1 % | 96 |
| `task_setioprio_deny` | 1,362 → 870 | 1,362 → 870 | 1,146 → 819 | 1,146 → 819 | 1,082 → 755 | 0.1 % / 0.1 % | 128 → 96 |
| `task_setnice_deny` | 1,362 → 870 | 1,362 → 870 | 1,146 → 819 | 1,146 → 819 | 1,082 → 755 | 0.1 % / 0.1 % | 128 → 96 |
| `task_setrlimit_deny` | 1,360 → 869 | 1,360 → 869 | 1,144 → 829 | 1,144 → 829 | 1,080 → 762 | 0.1 % / 0.1 % | 128 → 96 |
| `module_lock_observe` | 673 → 748 | 673 → 748 | 671 → 699 | 671 → 699 | 605 → 627 | 0.1 % / 0.1 % | 128 |
| `cgroup_move_deny` | 1,982 → 716 | 1,214 → 716 | 1,013 → 676 | 1,013 → 676 | 970 → 618 | 0.1 % / 0.1 % | 128 → 96 |
| `tcp_v6_connect` | 645 → 633 | 645 → 633 | 529 → 517 | 529 → 517 | 504 → 499 | 0.1 % / 0.1 % | 288 |
| `socket_connect_deny` | 442 → 610 | 442 → 610 | 355 → 375 | 377 → 375 | 418 → 415 | 0.1 % / 0.1 % | 64 |
| `tcp_v4_connect` | 624 → 602 | 624 → 602 | 577 → 556 | 577 → 556 | 552 → 538 | 0.1 % / 0.1 % | 192 |
| `sys_enter_openat` | 558 → 567 | 558 → 567 | 509 → 512 | 455 → 458 | 443 → 444 | 0.1 % / 0.1 % | 128 |
| `census_progs` | 558 → 528 | 558 → 528 | 557 → 527 | 557 → 527 | 512 → 485 | 0.1 % / 0.1 % | 64 |
| `fim_close_emit_observe` | 501 | 501 | 501 | 501 | 461 | 0.1 % / 0.1 % | 128 |
| `cgroup_join_born` | 384 → 398 | 384 → 398 | 384 → 398 | 384 → 398 | 518 → 486 | 0.0 % / 0.0 % | 32 |
| `role_exit` | 429 → 468 | 279 → 283 | 285 → 288 | 285 → 288 | 221 → 226 | 0.1 % / 0.0 % | 32 |
| `open_sensor_rmdir` | 459 | 459 | 399 | 399 | 363 | 0.1 % / 0.1 % | 64 |
| `census_links` | absent | 422 → 418 | 421 → 417 | 421 → 417 | 381 → 372 | — / 0.0 % | 64 |
| `fork_parent_record` | 375 → 414 | 375 → 414 | 400 → 318 | 400 → 318 | 366 → 308 | 0.0 % / 0.0 % | 64 |
| `file_send_sigiotask_deny` | 871 → 403 | 871 → 403 | 655 → 345 | 655 → 345 | 640 → 321 | 0.0 % / 0.0 % | 96 → 32 |
| `cgroup_join_traceme` | 355 → 330 | 334 → 330 | 333 → 329 | 333 → 329 | 334 → 319 | 0.0 % / 0.0 % | 32 |
| `nn_task_free` | 228 → 222 | 159 → 161 | 159 → 161 | 159 → 161 | 198 → 164 | 0.0 % / 0.0 % | 32 |
| `cgroup_move_stash` | 174 | 174 | 174 | 174 | 154 | 0.0 % / 0.0 % | 32 |
| `execq_exec_failed` | 143 → 155 | 143 | 167 → 143 | 167 → 143 | 156 → 139 | 0.0 % / 0.0 % | 64 |
| `cgroup_join_exit` | 147 → 149 | 147 → 149 | 146 → 148 | 146 → 148 | 128 → 126 | 0.0 % / 0.0 % | 32 |
| `epg_lite_fork` | 148 | 148 | 147 | 147 | 146 | 0.0 % / 0.0 % | 192 |
| `io_uring_exit` | 151 → 144 | 151 → 144 | 151 → 144 | 151 → 144 | 140 → 133 | 0.0 % / 0.0 % | 32 |
| `mount_guard_reconfigure` | 132 | 132 | 132 | 132 | 117 | 0.0 % / 0.0 % | 32 |
| `cgroup_join_src` | 120 | 120 | 120 | 120 | 119 | 0.0 % / 0.0 % | 64 |
| `epg_chroot_fs_refs` | 24 | 24 | 24 | 24 | 22 | 0.0 % / 0.0 % | 32 |
| `cgroup_subtree_mark` | 13 | 13 | 13 | 13 | 13 | 0.0 % / 0.0 % | 32 |
| `cgroup_move_clear` | 12 | 12 | 12 | 12 | 12 | 0.0 % / 0.0 % | 32 |
| `epg_lite_task_exit` | 8 | 8 | 8 | 8 | 8 | 0.0 % / 0.0 % | 32 |
| `epg_task_exit` | 8 | 8 | 8 | 8 | 8 | 0.0 % / 0.0 % | 32 |
| `fork_parent_forget` | 8 | 8 | 8 | 8 | 8 | 0.0 % / 0.0 % | 32 |
| `nn_calib_signals` | 6 | 6 | 6 | 6 | 6 | 0.0 % / 0.0 % | 32 |
| `nn_calib_override` | 4 | refused (does not count) | 4 | refused (does not count) | 4 | 0.0 % / 0.0 % | 32 |
| `probe_fexit_ip6_make_skb` | 2 | 2 | 2 | 2 | 2 | 0.0 % / 0.0 % | 32 |
| `probe_fexit_ip_make_skb` | 2 | 2 | 2 | 2 | 2 | 0.0 % / 0.0 % | 32 |

## Growth, program by program

The branch processes fewer instructions in total on every kernel. Some
programs process more. On 5.15, the binding kernel, the programs that grew
by more than 1 % are listed below by absolute growth. The last column is
the growth as a share of the 900k gate.

| program | main | branch | growth | | of the gate |
|---|---:|---:|---:|---:|---:|
| `module_read_file_observe` | 459,242 | 509,683 | +50,441 | +11.0 % | 5.60 % |
| `module_write_observe` | 37,119 | 50,549 | +13,430 | +36.2 % | 1.49 % |
| `probe_file_open` | 108,344 | 120,951 | +12,607 | +11.6 % | 1.40 % |
| `fim_file_open_sensor` | 147,208 | 159,065 | +11,857 | +8.1 % | 1.32 % |
| `udp_sendmsg_outbound` | 33,135 | 41,183 | +8,048 | +24.3 % | 0.89 % |
| `mount_guard_sb_mount_propagate` | 200,149 | 206,308 | +6,159 | +3.1 % | 0.68 % |
| `exec_check_lsm` | 142,094 | 148,012 | +5,918 | +4.2 % | 0.66 % |
| `fim_unlink_observe` | 56,357 | 61,054 | +4,697 | +8.3 % | 0.52 % |
| `fim_rename_observe` | 113,259 | 117,916 | +4,657 | +4.1 % | 0.52 % |
| `inet_csk_listen_start` | 3,475 | 5,960 | +2,485 | +71.5 % | 0.28 % |
| `io_uring_create` | 2,942 | 4,584 | +1,642 | +55.8 % | 0.18 % |
| `mount_guard_sb_remount` | 5,060 | 6,451 | +1,391 | +27.5 % | 0.15 % |
| `epg_lite_exec` | 2,937 | 3,613 | +676 | +23.0 % | 0.08 % |
| `epg_lite_capable` | 2,937 | 3,613 | +676 | +23.0 % | 0.08 % |
| `io_uring_submit` | 8,528 | 8,983 | +455 | +5.3 % | 0.05 % |
| `fim_file_cap_observe` | 8,718 | 9,076 | +358 | +4.1 % | 0.04 % |
| `tcp_close` | 21,406 | 21,650 | +244 | +1.1 % | 0.03 % |
| `fim_link_observe` | 16,621 | 16,860 | +239 | +1.4 % | 0.03 % |
| `socket_connect_deny` | 442 | 610 | +168 | +38.0 % | 0.02 % |
| `module_lock_observe` | 673 | 748 | +75 | +11.1 % | 0.01 % |
| `epg_lite_switch_ns` | 2,737 | 2,793 | +56 | +2.0 % | 0.01 % |
| `epg_lite_set_fs_root` | 2,061 | 2,113 | +52 | +2.5 % | 0.01 % |
| `role_exit` | 429 | 468 | +39 | +9.1 % | 0.00 % |
| `fork_parent_record` | 375 | 414 | +39 | +10.4 % | 0.00 % |
| `epg_commit_creds` | 2,316 | 2,347 | +31 | +1.3 % | 0.00 % |
| `epg_sys_enter` | 2,480 | 2,507 | +27 | +1.1 % | 0.00 % |
| `cgroup_join_born` | 384 | 398 | +14 | +3.6 % | 0.00 % |
| `execq_exec_failed` | 143 | 155 | +12 | +8.4 % | 0.00 % |
| `sys_enter_openat` | 558 | 567 | +9 | +1.6 % | 0.00 % |
| `cgroup_join_exit` | 147 | 149 | +2 | +1.4 % | 0.00 % |

- `module_read_file_observe` (+11 % on 5.15 and 6.1) is the only program
  that grows by more than 1.6 % of the gate. Its two remaining `memset`
  subprogram calls are `open_sensor::key_of`'s zeroed key, on `main` too:
  the calls rule 9 warns of on 5.15 and 6.1. Writing that key with
  volatile stores changes most programs, so it is a change of its own,
  measured on every kernel. The program is at 56.6 % of the gate, below
  the 80 % of S1.
- The others are the same source in LLVM 22's instruction selection and
  register allocation, and the cost of the fixes themselves:
  `exec_check_lsm` keeps its slot masks and gains `lsm_ret`'s two branches
  (+5,918 on 5.15, +14,192 on 7.0, the most on any kernel). None grows by
  more than 1.6 % of the gate on any of the five kernels.
- On 6.12, `cgroup_join_mark` grows from 25,555 to 36,145. That is the
  walk's own check, once, over all 256 bytes, counted with the program. On
  5.15 the same change takes it from 207,446 to 72,225.

## Stack

The S1 gate of a 448-byte stack chain is exceeded on `main` already, by
five programs, on every kernel. The branch has the same five:

- `fim_rename_observe`: 512 on `main`, 512 on the branch;
- `bpf_syscall_observe`: 512 on `main`, 480 on the branch;
- `fim_file_open_sensor`, `fim_unlink_observe` and `tcp_close`: 480 on
  both. `tcp_close`'s own frame is 440 → 448 bytes; the chain is the same.

No other chain crosses 448. The largest change below it is
`execmap_check`, 384 → 416. Bringing the five under 448 is not this lot's:
after the review of #618 the coordinator gave them to lots 1.3 and 1.4.

## After the review of #618

The review's fixes change two things in the object (sha256 `340d3f62…`):

- `opaque::lsm_ret` fails closed. A positive verdict, which no path of
  `exec_check_lsm` returns, came out as 0, an allow; it is now `-EACCES`,
  the hook's refusal. 0 and `-EACCES` come out as before, and every value
  comes out in `[-4095, 0]`
  (`xtask/tests/ebpf_barriers.rs::lsm_ret_allows_only_zero_and_fails_closed`
  runs the helper's own source on the host).
- `nn_cgroup_exempt_walk` takes no argument instead of an unused one,
  whose register the caller never set.

`nn-lab.sh verifier-check synced` with this object, the same guests and
agent build as above:

| kernel | OK | failing | processed, all programs (branch above → after the review) | `exec_check_lsm` | `cgroup_join_mark` |
|---|---:|---:|---|---|---|
| 5.15 (`5.15.0-204-generic`) | 121 | 0 | 4,103,678 → 4,109,024 (+0.13 %) | 148,012 → 153,358 (17.0 % of the gate; frame 152 → 160 bytes, chain 384) | 72,225, unchanged |
| 6.12 (`6.12.118+deb13-cloud-amd64`) | 124 | 0 | 2,429,817 → 2,429,454 (−0.01 %) | 106,751 → 106,388 (the exit range check passes) | 36,145, unchanged |

No other program changes on either kernel: the totals move by exactly
`exec_check_lsm`'s difference. The highest program is still
`module_read_file_observe`, at 56.6 % of the gate on 5.15. 6.12 is one of
the kernels that check an LSM program's exit range (the refusal this lot
fixed on 6.8, 6.12 and 7.0); 6.1, 6.8 and 7.0 were not run again.

## The eBPF object as a CI artefact (F16)

- ci.yml's `ebpf-build` job, after the build and its checks (map types,
  back-edges), writes `northnarrow-agent-ebpf.sha256` and uploads the
  object, its `.buildhash` stamp and the sha256 as the artefact
  `ebpf-object` (`gh run download <run> -n ebpf-object`): the object CI
  tested, by its sha256.
- The lab does not load that artefact yet. `nn-lab.sh sync` runs
  `cargo xtask build-ebpf` on the host before it copies the tree to the
  guest, so cargo can rebuild over a downloaded object (a fresh tree,
  changed sources), and `verifier-check synced` loads the guest's synced
  copy. Each report names the sha256 of the object it loaded; this file's
  method copied `main`'s object over the synced one by hand. The branch's
  object measured here (`d9f2ae7e…`, built in the lot's worktree) is not
  byte for byte CI's: the checkout path is in its `.rodata` and debug
  info, and the review of #618 found the instructions otherwise the same.
  Loading the artefact in the lab, and checking its sha256 where it is
  used, belongs to lot 1.10 (`nn-lab.sh`, lab-vm.yml).
- release.yml's `package` job prints the sha256 of the object it embeds.
  lab-vm.yml's guest job keeps the sha256 of the object its guest loads in
  its evidence (`ebpf-object.sha256`).
- The gap: the release rebuilds the object. A build is reproducible: two
  clean builds of `main`'s tree at one path give one sha256 (`4be2def0…`
  both times). CI and the release share the checkout path and every pin:
  the nightly, bpf-linker and both lockfiles. So the two sha256s are
  expected to be equal, and on this lot's PR they were: the release dry
  run embedded `a9de2b0a…`, the sha256 of CI's artefact, built on another
  runner. Nothing compares them automatically: the `package` job compiles
  the dependency tree and holds no token that reads another run's
  artefacts (SUP-003), and the comparison by hand before a tag is not yet
  in CONTRIBUTING.md's release procedure (docs lot 1.9). lab-vm.yml still
  builds its own object. Reusing the artefact there needs `nn-lab.sh sync`
  to accept a prebuilt object (lot 1.10).
- `xtask/tests/supply_chain.rs::the_ebpf_object_ci_tests_is_kept_and_every_build_names_its_own`
  holds all of this, and one bpf-linker version in every workflow.

## The privileged suites and the agent on the branch

On Ubuntu 22.04 (5.15) and Debian 13 (6.12), the branch's lab build with
the object above embedded:

| check | 5.15 | 6.12 |
|---|---|---|
| `install` (enforcing, both units enabled and started) | rc 0 | rc 0 |
| `own-pins-check` | PASS | PASS |
| `foreign-bpf-check` F1 F2 F4 F5 F6 | 47 PASS, 0 FAIL | 47 PASS, 0 FAIL |
| foreign BPF objects in the census after the checks | 15, all baseline | 17, all baseline |
| `test-ignored` (5 runs, the agent installed) | every run exit 0: 180 passed, 0 failed | every run exit 0: 180 passed, 0 failed |
| stop in a trusted-installer window (SIGTERM the watchdog, then the agent) | both inactive, 103 pins kept | both inactive, 107 pins kept |
| start | both active, 56 LSM programs, no failed unit | both active, 59 LSM programs, no failed unit |
| `uninstall.sh --purge` | no unit, no pin, no `.local` left | the same |

The suites first ran before the install. Run 3 then cascaded at
`agent_mounts`: there was no `/etc/northnarrow` when the first test agent
started (lot 356's known behaviour, seen in lot 400a's round too). The round was
stopped and run again with the agent installed, as the operator's host
has it.
