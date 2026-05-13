# Tappa 7 Task 5 — Deep Debug Log

**Date:** 2026-05-12
**Branch:** main
**Scope:** filesystem-protection LSM hooks (inode_unlink, inode_rmdir,
inode_rename, inode_setattr, file_ioctl) are loaded and "attached" but
not denying any attack.

This document is updated incrementally as the investigation proceeds.
The user will `cat` it instead of scrolling tmux.

---

## 0. Current state (after iteration 1 — commit `3019c24`)

Iteration 1 added unconditional zero-arg `bpf_printk!` body markers
to the three FS hooks that lacked them, and replaced every
`nn_printk_u64` inside `deny_if_protected` with zero-arg
`bpf_printk!` REACHED markers. `nn_printk_u64` was left intact in
`try_inode_rename` / `try_file_ioctl` as a control.

**Attack matrix — all still PASSED for attacker (FAIL for protection):**

| Command   | rc | Expected | Outcome |
|-----------|----|----------|---------|
| `chattr -i`  | 0 | -EPERM | attacker wins |
| `mv`         | 0 | -EPERM | attacker wins |
| `touch`      | 0 | -EPERM | attacker wins |
| `chmod`      | 0 | -EPERM | attacker wins |
| `rm <file>`  | 0 | -EPERM | attacker wins |

**Marker counts from `trace_pipe`:**

| Marker | Hits | Interpretation |
|---|---|---|
| `nn-diag-ioctl-body fired`   | **481** | `security_file_ioctl` hook dispatched (system noise + chattr) |
| `nn-diag-rename-body fired`  | **2**   | `security_inode_rename` hook dispatched (mv only) |
| `nn-diag-unlink-body fired`  | **0**   | `security_inode_unlink` **never dispatched** — rm bypasses our prog |
| `nn-diag-rmdir-body fired`   | **0**   | `security_inode_rmdir` **never dispatched** |
| `nn-diag-setattr-body fired` | **0**   | `security_inode_setattr` **never dispatched** — touch / chmod bypass |
| `nn-diag-REACHED-deny-if`    | **0**   | even on the two hooks the kernel *did* dispatch, control never reached `deny_if_protected` |
| `nn-diag-REACHED-key-none`   | **0**   | (helper not reached) |
| `nn-diag-REACHED-key-ok`     | **0**   | (helper not reached) |
| `nn-diag-REACHED-MISS`       | **0**   | (helper not reached) |
| `nn-diag-REACHED-MATCH`      | **0**   | (helper not reached) |
| `nn-diag: ENTER …` (any `nn_printk_u64`) | **0** | **`bpf_trace_vprintk` path is broken** |

Two independent failures stacked on top of each other:

1. Three of five FS hooks load but the kernel never calls them.
2. The two that *do* get called short-circuit silently between the
   body marker and `deny_if_protected`.

---

## 1. Source inspection — wrappers (post iteration 1)

`agent-ebpf/src/inode_protect.rs`:

| Hook | Body marker | Inner `try_*` instrumentation |
|---|---|---|
| `inode_unlink` (line 242) | yes | none yet (kernel never calls it) |
| `inode_rmdir`  (line 271) | yes | none yet (kernel never calls it) |
| `inode_rename` (line 299) | yes | broken `nn_printk_u64` at line 307 only |
| `inode_setattr` (line 338) | yes | none yet (kernel never calls it) |
| `file_ioctl` (line 365) | yes | broken `nn_printk_u64` at lines 381 / 385 only |

`deny_if_protected` (line 202) now has six zero-arg REACHED markers
covering every branch — none of them fire.

---

## 2. Hypotheses status

### A) BPF programs attached to wrong BTF id — **PARTIALLY CONFIRMED**

`inode_unlink`, `inode_rmdir`, `inode_setattr` body markers fire
**zero** times. `inode_rename` and `file_ioctl` markers fire normally.
Since the body marker is the very first instruction in the wrapper —
unconditional, zero-arg `bpf_printk!`, no `ctx.arg()` before it — the
only explanations are:

1. Kernel BPF-LSM dispatch never invokes our program for those three
   hooks (most likely).
2. The aya 0.13 `#[lsm(hook = "inode_unlink")]` macro is resolving
   `inode_unlink` to the wrong vmlinux BTF id (or none at all) on
   Linux 6.8.

Disambiguation: dump `attach_btf_id` per program from `bpftool prog
show id N -j` and compare against `bpftool btf dump file
/sys/kernel/btf/vmlinux | grep security_inode_unlink`. See test block
in §6.

### B) `nn_printk_u64` / `bpf_trace_vprintk` binding broken — **CONFIRMED**

Zero `nn_printk_u64` calls produced output. Two of them sit
immediately after a working zero-arg `bpf_printk!` body marker on the
same straight-line code path. There is no possible control-flow
explanation; the helper is silently dropping output on this kernel +
aya combo.

Resolution: rip out `nn_printk_u64` and the `bpf_trace_vprintk`
import. Replace remaining call sites with zero-arg `bpf_printk!`.
(Done in iteration 2.)

### C) Body marker fires but inner `try_*` short-circuits silently — **NEW, NOW PRIMARY**

`ioctl-body fires 481 times` but `REACHED-deny-if fires 0 times`.
Almost all 481 hits are non-chattr ioctls returning at the cmd filter,
but `chattr -i` *should* take the FS_IOC_SETFLAGS branch and reach
`deny_if_protected`. Candidate cutoffs:

1. `cmd` value read via `ctx.arg(1)` doesn't match either
   `FS_IOC_SETFLAGS` or `FS_IOC32_SETFLAGS` — modern chattr may issue
   `FS_IOC_FSSETXATTR` (0x4028_5821) instead.
2. `file` pointer at `ctx.arg(0)` is null or garbage.
3. `bpf_probe_read_kernel` of `file->f_inode` returns `Err(_)` because
   `FILE_F_INODE_OFFSET` is wrong on this kernel.
4. `deny_if_protected` is a function call after BPF-backend
   "always-inline" decay and the subprog call itself silently fails
   verification post-load (very speculative).

For `inode_rename`: rename-body fires twice (the test ran `mv` once
and there's a clean-up rename elsewhere maybe). Wrappers call
`deny_if_protected(FS_OP_RENAME, old_dir)` immediately after
`ctx.arg(0)`. Candidate cutoff:
1. `old_dir` is null (unlikely — kernel never passes null to LSM).
2. `deny_if_protected` does not actually get inlined and the subprog
   call is non-functional in BPF context for some reason.

Disambiguation: this iteration adds fine-grained zero-arg markers
between every line of `try_inode_rename` / `try_file_ioctl`. If a
specific marker fires and the next one doesn't, we localise the
cutoff to one line.

### D) `inode_key` always returns `None` (bad BTF offsets) — UNTESTED

We never see `REACHED-key-none` because we never reach
`deny_if_protected` in the first place. Re-evaluate after C is
resolved.

---

## 3. Iteration 2 plan

1. **Rip out `nn_printk_u64`.** Delete the helper, delete the
   `bpf_trace_vprintk` import, replace remaining call sites in
   `try_inode_rename` and `try_file_ioctl` with zero-arg
   `bpf_printk!` markers.
2. **Fine-grained markers inside `try_inode_rename` / `try_file_ioctl`.**
   One marker per decision point so we can localise the cutoff.
3. **Cheap `try-entry` markers in `try_inode_unlink` / `try_inode_rmdir`
   / `try_inode_setattr`.** They cost nothing while those hooks never
   fire and will give us instant feedback when we fix the dispatch.
4. **`cmd`-value forensics in `try_file_ioctl`.** Per-cmd zero-arg
   markers for the four known chattr-family ioctl numbers
   (FS_IOC_SETFLAGS / FS_IOC32_SETFLAGS / FS_IOC_FSSETXATTR /
   FS_IOC_FSGETXATTR). Print only on match, never on "other", to
   keep the 481 noise out of the trace.

Marker inventory after iteration 2:

| Marker | Fires when |
|---|---|
| `nn-diag-{unlink,rmdir,rename,setattr,ioctl}-body fired` | wrapper entry |
| `nn-diag-rename-tryentry` | inside `try_inode_rename` first line |
| `nn-diag-rename-pre-deny-old-dir` | before `deny_if_protected(old_dir)` |
| `nn-diag-rename-pre-deny-new-dir` | before `deny_if_protected(new_dir)` |
| `nn-diag-rename-old-dentry-none` | `inode_from_dentry(old_dentry)` returned None |
| `nn-diag-rename-pre-deny-old-inode` | before `deny_if_protected(old_inode)` |
| `nn-diag-rename-new-dentry-none` | `inode_from_dentry(new_dentry)` returned None |
| `nn-diag-rename-pre-deny-new-inode` | before `deny_if_protected(new_inode)` |
| `nn-diag-ioctl-tryentry` | inside `try_file_ioctl` first line |
| `nn-diag-ioctl-cmd-SETFLAGS` | cmd == FS_IOC_SETFLAGS |
| `nn-diag-ioctl-cmd-SETFLAGS32` | cmd == FS_IOC32_SETFLAGS |
| `nn-diag-ioctl-cmd-FSSETXATTR` | cmd == 0x4028_5821 |
| `nn-diag-ioctl-cmd-FSGETXATTR` | cmd == 0x801c_581f |
| `nn-diag-ioctl-cmd-matched` | passed the cmd-filter early-return |
| `nn-diag-ioctl-file-null` | `file` pointer is null |
| `nn-diag-ioctl-probe-err` | `bpf_probe_read_kernel` on `file->f_inode` failed |
| `nn-diag-ioctl-pre-deny` | about to call `deny_if_protected` |
| `nn-diag-REACHED-deny-if` | entered `deny_if_protected` |
| `nn-diag-REACHED-key-{none,ok}` | `inode_key` result |
| `nn-diag-REACHED-{MISS,MATCH,OVERRIDE}` | decision branch |
| `nn-diag-{unlink,rmdir,setattr}-tryentry` | inner wrapper of the three "never-dispatched" hooks |

---

## 4. Bugs identified

1. **CONFIRMED.** *aya 0.13's `bpf_trace_vprintk` binding silently
   drops output on Linux 6.8 BPF-LSM trampoline.* Attribution: aya
   0.13 (or its interaction with this kernel; not our code). Repro
   smoke-test: a `bpf_trace_vprintk` call placed on a straight-line
   path immediately after a working zero-arg `bpf_printk!` produces
   no `trace_pipe` output. Fix in our codebase: stop using the
   helper, use the macro path exclusively (zero-arg form known to
   work; multi-arg form still suspect per the long comment at line
   42).

2. **PARTIALLY CONFIRMED.** *Three of five FS-protection LSM
   programs load but the kernel never dispatches them
   (inode_unlink, inode_rmdir, inode_setattr).* Attribution: TBD.
   Either aya 0.13's `#[lsm(hook = "…")]` macro resolves the wrong
   vmlinux BTF id for these hook names on Linux 6.8, or our agent
   loader is dropping the attach during program registration.
   Disambiguator: `bpftool prog show id N -j` per program — see §6
   test block.

3. **OPEN.** *On the two hooks the kernel does dispatch
   (inode_rename, file_ioctl), control reaches the wrapper body but
   never reaches `deny_if_protected`.* Iteration 2 instruments every
   line between the two to localise the cutoff. After iteration 2
   results land, this bug becomes either "ctx.arg() returns garbage",
   "cmd value mismatch (chattr uses FSSETXATTR)", "btf-offset bug
   for file->f_inode", or "deny_if_protected subprog call broken".

---

## 5. Open questions

- What `attach_btf_id` is each of the seven LSM progs actually
  using? Specifically the three never-dispatched ones.
- Is the agent loader registering all seven? Or are some failing
  silently at attach? Check the agent startup log for "attach OK"
  per hook.
- What cmd value does the system's `chattr` binary use on Ubuntu
  6.8? Strace or our per-cmd markers will tell us.
- Are the `btf_offsets.rs` constants (DENTRY_D_INODE_OFFSET,
  FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET, etc.) verified against
  this kernel's vmlinux at agent boot? Re-check after we localise
  the iteration-2 cutoff.

---

## 6. Next steps (this iteration)

After this commit lands, user runs the test block from the chat
message. Three categories of evidence we need:

1. **Attack matrix rc values** — unchanged baseline.
2. **`trace_pipe` markers** — every `nn-diag-*` line, with counts.
3. **`attach_btf_id` per LSM prog** + matching vmlinux BTF id, so
   we can confirm or deny the dispatch mystery for the three
   never-fires hooks.

After results: update §0 with the new table, §4 with the resolved
bugs, §5/§6 with the next question.

---

## 7. Iteration 3 root cause — `dev_t` encoding mismatch (2026-05-13)

After iteration 2 the markers say:

- `setattr-body` fires → kernel dispatches the LSM prog ✓
- `setattr-pre-deny` fires → ctx.arg(0) → inode_from_dentry returns Some ✓
- `REACHED-deny-if` fires → into `deny_if_protected` ✓
- `REACHED-key-ok` fires → `inode_key()` returns Some(InodeKey) ✓
- `REACHED-MISS` fires → `PROTECTED_INODES.get(&key)` returns None ✗

So the hook runs, the key is constructed, but the lookup misses despite
`bpftool map dump name PROTECTED_INODES` showing the "right" key.

### 7.1 The empirical clue

User reported, from `stat /var/lib/northnarrow`:
- `dev = 2050` (decimal) = `0x802`
- `ino = 1835009` = `0x1c0001`

Map dump:
```
key: 02 08 00 00 00 00 00 00  01 00 1c 00 00 00 00 00
     └─ dev u64 LE = 0x802 ──┘ └─ ino u64 LE = 0x1c0001 ─┘
```

So userland inserted dev=`0x802`. That is the value returned by
`std::os::unix::fs::MetadataExt::dev()`, which is `statx().stx_dev_major/minor`
recombined → equivalent to glibc `st_dev`.

### 7.2 What value does eBPF actually read?

`/var/lib/northnarrow` lives on `/dev/sda2`. `/sys/dev/block/` shows
`8:2 → sda2`, so **major=8, minor=2**.

The kernel stores `super_block.s_dev` as **`dev_t` in kernel-internal
form** — the result of `MKDEV(major, minor)`:

```
#define MINORBITS 20
#define MKDEV(ma, mi) (((ma) << MINORBITS) | (mi))
```

So `s_dev = (8 << 20) | 2 = 0x800002 = 8388610`.

Userland `stat(2)` does NOT return this raw value. The kernel runs it
through `new_encode_dev(dev_t)` before stamping `kstat.dev`:

```c
static __always_inline u32 new_encode_dev(dev_t dev) {
    unsigned major = MAJOR(dev);            // 8
    unsigned minor = MINOR(dev);            // 2
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
    //   = 2          | 0x800       | 0
    //   = 0x802
}
```

So:

| Source                                            | dev value   | hex       |
|---------------------------------------------------|-------------|-----------|
| Userland `metadata.dev()` (statx-encoded)         | 2050        | `0x802`   |
| Kernel raw `inode->i_sb->s_dev` (MKDEV form)      | 8388610     | `0x800002`|

The eBPF code at `agent-ebpf/src/inode_protect.rs:136-145` reads the
raw `s_dev` (MKDEV form) directly:

```rust
let dev_slot = (sb_ptr as *const u8).add(SUPER_BLOCK_S_DEV_OFFSET) as *const u32;
let dev = bpf_probe_read_kernel::<u32>(dev_slot).ok()?;   // → 0x800002
...
Some(InodeKey { dev: dev as u64, ino })                    // → dev=0x800002
```

But userland at `agent/src/anti_tamper/filesystem.rs:99-103` inserts the
encoded form:

```rust
let key = InodeKey {
    dev: meta.dev(),   // → 2050 = 0x802  (encoded)
    ino: meta.ino(),
};
register_inode(ebpf, &key)?;
```

Map key bytes from each side:

- Userland writes:  `02 08 00 00 00 00 00 00 …`
- eBPF looks up:    `02 00 80 00 00 00 00 00 …`

The HashMap is a `memcmp` of 16-byte blobs. These will *never* match.
Hence permanent `REACHED-MISS`. The `ino` is identical on both sides,
so it's purely the dev half that breaks the comparison.

This is consistent with every piece of observed evidence:

- `bpftool map dump` shows the encoded form because that's literally
  what userland wrote (bpftool only displays bytes; it has no opinion
  about `dev_t` encoding).
- All five LSM hooks behave identically (`MISS` on every protected-dir
  attack) because every hook routes through the same `inode_key()`
  helper, which has the same bug for all of them.
- It only became visible in iteration 3 because earlier iterations
  never reached `is_protected()` at all (broken printk, then broken
  prev-retval, then missing body markers).

### 7.3 Why this didn't show up in any layout test

`common/src/wire.rs::InodeKey` is `#[repr(C)]` over two `u64`s — 16
bytes, no padding, identical layout in eBPF and userland. The tests
in `common/src/wire.rs` only verify *struct layout*, not *value
semantics* — and the bug is a semantic mismatch (which u32→u64
transform to use), not a layout one.

### 7.4 Aya `HashMap` key comparison — not the bug

Briefly considered as a suspect; ruled out. Aya's `HashMap::insert`
delegates to `bpf(BPF_MAP_UPDATE_ELEM, …)` with `&key` as a byte
blob, and `HashMap::get` (eBPF side) hashes/compares the same byte
blob. For two `#[repr(C)] { u64, u64 }` keys with no padding gaps,
the byte blob is exactly `[dev.to_ne_bytes(); ino.to_ne_bytes()]` on
both sides. The comparison is well-defined; the *inputs* are wrong.

---

## 8. Proposed fix

**Convert in userland, leave eBPF alone.**

The kernel-internal `s_dev` is the cheapest thing the eBPF hot path
can read (one `bpf_probe_read_kernel::<u32>`). Doing `new_encode_dev`
bit-math inside every LSM hook would mean four extra instructions
per inode op for no benefit. The userland conversion runs once at
startup.

### 8.1 Code change

`agent/src/anti_tamper/filesystem.rs:99-103`:

```rust
// BEFORE
let key = InodeKey {
    dev: meta.dev(),
    ino: meta.ino(),
};

// AFTER
let st_dev = meta.dev();
let major = unsafe { libc::major(st_dev) } as u64;
let minor = unsafe { libc::minor(st_dev) } as u64;
let key = InodeKey {
    // Kernel-internal MKDEV form — matches `inode->i_sb->s_dev` as
    // read by the eBPF inode_key() helper. `meta.dev()` returns the
    // userland-encoded form (`new_encode_dev`) which is NOT what the
    // kernel stores in super_block.s_dev. See docs/TAPPA7_TASK5_DEEP_DEBUG.md §7.
    dev: (major << 20) | minor,
    ino: meta.ino(),
};
```

Note: `libc::major` / `libc::minor` are `unsafe fn` in some libc
versions; the `unsafe` block is required.

A small helper deserves its own function for testability:

```rust
/// Convert the userland-encoded `dev_t` returned by `stat(2)` /
/// `MetadataExt::dev()` back into the kernel-internal `MKDEV` form
/// that `inode->i_sb->s_dev` actually holds. See
/// docs/TAPPA7_TASK5_DEEP_DEBUG.md §7 for the encoding mismatch this
/// resolves.
fn stat_dev_to_kernel_dev(st_dev: u64) -> u64 {
    // SAFETY: libc::major/minor are pure bit-math on the argument
    // with no side effects; called `unsafe` only because the C
    // prototypes are defined in <sys/sysmacros.h> as macros that
    // libc-rs exposes as `unsafe fn`.
    let major = unsafe { libc::major(st_dev) } as u64;
    let minor = unsafe { libc::minor(st_dev) } as u64;
    (major << 20) | minor
}
```

Then `register_inode` builds:

```rust
let key = InodeKey {
    dev: stat_dev_to_kernel_dev(meta.dev()),
    ino: meta.ino(),
};
```

The `info!` log line should keep printing the raw `meta.dev()` so the
human-readable value still matches what `stat /var/lib/northnarrow`
shows; add the kernel-internal form alongside it:

```rust
info!(
    path = %dir.display(),
    st_dev = meta.dev(),
    kernel_dev = key.dev,
    ino = key.ino,
    "anti-tamper FS: directory inode registered in {PROTECTED_INODES_MAP}"
);
```

### 8.2 Optional belt-and-braces: layout/value test

Add to `common/src/wire.rs` (or to the agent crate, since libc lives
there):

```rust
#[test]
fn inode_key_dev_matches_mkdev_for_sda2() {
    // /dev/sda2 → major=8 minor=2.
    // statx() / stat() returns the encoded form 0x802.
    // Kernel-internal MKDEV form is 0x800002.
    // Our converter must take 0x802 → 0x800002.
    assert_eq!(super::stat_dev_to_kernel_dev(0x802), 0x800002);
}
```

### 8.3 Verification plan

1. Apply patch, rebuild agent + ebpf, restart agent.
2. `bpftool map dump name PROTECTED_INODES` — expect key bytes
   `02 00 80 00 00 00 00 00 01 00 1c 00 00 00 00 00`
   (dev=0x800002, ino=0x1c0001).
3. Drop the immutable bit via the kernel-6.8 chattr gap, then run
   the failing case from §0:
   ```
   chmod 0777 /var/lib/northnarrow
   ```
   Expect:
   - rc = 1 (EPERM)
   - directory mode stays 0700
   - `trace_pipe` shows `…REACHED-MATCH` (not `…REACHED-MISS`)
   - audit ringbuffer emits an `FsProtectDenialRaw{operation=4}` record
4. Re-run the full attack matrix from §0. All five rows should flip
   from "attacker wins" to "blocked".

If step 2 still shows the wrong bytes, the converter is wrong — most
likely `libc::major` / `libc::minor` returning sign-extended values;
print `major/minor` from the agent startup log to confirm.

If step 3 still shows `…REACHED-MISS` even after the key bytes match,
there is a *second* bug (very unlikely given the byte-perfect map
contents this fix produces), and we'd next compare the BPF-side key
blob via a `bpf_printk!` of `key.dev` after constructing it. We
intentionally don't add that print pre-emptively to keep the hot
path clean.



---

## Resolution: dev_t encoding fix (8ff04c7, 2026-05-13)

### Root cause

Userland and kernel use different encodings for `dev_t` device identifiers:

- **Userland (`stat(2)`):** `meta.dev()` returns `new_encode_dev(MKDEV(major, minor))` — legacy compact form. For `/var/lib/northnarrow` on `/dev/sda2`: `MKDEV(8, 2) → 0x802 = 2050`.
- **Kernel (`super_block->s_dev`):** BPF-LSM hooks read `MKDEV(major, minor) = (major << 20) | minor`. Same device: `0x800002 = 8388610`.

The agent inserted PROTECTED_INODES keys using `meta.dev()` (stat form), while LSM hooks looked them up via `s_dev` (kernel form). The HashMap byte-compare failed silently: key `02 08 ...` ≠ stored `02 00 80 ...`. Every protected access produced `REACHED-MISS` in trace_pipe (32× MISS in iter2 pre-fix run).

This silently affected **all five FS hooks**: `inode_unlink`, `inode_rmdir`, `inode_rename`, `inode_setattr`, and `file_ioctl`. The previously documented "chattr bypass" was a symptom of the same root cause, not a Linux 6.8 LSM gap.

### Fix

`agent/src/anti_tamper/filesystem.rs`: new `stat_dev_to_kernel_dev()` helper converts userland-encoded `dev_t` to kernel MKDEV form before insertion. Startup log now prints both `st_dev` and `kernel_dev` for sanity-checking the conversion.

Unit tests:
- `stat_dev_to_kernel_dev_sda2` (0x802 → 0x800002)
- `stat_dev_to_kernel_dev_high_minor` (0x100801 → 0x800101)

### Live verification (2026-05-13, kernel 6.8.0-111-generic)

Startup log:
anti-tamper FS: directory inode registered in PROTECTED_INODES path=/var/lib/northnarrow st_dev=2050 kernel_dev=8388610 ino=1835288

`bpftool prog show | grep -c lsm` → **7** (task_kill + ptrace + 5 fs hooks).

Attack matrix:

| Attack | RC | LSM hook | Result |
|---|---|---|---|
| `chmod 0777 /var/lib/northnarrow` | 1 (EPERM) | `inode_setattr` | DENIED |
| `touch /var/lib/northnarrow/canary` | 1 (EPERM) | `inode_setattr` | DENIED |
| `mv /var/lib/northnarrow /var/lib/northnarrow.attk` | 1 (EPERM) | `inode_rename` | DENIED |
| `rm -rf /var/lib/northnarrow` | 1 (EPERM) | `inode_rmdir` | DENIED |
| `chattr -i /var/lib/northnarrow` | 1 (EPERM) | `file_ioctl` (FS_IOC_SETFLAGS) | DENIED |
| `kill -TERM <agent_pid>` (reverse) | 1 (EPERM) | `task_kill` | DENIED |

**Zero residual bypasses on the tested attack surface.** The "Known bypass: chattr on Linux 6.8" entry is marked RESOLVED — it was caused by the same dev_t mismatch, not a kernel LSM gap.

### Files modified
- `agent/src/anti_tamper/filesystem.rs` — `stat_dev_to_kernel_dev()` helper + updated startup log line

