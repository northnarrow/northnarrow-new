//! Lot 318 — the kernel halves of the external bug hunt's edition 1.4
//! (BUG37's residue, BUG101, BUG108 and N9): the parts no host test runs.
//! The eBPF programs run only in a kernel (the lab's rounds and the
//! privileged e2e show what they do); here the code is read, as
//! `self_defense.rs` and `cgroup_guard.rs` read theirs: each check a fix
//! rests on is there, in the order that makes it hold, and the fragile
//! pattern is gone from everywhere else.

mod support;

use std::fs;

use support::{repo_root, strip_comments};

fn code(rel: &str) -> String {
    strip_comments(
        &fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")),
    )
}

/// `needles` all in `hay`, in this order.
fn in_order(hay: &str, needles: &[&str]) -> Result<(), String> {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => return Err(format!("{n:?} not found after byte {at}")),
        }
    }
    Ok(())
}

/// The body of `fn name` (to its matching brace).
fn body<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = start + code[start..].find('{').expect("a body");
    let len = support::matching_brace(&code[open..]);
    &code[open..open + len]
}

/// The name of the function each match of `needle` in `code` is in.
fn callers(code: &str, needle: &str) -> Vec<String> {
    let mut out: Vec<String> = code
        .match_indices(needle)
        .map(|(at, _)| {
            let start = code[..at].rfind("fn ").unwrap_or(0);
            let end = code[start..].find('(').map_or(code.len(), |p| start + p);
            code[start..end].to_string()
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Lot 318 (the review of #545, F5): every use of the shared denial ring
/// in `code` (file `rel`): `the map` for its `#[map]` definition, else the
/// function it is in — whatever the method (`reserve`, `output`, a
/// reference taken to it): a writer that would bypass the budgets by
/// another call than `reserve` is caught too.
fn ring_users(rel: &str, code: &str) -> Vec<String> {
    let mut out: Vec<String> = code
        .match_indices("FS_PROTECT_EVENTS")
        .map(|(at, _)| {
            let line_start = code[..at].rfind('\n').map_or(0, |p| p + 1);
            if code[line_start..at].contains("static ") {
                return format!("{rel}: the map");
            }
            let start = code[..at].rfind("fn ").unwrap_or(0);
            let end = code[start..].find('(').map_or(code.len(), |p| start + p);
            format!("{rel}: {}", &code[start..end])
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Lot 318 (the review of #545, F5): the ring's users are found whatever
/// the call — a planted `output` writer and a reference passed on are
/// caught, as `reserve` is.
#[test]
fn a_planted_writer_of_the_denial_ring_is_caught_whatever_the_call() {
    let planted = "fn emit_denial_kind(operation: u8) {\n    let _ = crate::inode_protect::FS_PROTECT_EVENTS.output(&rec, 0);\n}\nfn sneaky() {\n    write_to(&FS_PROTECT_EVENTS);\n}\n";
    assert_eq!(
        ring_users("agent-ebpf/src/bpf_defense.rs", planted),
        [
            "agent-ebpf/src/bpf_defense.rs: fn emit_denial_kind",
            "agent-ebpf/src/bpf_defense.rs: fn sneaky",
        ]
    );
    let map =
        "#[map]\npub static FS_PROTECT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);\n";
    assert_eq!(
        ring_users("agent-ebpf/src/inode_protect.rs", map),
        ["agent-ebpf/src/inode_protect.rs: the map"]
    );
}

/// External bug hunt BUG37 (the residue lot 293 left, triage "parziale"):
/// every write of the shared denial ring goes behind a budget. The BPF
/// guard's refusals (`bpf_handle`, `bpf_map`, `bpf_link`, `bpf_prog_type`,
/// `bpf_prog_opt_out`, `sysctl_root_attach`) wrote the ring themselves: a
/// root loop of `BPF_MAP_GET_FD_BY_ID` on one of the agent's maps filled it
/// and the record of a refused `kill` was lost. Now the ring is reserved in
/// two places only — the unbudgeted writer, private to `inode_protect`
/// (called by the budgeted emitters only), and the sysctl record with its
/// own budget — and the BPF guard's writer is `emit_attempt`.
#[test]
fn every_write_of_the_denial_ring_is_behind_a_budget() {
    let root = repo_root();
    let mut files = Vec::new();
    support::rs_files(&root.join("agent-ebpf/src"), &mut files);
    let mut users = Vec::new();
    for f in &files {
        let c = strip_comments(&fs::read_to_string(f).unwrap());
        let rel = f.strip_prefix(&root).unwrap().display().to_string();
        users.extend(ring_users(&rel, &c));
    }
    users.sort();
    assert_eq!(
        users,
        [
            "agent-ebpf/src/inode_protect.rs: fn emit_denial",
            "agent-ebpf/src/inode_protect.rs: fn emit_sysctl_record",
            "agent-ebpf/src/inode_protect.rs: the map",
        ],
        "the denial ring used outside the map and the two budgeted writers"
    );
    let i = code("agent-ebpf/src/inode_protect.rs");
    // the unbudgeted writer is the module's own: the compiler keeps every
    // other module out of it
    assert!(
        i.contains("\nfn emit_denial(operation: u8, key: InodeKey) {"),
        "emit_denial is visible outside inode_protect"
    );
    // the BPF guard's refusals: behind the attempt budget
    let b = code("agent-ebpf/src/bpf_defense.rs");
    let k = body(&b, "emit_denial_kind");
    in_order(
        k,
        &[
            "crate::inode_protect::emit_attempt(",
            "operation,",
            "InodeKey {",
            "dev: kind as u64,",
            "ino: object_id as u64,",
        ],
    )
    .unwrap();
    assert!(!k.contains(".reserve"), "{k}");
    assert!(body(&b, "emit_denial").contains("emit_denial_kind(operation, 0, object_id)"));
    // and the attempt budget is the one lot 293 measured (no dedup by
    // caller, its own per-CPU counter, the self-test outside it)
    in_order(
        body(&i, "emit_attempt"),
        &[
            "if caller_is_self_test() {",
            "emit_denial(operation, key);",
            "return;",
            // lot 318 (the review of #545, F1): the non-decisive refusals
            // spend a budget of their own, before the decisive budget
            "if northnarrow_common::wire::is_minor_denial(operation) {",
            "if minor_budget() {",
            "emit_denial(operation, key);",
            "return;",
            "if attempt_budget() {",
            "emit_denial(operation, key);",
        ],
    )
    .unwrap();
    assert!(i.contains(
        "static MINOR_DENIAL_RATE: PerCpuArray<[u64; 2]> = PerCpuArray::with_max_entries(1, 0);"
    ));
    in_order(
        body(&i, "minor_budget"),
        &[
            "MINOR_DENIAL_RATE.get_ptr_mut(0)",
            "if (*rate)[1] >= MINOR_DENIAL_PER_SEC {",
            "ring_slot::MINOR_DENIAL_RATE",
            "return false;",
            "(*rate)[1] += 1;",
        ],
    )
    .unwrap();
    assert!(!body(&i, "minor_budget").contains("ATTEMPT_DENIAL_RATE"));
    assert!(!body(&i, "attempt_budget").contains("MINOR_DENIAL_RATE"));
    // the re-check of #545, R2: the rate-limited records (the task denials,
    // a write through a descriptor, a sysctl's refusal or opt-out) spend
    // the minor budget when not decisive, the task denials' when decisive
    in_order(
        body(&i, "limited_budget"),
        &[
            "if northnarrow_common::wire::is_minor_denial(operation) {",
            "return minor_budget();",
            "TASK_DENIAL_RATE.get_ptr_mut(0)",
            "if (*rate)[1] >= TASK_DENIAL_PER_SEC {",
            "ring_slot::TASK_DENIAL_RATE",
            "return false;",
        ],
    )
    .unwrap();
    for writer in ["emit_limited", "emit_sysctl_record"] {
        let w = body(&i, writer);
        assert!(
            w.contains("if !limited_budget(operation, now) {"),
            "{writer}: {w}"
        );
        assert!(
            !w.contains("TASK_DENIAL_RATE"),
            "{writer} spends a budget of its own"
        );
    }
    let w = code("common/src/wire/mod.rs");
    in_order(
        body(&w, "is_minor_denial"),
        &[
            "FS_OP_READ",
            "| FS_OP_BPF_HANDLE",
            "| FS_OP_BPF_PROG_TYPE",
            "| FS_OP_BPF_PROG_OPT_OUT",
            "| FS_OP_SYSCTL_ROOT_ATTACH",
            // the re-check, R1: the switches refused at the write-open
            "| FS_OP_KPROBES",
            "| FS_OP_LOCKDOWN",
            // R2: the task denials' budget, the decisive ones' alone
            "| FS_OP_SCHED",
            "| FS_OP_NICE",
            "| FS_OP_IOPRIO",
            "| FS_OP_SYSCTL",
        ],
    )
    .unwrap();
    // their drops are no security loss (F7); a decisive drop is one at once
    let r = code("crates/nn-linux/src/sensors/ring_drops.rs");
    assert!(r.contains(
        "pub const DECISIVE_DENIAL_BUDGETS: [u32; 2] = [ring_slot::DENIAL_RATE, ring_slot::TASK_DENIAL_RATE];"
    ));
    let sec = &r[r.find("pub const SECURITY_RINGS").unwrap()..];
    let sec = &sec[..sec.find("];").unwrap()];
    assert!(!sec.contains("MINOR_DENIAL_RATE"), "{sec}");
}

/// External bug hunt BUG101 (the kernel half; the record's is lot 315's):
/// the environment's deny does not depend on the target's set-id bits. It
/// was skipped for every set-id target ("the kernel sets AT_SECURE"): root
/// running a set-uid-root file (`su`) keeps its credentials and the loader
/// honours `LD_PRELOAD`, and so do a set-id file under `no_new_privs`, on a
/// `nosuid` mount, a set-id `#!` script and an owner a user namespace does
/// not map. The bits still decide what `GLIBC_TUNABLES` is reported at.
#[test]
fn a_set_id_target_does_not_escape_the_environment_deny() {
    let e = code("agent-ebpf/src/execpol.rs");
    let p = body(&e, "on_pass");
    in_order(
        p,
        &[
            "let setid = mode_bits & 0o6000 != 0;",
            "let root = tv & tier_sig::ROOT != 0;",
            "let env_deny_rule = conf(conf_slot::ENV_DENY) & tb != 0",
            "|| (root && conf(conf_slot::ENV_DENY_ROOT) & tb != 0);",
            // lot 325 (R2): the bits make an unfinished environment fail
            // closed — stricter, never an exemption
            "let unfinished = ef & env_flags::UNFINISHED != 0 && (env_deny_rule || setid);",
            "if (ef & env_flags::DENYABLE != 0 && env_deny_rule) || unfinished {",
            "env_act |= action::DENY;",
            "|| (setid && ef & env_flags::GLIBC_TUNABLES != 0);",
        ],
    )
    .unwrap();
    // the bits are read for the tunables' report and (lot 325) to refuse an
    // environment the scan could not finish, nothing else
    assert_eq!(
        p.matches("setid").count(),
        3,
        "the set-id bits decide something besides GLIBC_TUNABLES' report and lot 325's \
         fail-closed:\n{p}"
    );
    assert!(!p.contains("!setid"), "{p}");
    // the operator's document says so
    let d = fs::read_to_string(repo_root().join("docs/design/EXEC_POLICY.md")).unwrap();
    let flat = d.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !flat.contains("| the same at a **set-id target** | never denied |"),
        "EXEC_POLICY.md still says a set-id target is never denied"
    );
    for needle in [
        "a set-id target is denied as any other",
        "`setpriv --no-new-privs`",
    ] {
        assert!(flat.contains(needle), "EXEC_POLICY.md: missing {needle:?}");
    }
}

/// External bug hunt BUG108 (the kernel half; the published roots are lot
/// 311b's): a guarded mount is found by the identity of an ancestor — the
/// root of the mount at the guarded point — not by where the dentry walk
/// ends. On Fedora's and openSUSE's layout (`/home` a btrfs subvolume) the
/// walk ends on the top-level subvolume, and for a directory bound at
/// `/home` on its filesystem's root; neither is a key the agent publishes,
/// and the home had no class. The search reads each level's device as
/// `stat()` does (a btrfs subvolume's own) and runs whatever the walk
/// found. The re-check of #545 (R3): it stops at the task's own root — it
/// ignored it, and a container whose root is a directory in a home (an
/// unprivileged LXC container's `rootfs`, rootless podman's vfs or btrfs
/// storage) took that home's class above its root: every program of its
/// image, owned by its root (a host subuid), was `other_home`.
#[test]
fn a_guarded_mount_is_found_by_an_ancestor_s_identity() {
    let q = code("agent-ebpf/src/execq.rs");
    let c = body(&q, "classify");
    // after the names of the task's view, outside their branch
    in_order(
        c,
        &[
            "if flags & exe_flags::UNRESOLVED != 0 {",
            "} else if flags & exe_flags::TASK_ROOT != 0 {",
            "let g = nn_guarded_root(dentry as u64, task_root as u64);",
            "if g & GUARDED_ROOT_FOUND != 0 {",
            // a guarded point's own identity gives its path class only
            "if v & root_kind::GUARDED != 0 {",
            "c |= class::GUARDED_MOUNT;",
            "if v & root_kind::HOME != 0 {",
            "c |= class::HOME;",
            "if c & class::HOME != 0 {",
        ],
    )
    .unwrap();
    // the walk's end alone no longer decides
    assert!(!c.contains("root_dev"), "{c}");
    assert!(!c.contains("root_ino"), "{c}");
    // the map is read in `classify` only for a FUSE mount's device key
    assert_eq!(c.matches("EXECQ_ROOTS").count(), 1, "{c}");
    assert!(
        c.contains("if let Some(v) = EXECQ_ROOTS.get(&key) {"),
        "{c}"
    );
    assert!(q.contains(
        "#[no_mangle]\n#[inline(never)]\npub extern \"C\" fn nn_guarded_root(dentry: u64, task_root: u64) -> u64 {"
    ));
    assert!(c.contains(
        "let task_root =\n        crate::exec_lsm::task_root_of(aya_ebpf::helpers::bpf_get_current_task() as *const u8);"
    ));
    let g = body(&q, "guarded_root");
    in_order(
        g,
        &[
            "let sb = peek_u64(file_inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;",
            "let devs = crate::inode_dev::SbDev::of(sb,",
            "let mut d = peek_u64(dentry.add(o_parent)) as *const u8;",
            "for _ in 0..EXE_WALK_DEPTH {",
            // R3: not past the task's root
            "if d.is_null() || d == task_root {",
            "break;",
            "dev: u64::from(devs.dev(inode)),",
            "ino: peek_u64(inode.add(o_ino)),",
            "if let Some(v) = EXECQ_ROOTS.get(&key) {",
            "return GUARDED_ROOT_FOUND | u64::from(*v);",
            "if up == d {",
            "break;",
            "d = up;",
        ],
    )
    .unwrap();
    // the task's root is the walk's and the search's one reading
    let l = code("agent-ebpf/src/exec_lsm.rs");
    in_order(
        body(&l, "task_root_of"),
        &[
            "off_opt!(TASK_STRUCT_FS_OFFSET)",
            "off_opt!(FS_STRUCT_ROOT_OFFSET)",
            "+ off!(PATH_DENTRY_OFFSET))) as *const u8;",
        ],
    )
    .unwrap();
    assert!(body(&l, "try_exec_check_lsm").contains("let task_root = task_root_of(task);"));
    let p = code("agent-ebpf/src/execpol.rs");
    assert!(body(&p, "map_classify").contains("crate::exec_lsm::task_root_of("));
    // a btrfs subvolume's device, read as stat() does: the flag, not an
    // offset of 0, says the three offsets resolved (btrfs_inode.root is at
    // byte 0)
    let d = code("agent-ebpf/src/inode_dev.rs");
    in_order(
        body(&d, "of"),
        &[
            "if magic != BTRFS_SUPER_MAGIC {",
            "return d;",
            "off_opt!(BTRFS_INODE_ROOT_OFFSET)",
            "off_opt!(BTRFS_INODE_VFS_INODE_OFFSET)",
            "off_opt!(BTRFS_ROOT_ANON_DEV_OFFSET)",
            "if have == 3 {",
            "d.btrfs = 1;",
        ],
    )
    .unwrap();
    in_order(
        body(&d, "dev"),
        &[
            "if self.btrfs == 0 {",
            "return self.s_dev;",
            "(inode as usize).wrapping_sub(self.vfs_off)",
            "bi.add(self.root_off)",
            "root.add(self.anon_off)",
        ],
    )
    .unwrap();
    // room for every guarded root a user can make: FUSE's `mount_max` is
    // 1000, and 64 filled up unseen (lot 318's mini-hunt)
    assert!(q.contains(
        "pub static EXECQ_ROOTS: HashMap<ExecqKey, u32> = HashMap::with_max_entries(EXECQ_ROOTS_CAPACITY, 0);"
    ));
    assert!(q.contains("pub const EXECQ_ROOTS_CAPACITY: u32 = 1024;"));
    // both classifications use it: the exec pass's and the mapping's
    let e = code("agent-ebpf/src/execpol.rs");
    assert!(body(&e, "map_classify").contains("crate::execq::classify(s, dentry, (*s).flags)"));
    assert!(
        body(&q, "nn_execq_classify").contains("classify(s, dentry as *const u8, flags as u32)")
    );
}

/// BUG108's variant found by lot 318's mini-hunt: a file whose walk finds
/// no root within its 64 levels had no path class — a user makes such a
/// path anywhere they write (65 `mkdir`s by relative paths), and a binary
/// there was neither held nor judged by a cell. Now it is classed where a
/// user writes: tmp, var_tmp and home (other_home by its owner).
#[test]
fn a_file_the_walk_cannot_place_is_classed_where_a_user_writes() {
    let q = code("agent-ebpf/src/execq.rs");
    let c = body(&q, "classify");
    in_order(
        c,
        &[
            "if flags & exe_flags::UNRESOLVED != 0 {",
            "c |= class::TMP | class::VAR_TMP | class::HOME;",
            "} else if flags & exe_flags::TASK_ROOT != 0 {",
            "if c & class::HOME != 0 {",
            "c |= class::OTHER_HOME;",
        ],
    )
    .unwrap();
    // no early return before the classes are complete
    let unresolved = c.find("if flags & exe_flags::UNRESOLVED != 0 {").unwrap();
    assert!(!c[..unresolved].contains("return"), "{c}");
}

/// External bug hunt N9 (the sensor's half of BUG83; the rule's is lot
/// 314's): the io_uring sensor's per-process state goes with the process.
/// `IOURING_STATE` was never removed, and a process that reused the pid
/// inherited the classes of the one before it. A `sched_process_exit`
/// program removes it when the thread group is dead (`signal->live` is 0;
/// the leader's exit without the offsets), attached with the submit
/// program; not attached, the start says so (signed degradation).
#[test]
fn the_io_uring_state_goes_with_the_process() {
    let u = code("agent-ebpf/src/io_uring.rs");
    assert!(u.contains("#[tracepoint]\npub fn io_uring_exit(_ctx: TracePointContext) -> u32 {"));
    in_order(
        body(&u, "try_exit"),
        &[
            "let tgid = (pid_tgid >> 32) as u32;",
            "if IOURING_STATE.get(&tgid).is_none() && IOURING_TASK_BUDGET.get(&tgid).is_none() {",
            "return;",
            "if group_dead().unwrap_or(tgid == pid_tgid as u32) {",
            "let _ = IOURING_STATE.remove(&tgid);",
            "let _ = IOURING_TASK_BUDGET.remove(&tgid);",
        ],
    )
    .unwrap();
    in_order(
        body(&u, "group_dead"),
        &[
            "let o_signal = off_opt!(TASK_STRUCT_SIGNAL_OFFSET)?",
            "let o_live = off_opt!(SIGNAL_STRUCT_LIVE_OFFSET)?",
            "if signal == 0 {",
            "return None;",
            "Some(live == 0)",
        ],
    )
    .unwrap();
    assert_eq!(
        callers(&u, "IOURING_STATE.remove("),
        ["fn try_exit"],
        "IOURING_STATE removed elsewhere"
    );
    let m = code("crates/nn-linux/src/sensors/multiplexer.rs");
    assert!(m.contains("pub const IO_URING_EXIT_PROGRAM: &str = \"io_uring_exit\";"));
    let flat = m.replace(char::is_whitespace, "");
    in_order(
        &flat,
        &[
            "attach_tracepoint(&mutebpf,\"io_uring_create\",\"io_uring\",\"io_uring_create\")",
            "&[\"io_uring_submit_req\",\"io_uring_submit_sqe\"],",
            "Ok(name)=>{",
            "attach_tracepoint(&mutebpf,IO_URING_EXIT_PROGRAM,\"sched\",\"sched_process_exit\",)",
            "crate::boot::degradation::report(\"io_uring_sensor\",",
        ],
    )
    .unwrap();
}

/// The review of #538, F1 and F3 (N8's kernel half, given to lot 318): a
/// file of a FUSE filesystem outside the task's own root is guarded by its
/// superblock's magic (fuse, fuseblk, virtiofs), whatever the published
/// roots say and whether or not the map had room. A user's FUSE daemon
/// answers every GETATTR, the root's included, and the kernel takes the
/// inode number it gives: no key by inode can name a FUSE root. The agent
/// (lot 311b) publishes a FUSE mount by its device alone, `(s_dev,
/// FUSE_BY_DEVICE)` with `FUSE_BY_DEVICE = 0` on both sides; found, the
/// point's kind applies, else the file is classed where a user writes.
/// Inside the task's root (a virtiofs root filesystem) the names decide.
#[test]
fn a_fuse_file_is_guarded_whatever_its_root_says() {
    let q = code("agent-ebpf/src/execq.rs");
    assert!(q.contains("const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;"));
    assert!(q.contains("const FUSE_BY_DEVICE: u64 = 0;"));
    in_order(
        body(&q, "fuse_dev"),
        &[
            "let inode = peek_u64(dentry.add(off!(DENTRY_D_INODE_OFFSET))) as *const u8;",
            "let sb = peek_u64(inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;",
            "if peek_u64(sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET))) != FUSE_SUPER_MAGIC {",
            "return 0;",
            "if fs_type_is_virtiofs(sb) {",
            "return 0;",
            "FUSE_DEV_FOUND | u64::from(peek_u32(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET))))",
        ],
    )
    .unwrap();
    // virtiofs (a VM's or a Kata container's shared directory) shares the
    // magic: told apart by `sb->s_type->name`, through the shared check the
    // host tests (`wire::execq::is_virtiofs_name`)
    in_order(
        body(&q, "fs_type_is_virtiofs"),
        &[
            "off_opt!(SUPER_BLOCK_S_TYPE_OFFSET)",
            "off_opt!(FILE_SYSTEM_TYPE_NAME_OFFSET)",
            "let ty = peek_u64(sb.add(o_type & 0xffff)) as *const u8;",
            "let name = peek_u64(ty.add(o_name & 0xffff)) as *const u8;",
            "generated::bpf_probe_read_kernel_str(wp as *mut c_void, 16, name as *const c_void)",
            "northnarrow_common::wire::execq::is_virtiofs_name(w[0], w[1])",
        ],
    )
    .unwrap();
    let w = code("common/src/wire/execq.rs");
    assert!(w.contains(
        "pub const fn is_virtiofs_name(w0: u64, w1: u64) -> bool {\n    w0 == u64::from_le_bytes(*b\"virtiofs\") && w1 & 0xff == 0\n}"
    ));
    let c = body(&q, "classify");
    in_order(
        c,
        &[
            "let g = nn_guarded_root(dentry as u64, task_root as u64);",
            "let fuse = if flags & exe_flags::TASK_ROOT == 0 {",
            "fuse_dev(dentry)",
            "if fuse != 0 {",
            "c |= class::GUARDED_MOUNT;",
            "dev: fuse & FUSE_DEV_MASK,",
            "ino: FUSE_BY_DEVICE,",
            "if let Some(v) = EXECQ_ROOTS.get(&key) {",
            "g = GUARDED_ROOT_FOUND | u64::from(*v);",
            "} else if g & GUARDED_ROOT_FOUND == 0 {",
            "c |= class::TMP | class::VAR_TMP | class::HOME;",
            "if g & GUARDED_ROOT_FOUND != 0 {",
            "if c & class::HOME != 0 {",
        ],
    )
    .unwrap();
    // the user-space half's constant (lot 311b), and its key: the device
    // alone, never a stat of the root (the review of #545, F3)
    let k = code("agent/src/execq/kernel.rs");
    assert!(
        k.contains("pub const FUSE_BY_DEVICE: u64 = 0;"),
        "the agent keys a FUSE mount with another inode than the kernel's"
    );
    in_order(
        body(&k, "guarded_roots"),
        &[
            "let key = if nn_linux::mountinfo::is_fuse(&m.fstype) {",
            "dev: m.kernel_dev(),",
            "ino: FUSE_BY_DEVICE,",
        ],
    )
    .unwrap();
}

/// The review of #545, F2 (BUG108 on openSUSE's and ostree's layouts): the
/// guarded points themselves are published by their identity — `stat()`,
/// the link followed, a btrfs subvolume's device — beside the guarded
/// mounts' roots, by both controllers; their kind carries no `GUARDED`
/// bit, and the kernel adds `guarded_mount` for a mount's root only.
#[test]
fn the_guarded_points_are_published_by_identity() {
    let k = code("agent/src/execq/kernel.rs");
    assert!(k.contains(
        "pub const GUARDED_POINTS: [&str; 5] = [\"/tmp\", \"/var/tmp\", \"/home\", \"/root\", \"/dev/shm\"];"
    ));
    in_order(
        body(&k, "point_roots<'a>"),
        &[
            "let kind = root_kind_of(point) & !root_kind::GUARDED;",
            "let Ok(st) = std::fs::metadata(path) else {",
            "if !st.is_dir() {",
            "dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(st.dev()),",
            "ino: st.ino(),",
        ],
    )
    .unwrap();
    in_order(
        body(&k, "published_roots"),
        &[
            "let mut out = guarded_roots(table);",
            "point_roots(GUARDED_POINTS",
        ],
    )
    .unwrap();
    for ctl in [
        "agent/src/execq/controller.rs",
        "agent/src/execpol/controller.rs",
    ] {
        let c = code(ctl);
        assert!(c.contains("published_roots("), "{ctl}");
        assert!(
            !c.contains("guarded_roots("),
            "{ctl} publishes the mounts alone"
        );
    }
}
