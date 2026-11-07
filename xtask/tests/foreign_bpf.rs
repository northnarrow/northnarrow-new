//! Lot 290: foreign BPF — the parts no host test runs. The eBPF programs
//! run only in a kernel (the lab's `nn-lab.sh foreign-bpf-check` shows what
//! they refuse, record and enumerate); here the code is read: each check
//! the defence rests on is there, in the order that makes it hold, and the
//! agent wires it where it decides.

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

/// Named (item 2): a load of a refused type by a caller outside the family
/// is refused outside a window, past a fresh instance, unless the signed
/// opt-out names its executable and the type — in EVERY mode (no
/// `enforce()` on the path), before the observation; the opt-out reads the
/// caller's executable by device and inode.
#[test]
fn the_bpf_hook_refuses_the_rootkit_grade_types_in_every_mode() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    let h = body(&c, "try_bpf_syscall_observe");
    in_order(
        h,
        &[
            "if !observed(cmd) {\n        return 0;\n    }",
            "if caller_is_exempt() {",
            "if cmd == BPF_PROG_LOAD {\n            crate::bpf_census::mark_load();\n        }\n        return 0;\n    }",
            "| BPF_PROG_LOAD",
            "crate::fail_open::bump(fail_open_hook::BPF);",
            "if cmd == BPF_PROG_LOAD {\n        if denied_by_default(arg)\n            && !crate::inode_protect::override_active()\n            && !fresh_instance_may_load()\n        {",
            "if nn_loader_opted_out(u64::from(arg)) != LOADER_OPTED_OUT {\n                emit_denial(FS_OP_BPF_PROG_TYPE, arg);\n                return -EPERM;\n            }",
            "emit_denial(FS_OP_BPF_PROG_OPT_OUT, arg);",
            "crate::bpf_census::mark_load();",
            "should_report(pid, dedup)",
        ],
    )
    .unwrap();
    let start = h
        .find("if cmd == BPF_PROG_LOAD {\n        if denied_by_default(arg)")
        .expect("the load's refusal");
    let load = &h[start..start + h[start..].find("crate::bpf_census::mark_load();").unwrap()];
    assert!(
        !load.contains("enforce()"),
        "the type refusal holds in every mode"
    );
    in_order(
        body(&c, "nn_loader_opted_out"),
        &[
            "let bit = type_bit(prog_type as u32);",
            "caller_exe_key()",
            "BPF_LOADER_OPTOUT.get(&k)",
            "Some(mask) if *mask & bit != 0 => LOADER_OPTED_OUT,",
        ],
    )
    .unwrap();
    assert!(c.contains(
        "pub static BPF_LOADER_OPTOUT: HashMap<InodeKey, u32> = HashMap::pinned(64, 0);"
    ));
    // the types are common's, the hook calls its function
    let k = code("common/src/bpf_prog_class.rs");
    assert!(k.contains(
        "PROG_TYPE_KPROBE | PROG_TYPE_TRACING | PROG_TYPE_STRUCT_OPS | PROG_TYPE_EXT | PROG_TYPE_LSM"
    ));
}

/// Named (item 1): a handle on one of the agent's maps or programs by id,
/// and an `OBJ_GET` of a path under its pin directories, refused outside a
/// window in enforce mode (the link refusal unchanged, before it); the
/// `bpf_map` guard refuses a READ handle too (any path), the `bpf_prog`
/// guard a program handle (any path); a write handle stays refused in a
/// window.
#[test]
fn the_agent_s_maps_and_programs_are_off_limits_outside_a_window() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    let h = body(&c, "try_bpf_syscall_observe");
    in_order(
        h,
        &[
            "let own_map_handle = cmd == BPF_MAP_GET_FD_BY_ID && is_own_kind(arg, OWN_KIND_MAP);",
            "let own_prog_handle = cmd == BPF_PROG_GET_FD_BY_ID && is_own_kind(arg, OWN_KIND_PROG);",
            "let own_link_handle = cmd == BPF_LINK_GET_FD_BY_ID && is_own_kind(arg, OWN_KIND_LINK);",
            "Ok(p) => nn_obj_get_own_link(p),",
            "if pin == PIN_UNREADABLE {\n        crate::fail_open::bump(fail_open_hook::BPF);\n    }",
            "let own_dir_pin = pin == PIN_UNDER_DIRS;",
            "if (own_link_handle || own_link_pin) && enforce() {\n        emit_denial(FS_OP_BPF_LINK,",
            "if (own_map_handle || own_prog_handle || own_dir_pin)\n        && enforce()\n        && !crate::inode_protect::override_active()\n        && !fresh_instance_may_load()\n    {",
            "emit_denial_kind(FS_OP_BPF_HANDLE, kind, if kind == 0 { 0 } else { arg });\n        return -EPERM;",
        ],
    )
    .unwrap();
    assert!(c.contains("const PIN_DIRS_PREFIX: &[u8; 23] = b\"/sys/fs/bpf/northnarrow\";"));
    in_order(
        body(&c, "obj_get_names_own_link"),
        &[
            "let n = match bpf_probe_read_user_str_bytes(user_ptr as *const u8, &mut *buf) {",
            "let mut under = n >= PIN_DIRS_PREFIX.len();",
            "if (*buf)[k] != PIN_DIRS_PREFIX[k] {\n            under = false;",
            "let other: u64 = if under { PIN_UNDER_DIRS } else { 0 };",
            "let m = match bpf_probe_read_user_str_bytes(win_ptr as *const u8, win) {",
            "Some(kind) if *kind == OWN_KIND_LINK => PIN_OWN,\n        _ => other,",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "try_bpf_map_guard"),
        &[
            "let write = fmode & FMODE_WRITE != 0;",
            "if !write && (!enforce() || crate::inode_protect::override_active()) {\n        return 0;\n    }",
            "if !is_own_kind(id, OWN_KIND_MAP) || caller_is_exempt() || fresh_instance_may_load() {",
            "if !write {",
            "emit_denial_kind(FS_OP_BPF_HANDLE, OWN_KIND_MAP, id);\n        return -EPERM;",
            "if enforce() {\n        emit_denial(FS_OP_BPF_MAP, id);\n        return -EPERM;\n    }",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "try_bpf_prog_guard"),
        &[
            "let loading = crate::bpf_census::take_load_mark();",
            "let id = match prog_id_of(prog) {",
            "if loading {\n        crate::bpf_census::mark_seen(id, prog);\n        return 0;\n    }",
            "if !is_own_kind(id, OWN_KIND_PROG) || caller_is_exempt() || fresh_instance_may_load() {",
            "if enforce() && !crate::inode_protect::override_active() {\n        emit_denial_kind(FS_OP_BPF_HANDLE, OWN_KIND_PROG, id);\n        return -EPERM;",
        ],
    )
    .unwrap();
    assert!(
        c.contains("#[lsm(hook = \"bpf_prog\")]\npub fn bpf_prog_guard(ctx: LsmContext) -> i32 {")
    );
    // the agent attaches it and registers it as its own
    let u = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    in_order(
        body(&u, "attach"),
        &[
            "antitamper_bpf::attach_transient(ebpf, OBSERVE_PROGRAM, OBSERVE_HOOK, btf)",
            "antitamper_bpf::attach_transient(ebpf, PROG_GUARD_PROGRAM, PROG_GUARD_HOOK, btf)",
            "crate::bpf_crossview::Parts::setup(ebpf, btf)",
        ],
    )
    .unwrap();
}

/// Named (item 4): a load the hook let through marks its thread, a handle
/// command clears it, the `bpf_prog` hook takes the mark before anything
/// else and records the program's id with its loader; the iterators write
/// whole records through the typed seq file.
#[test]
fn a_seen_load_is_marked_and_the_iterators_write_whole_records() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    in_order(
        body(&c, "try_bpf_syscall_observe"),
        &[
            "crate::bpf_census::mark_load();",
            "} else if matches!(cmd, BPF_PROG_GET_FD_BY_ID | BPF_OBJ_GET) {",
            "crate::bpf_census::clear_load_mark();",
        ],
    )
    .unwrap();
    let k = code("agent-ebpf/src/bpf_census.rs");
    in_order(
        body(&k, "take_load_mark"),
        &[
            "let marked = unsafe { PROG_LOAD_INFLIGHT.get(&tid) }.is_some();",
            "let _ = PROG_LOAD_INFLIGHT.remove(&tid);",
            "marked",
        ],
    )
    .unwrap();
    in_order(
        body(&k, "mark_seen"),
        &[
            "tgid: (pid_tgid >> 32) as u32,",
            "let _ = SEEN_PROGS.insert(&id, &seen, 0);",
        ],
    )
    .unwrap();
    assert!(k.contains(
        "#[link_section = \"iter/bpf_prog\"]\npub fn nn_iter_progs(ctx: *mut c_void) -> i32 {"
    ));
    assert!(k.contains(
        "#[link_section = \"iter/bpf_link\"]\npub fn nn_iter_links(ctx: *mut c_void) -> i32 {"
    ));
    in_order(
        body(&k, "try_iter_progs"),
        &[
            "let meta = *(ctx as *const *const *mut c_void);",
            "let prog = *(ctx as *const u64).add(1);",
            "if prog == 0 || meta.is_null() {\n        return;\n    }",
            "let seq = *meta;",
            "crate::zero::zero(rec);",
            "(*rec).id = id;",
            "core::mem::size_of::<ProgRecord>() as u32,",
        ],
    )
    .unwrap();
    in_order(
        body(&k, "try_iter_links"),
        &[
            "let seq = *meta;",
            "core::mem::size_of::<LinkRecord>() as u32,",
        ],
    )
    .unwrap();
}

/// Named (item 4): the kernel-state round runs the cross-view each round
/// and signs its findings through the bus; the start hands it the guard's
/// parts; the own programs are both registrations'.
#[test]
fn the_cross_view_runs_in_the_kernel_state_round() {
    let k = code("crates/nn-linux/src/kernel_state.rs");
    in_order(
        body(&k, "spawn"),
        &[
            "let mut found = round(&mut w, Path::new(\"/\"));",
            "if let Some(c) = cross.as_mut() {\n                found.extend(crossview_round(c, &mut failing));",
            "tx.send(event_of(&f, monotonic_ns()))",
        ],
    )
    .unwrap();
    in_order(
        body(&k, "crossview_round"),
        &[
            "match cross.round() {",
            "found.into_iter().map(Finding::Bpf).collect()",
            "crate::boot::degradation::report(DEGRADATION, &line)",
        ],
    )
    .unwrap();
    let e = code("agent/src/boot/evidence.rs");
    in_order(
        &e,
        &[
            "let crossview = sensor.bpf_guard().crossview(",
            "nn_linux::kernel_state::spawn(sensor.event_tx_for(\"fs_protect\"), crossview);",
        ],
    )
    .unwrap();
    let u = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    assert!(body(&u, "register_own_objects")
        .contains("guard.0.own_progs.lock().extend(prog_ids.iter().copied());"));
    assert!(body(&u, "register_late_objects")
        .contains("guard.0.own_progs.lock().extend(prog_ids.iter().copied());"));
    let x = code("crates/nn-linux/src/bpf_crossview.rs");
    in_order(
        body(&x, "round"),
        &[
            "let seen = self.parts.seen()?;",
            "let en = self.parts.enumerate()?;",
            "let own = (self.own)();",
            "judge(&mut self.watch, seen, &en, &own)",
        ],
    )
    .unwrap();
}

/// Named (item 3): the configuration maps written once are frozen where
/// they are written; the per-loader opt-outs reach the kernel at the start,
/// at the registration and at `policy set`.
#[test]
fn the_configuration_maps_are_frozen_and_the_opt_out_is_applied() {
    let u = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    assert!(u.contains(
        "pub const FROZEN_AT_REGISTRATION: [&str; 3] = [MODE_MAP, OWN_EXE_MAP, PIN_NAMES_MAP];"
    ));
    in_order(
        body(&u, "register_own_objects"),
        &[
            "mode.set(0, if enforce { 1 } else { 0 }, 0)",
            "write_loader_opt_outs_object(ebpf)",
            "for (name, outcome) in freeze_config_maps(ebpf) {",
        ],
    )
    .unwrap();
    in_order(
        body(&u, "freeze_map"),
        &[
            "match fdinfo_frozen(&info) {",
            "Some(true) => return Ok(false),",
            "MAP_FREEZE,",
            "Ok(freeze_outcome(errno)? == Freeze::Now)",
        ],
    )
    .unwrap();
    in_order(
        body(
            &code("crates/nn-linux/src/sysctl_cgroup.rs"),
            "set_judge_flag",
        ),
        &["a.set(0, v, 0)", "freeze_named(ebpf, JUDGE_MAP)"],
    )
    .unwrap();
    in_order(
        body(
            &code("crates/nn-linux/src/sensors/dns_sensor.rs"),
            "exempt_resolvers",
        ),
        &[
            "exempt.insert(uid, 1, 0)",
            "freeze_named(ebpf, \"DNS_EXEMPT_UIDS\")",
        ],
    )
    .unwrap();
    in_order(
        body(&code("crates/nn-linux/src/sensors/connect_deny.rs"), "arm"),
        &["mode.set(0, 1, 0)", "freeze_named(ebpf, MAP_MODE)"],
    )
    .unwrap();
    in_order(
        body(&u, "apply_loader_policy"),
        &[
            "let (resolved, unresolved) = if signed {",
            "*LOADER_OPT_OUTS.write() = resolved;",
            "write_loader_opt_outs_pin(&pin)",
        ],
    )
    .unwrap();
    assert!(code("agent/src/boot/policy.rs")
        .contains("nn_linux::anti_tamper::bpf_defense::apply_loader_policy(&policy, signed)"));
    assert!(code("agent/src/admin/handlers/config.rs")
        .contains("nn_linux::anti_tamper::bpf_defense::apply_loader_policy("));
}

/// Named (lot 290, the lab's first start): `OWN_BPF_IDS` holds every map,
/// program and link of the object — at least twice its maps and programs
/// (a program has at most one link of its own here). At 256 the start of
/// this lot's object failed with `E2BIG` at the 257th registration.
#[test]
fn the_own_ids_map_holds_every_object_of_the_agent() {
    let dir = repo_root().join("agent-ebpf/src");
    let (mut maps, mut progs) = (0usize, 0usize);
    for e in fs::read_dir(&dir).unwrap().flatten() {
        let src = strip_comments(&fs::read_to_string(e.path()).unwrap());
        maps += src.matches("#[map]").count();
        progs += src
            .lines()
            .filter(|l| {
                let l = l.trim_start();
                [
                    "#[lsm(",
                    "#[kprobe",
                    "#[kretprobe",
                    "#[tracepoint",
                    "#[raw_tracepoint",
                    "#[btf_tracepoint",
                    "#[fentry",
                    "#[fexit",
                    "#[uprobe",
                    "#[cgroup_sysctl",
                    "#[link_section = \"",
                ]
                .iter()
                .any(|p| l.starts_with(p))
            })
            .count();
    }
    assert!(
        maps > 100 && progs > 90,
        "{maps} maps, {progs} programs counted"
    );
    let c = code("agent-ebpf/src/bpf_defense.rs");
    let cap: usize = c
        .split("pub const OWN_IDS_CAPACITY: u32 = ")
        .nth(1)
        .and_then(|r| r.split(';').next())
        .and_then(|v| v.trim().parse().ok())
        .expect("OWN_IDS_CAPACITY");
    assert!(
        cap >= 2 * (maps + progs),
        "OWN_BPF_IDS holds {cap}: the object has {maps} maps and {progs} programs"
    );
    assert!(c.contains("HashMap::with_max_entries(OWN_IDS_CAPACITY, 0);"));
}
