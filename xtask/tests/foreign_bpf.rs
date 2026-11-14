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
    // the types are common's, the hook calls its function: the nine, the
    // tracepoint and perf_event ones among them (the coordinator's decision
    // after the benign corpus)
    let k = code("common/src/bpf_prog_class.rs");
    assert!(k.contains(
        "        PROG_TYPE_KPROBE\n            | PROG_TYPE_TRACEPOINT\n            \
         | PROG_TYPE_PERF_EVENT\n            | PROG_TYPE_RAW_TRACEPOINT\n            \
         | PROG_TYPE_RAW_TRACEPOINT_WRITABLE\n            | PROG_TYPE_TRACING\n            \
         | PROG_TYPE_STRUCT_OPS\n            | PROG_TYPE_EXT\n            | PROG_TYPE_LSM\n    )"
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
    // the agent attaches it and registers it as its own (lot 302: pinned,
    // the bpf() guard with it — `the_bpf_guard_s_hooks_are_pinned`)
    let u = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    // whitespace aside (rustfmt breaks a long call over lines)
    let flat = |t: &str| t.replace(char::is_whitespace, "");
    in_order(
        &flat(body(&u, "attach")),
        &[
            "attach_guard_hook(ebpf,OBSERVE_PROGRAM,OBSERVE_HOOK,btf,pin_root,enforce",
            "attach_guard_hook(ebpf,PROG_GUARD_PROGRAM,PROG_GUARD_HOOK,btf,pin_root,enforce",
            "crate::bpf_crossview::Parts::setup(ebpf,btf)",
        ],
    )
    .unwrap();
}

/// Lot 302 (named, the host half of "the bpf guard denies during the gap"):
/// the BPF guard's three LSM hooks are pinned under the pin root like the
/// deny hooks and re-attached fresh (attach before purge: the previous
/// start's keeps refusing until this start's runs) — the `bpf` hook was
/// attached for the agent's life only, so through a restart or an
/// upgrade's gap a handle on one of the agent's links (the start-in-cgroup
/// tracker's, pinned beside the root and running all along) was given by
/// id (lot 301's residual). And the agent is an exempt caller of the
/// previous start's guard before its first program loads (registered in
/// `PROTECTED_PIDS` right after the object's load), whatever thread loads
/// and however long the start takes. The lab checks the gap
/// (`deny-selftest-check.sh` G).
#[test]
fn the_bpf_guard_s_hooks_are_pinned() {
    let u = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    let a = body(&u, "attach");
    assert!(
        a.contains(
            "antitamper_bpf::reattach_fresh(ebpf, GUARD_PROGRAM, GUARD_HOOK, btf, pin_root)"
        ),
        "the map guard pinned"
    );
    in_order(a, &["let enforce = enforce_mode();"]).unwrap();
    let flat = a.replace(char::is_whitespace, "");
    for (program, hook) in [
        ("OBSERVE_PROGRAM", "OBSERVE_HOOK"),
        ("PROG_GUARD_PROGRAM", "PROG_GUARD_HOOK"),
    ] {
        assert!(
            flat.contains(&format!(
                "attach_guard_hook(ebpf,{program},{hook},btf,pin_root,enforce"
            )),
            "{program} pinned where the guard enforces"
        );
    }
    assert!(
        !a.contains("attach_transient"),
        "no guard hook for the agent's life only"
    );
    // pinned where the guard enforces; an observing guard (the lab's and the
    // tests' builds) lives with the agent and retires an earlier start's pins
    in_order(
        body(&u, "attach_guard_hook"),
        &[
            "Some(root) if enforce => {",
            "antitamper_bpf::reattach_fresh(ebpf, program, hook, btf, Some(root))",
            "antitamper_bpf::attach_transient(ebpf, program, hook, btf)?;",
            "antitamper_bpf::purge_stale_pin(&link_pin);",
            "antitamper_bpf::purge_stale_pin(&prog_pin);",
        ],
    )
    .unwrap();
    let lib = code("antitamper-bpf/src/lib.rs");
    in_order(
        body(&lib, "reattach_fresh_held"),
        &[
            "prog.attach()",
            "purge_stale_pin(&link_path);",
            "prog.pin(&prog_path)",
            "fd_link.pin(&link_path)",
        ],
    )
    .unwrap();
    let m = code("crates/nn-linux/src/sensors/multiplexer.rs");
    in_order(
        &m,
        &[
            ".load(EBPF_BYTES)",
            "crate::anti_tamper::register_self_before_load(&mut ebpf)",
            "attach_exec_tracepoint(&mut ebpf, &attach_points)?;",
        ],
    )
    .unwrap();
    let t = code("crates/nn-linux/src/anti_tamper/mod.rs");
    in_order(
        body(&t, "register_self_before_load"),
        &["register_protected_pids(ebpf, &[std::process::id()])"],
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
        "#[link_section = \"iter/bpf_prog\"]\npub fn census_progs(ctx: *mut c_void) -> i32 {"
    ));
    assert!(k.contains(
        "#[link_section = \"iter/bpf_link\"]\npub fn census_links(ctx: *mut c_void) -> i32 {"
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
            "if let Some(o) = off_opt!(BPF_PROG_AUX_LOAD_TIME_OFFSET) {\n        (*rec).load_time = rd_u64(aux + o as u64).unwrap_or(0);",
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
            // lot 304: the cross-view first (the root's programs are told
            // by its enumeration of the round), its findings sent after
            // the round's
            "let crossed = match cross.as_mut() {",
            "Some(c) => crossview_round(c, &mut failing, agent_start),",
            "common::bpf_prog_class::KnownLink::RootCgroupSysctl,",
            "c.watch.program(id).as_ref(),",
            "round(&mut w, Path::new(\"/\"), &known)",
            "found.extend(crossed);",
            "tx.send(event_of(&f, monotonic_ns()))",
        ],
    )
    .unwrap();
    in_order(
        body(&k, "crossview_round"),
        &[
            "match cross.round() {",
            // lot 304: a known system program's baseline marked first
            "mark_known_baselines(&mut found, &|id, link| {",
            "cross.watch.program(id).as_ref(),",
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
            "let mut own = (self.own)();",
            "let me = std::process::id();",
            "own.extend(seen.iter().filter(|(_, l)| l.tgid == me).map(|(id, _)| *id));",
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

/// Lot 344 (named, the alpha's false positives): a fresh agent or watchdog
/// opening the agent's pins (maps, programs, the pin directories) before it
/// is a protected pid is the family's own start — let through by the deny
/// path above, and no longer reported as a foreign handle (NN-L-BPF-002
/// High for OUR watchdog at every start). The choice comes after every
/// refusal (a link handle is never exempt by executable, and is judged
/// first), names the maps', programs' and directories' handles only, and is
/// the report's own command — the review of #554 (F2): recorded (Low in
/// userland), never silenced, so a foreign program made the watchdog's
/// binary (`PR_SET_MM_EXE_FILE`) while the role is vacant leaves a trace.
#[test]
fn a_fresh_instance_s_own_start_is_not_reported_as_a_foreign_handle() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    let h = body(&c, "try_bpf_syscall_observe");
    in_order(
        h,
        &[
            "if (own_link_handle || own_link_pin) && enforce() {",
            "&& !fresh_instance_may_load()\n    {\n        let kind",
            "if matches!(cmd, BPF_LINK_DETACH | BPF_LINK_UPDATE) && enforce() {",
            "let foreign_handle =\n        own_map_handle || own_prog_handle || own_link_handle || own_link_pin || own_dir_pin;",
            "let fresh_instance =\n        (own_map_handle || own_prog_handle || own_dir_pin) && fresh_instance_may_load();",
            "let report_cmd = if fresh_instance {\n        BPF_CMD_FRESH_INSTANCE_GET_FD\n    } else if foreign_handle {\n        BPF_CMD_FOREIGN_GET_FD",
            "if should_report(pid, dedup) {\n        emit_syscall(report_cmd, arg);",
        ],
    )
    .unwrap();
    // the review of #554 (F2): nothing between the choice and the report
    // returns — the fresh instance's handle is recorded, not silenced
    let from = h.find("let foreign_handle =").unwrap();
    let to = h.find("emit_syscall(report_cmd, arg);").unwrap();
    assert!(
        !h[from..to].contains("return"),
        "a handle silenced before its report: {}",
        &h[from..to]
    );
    // the exemption is the deny path's: the binary by device and inode,
    // the role vacant, the main thread, the first minute
    in_order(
        body(&c, "fresh_instance_may_load"),
        &[
            "if (pid_tgid >> 32) as u32 != pid_tgid as u32 {\n        return false;\n    }",
            "let role = caller_role();",
            "Some(t) => *t == 0,",
            "< FRESH_INSTANCE_NS",
        ],
    )
    .unwrap();
}

/// Lot 344 (#554's KVM suites): the `bpf` hook's watchdog role is the
/// watchdog the agent verifies (`--watchdog-exe`, else its sibling) — the
/// one value the stale-pid scan takes too. It named the agent's sibling
/// `northnarrow-watchdog` on its own, so a watchdog the agent was told of
/// elsewhere took the agent's pins at its start as a foreign process
/// (NN-L-BPF-002 High). No binary is guessed in the guard's registration.
#[test]
fn the_hook_s_watchdog_is_the_watchdog_the_agent_verifies() {
    let c = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    let prod = &c[..c.find("#[cfg(test)]").expect("the tests")];
    assert!(
        !prod.contains("\"northnarrow-watchdog\""),
        "the guard names a watchdog binary of its own"
    );
    let reg = body(prod, "register_own_objects");
    assert!(reg.contains("let exe_keys = own_exe_keys(own_exes);"));
    assert!(
        !reg.contains("current_exe"),
        "the guard reads an executable of its own"
    );
    in_order(
        body(prod, "own_exe_keys"),
        &["[(own.agent, ROLE_AGENT), (own.watchdog, ROLE_WATCHDOG)]"],
    )
    .unwrap();
    let at = code("crates/nn-linux/src/anti_tamper/mod.rs");
    in_order(
        body(&at, "attach_reporting"),
        &[
            "match evict_stale_pids(ebpf, &own.keep()) {",
            "bpf_defense::register_own_objects(bpf_guard, ebpf, pin_root, own)",
        ],
    )
    .unwrap();
    in_order(
        &code("agent/src/boot/attach.rs"),
        &[
            "let own = cli.own_exes();",
            ".attach_anti_tamper(verified, &pids, &own)",
        ],
    )
    .unwrap();
    in_order(
        body(&code("agent/src/boot/cli.rs"), "own_exes"),
        &[
            "agent: ExeIdentity::of_process(std::process::id()),",
            "watchdog: ExeIdentity::of_file(&self.resolved_watchdog_exe()),",
        ],
    )
    .unwrap();
}

/// Named (lot 345; the re-check of #550, N2 and point 1 (ii)): what an
/// allowed loader (`install.sh --allow-bpf-tools`, `--allow-bpf-loader`)
/// still cannot load — read in the code the kernel runs, in the order that
/// makes it hold:
/// - the `bpf` hook refuses an fmod_ret (`expected_attach_type` at byte 68
///   of the kernel's copy of the attr) to a load the opt-out let through,
///   an unreadable one too;
/// - 6.9 and later: `bpf_prog_load` judges the kernel's copy of a foreign
///   load's instructions (a type refused by default: an opted-out one) for
///   the forbidden helpers and kfunc, before the verifier and any id;
/// - before 6.9: `bpf_prog` judges every foreign handle (the load's and one
///   by id) once verified, against targets it calibrates from the agent's
///   own programs, and the verifier's lockdown question for
///   `bpf_probe_write_user` is refused to a foreign caller;
/// - the agent arms one stage or the other, and freezes the configuration.
#[test]
fn an_allowed_loader_cannot_load_what_kills_or_blinds_the_agent() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    in_order(
        body(&c, "try_bpf_syscall_observe"),
        &[
            "if nn_loader_opted_out(u64::from(arg)) != LOADER_OPTED_OUT {",
            "(attr as *const u8).add(PROG_LOAD_ATTACH_TYPE_OFFSET) as *const u32,",
            "Ok(eat) => opt_out_refuses_attach(eat),\n                Err(_) => true,",
            "if refused_attach {\n                emit_denial_kind(FS_OP_BPF_PROG_TYPE, CONTENT_FMOD_RET, arg);\n                return -EPERM;",
            "emit_denial(FS_OP_BPF_PROG_OPT_OUT, arg);",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "content_refusal"),
        &[
            "let kfuncs_only = !denied_by_default(ty);\n    if (kfuncs_only && !every_type)\n        || caller_is_exempt()\n        || crate::inode_protect::override_active()\n        || fresh_instance_may_load()",
            "let Some(addr) = ptr_scalar(prog) else {\n        return Some((CONTENT_UNJUDGED, ty));",
            "match nn_prog_forbidden_call(addr, kfuncs_only as u64) {\n        SCAN_CLEAN => None,",
            "_ => Some((CONTENT_UNJUDGED, ty)),",
        ],
    )
    .unwrap();
    assert!(c.contains("#[lsm(hook = \"bpf_prog_load\")]\npub fn bpf_prog_load_guard("));
    in_order(
        body(&c, "try_bpf_prog_load_guard"),
        &[
            "if content_stage() != CONTENT_STAGE_LOAD {",
            "if let Some((why, ty)) = content_refusal(prog, every_type_armed()) {\n        emit_denial_kind(FS_OP_BPF_PROG_TYPE, why, ty);\n        return -EPERM;",
        ],
    )
    .unwrap();
    // before the load's seen mark and any own-object exemption: every
    // handle of a foreign caller
    in_order(
        body(&c, "try_bpf_prog_guard"),
        &[
            "if content_stage() == CONTENT_STAGE_HANDLE && !is_own_kind(id, OWN_KIND_PROG) {\n        if let Some((why, ty)) = content_refusal(prog, false) {\n            emit_denial_kind(FS_OP_BPF_PROG_TYPE, why, ty);\n            return -EPERM;",
            "if loading && calibration_armed() && (caller_is_exempt() || fresh_instance_may_load()) {\n        if let Some(addr) = ptr_scalar(prog) {\n            nn_calibrate(addr);",
            "if loading {\n        crate::bpf_census::mark_seen(id, prog);",
        ],
    )
    .unwrap();
    // the whole program read: CONTENT_MAX_INSNS = 32 spans x 32 blocks x
    // 32 chunks x 32 instructions, each instruction one key lookup
    in_order(
        body(&c, "nn_prog_forbidden_call"),
        &[
            "if len > CONTENT_MAX_INSNS as u64 {\n        return SCAN_UNJUDGED;",
            "while k < SCAN_FAN {",
            "let r = nn_scan_span(insns, from, len, kfuncs_only);",
        ],
    )
    .unwrap();
    assert!(
        body(&c, "nn_scan_span").contains("let r = nn_scan_block(insns, at, len, kfuncs_only);")
    );
    assert!(
        body(&c, "nn_scan_block").contains("let r = nn_scan_chunk(insns, at, len, kfuncs_only);")
    );
    assert_eq!(
        32 * 32 * 32 * 32,
        northnarrow_common_max_insns(),
        "the scan covers the most a load may hold"
    );
    in_order(
        body(&c, "nn_scan_chunk"),
        &[
            "Err(_) => return SCAN_UNJUDGED,",
            "if let Some(slot) = unsafe { PROG_CONTENT_KEYS.get(&call_key(insn)) } {\n            if kfuncs_only == 0 || judged_for_every_type(*slot) {\n                return *slot as u64;",
        ],
    )
    .unwrap();
    assert!(c.contains("#[lsm(hook = \"locked_down\")]\npub fn bpf_write_user_guard("));
    in_order(
        body(&c, "try_bpf_write_user_guard"),
        &[
            "if want == 0\n        || what != want\n        || caller_is_exempt()\n        || crate::inode_protect::override_active()\n        || fresh_instance_may_load()",
            "emit_denial_kind(FS_OP_BPF_PROG_TYPE, CONTENT_CALL, 0);\n    -EPERM",
        ],
    )
    .unwrap();
    // the agent's side
    let u = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    in_order(
        body(&u, "attach"),
        &[
            "let at_load = resolved.is_some_and(|r| r.prog_load_hook)",
            "PROG_LOAD_GUARD_PROGRAM,\n            PROG_LOAD_GUARD_HOOK,",
            "write_content_judge(ebpf, &judge, true)",
            "attach_guard_hook(ebpf, OBSERVE_PROGRAM, OBSERVE_HOOK, btf, pin_root, enforce)",
            "PROG_GUARD_PROGRAM,\n        PROG_GUARD_HOOK,",
            "if !at_load {",
            "match arm_content_at_handle(ebpf, btf, pin_root, enforce, lockdown) {",
        ],
    )
    .unwrap();
    in_order(
        body(&u, "arm_content_at_handle"),
        &[
            "WRITE_USER_GUARD_PROGRAM,\n            WRITE_USER_GUARD_HOOK,",
            "clear_seen(ebpf)?;\n        set_calibration(ebpf, kind)?;\n        let loaded = load_calibration(ebpf, program);\n        set_calibration(ebpf, CALIB_NONE)?;",
            "if let Err(e) = place_calibration(kind, &read_seen(ebpf)?, &mut calibrated) {",
            "freeze_named(ebpf, CALIB_MAP)?;",
            "write_content_judge(ebpf, &judge, true)?;",
        ],
    )
    .unwrap();
    assert!(body(&u, "load_calibration").contains("prog.unload()"));
}

/// Named (the review of #553, F1): on 6.13+ any root loaded a `syscall`
/// program (run by `BPF_PROG_RUN`), an XDP or a tc one — types no opt-out
/// is needed for, so the judge never read them — calling
/// `bpf_task_from_pid` and `bpf_send_signal_task`, and killed the agent
/// past its `task_kill` hook (`SI_KERNEL`). At the load stage a foreign
/// load of EVERY type is now read for the kfunc targets (and only them,
/// for those types), wherever this kernel has one; the agent counts them
/// into the configuration's every-type slot.
#[test]
fn a_load_of_every_type_is_read_for_the_signal_kfuncs() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    in_order(
        body(&c, "try_bpf_prog_load_guard"),
        &[
            "if content_stage() != CONTENT_STAGE_LOAD {",
            "content_refusal(prog, every_type_armed())",
            "return -EPERM;",
        ],
    )
    .unwrap();
    assert!(body(&c, "every_type_armed").contains("PROG_CONTENT_CONF.get(CONTENT_EVERY_TYPE_SLOT)"));
    let refusal = body(&c, "content_refusal");
    assert!(refusal.contains("let kfuncs_only = !denied_by_default(ty);"));
    assert!(refusal.contains("if (kfuncs_only && !every_type)"));
    assert!(!refusal.contains("if !denied_by_default(ty)"));
    in_order(
        body(&c, "nn_scan_chunk"),
        &[
            "PROG_CONTENT_KEYS.get(&call_key(insn))",
            "if kfuncs_only == 0 || judged_for_every_type(*slot) {",
        ],
    )
    .unwrap();
    for f in ["nn_prog_forbidden_call", "nn_scan_span", "nn_scan_block"] {
        assert!(
            body(&c, f).contains(", kfuncs_only);"),
            "{f} passes kfuncs_only on"
        );
    }
    let u = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    in_order(
        body(&u, "write_content_judge"),
        &[
            "let every = common::bpf_prog_class::CONTENT_EVERY_TYPE_SLOT;",
            "conf.set(every, judge.every_type, 0)",
            "freeze_named(ebpf, CONTENT_CONF_MAP)?;",
        ],
    )
    .unwrap();
    assert!(
        body(&u, "at_load").contains("every_type: kfunc_btf_ids.iter().flatten().count() as u32,")
    );
    assert!(body(&u, "attach").contains("r.forbidden_kfunc_ids"));
}

/// Named (the review of #553, F4): before 6.9, a failed calibration
/// dropped the `locked_down` guard for `bpf_probe_write_user` (which reads
/// no calibration) and left the opted-out loaders every signalling helper.
/// The guard is attached first now, and while the judge is off (its stage
/// not armed) the `bpf` hook honours no opt-out: their types are refused
/// again, and the observe failure says so.
#[test]
fn a_failed_calibration_suspends_the_opt_outs_and_keeps_the_lockdown_guard() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    in_order(
        body(&c, "nn_loader_opted_out"),
        &[
            "if bit == 0 || content_stage() == CONTENT_STAGE_OFF {\n        return 0;",
            "caller_exe_key()",
        ],
    )
    .unwrap();
    let u = code("crates/nn-linux/src/anti_tamper/bpf_defense.rs");
    in_order(
        body(&u, "arm_content_at_handle"),
        &[
            "WRITE_USER_GUARD_PROGRAM,\n            WRITE_USER_GUARD_HOOK,",
            "conf.set(CONTENT_LOCKDOWN_SLOT, *v, 0)",
            "clear_seen(ebpf)?;",
            "if let Some(why) = &judge.off {\n        freeze_named(ebpf, CONTENT_CONF_MAP)?;\n        return Err(format!(\"{why} — {OPT_OUTS_SUSPENDED}{write_user_note}\"));",
        ],
    )
    .unwrap();
    assert!(
        u.contains("refused to every loader outside a window again, until a start arms the judge")
    );
}

/// `bpf_prog_class::CONTENT_MAX_INSNS`, read from its source.
fn northnarrow_common_max_insns() -> u64 {
    let c = code("common/src/bpf_prog_class.rs");
    assert!(c.contains("pub const CONTENT_MAX_INSNS: u32 = 1 << 20;"));
    let e = code("agent-ebpf/src/bpf_defense.rs");
    assert!(e.contains("const SCAN_FAN: u64 = 32;"));
    1 << 20
}

/// Lot 349 (pre-alpha R002, named; the lab on Ubuntu 26.04, 7.0): from 6.9
/// the judge reads a load's content at `bpf_prog_load` only, and a window
/// lets a load through whatever it calls — a kprobe calling
/// `bpf_send_signal` or a syscall program calling `bpf_send_signal_task`,
/// loaded in a window, was then taken by id or through its pin by any root
/// process (and the syscall program run) with no refusal and no record. The
/// load's verdict is kept now, and the program's later handles outside a
/// window are refused to a caller outside the family and signed as the
/// load's refusal would be — in every mode (no `enforce()`), before the
/// census marks the load seen.
#[test]
fn a_window_s_forbidden_load_is_refused_at_its_later_handles() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    in_order(
        body(&c, "try_bpf_prog_load_guard"),
        &[
            "if content_stage() != CONTENT_STAGE_LOAD {",
            "let _ = PROG_CONTENT_HELD_INFLIGHT.remove(&tid);",
            "content_refusal(prog, every_type_armed())",
            "return -EPERM;",
            "if let Some(v) = window_verdict(prog, every_type_armed()) {",
            "PROG_CONTENT_HELD_INFLIGHT.insert(&tid, &v, 0);",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "window_verdict"),
        &[
            "if !crate::inode_protect::override_active() || caller_is_exempt() || fresh_instance_may_load() {",
            "return None;",
            "content_scan(prog, every_type).map(|(why, ty)| (u64::from(why) << 32) | u64::from(ty))",
        ],
    )
    .unwrap();
    let guard = body(&c, "try_bpf_prog_guard");
    in_order(
        guard,
        &[
            "let loading = crate::bpf_census::take_load_mark();",
            "if content_stage() == CONTENT_STAGE_LOAD {",
            "if loading {",
            "PROG_CONTENT_HELD_INFLIGHT.get_ptr(&tid)",
            "let _ = PROG_CONTENT_HELD_INFLIGHT.remove(&tid);",
            "if !hold(id, v) {",
            "return -EPERM;",
            "} else if let Some(v) = PROG_CONTENT_HELD.get_ptr(&id) {",
            "if !caller_is_exempt() && !crate::inode_protect::override_active() && !fresh_instance_may_load() {",
            "emit_denial_kind(FS_OP_BPF_PROG_TYPE, (v >> 32) as u8, v as u32);",
            "return -EPERM;",
            "if loading {",
            "crate::bpf_census::mark_seen(id, prog);",
        ],
    )
    .unwrap();
    let held = &guard[guard
        .find("if content_stage() == CONTENT_STAGE_LOAD {")
        .unwrap()..];
    let held = &held[..held.find("crate::bpf_census::mark_seen").unwrap()];
    assert!(
        !held.contains("enforce()"),
        "the held programs' refusal holds in every mode"
    );
    // the window's verdict reads the content alone; the refusal keeps the
    // caller's exemptions
    let scan = body(&c, "content_scan");
    for exemption in [
        "caller_is_exempt",
        "override_active",
        "fresh_instance_may_load",
    ] {
        assert!(
            !scan.contains(exemption),
            "content_scan judges no caller ({exemption})"
        );
        assert!(
            body(&c, "content_refusal").contains(exemption),
            "{exemption}"
        );
    }
    in_order(
        scan,
        &[
            "let kfuncs_only = !denied_by_default(ty);",
            "if kfuncs_only && !every_type {",
            "match nn_prog_forbidden_call(addr, kfuncs_only as u64) {",
            "_ => Some((CONTENT_UNJUDGED, ty)),",
        ],
    )
    .unwrap();
    // the review of #558 (F5): pinned — an agent's restart keeps it
    assert!(c.contains(
        "pub static PROG_CONTENT_HELD: HashMap<u32, u64> = HashMap::pinned(PROG_CONTENT_HELD_MAX, 0);"
    ));
    // the lab check
    let lab =
        fs::read_to_string(repo_root().join("deploy/lab/malsim/bpf-content-check.sh")).unwrap();
    in_order(
        &lab,
        &[
            "trusted-installer-grant --key \"$KEY\" --window-secs 40",
            "load-tracing --call send_signal --name k349_sig --pin $PINS/sig",
            "load-kfunc-signal --type syscall --pid \"$APID\" --sig 28 --name k349_kf --pin $PINS/kf",
            "for how in \"prog-fd-by-id $id\" \"obj-get $pin\"; do",
            "[[ $r1 == \"ERR EPERM\"* && $r == *\"a call of $call\"* ]]",
            "sudo rm -rf \"$PINS\" </dev/null",
        ],
    )
    .unwrap();
}

/// The review of #558 (F1, P1): the window's loader kept its own descriptor
/// (or passed it, or another root took it with `pidfd_getfd`) and, after
/// the window, ran the held program (`BPF_PROG_RUN` of a `syscall` program
/// calling `bpf_send_signal_task`, 6.13+: cmd 10 was not even `observed`)
/// or attached it (a kprobe calling `bpf_send_signal`, every kernel: a perf
/// event's `PERF_EVENT_IOC_SET_BPF`, silent, or `BPF_LINK_CREATE`, Medium
/// only), or put it in a prog array's tail-call slot — no `bpf_prog` hook
/// runs for any of them. Every run and attach of a held id is refused now
/// outside a window, through any descriptor, signed: the `bpf` hook judges
/// before its `observed` filter, the `file_ioctl` hooks before their
/// chattr fast path, both through one global function.
#[test]
fn a_held_program_is_refused_at_every_run_and_attach() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    in_order(
        body(&c, "try_bpf_syscall_observe"),
        &[
            "if !attr.is_null() && held_use_refused(cmd, attr) {",
            "return -EPERM;",
            "if !observed(cmd) {",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "held_use_refused"),
        &[
            "if cmd == BPF_MAP_UPDATE_ELEM {",
            "bpf_probe_read_kernel::<u64>(a.add(MAP_UPDATE_VALUE_OFFSET) as *const u64),",
            "crate::fail_open::bump(fail_open_hook::BPF);",
            "return nn_held_slot(u64::from(map_fd), value) == HELD_REFUSED;",
            "let Some(off) = prog_fd_offset(cmd) else {",
            "Ok(fd) => nn_held_use(u64::from(fd), u64::from(cmd)) == HELD_REFUSED,",
            "crate::fail_open::bump(fail_open_hook::BPF);",
        ],
    )
    .unwrap();
    let use_ = body(&c, "nn_held_use");
    in_order(
        use_,
        &[
            "if caller_is_exempt() || crate::inode_protect::override_active() {",
            "return HELD_PASS;",
            "prog_id_of_fd(fd as u32)",
            "crate::fail_open::bump(fail_open_hook::BPF);",
            "PROG_CONTENT_HELD.get(&id)",
            "if fresh_instance_may_load() {",
            "emit_held(FS_OP_BPF_HELD_USE, how as u32, verdict, id);",
            "HELD_REFUSED",
        ],
    )
    .unwrap();
    assert!(!use_.contains("enforce()"), "refused in every mode, as the load would be");
    in_order(
        body(&c, "nn_held_slot"),
        &[
            "Ok(Some((_, ty))) if ty == MAP_TYPE_PROG_ARRAY => {}",
            "Ok(_) => return HELD_PASS,",
            "bpf_probe_read_user::<u32>(value as *const u32)",
            "nn_held_use(u64::from(fd), u64::from(BPF_MAP_UPDATE_ELEM))",
        ],
    )
    .unwrap();
    // the program, not the descriptor: its id through the caller's table
    in_order(
        body(&c, "prog_id_of_fd"),
        &["private_of_fd(fd)?", "prog_id_of(prog as *const c_void)"],
    )
    .unwrap();
    // the perf event's attach, which no bpf command carries
    let ip = code("agent-ebpf/src/inode_protect.rs");
    in_order(
        body(&ip, "try_file_ioctl"),
        &[
            "let cmd: c_uint = ctx.arg(1);",
            "if cmd == PERF_EVENT_IOC_SET_BPF {",
            "let fd: u64 = ctx.arg(2);",
            "crate::bpf_defense::nn_held_use(fd, u64::from(BPF_HELD_SET_BPF)) == crate::bpf_defense::HELD_REFUSED",
            "return -EPERM;",
            "if cmd != FS_IOC_SETFLAGS",
        ],
    )
    .unwrap();
    assert!(ip.contains(
        "const PERF_EVENT_IOC_SET_BPF: c_uint = northnarrow_common::bpf_cmd::PERF_EVENT_IOC_SET_BPF;"
    ));
}

/// The review of #558 (F1): the window's forbidden load itself was silent
/// (`content_refusal` returns None in a window) — on every kernel it is
/// signed now when it is held, High, so it is never silent even through a
/// use no hook sees (a link attached inside the window, a netlink XDP
/// attach). Before 6.9 the `bpf_prog` hook holds it at the load's handle;
/// from 6.9 the load's verdict, kept by thread, is held there.
#[test]
fn a_window_s_forbidden_load_is_signed_at_its_load() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    in_order(
        body(&c, "hold"),
        &[
            "if PROG_CONTENT_HELD.insert(&id, &verdict, 0).is_err() {",
            "emit_held(FS_OP_BPF_HELD_USE, BPF_HELD_FULL, verdict, id);",
            "return false;",
            "emit_held(FS_OP_BPF_HELD_LOAD, 0, verdict, id);",
            "true",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "try_bpf_prog_guard"),
        &[
            "if content_stage() == CONTENT_STAGE_HANDLE && !is_own_kind(id, OWN_KIND_PROG) {",
            "content_refusal(prog, false)",
            "return -EPERM;",
            "if loading {",
            "if let Some(v) = window_verdict(prog, false) {",
            "if !hold(id, v) {",
            "return -EPERM;",
            "if content_stage() == CONTENT_STAGE_LOAD {",
            "if !hold(id, v) {",
            "return -EPERM;",
        ],
    )
    .unwrap();
    in_order(
        body(&c, "emit_held"),
        &["crate::inode_protect::emit_attempt(", "dev: bpf_held_dev(how, verdict),", "ino: id as u64,"],
    )
    .unwrap();
}

/// The review of #558 (F5): the held set (1024 ids) was never emptied and,
/// full, kept nothing (a fail-open): a window holder's 1024 tiny forbidden
/// loads left every later window's forbidden load unheld. Full, the load
/// is refused now (fail closed, signed); each kernel-state round releases
/// the ids no longer loaded, read before its enumeration.
#[test]
fn a_full_held_set_refuses_the_window_s_load_and_the_round_empties_it() {
    let c = code("agent-ebpf/src/bpf_defense.rs");
    let g = body(&c, "try_bpf_prog_guard");
    assert!(
        !g.contains("PROG_CONTENT_HELD.insert"),
        "every insert goes through hold(), which fails closed"
    );
    assert!(!body(&c, "hold").contains("fail_open"), "full is no fail-open");
    let x = code("crates/nn-linux/src/bpf_crossview.rs");
    in_order(
        body(&x, "round"),
        &[
            "let held = self.parts.held();",
            "let en = self.parts.enumerate()?;",
            "let gone = stale_held(&held, &en.progs);",
            "self.parts.release_held(&gone);",
        ],
    )
    .unwrap();
    assert!(x.contains("pub const HELD_MAP: &str = \"PROG_CONTENT_HELD\";"));
    assert!(c.contains("pub static PROG_CONTENT_HELD: HashMap<u32, u64> ="));
}
