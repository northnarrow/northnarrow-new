//! Lot 341 (the alpha profile; the coordinator's decision of 13/11): the
//! alpha promises a tester it never breaks anything on the machine. Under
//! the start's ONE no-enforcement gate (`alpha`, `--detect-only`,
//! `NN_DETECT_ONLY`) the HOST-WIDE denies — the guards that refuse a
//! third-party tool something on the host — go to observe, each attempt
//! signed "would deny"; the denies that protect the AGENT itself hold under
//! every profile.
//!
//! The eBPF programs run only in a kernel (the privileged
//! `agent/tests/host_deny_privileged_e2e.rs` and the lab load a foreign
//! tracing program and try a handle on the agent's map). Here the code is
//! read: every deny site of the object is either routed through the
//! profile's switch (`agent-ebpf/src/host_deny.rs`) or listed below as the
//! agent's self-protection with its reason (or as a response path whose
//! own mode the gate sets) — a new deny site fails until it is classified —
//! and the agent writes the switch from the resolved gate before anything
//! attaches.

mod support;

use std::collections::BTreeMap;

use support::{matching_brace, product_code, repo_root};

/// How a deny site of the eBPF object meets the profile.
#[derive(Clone, Copy, Debug)]
enum Route {
    /// A host-wide deny: decided by `crate::host_deny::judge` (one call a
    /// site in the function), observed under the gate.
    Profile,
    /// The agent's self-protection: enforced under every profile — the
    /// function never reads the profile's switch. The reason.
    Enforced(&'static str),
    /// A response path whose own mode the resolved gate sets (named in
    /// `xtask/tests/alpha_profile.rs`): the reason.
    Gated(&'static str),
    /// Returns what another listed function decided (named).
    Delegated(&'static str),
}

use Route::{Delegated, Enforced, Gated, Profile};

const AGENT: &str = "the agent, its watchdog or a worker (PROTECTED_PIDS, or a process running \
                     the agent's or the watchdog's binary)";
const OWN_FILES: &str = "the agent's files, units, directories and pins (PROTECTED_INODES)";

/// Every deny site of `agent-ebpf/src`, by file and function: `(file,
/// function, sites, route)`. A function may hold sites of two routes (one
/// row each).
const SITES: &[(&str, &str, usize, Route)] = &[
    ("bpf_defense.rs", "try_bpf_map_guard", 2, Enforced("a read or write handle on one of the agent's MAPS (a program is loaded against a map, or a map written, only through one)")),
    ("bpf_defense.rs", "try_bpf_prog_guard", 1, Enforced("a handle on one of the agent's PROGRAMS (an freplace of one of its functions needs it)")),
    ("bpf_defense.rs", "try_bpf_syscall_observe", 2, Profile),
    ("bpf_defense.rs", "try_bpf_syscall_observe", 3, Enforced("a handle on one of the agent's links (by id or its pin), a handle by id on its maps or programs or one under its pin directories, a detach or update of one of its links")),
    ("cgroup_files.rs", "refuse_switch", 1, Profile),
    ("cgroup_files.rs", "refuse_limit", 1, Enforced("a resource file of the agent's units' cgroups (kill, freeze, limits)")),
    ("cgroup_files.rs", "refuse_v1", 1, Profile),
    ("cgroup_files.rs", "refuse_sysctl", 1, Profile),
    ("cgroup_files.rs", "refuse_oom_adj", 1, Enforced("the oom_score_adj of the agent, its watchdog or a worker")),
    ("cgroup_guard.rs", "try_cgroup_move_deny", 1, Enforced("a move of the agent's processes out of its cgroup")),
    ("epg.rs", "respond", 1, Gated("the exploit guard's SIGKILL: detect mode under the gate (effective_response)")),
    ("epg_lite.rs", "use_point_found", 3, Gated("the exploit guard's response (EPERM, SIGKILL): detect mode under the gate (effective_response)")),
    ("execpol.rs", "env_commit", 1, Gated("the exec environment's SIGKILL: the exec policy's audit mode under the gate (execpol_mode)")),
    ("execpol.rs", "on_pass", 1, Gated("the exec policy: audit mode under the gate (execpol_mode)")),
    ("execpol.rs", "try_exec_env_lsm", 1, Gated("the exec policy: audit mode under the gate (execpol_mode)")),
    ("execpol.rs", "try_execmap", 1, Gated("the exec policy: audit mode under the gate (execpol_mode)")),
    ("execq.rs", "maybe_stop", 1, Gated("the exec quarantine's hold (SIGSTOP): observe mode under the gate (execq_config)")),
    ("execq.rs", "note_pass", 1, Gated("the exec quarantine: observe mode under the gate (execq_config)")),
    ("execq.rs", "refuse_script", 1, Gated("the exec quarantine: observe mode under the gate (execq_config)")),
    ("inode_protect.rs", "try_inode_unlink", 2, Enforced(OWN_FILES)),
    ("inode_protect.rs", "try_inode_rmdir", 2, Enforced(OWN_FILES)),
    ("inode_protect.rs", "try_inode_rename", 4, Enforced(OWN_FILES)),
    ("inode_protect.rs", "try_inode_setattr", 1, Enforced(OWN_FILES)),
    ("inode_protect.rs", "try_file_ioctl", 1, Enforced(OWN_FILES)),
    ("inode_protect.rs", "try_protected_open_deny", 2, Enforced("a read-open of the agent's key, a write-open of its protected files")),
    ("inode_protect.rs", "try_protected_open_deny", 1, Delegated("refuse_write(")),
    ("inode_protect.rs", "try_protected_write_deny", 1, Enforced("a write through a descriptor of the agent's protected files")),
    ("inode_protect.rs", "try_protected_write_deny", 1, Delegated("refuse_write(")),
    ("inode_protect.rs", "deny_new_entry", 1, Enforced(OWN_FILES)),
    ("inode_protect.rs", "deny_xattr", 1, Enforced(OWN_FILES)),
    ("module_load.rs", "try_read_file", 1, Gated("the module-load judge: record mode under the gate (module_trust::kernel_mode)")),
    ("module_load.rs", "try_load_data", 1, Gated("the module-load judge: record mode under the gate (module_trust::kernel_mode)")),
    ("module_load.rs", "deny_kexec", 1, Profile),
    ("ptrace_check.rs", "try_ptrace_access_check", 1, Profile),
    ("ptrace_check.rs", "try_ptrace_access_check", 1, Enforced(AGENT)),
    ("sigio_guard.rs", "try_file_send_sigiotask", 1, Enforced(AGENT)),
    ("socket_connect.rs", "try_socket_connect", 1, Gated("the kernel connect deny (its EPERM a negative constant): not armed under the gate (policy::arming)")),
    ("sysctl_guard.rs", "nn_sysctl_guard", 1, Delegated("try_sysctl_guard(")),
    ("sysctl_guard.rs", "try_sysctl_guard", 1, Profile),
    ("task_kill.rs", "try_task_kill", 1, Enforced(AGENT)),
    ("task_limits.rs", "task_setrlimit_deny", 1, Enforced(AGENT)),
    ("task_limits.rs", "task_setscheduler_deny", 1, Enforced(AGENT)),
    ("task_limits.rs", "task_setnice_deny", 1, Enforced(AGENT)),
    ("task_limits.rs", "task_setioprio_deny", 1, Enforced(AGENT)),
];

/// The eBPF object's production code, by file name.
fn ebpf_code() -> BTreeMap<String, String> {
    product_code(&repo_root())
        .into_iter()
        .filter_map(|(rel, text)| {
            rel.strip_prefix("agent-ebpf/src/")
                .map(|f| (f.to_string(), text))
        })
        .collect()
}

/// Every function of `code` with a body: `(name, body)`.
fn functions(code: &str) -> Vec<(String, &str)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = code[from..].find("fn ") {
        let at = from + i;
        from = at + 3;
        if at > 0 {
            let prev = code.as_bytes()[at - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                continue;
            }
        }
        let rest = &code[at + 3..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let (Some(open), semi) = (rest.find('{'), rest.find(';')) else {
            continue;
        };
        if semi.is_some_and(|s| s < open) {
            continue; // a declaration
        }
        let start = at + 3 + open;
        let len = matching_brace(&code[start..]);
        out.push((name, &code[start..start + len]));
    }
    out
}

/// The deny sites of function `name` of `file` (whose code is `text`):
/// each `-EPERM` / `-EACCES` returned or stored, and each use of a refusal
/// constant the file defines negative (`const EPERM: i32 = -1;`, returned
/// bare — the connect deny's spelling); each kill or stop the kernel sends
/// (`bpf_send_signal`); the sysctl program's refusal verdict; and each
/// refusal `cgroup_files`' refusers sign (their `true` makes
/// `refuse_write`'s caller return `-EPERM`).
fn deny_sites(file: &str, text: &str, name: &str, body: &str) -> usize {
    let mut n = body.matches("-EPERM").count()
        + body.matches("-EACCES").count()
        + body.matches("bpf_send_signal(").count();
    for c in negative_consts(text) {
        n += words(body, &c);
    }
    if file == "sysctl_guard.rs" {
        n += body.matches("SysctlVerdict::Refuse =>").count();
    }
    if file == "cgroup_files.rs" && name.starts_with("refuse_") && name != "refuse_write" {
        n += body.matches("sign(phase,").count() + body.matches("emit_task_denial(").count();
    }
    n
}

/// The constants `text` defines with a negative value (`const NAME: T =
/// -N;`).
fn negative_consts(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l
                .strip_prefix("const ")
                .or_else(|| l.strip_prefix("pub const "))?;
            let (name, value) = rest.split_once(':')?;
            value
                .split_once('=')
                .filter(|(_, v)| v.trim_start().starts_with('-'))
                .map(|_| name.trim().to_string())
        })
        .collect()
}

/// The uses of the word `w` in `hay` (not part of a longer name).
fn words(hay: &str, w: &str) -> usize {
    let b = hay.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    hay.match_indices(w)
        .filter(|(at, _)| {
            (*at == 0 || !ident(b[at - 1])) && b.get(at + w.len()).is_none_or(|c| !ident(*c))
        })
        .count()
}

/// Named: every deny site of the eBPF object is classified — routed
/// through the profile's switch, the agent's self-protection (with its
/// reason), a response path whose mode the gate sets, or a function that
/// returns a classified one's verdict. A new site, or one more in a
/// function, fails here until it is classified.
#[test]
fn every_deny_site_takes_the_profile_or_is_listed_self_protection() {
    let code = ebpf_code();
    let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (file, text) in &code {
        for (name, body) in functions(text) {
            let n = deny_sites(file, text, &name, body);
            if n > 0 {
                *found.entry((file.clone(), name)).or_default() += n;
            }
        }
    }
    let mut listed: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (file, name, n, _) in SITES {
        *listed
            .entry((file.to_string(), name.to_string()))
            .or_default() += n;
    }
    let census: Vec<String> = found
        .iter()
        .map(|((f, n), c)| format!("({f:?}, {n:?}, {c})"))
        .collect();
    assert_eq!(
        found, listed,
        "the deny sites of agent-ebpf changed — classify each (Profile, Enforced with its \
         reason, Gated, Delegated): {census:#?}"
    );
}

/// Named: each host-wide site decides through the switch (one `judge` a
/// site); a function of the agent's self-protection or of a gated response
/// path never reads it — no profile relaxes them.
#[test]
fn the_self_protection_never_reads_the_profile_s_switch() {
    let code = ebpf_code();
    let body_of = |file: &str, name: &str| -> String {
        let text = code.get(file).unwrap_or_else(|| panic!("{file} not found"));
        functions(text)
            .into_iter()
            .filter(|(n, _)| n == name)
            .map(|(_, b)| b.to_string())
            .next()
            .unwrap_or_else(|| panic!("fn {name} not found in {file}"))
    };
    let mut profile: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (file, name, n, route) in SITES {
        match route {
            Profile => *profile.entry((file, name)).or_default() += n,
            Enforced(why) | Gated(why) => assert!(!why.is_empty()),
            Delegated(call) => assert!(
                body_of(file, name).contains(call),
                "{file} {name} returns {call}…'s verdict"
            ),
        }
    }
    for (file, name, _, route) in SITES {
        let body = body_of(file, name);
        let judged = body.matches("crate::host_deny::judge").count();
        match profile.get(&(*file, *name)) {
            Some(n) => {
                assert_eq!(
                    judged, *n,
                    "{file} {name}: one crate::host_deny::judge a host-wide site"
                );
                // and each refuses only as the switch decided (`refuse`)
                let tail = body.trim_end().trim_end_matches('}').trim_end();
                let decided = body.matches("if refuse {").count()
                    + body.matches("if !refuse ").count()
                    + usize::from(tail.ends_with("\n    refuse"));
                assert!(
                    decided >= *n,
                    "{file} {name}: {n} host-wide sites, {decided} decided by the switch's `refuse`"
                );
            }
            None => assert!(
                !body.contains("host_deny"),
                "{file} {name} ({route:?}) must not read the profile's switch"
            ),
        }
    }
}

/// Named: every refusal code of a host-wide deny is signed only as the
/// switch decided it (`judge(<code>)` gives the code to sign, marked
/// "would deny" under the gate) — never directly. The kprobes and lockdown
/// switches' code comes from `switch_file_op`; PID 1's ptrace is the
/// branch that is not the agent's.
#[test]
fn every_host_wide_refusal_is_signed_as_the_switch_decided() {
    let code = ebpf_code();
    for name in [
        "FS_OP_BPF_PROG_TYPE",
        "FS_OP_SYSCTL_ROOT_ATTACH",
        "FS_OP_KEXEC",
        "FS_OP_SYSCTL",
        "FS_OP_SYSCTL_VALUE",
        "FS_OP_CGROUP_V1",
        "FS_OP_KPROBES",
        "FS_OP_LOCKDOWN",
    ] {
        let mut uses = 0;
        for (file, text) in &code {
            let text = blank_uses(text);
            let mut from = 0;
            while let Some(i) = text[from..].find(name) {
                let at = from + i;
                from = at + name.len();
                let next = text.as_bytes().get(from).copied().unwrap_or(b' ');
                if next.is_ascii_alphanumeric() || next == b'_' {
                    continue; // a longer name (FS_OP_SYSCTL_VALUE)
                }
                uses += 1;
                let before = text[..at].trim_end_matches("northnarrow_common::wire::");
                assert!(
                    before.ends_with("crate::host_deny::judge(")
                        || before.ends_with("crate::host_deny::judge_no_task("),
                    "{file}: {name} used outside crate::host_deny::judge"
                );
            }
        }
        assert!(
            uses > 0 || matches!(name, "FS_OP_KPROBES" | "FS_OP_LOCKDOWN"),
            "{name} no longer refused anywhere"
        );
    }
    let files = &code["cgroup_files.rs"];
    let switch = functions(files)
        .into_iter()
        .find(|(n, _)| n == "refuse_switch")
        .expect("refuse_switch")
        .1;
    let op = switch
        .find("let op = switch_file_op(")
        .expect("the switch's code");
    let judged = switch
        .find("let (refuse, op) = crate::host_deny::judge(op);")
        .expect("judged");
    let signed = switch.find("sign(phase, op, key);").expect("signed");
    assert!(op < judged && judged < signed);
    assert!(switch
        .trim_end()
        .trim_end_matches('}')
        .trim_end()
        .ends_with("refuse"));
    let ptrace = &code["ptrace_check.rs"];
    let check = functions(ptrace)
        .into_iter()
        .find(|(n, _)| n == "try_ptrace_access_check")
        .expect("try_ptrace_access_check")
        .1;
    let own = check
        .find("let own_target = crate::task_kill::is_protected_pid(target_tgid)")
        .expect("the agent's targets");
    let branch = check.rfind("if !own_target {").expect("PID 1's branch");
    let pid1 = branch
        + check[branch..]
            .find("let (refuse, op) = crate::host_deny::judge(FS_OP_PTRACE);")
            .expect("PID 1's branch judged");
    assert!(check[pid1..].starts_with(
        "let (refuse, op) = crate::host_deny::judge(FS_OP_PTRACE);\n        if mode & PTRACE_MODE_NOAUDIT == 0 {\n            crate::inode_protect::emit_task_denial(op, mode as u64, target_tgid);\n        }\n        return if refuse { -EPERM } else { 0 };"
    ));
    let agent = check
        .rfind("crate::inode_protect::emit_task_denial(FS_OP_PTRACE, mode as u64, target_tgid);\n    }\n    -EPERM")
        .expect("the agent's ptrace refused");
    assert!(own < pid1 && pid1 < agent);
    // a "would deny" at an open refuses nothing: behind the per-caller dedup
    let sign = functions(files)
        .into_iter()
        .find(|(n, _)| n == "sign")
        .expect("cgroup_files::sign")
        .1;
    support_in_order(
        sign,
        &[
            "Phase::Open if northnarrow_common::wire::is_would_deny(operation) => {\n            crate::inode_protect::emit_limited(operation, key)\n        }",
            "Phase::Open => crate::inode_protect::emit_attempt(operation, key),",
        ],
    );
}

/// `needles` all in `hay`, in this order.
fn support_in_order(hay: &str, needles: &[&str]) {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => panic!("{n:?} not found after byte {at} in:\n{hay}"),
        }
    }
}

/// Named: the record of a deny the gate let through says "would deny" —
/// the decision pipeline asks for it before any other outcome.
#[test]
fn a_let_through_deny_is_recorded_would_deny_before_any_other_outcome() {
    let all = product_code(&repo_root());
    let pe = &all["agent/src/pipeline/process_event.rs"];
    support_in_order(
        pe,
        &[
            "let outcome = if let Some(text) = would_deny_outcome(&event) {\n                            text\n                        } else if let Some(exemption) = &covered {",
            "sink.record_denial(",
            "pub(crate) fn would_deny_outcome(event: &Event) -> Option<String> {",
            "would_deny: true,",
            "nn_core::response::profile::would_deny(",
        ],
    );
}

/// `text` with its `use` items blanked.
fn blank_uses(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("use ") {
        let word_start = i == 0 || {
            let p = rest.as_bytes()[i - 1];
            !(p.is_ascii_alphanumeric() || p == b'_')
        };
        if !word_start {
            out.push_str(&rest[..i + 4]);
            rest = &rest[i + 4..];
            continue;
        }
        out.push_str(&rest[..i]);
        let end = rest[i..].find(';').map_or(rest.len(), |e| i + e + 1);
        out.extend(
            rest[i..end]
                .chars()
                .map(|c| if c == '\n' { '\n' } else { ' ' }),
        );
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Named: the switch is the start's resolved gate's, written into the
/// object right after it loads and before any program attaches, then
/// frozen; per load, never pinned; its zero enforces.
#[test]
fn the_switch_is_written_from_the_resolved_gate_before_any_attach() {
    let all = product_code(&repo_root());
    let at = |rel: &str| {
        all.get(rel)
            .unwrap_or_else(|| panic!("{rel} not found"))
            .as_str()
    };
    let attach = at("agent/src/boot/attach.rs");
    let load = &attach[attach.find("fn load(").expect("attach::load")..];
    assert!(load.contains("host_deny_observe: detect_only,"));
    let mux = at("crates/nn-linux/src/sensors/multiplexer.rs");
    let start = &mux[mux.find("async fn do_start(").expect("do_start")..];
    let loaded = start.find(".load(EBPF_BYTES)").expect("the load");
    let armed = start
        .find("crate::anti_tamper::host_deny::arm(&mut ebpf, plan.host_deny_observe)")
        .expect("the switch armed");
    let first_attach = start
        .find("attach_fork_parent(&mut ebpf);")
        .expect("the first attach");
    assert!(loaded < armed && armed < first_attach);
    let userland = at("crates/nn-linux/src/anti_tamper/host_deny.rs");
    let arm = &userland[userland.find("pub fn arm(").expect("arm")..];
    let set = arm
        .find("mode.set(0, mode_value(observe), 0)")
        .expect("written");
    let frozen = arm
        .find("super::bpf_defense::freeze_named(ebpf, MODE_MAP)")
        .expect("frozen");
    assert!(set < frozen);
    // the round's half (the guarded sysctls put back) follows the same
    // gate: every call of the put-back writes only when the start enforces
    assert!(arm.contains("OBSERVE.store(observe, std::sync::atomic::Ordering::Release);"));
    let mut calls = 0;
    for (rel, text) in &all {
        for (at, _) in text.match_indices("crate::sysctl_guard::check(") {
            calls += 1;
            let call = &text[at..at + text[at..].find(")\n").expect("the call's end")];
            assert!(
                call.contains("!crate::anti_tamper::host_deny::observing(),"),
                "{rel}: the guarded sysctls put back whatever the gate:\n{call}"
            );
        }
    }
    assert_eq!(calls, 2, "the integrity round and a window's close");
    let kernel = at("agent-ebpf/src/host_deny.rs");
    assert!(
        kernel.contains("pub static HOST_DENY_MODE: Array<u32> = Array::with_max_entries(1, 0);")
    );
    assert!(kernel.contains("matches!(HOST_DENY_MODE.get(0), Some(m) if *m == HOST_DENY_OBSERVE)"));
}
