//! Lot 341 (the alpha profile; the coordinator's decision of 13/11, as
//! corrected after the review of #550): `alpha` means no response against
//! a user's programs — no kill, isolation, quarantine, exec-quarantine hold,
//! exec-policy deny, connect deny or exploit-guard response, each of them
//! recorded with what it would have done. The host's integrity and the
//! agent's self-protection are enforced under every profile. The host-wide
//! denies the first round left in observe were self-protection in disguise:
//! `kernel.ftrace_enabled=0`, `kprobes/enabled=0` and lockdown blind the
//! agent's hooks; a foreign tracing program's `bpf_send_signal` kills it past
//! `task_kill`; a cgroup v1 freezer freezes it; a ptrace of PID 1 races the
//! trusted writes the deny hooks let PID 1 make; a kexec image or an
//! untrusted module runs code no hook of the agent sees.
//!
//! The eBPF programs run only in a kernel (the lab's `nn-lab.sh
//! host-deny-check`). Here the code is read: every deny site of the object
//! is listed — the agent's self-protection or the host's integrity with its
//! reason, or a response path whose own mode the gate sets — a new deny site
//! fails until it is classified; and a self-protection site's function, and
//! every function it calls in the object (the review's planted helper, F6),
//! reads no switch of the gate.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use support::{matching_brace, product_code, repo_root};

/// How a deny site of the eBPF object meets the profile.
#[derive(Clone, Copy, Debug)]
enum Route {
    /// The agent's self-protection or the host's integrity: enforced under
    /// every profile — the function, and every function it calls, reads no
    /// switch of the gate ([`GATE_SWITCHES`]). The reason.
    Enforced(&'static str),
    /// A response path whose own mode the resolved gate sets (named in
    /// `xtask/tests/alpha_profile.rs`): the reason.
    Gated(&'static str),
    /// Returns what another listed function decided (named).
    Delegated(&'static str),
}

use Route::{Delegated, Enforced, Gated};

const AGENT: &str = "the agent, its watchdog or a worker (PROTECTED_PIDS, or a process running \
                     the agent's or the watchdog's binary)";
const OWN_FILES: &str = "the agent's files, units, directories and pins (PROTECTED_INODES)";

/// The switches the start writes from the resolved gate (`--detect-only`,
/// the detect-only variables, the `alpha` profile), each with the one file
/// of the object that declares and reads it: the exec quarantine's, the
/// exec policy's, the exploit guard's and the kernel connect deny's modes.
/// `HOST_DENY_MODE`, the first round's switch of the host-wide denies, is
/// gone and stays forbidden.
const GATE_SWITCHES: &[(&str, &str)] = &[
    ("EXECQ_CONF", "execq.rs"),
    ("EXECPOL_CONF", "execpol.rs"),
    ("EPG_CONFIG", "epg.rs"),
    ("NET_CONNECT_DENY_MODE", "socket_connect.rs"),
    ("HOST_DENY_MODE", ""),
];

/// Every deny site of `agent-ebpf/src`, by file and function: `(file,
/// function, sites, route)`. A function may hold sites of two routes (one
/// row each).
const SITES: &[(&str, &str, usize, Route)] = &[
    ("bpf_defense.rs", "try_bpf_map_guard", 2, Enforced("a read or write handle on one of the agent's MAPS (a program is loaded against a map, or a map written, only through one)")),
    ("bpf_defense.rs", "try_bpf_prog_guard", 1, Enforced("a handle on one of the agent's PROGRAMS (an freplace of one of its functions needs it)")),
    ("bpf_defense.rs", "try_bpf_syscall_observe", 1, Enforced("a foreign load of the nine program types that signal a process (`bpf_send_signal` kills the agent past task_kill), rewrite its memory, override a kernel function's return or take a hook's place, outside a window and the signed per-loader opt-out (install.sh --allow-bpf-tools / --allow-bpf-loader)")),
    ("bpf_defense.rs", "try_bpf_syscall_observe", 1, Enforced("a cgroup/sysctl program on the root cgroup: it runs after the sysctl guard and rewrites the value the guard judged")),
    ("bpf_defense.rs", "try_bpf_syscall_observe", 3, Enforced("a handle on one of the agent's links (by id or its pin), a handle by id on its maps or programs or one under its pin directories, a detach or update of one of its links")),
    ("cgroup_files.rs", "refuse_switch", 1, Enforced("the kprobes and lockdown switches: kprobes/enabled=0 disarms every kprobe of the agent, lockdown takes the kernel-memory helpers from its programs (it blinds the agent)")),
    ("cgroup_files.rs", "refuse_limit", 1, Enforced("a resource file of the agent's units' cgroups (kill, freeze, limits)")),
    ("cgroup_files.rs", "refuse_v1", 1, Enforced("a cgroup v1 write (cgroup.procs, tasks, freezer.state under a controller): a v1 freezer moves and freezes the agent past the v2 move guard (lot 273b)")),
    ("cgroup_files.rs", "refuse_sysctl", 1, Enforced("a guarded sysctl's file: kernel.ftrace_enabled=0 silences the BPF trampolines, the deny hooks' among them; the others abort or starve the agent")),
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
    ("module_load.rs", "try_read_file", 1, Enforced("an untrusted kernel module: it can do anything to the agent; only the signed policy relaxes the judge (module_trust::kernel_mode takes no gate)")),
    ("module_load.rs", "try_load_data", 1, Enforced("an untrusted kernel module: it can do anything to the agent; only the signed policy relaxes the judge (module_trust::kernel_mode takes no gate)")),
    ("module_load.rs", "deny_kexec", 1, Enforced("a kexec image: a kernel booted without the agent's hooks (the host's integrity)")),
    ("ptrace_check.rs", "try_ptrace_access_check", 1, Enforced("a ptrace of the agent, its watchdog or a worker, and an attach of PID 1: its memory swapped between a deny hook's read of a write PID 1 may make (a unit's limit, a thaw) and the kernel's (lot 273c)")),
    ("sigio_guard.rs", "try_file_send_sigiotask", 1, Enforced(AGENT)),
    ("socket_connect.rs", "try_socket_connect", 1, Gated("the kernel connect deny (its EPERM a negative constant): not armed under the gate (policy::arming)")),
    ("sysctl_guard.rs", "nn_sysctl_guard", 1, Delegated("try_sysctl_guard(")),
    ("sysctl_guard.rs", "try_sysctl_guard", 1, Enforced("the sysctl guard's value judge: the values refuse_sysctl guards")),
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

/// Every function of the object with a body, by name (two files may each
/// define one of a name: both bodies are kept).
fn all_functions(code: &BTreeMap<String, String>) -> BTreeMap<String, Vec<(String, String)>> {
    let mut out: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (file, text) in code {
        for (name, body) in functions(text) {
            out.entry(name)
                .or_default()
                .push((file.clone(), body.to_string()));
        }
    }
    out
}

/// The functions `body` calls: `(module, name)` — `module` the path
/// segment before the name (`crate::execq::conf(` → `execq`), `None` for a
/// bare call or a method.
fn calls(body: &str) -> BTreeSet<(Option<String>, String)> {
    let b = body.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = BTreeSet::new();
    for (at, _) in body.match_indices('(') {
        let mut s = at;
        while s > 0 && ident(b[s - 1]) {
            s -= 1;
        }
        if s == at || b[s].is_ascii_digit() {
            continue;
        }
        let mut module = None;
        if s >= 2 && &body[s - 2..s] == "::" {
            let mut m = s - 2;
            while m > 0 && ident(b[m - 1]) {
                m -= 1;
            }
            module = Some(body[m..s - 2].to_string());
        }
        out.insert((module, body[s..at].to_string()));
    }
    out
}

/// The bodies a call of `(module, name)` from `file` may run: the named
/// module's function; a bare call's or a method's in `file` when it
/// defines one, else every file's of that name (an over-approximation).
fn callees<'a>(
    fns: &'a BTreeMap<String, Vec<(String, String)>>,
    file: &str,
    module: &Option<String>,
    name: &str,
) -> Vec<&'a (String, String)> {
    let all: Vec<&(String, String)> = fns.get(name).into_iter().flatten().collect();
    let pick = |f: &str| -> Vec<&'a (String, String)> {
        all.iter()
            .copied()
            .filter(|(in_file, _)| in_file == f)
            .collect()
    };
    let own = match module.as_deref() {
        Some(m) if !matches!(m, "crate" | "self" | "super") => pick(&format!("{m}.rs")),
        _ => pick(file),
    };
    if own.is_empty() {
        all
    } else {
        own
    }
}

/// The gate's switches a self-protection site reaches: for each `Enforced`
/// row, its function and every function of the object it calls, to any
/// depth, and each switch named in one of them — `(site, the function that
/// names it, the switch)`. Also each switch named in a file other than its
/// own (an alias, a re-export: the name is the only handle the code reads
/// it by).
fn gate_reads(code: &BTreeMap<String, String>) -> Vec<String> {
    let fns = all_functions(code);
    let mut found = Vec::new();
    for (file, text) in code {
        for (switch, owner) in GATE_SWITCHES {
            if file != owner && words(text, switch) > 0 {
                found.push(format!("{file} names {switch} (only {owner:?} may)"));
            }
        }
    }
    for (file, name, _, route) in SITES {
        if !matches!(route, Enforced(_)) {
            continue;
        }
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        let mut todo: Vec<(&str, String)> = callees(&fns, file, &None, name)
            .into_iter()
            .map(|(f, body)| (body.as_str(), format!("{f} {name}")))
            .collect();
        while let Some((body, at)) = todo.pop() {
            if !seen.insert((at.clone(), body.to_string())) {
                continue;
            }
            for (switch, _) in GATE_SWITCHES {
                if words(body, switch) > 0 {
                    found.push(format!("{file} {name} reaches {switch} through {at}"));
                }
            }
            let in_file = at.split(' ').next().unwrap_or_default().to_string();
            for (module, callee) in calls(body) {
                for (f, next) in callees(&fns, &in_file, &module, &callee) {
                    todo.push((next.as_str(), format!("{f} {callee}")));
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Named: every deny site of the eBPF object is classified — the agent's
/// self-protection or the host's integrity (with its reason), a response
/// path whose mode the gate sets, or a function that returns a classified
/// one's verdict. A new site, or one more in a function, fails here until
/// it is classified.
#[test]
fn every_deny_site_is_listed_enforced_or_gated() {
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
    for (file, name, n, route) in SITES {
        *listed
            .entry((file.to_string(), name.to_string()))
            .or_default() += n;
        match route {
            Enforced(why) | Gated(why) => assert!(!why.is_empty()),
            Delegated(call) => {
                let text = &code[*file];
                let body = functions(text)
                    .into_iter()
                    .find(|(f, _)| f == name)
                    .map(|(_, b)| b)
                    .unwrap_or_else(|| panic!("fn {name} not found in {file}"));
                assert!(
                    body.contains(call),
                    "{file} {name} returns {call}…'s verdict"
                );
            }
        }
    }
    let census: Vec<String> = found
        .iter()
        .map(|((f, n), c)| format!("({f:?}, {n:?}, {c})"))
        .collect();
    assert_eq!(
        found, listed,
        "the deny sites of agent-ebpf changed — classify each (Enforced with its reason, \
         Gated, Delegated): {census:#?}"
    );
}

/// Named (the review of #550, F1–F4, F6): no self-protection site reads a
/// switch of the gate — not in its own body, not through a helper of the
/// object it calls at any depth — and no file but a switch's own names it.
/// The first round's host-wide switch (`HOST_DENY_MODE`) is gone.
#[test]
fn the_self_protection_reads_no_switch_of_the_gate() {
    let code = ebpf_code();
    let reads = gate_reads(&code);
    assert!(
        reads.is_empty(),
        "the agent's self-protection must hold under every profile: {reads:#?}"
    );
    assert!(!code.contains_key("host_deny.rs"));
    for (switch, owner) in GATE_SWITCHES {
        if !owner.is_empty() {
            assert!(
                words(&code[*owner], switch) > 0,
                "{owner} declares {switch} (the list is current)"
            );
        }
    }
}

/// `code` with `helper` added to `file` and `call` put first in `site`'s
/// body.
fn planted(
    code: &BTreeMap<String, String>,
    file: &str,
    site: &str,
    call: &str,
    helper: &str,
) -> BTreeMap<String, String> {
    let mut code = code.clone();
    let text = code.get_mut(file).expect("the site's file");
    let at = text
        .find(&format!("fn {site}("))
        .unwrap_or_else(|| panic!("fn {site} in {file}"));
    let open = at + text[at..].find('{').expect("a body") + 1;
    text.insert_str(open, call);
    text.push_str(helper);
    code
}

/// Named (the review of #550, F6: its probe, planted): a self-protection
/// function that reads a switch of the gate through a helper — one or two
/// calls deep, or by an alias — fails the ratchet. The review's probe read
/// the first round's switch from `try_task_kill` through `probe_relaxed`
/// and the ratchet stayed green.
#[test]
fn a_helper_that_reads_the_gate_from_the_self_protection_is_caught() {
    let code = ebpf_code();
    assert!(gate_reads(&code).is_empty());
    let one = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if probe_relaxed() {\n        return 0;\n    }\n",
        "\n#[inline(always)]\nfn probe_relaxed() -> bool {\n    \
         matches!(unsafe { crate::execq::EXECQ_CONF.get(0) }, Some(m) if *m != 0)\n}\n",
    );
    let r = gate_reads(&one);
    assert!(
        r.iter()
            .any(|l| l.contains("try_task_kill reaches EXECQ_CONF")),
        "{r:#?}"
    );
    // two calls deep, the switch read in its own file (no name outside it)
    let mut deep = planted(
        &code,
        "task_kill.rs",
        "try_task_kill",
        "\n    if relaxed_outer() {\n        return 0;\n    }\n",
        "\nfn relaxed_outer() -> bool {\n    crate::execpol::relaxed_inner()\n}\n",
    );
    deep.get_mut("execpol.rs").unwrap().push_str(
        "\npub(crate) fn relaxed_inner() -> bool {\n    EXECPOL_CONF.get(0).is_none()\n}\n",
    );
    let r = gate_reads(&deep);
    assert!(
        r.iter()
            .any(|l| l
                .contains("try_task_kill reaches EXECPOL_CONF through execpol.rs relaxed_inner")),
        "{r:#?}"
    );
    // an alias of the switch in a self-protection file
    let alias = planted(
        &code,
        "cgroup_files.rs",
        "refuse_sysctl",
        "\n    if MODE.get(0).is_some() {\n        return false;\n    }\n",
        "\nuse crate::socket_connect::NET_CONNECT_DENY_MODE as MODE;\n",
    );
    let r = gate_reads(&alias);
    assert!(
        r.iter()
            .any(|l| l.contains("cgroup_files.rs names NET_CONNECT_DENY_MODE")),
        "{r:#?}"
    );
    // the first round's switch, back under any name of a site's helper
    let back = planted(
        &code,
        "sysctl_guard.rs",
        "try_sysctl_guard",
        "\n    if observes() {\n        return 1;\n    }\n",
        "\nfn observes() -> bool {\n    HOST_DENY_MODE.get(0).is_some()\n}\n",
    );
    let r = gate_reads(&back);
    assert!(
        r.iter()
            .any(|l| l.contains("try_sysctl_guard reaches HOST_DENY_MODE")),
        "{r:#?}"
    );
}
