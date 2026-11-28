//! The trusted-installer window's vocabulary (FIM-009 self-upgrade, §15.1;
//! lab PR 225): the agent's own systemd units, the only ones whose
//! NN-L-FIM-009 verdict an open window downgrades, and who opened a window
//! and until when.
//!
//! R08b (lab PR 251): cut verbatim from the agent's
//! `anti_tamper::trusted_installer`, which re-exports both and keeps the
//! window itself — its kernel half (`FS_GRANT`, `KILL_GRANT`), its signed
//! close, its clock — until R04b splits the window from its kernel sync.
//! The rules that read them move to nn-core; they reach the window through
//! their host ([`crate::posture::host::PostureAgent::InstallerWindow`]).
//! R10 (lab PR 259): the window's ceiling too, which the agent clamps a
//! signed grant to and nn-admin clamps `--window-secs` to before it signs
//! (`MAX_TRUSTED_INSTALLER_WINDOW_SECS`, cut verbatim; the agent's module
//! re-exports it).

/// The agent's OWN systemd unit paths — the ONLY units whose
/// `NN-L-FIM-009` verdict the override downgrades. A write to any other
/// unit path still trips `KillProcess` even inside an open window. These
/// are the canonical install locations (`deploy/install.sh` copies the
/// units to `/etc/systemd/system/`).
pub const OWN_SYSTEMD_UNITS: &[&str] = &[
    "/etc/systemd/system/northnarrow-agent.service",
    "/etc/systemd/system/northnarrow-watchdog.service",
    // Review 26: a distro package ships the units in the vendor
    // directory. On a merged-/usr host the FIM sensor may report that
    // directory through either spelling.
    "/usr/lib/systemd/system/northnarrow-agent.service",
    "/usr/lib/systemd/system/northnarrow-watchdog.service",
    "/lib/systemd/system/northnarrow-agent.service",
    "/lib/systemd/system/northnarrow-watchdog.service",
    // Lab PR 216: the watchdog's `OnFailure=` handler.
    "/etc/systemd/system/northnarrow-watchdog-failed.service",
    "/usr/lib/systemd/system/northnarrow-watchdog-failed.service",
    "/lib/systemd/system/northnarrow-watchdog-failed.service",
    // Lot 273d: the units' slice.
    "/etc/systemd/system/northnarrow.slice",
    "/usr/lib/systemd/system/northnarrow.slice",
    "/lib/systemd/system/northnarrow.slice",
];

/// Lot 273d (round 17's C111): our units' drop-in directories under the
/// unit directories NN-L-FIM-009 watches. A drop-in written in one of them
/// inside an open window is the operator's configuration — judged at the
/// window's close (`own_dropins`), never a reason to kill its writer.
pub const OWN_UNIT_DROPIN_DIRS: &[&str] = &[
    "northnarrow-agent.service.d",
    "northnarrow-watchdog.service.d",
    "northnarrow-.service.d",
    "northnarrow.slice.d",
];

/// `path` is a drop-in of our units: `<unit dir>/<one of
/// [`OWN_UNIT_DROPIN_DIRS`]>/<name>.conf`, one level deep, no `.` or `..`.
pub fn is_own_unit_dropin(path: &str) -> bool {
    [
        "/etc/systemd/system/",
        "/usr/lib/systemd/system/",
        "/lib/systemd/system/",
    ]
    .iter()
    .filter_map(|p| path.strip_prefix(p))
    .any(|rest| match rest.split_once('/') {
        Some((dir, name)) => {
            OWN_UNIT_DROPIN_DIRS.contains(&dir)
                && name.ends_with(".conf")
                && !name.contains('/')
                && name != ".conf"
                && !name.starts_with('.')
        }
        None => false,
    })
}

/// Lab PR 225: who opened the current window and when it ends — named in
/// the records the window sanctions (a stop or restart of the agent's own
/// units, NN-L-EVA-001 at Low: [`crate::impair`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowGrant {
    /// Fingerprint of the admin key whose signed grant opened the window.
    pub key_id: String,
    /// The window's deadline, wall clock (UTC, RFC 3339 to the second).
    pub expires_at: String,
    /// Lot 278: the installer the window was granted to — the process that
    /// ran `nn-admin trusted-installer-grant` (the requester's parent) —
    /// when the agent could tell it. R009 records, at Low, what that
    /// process's own tree executes from a home or `/tmp` while the window
    /// is open, after the grant: the tree by lineage from that process
    /// (its pid and its start), never by a name or a path.
    pub grantee: Option<WindowGrantee>,
}

/// Lot 278: the process a trusted-installer window was granted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowGrantee {
    pub pid: u32,
    /// Its start, `starttime` (field 22) of `/proc/<pid>/stat`, in clock
    /// ticks since boot: with the pid, the process itself (a pid reused
    /// since names another start).
    pub start_ticks: u64,
    /// When the window was granted to it (`CLOCK_MONOTONIC` ns, the clock
    /// of the exec events): what its tree executed before is not covered.
    pub granted_ns: u64,
}

/// Hard ceiling on a grant window. A grant whose `window_secs` exceeds
/// this is clamped down — a captured or fat-fingered grant can never
/// hold the FS pin open longer than this, and the operator lifecycle
/// (arm → install → `systemctl restart`) closes it far sooner in
/// practice. 10 minutes is generous for an in-place upgrade.
pub const MAX_TRUSTED_INSTALLER_WINDOW_SECS: u32 = 600;

// ── Lot 2.3b: the window per process tree, the user flows ──────────────
//
// The decisions of the flows that need no host: `nn-admin window-run`'s
// environment, the admission policy's shapes of a root, the system code the
// window freezes against outsiders, our units' enablement links a lease may
// name, and PID 1's environment. The design:
// `docs/design/ANTITAMPER_TRUST_MODEL.md`, "Trusted-installer window per
// process tree", sections 1 to 3.

/// `nn-admin window-run`'s `PATH`: the system default, whatever the
/// caller's was (a directory a user can write is never searched).
pub const WINDOW_RUN_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The variables `nn-admin window-run` passes to its command, besides
/// [`WINDOW_RUN_PATH`] and the `LC_*` family; every other is dropped. The
/// terminal, the locale and the user's identity; the key `install.sh` signs
/// a rollback's window with (`NN_GRANT_KEY`); and the non-interactive
/// switches of the package tools (`DEBIAN_FRONTEND`, `DEBIAN_PRIORITY`,
/// `DEBCONF_NONINTERACTIVE_SEEN`). None of them is a variable the
/// kernel's eviction rule judges dangerous (a ratchet holds it): a root
/// login shell's exported functions (`BASH_FUNC_which%%` on RHEL), its
/// options and the loader's variables never reach the command.
pub const WINDOW_RUN_ENV_KEPT: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "TERM",
    "LANG",
    "LANGUAGE",
    "TZ",
    "NO_COLOR",
    "NN_GRANT_KEY",
    "DEBIAN_FRONTEND",
    "DEBIAN_PRIORITY",
    "DEBCONF_NONINTERACTIVE_SEEN",
];

/// The longest value [`window_run_env`] passes on (a longer one is dropped:
/// the kernel's eviction rule reads a bounded environment).
pub const WINDOW_RUN_ENV_VALUE_MAX: usize = 1024;

/// The environment `nn-admin window-run` gives its command, from the
/// caller's `vars`: [`WINDOW_RUN_PATH`], the kept names
/// ([`WINDOW_RUN_ENV_KEPT`]) and the `LC_*` locale variables, each with a
/// value no longer than [`WINDOW_RUN_ENV_VALUE_MAX`] and free of NUL; every
/// other variable is dropped. Sorted by name, one value per name.
pub fn window_run_env<I>(vars: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let locale = |k: &str| {
        k == "LANG"
            || k == "LANGUAGE"
            || (k.len() > 3
                && k.starts_with("LC_")
                && k[3..].bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
    };
    let mut out: std::collections::BTreeMap<String, String> = vars
        .into_iter()
        .filter(|(k, v)| {
            (WINDOW_RUN_ENV_KEPT.contains(&k.as_str()) || locale(k))
                && v.len() <= WINDOW_RUN_ENV_VALUE_MAX
                && !v.contains('\0')
                // a locale named by a path, a time zone read from a file of
                // the caller's choosing: the C library would load them
                && !(locale(k) && v.contains('/'))
                && !(k == "TZ" && (v.starts_with('/') || v.starts_with(':')))
        })
        .collect();
    out.insert("PATH".to_string(), WINDOW_RUN_PATH.to_string());
    out.into_iter().collect()
}

/// Our package's name in the package managers' databases.
pub const OUR_PACKAGE: &str = "northnarrow";

/// The system directories a root's or a line's shell is read from.
const SYSTEM_BIN_DIRS: &[&str] = &["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"];

/// The shells our scripts and the package scriptlets run under.
const SHELLS: &[&str] = &["sh", "bash", "dash"];

/// Whether `exe` (`/proc/<pid>/exe`, resolved) is a system shell — a
/// script root's, or a scriptlet's between a package manager and
/// `nn-admin`.
pub fn is_system_shell(exe: &str) -> bool {
    SYSTEM_BIN_DIRS.iter().any(|d| {
        exe.strip_prefix(d)
            .is_some_and(|name| SHELLS.contains(&name))
    })
}

/// The package managers whose process may root a window for our package's
/// scriptlet: their packaged binaries.
const PACKAGE_MANAGERS: &[&str] = &[
    "/usr/bin/dpkg",
    "/usr/bin/rpm",
    "/usr/bin/dnf5",
    "/usr/bin/microdnf",
    "/usr/bin/zypper",
];

/// dnf and yum before dnf5 are Python programs: the process runs the
/// interpreter, the program is its first argument.
const PYTHON_PACKAGE_MANAGERS: &[&str] = &[
    "/usr/bin/dnf",
    "/usr/bin/dnf-3",
    "/usr/bin/yum",
    "/bin/dnf",
    "/bin/yum",
];

/// The package manager `exe` (resolved) running `cmdline` is, by its
/// packaged program: `dpkg`, `rpm`, … — `None` for any other process.
pub fn package_manager(exe: &str, cmdline: &[String]) -> Option<&'static str> {
    let usr = |p: &str| {
        p.strip_prefix("/usr")
            .filter(|r| r.starts_with('/'))
            .map(str::to_string)
    };
    if let Some(m) = PACKAGE_MANAGERS
        .iter()
        .find(|m| **m == exe || usr(m).as_deref() == Some(exe))
    {
        return m.rsplit('/').next();
    }
    let python = ["/usr/bin/", "/usr/libexec/"].iter().any(|d| {
        exe.strip_prefix(d).is_some_and(|n| {
            (n.starts_with("python3") || n.starts_with("platform-python")) && !n.contains('/')
        })
    });
    if !python {
        return None;
    }
    let prog = cmdline.get(1)?;
    PYTHON_PACKAGE_MANAGERS
        .iter()
        .find(|m| **m == prog.as_str())
        .and_then(|m| m.rsplit('/').next())
}

/// Whether the environment `env` (`/proc/<pid>/environ`'s `NAME=value`
/// entries) is that of a scriptlet of our package: dpkg's
/// `DPKG_MAINTSCRIPT_PACKAGE`, or rpm's `RPM_PACKAGE_NAME`, naming
/// [`OUR_PACKAGE`].
pub fn is_our_scriptlet_env<'a, I>(env: I) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    env.into_iter().any(|e| {
        matches!(
            e.split_once('='),
            Some(("DPKG_MAINTSCRIPT_PACKAGE" | "RPM_PACKAGE_NAME", v)) if v == OUR_PACKAGE
        )
    })
}

/// The system code a window freezes against every process outside its
/// tree (the design's section 3, "The system's code is frozen"), and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freeze {
    /// The object and everything below it (the kernel walks up to
    /// [`FREEZE_WALK`] directories from what is changed).
    Subtree,
    /// Only the object itself: it is not renamed, removed or replaced (an
    /// ancestor of a frozen subtree; a file of the loader's configuration).
    SelfOnly,
}

/// How many directories the kernel walks up from the object an outsider
/// changes, looking for a frozen subtree (`common::window_tree`'s).
pub const FREEZE_WALK: usize = common::window_tree::FREEZE_WALK as usize;

/// The frozen objects, by path: the default `PATH` directories
/// (`/usr/local` included), the loader's search directories, the
/// interpreters' library directories, the loader's configuration, the
/// package managers' hook, plugin and maintainer-script directories, PID
/// 1's manager configuration and `binfmt_misc`; and, rename-only, the
/// ancestors that would move them. An object that does not exist at the
/// grant is frozen by its name in its parent (it cannot be created):
/// [`frozen_names`].
pub const FROZEN: &[(&str, Freeze)] = &[
    ("/usr/local/sbin", Freeze::Subtree),
    ("/usr/local/bin", Freeze::Subtree),
    ("/usr/sbin", Freeze::Subtree),
    ("/usr/bin", Freeze::Subtree),
    ("/sbin", Freeze::Subtree),
    ("/bin", Freeze::Subtree),
    ("/usr/lib", Freeze::Subtree),
    ("/usr/lib64", Freeze::Subtree),
    ("/usr/libexec", Freeze::Subtree),
    ("/lib", Freeze::Subtree),
    ("/lib64", Freeze::Subtree),
    ("/usr/local/lib", Freeze::Subtree),
    ("/usr/local/lib64", Freeze::Subtree),
    ("/usr/share/perl5", Freeze::Subtree),
    ("/usr/share/perl", Freeze::Subtree),
    ("/etc/ld.so.preload", Freeze::Subtree),
    ("/etc/ld.so.cache", Freeze::Subtree),
    ("/etc/ld.so.conf", Freeze::Subtree),
    ("/etc/ld.so.conf.d", Freeze::Subtree),
    ("/etc/apt/apt.conf", Freeze::Subtree),
    ("/etc/apt/apt.conf.d", Freeze::Subtree),
    ("/etc/dpkg/dpkg.cfg", Freeze::Subtree),
    ("/etc/dpkg/dpkg.cfg.d", Freeze::Subtree),
    ("/var/lib/dpkg/info", Freeze::Subtree),
    ("/etc/dnf/dnf.conf", Freeze::Subtree),
    ("/etc/dnf/plugins", Freeze::Subtree),
    ("/etc/yum.conf", Freeze::Subtree),
    ("/etc/yum/pluginconf.d", Freeze::Subtree),
    ("/etc/rpm", Freeze::Subtree),
    ("/etc/systemd/system.conf", Freeze::Subtree),
    ("/etc/systemd/system.conf.d", Freeze::Subtree),
    ("/run/systemd/system.conf.d", Freeze::Subtree),
    ("/proc/sys/fs/binfmt_misc", Freeze::Subtree),
    ("/usr", Freeze::SelfOnly),
    ("/usr/local", Freeze::SelfOnly),
    ("/usr/share", Freeze::SelfOnly),
    ("/etc/apt", Freeze::SelfOnly),
    ("/etc/dpkg", Freeze::SelfOnly),
    ("/var/lib/dpkg", Freeze::SelfOnly),
    ("/var/lib", Freeze::SelfOnly),
    ("/etc/dnf", Freeze::SelfOnly),
    ("/etc/yum", Freeze::SelfOnly),
    ("/etc/systemd", Freeze::SelfOnly),
    ("/run/systemd", Freeze::SelfOnly),
];

/// The frozen objects whose name is frozen in their parent directory
/// (`(parent, name, how)`): every [`FROZEN`] object directly below a
/// directory that is itself not a frozen subtree — so that an outsider can
/// neither create one that does not exist (`/etc/ld.so.preload`) nor put
/// another in its place. The name of an object below a frozen subtree is
/// that subtree's already.
pub fn frozen_names() -> Vec<(&'static str, &'static str, Freeze)> {
    frozen_names_of(FROZEN)
}

/// [`frozen_names`] of the list `frozen`.
fn frozen_names_of(frozen: &[(&'static str, Freeze)]) -> Vec<(&'static str, &'static str, Freeze)> {
    frozen
        .iter()
        .filter_map(|(path, how)| {
            let (parent, name) = path.rsplit_once('/')?;
            let parent = if parent.is_empty() { "/" } else { parent };
            // component by component (`/usr/lib64` is not below `/usr/lib`)
            let under_subtree = frozen
                .iter()
                .any(|(p, h)| *h == Freeze::Subtree && std::path::Path::new(parent).starts_with(p));
            (!under_subtree && !name.is_empty()).then_some((parent, name, *how))
        })
        .collect()
}

/// The longest name the kernel compares for [`frozen_names`] (its 32-byte
/// key, the terminating NUL included).
pub const FROZEN_NAME_MAX: usize = 31;

/// Whether `name` is one of our units' enablement links' names
/// (`common::window_tree::UNIT_LINK_NAMES`, the kernel's), as a lease's
/// link must be named.
pub fn is_unit_link_name(name: &str) -> bool {
    common::window_tree::UNIT_LINK_NAMES.contains(&name.as_bytes())
}

/// The unit directories our enablement links live in.
const UNIT_LINK_ROOTS: &[&str] = &[
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/lib/systemd/system/",
    "/run/systemd/system/",
];

/// The link a lease may name (`path`, absolute): one of our units' names
/// ([`is_unit_link_name`]) in a `<target>.wants` or `<target>.requires`
/// directory of a unit directory, one level deep, no `.` or `..` and no
/// other separator — `(directory, name)`. `None` for any other path: a
/// mask, a drop-in, a link to another unit, any file of ours.
pub fn lease_link(path: &str) -> Option<(&str, &str)> {
    let (dir, name) = path.rsplit_once('/')?;
    if !is_unit_link_name(name) {
        return None;
    }
    let target = UNIT_LINK_ROOTS.iter().find_map(|r| {
        format!("{dir}/")
            .strip_prefix(r)
            .map(|t| t.trim_end_matches('/').to_string())
    })?;
    let unit = target
        .strip_suffix(".wants")
        .or_else(|| target.strip_suffix(".requires"))?;
    // (no `/` either: the characters below exclude it)
    let ok = !unit.is_empty()
        && !unit.starts_with('.')
        && unit.contains('.')
        && unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@:\\".contains(&b));
    ok.then_some((dir, name))
}

/// Whether PID 1's manager environment changed between the window's grant
/// (`at_grant`) and now (`now`): the same variables, in any order. A
/// change closes the window, High (the design's section 3, "PID 1's
/// global environment": detected, not refused).
pub fn pid1_env_changed(at_grant: &[String], now: &[String]) -> bool {
    let mut a: Vec<&String> = at_grant.iter().collect();
    let mut b: Vec<&String> = now.iter().collect();
    a.sort();
    b.sort();
    a != b
}

#[cfg(test)]
mod window_flow_tests {
    use super::*;

    fn s(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Lot 2.3b (the re-check of #647): `window-run`'s command gets the
    /// system `PATH` and the kept names only — a RHEL root login shell's
    /// `BASH_FUNC_which%%`, the loader's variables and a user's `PATH` are
    /// dropped, the locale kept.
    #[test]
    fn window_run_keeps_the_allowlist_and_the_system_path_only() {
        let env = window_run_env(s(&[
            ("PATH", "/home/u/bin:/usr/bin"),
            (
                "BASH_FUNC_which%%",
                "() { ( alias; eval ${which_declare} ) | /usr/bin/which }",
            ),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("SHELLOPTS", "xtrace"),
            ("PS4", "$(id)"),
            ("HOME", "/root"),
            ("LANG", "C.UTF-8"),
            ("LC_ALL", "C"),
            ("LC_", "x"),
            ("LC_lower", "x"),
            ("TERM", "xterm"),
            ("NN_GRANT_KEY", "/root/admin.key"),
            ("DEBIAN_FRONTEND", "noninteractive"),
            ("TZDIR", "/tmp/tz"),
            ("USER", &"u".repeat(WINDOW_RUN_ENV_VALUE_MAX + 1)),
            ("LC_CTYPE", "/tmp/locale"),
            ("TZ", ":/tmp/zone"),
        ]));
        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "DEBIAN_FRONTEND",
                "HOME",
                "LANG",
                "LC_ALL",
                "NN_GRANT_KEY",
                "PATH",
                "TERM"
            ]
        );
        assert!(env.contains(&("PATH".to_string(), WINDOW_RUN_PATH.to_string())));
        // a zone by its name is kept, by a path it is not
        let tz = window_run_env(s(&[("TZ", "Europe/Rome"), ("LANGUAGE", "it:en")]));
        assert!(
            tz.contains(&("TZ".to_string(), "Europe/Rome".to_string())),
            "{tz:?}"
        );
        assert!(
            tz.contains(&("LANGUAGE".to_string(), "it:en".to_string())),
            "{tz:?}"
        );
        assert!(
            window_run_env(s(&[("TZ", "/etc/x")]))
                .iter()
                .all(|(k, _)| k != "TZ")
        );
    }

    /// Lot 2.3b: no name `window-run` keeps is one the kernel's eviction
    /// rule judges dangerous (`common::window_tree::DANGEROUS_ENV`): the
    /// environment is sanitised, the eviction list is not weakened.
    #[test]
    fn no_kept_variable_is_one_the_eviction_rule_judges_dangerous() {
        let mut names: Vec<String> = WINDOW_RUN_ENV_KEPT.iter().map(|n| n.to_string()).collect();
        names.push("PATH".to_string());
        names.push("LC_ALL".to_string());
        for n in names {
            let var = format!("{n}=x");
            for p in common::window_tree::DANGEROUS_ENV {
                assert!(
                    !var.as_bytes().starts_with(p),
                    "{n} kept by window-run is judged dangerous ({})",
                    String::from_utf8_lossy(p)
                );
            }
        }
    }

    /// Lot 2.3b (the admission policy): a system shell, a package manager
    /// by its packaged program, our scriptlet by its package manager's
    /// variables — and nothing else.
    #[test]
    fn the_admission_shapes_are_told_by_their_program() {
        assert!(is_system_shell("/usr/bin/bash") && is_system_shell("/bin/sh"));
        assert!(is_system_shell("/usr/bin/dash"));
        for not in [
            "/tmp/bash",
            "/usr/local/bin/bash",
            "/usr/bin/zsh",
            "/usr/bin/bash5",
            "/usr/bin/",
        ] {
            assert!(!is_system_shell(not), "{not}");
        }
        let cmd = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            package_manager("/usr/bin/dpkg", &cmd(&["dpkg"])),
            Some("dpkg")
        );
        assert_eq!(package_manager("/bin/rpm", &cmd(&["rpm"])), Some("rpm"));
        assert_eq!(
            package_manager(
                "/usr/bin/python3.9",
                &cmd(&["/usr/bin/python3", "/usr/bin/dnf", "install"])
            ),
            Some("dnf")
        );
        assert_eq!(
            package_manager(
                "/usr/libexec/platform-python3.6",
                &cmd(&["/usr/libexec/platform-python", "/usr/bin/yum"])
            ),
            Some("yum")
        );
        for (exe, c) in [
            ("/usr/bin/python3.9", cmd(&["python3", "/tmp/dnf"])),
            ("/usr/bin/python3.9", cmd(&["python3"])),
            ("/tmp/dpkg", cmd(&["dpkg"])),
            ("/usr/sbin/sshd", cmd(&["sshd"])),
            ("/usr/bin/apt", cmd(&["apt"])),
            ("/home/u/python3", cmd(&["python3", "/usr/bin/dnf"])),
            ("/tmp/python3", cmd(&["python3", "/usr/bin/dnf"])),
            ("/usr/bin/perl", cmd(&["perl", "/usr/bin/dnf"])),
        ] {
            assert_eq!(package_manager(exe, &c), None, "{exe} {c:?}");
        }
        assert!(is_our_scriptlet_env([
            "A=1",
            "DPKG_MAINTSCRIPT_PACKAGE=northnarrow"
        ]));
        assert!(is_our_scriptlet_env(["RPM_PACKAGE_NAME=northnarrow"]));
        assert!(!is_our_scriptlet_env(["DPKG_MAINTSCRIPT_PACKAGE=other"]));
        assert!(!is_our_scriptlet_env([
            "DPKG_MAINTSCRIPT_PACKAGE=northnarrow-extra"
        ]));
        assert!(!is_our_scriptlet_env([
            "XDPKG_MAINTSCRIPT_PACKAGE=northnarrow"
        ]));
    }

    /// Lot 2.3b (D5): the frozen set holds every class the design names,
    /// each subtree's ancestors are frozen against a rename, and a name is
    /// frozen in its parent only outside a frozen subtree.
    #[test]
    fn the_frozen_set_covers_the_design_s_classes_and_their_ancestors() {
        let subtree = |p: &str| FROZEN.iter().any(|(f, h)| *f == p && *h == Freeze::Subtree);
        for p in [
            "/usr/bin",
            "/usr/local/bin",
            "/usr/lib",
            "/etc/ld.so.preload",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf.d",
            "/etc/apt/apt.conf",
            "/etc/apt/apt.conf.d",
            "/etc/dpkg/dpkg.cfg",
            "/etc/dpkg/dpkg.cfg.d",
            "/etc/dnf/dnf.conf",
            "/etc/yum.conf",
            "/var/lib/dpkg/info",
            "/etc/dnf/plugins",
            "/etc/systemd/system.conf",
            "/etc/systemd/system.conf.d",
            "/run/systemd/system.conf.d",
            "/proc/sys/fs/binfmt_misc",
        ] {
            assert!(subtree(p), "{p}");
        }
        // every subtree's parents up to `/` (but `/etc`, `/proc`, `/run`
        // and `/var`, which the agent's own ancestors or the kernel hold)
        // are frozen against a rename
        for (p, h) in FROZEN {
            if *h != Freeze::Subtree {
                continue;
            }
            let mut cur = *p;
            while let Some((parent, _)) = cur.rsplit_once('/') {
                if parent.is_empty()
                    || ["/etc", "/proc", "/proc/sys", "/proc/sys/fs", "/run", "/var"]
                        .contains(&parent)
                {
                    break;
                }
                assert!(
                    FROZEN.iter().any(|(f, _)| *f == parent),
                    "{parent} (above {p}) can be renamed"
                );
                cur = parent;
            }
        }
        let names = frozen_names();
        assert!(names.contains(&("/etc", "ld.so.preload", Freeze::Subtree)));
        assert!(names.contains(&("/run/systemd", "system.conf.d", Freeze::Subtree)));
        assert!(names.contains(&("/etc", "apt", Freeze::SelfOnly)));
        assert!(names.contains(&("/", "usr", Freeze::SelfOnly)));
        // `/usr` is rename-only, not a subtree: `/usr/bin` is named there
        assert!(names.contains(&("/usr", "bin", Freeze::Subtree)));
        assert!(
            names.contains(&("/", "bin", Freeze::Subtree)),
            "merged-/usr's link"
        );
        assert!(
            !names.iter().any(|(p, _, _)| *p == "/usr/lib"),
            "below /usr/lib"
        );
        for (_, n, _) in &names {
            assert!(n.len() <= FROZEN_NAME_MAX && !n.contains('/'), "{n}");
        }
        // an object below a frozen subtree is named by it already
        let below = frozen_names_of(&[
            ("/usr/lib", Freeze::Subtree),
            ("/usr/lib/x", Freeze::Subtree),
            ("/usr/lib64", Freeze::Subtree),
        ]);
        assert!(
            !below.iter().any(|(p, n, _)| *p == "/usr/lib" && *n == "x"),
            "{below:?}"
        );
        assert!(
            below.contains(&("/usr", "lib64", Freeze::Subtree)),
            "not below /usr/lib: {below:?}"
        );
    }

    /// Lot 2.3b: a lease names one of our units' enablement links and
    /// nothing else.
    #[test]
    fn a_lease_names_one_of_our_enablement_links_only() {
        assert_eq!(
            lease_link("/etc/systemd/system/multi-user.target.wants/northnarrow-agent.service"),
            Some((
                "/etc/systemd/system/multi-user.target.wants",
                "northnarrow-agent.service"
            ))
        );
        assert!(lease_link("/etc/systemd/system/northnarrow-agent.service.requires/northnarrow-watchdog.service").is_some());
        assert_eq!(
            lease_link("/etc/systemd/system/multi-user.target.wants/northnarrow.slice"),
            None
        );
        assert!(
            lease_link(
                "/usr/lib/systemd/system/sysinit.target.requires/northnarrow-watchdog.service"
            )
            .is_some()
        );
        for not in [
            "/etc/systemd/system/northnarrow-agent.service",
            "/etc/systemd/system/multi-user.target.wants/sshd.service",
            "/etc/systemd/system/multi-user.target.d/northnarrow-agent.service",
            "/etc/systemd/system/../system/multi-user.target.wants/northnarrow-agent.service",
            "/etc/systemd/system/a/multi-user.target.wants/northnarrow-agent.service",
            "/etc/systemd/system/.wants/northnarrow-agent.service",
            "/tmp/multi-user.target.wants/northnarrow-agent.service",
            "/etc/systemd/system/multi-user.target.wants/northnarrow-agent.service.d",
            "northnarrow-agent.service",
        ] {
            assert_eq!(lease_link(not), None, "{not}");
        }
    }

    /// Lot 2.3b: PID 1's environment is compared as a set.
    #[test]
    fn pid1_s_environment_is_compared_as_a_set() {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(!pid1_env_changed(&v(&["A=1", "B=2"]), &v(&["B=2", "A=1"])));
        assert!(pid1_env_changed(
            &v(&["A=1"]),
            &v(&["A=1", "LD_PRELOAD=/x.so"])
        ));
        assert!(pid1_env_changed(&v(&["A=1"]), &v(&["A=2"])));
        assert!(pid1_env_changed(&v(&["A=1", "B=2"]), &v(&["A=1"])));
    }
}
