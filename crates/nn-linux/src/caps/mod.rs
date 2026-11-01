//! The capabilities of the core's threads (Wave 4 restructure, R14c — plan
//! §3.1, §3.2).
//!
//! The unit's bounding set is the ceiling of the whole process
//! (`deploy/systemd/northnarrow-agent.service`); Linux keeps the effective,
//! permitted and inheritable sets per thread (`capset(2)` changes the
//! calling thread only, and a thread starts with its creator's). A thread
//! with a [`Role`] keeps effective only what the role names:
//!
//! | role | threads | effective | permitted |
//! |---|---|---|---|
//! | [`Role::Decision`] | `nn-decision` | [`Role::Decision`]'s set | the same: the rest given up for good, and a seccomp filter of its own ([`filter`]) refuses `capset`, `execve`, `execveat`, `bpf` and the calls that reach another process's memory |
//! | [`Role::Actuator`] | `nn-response-*`, `nn-response-watch` | `KILL NET_ADMIN SETFCAP DAC_OVERRIDE SYS_PTRACE` | the bounding set |
//! | [`Role::Writer`] | `nn-canary-log` | `LINUX_IMMUTABLE` | the bounding set |
//! | [`Role::Supervisor`] | `nn-workers` | `SETUID SETGID KILL BPF` | the bounding set |
//! | [`Role::Loader`] | the start's thread while the eBPF object loads and attaches ([`lower`]) | `BPF PERFMON` (and `SYS_ADMIN` where the Debian drop-in grants it) | the bounding set |
//! | [`Role::Errands`] | `nn-errands` ([`errands`]): what the decision's filter refuses it, done for it | `BPF` | the bounding set |
//!
//! Every other thread — tokio's runtime, the sensors' pumps, the admin
//! server's tasks, the chain writers that run on the runtime — keeps the
//! bounding set effective ([`restore_core`] at a runtime thread's start:
//! a thread started by a role's thread is not left with that role's set).
//!
//! What this is, and what it is not: the threads share one address space,
//! so a thread's set is no wall against code that runs in the process —
//! the process boundary is the worker's ([`crate::worker`], plan §3.5). A
//! thread's set bounds what that thread's own calls can do: a flaw that
//! steers the decision into an `execve`, a `bpf` or a `capset`, or into an
//! action of another thread's (a kill, an nft rule, a `chattr`), meets
//! `EPERM`.

pub mod errands;
pub mod filter;

#[cfg(test)]
mod tests;

use std::fmt;
use std::io;

/// Capability numbers (`linux/capability.h`): the ones the core uses.
pub mod cap {
    pub const DAC_OVERRIDE: u8 = 1;
    pub const KILL: u8 = 5;
    pub const SETGID: u8 = 6;
    pub const SETUID: u8 = 7;
    pub const LINUX_IMMUTABLE: u8 = 9;
    pub const NET_ADMIN: u8 = 12;
    pub const SYS_PTRACE: u8 = 19;
    pub const SYS_ADMIN: u8 = 21;
    pub const SETFCAP: u8 = 31;
    pub const PERFMON: u8 = 38;
    pub const BPF: u8 = 39;
}

/// Every capability's name, by number (`CAP_` left out).
pub const NAMES: [&str; 41] = [
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_PTRACE",
    "SYS_PACCT",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "AUDIT_READ",
    "PERFMON",
    "BPF",
    "CHECKPOINT_RESTORE",
];

/// A set of capabilities (bit N: capability N).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CapSet(u64);

impl CapSet {
    pub const EMPTY: Self = Self(0);

    /// The set of `caps`.
    pub const fn of(caps: &[u8]) -> Self {
        let mut bits = 0u64;
        let mut i = 0;
        while i < caps.len() {
            bits |= 1 << caps[i];
            i += 1;
        }
        Self(bits)
    }

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, cap: u8) -> bool {
        cap < 64 && self.0 & (1 << cap) != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// `self` without `other`'s.
    pub const fn minus(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// The names, by number (`CAP_` left out; a number past [`NAMES`] as
    /// itself).
    pub fn names(self) -> Vec<String> {
        (0u8..64)
            .filter(|c| self.contains(*c))
            .map(|c| {
                NAMES
                    .get(usize::from(c))
                    .map_or_else(|| c.to_string(), |n| (*n).to_string())
            })
            .collect()
    }
}

impl fmt::Display for CapSet {
    /// `KILL NET_ADMIN …`, or `none`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        f.write_str(&self.names().join(" "))
    }
}

impl fmt::Debug for CapSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapSet({self})")
    }
}

/// A thread's three sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreadCaps {
    pub effective: CapSet,
    pub permitted: CapSet,
    pub inheritable: CapSet,
}

#[repr(C)]
struct Header {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `_LINUX_CAPABILITY_VERSION_3`: two data entries (64 bits).
const VERSION_3: u32 = 0x2008_0522;

/// The calling thread's sets (`capget`, pid 0: this thread).
pub fn this_thread() -> io::Result<ThreadCaps> {
    let hdr = Header {
        version: VERSION_3,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: capget with a version-3 header and its two data entries.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &hdr, data.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let join = |f: fn(&Data) -> u32| {
        CapSet::from_bits(u64::from(f(&data[0])) | (u64::from(f(&data[1])) << 32))
    };
    Ok(ThreadCaps {
        effective: join(|d| d.effective),
        permitted: join(|d| d.permitted),
        inheritable: join(|d| d.inheritable),
    })
}

/// Set the calling thread's sets (`capset`, pid 0: this thread only). The
/// kernel refuses a permitted or inheritable set larger than the thread
/// holds, and an effective set outside the permitted one.
pub fn set_this_thread(c: ThreadCaps) -> io::Result<()> {
    let hdr = Header {
        version: VERSION_3,
        pid: 0,
    };
    let split = |s: CapSet| (s.bits() as u32, (s.bits() >> 32) as u32);
    let (e0, e1) = split(c.effective);
    let (p0, p1) = split(c.permitted);
    let (i0, i1) = split(c.inheritable);
    let data = [
        Data {
            effective: e0,
            permitted: p0,
            inheritable: i0,
        },
        Data {
            effective: e1,
            permitted: p1,
            inheritable: i1,
        },
    ];
    // SAFETY: capset with a version-3 header and its two data entries.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What a thread of the core does, and so what it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The decision thread (R12b): judges the events.
    Decision,
    /// The response dispatcher's workers and their stall watch (R12c): the
    /// actions.
    Actuator,
    /// A chain writer on a thread of its own.
    Writer,
    /// The workers' supervisor (R14a): starts the workers as their account,
    /// signals them, registers their pids in the kernel.
    Supervisor,
    /// The eBPF object's load and attach.
    Loader,
    /// The decision's errands ([`errands`]): a kernel map entry, an `rpm`
    /// query.
    Errands,
}

impl Role {
    pub const ALL: [Role; 6] = [
        Role::Decision,
        Role::Actuator,
        Role::Writer,
        Role::Supervisor,
        Role::Loader,
        Role::Errands,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Role::Decision => "decision",
            Role::Actuator => "actuator",
            Role::Writer => "writer",
            Role::Supervisor => "supervisor",
            Role::Loader => "loader",
            Role::Errands => "errands",
        }
    }

    /// What the role keeps effective (of what the thread holds: a
    /// capability the unit does not grant stays out).
    ///
    /// - decision: `SYS_PTRACE` only — it reads `/proc/<pid>/exe` of the
    ///   process it judges (the rules' trusted actor, the COMBAT guard, the
    ///   lineage), which `ptrace_may_access` refuses for another user's or
    ///   a more privileged process without it. Measured in the lab
    ///   (`deploy/lab/caps/thread-caps.sh`): the one capability the
    ///   decision's checks were granted. Its filter takes away the parts of
    ///   it that write: `ptrace`, `process_vm_writev`, `pidfd_getfd`.
    /// - actuator: plan §3.2's actions — `KILL` (kill, `pidfd_send_signal`,
    ///   `cgroup.kill`), `NET_ADMIN` (nft, iptables), `SETFCAP` (the strip),
    ///   `DAC_OVERRIDE` (quarantine) — and `SYS_PTRACE`: quarantine and the
    ///   strip reach the file through `/proc/1/root` and the target's
    ///   `/proc/<pid>/exe` (§3.2's own entry for it).
    /// - writer: `LINUX_IMMUTABLE` (the state directory's `chattr +i`
    ///   lifted for a new chain file).
    /// - supervisor: `SETUID`, `SETGID` (the worker's account, set in the
    ///   child before `exec`), `KILL` (the worker runs as another user),
    ///   `BPF` (its pid's role in `PROTECTED_PIDS`).
    /// - loader: `BPF`, `PERFMON` (load, attach, pin) and `SYS_ADMIN`
    ///   where the unit has it (the Debian drop-in: tracepoint attach under
    ///   `perf_event_paranoid` 3).
    /// - errands: `BPF` (`DEFENDER_PIDS`); the `rpm` it starts is a program
    ///   of its own (root's sets at its `execve`, as before).
    pub const fn wants(self) -> CapSet {
        use cap::*;
        match self {
            Role::Decision => CapSet::of(&[SYS_PTRACE]),
            Role::Actuator => CapSet::of(&[KILL, NET_ADMIN, SETFCAP, DAC_OVERRIDE, SYS_PTRACE]),
            Role::Writer => CapSet::of(&[LINUX_IMMUTABLE]),
            Role::Supervisor => CapSet::of(&[SETUID, SETGID, KILL, BPF]),
            Role::Loader => CapSet::of(&[BPF, PERFMON, SYS_ADMIN]),
            Role::Errands => CapSet::of(&[BPF]),
        }
    }

    /// The role gives up the rest for good (its permitted set too) and
    /// takes its own seccomp filter: the decision only. The others keep
    /// the bounding set permitted, so that a thread they start (a runtime
    /// thread, a spare worker) can be given its own set.
    pub const fn for_good(self) -> bool {
        matches!(self, Role::Decision)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What [`enter`] did to the calling thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entered {
    pub role: Role,
    pub before: ThreadCaps,
    pub after: ThreadCaps,
    /// The role's capabilities the thread did not hold (the unit does not
    /// grant them, or a test runs unprivileged).
    pub missing: CapSet,
    /// The decision's filter: installed (`Some(Ok)`), refused
    /// (`Some(Err(why))`); `None` for the other roles.
    pub filter: Option<Result<(), String>>,
}

impl Entered {
    /// One line for the journal.
    pub fn line(&self) -> String {
        let mut s = format!(
            "role {}: effective {}, permitted {}",
            self.role, self.after.effective, self.after.permitted
        );
        if !self.missing.is_empty() {
            s.push_str(&format!(" (not held: {})", self.missing));
        }
        match &self.filter {
            Some(Ok(())) => s.push_str(", seccomp filter on"),
            Some(Err(e)) => s.push_str(&format!(", seccomp filter NOT installed: {e}")),
            None => {}
        }
        s
    }

    /// The thread holds no more than its role allows, and its filter is
    /// on when it has one.
    pub fn complete(&self) -> bool {
        let allowed = self.role.wants();
        self.after.effective.minus(allowed).is_empty()
            && (!self.role.for_good() || self.after.permitted.minus(allowed).is_empty())
            && self.after.inheritable.is_empty()
            && !matches!(self.filter, Some(Err(_)))
    }
}

/// Give the calling thread `role`'s capabilities: effective the role's set
/// (of what the thread holds), inheritable none (the ambient set goes with
/// it); for the decision, permitted the same, then `PR_SET_NO_NEW_PRIVS`
/// and its seccomp filter on this thread only. An error only when the
/// thread's sets could not be read or set; a filter the kernel refuses is
/// in [`Entered::filter`].
pub fn enter(role: Role) -> io::Result<Entered> {
    let before = this_thread()?;
    let keep = role.wants().intersection(before.permitted);
    let target = ThreadCaps {
        effective: keep,
        permitted: if role.for_good() {
            keep
        } else {
            before.permitted
        },
        inheritable: CapSet::EMPTY,
    };
    set_this_thread(target)?;
    let filter = role
        .for_good()
        .then(|| filter::install_decision().map_err(|e| e.to_string()));
    Ok(Entered {
        role,
        before,
        after: this_thread()?,
        missing: role.wants().minus(before.permitted),
        filter,
    })
}

/// [`enter`], its outcome said in the journal; a thread left with more than
/// its role (a set that could not be changed, a filter refused) is a
/// degradation, signed (`thread_caps`). For a thread's first line.
pub fn enter_or_report(role: Role) -> Option<Entered> {
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("?");
    match enter(role) {
        Ok(e) => {
            if e.complete() {
                tracing::info!(thread = name, "thread capabilities: {}", e.line());
            } else {
                let detail = format!("thread {name}: {}", e.line());
                tracing::error!("thread capabilities: {detail}");
                crate::boot::degradation::report("thread_caps", &detail);
            }
            Some(e)
        }
        Err(err) => {
            let detail = format!(
                "thread {name}: role {role}: its capabilities could not be set ({err}) — it keeps \
                 the core's"
            );
            tracing::error!("thread capabilities: {detail}");
            crate::boot::degradation::report("thread_caps", &detail);
            None
        }
    }
}

/// A thread of the core that is no role's: effective all it holds
/// (permitted). A runtime thread starts with the sets of the thread that
/// made it start (`spawn_blocking` from a role's thread); this gives it the
/// core's back. A thread whose permitted set was given up (one started by
/// the decision thread, which never starts any) cannot: said, once per
/// thread, in the journal.
pub fn restore_core() {
    let Ok(now) = this_thread() else {
        return;
    };
    if now.effective == now.permitted && now.inheritable.is_empty() {
        return;
    }
    let target = ThreadCaps {
        effective: now.permitted,
        permitted: now.permitted,
        inheritable: CapSet::EMPTY,
    };
    if let Err(e) = set_this_thread(target) {
        tracing::error!(error = %e, effective = %now.effective, "a core thread's capabilities could not be restored");
    }
}

/// The calling thread's effective set lowered to `role`'s (of what it
/// holds) until the guard drops, which sets back the sets the thread had.
/// For a phase of a thread that then does other work — the loader: the
/// start's thread while the eBPF object loads and attaches, a future the
/// runtime's `block_on` drives on that thread alone (the guard is not
/// `Send`: it stays on the thread it changed). A thread started meanwhile
/// that is to keep the core's set calls [`restore_core`] first (a runtime
/// thread does, from the runtime's start hook; the sensors' pumps do).
pub fn lower(role: Role) -> io::Result<Lowered> {
    debug_assert!(!role.for_good(), "a role for good is entered, not lowered");
    let before = this_thread()?;
    set_this_thread(ThreadCaps {
        effective: role.wants().intersection(before.permitted),
        ..before
    })?;
    Ok(Lowered {
        role,
        before,
        _not_send: std::marker::PhantomData,
    })
}

/// See [`lower`].
#[derive(Debug)]
pub struct Lowered {
    role: Role,
    before: ThreadCaps,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Lowered {
    pub fn role(&self) -> Role {
        self.role
    }
}

impl Drop for Lowered {
    fn drop(&mut self) {
        if let Err(e) = set_this_thread(self.before) {
            tracing::error!(error = %e, role = %self.role, "a thread's capabilities could not be set back after its phase");
        }
    }
}
