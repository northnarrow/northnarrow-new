//! The workers' sandbox (Wave 4 restructure, R14a — plan §3.1, §3.5;
//! `docs/architecture/PROCESS_MODEL.md`, `docs/operator/WORKERS.md`).
//!
//! A worker — the agent's binary started by the core as `--worker <kind>
//! --ipc-fd 3`, as the `northnarrow-worker` account — calls [`enter`]
//! before it reads anything, and exits if it fails. What it does, in
//! order:
//!
//! 1. refuses to run as root, with a group 0, or with any supplementary
//!    group (the core's `pre_exec` set them; a worker never finds itself
//!    privileged);
//! 2. forbids privilege gains (`PR_SET_NO_NEW_PRIVS`), makes itself not
//!    dumpable (no core, no ptrace by its own user), closes every
//!    descriptor above its channel and caps what it may create: no process
//!    (`RLIMIT_NPROC` 0), no core, a few descriptors, bounded memory;
//! 3. measures itself — ids, groups, the capability sets (capget, and the
//!    ambient and bounding sets one capability at a time), the flags, the
//!    limits — while it still may ([`SandboxLevel`]);
//! 4. Landlock (the `landlock` crate, best effort): every filesystem right
//!    the running kernel's ABI handles, with no rule (no path can be
//!    opened, created, removed or executed); TCP bind and connect with no
//!    rule (ABI ≥ 4); signals and abstract UNIX sockets scoped to its own
//!    domain (ABI ≥ 6). What the kernel enforced is **measured** after the
//!    ruleset binds the worker — a directory opened, a TCP connect to
//!    loopback, a connect to an abstract socket made before the ruleset
//!    (review of #480, F7) — and declared: ABI 1 on 5.15, 2 on 6.1, 4 on
//!    6.8, 6 on 6.12, never assumed (plan §5 risk 8);
//! 5. last, the seccomp allowlist ([`seccomp`], the `seccompiler` crate):
//!    any other system call kills the process.
//!
//! The core then checks the declared level (`nn_proto::ipc::check_hello`)
//! and signs it in the capability manifest. The core itself takes no
//! Landlock ruleset: it acts on any path, through `/proc/1/root` (plan
//! §3.1).

use std::io;
use std::os::fd::RawFd;

use landlock::{
    Access, AccessFs, AccessNet, CompatLevel, Compatible, LandlockStatus, RulesetAttr,
    RulesetStatus, Scope, ABI,
};
use nn_proto::ipc::{LandlockEnforced, SandboxLevel};

pub mod seccomp;

/// The descriptors a worker may hold at once: stdio, its channel and a
/// margin.
pub const MAX_FDS: u64 = 8;

/// A sandbox to enter.
#[derive(Debug, Clone)]
pub struct Profile {
    /// For the messages.
    pub name: &'static str,
    /// The worker's channel: every descriptor above it is closed.
    pub ipc_fd: RawFd,
    /// The address-space cap (`RLIMIT_AS`), bytes.
    pub memory: u64,
    /// The system calls the worker keeps.
    pub syscalls: seccomp::Allowlist,
}

impl Profile {
    /// The `parse` worker (plan §3.1): no file, no network, no process,
    /// memory for its parsers; its channel is all it talks to.
    pub fn parse(ipc_fd: RawFd) -> Self {
        Self {
            name: "parse",
            ipc_fd,
            memory: 512 << 20,
            syscalls: seccomp::Allowlist::parse_worker(ipc_fd, std::process::id()),
        }
    }
}

/// Why a worker did not enter its sandbox: it exits, and the core signs
/// the degradation.
#[derive(Debug)]
pub enum SandboxError {
    /// Run as root, a group 0, or with supplementary groups.
    Privileged(String),
    /// A step failed (`prctl`, `setrlimit`, Landlock, seccomp).
    Step(&'static str, String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Privileged(why) => write!(f, "refusing to run privileged: {why}"),
            SandboxError::Step(step, why) => write!(f, "{step}: {why}"),
        }
    }
}

impl std::error::Error for SandboxError {}

fn step(name: &'static str) -> impl Fn(io::Error) -> SandboxError {
    move |e| SandboxError::Step(name, e.to_string())
}

/// Enter `profile` (see the module's documentation): the level entered,
/// or why not. On an error the caller exits at once.
pub fn enter(profile: &Profile) -> Result<SandboxLevel, SandboxError> {
    refuse_privileged()?;
    harden(profile)?;
    let mut level = measure()?;
    landlock_restrict(&mut level)?;
    seccomp::install(&profile.syscalls).map_err(step("seccomp"))?;
    level.seccomp = true;
    Ok(level)
}

/// `debug-trigger` builds only — the compromised-worker harness
/// (`crate::worker::hostile`): every step of [`enter`] but the seccomp
/// filter, so that what the layers beneath it refuse can be measured. No
/// production path calls it: a worker always enters [`enter`].
#[cfg(feature = "debug-trigger")]
pub fn enter_without_seccomp(profile: &Profile) -> Result<SandboxLevel, SandboxError> {
    refuse_privileged()?;
    harden(profile)?;
    let mut level = measure()?;
    landlock_restrict(&mut level)?;
    Ok(level)
}

/// Step 1.
fn refuse_privileged() -> Result<(), SandboxError> {
    let (uid, gid) = ids();
    if uid.contains(&0) {
        return Err(SandboxError::Privileged(format!("uid {uid:?}")));
    }
    if gid.contains(&0) {
        return Err(SandboxError::Privileged(format!("gid {gid:?}")));
    }
    let groups = supplementary_groups();
    if groups != 0 {
        return Err(SandboxError::Privileged(format!(
            "{groups} supplementary groups"
        )));
    }
    Ok(())
}

/// Step 2.
fn harden(profile: &Profile) -> Result<(), SandboxError> {
    // SAFETY: prctl with integer arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(step("PR_SET_NO_NEW_PRIVS")(io::Error::last_os_error()));
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(step("PR_SET_DUMPABLE")(io::Error::last_os_error()));
        }
    }
    close_from(profile.ipc_fd + 1);
    for (res, v, name) in [
        (libc::RLIMIT_CORE, 0, "RLIMIT_CORE"),
        (libc::RLIMIT_NPROC, 0, "RLIMIT_NPROC"),
        (libc::RLIMIT_NOFILE, MAX_FDS, "RLIMIT_NOFILE"),
        (libc::RLIMIT_AS, profile.memory, "RLIMIT_AS"),
    ] {
        setrlimit(res, v).map_err(step(name))?;
    }
    Ok(())
}

fn setrlimit(res: libc::__rlimit_resource_t, v: u64) -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: v as libc::rlim_t,
        rlim_max: v as libc::rlim_t,
    };
    // SAFETY: setrlimit with a valid rlimit struct.
    if unsafe { libc::setrlimit(res, &lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn getrlimit(res: libc::__rlimit_resource_t) -> u64 {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit into a valid rlimit struct.
    if unsafe { libc::getrlimit(res, &mut lim) } != 0 {
        return u64::MAX;
    }
    lim.rlim_cur
}

/// Close every descriptor from `first` up (`close_range(2)`, else one by
/// one).
pub fn close_from(first: RawFd) {
    // SAFETY: close_range on a range of our own descriptors.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, first as u32, u32::MAX, 0u32) };
    if rc != 0 {
        for fd in first..1024 {
            // SAFETY: closing a descriptor we may or may not hold.
            unsafe { libc::close(fd) };
        }
    }
}

/// Real, effective and saved uids and gids.
pub fn ids() -> ([u32; 3], [u32; 3]) {
    let (mut r, mut e, mut s) = (0, 0, 0);
    let (mut rg, mut eg, mut sg) = (0, 0, 0);
    // SAFETY: getresuid/getresgid into local integers.
    unsafe {
        libc::getresuid(&mut r, &mut e, &mut s);
        libc::getresgid(&mut rg, &mut eg, &mut sg);
    }
    ([r, e, s], [rg, eg, sg])
}

fn supplementary_groups() -> u32 {
    // SAFETY: getgroups(0, NULL) returns the count.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The capability sets of the calling thread: effective, permitted,
/// inheritable (capget, version 3), ambient and bounding (one prctl per
/// capability, up to the first the kernel does not know).
pub fn capability_sets() -> io::Result<CapSets> {
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
    const VERSION_3: u32 = 0x2008_0522;
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
    let join = |f: fn(&Data) -> u32| u64::from(f(&data[0])) | (u64::from(f(&data[1])) << 32);
    let mut sets = CapSets {
        eff: join(|d| d.effective),
        prm: join(|d| d.permitted),
        inh: join(|d| d.inheritable),
        amb: 0,
        bnd: 0,
    };
    for cap in 0..64u64 {
        // SAFETY: prctl with integer arguments.
        let b = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if b < 0 {
            break;
        }
        if b == 1 {
            sets.bnd |= 1 << cap;
        }
        // SAFETY: prctl with integer arguments.
        let a = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong,
                cap,
                0,
                0,
            )
        };
        if a == 1 {
            sets.amb |= 1 << cap;
        }
    }
    Ok(sets)
}

/// A thread's capability sets, one bit per capability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapSets {
    pub eff: u64,
    pub prm: u64,
    pub inh: u64,
    pub amb: u64,
    pub bnd: u64,
}

/// Step 3: what the worker is, before Landlock closes `/proc` and seccomp
/// the system calls that tell.
fn measure() -> Result<SandboxLevel, SandboxError> {
    let (uid, gid) = ids();
    let caps = capability_sets().map_err(step("capget"))?;
    // SAFETY: prctl with integer arguments.
    let (nnp, dumpable) = unsafe {
        (
            libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
            libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0),
        )
    };
    Ok(SandboxLevel {
        uid: uid[0],
        gid: gid[0],
        groups: supplementary_groups(),
        no_new_privs: nnp == 1,
        dumpable: dumpable != 0,
        cap_eff: caps.eff,
        cap_prm: caps.prm,
        cap_inh: caps.inh,
        cap_amb: caps.amb,
        cap_bnd: caps.bnd,
        nofile: getrlimit(libc::RLIMIT_NOFILE),
        nproc: getrlimit(libc::RLIMIT_NPROC),
        core: getrlimit(libc::RLIMIT_CORE),
        ..SandboxLevel::default()
    })
}

/// The newest ABI this build knows: the rights asked for. The kernel's own
/// decides what is enforced (best effort), and the level says which.
const LANDLOCK_ASK: ABI = ABI::V9;

/// What Landlock refused once it bound the calling thread, measured (review
/// of #480, F7: not derived from the ABI's number).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Measured {
    /// A directory (`/`, readable by every account) could not be opened.
    pub fs: bool,
    /// A TCP connect to loopback was refused with `EACCES` (Landlock's own
    /// errno; a closed port says `ECONNREFUSED`).
    pub net: bool,
    /// A connect to an abstract socket listening outside the domain (made
    /// before the ruleset) was refused with `EPERM`.
    pub scope: bool,
}

/// The peer of the scope's probe: an abstract listener this thread makes
/// before it restricts itself, so outside its Landlock domain.
struct ScopePeer {
    fd: RawFd,
    addr: libc::sockaddr_un,
    len: libc::socklen_t,
}

impl Drop for ScopePeer {
    fn drop(&mut self) {
        // SAFETY: our own descriptor.
        unsafe { libc::close(self.fd) };
    }
}

fn abstract_addr(name: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let n = name.len().min(sa.sun_path.len() - 1);
    for (dst, src) in sa.sun_path.iter_mut().skip(1).zip(name.iter().take(n)) {
        *dst = *src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + 1 + n;
    (sa, len as libc::socklen_t)
}

fn scope_peer() -> Option<ScopePeer> {
    // a name of its own: this process and the time
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = format!("nn-landlock-probe-{}-{t}", std::process::id());
    let (addr, len) = abstract_addr(name.as_bytes());
    // SAFETY: socket, bind and listen on our own descriptor and address.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return None;
        }
        let peer = ScopePeer { fd, addr, len };
        if libc::bind(fd, (&peer.addr as *const libc::sockaddr_un).cast(), len) != 0
            || libc::listen(fd, 1) != 0
        {
            return None;
        }
        Some(peer)
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Measure what the domain the calling thread is in refuses.
fn measure_landlock(peer: Option<&ScopePeer>) -> Measured {
    // SAFETY (each block): plain system calls on descriptors of our own,
    // closed at once; static or local addresses.
    let fs = unsafe {
        let fd = libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        if fd >= 0 {
            libc::close(fd);
            false
        } else {
            errno() == libc::EACCES
        }
    };
    let net = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            false
        } else {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 1u16.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
                },
                sin_zero: [0; 8],
            };
            let rc = libc::connect(
                fd,
                (&sa as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            let refused = rc != 0 && errno() == libc::EACCES;
            libc::close(fd);
            refused
        }
    };
    let scope = match peer {
        None => false,
        Some(p) => unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                false
            } else {
                let rc = libc::connect(fd, (&p.addr as *const libc::sockaddr_un).cast(), p.len);
                let refused = rc != 0 && errno() == libc::EPERM;
                libc::close(fd);
                refused
            }
        },
    };
    Measured { fs, net, scope }
}

/// Step 4: Landlock, best effort; what it refuses measured, then declared.
fn landlock_restrict(level: &mut SandboxLevel) -> Result<(), SandboxError> {
    let fail = |e: landlock::RulesetError| SandboxError::Step("landlock", e.to_string());
    let peer = scope_peer();
    let status = landlock::Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(LANDLOCK_ASK))
        .map_err(fail)?
        .handle_access(AccessNet::from_all(LANDLOCK_ASK))
        .map_err(fail)?
        .scope(Scope::from_all(LANDLOCK_ASK))
        .map_err(fail)?
        .create()
        .map_err(fail)?
        .restrict_self()
        .map_err(fail)?;
    let abi = match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => effective_abi as u8,
        _ => 0,
    };
    let enforced = match status.ruleset {
        RulesetStatus::FullyEnforced => LandlockEnforced::Full,
        RulesetStatus::PartiallyEnforced => LandlockEnforced::Partial,
        RulesetStatus::NotEnforced => LandlockEnforced::None,
    };
    let measured = measure_landlock(peer.as_ref());
    drop(peer);
    declare(level, abi, enforced, measured);
    Ok(())
}

/// The level declared: the kernel's `abi`, the crate's `enforced` state,
/// and what was `measured` refused. A refusal measured without Landlock
/// (no ABI, or the ruleset not enforced) is not Landlock's and is not
/// declared as such; what the core requires of each ABI is its check
/// (`nn_proto::ipc::check_hello`).
pub fn declare(level: &mut SandboxLevel, abi: u8, enforced: LandlockEnforced, measured: Measured) {
    level.landlock_abi = abi;
    level.landlock = if abi == 0 {
        LandlockEnforced::None
    } else {
        enforced
    };
    let on = level.landlock != LandlockEnforced::None;
    level.fs_denied = on && measured.fs;
    level.net_denied = on && measured.net;
    level.scoped = on && measured.scope;
}

/// The Landlock ABI of the running kernel, as `landlock_create_ruleset`'s
/// version query gives it (0: not built in, or not enabled in `lsm=`).
/// The core reads it for the manifest without entering a sandbox.
pub fn kernel_landlock_abi() -> u8 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: landlock_create_ruleset(NULL, 0, VERSION) only returns the
    // ABI version.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    u8::try_from(v).unwrap_or(0)
}

#[cfg(test)]
mod tests;
