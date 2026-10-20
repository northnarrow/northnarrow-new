//! Lab PR 222 — microbenchmark of open-for-write latency, with and without
//! the copy-on-first-write guard.
//!
//! ```text
//! cow_bench --dir DIR [--files 1000] [--size 4096] [--rounds 3]
//!           [--simulate-copy JOURNAL_DIR]
//! ```
//!
//! Creates `--files` files of `--size` bytes in `--dir` (not timed), then,
//! `--rounds` times, opens each one `O_WRONLY`, rewrites it and closes it,
//! timing the `open(2)` alone and the whole open-write-close. With the
//! guard running on a scope that holds `--dir`, round 1 of a process an
//! untrusted writer is the copy path (the open waits for the copy), the
//! later rounds the already-copied fast path; run it twice (guard off,
//! guard on) for the comparison. As root on the guest it measures the
//! real thing.
//!
//! `--simulate-copy JOURNAL_DIR` needs no root and no guard: before each
//! open it does in-process the work the guard does for a copy (the `/proc`
//! reads of the trust and flags checks, the reflink or bounded copy into
//! the journal directory, the SHA-256 of the object) — the guard's own
//! cost without the fanotify round trip.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn pct(sorted: &[Duration], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i].as_secs_f64() * 1e6
}

fn summary(label: &str, mut v: Vec<Duration>) -> String {
    v.sort();
    let mean = v.iter().map(|d| d.as_secs_f64()).sum::<f64>() / v.len().max(1) as f64 * 1e6;
    format!(
        "{label}: n={} mean={mean:.1}us p50={:.1}us p90={:.1}us p99={:.1}us max={:.1}us",
        v.len(),
        pct(&v, 0.5),
        pct(&v, 0.9),
        pct(&v, 0.99),
        pct(&v, 1.0)
    )
}

/// What the guard does for one copy, in this process: the critical path
/// (what the open waits for). The SHA-256 the index worker computes after
/// the answer is [`hash_object`].
fn simulate_copy(file: &std::fs::File, journal: &std::fs::File, n: u64) -> std::io::Result<()> {
    use northnarrow_agent::cow::{copy, fanotify, trust};
    // the fast checks: own thread, fstat, flags, tgid, start, exe
    let _ = fanotify::is_own_thread(1);
    let st = fanotify::fstat(file.as_raw_fd())?;
    let _ = std::fs::read_to_string("/proc/self/syscall");
    let me = std::process::id() as i32;
    let _ = fanotify::tgid_of(me);
    let _ = trust::proc_start_ticks(Path::new("/proc"), me as u32);
    let _ = std::fs::read_link("/proc/self/exe");
    let _ = fanotify::fd_path(file.as_raw_fd());
    let _ = fanotify::btime(file.as_raw_fd(), None);
    let dir = journal;
    let name = std::ffi::CString::new(format!("{n:016x}")).unwrap_or_default();
    match copy::snapshot(
        file.as_raw_fd(),
        &st,
        dir.as_raw_fd(),
        &name,
        16 << 20,
        Instant::now() + Duration::from_millis(50),
    ) {
        copy::Snapshot::Reflinked { .. } | copy::Snapshot::Copied { .. } => {}
        other => return Err(std::io::Error::other(format!("{other:?}"))),
    }
    Ok(())
}

/// The index worker's SHA-256 of the object (after the open was answered).
fn hash_object(journal: &Path, n: u64) -> std::io::Result<()> {
    let obj = std::fs::File::open(journal.join(format!("{n:016x}")))?;
    northnarrow_agent::cow::copy::sha256_fd(obj.as_raw_fd())?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(dir) = arg(&args, "--dir").map(PathBuf::from) else {
        eprintln!("usage: cow_bench --dir DIR [--files N] [--size BYTES] [--rounds R] [--simulate-copy JOURNAL_DIR]");
        std::process::exit(2);
    };
    let files: usize = arg(&args, "--files")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let size: usize = arg(&args, "--size")
        .and_then(|v| v.parse().ok())
        .unwrap_or(4096);
    let rounds: usize = arg(&args, "--rounds")
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let journal = arg(&args, "--simulate-copy").map(PathBuf::from);
    std::fs::create_dir_all(&dir).expect("create --dir");
    if let Some(j) = &journal {
        std::fs::create_dir_all(j).expect("create the journal directory");
    }
    let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let paths: Vec<PathBuf> = (0..files)
        .map(|i| dir.join(format!("bench-{i:06}.dat")))
        .collect();
    for p in &paths {
        std::fs::write(p, &data).expect("create a file");
    }
    let mut copied = 0u64;
    let journal_dir = journal
        .as_ref()
        .map(|j| std::fs::File::open(j).expect("open the journal directory"));
    let mut hash_t = Vec::new();
    for round in 1..=rounds {
        let mut open_t = Vec::with_capacity(files);
        let mut all_t = Vec::with_capacity(files);
        for p in &paths {
            let t0 = Instant::now();
            if let (Some(jd), 1) = (&journal_dir, round) {
                // the event fd the kernel opens for the guard
                let f = std::fs::File::open(p).expect("open for the simulated copy");
                simulate_copy(&f, jd, copied).expect("simulated copy");
                copied += 1;
            }
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(p)
                .expect("open O_WRONLY");
            let t1 = Instant::now();
            use std::os::unix::fs::FileExt;
            f.write_all_at(&data, 0).expect("rewrite");
            drop(f);
            let t2 = Instant::now();
            open_t.push(t1 - t0);
            all_t.push(t2 - t0);
            if let (Some(j), 1) = (&journal, round) {
                let h0 = Instant::now();
                hash_object(j, copied - 1).expect("hash");
                hash_t.push(h0.elapsed());
            }
        }
        println!("round {round} {}", summary("open", open_t));
        println!("round {round} {}", summary("open+write+close", all_t));
    }
    if !hash_t.is_empty() {
        println!(
            "{}",
            summary(
                "deferred sha256 of the copy (index worker, not on the open)",
                hash_t
            )
        );
    }
    for p in &paths {
        let _ = std::fs::remove_file(p);
    }
    if let Some(j) = &journal {
        for n in 0..copied {
            let _ = std::fs::remove_file(j.join(format!("{n:016x}")));
        }
    }
}
