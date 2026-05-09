//! Hardware diagnostic for ADE performance tuning (Sub-tappa 6.8).
//!
//! Prints a self-contained report of the host's CPU and memory
//! profile, then runs two micro-benchmarks (single-thread matrix
//! multiply for compute and sequential memory streaming for
//! bandwidth) and produces a verdict pinpointing the likely
//! bottleneck for CPU-only LLM inference.
//!
//! Run with:
//!
//! ```text
//! cargo run -p northnarrow-agent --release --example diag_hw
//! ```
//!
//! The output is meant to be pasted into
//! `docs/PERFORMANCE_HARDWARE.md` so each deployment captures its
//! own baseline before applying the Sub-tappa 6.8 tuning knobs.

use std::time::Instant;

fn main() {
    println!("=== ADE Hardware Diagnostic (Sub-tappa 6.8) ===\n");

    let cpu = read_cpuinfo();
    print_cpu_block(&cpu);

    let mem = read_meminfo();
    print_mem_block(&mem);

    let gflops = bench_matmul_f32(1024);
    println!("Compute benchmark (single-thread):");
    println!("  matmul f32 1024x1024  ~{gflops:.2} GFLOPS\n");

    let gbps = bench_memory_bandwidth(1024 * 1024 * 1024);
    println!("Memory benchmark:");
    println!("  sequential read 1 GB  ~{gbps:.2} GB/s\n");

    print_verdict(&cpu, &mem, gflops, gbps);
}

#[derive(Default, Debug)]
struct CpuInfo {
    model_name: String,
    logical_cores: usize,
    physical_cores: usize,
    flags: Vec<String>,
}

impl CpuInfo {
    fn has(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }
    fn relevant_flags(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for f in [
            "avx", "avx2", "avx512f", "fma", "f16c", "ssse3", "sse4_1", "sse4_2", "bmi2",
        ] {
            if self.has(f) {
                out.push(f);
            }
        }
        out
    }
}

fn read_cpuinfo() -> CpuInfo {
    let mut info = CpuInfo {
        logical_cores: num_cpus_logical(),
        physical_cores: num_cpus_physical(),
        ..Default::default()
    };
    let raw = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(s) => s,
        Err(_) => return info,
    };
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if info.model_name.is_empty() && k == "model name" {
                info.model_name = v.to_string();
            }
            if info.flags.is_empty() && k == "flags" {
                info.flags = v.split_whitespace().map(|s| s.to_string()).collect();
            }
            if !info.model_name.is_empty() && !info.flags.is_empty() {
                break;
            }
        }
    }
    info
}

fn print_cpu_block(cpu: &CpuInfo) {
    println!("CPU:");
    println!(
        "  model         = {}",
        if cpu.model_name.is_empty() {
            "(unknown)"
        } else {
            cpu.model_name.as_str()
        }
    );
    println!(
        "  logical_cores = {} (physical={})",
        cpu.logical_cores, cpu.physical_cores
    );
    let rel = cpu.relevant_flags();
    println!(
        "  isa_flags     = {}",
        if rel.is_empty() {
            "(none detected)".to_string()
        } else {
            rel.join(", ")
        }
    );
    println!();
}

#[derive(Default, Debug)]
struct MemInfo {
    total_kb: u64,
    available_kb: u64,
    free_kb: u64,
}

fn read_meminfo() -> MemInfo {
    let mut info = MemInfo::default();
    let raw = match std::fs::read_to_string("/proc/meminfo") {
        Ok(s) => s,
        Err(_) => return info,
    };
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            let n: u64 = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            match k {
                "MemTotal" => info.total_kb = n,
                "MemAvailable" => info.available_kb = n,
                "MemFree" => info.free_kb = n,
                _ => {}
            }
        }
    }
    info
}

fn print_mem_block(mem: &MemInfo) {
    let to_gib = |kb: u64| (kb as f64) / 1024.0 / 1024.0;
    println!("Memory:");
    println!("  total         = {:>6.2} GiB", to_gib(mem.total_kb));
    println!("  available     = {:>6.2} GiB", to_gib(mem.available_kb));
    println!("  free          = {:>6.2} GiB", to_gib(mem.free_kb));
    println!();
}

/// Single-thread matmul f32 in plain Rust. Compiler vectorises the
/// inner loop on AVX2 hosts so this benches the realistic compute
/// throughput a CPU LLM kernel can hope to extract per core.
fn bench_matmul_f32(n: usize) -> f64 {
    let a: Vec<f32> = (0..n * n).map(|i| (i as f32 * 0.001).sin()).collect();
    let b: Vec<f32> = (0..n * n).map(|i| (i as f32 * 0.0007).cos()).collect();
    let mut c = vec![0f32; n * n];

    let start = Instant::now();
    for i in 0..n {
        for k in 0..n {
            let aik = a[i * n + k];
            let row_b = &b[k * n..k * n + n];
            let row_c = &mut c[i * n..i * n + n];
            for j in 0..n {
                row_c[j] += aik * row_b[j];
            }
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let _sink = c.iter().sum::<f32>();

    // 2 * n^3 floating-point operations (mul + add per element).
    let ops = 2.0 * (n as f64) * (n as f64) * (n as f64);
    (ops / elapsed) / 1e9
}

/// Sequential read bandwidth: sum a `bytes`-byte buffer chunked
/// into u64 words. Run twice — first call warms the page cache, the
/// second is the timed pass.
fn bench_memory_bandwidth(bytes: usize) -> f64 {
    let words = bytes / 8;
    let buf: Vec<u64> = (0..words as u64).collect();

    // Warm-up (touch every page).
    let mut warm: u64 = 0;
    for &x in &buf {
        warm = warm.wrapping_add(x);
    }
    std::hint::black_box(warm);

    let start = Instant::now();
    let mut acc: u64 = 0;
    for &x in &buf {
        acc = acc.wrapping_add(x);
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(acc);

    (bytes as f64 / 1e9) / elapsed
}

fn print_verdict(cpu: &CpuInfo, mem: &MemInfo, gflops: f64, gbps: f64) {
    println!("Verdict:");

    // Foundation-Sec 8B Q4_K_M is ~5 GiB on disk; mlock-friendly
    // budget needs at least 8 GiB available.
    let mem_gib = (mem.available_kb as f64) / 1024.0 / 1024.0;
    if mem_gib < 7.5 {
        println!(
            "  WARN: only {:.1} GiB available — Foundation-Sec 8B Q4 needs ~5 GiB resident",
            mem_gib
        );
    }

    if !cpu.has("avx2") {
        println!("  WARN: AVX2 not advertised — candle CPU kernels will be ~3-5x slower");
    } else if cpu.has("avx512f") {
        println!("  AVX-512 detected — candle will use the wider SIMD lanes when compiled with target-cpu=native");
    } else {
        println!("  AVX2 detected — candle will use 256-bit SIMD");
    }

    // LLM CPU inference is overwhelmingly memory-bound on quantised
    // models because every decode step streams the whole weight set.
    // A rough rule of thumb: if compute-per-byte > ~0.5 the host is
    // compute-bound, otherwise memory-bound. With 5 GiB of weights
    // and a target of ~5 tok/s the host needs ~25 GB/s of effective
    // bandwidth — most consumer/cloud CPUs don't get there.
    let compute_per_byte = gflops / gbps.max(0.01);
    if compute_per_byte < 0.5 {
        println!(
            "  bottleneck   = MEMORY-BOUND (compute_per_byte={:.2} GFLOPS/GB/s)",
            compute_per_byte
        );
    } else {
        println!(
            "  bottleneck   = COMPUTE-BOUND (compute_per_byte={:.2} GFLOPS/GB/s)",
            compute_per_byte
        );
    }

    let cores = cpu.physical_cores.max(1);
    let suggested_threads = (cores - 1).max(1);
    println!(
        "  suggested ade-threads = {} (physical_cores - 1)",
        suggested_threads
    );
    println!();
}

/// `num_cpus::get` reads `/sys/devices/system/cpu/online`; we keep
/// the fallback simple to avoid pulling the crate just for the demo.
fn num_cpus_logical() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Best-effort physical-core count. Reads `core id` lines from
/// `/proc/cpuinfo` and counts the unique pairs (physical_id, core_id).
fn num_cpus_physical() -> usize {
    let raw = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(s) => s,
        Err(_) => return num_cpus_logical(),
    };
    let mut current_phys: Option<String> = None;
    let mut current_core: Option<String> = None;
    let mut seen = std::collections::HashSet::new();
    for line in raw.lines() {
        if line.is_empty() {
            if let (Some(p), Some(c)) = (current_phys.take(), current_core.take()) {
                seen.insert((p, c));
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim().to_string();
            match k {
                "physical id" => current_phys = Some(v),
                "core id" => current_core = Some(v),
                _ => {}
            }
        }
    }
    if let (Some(p), Some(c)) = (current_phys, current_core) {
        seen.insert((p, c));
    }
    if seen.is_empty() {
        num_cpus_logical()
    } else {
        seen.len()
    }
}
