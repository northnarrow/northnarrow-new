#![no_main]
//! The install manifest is parsed at every boot and decides whether the
//! agent starts: any content must yield a verdict, never a panic.
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!("nn-fuzz-manifest-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("install-manifest.json");
    if std::fs::write(&p, data).is_ok() {
        let _ = northnarrow_agent::install_manifest::check(&p, Path::new("/proc/self/exe"), "deadbeef");
    }
});
