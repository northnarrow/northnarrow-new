#![no_main]
//! Operator canary templates (`/etc/northnarrow/canary-templates/<family>.tmpl`)
//! are rendered when a credential canary is deployed: any body must render
//! or be refused (unresolved placeholder, unreadable file), never panic.
//! Input: one byte selecting the family, then the template body.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::canary::templates::{render, CredFamily};

const FAMILIES: [&str; 5] = ["aws", "azure", "gcp", "docker", "generic"];

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let Ok(family) = CredFamily::from_wire(FAMILIES[*sel as usize % FAMILIES.len()]) else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("nn-fuzz-canary-{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join(format!("{}.tmpl", family.as_wire()));
    if std::fs::write(&path, body).is_ok() {
        if let Ok(out) = render(family, "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3", Some(&dir)) {
            // a rendered canary never keeps a placeholder on disk
            assert!(
                !out.contains("{{") || !out[out.find("{{").unwrap()..].contains("}}"),
                "unresolved placeholder survived rendering"
            );
        }
    }
});
