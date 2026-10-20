#![no_main]
//! Operator canary templates (`/etc/northnarrow/canary-templates/<family>.tmpl`)
//! are rendered when a credential canary is deployed. Beyond "never
//! panics" (render, or refuse: unresolved placeholder, unreadable file):
//! - a rendered canary keeps no `{{` (DEC-017: an unclosed placeholder
//!   used to pass into the decoy);
//! - a JSON family's canary is a JSON document;
//! - rendering is a function of the seed: the same body renders the same.
//!
//! Input: one byte selecting the family, then the template body. The body
//! is written into this process's private scratch directory (WDG-R09).
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::canary::templates::{render, CredFamily};

mod scratch;

const FAMILIES: [&str; 5] = ["aws", "azure", "gcp", "docker", "generic"];
const SEED: &str = "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3";

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let Ok(family) = CredFamily::from_wire(FAMILIES[*sel as usize % FAMILIES.len()]) else {
        return;
    };
    let dir = scratch::dir("nn-fuzz-canary-");
    if scratch::replace(dir, &format!("{}.tmpl", family.as_wire()), body).is_err() {
        return;
    }
    if let Ok(out) = render(family, SEED, Some(dir)) {
        assert!(!out.contains("{{"), "a placeholder survived rendering");
        if matches!(
            family,
            CredFamily::Azure | CredFamily::Gcp | CredFamily::Docker
        ) {
            assert!(
                serde_json::from_str::<serde_json::Value>(&out).is_ok(),
                "a JSON family rendered a non-JSON canary"
            );
        }
        assert_eq!(render(family, SEED, Some(dir)).ok(), Some(out));
    }
});
