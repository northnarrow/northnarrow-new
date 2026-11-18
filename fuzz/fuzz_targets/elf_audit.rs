#![no_main]
//! The exec pump reads a program's dynamic section to tell whether glibc's
//! loader would load a library for auditing (fix round 3 of #578, R2-2).
//! Whatever bytes the file holds the reader never panics, never asks for
//! more than one table of program headers or one chunk of the dynamic
//! section in a read, and says "names an auditor" only for an ELF file.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::fuzz_api::{elf_audit_read, ELF_AUDIT_READ_BOUND};

fuzz_target!(|data: &[u8]| {
    let (found, most) = elf_audit_read(data);
    assert!(most <= ELF_AUDIT_READ_BOUND, "a read of {most} bytes");
    if found == Some(true) {
        assert!(data.starts_with(b"\x7fELF"), "an auditor named by a non-ELF file");
    }
});
