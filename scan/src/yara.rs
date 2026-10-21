//! Reserved for the YARA engine (lab PR 223, `docs/design/EXEC_QUARANTINE.md`
//! §6). Neither engine fits this release: libyara is C (the charter keeps C
//! out of production) and yara-x needs rustc 1.95 (the workspace supports
//! 1.89) and compiles rules with wasmtime/cranelift into executable memory,
//! which the scanner's seccomp filter refuses by design. The rule packs are
//! already a signed-overlay design; the engine is the follow-up.
compile_error!(
    "the `yara` feature is reserved: no YARA engine is acceptable in this release \
     (docs/design/EXEC_QUARANTINE.md §6)"
);
