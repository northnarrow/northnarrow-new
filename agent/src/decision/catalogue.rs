//! R08b shim (Wave 4 restructure, lab PR 251; plan §4.1 rule 2, removed in
//! R17): the rule catalogue's table — what each rule is, as data, which the
//! per-rule policy resolves rule names against — is nn-core's
//! (`nn_core::decision::catalogue`). Its renderer, which composes the rules
//! the agent decides outside the engine (the exec quarantine, the exec
//! policy) and writes `docs/detection/`, and the tests that hold the table
//! to the rules and the docs, stay here.

pub use nn_core::decision::catalogue::*;

pub mod render;
#[cfg(test)]
mod tests;
