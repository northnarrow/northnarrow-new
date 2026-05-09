//! Integration tests for the RAG module.
//!
//! Filled out incrementally as the store, retrieval and seed
//! modules land. The always-on subset never touches the file system
//! and never requires a model file; the heavier tests live in the
//! per-module `#[cfg(test)]` blocks.
