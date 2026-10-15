//! Error type used across the ADE module.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdeError {
    #[error("model file not found: {path}")]
    ModelMissing { path: PathBuf },

    #[error("system prompt missing or unreadable ({path}): {source}")]
    SystemPromptLoad {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("system prompt is empty")]
    SystemPromptEmpty,

    #[error("inference timed out after {seconds}s")]
    Timeout { seconds: u64 },

    #[error("inference backend error: {0}")]
    Backend(String),

    /// External audit LLMR-004: a model artefact someone other than root
    /// could have written. The ADE stays off — never the mock backend.
    #[error("{0}")]
    ModelUntrusted(String),

    /// External audit LLMR-008: the prompt does not fit the model's window.
    /// The backend refuses it rather than cut it: a cut from the front
    /// removed the system prompt, the model's instructions.
    #[error("prompt exceeds the model window ({tokens} tokens > {window})")]
    PromptExceedsWindow { tokens: usize, window: usize },

    #[error("backend join error: {0}")]
    BackendJoin(String),

    #[error("malformed model output: {0}")]
    MalformedOutput(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
