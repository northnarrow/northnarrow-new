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

    #[error("backend join error: {0}")]
    BackendJoin(String),

    #[error("malformed model output: {0}")]
    MalformedOutput(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
