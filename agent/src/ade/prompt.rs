//! Prompt assembly for ADE.
//!
//! The prompt has two parts:
//!
//! - the [`SystemPrompt`] — loaded once at startup, holds the schema,
//!   the 5-step procedure, and few-shot examples.
//! - the per-event "user" message — host context, correlated events,
//!   and the focal event itself — built by
//!   [`super::structured_prompt::build_structured_prompt_with_rag`] from
//!   the sanitized event. External audit LLMP-012: the Tappa 6 builder
//!   that printed the raw event and host context here
//!   (`build_event_prompt`) had no caller but its tests and is removed.
//!
//! Wrapping the two parts into a chat template is the backend's
//! responsibility (Llama 3.1 wants `<|begin_of_text|>` /
//! `<|start_header_id|>` markers; the mock backend doesn't care).
//! See [`PromptParts::into_llama3_chat`] and
//! [`PromptParts::into_plain_text`].
//!
//! When the prompt grows past the backend's window
//! ([`super::InferenceBackend::prompt_window`]) the engine drops the
//! oldest correlated events first, then the RAG block; it never cuts the
//! system prompt or the focal event (external audit LLMR-008: the backend
//! used to cut the prompt's head, which is the system prompt).

use std::fs;
use std::path::Path;

use super::error::AdeError;

/// Loaded system prompt + lightweight metadata.
#[derive(Debug, Clone)]
pub struct SystemPrompt {
    pub raw: String,
}

/// The v1 system prompt, built into the agent (found in the lab with
/// external audit LLMR-004: the default was a path relative to the working
/// directory, `dataset/system_prompt_v1.md`, which nothing installs — a
/// service started from `/` never found it).
const EMBEDDED_V1: &str = include_str!("../../../dataset/system_prompt_v1.md");

impl SystemPrompt {
    /// The prompt at `path`. The default path
    /// ([`super::config::AdeConfig::DEFAULT_SYSTEM_PROMPT_PATH`]) is the
    /// prompt built into the agent; any other file is the model's
    /// instructions too, so it is read only when root owns it and every
    /// directory above it, closed to others
    /// ([`super::model_trust::open_trusted`], external audit LLMR-004).
    pub fn load(path: &Path) -> Result<Self, AdeError> {
        if path == Path::new(super::config::AdeConfig::DEFAULT_SYSTEM_PROMPT_PATH) {
            return Ok(SystemPrompt {
                raw: EMBEDDED_V1.to_string(),
            });
        }
        let not_found = |e: std::io::Error| AdeError::SystemPromptLoad {
            path: path.display().to_string(),
            source: e,
        };
        fs::metadata(path).map_err(not_found)?;
        let (mut f, _) = super::model_trust::open_trusted(path)?;
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut f, &mut raw).map_err(not_found)?;
        if raw.trim().is_empty() {
            return Err(AdeError::SystemPromptEmpty);
        }
        Ok(SystemPrompt { raw })
    }
}

/// Split prompt: system role + user role. Backends apply their own
/// chat template.
#[derive(Debug, Clone)]
pub struct PromptParts {
    pub system: String,
    pub user: String,
}

impl PromptParts {
    /// Llama 3.1 chat template. The leading `<|begin_of_text|>` is
    /// included literally because backends typically pass
    /// `add_special_tokens=false` to the tokenizer to keep the
    /// template explicit and reproducible.
    pub fn into_llama3_chat(self) -> String {
        format!(
            "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n\
             {system}<|eot_id|>\
             <|start_header_id|>user<|end_header_id|>\n\n\
             {user}<|eot_id|>\
             <|start_header_id|>assistant<|end_header_id|>\n\n",
            system = self.system,
            user = self.user,
        )
    }

    /// Plain concatenation — used by `MockBackend` (which ignores
    /// the prompt content anyway) and by older test fixtures.
    pub fn into_plain_text(self) -> String {
        format!("{}\n\n{}", self.system, self.user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llama3_chat_template_round_trip_has_required_markers() {
        let parts = PromptParts {
            system: "S".into(),
            user: "U".into(),
        };
        let s = parts.into_llama3_chat();
        assert!(s.starts_with("<|begin_of_text|>"));
        assert!(s.contains("<|start_header_id|>system<|end_header_id|>"));
        assert!(s.contains("<|start_header_id|>user<|end_header_id|>"));
        assert!(s.contains("<|start_header_id|>assistant<|end_header_id|>"));
        assert!(s.contains("<|eot_id|>"));
        assert!(s.contains("\nS<|eot_id|>"));
        assert!(s.contains("\nU<|eot_id|>"));
        // Trailing newlines after the assistant header give the model
        // a clean place to start its first JSON token.
        assert!(s.ends_with("<|end_header_id|>\n\n"));
    }

    #[test]
    fn plain_text_template_concatenates_system_and_user() {
        let parts = PromptParts {
            system: "S".into(),
            user: "U".into(),
        };
        let s = parts.into_plain_text();
        assert!(s.starts_with("S"));
        assert!(s.ends_with("U"));
    }
}
