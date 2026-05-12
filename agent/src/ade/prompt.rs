//! Prompt assembly for ADE.
//!
//! The prompt has two parts:
//!
//! - the [`SystemPrompt`] — loaded once at startup, holds the schema,
//!   the 5-step procedure, and few-shot examples.
//! - the per-event "user" message — host context, correlated events,
//!   and the focal event itself.
//!
//! Wrapping the two parts into a chat template is the backend's
//! responsibility (Llama 3.1 wants `<|begin_of_text|>` /
//! `<|start_header_id|>` markers; the mock backend doesn't care).
//! See [`PromptParts::into_llama3_chat`] and
//! [`PromptParts::into_plain_text`].
//!
//! Truncation strategy when the prompt grows past
//! `max_context_tokens`: drop oldest correlated events first; never
//! truncate the system prompt or the focal event itself.

use std::fs;
use std::path::Path;

use common::Event;

use super::config::AdeConfig;
use super::context::{EventContext, HostContext};
use super::error::AdeError;

/// Loaded system prompt + lightweight metadata.
#[derive(Debug, Clone)]
pub struct SystemPrompt {
    pub raw: String,
}

impl SystemPrompt {
    pub fn load(path: &Path) -> Result<Self, AdeError> {
        let raw = fs::read_to_string(path).map_err(|e| AdeError::SystemPromptLoad {
            path: path.display().to_string(),
            source: e,
        })?;
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

/// Build the structured prompt for a single event. Returns
/// `(system, user)` parts; the backend formats the chat template.
pub fn build_event_prompt(
    system: &SystemPrompt,
    config: &AdeConfig,
    event: &Event,
    context: &EventContext,
) -> PromptParts {
    let mut user = String::with_capacity(1024);
    user.push_str("## Contesto host\n");
    push_host_context(&mut user, &context.host_context);
    if let Some(role) = &config.host_role {
        user.push_str(&format!("- host_role: {role}\n"));
    }
    user.push_str(&format!("- language_used: {}\n", config.language));

    if !context.recent_events.is_empty() {
        user.push_str("\n## Eventi correlati recenti\n");
        // Newest-first scan, then take 20: the freshest correlated
        // events matter most for the analyst's hypothesis.
        for e in context.recent_events.iter().rev().take(20) {
            user.push_str(&format_event_line(e));
            user.push('\n');
        }
    }

    user.push_str("\n## Evento da analizzare\n");
    user.push_str(&format_event_block(event));
    user.push_str(
        "\n\n## Output\n\
         Produci ora il JSON ADE v1.0.0 conforme allo schema. \
         Niente prosa prima/dopo. Niente code fences.\n",
    );

    PromptParts {
        system: system.raw.clone(),
        user,
    }
}

fn push_host_context(buf: &mut String, ctx: &HostContext) {
    buf.push_str(&format!("- hostname: {}\n", ctx.hostname));
    buf.push_str(&format!("- host_id: {}\n", ctx.host_id));
    buf.push_str(&format!("- kernel_version: {}\n", ctx.kernel_version));
    buf.push_str(&format!("- agent_version: {}\n", ctx.agent_version));
}

/// One-line summary used inside the "recent events" block.
pub(crate) fn format_event_line(event: &Event) -> String {
    match event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            comm,
            filename,
            ..
        } => format!(
            "- process_spawn pid={pid} ppid={ppid} uid={uid} comm={comm} filename={filename}"
        ),
        Event::FileOpen {
            pid,
            uid,
            comm,
            filename,
            flags,
            ..
        } => format!(
            "- file_open pid={pid} uid={uid} comm={comm} flags={flags:#o} filename={filename}"
        ),
        Event::ExecCheck {
            pid,
            ppid,
            uid,
            comm,
            filename,
            ..
        } => {
            format!("- exec_check pid={pid} ppid={ppid} uid={uid} comm={comm} filename={filename}")
        }
        Event::TcpConnect {
            pid,
            uid,
            comm,
            family,
            dst_port,
            ..
        } => format!(
            "- tcp_connect pid={pid} uid={uid} comm={comm} family={family} dst_port={dst_port}"
        ),
        Event::DnsQuery {
            pid,
            uid,
            comm,
            query_name,
            query_type,
            ..
        } => format!(
            "- dns_query pid={pid} uid={uid} comm={comm} qname={query_name} qtype={query_type}"
        ),
        Event::FsProtectDenial {
            pid,
            uid,
            comm,
            target_dev,
            target_ino,
            operation,
            ..
        } => format!(
            "- fs_protect_denial pid={pid} uid={uid} comm={comm} op={operation} \
             dev={target_dev} ino={target_ino}"
        ),
    }
}

/// Multi-line block used for the focal event so the model has every
/// detail at a glance.
fn format_event_block(event: &Event) -> String {
    serde_json::to_string_pretty(event).unwrap_or_else(|_| format!("{event:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ade::context::{EventContext, HostContext};

    fn host() -> HostContext {
        HostContext {
            hostname: "h1".into(),
            host_id: "id1".into(),
            kernel_version: "6.8.0".into(),
            agent_version: "0.0.1".into(),
        }
    }

    #[test]
    fn build_event_prompt_includes_event_and_host() {
        let sys = SystemPrompt {
            raw: "PROMPT".into(),
        };
        let cfg = AdeConfig::default();
        let event = Event::ProcessSpawn {
            pid: 42,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "ls".into(),
            filename: "/bin/ls".into(),
            timestamp_ns: 0,
        };
        let ctx = EventContext {
            recent_events: vec![],
            host_context: host(),
        };
        let parts = build_event_prompt(&sys, &cfg, &event, &ctx);
        assert_eq!(parts.system, "PROMPT");
        assert!(parts.user.contains("hostname: h1"));
        assert!(parts.user.contains("language_used: it-IT"));
        assert!(parts.user.contains("/bin/ls"));
        assert!(parts.user.contains("Evento da analizzare"));
    }

    #[test]
    fn build_event_prompt_includes_recent_events_when_present() {
        let sys = SystemPrompt {
            raw: "PROMPT".into(),
        };
        let cfg = AdeConfig::default();
        let focal = Event::ProcessSpawn {
            pid: 42,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "x".into(),
            filename: "/tmp/x".into(),
            timestamp_ns: 10,
        };
        let recent = Event::ProcessSpawn {
            pid: 41,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "p".into(),
            filename: "/tmp/parent".into(),
            timestamp_ns: 5,
        };
        let ctx = EventContext {
            recent_events: vec![recent],
            host_context: host(),
        };
        let parts = build_event_prompt(&sys, &cfg, &focal, &ctx);
        assert!(parts.user.contains("Eventi correlati recenti"));
        assert!(parts.user.contains("/tmp/parent"));
    }

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
