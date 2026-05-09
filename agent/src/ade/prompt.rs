//! Prompt assembly for ADE.
//!
//! The system prompt is loaded once at startup; per-event prompts
//! sandwich the (canonical) event JSON between the system prompt and
//! a short reminder of the output contract. Recent correlated events
//! and host context get folded in as compact lines so a 2K-token
//! context window stays roomy enough for the example block.
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

/// Build the full prompt sent to the model for a single event.
pub fn build_event_prompt(
    system: &SystemPrompt,
    config: &AdeConfig,
    event: &Event,
    context: &EventContext,
) -> String {
    let mut buf = String::with_capacity(system.raw.len() + 1024);
    buf.push_str(&system.raw);
    buf.push_str("\n\n## Contesto host\n");
    push_host_context(&mut buf, &context.host_context);
    if let Some(role) = &config.host_role {
        buf.push_str(&format!("- host_role: {role}\n"));
    }
    buf.push_str(&format!("- language_used: {}\n", config.language));

    if !context.recent_events.is_empty() {
        buf.push_str("\n## Eventi correlati recenti\n");
        // Newest first; the trace context only really helps for the
        // last few events anyway.
        for e in context.recent_events.iter().rev().take(20) {
            buf.push_str(&format_event_line(e));
            buf.push('\n');
        }
    }

    buf.push_str("\n## Evento da analizzare\n");
    buf.push_str(&format_event_block(event));
    buf.push_str("\n\n## Output\nProduci ora il JSON ADE v1.0.0 conforme allo schema.\n");
    buf
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
            raw: "PROMPT\n".into(),
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
        let p = build_event_prompt(&sys, &cfg, &event, &ctx);
        assert!(p.contains("PROMPT"));
        assert!(p.contains("hostname: h1"));
        assert!(p.contains("language_used: it-IT"));
        assert!(p.contains("/bin/ls"));
        assert!(p.contains("Evento da analizzare"));
    }

    #[test]
    fn build_event_prompt_includes_recent_events_when_present() {
        let sys = SystemPrompt {
            raw: "PROMPT\n".into(),
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
        let p = build_event_prompt(&sys, &cfg, &focal, &ctx);
        assert!(p.contains("Eventi correlati recenti"));
        assert!(p.contains("/tmp/parent"));
    }
}
