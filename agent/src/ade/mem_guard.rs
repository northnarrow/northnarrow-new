//! Pre-flight RAM guard for ADE model load (Beta Step 2b).
//!
//! ADE loads the Foundation-Sec-8B Q4_K_M GGUF (~5 GB of weights) and
//! then allocates a KV cache, scratch buffers, the tokenizer and a
//! rayon pool on top — `docs/ADE_BACKEND_NOTES.md` measures ~7 GB peak
//! RSS. On a VM that doesn't have that much free, the load OOM-crashes
//! the agent (and, pre Step 2a, could take the host down with it).
//!
//! This guard reads `MemAvailable` from `/proc/meminfo` and the model
//! file's on-disk size and refuses the load when there isn't enough
//! headroom, so a small host degrades gracefully to detection-only
//! (rule engine) instead of crash-looping. It mirrors the agent's
//! existing warn-and-continue posture for an unusable bpffs mount.

use std::path::Path;

/// Runtime overhead we require *on top of* the model's on-disk size
/// before attempting a load. The GGUF maps to ~its file size of
/// weights; `docs/ADE_BACKEND_NOTES.md` measures ~7 GB peak RSS for the
/// ~5 GB model, i.e. ~2 GB of KV-cache + scratch + tokenizer + rayon
/// overhead. Rounded up to 3 GiB so we keep a real margin rather than
/// loading into a host that would then thrash or OOM mid-inference.
pub const ADE_MEM_SLACK_BYTES: u64 = 3 * 1024 * 1024 * 1024;

/// Outcome of the pre-load memory check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdeMemCheck {
    /// Enough free memory — proceed with the load.
    Ok {
        available_bytes: u64,
        required_bytes: u64,
    },
    /// Not enough free memory — skip ADE, run detection-only.
    Insufficient {
        available_bytes: u64,
        required_bytes: u64,
    },
    /// Couldn't determine model size or available memory. The caller
    /// proceeds (fail-open): this guard is a best-effort safety net,
    /// not a correctness gate, and the loader surfaces a clearer error
    /// for a genuinely missing/unreadable model.
    Unknown { reason: String },
}

/// Decide purely from the two numbers — split out for unit testing
/// without touching `/proc` or the filesystem.
pub fn decide(available_bytes: u64, model_size_bytes: u64) -> AdeMemCheck {
    let required_bytes = model_size_bytes.saturating_add(ADE_MEM_SLACK_BYTES);
    if available_bytes >= required_bytes {
        AdeMemCheck::Ok {
            available_bytes,
            required_bytes,
        }
    } else {
        AdeMemCheck::Insufficient {
            available_bytes,
            required_bytes,
        }
    }
}

/// Check whether the host has enough free memory to load `model_path`.
pub fn check_ade_memory(model_path: &Path) -> AdeMemCheck {
    let model_size_bytes = match std::fs::metadata(model_path) {
        Ok(m) => m.len(),
        Err(e) => {
            return AdeMemCheck::Unknown {
                reason: format!("stat model {}: {e}", model_path.display()),
            }
        }
    };
    let Some(available_bytes) = read_mem_available_bytes() else {
        return AdeMemCheck::Unknown {
            reason: "MemAvailable absent from /proc/meminfo".to_string(),
        };
    };
    decide(available_bytes, model_size_bytes)
}

/// Read `MemAvailable` (bytes) from `/proc/meminfo`.
fn read_mem_available_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_available(&text)
}

/// Parse the `MemAvailable:` line (reported in kB) into bytes.
pub(crate) fn parse_mem_available(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn parse_mem_available_extracts_kb_as_bytes() {
        let meminfo = "MemTotal:       15998884 kB\nMemFree:  123456 kB\nMemAvailable:   13670000 kB\nBuffers: 1 kB\n";
        assert_eq!(
            parse_mem_available(meminfo),
            Some(13_670_000 * 1024)
        );
    }

    #[test]
    fn parse_mem_available_missing_line_is_none() {
        let meminfo = "MemTotal: 15998884 kB\nMemFree: 123456 kB\n";
        assert_eq!(parse_mem_available(meminfo), None);
    }

    #[test]
    fn decide_ok_when_available_covers_model_plus_slack() {
        // 5 GiB model needs 5 + 3 = 8 GiB; host has 13.67 GiB free.
        let avail = 13 * GIB + 700 * 1024 * 1024;
        match decide(avail, 5 * GIB) {
            AdeMemCheck::Ok { required_bytes, .. } => {
                assert_eq!(required_bytes, 5 * GIB + ADE_MEM_SLACK_BYTES);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn decide_insufficient_when_below_required() {
        // 5 GiB model needs 8 GiB; a 6 GiB VM with 4 GiB free fails.
        assert!(matches!(
            decide(4 * GIB, 5 * GIB),
            AdeMemCheck::Insufficient { .. }
        ));
    }

    #[test]
    fn decide_boundary_exactly_required_is_ok() {
        let required = 5 * GIB + ADE_MEM_SLACK_BYTES;
        assert!(matches!(decide(required, 5 * GIB), AdeMemCheck::Ok { .. }));
    }
}
