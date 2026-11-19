//! The anti-tamper baits: each path with its inert template (Tappa 9.5.1;
//! the agent's `fim::honeypot`, which deploys them and sweeps them at boot).
//!
//! R08b (lab PR 251): cut verbatim from the agent's `fim::honeypot`, which
//! re-exports it, because NN-L-FIM-024 (`fim::rules`, moving to nn-core
//! with the engine) watches these paths ([`BAIT_PATHS`]): content, as the
//! canary templates of R07 (lab PR 247). The templates are embedded from
//! `configs/honeypot-baits/` (`NN_REPO_ROOT`), so the agent's recreate holds
//! what `deploy/install.sh` writes.

macro_rules! bait {
    ($name:literal) => {
        include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/configs/honeypot-baits/",
            $name
        ))
    };
}

/// The baits: each path with its template, embedded from
/// `configs/honeypot-baits/`. External audit NN-AUD-289 (FIMR-015): the
/// paths were a list in `fim::rules` and the contents a `match` here,
/// paired only by a test, and the sweep took a bait without a template
/// for a bug — `.expect`, a panic (`panic = "abort"`: the agent). One
/// table now: a bait cannot be listed without its content.
pub const BAITS: &[(&str, &str)] = &[
    ("/etc/northnarrow/agent.dev.lock", bait!("agent.dev.lock")),
    (
        "/etc/northnarrow/kill_switch.conf",
        bait!("kill_switch.conf"),
    ),
    (
        "/etc/northnarrow/maintenance.mode",
        bait!("maintenance.mode"),
    ),
    (
        "/etc/northnarrow/debug_disable.flag",
        bait!("debug_disable.flag"),
    ),
    (
        "/etc/northnarrow/agent.legacy.conf",
        bait!("agent.legacy.conf"),
    ),
    (
        "/var/lib/northnarrow/shutdown.signal",
        bait!("shutdown.signal"),
    ),
    ("/var/lib/northnarrow/disable.token", bait!("disable.token")),
    (
        "/var/lib/northnarrow/override.config",
        bait!("override.config"),
    ),
    ("/run/northnarrow/pause.flag", bait!("pause.flag")),
    ("/run/northnarrow/unload.signal", bait!("unload.signal")),
];

/// The paths of [`BAITS`], in its order: what
/// [`crate::fim::rules::HONEYPOT_PATHS`] is.
pub const BAIT_PATHS: [&str; BAITS.len()] = {
    let mut paths = [""; BAITS.len()];
    let mut i = 0;
    while i < BAITS.len() {
        paths[i] = BAITS[i].0;
        i += 1;
    }
    paths
};

/// The template of a bait (its `last_modified=` line empty), embedded from
/// `configs/honeypot-baits/`. `None` for any path not in [`BAITS`].
pub fn bait_content(path: &str) -> Option<&'static str> {
    BAITS
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, content)| *content)
}

/// Lot 373 (the rc7 soak): `bytes` are the bait of `path` as the agent's
/// boot sweep (`fim::honeypot::render_bait`) and `deploy/install.sh`
/// (`install_bait`) write it — its template line for line, its
/// `last_modified=` line a UTC stamp to the second
/// (`2026-10-20T09:30:00Z`). A bait that says anything else (`paused=true`,
/// a line added, removed or changed) is not: its content is an attempt on
/// the control surface. `false` for a path not in [`BAITS`].
pub fn is_bait_rendering(path: &str, bytes: &[u8]) -> bool {
    let Some(template) = bait_content(path) else {
        return false;
    };
    let Ok(text) = core::str::from_utf8(bytes) else {
        return false;
    };
    let mut want = template.split_inclusive('\n');
    let mut have = text.split_inclusive('\n');
    loop {
        match (want.next(), have.next()) {
            (None, None) => return true,
            (Some(w), Some(h)) if w.starts_with(LAST_MODIFIED) => {
                let (w_end, h_end) = (w.ends_with('\n'), h.ends_with('\n'));
                let stamp = h
                    .strip_prefix(LAST_MODIFIED)
                    .map(|s| s.strip_suffix('\n').unwrap_or(s));
                if w_end != h_end || !stamp.is_some_and(is_utc_stamp) {
                    return false;
                }
            }
            (Some(w), Some(h)) if w == h => {}
            _ => return false,
        }
    }
}

/// Prefix of the line a bait's write fills with its stamp.
const LAST_MODIFIED: &str = "last_modified=";

/// `YYYY-MM-DDTHH:MM:SSZ`, digits where digits go.
fn is_utc_stamp(s: &str) -> bool {
    const SHAPE: &[u8; 20] = b"0000-00-00T00:00:00Z";
    s.len() == SHAPE.len()
        && s.bytes().zip(SHAPE.iter()).all(|(b, want)| {
            if *want == b'0' {
                b.is_ascii_digit()
            } else {
                b == *want
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(path: &str, stamp: &str) -> String {
        bait_content(path)
            .expect("a bait")
            .replace("last_modified=\n", &format!("last_modified={stamp}\n"))
    }

    /// Lot 373: the bait as written (any stamp) is the bait;
    /// a changed value, a line added or removed, another path's template
    /// or a malformed stamp is not.
    #[test]
    fn a_bait_is_told_by_its_template_and_its_stamp() {
        for (path, template) in BAITS {
            assert!(template.contains("last_modified=\n"), "{path}");
            assert!(is_bait_rendering(
                path,
                rendered(path, "2026-11-19T07:00:36Z").as_bytes()
            ));
            // the template itself, its date line empty, is what neither
            // the sweep nor the install writes
            assert!(
                !is_bait_rendering(path, template.as_bytes()),
                "{path}: no stamp"
            );
            let hostile = rendered(path, "2026-11-19T07:00:36Z").replacen('=', "=1", 1);
            assert!(
                !is_bait_rendering(path, hostile.as_bytes()),
                "{path}: a value changed"
            );
            let added = format!("{}enabled=0\n", rendered(path, "2026-11-19T07:00:36Z"));
            assert!(
                !is_bait_rendering(path, added.as_bytes()),
                "{path}: a line added"
            );
            let bad = rendered(path, "2026-11-19 07:00:36");
            assert!(
                !is_bait_rendering(path, bad.as_bytes()),
                "{path}: not a stamp"
            );
            assert!(!is_bait_rendering(path, b""), "{path}: empty");
        }
        let pause = rendered("/run/northnarrow/pause.flag", "2026-11-19T07:00:36Z");
        assert!(!is_bait_rendering(
            "/run/northnarrow/unload.signal",
            pause.as_bytes()
        ));
        assert!(!is_bait_rendering("/etc/passwd", pause.as_bytes()));
        let paused = pause.replace("paused=false", "paused=true");
        assert!(!is_bait_rendering(
            "/run/northnarrow/pause.flag",
            paused.as_bytes()
        ));
    }
}
