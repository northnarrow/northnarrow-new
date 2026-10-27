//! Tappa 10.5 (D1) — shared configuration loaders.
//!
//! Houses the generic `.v1` + `.local` overlay parser
//! ([`overlay`]) extracted from the Tappa 9 C7 FIM watched-paths
//! loader, plus the per-family comm-allowlist typed wrappers
//! ([`comm_allowlist`]) the Tappa 10.5 process + network rule
//! families consume. The FIM loader (`fim/paths_config.rs`) is now
//! a thin path-typed wrapper over [`overlay::load_flat_list`].

pub mod comm_allowlist;
pub mod overlay;
pub mod overlay_auth;
pub mod overlay_floor;

/// The shipped default lists of every family, against `deploy/install.sh`
/// and `configs/`. R07 (lab PR 247): from `overlay`'s tests (the loader's
/// own moved to nn-core with it); these name the agent's lists.
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::overlay::Shipped;

    /// Every shipped default list: its file name in `/etc/northnarrow` and
    /// its shipped copies.
    fn shipped_lists() -> [(&'static str, Shipped<'static>); 6] {
        [
            ("fim-paths.v1", crate::fim::paths_config::FIM_PATHS_SHIPPED),
            (
                "netflow-blocklist.v1",
                crate::net::blocklist::NETFLOW_BLOCKLIST_SHIPPED,
            ),
            (
                "netflow-ja3-blocklist.v1",
                crate::net::blocklist::JA3_BLOCKLIST_SHIPPED,
            ),
            (
                "process-comm-allowlist.v1",
                crate::config::comm_allowlist::PROCESS_COMM_ALLOWLIST_SHIPPED,
            ),
            (
                "netflow-comm-allowlist.v1",
                crate::config::comm_allowlist::NETFLOW_COMM_ALLOWLIST_SHIPPED,
            ),
            // Lab PR 225.
            ("security-tools.v1", crate::impair::SECURITY_TOOLS_SHIPPED),
        ]
    }

    /// External audit LLMR-015: `install.sh` replaces exactly the copies the
    /// agent supersedes — its `SHIPPED_V1_EARLIER` table is the agent's —
    /// and installs every list through the same check.
    #[test]
    fn install_sh_knows_the_same_shipped_lists() {
        use std::collections::BTreeMap;
        let install =
            std::fs::read_to_string(concat!(env!("NN_REPO_ROOT"), "/deploy/install.sh")).unwrap();
        let start = install
            .find("declare -A SHIPPED_V1_EARLIER=(")
            .expect("deploy/install.sh declares SHIPPED_V1_EARLIER");
        let block = &install[start..];
        let block = &block[..block.find("\n)").unwrap()];
        let mut table = BTreeMap::new();
        for line in block.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, hashes) = line
                .strip_prefix('[')
                .and_then(|l| l.split_once("]="))
                .unwrap_or_else(|| panic!("unexpected line in SHIPPED_V1_EARLIER: {line}"));
            let hashes: BTreeSet<String> = hashes
                .trim_matches('"')
                .split_whitespace()
                .map(String::from)
                .collect();
            table.insert(name.to_string(), hashes);
        }
        let ours: BTreeMap<String, BTreeSet<String>> = shipped_lists()
            .iter()
            .map(|(name, shipped)| {
                (
                    name.to_string(),
                    shipped
                        .earlier_sha256
                        .iter()
                        .map(|h| h.to_string())
                        .collect(),
                )
            })
            .collect();
        assert_eq!(table, ours);
        for (name, _) in shipped_lists() {
            assert!(
                install.contains(&format!("install_shipped_v1 {name} ")),
                "install.sh installs {name} through install_shipped_v1"
            );
        }
    }

    /// External audit LLMR-015: the built-in copy of each list, pinned. A
    /// change to `configs/<list>.v1` turns the copy every installed host has
    /// into an "edited" one unless its SHA-256 moves to the earlier ones,
    /// here and in `install.sh`.
    #[test]
    fn the_shipped_lists_are_pinned() {
        let pins = [
            (
                "fim-paths.v1",
                "44a5f17e037148eb31a8798d7c0918e31d4657ba2ca7003b696a775741326508",
            ),
            (
                "netflow-blocklist.v1",
                "4588710cd342c6eeb5054acb108d47aa6dbf020feb768c8775fdc2d30e4c84f9",
            ),
            (
                "netflow-ja3-blocklist.v1",
                "3549750f6c1530fc139f9853d173bccb72612b58086392517fa9fe1f3a815870",
            ),
            (
                "process-comm-allowlist.v1",
                "a096c0dc64852fba9861009935028b28888307ae04dee99f4aa51f6b72ffdea0",
            ),
            (
                "netflow-comm-allowlist.v1",
                "46a1965afe80c7b578bb3584126f35a46d678bd59a6e2ca59081f65381d93266",
            ),
            (
                "security-tools.v1",
                "38cef57a92f6b394be9307c0f16e8799d553d0cff7bb6d7fd3db0b3906736335",
            ),
        ];
        for ((name, shipped), (pin_name, pin)) in shipped_lists().into_iter().zip(pins) {
            assert_eq!(name, pin_name);
            let sha = shipped.builtin_sha256();
            assert_eq!(
                sha, pin,
                "configs/{name} changed: add {pin} to its EARLIER_*_SHA256 table and to \
                 SHIPPED_V1_EARLIER in deploy/install.sh, then pin {sha} here"
            );
            assert!(!shipped.earlier_sha256.contains(&pin));
            let distinct: BTreeSet<&&str> = shipped.earlier_sha256.iter().collect();
            assert_eq!(distinct.len(), shipped.earlier_sha256.len(), "{name}");
            for h in shipped.earlier_sha256 {
                assert!(
                    h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                    "{name}: {h}"
                );
            }
            let file = std::fs::read_to_string(format!("{}/configs/{name}", env!("NN_REPO_ROOT")))
                .unwrap();
            assert_eq!(
                file, shipped.builtin,
                "{name}: the built-in copy is configs/"
            );
        }
    }
}
