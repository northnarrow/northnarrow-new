//! Tappa 9.5 (K2) — canary registry: deploy + list + burn +
//! refresh state machine + chained on-disk DB.
//!
//! Persists to `/var/lib/northnarrow/canaries.jsonl` (Tappa 7
//! LSM-protected via the Tappa 9 C7 `STATE_PROTECTED_FILES`
//! extension that K7 deploy bootstrap will widen for the
//! canary chains). Same hash-chain + signature shape as the
//! Tappa 8 audit log + Tappa 9 baseline + drift chains —
//! verification reuses the same `prev_hash` / `entry_hash` /
//! `agent_sig` triple primitives.
//!
//! ## What this commit (K2) ships
//!
//! - [`CanaryToken`] — on-disk JSONL row matching design §4.1:
//!   `name` + `canary_id` + `canary_type` + `deployment` +
//!   `deployed_at_unix` + `deployed_by_fp` + `tripped` +
//!   `first_trip_access_hash` + chain integrity fields
//!   (agent_id / prev_hash / entry_hash / agent_sig).
//! - [`CanaryTokenDraft`] — operator-supplied fields for
//!   `Registry::deploy` (chain fields are computed by `deploy`,
//!   never supplied by the caller — same invariant as Tappa 9
//!   C3's `BaselineEntryDraft`).
//! - [`RegistryAction`] — discriminated union of registry
//!   actions persisted to the chain: `Deploy` / `Burn` /
//!   `Refresh` / `Trip` / `DecoyCheck`. The chain captures EVERY
//!   state transition for audit-grade traceability.
//! - [`Registry::open`] — opens the JSONL log, walks any
//!   existing entries to recover the in-memory state (which
//!   canaries are live, which are tripped, the chain tail-
//!   hash). Missing file → empty state (chain starts at
//!   `audit::GENESIS_PREV_HASH`).
//! - [`Registry::deploy`] / `burn` / `refresh` — the three
//!   state-transition methods. Each appends a chained row,
//!   advances the in-memory tail-hash, updates the live-set.
//! - [`Registry::list`] — operator-facing read API. Returns a
//!   cloned snapshot of every active canary (`burn` rows
//!   remove from the live set; `refresh` resets `tripped`).
//! - [`Registry::mark_tripped`] — called by the K3 detector
//!   on first access. External audit DEC-011: appends a `Trip`
//!   row carrying the `entry_hash` of the access row (in the
//!   SEPARATE `canary_access.jsonl` chain K3 writes), so a
//!   tripped canary stays tripped across a restart until an
//!   operator refreshes it (§12 Q2). It used to change the
//!   in-memory state only: every restart re-armed the K5
//!   response for a canary already tripped.
//! - External audit DEC-010: a File / Credential row carries the
//!   SHA-256 of the decoy written and the seed it was rendered
//!   from; at boot [`check_decoy`] compares the file with it, and
//!   a change of what the boot found is a `DecoyCheck` row, so
//!   `nn-admin canary list` shows a decoy modified, removed or
//!   replaced while the agent was down.
//! - [`verify_chain`] — pure off-host verifier symmetric to
//!   `crate::audit::verify_chain` + `crate::fim::baseline::
//!   verify_chain`. Replays a sequence of [`CanaryToken`]
//!   rows, recomputing entry_hash + checking agent_sig
//!   against a supplied verifying key.
//! - Lab PR 260: the access row with `first_trip: true` is the trip's
//!   commit — the detector writes and syncs it before the `Trip` row that
//!   names it. An agent stopped between the two (lab PR 258's KVM run:
//!   the e2e fixture's SIGQUIT landed there) left this registry at its
//!   deploy row, and the next start re-armed a tripped canary: its trip
//!   forgotten here, its next access a first trip again.
//!   [`Registry::unrecorded_trips`] finds, at open, the first-trip rows of
//!   an armed canary's arming that no row here names, and the boot records
//!   each (a `Trip` row naming it). A `Refresh` row names the trip it
//!   clears, so the open knows which first-trip rows a refresh re-armed
//!   after.
//!
//! ## What this commit (K2) deliberately does NOT ship
//!
//! - **No K3 detector integration.** The K3 inline-filter
//!   intercept (§12 Q9 OPTION B lock-in) consumes
//!   `Registry::is_canary_inode` / `is_canary_exe` / etc. —
//!   those query helpers ship in K3 alongside the
//!   `Event::CanaryTripped` emit path.
//! - **No K4 templates.** Cred-canary content renderer
//!   (5 cred families) lives in `canary/templates.rs`. K2's
//!   `deploy` accepts whatever `CanaryDeployment` payload the
//!   admin op carries.
//! - **No K5 rules.** NN-L-CANARY-001..004 fire on
//!   `Event::CanaryTripped` which only K3 emits.
//! - **No K6 admin-socket dispatch.** `nn-admin canary deploy`
//!   admin op wiring is K6.
//! - **No K8 priv-e2e.** Deployment + trip end-to-end on a
//!   real kernel is the K8 sprint.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use common::wire::InodeKey;
use ed25519_dalek::{Signature, VerifyingKey};
use nn_proto::admin_signed_payload::{CanaryDeploymentWire, CanaryTypeWire};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{AgentSigningKey, GENESIS_PREV_HASH};
use crate::canary::access_log::{CanaryAccessEntry, FirstTripRow};

/// Default deploy location of the chained registry log. Lives
/// alongside the other Tappa 8/9 state files under
/// `/var/lib/northnarrow/` so the Tappa 7 task 5 FS-LSM
/// protection + the §6.5 PROTECTED_PIDS caller exemption
/// naturally cover it once K7 adds it to the state directory's
/// protected-files list.
pub const DEFAULT_REGISTRY_PATH: &str = "/var/lib/northnarrow/canaries.jsonl";

/// File mode for the persisted registry log: root only (external
/// audit EVD-019, [`crate::chainlog::STATE_LOG_FILE_MODE`]; it lists
/// where every decoy is). Operators read it with `sudo` or `nn-admin`.
const REGISTRY_FILE_MODE: u32 = crate::chainlog::STATE_LOG_FILE_MODE;

/// Bumped when the on-disk schema or hash-input bytes change.
/// Verifiers consult this to refuse a chain they were not
/// built to read. Stays at 1 for K2 — any future field
/// addition with `#[serde(default)]` keeps the version stable.
pub const CANARY_REGISTRY_FORMAT_VERSION: u32 = 1;

// ── on-disk schema ──────────────────────────────────────────────────

/// Discriminator for the kinds of state-transition rows the
/// registry chain captures. The on-disk format embeds this
/// tag so a single replay loop can dispatch correctly across
/// actions. Variant order MUST stay stable and new variants are
/// appended (the serde representation drives wire-byte semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAction {
    /// Operator deployed a fresh canary. Carries the full
    /// canary state in the row's `deployment`/`canary_type`/
    /// etc. fields.
    Deploy,
    /// Operator retired a previously-deployed canary
    /// (`nn-admin canary burn <id>`). Removes from the live
    /// set; the original deploy row stays in the chain as
    /// audit history.
    Burn,
    /// Operator reset a tripped canary
    /// (`nn-admin canary refresh <id>`). In-memory `tripped`
    /// flag clears; subsequent accesses re-fire the rule
    /// (§12 Q2 single-trip lock-in respected via operator-
    /// intent audit row, not magic auto-state-change). A File /
    /// Credential decoy is written again with a new seed; the row
    /// carries its content and `decoy_state: intact`.
    Refresh,
    /// External audit DEC-011: the first access the K3 detector saw.
    /// `first_trip_access_hash` is the access row's `entry_hash`. An
    /// agent older than this row skips it as unreadable (DEC-006).
    Trip,
    /// External audit DEC-010: the boot found the decoy in a state other
    /// than the one last recorded (`decoy_state`).
    DecoyCheck,
}

/// External audit DEC-010: what the boot found at a File / Credential
/// canary's path, against the content its row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyState {
    /// The file written at deploy or refresh (or, for a row recorded
    /// before content hashes, a regular file).
    Intact,
    /// A regular file with other content.
    Modified,
    /// Nothing at the path.
    Missing,
    /// A symlink, FIFO, directory, socket or device at the path.
    NotRegular,
    /// Present but not readable.
    Unreadable,
}

impl DecoyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DecoyState::Intact => "intact",
            DecoyState::Modified => "modified",
            DecoyState::Missing => "missing",
            DecoyState::NotRegular => "not_regular",
            DecoyState::Unreadable => "unreadable",
        }
    }
}

/// External audit DEC-010 / DEC-008: what a File / Credential decoy was
/// written with — the SHA-256 of its bytes and the seed they were rendered
/// from (agent-only: the registry lives in `/var/lib/northnarrow`, 0700).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyContent {
    pub contents_sha256: String,
    pub content_seed: Option<String>,
}

/// One on-disk JSONL row per design §4.1. Field order MATTERS
/// for the `entry_hash` computation: `serde_json` preserves
/// struct field declaration order on serialisation, so any
/// reorder is a chain-format break — bump
/// [`CANARY_REGISTRY_FORMAT_VERSION`] in that case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryToken {
    /// ISO-8601 UTC timestamp of the action. Same fixed-width
    /// format as Tappa 8 audit + Tappa 9 baseline/drift chains
    /// (`%Y-%m-%dT%H:%M:%S%.6fZ`).
    pub ts: String,
    /// The action this row records — Deploy / Burn / Refresh.
    pub action: RegistryAction,
    /// Per-canary stable ID — `SHA-256(name || deployed_at ||
    /// random_salt)[..16]` rendered as 32-hex-chars. Same ID
    /// is referenced across all rows for a given canary's
    /// lifecycle (Deploy → … → Burn).
    pub canary_id: String,
    /// Operator-supplied human-readable name. Used as the
    /// primary reference in `nn-admin canary list` output;
    /// the `canary_id` is what `burn`/`refresh` ops carry on
    /// the wire (collision-resistant).
    pub name: String,
    /// Canary type — see [`CanaryTypeWire`].
    pub canary_type: CanaryTypeWire,
    /// Type-specific deployment data (path / port / cred
    /// family). On Burn / Refresh rows this is a copy of the
    /// Deploy-row deployment (chain rows are self-contained;
    /// off-host verifiers don't need to cross-reference earlier
    /// rows to know what the canary is).
    pub deployment: CanaryDeploymentWire,
    /// Unix timestamp at the canary's ORIGINAL deploy time.
    /// Burn / Refresh rows carry the same value as their
    /// matching Deploy row — operators sort registries by
    /// "when was this canary first deployed".
    pub deployed_at_unix: u64,
    /// 8-hex-char fingerprint (`SHA-256(operator_pubkey)[..4]`)
    /// of the operator key that signed the deploy op. Same
    /// shape as the Tappa 8 audit log's `key_fp` field. Burn /
    /// Refresh rows carry the operator who performed THAT
    /// action (not the original deployer) for accountability.
    pub deployed_by_fp: String,
    /// `true` once any access has been observed (set by the K3
    /// detector via [`Registry::mark_tripped`]). Subsequent
    /// accesses do NOT re-fire the posture transition until
    /// an operator runs `nn-admin canary refresh <id>` (§12
    /// Q2 manual-only lock-in).
    pub tripped: bool,
    /// Populated when `tripped = true`. The first-trip
    /// `CanaryAccessEntry`'s entry_hash from the SEPARATE
    /// `canary_access.jsonl` chain (K3-side), for cross-chain
    /// reference. `None` until the first trip.
    ///
    /// Lab PR 260: on a `Refresh` row (`tripped: false`), the trip the
    /// refresh cleared — its first access row's hash — and `None` for the
    /// refresh of an armed canary (and on every `Refresh` row written
    /// before; agents before lab PR 260 read the field as cleared, as
    /// they always did).
    pub first_trip_access_hash: Option<String>,
    /// External audit DEC-010: SHA-256 (hex) of the decoy bytes written
    /// at deploy or the last refresh, on every row of a File /
    /// Credential canary. Absent on rows written before it (they
    /// serialise as they did, so their hashes verify).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contents_sha256: Option<String>,
    /// External audit DEC-008: the seed the decoy was rendered from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_seed: Option<String>,
    /// External audit DEC-010: on `DecoyCheck` rows, what the boot found;
    /// on `Refresh` rows that wrote the decoy again, `intact`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_state: Option<DecoyState>,
    /// Chain integrity (Tappa 8 B1 shape).
    pub agent_id: String,
    /// External audit NN-AUD-174: the row's 0-based position in the file,
    /// on rows written from lab PR 160 on (pre-image domain-tagged with
    /// [`crate::chain_anchor::CANARY_REGISTRY_DOMAIN_V2`]); absent on older
    /// rows, which keep their bytes and pre-image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub prev_hash: String,
    pub entry_hash: String,
    pub agent_sig: String,
}

/// Operator-supplied fields for [`Registry::deploy`]. Chain
/// integrity fields (`ts`, `prev_hash`, `entry_hash`,
/// `agent_sig`, `agent_id`, `deployed_at_unix`, `canary_id`,
/// `tripped`, `first_trip_access_hash`, `action`) are computed
/// by `deploy`, never supplied by the caller — that's exactly
/// the property the chain enforces. Same invariant as Tappa 9
/// C3's `BaselineEntryDraft`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryTokenDraft {
    pub name: String,
    pub canary_type: CanaryTypeWire,
    pub deployment: CanaryDeploymentWire,
    /// Operator-key fingerprint that signed the deploy op
    /// (8 hex chars, `SHA-256(pubkey)[..4]`). The admin-socket
    /// dispatch (K6) computes this from the verified
    /// `KeyedSignature` and passes it in.
    pub deployed_by_fp: String,
    /// What the File / Credential decoy was written with (`None` for
    /// Process / Network canaries).
    pub content: Option<DecoyContent>,
}

/// Live in-memory state for a single deployed canary. Distilled
/// from the chain at boot by [`Registry::open`]; mutated by
/// `deploy` / `burn` / `refresh` / `mark_tripped`. The chain
/// is the source of truth; this map is the operator-facing
/// view (no audit-history rows; only currently-active canaries
/// with their current trip state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryLiveState {
    pub name: String,
    pub canary_id: String,
    pub canary_type: CanaryTypeWire,
    pub deployment: CanaryDeploymentWire,
    pub deployed_at_unix: u64,
    pub deployed_by_fp: String,
    pub tripped: bool,
    pub first_trip_access_hash: Option<String>,
    /// External audit DEC-010: what the decoy was written with.
    pub content: Option<DecoyContent>,
    /// External audit DEC-010: the decoy state last recorded.
    pub decoy_state: DecoyState,
}

/// Lab PR 260: what the registry's rows say of a canary id's armings, for
/// [`Registry::unrecorded_trips`]. Kept for every id the rows name, a
/// burned one included (an id deployed again carries its history).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ArmHistory {
    /// The access rows the rows name (`first_trip_access_hash`: a `Trip`
    /// row's trip, a `Refresh` row's cleared trip, the copy a `Burn` or
    /// `DecoyCheck` row carries): trips the registry accounts for.
    named: BTreeSet<String>,
    /// The `ts` of the last `Deploy` or `Refresh` row: the last arming.
    armed_at: String,
    /// Whether that row is a `Refresh` (a `Deploy` otherwise).
    refreshed: bool,
    /// The trip that `Refresh` row cleared (its `first_trip_access_hash`).
    cleared: Option<String>,
}

impl ArmHistory {
    /// What a row the registry writes or applies says of its canary's
    /// armings.
    fn note(&mut self, row: &CanaryToken) {
        if let Some(named) = &row.first_trip_access_hash {
            self.named.insert(named.clone());
        }
        if matches!(row.action, RegistryAction::Deploy | RegistryAction::Refresh) {
            self.armed_at = row.ts.clone();
            self.refreshed = row.action == RegistryAction::Refresh;
            self.cleared = row
                .first_trip_access_hash
                .clone()
                .filter(|_| self.refreshed);
        }
    }

    /// The trip of this arming among `rows` (the access log's genuine
    /// first-trip rows, every canary's) that no registry row names, if
    /// any.
    ///
    /// The first-trip rows of this canary up to the latest one the
    /// registry names are accounted for: recorded trips, cleared by a
    /// refresh, or written before them. After it, a first-trip row no row
    /// names was written in this arming — the agent marks the canary
    /// tripped in memory at a first trip, so it writes no other first-trip
    /// row until a refresh, and a refresh names the trip it clears — but
    /// for a refresh this registry cannot place in the access log: one of
    /// an armed canary, one written before lab PR 260 (which named
    /// nothing; an agent before lab PR 143 also wrote no `Trip` row), or
    /// one whose trip's row is not in the log. A row written before that
    /// refresh's time counts for it as before it.
    fn unrecorded(&self, state: &CanaryLiveState, rows: &[FirstTripRow]) -> Option<UnrecordedTrip> {
        let mine: Vec<&FirstTripRow> = rows
            .iter()
            .filter(|r| r.entry.canary_id == state.canary_id)
            .collect();
        let named = |r: &FirstTripRow| self.named.contains(&r.entry.entry_hash);
        let fence = mine.iter().filter(|r| named(r)).map(|r| r.row).max();
        let placed = self
            .cleared
            .as_ref()
            .is_some_and(|c| mine.iter().any(|r| &r.entry.entry_hash == c));
        let unnamed: Vec<&FirstTripRow> = mine
            .into_iter()
            .filter(|r| !named(r))
            .filter(|r| fence.is_none_or(|f| r.row > f))
            .filter(|r| !self.refreshed || placed || r.entry.ts >= self.armed_at)
            .collect();
        let last = unnamed.iter().max_by_key(|r| r.row)?;
        Some(UnrecordedTrip {
            canary_id: state.canary_id.clone(),
            name: state.name.clone(),
            access: last.entry.clone(),
            access_row: last.row,
            first_trip_rows: unnamed.len(),
        })
    }
}

/// Lab PR 260: a trip of an armed canary that its access log holds and
/// the registry does not record ([`Registry::unrecorded_trips`]): the
/// agent stopped between the access row and the `Trip` row (or that row
/// could not be written), and the K5 response to the access did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrecordedTrip {
    pub canary_id: String,
    pub name: String,
    /// The trip's access row: the latest first-trip row of the canary's
    /// arming no registry row names.
    pub access: CanaryAccessEntry,
    /// Its position in the access log ([`FirstTripRow::row`]).
    pub access_row: u64,
    /// How many first-trip rows of that arming no registry row names: 1,
    /// unless an agent before lab PR 260, re-arming the canary at a start,
    /// stopped at the same point again.
    pub first_trip_rows: usize,
}

// ── registry ────────────────────────────────────────────────────────

/// Append-only writer + in-memory live-set for the canary
/// registry. Holds the [`AgentSigningKey`] in memory + tracks
/// the chain tail-hash so each `deploy`/`burn`/`refresh`
/// produces a well-chained next row. Live-set is a BTreeMap
/// keyed by `canary_id` for deterministic `list()` iteration.
///
/// Same shape as [`AuditLog`](nn_evidence::audit::AuditLog) +
/// the agent's `fim::baseline::BaselineDb`.
pub struct Registry {
    path: PathBuf,
    key: AgentSigningKey,
    agent_id: [u8; 16],
    last_hash: String,
    live: BTreeMap<String, CanaryLiveState>,
    /// Lab PR 260: each canary id's armings, as its genuine rows say.
    history: BTreeMap<String, ArmHistory>,
    tail_repair: Option<crate::chainlog::TailRepair>,
    skipped_lines: usize,
    /// External audit NN-AUD-174: rows in the file (the next `seq`) and
    /// what the open's verification found.
    rows: u64,
    chain_findings: Vec<crate::chain_anchor::ChainFinding>,
}

/// Lab PR 260, `debug-trigger` builds only: the file, next to the
/// registry, that stops the agent at the detector's next trip mark
/// ([`Registry::debug_stop_before_trip_mark`]).
#[cfg(feature = "debug-trigger")]
pub const DEBUG_STOP_BEFORE_TRIP_MARK: &str = "debug-canary-stop-before-trip";

impl Registry {
    /// Open `path` for append, walk any existing entries to
    /// recover `last_hash` + the in-memory live-set. Missing
    /// file → empty registry (`last_hash = GENESIS_PREV_HASH`,
    /// empty `live` map). K7 deploy bootstrap is responsible
    /// for ensuring the parent directory exists with the right
    /// mode; this `open` doesn't create the parent.
    pub fn open(path: &Path, key: AgentSigningKey, agent_id: [u8; 16]) -> Result<Self> {
        // External audit DEC-006: one bad line switched deception off for
        // good. A torn last write is repaired; a line that cannot be read
        // anywhere else is skipped and reported (`skipped_lines`), and the
        // canaries that can be read stay deployed and watched.
        let tail_repair = crate::chainlog::repair_torn_tail(path, |l| {
            serde_json::from_slice::<CanaryToken>(l).is_ok()
        })?;
        // External audit NN-AUD-174: every row is verified at open.
        let read = read_chain(path, &key.verifying_key())?;
        Ok(Self {
            // review 44: appends go through a directory fd taken now
            path: crate::anchored::anchor(path),
            key,
            agent_id,
            last_hash: read.last_hash,
            live: read.live,
            history: read.history,
            tail_repair,
            skipped_lines: read.skipped,
            rows: read.seq.rows(),
            chain_findings: read.findings,
        })
    }

    /// Lab PR 260: the trips the access log at `access_log` holds for this
    /// registry's armed canaries and the registry does not record — the
    /// agent stopped between an access row and the `Trip` row naming it,
    /// or that row could not be written. Read at open, before the detector
    /// runs; the caller records each ([`Registry::mark_tripped`] with the
    /// access row's hash) after attesting it. Only the genuine first-trip
    /// rows of the armed canaries count
    /// ([`crate::canary::access_log::first_trip_rows`]): a row this key did
    /// not sign, or one moved, trips nothing. No armed canary: the log is
    /// not read.
    pub fn unrecorded_trips(&self, access_log: &Path) -> Result<Vec<UnrecordedTrip>> {
        let armed: Vec<(&CanaryLiveState, &ArmHistory)> = self
            .live
            .values()
            .filter(|s| !s.tripped)
            .filter_map(|s| self.history.get(&s.canary_id).map(|h| (s, h)))
            .collect();
        if armed.is_empty() {
            return Ok(Vec::new());
        }
        let ids: BTreeSet<String> = armed.iter().map(|(s, _)| s.canary_id.clone()).collect();
        let rows = crate::canary::access_log::first_trip_rows(
            access_log,
            &self.key.verifying_key(),
            &ids,
        )?;
        Ok(armed
            .into_iter()
            .filter_map(|(state, history)| history.unrecorded(state, &rows))
            .collect())
    }

    /// Lab PR 260, `debug-trigger` builds only: when the file
    /// [`DEBUG_STOP_BEFORE_TRIP_MARK`] is next to the registry, remove it
    /// and abort — as a crash: no destructor runs, nothing more is written.
    /// The Linux host calls it before the detector's trip mark, after the
    /// access row: the privileged e2e stops the agent there and checks the
    /// next start records the trip.
    #[cfg(feature = "debug-trigger")]
    pub fn debug_stop_before_trip_mark(&self) {
        if std::fs::remove_file(self.path.with_file_name(DEBUG_STOP_BEFORE_TRIP_MARK)).is_ok() {
            tracing::warn!(
                "debug-trigger: the agent stops between the access row and the trip mark, on \
                 request (lab test of lab PR 260)"
            );
            std::process::abort();
        }
    }

    /// External audit NN-AUD-174: what the open's verification found (rows
    /// that do not verify, row numbers or links broken), for the caller to
    /// attest once.
    pub fn take_chain_findings(&mut self) -> Vec<crate::chain_anchor::ChainFinding> {
        std::mem::take(&mut self.chain_findings)
    }

    /// What the open found wrong, for the caller to attest once: the
    /// torn tail it repaired and the number of unreadable lines skipped.
    pub fn take_open_findings(&mut self) -> (Option<crate::chainlog::TailRepair>, usize) {
        (
            self.tail_repair.take(),
            std::mem::take(&mut self.skipped_lines),
        )
    }

    /// Deploy a fresh canary. Computes `canary_id` (per-canary
    /// stable ID — `SHA-256(name || deployed_at_unix ||
    /// random_salt)[..16]` rendered as 32 hex chars), allocates
    /// `deployed_at_unix = now()`, builds the signed chain row,
    /// writes it via `O_APPEND` + fsync, advances the in-memory
    /// tail. Returns the persisted [`CanaryToken`] + the
    /// freshly-allocated `canary_id` so callers (K6 admin
    /// dispatch) can surface it to the operator.
    ///
    /// Per §12 Q1 EXPLICIT-PER-HOST lock-in: this method ONLY
    /// commits the registry row; physical deployment (touching
    /// the canary file / spawning the listener / installing the
    /// binary) happens in K3/K6 callers BEFORE invoking deploy.
    /// The chain row is the audit-grade record of intent + the
    /// agent's commitment to detect.
    pub fn deploy(&mut self, draft: CanaryTokenDraft) -> Result<CanaryToken> {
        let deployed_at_unix = now_unix();
        let canary_id = compute_canary_id(&draft.name, deployed_at_unix);
        if self.live.contains_key(&canary_id) {
            // Collision is statistically impossible with the
            // 16-byte ID + ts + name input, but surface defensively
            // so a re-deploy of the SAME name-at-same-second-by-
            // accident doesn't silently double-emit.
            return Err(anyhow!(
                "canary_id collision: id={canary_id} already in live set"
            ));
        }
        let state = CanaryLiveState {
            name: draft.name,
            canary_id: canary_id.clone(),
            canary_type: draft.canary_type,
            deployment: draft.deployment,
            deployed_at_unix,
            deployed_by_fp: draft.deployed_by_fp.clone(),
            tripped: false,
            first_trip_access_hash: None,
            content: draft.content,
            decoy_state: DecoyState::Intact,
        };
        let entry = self.append(RegistryAction::Deploy, &state, &draft.deployed_by_fp, None)?;
        self.live.insert(canary_id, state);
        Ok(entry)
    }

    /// Burn (retire) a deployed canary. Looks up `canary_id` in
    /// the live set, appends a `Burn` row to the chain copying
    /// the canary's deployment fields (so the chain row is self-
    /// contained), removes from the live set. Returns the
    /// persisted Burn row.
    ///
    /// Errors with `CanaryIdNotFound` if `canary_id` isn't in
    /// the live set — re-burning an already-burned canary is
    /// rejected (the chain stays clean; operator gets a clear
    /// "no such canary" signal).
    pub fn burn(&mut self, canary_id: &str, burned_by_fp: &str) -> Result<CanaryToken> {
        let state = self
            .live
            .get(canary_id)
            .ok_or(RegistryError::CanaryIdNotFound)?
            .clone();
        let entry = self.append(RegistryAction::Burn, &state, burned_by_fp, None)?;
        self.live.remove(canary_id);
        Ok(entry)
    }

    /// Refresh (reset tripped flag on) a deployed canary.
    /// Looks up `canary_id` in the live set, appends a
    /// `Refresh` row to the chain, clears the `tripped` flag +
    /// `first_trip_access_hash` in the live set. Returns the
    /// persisted Refresh row.
    ///
    /// `content` is what the decoy was written with again (external
    /// audit DEC-008: a new seed), recorded with `decoy_state: intact`;
    /// `None` (a Process / Network canary) keeps the content recorded.
    ///
    /// Errors with `CanaryIdNotFound` if `canary_id` isn't in
    /// the live set. A refresh on a NOT-tripped canary is
    /// allowed (no-op semantically; the chain still captures
    /// operator intent — useful for explicit lifecycle markers).
    pub fn refresh(
        &mut self,
        canary_id: &str,
        refreshed_by_fp: &str,
        content: Option<DecoyContent>,
    ) -> Result<CanaryToken> {
        let mut state = self
            .live
            .get(canary_id)
            .ok_or(RegistryError::CanaryIdNotFound)?
            .clone();
        // Lab PR 260: the row names the trip it clears (its first access
        // row), the place of this refresh in the access log: a first-trip
        // row after that one is a trip of the arming this row starts. The
        // live state keeps no hash.
        if !state.tripped {
            state.first_trip_access_hash = None;
        }
        state.tripped = false;
        let rewritten = content.is_some();
        if let Some(c) = content {
            state.content = Some(c);
            state.decoy_state = DecoyState::Intact;
        }
        let decoy_state = rewritten.then_some(DecoyState::Intact);
        let entry = self.append(
            RegistryAction::Refresh,
            &state,
            refreshed_by_fp,
            decoy_state,
        )?;
        state.first_trip_access_hash = None;
        self.live.insert(canary_id.to_string(), state);
        Ok(entry)
    }

    /// `true` when `canary_id` is deployed and not tripped: its next
    /// access is the first trip.
    pub fn is_armed(&self, canary_id: &str) -> bool {
        self.live.get(canary_id).is_some_and(|s| !s.tripped)
    }

    /// Mark a canary as tripped (called by the K3 detector on its
    /// first access, after the access row is appended; lab PR 260: and by
    /// the boot for a trip [`Registry::unrecorded_trips`] found).
    /// `access_hash` is the `entry_hash` of THAT row in the
    /// `canary_access.jsonl` chain, recorded for cross-reference.
    ///
    /// External audit DEC-011: appends a signed `Trip` row, so the
    /// state survives a restart. The in-memory state is set first:
    /// if the row cannot be written, this boot still responds to the
    /// first access only, and the error is returned for the caller to
    /// report.
    ///
    /// Idempotent: on a canary already tripped (or not deployed)
    /// nothing is written and `Ok(false)` is returned — the rule
    /// engine's "subsequent accesses don't re-fire" guarantee
    /// per §12 Q2 single-trip lock-in.
    pub fn mark_tripped(&mut self, canary_id: &str, access_hash: Option<String>) -> Result<bool> {
        let state = match self.live.get_mut(canary_id) {
            Some(s) if !s.tripped => {
                s.tripped = true;
                s.first_trip_access_hash = access_hash;
                s.clone()
            }
            _ => return Ok(false),
        };
        self.append(RegistryAction::Trip, &state, AGENT_ACTOR, None)
            .context("recording the first trip in the canary registry")?;
        Ok(true)
    }

    /// External audit DEC-010: record what the boot found at a decoy,
    /// when it differs from the state last recorded (a `DecoyCheck`
    /// row). `Ok(true)` when the state changed (and was recorded),
    /// `Ok(false)` when it is the one recorded, or the canary is not
    /// deployed.
    pub fn record_decoy_state(&mut self, canary_id: &str, found: DecoyState) -> Result<bool> {
        let mut state = match self.live.get(canary_id) {
            Some(s) if s.decoy_state != found => s.clone(),
            _ => return Ok(false),
        };
        state.decoy_state = found;
        self.append(RegistryAction::DecoyCheck, &state, AGENT_ACTOR, Some(found))?;
        self.live.insert(canary_id.to_string(), state);
        Ok(true)
    }

    /// Operator-facing read API. Returns a cloned snapshot of
    /// every currently-active canary, deterministically ordered
    /// by `canary_id` (the BTreeMap key order). Burned canaries
    /// are NOT included — they stay in the chain as audit
    /// history. The CLI surfaces this via `nn-admin canary
    /// list`.
    pub fn list(&self) -> Vec<CanaryLiveState> {
        self.live.values().cloned().collect()
    }

    /// Look up a single canary's live state. `None` if the
    /// canary_id isn't in the live set (never deployed OR
    /// already burned).
    pub fn get(&self, canary_id: &str) -> Option<CanaryLiveState> {
        self.live.get(canary_id).cloned()
    }

    /// Count of currently-active (non-burned) canaries.
    /// `nn-admin canary list` summary line + future K6 status
    /// snapshot use this.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// True when zero canaries are deployed.
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Tail hash an auditor would chain the NEXT row off.
    /// Test helper + future cross-chain reference primitive.
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Build, sign and append the row of `action` for `state`, and
    /// advance the tail. The live set is the caller's to update.
    fn append(
        &mut self,
        action: RegistryAction,
        state: &CanaryLiveState,
        actor_fp: &str,
        decoy_state: Option<DecoyState>,
    ) -> Result<CanaryToken> {
        let entry = build_signed_entry(
            action,
            state,
            actor_fp,
            decoy_state,
            &self.key,
            &self.agent_id,
            &self.last_hash,
            self.rows,
        )?;
        self.append_row(&entry)?;
        self.last_hash = entry.entry_hash.clone();
        self.history
            .entry(entry.canary_id.clone())
            .or_default()
            .note(&entry);
        Ok(entry)
    }

    /// Internal: append one signed row to the JSONL log via
    /// `O_APPEND` + fsync. The in-memory tail advance + live-
    /// set mutation happen in the caller after this returns
    /// `Ok(())`.
    fn append_row(&mut self, entry: &CanaryToken) -> Result<()> {
        let mut line =
            serde_json::to_string(entry).map_err(|e| anyhow!("serialising canary entry: {e}"))?;
        line.push('\n');
        crate::canary::chain_lines::check_row_len(&line)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(REGISTRY_FILE_MODE)
            .open(&self.path)
            .with_context(|| {
                format!(
                    "opening canary registry log {} for append",
                    self.path.display()
                )
            })?;
        f.write_all(line.as_bytes())
            .with_context(|| format!("appending canary entry to {}", self.path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", self.path.display()))?;
        self.rows += 1;
        Ok(())
    }
}

/// Typed error variants for [`Registry::burn`] / `refresh`.
/// Surfaced distinctly (not `anyhow::Error`) so the K6 admin
/// dispatch can map each variant to the right `AdminResult`
/// without string-matching.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("canary_id not found in live set (never deployed or already burned)")]
    CanaryIdNotFound,
}

// ── chain helpers ───────────────────────────────────────────────────

/// What [`read_chain`] recovers.
struct ChainRead {
    last_hash: String,
    live: BTreeMap<String, CanaryLiveState>,
    history: BTreeMap<String, ArmHistory>,
    skipped: usize,
    seq: crate::chain_anchor::RowSeq,
    findings: Vec<crate::chain_anchor::ChainFinding>,
}

/// Walk the existing chain to (a) find the tail hash and
/// (b) reconstruct the in-memory live-set. Each Deploy row
/// inserts; each Burn row removes; each Refresh row clears
/// the tripped flag for the matching canary_id (and records the
/// decoy written again); each Trip row sets it; each DecoyCheck
/// row records what the boot found at the decoy. Missing file
/// → empty (genesis tail + empty live set). A line that cannot
/// be read — it does not parse, is not UTF-8 or is over
/// [`crate::canary::chain_lines::MAX_CHAIN_LINE_BYTES`] — is
/// skipped and counted (external audit DEC-006, DEC-012); only
/// a file that cannot be read at all fails the open.
///
/// External audit NN-AUD-174: every row is verified against `pubkey`
/// (the registry is small). A row that does not verify is not applied —
/// an unsigned `Burn` no longer removes a canary, which stays armed — and
/// the chain is not continued from it; broken row numbers or links are
/// reported. Unlike the FIM baseline, nothing before a bad row is dropped.
///
/// Lab PR 260: and (c) each canary id's armings, from the rows applied
/// ([`ArmHistory`]), for [`Registry::unrecorded_trips`].
fn read_chain(path: &Path, pubkey: &VerifyingKey) -> Result<ChainRead> {
    let mut seq = crate::chain_anchor::RowSeq::default();
    let f = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ChainRead {
                last_hash: GENESIS_PREV_HASH.to_string(),
                live: BTreeMap::new(),
                history: BTreeMap::new(),
                skipped: 0,
                seq,
                findings: Vec::new(),
            });
        }
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
    };
    // External audit DEC-012 (lab PR 178): a line over the cap or not
    // UTF-8 is skipped and counted like one that does not parse — it used
    // to fail the open, and the boot ran without deception.
    let mut reader = crate::canary::chain_lines::ChainLines::new(BufReader::new(f));
    let mut last: Option<String> = None;
    let mut live: BTreeMap<String, CanaryLiveState> = BTreeMap::new();
    let mut history: BTreeMap<String, ArmHistory> = BTreeMap::new();
    let mut skipped = 0usize;
    let mut unverified = 0usize;
    let mut breaks: Vec<String> = Vec::new();
    while let Some(line) = reader
        .next_line()
        .with_context(|| format!("reading line from {}", path.display()))?
    {
        let parsed = match line {
            crate::canary::chain_lines::ChainLine::Text(l) => {
                serde_json::from_str::<CanaryToken>(l).ok().map(|e| {
                    let canonical = crate::chain_anchor::is_canonical(&e, l.as_bytes());
                    (e, canonical)
                })
            }
            crate::canary::chain_lines::ChainLine::Unreadable => None,
        };
        let Some((entry, canonical)) = parsed else {
            skipped += 1;
            seq.skip();
            continue;
        };
        let row = seq.rows();
        if let Err(b) = seq.push(entry.seq) {
            breaks.push(b.to_string());
        }
        // External audit EVD-007 (lab PR 204): a numbered row whose bytes are
        // not its canonical serialisation is not applied, like one that does
        // not verify.
        if verify_row(&entry, pubkey).is_err() || (entry.seq.is_some() && !canonical) {
            unverified += 1;
            continue;
        }
        let expected = last.as_deref().unwrap_or(GENESIS_PREV_HASH);
        if entry.prev_hash != expected {
            breaks.push(format!(
                "row {row} does not chain from the genuine row before it: rows were removed"
            ));
        }
        let content = entry
            .contents_sha256
            .clone()
            .map(|contents_sha256| DecoyContent {
                contents_sha256,
                content_seed: entry.content_seed.clone(),
            });
        match entry.action {
            RegistryAction::Deploy => {
                live.insert(
                    entry.canary_id.clone(),
                    CanaryLiveState {
                        name: entry.name.clone(),
                        canary_id: entry.canary_id.clone(),
                        canary_type: entry.canary_type,
                        deployment: entry.deployment.clone(),
                        deployed_at_unix: entry.deployed_at_unix,
                        deployed_by_fp: entry.deployed_by_fp.clone(),
                        tripped: entry.tripped,
                        first_trip_access_hash: entry.first_trip_access_hash.clone(),
                        content,
                        decoy_state: DecoyState::Intact,
                    },
                );
            }
            RegistryAction::Burn => {
                live.remove(&entry.canary_id);
            }
            RegistryAction::Refresh => {
                if let Some(s) = live.get_mut(&entry.canary_id) {
                    s.tripped = false;
                    s.first_trip_access_hash = None;
                    if content.is_some() {
                        s.content = content;
                    }
                    if let Some(d) = entry.decoy_state {
                        s.decoy_state = d;
                    }
                }
            }
            // External audit DEC-011: a trip survives the restart.
            RegistryAction::Trip => {
                if let Some(s) = live.get_mut(&entry.canary_id) {
                    s.tripped = true;
                    s.first_trip_access_hash = entry.first_trip_access_hash.clone();
                }
            }
            RegistryAction::DecoyCheck => {
                if let (Some(s), Some(d)) = (live.get_mut(&entry.canary_id), entry.decoy_state) {
                    s.decoy_state = d;
                }
            }
        }
        // Lab PR 260: what the row says of the canary's armings.
        history
            .entry(entry.canary_id.clone())
            .or_default()
            .note(&entry);
        last = Some(entry.entry_hash);
    }
    let mut findings = Vec::new();
    if unverified > 0 {
        findings.push(crate::chain_anchor::ChainFinding::new(
            "canary_registry",
            path,
            "chain_lines_unverified",
            format!(
                "{unverified} row(s) fail hash or signature verification: not applied (a canary \
                 they would retire stays armed)"
            ),
        ));
    }
    if let Some(first) = breaks.first() {
        findings.push(crate::chain_anchor::ChainFinding::new(
            "canary_registry",
            path,
            "chain_sequence_broken",
            format!("{first} ({} break(s) in all)", breaks.len()),
        ));
    }
    Ok(ChainRead {
        last_hash: last.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()),
        live,
        history,
        skipped,
        seq,
        findings,
    })
}

/// The actor of the rows the agent writes on its own (Trip, DecoyCheck),
/// as in the audit log.
pub const AGENT_ACTOR: &str = "agent-self";

/// Lab PR 260: the audit op of a trip the boot found in the access log and
/// the registry did not record ([`Registry::unrecorded_trips`]).
pub const TRIP_RECOVERED_OP: &str = "canary_trip_recovered";

/// Pure helper: compute `entry_hash` + signature for a chain
/// row against a given `prev_hash` and signing key. Every row
/// carries the canary's current state (chain rows are
/// self-contained). Symmetric to
/// `crate::fim::baseline::build_signed_entry`.
#[allow(clippy::too_many_arguments)]
fn build_signed_entry(
    action: RegistryAction,
    state: &CanaryLiveState,
    actor_fp: &str,
    decoy_state: Option<DecoyState>,
    key: &AgentSigningKey,
    agent_id: &[u8; 16],
    prev_hash: &str,
    seq: u64,
) -> Result<CanaryToken> {
    let ts = format_ts(Utc::now());
    let mut entry = CanaryToken {
        ts,
        action,
        canary_id: state.canary_id.clone(),
        name: state.name.clone(),
        canary_type: state.canary_type,
        deployment: state.deployment.clone(),
        deployed_at_unix: state.deployed_at_unix,
        deployed_by_fp: actor_fp.to_string(),
        tripped: state.tripped,
        first_trip_access_hash: state.first_trip_access_hash.clone(),
        contents_sha256: state.content.as_ref().map(|c| c.contents_sha256.clone()),
        content_seed: state.content.as_ref().and_then(|c| c.content_seed.clone()),
        decoy_state,
        agent_id: hex::encode(agent_id),
        seq: Some(seq),
        prev_hash: prev_hash.to_string(),
        // Filled below — empty here so the pre-image
        // serialisation excludes them.
        entry_hash: String::new(),
        agent_sig: String::new(),
    };
    let entry_hash = compute_entry_hash(&entry)?;
    entry.entry_hash = hex::encode(entry_hash);
    let sig = key.sign(&entry_hash);
    entry.agent_sig = B64.encode(sig.to_bytes());
    Ok(entry)
}

/// Compute `entry_hash` over the canonical pre-image:
/// `SHA-256(prev_hash_bytes || canonical_json(entry minus
/// entry_hash + agent_sig))`. Both `entry_hash` and `agent_sig`
/// MUST be empty strings at call time so the JSON pre-image
/// stays free of those fields' eventual contents — verifiers
/// reproduce the same bytes by clearing those fields before
/// recomputing.
///
/// External audit NN-AUD-174: a numbered row (`seq` set) prefixes the
/// pre-image with [`crate::chain_anchor::CANARY_REGISTRY_DOMAIN_V2`].
///
/// External audit EVD-023 (NN-AUD-427, lab PR 204): a row that still
/// carries `entry_hash` or `agent_sig` is an error in every build.
fn compute_entry_hash(entry: &CanaryToken) -> Result<[u8; 32]> {
    crate::chain_anchor::check_unsealed(&entry.entry_hash, &entry.agent_sig)?;
    let body =
        serde_json::to_vec(entry).map_err(|e| anyhow!("serialising canary pre-image: {e}"))?;
    let domain = entry
        .seq
        .map(|_| crate::chain_anchor::CANARY_REGISTRY_DOMAIN_V2);
    crate::chain_anchor::flat_digest(domain, &entry.prev_hash, &body)
}

/// External audit NN-AUD-174: one row's own hash and signature.
fn verify_row(entry: &CanaryToken, pubkey: &VerifyingKey) -> Result<(), RegistryVerifyError> {
    let idx = 0;
    let mut stripped = entry.clone();
    stripped.entry_hash.clear();
    stripped.agent_sig.clear();
    let recomputed =
        compute_entry_hash(&stripped).map_err(|e| RegistryVerifyError::MalformedField {
            idx,
            reason: e.to_string(),
        })?;
    if hex::encode(recomputed) != entry.entry_hash {
        return Err(RegistryVerifyError::EntryHashMismatch {
            idx,
            recomputed: hex::encode(recomputed),
            stored: entry.entry_hash.clone(),
        });
    }
    let sig = B64
        .decode(&entry.agent_sig)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        .ok_or(RegistryVerifyError::SignatureInvalid { idx })?;
    // External audit NN-AUD-292 (FIMP-013): strict.
    pubkey
        .verify_strict(&recomputed, &Signature::from_bytes(&sig))
        .map_err(|_| RegistryVerifyError::SignatureInvalid { idx })
}

/// External audit NN-AUD-174: whether one raw line is a genuine registry
/// row. External audit EVD-007 (lab PR 204): a numbered row must also be in
/// its canonical bytes.
pub fn row_is_genuine(line: &[u8], pubkey: &VerifyingKey) -> bool {
    serde_json::from_slice::<CanaryToken>(line).is_ok_and(|e| {
        verify_row(&e, pubkey).is_ok()
            && (e.seq.is_none() || crate::chain_anchor::is_canonical(&e, line))
    })
}

/// Per-canary stable ID — `SHA-256(name || ":" ||
/// deployed_at_unix)[..16]` rendered as 32 hex chars. The
/// ":" delimiter prevents the trivial collision where
/// `name="a"` at ts `12` would collide with `name="a:1"` at
/// ts `2` (both serialise to the same byte stream without
/// the delimiter). 16 bytes (128 bits of entropy from the
/// SHA prefix) is more than enough for the operator-scale
/// canary deployment shape (~10-50 per host).
fn compute_canary_id(name: &str, deployed_at_unix: u64) -> String {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b":");
    h.update(deployed_at_unix.to_le_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16])
}

fn format_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── decoy check (external audit DEC-010) ───────────────────────────

/// A decoy larger than this is not read: it is not what a deploy writes.
pub const MAX_DECOY_BYTES: u64 = 1 << 20;

/// What [`check_decoy`] found at a decoy's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyCheck {
    pub state: DecoyState,
    /// SHA-256 (hex) of the regular file read, when it was read.
    pub found_sha256: Option<String>,
    /// The kernel `(dev, ino)` of the regular file checked: the inode to
    /// watch. `None` unless the path holds a regular file.
    pub key: Option<InodeKey>,
}

/// External audit DEC-010: compare the file at a File / Credential
/// canary's `path` with the SHA-256 its row records (`None` for a row
/// written before content hashes: a regular file then counts as intact).
///
/// The path is examined without following a link and without opening
/// anything but a regular file (a FIFO would block, a device could act on
/// the open); the file is opened `O_NOFOLLOW|O_NONBLOCK` and must be the
/// inode examined. The agent's own read is not reported by the FIM (its
/// PID is exempt). Before this, the boot re-armed whatever was at the
/// path: a decoy emptied or replaced while the agent was down was adopted
/// in silence.
pub fn check_decoy(path: &Path, expected_sha256: Option<&str>) -> DecoyCheck {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let found = |state, found_sha256, key| DecoyCheck {
        state,
        found_sha256,
        key,
    };
    let lmeta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return found(DecoyState::Missing, None, None)
        }
        Err(_) => return found(DecoyState::Unreadable, None, None),
    };
    if !lmeta.file_type().is_file() {
        return found(DecoyState::NotRegular, None, None);
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return found(DecoyState::Missing, None, None)
        }
        Err(_) => return found(DecoyState::Unreadable, None, None),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_) => return found(DecoyState::Unreadable, None, None),
    };
    if !meta.is_file() || meta.ino() != lmeta.ino() || meta.dev() != lmeta.dev() {
        // replaced between the two looks
        return found(DecoyState::NotRegular, None, None);
    }
    let key = Some(InodeKey {
        dev: crate::fim::attach::stat_dev_to_kernel_dev(meta.dev()),
        ino: meta.ino(),
    });
    if meta.len() > MAX_DECOY_BYTES {
        return found(DecoyState::Modified, None, key);
    }
    let mut body = Vec::with_capacity(meta.len() as usize);
    if file
        .take(MAX_DECOY_BYTES + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return found(DecoyState::Unreadable, None, key);
    }
    let sha = hex::encode(Sha256::digest(&body));
    let state = match expected_sha256 {
        Some(want) if want != sha => DecoyState::Modified,
        _ => DecoyState::Intact,
    };
    found(state, Some(sha), key)
}

// ── off-host verifier ───────────────────────────────────────────────

/// Outcome of one [`verify_chain`] run on a tampered chain.
/// Carrying the 0-based index lets the operator pinpoint the
/// first broken entry without re-running the verifier.
/// Symmetric to the agent's `fim::baseline::BaselineVerifyError`
/// and [`crate::audit::AuditVerifyError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryVerifyError {
    #[error("entry {idx}: prev_hash {got} does not match expected {expected}")]
    PrevHashMismatch {
        idx: usize,
        got: String,
        expected: String,
    },
    #[error("entry {idx}: entry_hash mismatch (recomputed {recomputed}, stored {stored})")]
    EntryHashMismatch {
        idx: usize,
        recomputed: String,
        stored: String,
    },
    #[error("entry {idx}: agent_sig invalid")]
    SignatureInvalid { idx: usize },
    #[error("entry {idx}: malformed field — {reason}")]
    MalformedField { idx: usize, reason: String },
    /// External audit NN-AUD-174: a numbered row out of place.
    #[error("entry {idx}: {reason}")]
    Sequence {
        idx: usize,
        reason: crate::chain_anchor::SeqBreak,
    },
}

/// Replay `entries` in order, recomputing each `entry_hash`
/// and checking each `agent_sig` against `pubkey`. Returns
/// `Ok(())` on a fully-intact chain. External audit NN-AUD-174: this is
/// the full off-host check (`nn-admin chain verify --log
/// canary-registry`); [`Registry::open`] verifies each row on its own
/// (hash, signature, link, number) and reports instead of refusing.
/// Rows without `seq` verify as before; from the first numbered row on,
/// each must carry its position.
pub fn verify_chain(
    entries: &[CanaryToken],
    pubkey: &VerifyingKey,
) -> Result<(), RegistryVerifyError> {
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    let mut seq = crate::chain_anchor::RowSeq::default();
    for (idx, entry) in entries.iter().enumerate() {
        seq.push(entry.seq)
            .map_err(|reason| RegistryVerifyError::Sequence { idx, reason })?;
        if entry.prev_hash != expected_prev {
            return Err(RegistryVerifyError::PrevHashMismatch {
                idx,
                got: entry.prev_hash.clone(),
                expected: expected_prev,
            });
        }
        // Recompute against a stripped copy (entry_hash +
        // agent_sig cleared), matching the pre-image
        // build_signed_entry hashed.
        let mut stripped = entry.clone();
        stripped.entry_hash.clear();
        stripped.agent_sig.clear();
        let recomputed =
            compute_entry_hash(&stripped).map_err(|e| RegistryVerifyError::MalformedField {
                idx,
                reason: e.to_string(),
            })?;
        let recomputed_hex = hex::encode(recomputed);
        if recomputed_hex != entry.entry_hash {
            return Err(RegistryVerifyError::EntryHashMismatch {
                idx,
                recomputed: recomputed_hex,
                stored: entry.entry_hash.clone(),
            });
        }
        let sig_bytes =
            B64.decode(&entry.agent_sig)
                .map_err(|e| RegistryVerifyError::MalformedField {
                    idx,
                    reason: format!("agent_sig base64 decode: {e}"),
                })?;
        if sig_bytes.len() != 64 {
            return Err(RegistryVerifyError::MalformedField {
                idx,
                reason: format!("agent_sig length {} (expected 64)", sig_bytes.len()),
            });
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);
        if pubkey.verify_strict(&recomputed, &sig).is_err() {
            return Err(RegistryVerifyError::SignatureInvalid { idx });
        }
        expected_prev = entry.entry_hash.clone();
    }
    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Per-test signing key — bootstrap via the same
    /// `AgentSigningKey::load_or_bootstrap` path the production
    /// agent uses, so the test exercises the full key-load
    /// shape (not a synthetic in-memory key).
    fn fresh_signing_key(dir: &TempDir) -> (AgentSigningKey, VerifyingKey) {
        let key_path = dir.path().join("agent.sig.key");
        let k = AgentSigningKey::load_or_bootstrap(&key_path).unwrap();
        let vk = k.verifying_key();
        (k, vk)
    }

    fn sample_draft(seq: u32) -> CanaryTokenDraft {
        CanaryTokenDraft {
            name: format!("test_canary_{seq}"),
            canary_type: CanaryTypeWire::File,
            deployment: CanaryDeploymentWire::File {
                path: format!("/tmp/decoy_{seq}.txt"),
                template: None,
            },
            deployed_by_fp: format!("{seq:08x}"),
            content: None,
        }
    }

    /// External audit NN-AUD-292 (FIMP-013): the registry's rows pass the
    /// strict check with the agent's key (whole chain and one row at a
    /// time); rows carrying a small-order signature, under a small-order
    /// key, passed the lax one and are refused now.
    #[test]
    fn registry_chain_is_verified_strictly() {
        use crate::chain_anchor::small_order;
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canaries.jsonl");
        let (key, pubkey) = fresh_signing_key(&dir);
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        for i in 1..=8 {
            reg.deploy(sample_draft(i)).unwrap();
        }
        let parse = |text: &str| -> Vec<CanaryToken> {
            text.lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };
        let text = std::fs::read_to_string(&log_path).unwrap();
        verify_chain(&parse(&text), &pubkey).expect("strict accepts the agent's rows");
        assert!(text.lines().all(|l| row_is_genuine(l.as_bytes(), &pubkey)));
        let forged_text = small_order::forge(&text);
        let forged = parse(&forged_text);
        small_order::assert_premise(&hex::decode(&forged[0].entry_hash).unwrap());
        assert!(matches!(
            verify_chain(&forged, &small_order::key()),
            Err(RegistryVerifyError::SignatureInvalid { idx: 0 })
        ));
        let first = forged_text.lines().next().unwrap();
        assert!(!row_is_genuine(first.as_bytes(), &small_order::key()));
    }

    /// External audit DEC-006: an unreadable line no longer switches the
    /// canary subsystem off — it is skipped and reported, the readable
    /// canaries stay deployed, and a torn last write is repaired.
    #[test]
    fn an_unreadable_line_is_skipped_and_the_rest_kept() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canaries.jsonl");
        {
            let (key, _) = fresh_signing_key(&dir);
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            reg.deploy(sample_draft(1)).unwrap();
            reg.deploy(sample_draft(2)).unwrap();
        }
        let mut body = std::fs::read_to_string(&log_path).unwrap();
        body.insert_str(body.find('\n').unwrap() + 1, "garbage line\n");
        body.push_str("{\"torn\":");
        std::fs::write(&log_path, &body).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).expect("opens");
        assert_eq!(reg.list().len(), 2, "both canaries still deployed");
        let (repair, skipped) = reg.take_open_findings();
        assert!(repair.is_some(), "the torn tail was repaired");
        assert_eq!(skipped, 1);
        reg.deploy(sample_draft(3)).expect("appends continue");
    }

    /// External audit DEC-012 (lab PR 178): a complete line that is not
    /// UTF-8 failed the open — `lines()` returned `InvalidData` — and the
    /// boot ran without deception. It is skipped and counted now.
    #[test]
    fn non_utf8_line_is_skipped_not_fatal() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canaries.jsonl");
        {
            let (key, _) = fresh_signing_key(&dir);
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            reg.deploy(sample_draft(1)).unwrap();
            reg.deploy(sample_draft(2)).unwrap();
        }
        let mut body = std::fs::read(&log_path).unwrap();
        let first_nl = body.iter().position(|&b| b == b'\n').unwrap();
        body.splice(
            first_nl + 1..first_nl + 1,
            b"\xff\xfe{\"seq\":1}\n".iter().copied(),
        );
        std::fs::write(&log_path, &body).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).expect("opens");
        assert_eq!(reg.list().len(), 2, "both canaries still deployed");
        let (_, skipped) = reg.take_open_findings();
        assert_eq!(skipped, 1);
        reg.deploy(sample_draft(3)).expect("appends continue");
    }

    /// External audit DEC-012 (lab PR 178): a line over the cap is consumed
    /// without being stored, skipped and counted; the rows around it live.
    #[test]
    fn oversized_line_is_skipped_and_counted() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canaries.jsonl");
        {
            let (key, _) = fresh_signing_key(&dir);
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            reg.deploy(sample_draft(1)).unwrap();
            reg.deploy(sample_draft(2)).unwrap();
        }
        let mut body = std::fs::read_to_string(&log_path).unwrap();
        let big = format!(
            "{{\"pad\":\"{}\"}}\n",
            "x".repeat(crate::canary::chain_lines::MAX_CHAIN_LINE_BYTES)
        );
        body.insert_str(body.find('\n').unwrap() + 1, &big);
        std::fs::write(&log_path, &body).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).expect("opens");
        assert_eq!(reg.list().len(), 2, "both canaries still deployed");
        assert_eq!(reg.take_open_findings().1, 1);
        // a line put in between moves the rows after it: reported
        assert!(reg
            .take_chain_findings()
            .iter()
            .any(|f| f.kind == "chain_sequence_broken"));
    }

    /// External audit DEC-012: the writer refuses a row the reader would
    /// skip at the next boot, rather than writing it.
    #[test]
    fn a_row_over_the_line_cap_is_not_written() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let mut draft = sample_draft(1);
        draft.name = "\u{1}".repeat(crate::canary::chain_lines::MAX_CHAIN_LINE_BYTES / 6 + 1);
        assert!(reg.deploy(draft).is_err());
        assert!(reg.is_empty());
        assert!(!log_path.exists() || std::fs::metadata(&log_path).unwrap().len() == 0);
        reg.deploy(sample_draft(2))
            .expect("the next row is written");
    }

    // ── K2 test #1: deploy appends + advances tail ────────────────

    #[test]
    fn deploy_appends_signed_row_and_advances_tail() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let entry = reg.deploy(sample_draft(1)).expect("first deploy");
        assert_eq!(entry.action, RegistryAction::Deploy);
        assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(reg.last_hash(), entry.entry_hash);
        assert_eq!(reg.len(), 1);
        let raw = std::fs::read_to_string(&log_path).unwrap();
        assert!(raw.ends_with('\n'));
        assert_eq!(raw.lines().count(), 1);
        let parsed: CanaryToken = serde_json::from_str(raw.trim_end()).unwrap();
        assert_eq!(parsed, entry);
        verify_chain(&[parsed], &pubkey).expect("single-entry chain verifies");
    }

    // ── K2 test #2: burn removes from live + records audit ────────

    #[test]
    fn burn_removes_from_live_and_appends_burn_row() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let deploy = reg.deploy(sample_draft(1)).unwrap();
        assert_eq!(reg.len(), 1);
        let burn = reg.burn(&deploy.canary_id, "ffffffff").expect("burn");
        assert_eq!(burn.action, RegistryAction::Burn);
        assert_eq!(burn.canary_id, deploy.canary_id);
        assert_eq!(burn.prev_hash, deploy.entry_hash);
        assert_eq!(burn.deployed_by_fp, "ffffffff");
        assert_eq!(reg.len(), 0);
        assert!(reg.get(&deploy.canary_id).is_none());
        let raw = std::fs::read_to_string(&log_path).unwrap();
        let rows: Vec<CanaryToken> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        verify_chain(&rows, &pubkey).expect("deploy + burn chain verifies");
    }

    // ── K2 test #3: refresh clears tripped + records audit ────────

    #[test]
    fn refresh_clears_tripped_flag_and_appends_refresh_row() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let deploy = reg.deploy(sample_draft(2)).unwrap();
        assert!(reg
            .mark_tripped(&deploy.canary_id, Some("abc123".to_string()))
            .unwrap());
        let state_pre = reg.get(&deploy.canary_id).unwrap();
        assert!(state_pre.tripped);
        assert_eq!(state_pre.first_trip_access_hash.as_deref(), Some("abc123"));
        let refresh = reg.refresh(&deploy.canary_id, "11111111", None).unwrap();
        assert_eq!(refresh.action, RegistryAction::Refresh);
        assert_eq!(refresh.deployed_by_fp, "11111111");
        let state_post = reg.get(&deploy.canary_id).unwrap();
        assert!(!state_post.tripped);
        assert!(state_post.first_trip_access_hash.is_none());
        let rows: Vec<CanaryToken> = std::fs::read_to_string(&log_path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 3, "deploy, trip, refresh");
        verify_chain(&rows, &pubkey).expect("deploy + trip + refresh chain verifies");
    }

    // ── K2 test #4: mark_tripped is idempotent (§12 Q2 lock-in) ───

    #[test]
    fn mark_tripped_is_idempotent_no_refire() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let deploy = reg.deploy(sample_draft(3)).unwrap();
        assert!(reg
            .mark_tripped(&deploy.canary_id, Some("first".to_string()))
            .unwrap());
        // Second + third calls: return false (single-trip
        // semantics — no re-fire). first_trip_access_hash stays
        // the ORIGINAL value.
        assert!(!reg
            .mark_tripped(&deploy.canary_id, Some("second".to_string()))
            .unwrap());
        assert!(!reg
            .mark_tripped(&deploy.canary_id, Some("third".to_string()))
            .unwrap());
        let state = reg.get(&deploy.canary_id).unwrap();
        assert!(state.tripped);
        assert_eq!(
            state.first_trip_access_hash.as_deref(),
            Some("first"),
            "first_trip_access_hash must lock to the FIRST observed access"
        );
    }

    // ── K2 test #5: burn rejects unknown canary_id ────────────────

    #[test]
    fn burn_rejects_unknown_canary_id() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let err = reg.burn("deadbeef", "ffffffff").unwrap_err();
        let typed = err
            .downcast::<RegistryError>()
            .expect("burn must return RegistryError");
        assert_eq!(typed, RegistryError::CanaryIdNotFound);
        // Chain stays empty after the rejected burn.
        assert_eq!(reg.last_hash(), GENESIS_PREV_HASH);
        assert!(!log_path.exists() || std::fs::read_to_string(&log_path).unwrap().is_empty());
    }

    // ── K2 test #6: chain integrity — payload tamper detected ─────

    #[test]
    fn verify_chain_detects_payload_tamper() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let _ = reg.deploy(sample_draft(1)).unwrap();
        let _ = reg.deploy(sample_draft(2)).unwrap();
        let raw = std::fs::read_to_string(&log_path).unwrap();
        let mut entries: Vec<CanaryToken> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Attacker rewrites the first row's name field.
        entries[0].name = "tampered_canary".to_string();
        let err = verify_chain(&entries, &pubkey).expect_err("tampered chain must fail");
        assert!(
            matches!(err, RegistryVerifyError::EntryHashMismatch { idx: 0, .. }),
            "expected EntryHashMismatch on entry 0; got: {err:?}"
        );
    }

    // ── K2 test #7: chain integrity — signature tamper detected ───

    #[test]
    fn verify_chain_detects_signature_tamper() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let _ = reg.deploy(sample_draft(1)).unwrap();
        let raw = std::fs::read_to_string(&log_path).unwrap();
        let mut entries: Vec<CanaryToken> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Re-encode the agent_sig with a flipped bit. The
        // entry_hash recompute will still succeed (same bytes)
        // but the signature verify will reject.
        let mut sig_bytes = B64.decode(&entries[0].agent_sig).unwrap();
        sig_bytes[0] ^= 0x01;
        entries[0].agent_sig = B64.encode(&sig_bytes);
        let err = verify_chain(&entries, &pubkey).expect_err("tampered sig must fail");
        assert!(
            matches!(err, RegistryVerifyError::SignatureInvalid { idx: 0 }),
            "expected SignatureInvalid on entry 0; got: {err:?}"
        );
    }

    // ── K2 test #8: chain integrity — prev_hash break detected ────

    #[test]
    fn verify_chain_detects_prev_hash_break() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let _ = reg.deploy(sample_draft(1)).unwrap();
        let _ = reg.deploy(sample_draft(2)).unwrap();
        let _ = reg.deploy(sample_draft(3)).unwrap();
        let raw = std::fs::read_to_string(&log_path).unwrap();
        let mut entries: Vec<CanaryToken> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Attacker drops entry 1, leaving entry 2 with a
        // prev_hash that points at entry 0's tail rather than
        // entry 1's tail. Verify must reject at idx=1 — on numbered
        // rows (NN-AUD-174) the row number names the gap first.
        entries.remove(1);
        let err = verify_chain(&entries, &pubkey)
            .expect_err("dropped-entry chain must fail prev_hash check");
        assert!(
            matches!(
                err,
                RegistryVerifyError::PrevHashMismatch { idx: 1, .. }
                    | RegistryVerifyError::Sequence { idx: 1, .. }
            ),
            "expected a break on entry 1; got: {err:?}"
        );
    }

    // ── K2 test #9: open recovers tail + live-set on reopen ───────

    #[test]
    fn open_recovers_tail_hash_and_live_set_on_reopen() {
        let dir = TempDir::new().unwrap();
        let (key1, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let (id1, id2, second_tail);
        {
            let mut reg = Registry::open(&log_path, key1, [0u8; 16]).unwrap();
            let d1 = reg.deploy(sample_draft(1)).unwrap();
            let d2 = reg.deploy(sample_draft(2)).unwrap();
            id1 = d1.canary_id;
            id2 = d2.canary_id;
            second_tail = d2.entry_hash;
            // Drop reg here — simulates agent restart.
        }
        let key2 = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key"))
            .expect("reload same key");
        let reg2 = Registry::open(&log_path, key2, [0u8; 16]).unwrap();
        assert_eq!(reg2.last_hash(), second_tail);
        assert_eq!(reg2.len(), 2);
        assert!(reg2.get(&id1).is_some());
        assert!(reg2.get(&id2).is_some());
    }

    // ── K2 test #10: deploy → burn round-trip removes from reopen ─

    #[test]
    fn open_reflects_burn_in_recovered_live_set() {
        let dir = TempDir::new().unwrap();
        let (key1, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let id1 = {
            let mut reg = Registry::open(&log_path, key1, [0u8; 16]).unwrap();
            let d = reg.deploy(sample_draft(1)).unwrap();
            // Deploy a second canary that we burn.
            let d2 = reg.deploy(sample_draft(2)).unwrap();
            reg.burn(&d2.canary_id, "00000000").unwrap();
            d.canary_id
        };
        let key2 = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key"))
            .expect("reload same key");
        let reg2 = Registry::open(&log_path, key2, [0u8; 16]).unwrap();
        // After reopen: only the non-burned canary survives in
        // the live set. The chain still has 3 rows (deploy,
        // deploy, burn) — chain integrity preserved.
        assert_eq!(reg2.len(), 1);
        assert!(reg2.get(&id1).is_some());
        let chain_rows = std::fs::read_to_string(&log_path).unwrap().lines().count();
        assert_eq!(chain_rows, 3);
    }

    fn rows(path: &Path) -> Vec<CanaryToken> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn reopen(dir: &TempDir, log_path: &Path) -> Registry {
        let key = AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig.key")).unwrap();
        Registry::open(log_path, key, [0u8; 16]).unwrap()
    }

    /// External audit DEC-011: a trip is a signed row, and the canary is
    /// still tripped (with the access row's hash) after a restart — it
    /// used to come back armed, and the K5 response fired again.
    #[test]
    fn tripped_state_survives_reopen() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let id = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
            assert!(reg.is_armed(&id));
            assert!(reg.mark_tripped(&id, Some("acc0".to_string())).unwrap());
            assert!(!reg.is_armed(&id));
            id
        };
        let all = rows(&log_path);
        assert_eq!(all[1].action, RegistryAction::Trip);
        assert!(all[1].tripped);
        assert_eq!(all[1].deployed_by_fp, AGENT_ACTOR);
        verify_chain(&all, &pubkey).expect("deploy + trip verifies");
        let mut reg = reopen(&dir, &log_path);
        let state = reg.get(&id).unwrap();
        assert!(state.tripped, "still tripped after the restart");
        assert_eq!(state.first_trip_access_hash.as_deref(), Some("acc0"));
        assert!(!reg.is_armed(&id));
        assert!(!reg.mark_tripped(&id, Some("acc1".to_string())).unwrap());
        assert_eq!(rows(&log_path).len(), 2, "a later access writes no row");
    }

    /// External audit DEC-011: a refresh re-arms the canary for good.
    #[test]
    fn refresh_clears_trip_across_reopen() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let id = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
            reg.mark_tripped(&id, Some("acc0".to_string())).unwrap();
            reg.refresh(&id, "11111111", None).unwrap();
            id
        };
        let reg = reopen(&dir, &log_path);
        let state = reg.get(&id).unwrap();
        assert!(!state.tripped);
        assert!(state.first_trip_access_hash.is_none());
        assert!(reg.is_armed(&id));
    }

    /// External audit DEC-011: a chain written before Trip rows (deploys
    /// only — the trips lived in memory) opens with its canaries armed.
    #[test]
    fn legacy_chain_without_trip_rows_opens_untripped() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let id = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            reg.deploy(sample_draft(1)).unwrap().canary_id
        };
        let mut reg = reopen(&dir, &log_path);
        assert!(reg.is_armed(&id));
        assert_eq!(reg.take_open_findings().1, 0, "nothing unreadable");
    }

    /// External audit DEC-010: a File / Credential deploy row records the
    /// SHA-256 of the decoy and its seed; a row written before the fields
    /// existed re-serialises byte for byte, so it still verifies.
    #[test]
    fn deploy_row_carries_contents_sha256_and_legacy_rows_verify() {
        /// The row as agents before DEC-010 / DEC-011 wrote it.
        #[derive(Serialize)]
        struct LegacyRow<'a> {
            ts: &'a str,
            action: RegistryAction,
            canary_id: &'a str,
            name: &'a str,
            canary_type: CanaryTypeWire,
            deployment: CanaryDeploymentWire,
            deployed_at_unix: u64,
            deployed_by_fp: &'a str,
            tripped: bool,
            first_trip_access_hash: Option<String>,
            agent_id: String,
            prev_hash: &'a str,
            entry_hash: String,
            agent_sig: String,
        }
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut legacy = LegacyRow {
            ts: "2026-10-01T10:00:00.000000Z",
            action: RegistryAction::Deploy,
            canary_id: "00112233445566778899aabbccddeeff",
            name: "old",
            canary_type: CanaryTypeWire::File,
            deployment: CanaryDeploymentWire::File {
                path: "/home/u/old.txt".to_string(),
                template: None,
            },
            deployed_at_unix: 1_790_000_000,
            deployed_by_fp: "deadbeef",
            tripped: false,
            first_trip_access_hash: None,
            agent_id: hex::encode([0u8; 16]),
            prev_hash: GENESIS_PREV_HASH,
            entry_hash: String::new(),
            agent_sig: String::new(),
        };
        let mut h = Sha256::new();
        h.update(hex::decode(GENESIS_PREV_HASH).unwrap());
        h.update(serde_json::to_vec(&legacy).unwrap());
        let digest: [u8; 32] = h.finalize().into();
        legacy.entry_hash = hex::encode(digest);
        legacy.agent_sig = B64.encode(key.sign(&digest).to_bytes());
        std::fs::write(
            &log_path,
            format!("{}\n", serde_json::to_string(&legacy).unwrap()),
        )
        .unwrap();

        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        assert!(reg.get(legacy.canary_id).unwrap().content.is_none());
        let mut draft = sample_draft(2);
        draft.content = Some(DecoyContent {
            contents_sha256: "ab".repeat(32),
            content_seed: Some("cd".repeat(32)),
        });
        let row = reg.deploy(draft).unwrap();
        assert_eq!(
            row.contents_sha256.as_deref(),
            Some("ab".repeat(32).as_str())
        );
        assert_eq!(row.content_seed.as_deref(), Some("cd".repeat(32).as_str()));
        let all = rows(&log_path);
        let raw = std::fs::read_to_string(&log_path).unwrap();
        let first_line = raw.lines().next().unwrap();
        assert!(!first_line.contains("contents_sha256"));
        assert_eq!(serde_json::to_string(&all[0]).unwrap(), first_line);
        verify_chain(&all, &pubkey).expect("a legacy row and a new one verify");
        // a burn carries the content too (rows are self-contained)
        let burn = reg.burn(&row.canary_id, "ffffffff").unwrap();
        assert_eq!(burn.contents_sha256, row.contents_sha256);
        let reg = reopen(&dir, &log_path);
        assert!(reg.get(&row.canary_id).is_none());
    }

    /// External audit DEC-010: what the boot reports at a decoy's path.
    #[test]
    fn decoy_check_reports_modified_missing_not_regular() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("decoy.txt");
        std::fs::write(&p, b"abc").unwrap();
        let sha = hex::encode(Sha256::digest(b"abc"));
        let c = check_decoy(&p, Some(&sha));
        assert_eq!(c.state, DecoyState::Intact);
        assert_eq!(c.found_sha256.as_deref(), Some(sha.as_str()));
        use std::os::unix::fs::MetadataExt;
        assert_eq!(c.key.unwrap().ino, std::fs::metadata(&p).unwrap().ino());
        // a row written before content hashes: present is all it can say
        assert_eq!(check_decoy(&p, None).state, DecoyState::Intact);

        std::fs::write(&p, b"").unwrap();
        let c = check_decoy(&p, Some(&sha));
        assert_eq!(c.state, DecoyState::Modified, "emptied");
        assert!(c.key.is_some(), "a modified regular file is still watched");

        std::fs::remove_file(&p).unwrap();
        assert_eq!(check_decoy(&p, Some(&sha)).state, DecoyState::Missing);

        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"abc").unwrap();
        std::os::unix::fs::symlink(&target, &p).unwrap();
        let c = check_decoy(&p, Some(&sha));
        assert_eq!(c.state, DecoyState::NotRegular, "a link to the same bytes");
        assert!(c.key.is_none());
        std::fs::remove_file(&p).unwrap();

        let fifo = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: mkfifo on a NUL-terminated path in our temp dir.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(check_decoy(&p, Some(&sha)).state, DecoyState::NotRegular);
        std::fs::remove_file(&p).unwrap();

        std::fs::create_dir(&p).unwrap();
        assert_eq!(check_decoy(&p, Some(&sha)).state, DecoyState::NotRegular);
        std::fs::remove_dir(&p).unwrap();

        std::fs::write(&p, vec![b'x'; (MAX_DECOY_BYTES + 1) as usize]).unwrap();
        let c = check_decoy(&p, Some(&sha));
        assert_eq!(c.state, DecoyState::Modified, "too large to be the decoy");
        assert!(c.found_sha256.is_none(), "not read");
    }

    /// External audit DEC-010: a decoy state is a row when it changes, not
    /// at every boot, and `canary list` (the chain) shows it.
    #[test]
    fn a_decoy_state_is_recorded_once_per_change() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let id = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
            assert!(!reg.record_decoy_state(&id, DecoyState::Intact).unwrap());
            assert!(reg.record_decoy_state(&id, DecoyState::Modified).unwrap());
            id
        };
        let mut reg = reopen(&dir, &log_path);
        assert_eq!(reg.get(&id).unwrap().decoy_state, DecoyState::Modified);
        assert!(!reg.record_decoy_state(&id, DecoyState::Modified).unwrap());
        // a refresh writes the decoy again
        reg.refresh(
            &id,
            "11111111",
            Some(DecoyContent {
                contents_sha256: "ef".repeat(32),
                content_seed: None,
            }),
        )
        .unwrap();
        assert_eq!(reg.get(&id).unwrap().decoy_state, DecoyState::Intact);
        let all = rows(&log_path);
        let actions: Vec<_> = all.iter().map(|r| r.action).collect();
        assert_eq!(
            actions,
            [
                RegistryAction::Deploy,
                RegistryAction::DecoyCheck,
                RegistryAction::Refresh
            ]
        );
        assert_eq!(all[1].decoy_state, Some(DecoyState::Modified));
        assert!(serde_json::to_string(&all[1])
            .unwrap()
            .contains("\"decoy_state\":\"modified\""));
        assert_eq!(all[2].decoy_state, Some(DecoyState::Intact));
        verify_chain(&all, &pubkey).unwrap();
        let reg = reopen(&dir, &log_path);
        let state = reg.get(&id).unwrap();
        assert_eq!(state.decoy_state, DecoyState::Intact);
        assert_eq!(state.content.unwrap().contents_sha256, "ef".repeat(32));
    }

    // ── External audit NN-AUD-174 (lab PR 160) ──────────────────────

    /// Before lab PR 160 `read_chain` applied any row that parsed: an
    /// unsigned `Burn` written into the file (no key needed) retired a
    /// canary silently at the next start. Now the row does not verify, is
    /// not applied, and is reported.
    #[test]
    fn registry_open_ignores_an_unsigned_burn_row() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canaries.jsonl");
        let deployed = {
            let (key, _) = fresh_signing_key(&dir);
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            reg.deploy(sample_draft(1)).unwrap()
        };
        let mut burn = deployed.clone();
        burn.action = RegistryAction::Burn;
        burn.seq = Some(1);
        burn.prev_hash = deployed.entry_hash.clone();
        burn.entry_hash = "ab".repeat(32);
        burn.agent_sig = B64.encode([7u8; 64]);
        let mut body = std::fs::read_to_string(&log_path).unwrap();
        body.push_str(&serde_json::to_string(&burn).unwrap());
        body.push('\n');
        std::fs::write(&log_path, body).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        assert_eq!(reg.list().len(), 1, "the canary stays armed");
        let found = reg.take_chain_findings();
        assert!(
            found.iter().any(|f| f.kind == "chain_lines_unverified"),
            "{found:?}"
        );
        // the chain continues from the last genuine row
        assert_eq!(reg.last_hash(), deployed.entry_hash);
        let next = reg.refresh(&deployed.canary_id, "00000000", None).unwrap();
        assert_eq!(next.seq, Some(2), "positions count the forged row");
    }

    /// Rows written before lab PR 160 (no `seq`, untagged pre-image) open
    /// and verify as before; numbering starts at their count.
    #[test]
    fn legacy_registry_rows_verify_and_numbering_starts_after_them() {
        let dir = TempDir::new().unwrap();
        let (key, pk) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut prev = GENESIS_PREV_HASH.to_string();
        let mut body = String::new();
        for i in 0..2 {
            let d = sample_draft(i);
            let state = CanaryLiveState {
                name: d.name.clone(),
                canary_id: compute_canary_id(&d.name, 1),
                canary_type: d.canary_type,
                deployment: d.deployment.clone(),
                deployed_at_unix: 1,
                deployed_by_fp: d.deployed_by_fp.clone(),
                tripped: false,
                first_trip_access_hash: None,
                content: None,
                decoy_state: DecoyState::Intact,
            };
            let mut e = build_signed_entry(
                RegistryAction::Deploy,
                &state,
                &d.deployed_by_fp,
                None,
                &key,
                &[0u8; 16],
                &prev,
                0,
            )
            .unwrap();
            e.seq = None;
            e.entry_hash.clear();
            e.agent_sig.clear();
            let h = compute_entry_hash(&e).unwrap();
            e.entry_hash = hex::encode(h);
            e.agent_sig = B64.encode(key.sign(&h).to_bytes());
            body.push_str(&serde_json::to_string(&e).unwrap());
            body.push('\n');
            prev = e.entry_hash;
        }
        std::fs::write(&log_path, &body).unwrap();
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        assert!(reg.take_chain_findings().is_empty());
        assert_eq!(reg.len(), 2);
        let row = reg.deploy(sample_draft(5)).unwrap();
        assert_eq!(row.seq, Some(2));
        let rows: Vec<CanaryToken> = std::fs::read_to_string(&log_path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        verify_chain(&rows, &pk).expect("old rows then numbered rows verify");
    }

    /// External audit NN-AUD-174: the same key signs every chain; a numbered
    /// registry row whose hash was made for the access-log domain (or
    /// untagged) is refused here.
    #[test]
    fn a_registry_row_signed_for_another_domain_is_rejected() {
        let dir = TempDir::new().unwrap();
        let (key, pk) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let good = reg.deploy(sample_draft(1)).unwrap();
        verify_chain(std::slice::from_ref(&good), &pk).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        for domain in [None, Some(crate::chain_anchor::CANARY_ACCESS_DOMAIN_V2)] {
            let mut e = good.clone();
            e.entry_hash.clear();
            e.agent_sig.clear();
            let body = serde_json::to_vec(&e).unwrap();
            let h = crate::chain_anchor::flat_digest(domain, &e.prev_hash, &body).unwrap();
            e.entry_hash = hex::encode(h);
            e.agent_sig = B64.encode(key.sign(&h).to_bytes());
            assert!(matches!(
                verify_chain(&[e.clone()], &pk),
                Err(RegistryVerifyError::EntryHashMismatch { idx: 0, .. })
            ));
            assert!(!row_is_genuine(
                serde_json::to_string(&e).unwrap().as_bytes(),
                &pk
            ));
        }
    }

    // ── External audit, Wave 3, lab PR 204 ─────────────────────────────

    /// EVD-007 (NN-AUD-273): a numbered registry row rewritten with a key
    /// the type does not have (`"burned":true` reads like a retirement)
    /// still decodes to the genuine row and verifies; its bytes are not
    /// what the agent wrote. It is not applied at open, not a head, and
    /// `chain verify` refuses it. On the starting code it verified.
    #[test]
    fn a_numbered_registry_row_not_in_canonical_form_is_not_applied() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canaries.jsonl");
        let (key, pk) = fresh_signing_key(&dir);
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        reg.deploy(sample_draft(1)).unwrap();
        let second = reg.deploy(sample_draft(2)).unwrap();
        drop(reg);
        let body = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(row_is_genuine(lines[1].as_bytes(), &pk));
        let forged = format!("{},\"burned\":true}}", lines[1].strip_suffix('}').unwrap());
        let decoded: CanaryToken = serde_json::from_str(&forged).unwrap();
        assert!(
            verify_row(&decoded, &pk).is_ok(),
            "the decoded row verifies"
        );
        assert!(!row_is_genuine(forged.as_bytes(), &pk));
        std::fs::write(&log_path, format!("{}\n{forged}\n", lines[0])).unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        assert!(reg.get(&second.canary_id).is_none(), "not applied");
        assert!(reg
            .take_chain_findings()
            .iter()
            .any(|f| f.kind == "chain_lines_unverified"));
    }

    // ── Lab PR 260: the trip the access log holds ──────────────────────

    use crate::canary::access_log::{CanaryAccessDb, CanaryAccessDraft};
    use nn_model::{CanaryAccessKind, CanaryTypeTag};

    const ACCESS_LOG: &str = "canary_access.jsonl";

    fn access_db(dir: &TempDir) -> CanaryAccessDb {
        let (key, _) = fresh_signing_key(dir);
        CanaryAccessDb::open(&dir.path().join(ACCESS_LOG), key, [0u8; 16]).unwrap()
    }

    /// An access of `canary_id` as the detector records it.
    fn access(id: &str, first_trip: bool, pid: u32) -> CanaryAccessDraft {
        CanaryAccessDraft {
            canary_id: id.to_string(),
            canary_name: "decoy".to_string(),
            canary_type: CanaryTypeTag::File,
            access_kind: CanaryAccessKind::FileOpen,
            accessor_pid: pid,
            accessor_uid: 1000,
            accessor_comm: "cat".to_string(),
            accessor_exe: Some("/usr/bin/cat".to_string()),
            first_trip,
        }
    }

    /// The boot (the agent's `record_unrecorded_trips`, without its audit
    /// row): the registry opens, then the access log (its torn tail
    /// repaired), then each trip the registry does not record is recorded.
    fn boot(dir: &TempDir) -> (Registry, Vec<UnrecordedTrip>) {
        let mut reg = reopen(dir, &dir.path().join("canaries.jsonl"));
        drop(access_db(dir));
        let found = reg.unrecorded_trips(&dir.path().join(ACCESS_LOG)).unwrap();
        for trip in &found {
            assert!(reg
                .mark_tripped(&trip.canary_id, Some(trip.access.entry_hash.clone()))
                .unwrap());
        }
        (reg, found)
    }

    fn actions(path: &Path, id: &str) -> Vec<RegistryAction> {
        rows(path)
            .into_iter()
            .filter(|r| r.canary_id == id)
            .map(|r| r.action)
            .collect()
    }

    /// The finding of lab PR 258's KVM run: the agent stopped between the
    /// access row and the `Trip` row, and the next start re-armed the
    /// canary. Now that start records the trip — a `Trip` row naming the
    /// access row — and the one after it finds nothing more to record; the
    /// chain verifies. On the starting code the canary came back armed.
    #[test]
    fn a_trip_the_registry_did_not_record_is_recorded_at_the_next_open() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let (id, trip) = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
            assert!(reg.is_armed(&id));
            let trip = access_db(&dir).append(access(&id, true, 4242)).unwrap();
            // stopped here: no `Trip` row
            (id, trip)
        };
        let (reg, found) = boot(&dir);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].canary_id, id);
        assert_eq!(found[0].name, "test_canary_1");
        assert_eq!(found[0].access, trip);
        assert_eq!((found[0].access_row, found[0].first_trip_rows), (0, 1));
        assert!(!reg.is_armed(&id), "tripped");
        assert_eq!(
            reg.get(&id).unwrap().first_trip_access_hash.as_deref(),
            Some(trip.entry_hash.as_str())
        );
        let all = rows(&log_path);
        assert_eq!(
            actions(&log_path, &id),
            [RegistryAction::Deploy, RegistryAction::Trip]
        );
        assert_eq!(all[1].first_trip_access_hash, Some(trip.entry_hash.clone()));
        assert_eq!(all[1].deployed_by_fp, AGENT_ACTOR);
        verify_chain(&all, &pubkey).unwrap();
        drop(reg);
        let (reg, found) = boot(&dir);
        assert!(found.is_empty(), "recorded once: {found:?}");
        assert!(!reg.is_armed(&id));
        assert_eq!(rows(&log_path).len(), 2);
    }

    /// A refresh names the trip it clears (the field said nothing on a
    /// `Refresh` row), the live state keeps no hash, and the canary is
    /// armed after a restart: the first-trip row it cleared is not a trip
    /// of the new arming. An agent before this lot reads the row as it
    /// always did: it clears the trip.
    #[test]
    fn a_refresh_names_the_trip_it_clears_and_rearms_for_good() {
        let dir = TempDir::new().unwrap();
        let (key, pubkey) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
        let trip = access_db(&dir).append(access(&id, true, 1)).unwrap();
        assert!(reg
            .mark_tripped(&id, Some(trip.entry_hash.clone()))
            .unwrap());
        let refresh = reg.refresh(&id, "11111111", None).unwrap();
        assert_eq!(refresh.action, RegistryAction::Refresh);
        assert!(!refresh.tripped);
        assert_eq!(
            refresh.first_trip_access_hash,
            Some(trip.entry_hash.clone())
        );
        assert_eq!(reg.get(&id).unwrap().first_trip_access_hash, None);
        assert!(reg.is_armed(&id));
        // a refresh of an armed canary names nothing
        let again = reg.refresh(&id, "11111111", None).unwrap();
        assert_eq!(again.first_trip_access_hash, None);
        drop(reg);
        verify_chain(&rows(&log_path), &pubkey).unwrap();
        let (reg, found) = boot(&dir);
        assert!(found.is_empty(), "{found:?}");
        assert!(reg.is_armed(&id));
        assert_eq!(reg.get(&id).unwrap().first_trip_access_hash, None);
    }

    /// After a refresh, the next first-trip row is a trip of the new
    /// arming: a stop before its `Trip` row is recorded at the next open,
    /// the trip the refresh cleared is not (nor a later access).
    #[test]
    fn a_trip_after_a_refresh_is_recorded_the_one_it_cleared_is_not() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let (id, second) = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
            let mut log = access_db(&dir);
            let first = log.append(access(&id, true, 1)).unwrap();
            reg.mark_tripped(&id, Some(first.entry_hash)).unwrap();
            log.append(access(&id, false, 2)).unwrap();
            reg.refresh(&id, "11111111", None).unwrap();
            // stopped after this one's access row
            let second = log.append(access(&id, true, 3)).unwrap();
            (id, second)
        };
        let (reg, found) = boot(&dir);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].access, second);
        assert_eq!(found[0].access_row, 2);
        assert!(!reg.is_armed(&id));
        assert_eq!(
            actions(&log_path, &id),
            [
                RegistryAction::Deploy,
                RegistryAction::Trip,
                RegistryAction::Refresh,
                RegistryAction::Trip
            ]
        );
        // refreshed again: armed for good
        let mut reg = reg;
        reg.refresh(&id, "11111111", None).unwrap();
        drop(reg);
        let (reg, found) = boot(&dir);
        assert!(found.is_empty(), "{found:?}");
        assert!(reg.is_armed(&id));
    }

    /// A `Trip` row that could not be written (the canary tripped for that
    /// run), then a refresh that could: the refresh names the trip it
    /// cleared, so the next open does not take that trip's access row for
    /// a trip of the new arming. Without the name the canary would come
    /// back tripped — a refresh the operator made, undone.
    #[test]
    fn a_refresh_after_a_trip_the_registry_could_not_record_rearms_for_good() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let aside = dir.path().join("canaries.jsonl.aside");
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
        let trip = access_db(&dir).append(access(&id, true, 1)).unwrap();
        // the registry cannot be appended to: a directory at its path
        std::fs::rename(&log_path, &aside).unwrap();
        std::fs::create_dir(&log_path).unwrap();
        assert!(reg
            .mark_tripped(&id, Some(trip.entry_hash.clone()))
            .is_err());
        assert!(!reg.is_armed(&id), "tripped for this run");
        std::fs::remove_dir(&log_path).unwrap();
        std::fs::rename(&aside, &log_path).unwrap();
        let refresh = reg.refresh(&id, "11111111", None).unwrap();
        assert_eq!(refresh.first_trip_access_hash, Some(trip.entry_hash));
        drop(reg);
        assert_eq!(
            actions(&log_path, &id),
            [RegistryAction::Deploy, RegistryAction::Refresh]
        );
        let (reg, found) = boot(&dir);
        assert!(found.is_empty(), "{found:?}");
        assert!(reg.is_armed(&id));
    }

    /// Agents before lab PR 143 wrote no `Trip` row and agents before this
    /// lot named nothing in a `Refresh` row: a first-trip row written
    /// before such a refresh (by time) was refreshed, one written after it
    /// is a trip of its arming.
    #[test]
    fn a_refresh_that_names_nothing_is_placed_by_its_time() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let id = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
            // the trip lived in memory (no `Trip` row) ...
            access_db(&dir).append(access(&id, true, 1)).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
            // ... and the refresh, of a canary the registry held armed,
            // names nothing
            assert_eq!(
                reg.refresh(&id, "11111111", None)
                    .unwrap()
                    .first_trip_access_hash,
                None
            );
            id
        };
        let (reg, found) = boot(&dir);
        assert!(found.is_empty(), "refreshed after it: {found:?}");
        assert!(reg.is_armed(&id));
        drop(reg);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let after = access_db(&dir).append(access(&id, true, 2)).unwrap();
        let (reg, found) = boot(&dir);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].access, after);
        assert_eq!(
            found[0].first_trip_rows, 1,
            "the refreshed one is not counted"
        );
        assert!(!reg.is_armed(&id));
    }

    /// An agent before this lot that stopped in the gap re-armed the canary
    /// at its next start, and its next first trip was recorded: the older
    /// first-trip row is before a row the registry names, so a refresh
    /// re-armed after both — one that names that trip (this lot's), or one
    /// that names nothing (written before). Two such stops in a row leave
    /// two rows no row names: the trip is recorded with the later one, and
    /// both are counted.
    #[test]
    fn first_trip_rows_before_a_row_the_registry_names_are_accounted_for() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let (named, legacy) = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            let named = reg.deploy(sample_draft(1)).unwrap().canary_id;
            let legacy = reg.deploy(sample_draft(2)).unwrap().canary_id;
            let mut log = access_db(&dir);
            for id in [&named, &legacy] {
                log.append(access(id, true, 1)).unwrap();
                let recorded = log.append(access(id, true, 2)).unwrap();
                reg.mark_tripped(id, Some(recorded.entry_hash)).unwrap();
            }
            reg.refresh(&named, "11111111", None).unwrap();
            // a refresh as written before this lot: it names nothing
            let mut state = reg.get(&legacy).unwrap();
            state.tripped = false;
            state.first_trip_access_hash = None;
            reg.append(RegistryAction::Refresh, &state, "11111111", None)
                .unwrap();
            (named, legacy)
        };
        let (reg, found) = boot(&dir);
        assert!(found.is_empty(), "{found:?}");
        assert!(reg.is_armed(&named));
        assert!(reg.is_armed(&legacy));
        drop(reg);
        let trips: BTreeMap<String, CanaryAccessEntry> = {
            let mut log = access_db(&dir);
            [&named, &legacy]
                .into_iter()
                .map(|id| {
                    log.append(access(id, true, 3)).unwrap();
                    (id.clone(), log.append(access(id, true, 4)).unwrap())
                })
                .collect()
        };
        let (reg, found) = boot(&dir);
        assert_eq!(found.len(), 2, "{found:?}");
        for found in &found {
            assert_eq!(found.access, trips[&found.canary_id], "the later one");
            assert_eq!(found.first_trip_rows, 2);
            assert!(!reg.is_armed(&found.canary_id));
        }
    }

    /// What trips nothing: an access row nobody signed for an armed
    /// canary, a copy of a trip a refresh cleared, a later access, another
    /// canary's trip (each canary is judged on its own rows), the rows of a
    /// burned canary; and with no armed canary the access log is not read.
    #[test]
    fn rows_that_trip_nothing() {
        let dir = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir);
        let log_path = dir.path().join("canaries.jsonl");
        let access_path = dir.path().join(ACCESS_LOG);
        let (armed, other, burned) = {
            let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
            let armed = reg.deploy(sample_draft(1)).unwrap().canary_id;
            let other = reg.deploy(sample_draft(2)).unwrap().canary_id;
            let burned = reg.deploy(sample_draft(3)).unwrap().canary_id;
            let mut log = access_db(&dir);
            let cleared = log.append(access(&armed, true, 1)).unwrap();
            reg.mark_tripped(&armed, Some(cleared.entry_hash.clone()))
                .unwrap();
            reg.refresh(&armed, "11111111", None).unwrap();
            log.append(access(&other, false, 2)).unwrap();
            log.append(access(&burned, true, 3)).unwrap();
            reg.burn(&burned, "11111111").unwrap();
            drop(log);
            let mut forged = cleared.clone();
            forged.seq = Some(3);
            forged.accessor_pid = 5;
            forged.entry_hash = "cd".repeat(32);
            let mut body = std::fs::read_to_string(&access_path).unwrap();
            let copy = body.lines().next().unwrap().to_string();
            body.push_str(&format!(
                "{}\n{copy}\n",
                serde_json::to_string(&forged).unwrap()
            ));
            std::fs::write(&access_path, body).unwrap();
            (armed, other, burned)
        };
        let (reg, found) = boot(&dir);
        assert!(found.is_empty(), "{found:?}");
        assert!(reg.is_armed(&armed));
        assert!(reg.is_armed(&other));
        assert!(reg.get(&burned).is_none());
        // no armed canary: the log is not read (a directory at its path)
        let dir2 = TempDir::new().unwrap();
        let (key, _) = fresh_signing_key(&dir2);
        let mut reg = Registry::open(&dir2.path().join("canaries.jsonl"), key, [0u8; 16]).unwrap();
        let id = reg.deploy(sample_draft(1)).unwrap().canary_id;
        reg.mark_tripped(&id, None).unwrap();
        std::fs::create_dir(dir2.path().join(ACCESS_LOG)).unwrap();
        assert!(reg
            .unrecorded_trips(&dir2.path().join(ACCESS_LOG))
            .unwrap()
            .is_empty());
        reg.refresh(&id, "11111111", None).unwrap();
        assert!(
            reg.unrecorded_trips(&dir2.path().join(ACCESS_LOG)).is_err(),
            "an armed canary: the log is read, and a directory cannot be"
        );
    }

    /// EVD-023 (NN-AUD-427): a pre-image that carries its seal is refused
    /// in every build.
    #[test]
    fn registry_compute_entry_hash_refuses_a_sealed_row() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("canaries.jsonl");
        let (key, _) = fresh_signing_key(&dir);
        let mut reg = Registry::open(&log_path, key, [0u8; 16]).unwrap();
        let row = reg.deploy(sample_draft(1)).unwrap();
        assert!(compute_entry_hash(&row).is_err());
        let mut stripped = row.clone();
        stripped.entry_hash.clear();
        stripped.agent_sig.clear();
        assert_eq!(
            hex::encode(compute_entry_hash(&stripped).unwrap()),
            row.entry_hash
        );
    }
}
