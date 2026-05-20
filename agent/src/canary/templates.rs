//! Tappa 9.5 (K4) — credential canary content templates.
//!
//! Renders the BYTES that go on disk for a `Credential`-typed
//! canary deployment. Per §12 Q5 LEVEL A lock-in: every
//! rendered credential is FORMAT-VALID (passes the family's
//! standard regex / parser) but DOES NOT authenticate against
//! any real backend — there's no AWS account behind the AKIA
//! key, no Azure tenant behind the GUID, no Google project
//! behind the service-account JSON. Operators with online-
//! verification budgets feed the rendered bytes into their
//! SIEM/SOAR via the canary_access.jsonl chain K3 writes;
//! sovereign deployments stop at on-host detection.
//!
//! ## Five families
//!
//! All five sourced from the design §1.2 threat-model recap:
//!
//! | Family   | Format                                          |
//! |----------|-------------------------------------------------|
//! | `aws`    | `.aws/credentials` ini-shape: AKIA + 40-char secret |
//! | `azure`  | service-principal JSON: appId/password/tenant GUIDs |
//! | `gcp`    | service-account JSON: project + private_key PEM stub |
//! | `docker` | `~/.docker/config.json` shape: registry auths   |
//! | `generic`| OAuth bearer-token .env shape                   |
//!
//! ## Determinism (§12 Q5 Level A)
//!
//! Render output is DETERMINISTIC per `canary_id`. The same
//! canary_id always renders the same bytes — so the chained
//! `canaries.jsonl` registry can record a stable
//! `contents_hash` field for the deployment AND an operator
//! re-rendering with the same canary_id (e.g. after a
//! disaster-recovery restore) gets identical content.
//!
//! Random-ish field values come from
//! `SHA-256(canary_id || ":" || field_name)` truncated +
//! alphabet-mapped — no `rand` RNG state, no chrono, no
//! workspace-state dependency. Pure function of canary_id.
//!
//! ## Template lookup
//!
//! Templates live in `configs/canary-templates/<family>.tmpl`
//! in the repo + are dropped under
//! `/etc/northnarrow/canary-templates/` at install time by
//! K7's `deploy/install.sh` (the same pattern as Tappa 9 C7
//! `fim-paths.v1`). The renderer:
//!
//! 1. Tries the operator override at
//!    `/etc/northnarrow/canary-templates/<family>.tmpl` first.
//! 2. Falls back to the built-in default compiled in via
//!    `include_str!` (zero-disk-dep tests; production
//!    operators get the file too via install.sh).
//!
//! Operator overrides let high-value sites tune deception
//! content to their specific environment without recompiling
//! the agent. K2 audit chain captures every deploy op so the
//! template-version-in-effect at deploy time is recoverable
//! via the deployment row.

use std::collections::HashMap;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Default deploy location of the operator-overrideable
/// template directory. K7 `install.sh` drops the repo's
/// `configs/canary-templates/` here at install time.
pub const DEFAULT_TEMPLATE_DIR: &str = "/etc/northnarrow/canary-templates";

/// Built-in template defaults — compiled into the agent
/// binary so tests + first-boot agents that haven't run
/// `install.sh` yet still render valid canary content.
const AWS_TMPL: &str = include_str!("../../../configs/canary-templates/aws.tmpl");
const AZURE_TMPL: &str = include_str!("../../../configs/canary-templates/azure.tmpl");
const GCP_TMPL: &str = include_str!("../../../configs/canary-templates/gcp.tmpl");
const DOCKER_TMPL: &str = include_str!("../../../configs/canary-templates/docker.tmpl");
const GENERIC_TMPL: &str = include_str!("../../../configs/canary-templates/generic.tmpl");

/// The 5 credential families K4 ships. Wire-stable identifier
/// strings ("aws" / "azure" / "gcp" / "docker" / "generic")
/// match the `cred_family` field on
/// [`common::wire::admin_signed_payload::CanaryDeploymentWire::Credential`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredFamily {
    Aws,
    Azure,
    Gcp,
    Docker,
    Generic,
}

impl CredFamily {
    /// Parse the wire-stable family identifier string.
    pub fn from_wire(s: &str) -> Result<Self, RenderError> {
        match s {
            "aws" => Ok(CredFamily::Aws),
            "azure" => Ok(CredFamily::Azure),
            "gcp" => Ok(CredFamily::Gcp),
            "docker" => Ok(CredFamily::Docker),
            "generic" => Ok(CredFamily::Generic),
            other => Err(RenderError::UnknownFamily(other.to_string())),
        }
    }

    /// Wire-stable identifier string. Stays stable across
    /// agent versions; new families append (mirrors the
    /// CanaryTypeWire / Role discriminator pattern).
    pub fn as_wire(&self) -> &'static str {
        match self {
            CredFamily::Aws => "aws",
            CredFamily::Azure => "azure",
            CredFamily::Gcp => "gcp",
            CredFamily::Docker => "docker",
            CredFamily::Generic => "generic",
        }
    }

    /// Built-in template string compiled into the agent binary.
    /// Operator-override-aware variant in `render`; this is
    /// the fallback only.
    fn builtin_template(&self) -> &'static str {
        match self {
            CredFamily::Aws => AWS_TMPL,
            CredFamily::Azure => AZURE_TMPL,
            CredFamily::Gcp => GCP_TMPL,
            CredFamily::Docker => DOCKER_TMPL,
            CredFamily::Generic => GENERIC_TMPL,
        }
    }
}

/// Outcome of [`render`] failures. Typed via thiserror so K6
/// admin dispatch can map each variant to the right
/// `AdminResult` without string-matching.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("unknown credential family `{0}` — expected one of: aws, azure, gcp, docker, generic")]
    UnknownFamily(String),
    #[error("template file {path} read failed: {source}")]
    TemplateRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("template body contains unresolved placeholder `{0}` — template version mismatch")]
    UnresolvedPlaceholder(String),
}

/// Pure renderer. Given a `canary_id` (the K2 stable-ID hex
/// string), produce the canary's file content for `family`.
/// Output is deterministic per canary_id — same canary_id
/// always renders the same bytes.
///
/// `template_dir` lets the caller override the operator
/// directory for tests; production callers pass
/// `Some(Path::new(DEFAULT_TEMPLATE_DIR))`. `None` skips the
/// override lookup entirely (built-in templates only).
pub fn render(
    family: CredFamily,
    canary_id: &str,
    template_dir: Option<&std::path::Path>,
) -> Result<String, RenderError> {
    let template = load_template(family, template_dir)?;
    let placeholders = build_placeholders(family, canary_id);
    substitute(&template, &placeholders)
}

/// Load the template body for `family`. Tries operator
/// override under `template_dir` first; falls back to the
/// `include_str!` built-in.
fn load_template(
    family: CredFamily,
    template_dir: Option<&std::path::Path>,
) -> Result<String, RenderError> {
    if let Some(dir) = template_dir {
        let candidate = dir.join(format!("{}.tmpl", family.as_wire()));
        match std::fs::read_to_string(&candidate) {
            Ok(body) => return Ok(body),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Fall through to the built-in default.
            }
            Err(e) => {
                return Err(RenderError::TemplateRead {
                    path: candidate,
                    source: e,
                });
            }
        }
    }
    Ok(family.builtin_template().to_string())
}

/// Build the per-family placeholder map. Every value is a
/// deterministic function of `canary_id` via SHA-256, mapped
/// to the format the family's spec requires (AKIA prefix,
/// GUID shape, base64 token shape, etc.).
fn build_placeholders(family: CredFamily, canary_id: &str) -> HashMap<&'static str, String> {
    let mut m = HashMap::new();
    match family {
        CredFamily::Aws => {
            // AWS Access Key ID: 16-char base32 body (uppercase
            // [A-Z2-7]) with the standard `AKIA` prefix → 20
            // chars total. Real AWS rotates the prefix
            // occasionally (AKIA / ASIA / etc.); AKIA is the
            // long-lived-key shape attackers expect to find.
            m.insert(
                "access_key_id",
                format!("AKIA{}", derive_base32(canary_id, "akia_body", 16)),
            );
            // AWS Secret Access Key: 40 base64-ish chars
            // (no padding, no '/' or '+' surprises — AWS
            // accepts [A-Za-z0-9/+]+, we stick to alphanumeric
            // for cleaner regex-match in test grep).
            m.insert(
                "secret_access_key",
                derive_base64ish(canary_id, "secret_body", 40),
            );
        }
        CredFamily::Azure => {
            // Three GUIDs (8-4-4-4-12 hex chars, version 4
            // shape with the 4xxx + yxxx variant bits set per
            // RFC 4122). Plus a password that looks like a
            // 40-char base64 secret.
            m.insert("app_id", derive_guid(canary_id, "app_id"));
            m.insert("tenant_id", derive_guid(canary_id, "tenant_id"));
            m.insert("object_id", derive_guid(canary_id, "object_id"));
            m.insert(
                "password",
                derive_base64ish(canary_id, "azure_password", 40),
            );
            m.insert("short_id", short_id(canary_id));
        }
        CredFamily::Gcp => {
            // GCP service-account JSON shape (real format per
            // Google's documentation). private_key_body is a
            // base64 blob between BEGIN/END PRIVATE KEY
            // markers — Level A means PEM-parseable, NOT
            // cryptographically valid (no real RSA key gen at
            // render time; that'd require the openssl crate
            // which violates the Tappa 0 minimal-dep charter).
            m.insert(
                "private_key_id",
                derive_hex(canary_id, "private_key_id", 40),
            );
            m.insert(
                "private_key_body",
                derive_pem_body(canary_id, "private_key_body"),
            );
            m.insert("client_id", derive_decimal(canary_id, "client_id", 21));
            m.insert("short_id", short_id(canary_id));
        }
        CredFamily::Docker => {
            // Docker config.json: each registry's `auth` is the
            // base64-encoded "user:password" pair. Real Docker
            // login writes this exact shape; format checkers
            // (skopeo, docker-credential-helper) accept it.
            m.insert("basic_auth", derive_basic_auth(canary_id, "registry"));
            m.insert("ghcr_auth", derive_basic_auth(canary_id, "ghcr"));
            m.insert("short_id", short_id(canary_id));
        }
        CredFamily::Generic => {
            // OAuth bearer-token .env shape. The token itself
            // is a 60-char base64-ish blob (matches the
            // standard OAuth opaque-token shape from RFC 6749
            // §1.5).
            m.insert("bearer_token", derive_base64ish(canary_id, "bearer", 60));
            m.insert("tenant_id", derive_guid(canary_id, "tenant_id"));
        }
    }
    m
}

/// Plain `{{key}}` → `value` substitution. Errors out on
/// unresolved placeholders so a template-version drift
/// (operator overlay carries a NEW placeholder name the
/// agent's `build_placeholders` doesn't know about) fails
/// LOUDLY at deploy time rather than persisting a
/// canary file with literal `{{tenant_id}}` strings on disk.
fn substitute(template: &str, placeholders: &HashMap<&str, String>) -> Result<String, RenderError> {
    let mut out = template.to_string();
    for (key, value) in placeholders {
        out = out.replace(&format!("{{{{{key}}}}}"), value);
    }
    // Defensive: any remaining `{{…}}` is an unresolved
    // placeholder. Scan + surface the first one.
    if let Some(start) = out.find("{{") {
        if let Some(end_rel) = out[start..].find("}}") {
            let placeholder = &out[start + 2..start + end_rel];
            return Err(RenderError::UnresolvedPlaceholder(placeholder.to_string()));
        }
    }
    Ok(out)
}

// ── deterministic derivation helpers ────────────────────────────────

/// SHA-256(canary_id || ":" || field) → raw 32 bytes. The
/// `:` separator prevents collision between e.g. `canary_id =
/// "x"` + `field = "y"` and `canary_id = "x:y"` + `field = ""`.
fn derive_bytes(canary_id: &str, field: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canary_id.as_bytes());
    h.update(b":");
    h.update(field.as_bytes());
    h.finalize().into()
}

/// Base-32 alphabet (RFC 4648 — uppercase A-Z + 2-7). Used
/// for the AWS Access Key ID body.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Map `len` bytes from the SHA-256 digest into base-32
/// characters. `len` MUST be ≤ 32 (we never need more than
/// 16 for AWS keys).
fn derive_base32(canary_id: &str, field: &str, len: usize) -> String {
    debug_assert!(len <= 32);
    let bytes = derive_bytes(canary_id, field);
    bytes[..len]
        .iter()
        .map(|b| BASE32[(*b as usize) % 32] as char)
        .collect()
}

/// Generate a base64-ish opaque token. Uses the standard
/// base64 alphabet but skips `/` and `+` so the resulting
/// string is grep-friendly + matches the cleaner shape AWS
/// secret keys + most OAuth tokens use in the wild.
fn derive_base64ish(canary_id: &str, field: &str, len: usize) -> String {
    // Hash a couple of times so we have ≥ len/1.3 raw bytes
    // (base64 expands 3→4). For len up to 60 + a small
    // safety margin, two rounds is plenty.
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&derive_bytes(canary_id, &format!("{field}/0")));
    buf.extend_from_slice(&derive_bytes(canary_id, &format!("{field}/1")));
    let encoded = B64.encode(&buf);
    let trimmed: String = encoded
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(len)
        .collect();
    if trimmed.len() < len {
        // Pad with alphanumeric hash bytes if the filter ate
        // too many chars. Shouldn't happen for len ≤ 60 + 2
        // hash rounds, but defend against base64's '+' / '/'
        // edge case.
        let extra = derive_bytes(canary_id, &format!("{field}/pad"));
        let mut padded = trimmed;
        for b in extra {
            if padded.len() >= len {
                break;
            }
            let c = ((b % 26) + b'A') as char;
            padded.push(c);
        }
        padded
    } else {
        trimmed
    }
}

/// Generate a hex string of `len` chars (≤ 64).
fn derive_hex(canary_id: &str, field: &str, len: usize) -> String {
    debug_assert!(len <= 64);
    let bytes = derive_bytes(canary_id, field);
    hex::encode(bytes).chars().take(len).collect()
}

/// Generate a decimal string of `len` digits (≤ 38 — u128
/// max). Used for the GCP `client_id` which is a 21-digit
/// integer.
fn derive_decimal(canary_id: &str, field: &str, len: usize) -> String {
    debug_assert!(len <= 38);
    let bytes = derive_bytes(canary_id, field);
    // Treat the first 16 bytes as a u128, format as decimal,
    // truncate/pad to len.
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[..16]);
    let n = u128::from_be_bytes(arr);
    let s = n.to_string();
    if s.len() >= len {
        s[..len].to_string()
    } else {
        // Pad with extra digits derived from the next bytes.
        let mut padded = s;
        for b in &bytes[16..] {
            if padded.len() >= len {
                break;
            }
            padded.push(((b % 10) + b'0') as char);
        }
        padded
    }
}

/// Generate an RFC 4122 v4 UUID (random shape) deterministically
/// from canary_id + field. Sets the version (0b0100xxxx in
/// byte 6) + variant (0b10xxxxxx in byte 8) bits per the
/// spec so the result passes UUID-format checkers (Azure
/// SDK, .NET Guid.Parse, etc.).
fn derive_guid(canary_id: &str, field: &str) -> String {
    let mut bytes = derive_bytes(canary_id, field);
    // Version 4 in the high nibble of byte 6.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // Variant 10xx in the high two bits of byte 8.
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let hex = hex::encode(&bytes[..16]);
    // 8-4-4-4-12 layout.
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Generate a PEM-parseable private-key body block (30 lines
/// of 64-char base64). NOT a valid RSA key (the bytes are
/// SHA-derived noise, not a DER-encoded RSAPrivateKey), but
/// `openssl pkey -in <file> -text -noout` accepts the framing
/// and reports "unable to load Private Key" on the body
/// (FORMAT check passes; cryptographic check fails — Level A
/// per §12 Q5, exactly the operator-controlled shape).
fn derive_pem_body(canary_id: &str, field: &str) -> String {
    let mut buf = Vec::with_capacity(64 * 30);
    for i in 0..15 {
        buf.extend_from_slice(&derive_bytes(canary_id, &format!("{field}/{i}")));
    }
    let encoded = B64.encode(&buf);
    // Wrap to 64-char lines per PEM convention. The GCP
    // template embeds this inside a JSON string value, so the
    // separator is the LITERAL two-char sequence `\` `n` (a
    // JSON-escaped newline) — when serde-json parses the
    // surrounding object, it converts back to real newlines.
    // openssl pkey -in <decoded-file> -text -noout accepts
    // the framing.
    encoded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\\n")
}

/// Generate a Docker basic-auth blob — base64("user:password")
/// shape. Real Docker login writes the same shape; the
/// `docker login --username-stdin` flow's output dropped
/// straight into `~/.docker/config.json`.
fn derive_basic_auth(canary_id: &str, field: &str) -> String {
    let user = format!("deploy-{}", short_id(canary_id));
    let pass = derive_base64ish(canary_id, field, 32);
    B64.encode(format!("{user}:{pass}").as_bytes())
}

/// Short 8-char hex prefix of `canary_id`. Used in
/// human-readable identifiers (`deploy-<short>`,
/// `northnarrow-prod-<short>`) to thread visual continuity
/// without exposing the full 32-char canary_id in every
/// field.
fn short_id(canary_id: &str) -> String {
    canary_id.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Stable canary_id for deterministic-output assertions.
    /// Real K2 IDs are SHA-256(name||":"||deployed_at)[..16] —
    /// 32 hex chars; this fixture mirrors the shape.
    const TEST_ID: &str = "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3";

    // ── K4 test #1: AWS format-validity ─────────────────────

    /// Render AWS credentials → output contains:
    /// (a) `aws_access_key_id = AKIA...` with 16 base32 chars,
    /// (b) `aws_secret_access_key = ` with 40 alphanumeric chars.
    /// Both formats match the published AWS spec — `aws-cli`
    /// + `boto3` parse them without complaint.
    #[test]
    fn render_aws_produces_format_valid_access_key() {
        let body = render(CredFamily::Aws, TEST_ID, None).expect("render AWS");
        // Extract AKIA line.
        let akia_line = body
            .lines()
            .find(|l| l.contains("aws_access_key_id"))
            .expect("AKIA line present");
        let akia = akia_line.split('=').nth(1).unwrap().trim();
        assert!(
            akia.starts_with("AKIA"),
            "AWS access key must start with AKIA, got {akia}"
        );
        assert_eq!(akia.len(), 20, "AWS access key is 20 chars total");
        for c in akia[4..].chars() {
            assert!(
                c.is_ascii_uppercase() || ('2'..='7').contains(&c),
                "AWS key body uses RFC 4648 base32 alphabet"
            );
        }
        // Extract secret line.
        let secret_line = body
            .lines()
            .find(|l| l.contains("aws_secret_access_key"))
            .expect("secret line present");
        let secret = secret_line.split('=').nth(1).unwrap().trim();
        assert_eq!(secret.len(), 40, "AWS secret key is 40 chars");
        assert!(
            secret.chars().all(|c| c.is_ascii_alphanumeric()),
            "AWS secret key uses base64-ish alphanumeric chars"
        );
    }

    // ── K4 test #2: Azure service-principal shape ────────────

    #[test]
    fn render_azure_matches_service_principal_shape() {
        let body = render(CredFamily::Azure, TEST_ID, None).expect("render Azure");
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("Azure template must be valid JSON");
        // Required fields per the standard Azure
        // service-principal output of `az ad sp create-for-rbac`.
        for field in &["appId", "tenant", "objectId", "password"] {
            assert!(
                parsed.get(*field).is_some(),
                "Azure JSON must contain field `{field}`"
            );
        }
        // GUID shape check on appId / tenant / objectId.
        for guid_field in &["appId", "tenant", "objectId"] {
            let g = parsed[*guid_field].as_str().unwrap();
            assert_eq!(
                g.len(),
                36,
                "GUID `{guid_field}` is 36 chars (8-4-4-4-12 + 4 dashes)"
            );
            assert_eq!(g.chars().filter(|c| *c == '-').count(), 4);
            // Version 4 marker: 13th char must be '4'.
            assert_eq!(
                g.chars().nth(14),
                Some('4'),
                "GUID must be v4 — 13th hex char (offset 14 with dashes) is '4'"
            );
            // Variant marker: 17th hex char (offset 19 with
            // dashes) is one of [89ab].
            let variant = g.chars().nth(19).unwrap();
            assert!(
                matches!(variant, '8' | '9' | 'a' | 'b'),
                "GUID variant nibble must be 8/9/a/b, got {variant}"
            );
        }
    }

    // ── K4 test #3: GCP service-account shape ────────────────

    #[test]
    fn render_gcp_matches_service_account_shape() {
        let body = render(CredFamily::Gcp, TEST_ID, None).expect("render GCP");
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("GCP template must be valid JSON");
        // Mandatory fields per Google's documented service-
        // account JSON format.
        assert_eq!(parsed["type"], "service_account");
        for field in &[
            "project_id",
            "private_key_id",
            "private_key",
            "client_email",
            "client_id",
            "auth_uri",
            "token_uri",
        ] {
            assert!(
                parsed.get(*field).is_some(),
                "GCP service-account JSON must contain `{field}`"
            );
        }
        // PEM framing on private_key.
        let pem = parsed["private_key"].as_str().unwrap();
        assert!(
            pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "private_key must start with PEM BEGIN marker"
        );
        assert!(
            pem.ends_with("-----END PRIVATE KEY-----\n"),
            "private_key must end with PEM END marker + newline"
        );
        // private_key_id is 40 hex chars per the GCP format.
        let kid = parsed["private_key_id"].as_str().unwrap();
        assert_eq!(kid.len(), 40);
        assert!(kid.chars().all(|c| c.is_ascii_hexdigit()));
        // client_id is a 21-digit decimal string.
        let cid = parsed["client_id"].as_str().unwrap();
        assert_eq!(cid.len(), 21);
        assert!(cid.chars().all(|c| c.is_ascii_digit()));
    }

    // ── K4 test #4: Docker config.json shape ─────────────────

    #[test]
    fn render_docker_matches_config_json_shape() {
        let body = render(CredFamily::Docker, TEST_ID, None).expect("render Docker");
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("Docker template must be valid JSON");
        let auths = parsed.get("auths").expect("auths field present");
        assert!(auths.is_object());
        // At least the registry.northnarrow.io entry exists.
        let registry = auths
            .get("registry.northnarrow.io")
            .expect("registry.northnarrow.io entry present");
        let auth = registry["auth"].as_str().unwrap();
        // The `auth` field is base64-encoded "user:password";
        // decoding must succeed AND contain a ":" separator.
        let decoded = B64.decode(auth).expect("auth field must be valid base64");
        let decoded_str = std::str::from_utf8(&decoded).unwrap();
        assert!(
            decoded_str.contains(':'),
            "Docker basic-auth decodes to user:password format"
        );
        // ghcr.io entry also populated.
        assert!(auths.get("ghcr.io").is_some());
    }

    // ── K4 test #5: determinism ──────────────────────────────

    /// Same canary_id renders identical bytes across calls.
    /// The K2 deployment can record a stable contents_hash;
    /// disaster-recovery re-renders produce the same content
    /// the original deploy did.
    #[test]
    fn render_with_same_canary_id_is_deterministic() {
        for family in [
            CredFamily::Aws,
            CredFamily::Azure,
            CredFamily::Gcp,
            CredFamily::Docker,
            CredFamily::Generic,
        ] {
            let a = render(family, TEST_ID, None).expect("render");
            let b = render(family, TEST_ID, None).expect("render");
            assert_eq!(a, b, "{family:?} must be deterministic on canary_id");
            // Different canary_id → different content.
            let c = render(family, "deadbeefcafebabe1234567890abcdef", None).expect("render");
            assert_ne!(
                a, c,
                "{family:?} must produce different content for different canary_id"
            );
        }
    }

    // ── K4 test #6: unknown-family + missing-placeholder errors ──

    #[test]
    fn from_wire_rejects_unknown_family() {
        let err = CredFamily::from_wire("oracle").unwrap_err();
        match err {
            RenderError::UnknownFamily(s) => assert_eq!(s, "oracle"),
            other => panic!("expected UnknownFamily, got {other:?}"),
        }
    }

    #[test]
    fn render_with_unresolved_placeholder_returns_typed_error() {
        // Operator-override file with a placeholder the
        // built-in placeholder map doesn't know about.
        let dir = TempDir::new().unwrap();
        let bad = dir.path().join("aws.tmpl");
        std::fs::write(&bad, "aws_access_key_id = AKIA{{not_a_real_placeholder}}\n").unwrap();
        let err = render(CredFamily::Aws, TEST_ID, Some(dir.path())).unwrap_err();
        match err {
            RenderError::UnresolvedPlaceholder(p) => {
                assert_eq!(p, "not_a_real_placeholder");
            }
            other => panic!("expected UnresolvedPlaceholder, got {other:?}"),
        }
    }

    // ── K4 test #7: operator override resolves before built-in ──

    #[test]
    fn operator_override_takes_precedence_over_builtin() {
        let dir = TempDir::new().unwrap();
        let override_file = dir.path().join("aws.tmpl");
        std::fs::write(
            &override_file,
            "operator-override aws_access_key_id = {{access_key_id}}\n",
        )
        .unwrap();
        let body = render(CredFamily::Aws, TEST_ID, Some(dir.path())).expect("render");
        assert!(
            body.starts_with("operator-override aws_access_key_id = AKIA"),
            "operator override must take precedence: {body}"
        );
    }
}
