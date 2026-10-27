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
//! ## Content says nothing about what it is (external audit DEC-007)
//!
//! What lands on disk is read by the attacker: the templates and the
//! File canary body carry no product name, no "do not use" comment, no
//! rule id and no operator fingerprint. Which files are canaries is
//! recorded only in the signed registry (`/var/lib/northnarrow`, 0700).
//! The default names are neutral; an operator who wants the decoys to
//! look like the site (its domains, project names) edits the copies in
//! `/etc/northnarrow/canary-templates/` (comments there would be copied
//! into the decoy, so the templates have none).
//!
//! ## Seed (external audit DEC-008)
//!
//! Every value is derived from a seed: `SHA-256(seed || ":" || field)`,
//! truncated and mapped to the family's alphabet. The deploy (and a
//! refresh) draws a fresh 32-byte seed from the OS RNG
//! ([`new_content_seed`]) and records it in the registry row with the
//! SHA-256 of the bytes written, so two deploys never render the same
//! content and a decoy can be re-rendered from its row. The seed used to
//! be `"<operator key fingerprint>:<path>"`: the fingerprint appeared in
//! clear in the decoy (`short_id` was the seed's first 8 characters) and
//! every host with the same path got the same credential. `short_id` is
//! now hashed from the seed, never a prefix of it.
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
//!    `/etc/northnarrow/canary-templates/<family>.tmpl` first —
//!    unless it is byte-identical to a template an earlier release
//!    shipped ([`SUPERSEDED_TEMPLATE_SHA256`]), which named the
//!    product: `install.sh` replaces those, and the agent does not
//!    use one left behind. The file is read without following a
//!    link, without blocking on a FIFO, from a regular file of at
//!    most [`MAX_TEMPLATE_BYTES`]; one there but refused fails the
//!    render (external audit DEC-016, lab PR 178). The rendered
//!    decoy keeps no `{{`, and a JSON family's is a JSON document
//!    (DEC-017).
//! 2. Falls back to the built-in default compiled in via
//!    `include_str!` (zero-disk-dep tests; production
//!    operators get the file too via install.sh).
//!
//! Operator overrides let high-value sites tune deception
//! content to their specific environment without recompiling
//! the agent.

use std::collections::HashMap;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use nn_core::content_host::ContentHost;
use sha2::{Digest, Sha256};

use crate::chain_host_linux::LinuxHost;

/// Default deploy location of the operator-overrideable
/// template directory. K7 `install.sh` drops the repo's
/// `configs/canary-templates/` here at install time.
pub const DEFAULT_TEMPLATE_DIR: &str = "/etc/northnarrow/canary-templates";

/// Built-in template defaults — compiled into the agent
/// binary so tests + first-boot agents that haven't run
/// `install.sh` yet still render valid canary content.
const AWS_TMPL: &str = include_str!(concat!(
    env!("NN_REPO_ROOT"),
    "/configs/canary-templates/aws.tmpl"
));
const AZURE_TMPL: &str = include_str!(concat!(
    env!("NN_REPO_ROOT"),
    "/configs/canary-templates/azure.tmpl"
));
const GCP_TMPL: &str = include_str!(concat!(
    env!("NN_REPO_ROOT"),
    "/configs/canary-templates/gcp.tmpl"
));
const DOCKER_TMPL: &str = include_str!(concat!(
    env!("NN_REPO_ROOT"),
    "/configs/canary-templates/docker.tmpl"
));
const GENERIC_TMPL: &str = include_str!(concat!(
    env!("NN_REPO_ROOT"),
    "/configs/canary-templates/generic.tmpl"
));

/// The 5 credential families K4 ships. Wire-stable identifier
/// strings ("aws" / "azure" / "gcp" / "docker" / "generic")
/// match the `cred_family` field on
/// [`nn_proto::admin_signed_payload::CanaryDeploymentWire::Credential`].
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

    /// The families whose decoy is a JSON document (external audit
    /// DEC-017: checked after rendering).
    fn is_json(&self) -> bool {
        matches!(
            self,
            CredFamily::Azure | CredFamily::Gcp | CredFamily::Docker
        )
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
    /// External audit DEC-017 (lab PR 178): a JSON family's template that
    /// does not render a JSON document.
    #[error("rendered `{family}` decoy is not valid JSON: {reason}")]
    MalformedOutput {
        family: &'static str,
        reason: String,
    },
}

/// Largest operator template read (external audit DEC-016, lab PR 178):
/// 64 KiB. The shipped ones are under 1 KiB.
pub const MAX_TEMPLATE_BYTES: u64 = 64 * 1024;

/// SHA-256 (hex) of each template an earlier release shipped (external
/// audit DEC-007): they named the product (`NorthNarrow XDR`, `DO NOT
/// USE`, `northnarrow.io`). `install.sh` replaces an on-disk copy that is
/// byte-identical to one of these and keeps an operator's edit;
/// [`render`] does not use one it still finds.
pub const SUPERSEDED_TEMPLATE_SHA256: &[(&str, &str)] = &[
    (
        "aws",
        "cd728e77335951708ad263d4e2d52f808cd9522d1a63546f6621a8e33b15af79",
    ),
    (
        "azure",
        "1f2676fce70db95d9f2aeaf2a2c2628dd7211cf75d8464329acb208b9350ae04",
    ),
    (
        "docker",
        "c203d592a626a1ce6fa2ff74ac0935c454eda83060ba67242aa19906a662078d",
    ),
    (
        "gcp",
        "61f3817c87f6ca8892072a60f459b577ebcb98903b50aec9cdff6ec2c9e8c63a",
    ),
    (
        "generic",
        "b888d4187b100e984aac3c6f701d9ba649e67d76e55774a768d80ef4ee7be88a",
    ),
];

/// A fresh content seed (external audit DEC-008): 32 bytes from the OS
/// RNG, hex. One per deploy and per refresh, recorded in the registry row.
pub fn new_content_seed() -> String {
    use rand::Rng;
    let mut seed = [0u8; 32];
    crate::os_rng::OsRng.fill_bytes(&mut seed);
    hex::encode(seed)
}

/// The body of a File canary (external audit DEC-007): bytes derived from
/// `seed`, 512 to 4095 of them — no marker, no fingerprint, no rule id,
/// and no size or content shared by every decoy. It used to be three
/// comment lines naming the product, the operator key and the rule.
pub fn render_file_body(seed: &str) -> Vec<u8> {
    let n = derive_bytes(seed, "file_len");
    let len = 512 + usize::from(u16::from_be_bytes([n[0], n[1]])) % 3584;
    let mut out = Vec::with_capacity(len + 32);
    let mut block = 0u32;
    while out.len() < len {
        out.extend_from_slice(&derive_bytes(seed, &format!("file_body/{block}")));
        block += 1;
    }
    out.truncate(len);
    out
}

/// Pure renderer. Given a content `seed` (see [`new_content_seed`]),
/// produce the canary's file content for `family`. Output is
/// deterministic per seed — the same seed always renders the same
/// bytes, so a row's recorded seed re-renders its decoy.
///
/// `template_dir` lets the caller override the operator
/// directory for tests; production callers pass
/// `Some(Path::new(DEFAULT_TEMPLATE_DIR))`. `None` skips the
/// override lookup entirely (built-in templates only).
pub fn render(
    family: CredFamily,
    seed: &str,
    template_dir: Option<&std::path::Path>,
) -> Result<String, RenderError> {
    let template = load_template::<LinuxHost>(family, template_dir)?;
    let placeholders = build_placeholders(family, seed);
    let out = substitute(&template, &placeholders)?;
    // External audit DEC-017: a JSON family's decoy is a JSON document.
    if family.is_json() {
        if let Err(e) = serde_json::from_str::<serde_json::Value>(&out) {
            return Err(RenderError::MalformedOutput {
                family: family.as_wire(),
                reason: e.to_string(),
            });
        }
    }
    Ok(out)
}

/// Load the template body for `family`. Tries operator
/// override under `template_dir` first; falls back to the
/// `include_str!` built-in.
fn load_template<H: ContentHost>(
    family: CredFamily,
    template_dir: Option<&std::path::Path>,
) -> Result<String, RenderError> {
    if let Some(dir) = template_dir {
        let candidate = dir.join(format!("{}.tmpl", family.as_wire()));
        match read_template::<H>(&candidate) {
            Ok(body) if is_superseded(family, &body) => {
                // External audit DEC-007: an earlier release's template left
                // on disk (an upgrade that did not run install.sh) named the
                // product; the built-in one replaces it.
                tracing::warn!(
                    path = %candidate.display(),
                    "canary template is the one an earlier release shipped (it names the \
                     product) — the built-in template is used; install.sh --upgrade replaces it"
                );
            }
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

/// External audit DEC-016 (lab PR 178): an operator template is read once,
/// without following a link at its name, without blocking on a FIFO
/// planted there, from a regular file only and at most
/// [`MAX_TEMPLATE_BYTES`] — the overlay reader's pattern
/// (`config::overlay_auth::read_overlay`). It was `read_to_string`: the
/// templates are write-allowed at run time (MUTATE-only, so a live edit
/// does not trip COMBAT), and one grown in place, or a missing family's
/// file created as a link to `/dev/zero`, was read without limit at the
/// next deploy. A template present but refused is
/// [`RenderError::TemplateRead`] (the deploy is refused and the file
/// named), never a silent fall-back to the built-in one. The open is the
/// host's ([`ContentHost`], R07: the agent's is `LinuxHost`,
/// `O_NOFOLLOW | O_NONBLOCK`).
fn read_template<H: ContentHost>(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let f = H::open_read_nofollow(path).map_err(|e| {
        if H::is_symlink_refusal(&e) {
            std::io::Error::other("a symbolic link (not read through one)")
        } else {
            e
        }
    })?;
    if !f.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    f.take(MAX_TEMPLATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TEMPLATE_BYTES {
        return Err(std::io::Error::other(format!(
            "larger than {MAX_TEMPLATE_BYTES} bytes"
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not UTF-8"))
}

/// `body` is byte-identical to the template an earlier release shipped
/// for `family`.
fn is_superseded(family: CredFamily, body: &str) -> bool {
    let sha = hex::encode(Sha256::digest(body.as_bytes()));
    SUPERSEDED_TEMPLATE_SHA256
        .iter()
        .any(|(f, h)| *f == family.as_wire() && *h == sha)
}

/// Build the per-family placeholder map. Every value is a
/// deterministic function of `seed` via SHA-256, mapped
/// to the format the family's spec requires (AKIA prefix,
/// GUID shape, base64 token shape, etc.).
fn build_placeholders(family: CredFamily, seed: &str) -> HashMap<&'static str, String> {
    let mut m = HashMap::new();
    // Every family: an operator template may use it (it was offered to
    // azure / gcp / docker before).
    m.insert("short_id", short_id(seed));
    match family {
        CredFamily::Aws => {
            // AWS Access Key ID: 16-char base32 body (uppercase
            // [A-Z2-7]) with the standard `AKIA` prefix → 20
            // chars total. Real AWS rotates the prefix
            // occasionally (AKIA / ASIA / etc.); AKIA is the
            // long-lived-key shape attackers expect to find.
            m.insert(
                "access_key_id",
                format!("AKIA{}", derive_base32(seed, "akia_body", 16)),
            );
            // AWS Secret Access Key: 40 base64-ish chars
            // (no padding, no '/' or '+' surprises — AWS
            // accepts [A-Za-z0-9/+]+, we stick to alphanumeric
            // for cleaner regex-match in test grep).
            m.insert(
                "secret_access_key",
                derive_base64ish(seed, "secret_body", 40),
            );
        }
        CredFamily::Azure => {
            // Three GUIDs (8-4-4-4-12 hex chars, version 4
            // shape with the 4xxx + yxxx variant bits set per
            // RFC 4122). Plus a password that looks like a
            // 40-char base64 secret.
            m.insert("app_id", derive_guid(seed, "app_id"));
            m.insert("tenant_id", derive_guid(seed, "tenant_id"));
            m.insert("object_id", derive_guid(seed, "object_id"));
            m.insert("password", derive_base64ish(seed, "azure_password", 40));
            // `az ad sp create-for-rbac` names a principal
            // `azure-cli-YYYY-MM-DD-HH-MM-SS` by default.
            m.insert("az_stamp", derive_stamp(seed, "az_stamp"));
        }
        CredFamily::Gcp => {
            // GCP service-account JSON shape (real format per
            // Google's documentation). private_key_body is a
            // base64 blob between BEGIN/END PRIVATE KEY
            // markers — Level A means PEM-parseable, NOT
            // cryptographically valid (no real RSA key gen at
            // render time; that'd require the openssl crate
            // which violates the Tappa 0 minimal-dep charter).
            m.insert("private_key_id", derive_hex(seed, "private_key_id", 40));
            m.insert(
                "private_key_body",
                derive_pem_body(seed, "private_key_body"),
            );
            m.insert("client_id", derive_decimal(seed, "client_id", 21));
            // A generated project id: a name plus six digits.
            m.insert(
                "project_id",
                format!("prod-platform-{}", derive_decimal(seed, "project_id", 6)),
            );
        }
        CredFamily::Docker => {
            // Docker config.json: each registry's `auth` is the
            // base64-encoded "user:password" pair. Real Docker
            // login writes this exact shape; format checkers
            // (skopeo, docker-credential-helper) accept it.
            m.insert("basic_auth", derive_basic_auth(seed, "registry"));
            m.insert("ghcr_auth", derive_basic_auth(seed, "ghcr"));
        }
        CredFamily::Generic => {
            // OAuth bearer-token .env shape. The token itself
            // is a 60-char base64-ish blob (matches the
            // standard OAuth opaque-token shape from RFC 6749
            // §1.5).
            m.insert("bearer_token", derive_base64ish(seed, "bearer", 60));
            m.insert("tenant_id", derive_guid(seed, "tenant_id"));
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
    // Any `{{` left is an unresolved placeholder (external audit DEC-017,
    // lab PR 178: an unclosed `{{tenant_id` used to pass, needing a `}}`
    // after it, and went into the decoy). The error names it — up to its
    // `}}`, at most 32 characters, escaped — for the operator.
    if let Some(start) = out.find("{{") {
        let rest = &out[start + 2..];
        let name = rest.find("}}").map_or(rest, |end| &rest[..end]);
        let shown: String = name.chars().take(32).flat_map(char::escape_debug).collect();
        return Err(RenderError::UnresolvedPlaceholder(shown));
    }
    Ok(out)
}

// ── deterministic derivation helpers ────────────────────────────────

/// SHA-256(seed || ":" || field) → raw 32 bytes. The
/// `:` separator prevents collision between e.g. `seed =
/// "x"` + `field = "y"` and `seed = "x:y"` + `field = ""`.
fn derive_bytes(seed: &str, field: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
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
fn derive_base32(seed: &str, field: &str, len: usize) -> String {
    debug_assert!(len <= 32);
    let bytes = derive_bytes(seed, field);
    bytes[..len]
        .iter()
        .map(|b| BASE32[(*b as usize) % 32] as char)
        .collect()
}

/// Generate a base64-ish opaque token. Uses the standard
/// base64 alphabet but skips `/` and `+` so the resulting
/// string is grep-friendly + matches the cleaner shape AWS
/// secret keys + most OAuth tokens use in the wild.
fn derive_base64ish(seed: &str, field: &str, len: usize) -> String {
    // Hash a couple of times so we have ≥ len/1.3 raw bytes
    // (base64 expands 3→4). For len up to 60 + a small
    // safety margin, two rounds is plenty.
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&derive_bytes(seed, &format!("{field}/0")));
    buf.extend_from_slice(&derive_bytes(seed, &format!("{field}/1")));
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
        let extra = derive_bytes(seed, &format!("{field}/pad"));
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
fn derive_hex(seed: &str, field: &str, len: usize) -> String {
    debug_assert!(len <= 64);
    let bytes = derive_bytes(seed, field);
    hex::encode(bytes).chars().take(len).collect()
}

/// Generate a decimal string of `len` digits (≤ 38 — u128
/// max). Used for the GCP `client_id` which is a 21-digit
/// integer.
fn derive_decimal(seed: &str, field: &str, len: usize) -> String {
    debug_assert!(len <= 38);
    let bytes = derive_bytes(seed, field);
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
/// from seed + field. Sets the version (0b0100xxxx in
/// byte 6) + variant (0b10xxxxxx in byte 8) bits per the
/// spec so the result passes UUID-format checkers (Azure
/// SDK, .NET Guid.Parse, etc.).
fn derive_guid(seed: &str, field: &str) -> String {
    let mut bytes = derive_bytes(seed, field);
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

/// A `YYYY-MM-DD-HH-MM-SS` stamp in 2023–2025 derived from seed +
/// field (the Azure CLI's default service-principal name suffix).
fn derive_stamp(seed: &str, field: &str) -> String {
    let b = derive_bytes(seed, field);
    format!(
        "{}-{:02}-{:02}-{:02}-{:02}-{:02}",
        2023 + u32::from(b[0] % 3),
        1 + b[1] % 12,
        1 + b[2] % 28,
        b[3] % 24,
        b[4] % 60,
        b[5] % 60
    )
}

/// Generate a PEM-parseable private-key body block (30 lines
/// of 64-char base64). NOT a valid RSA key (the bytes are
/// SHA-derived noise, not a DER-encoded RSAPrivateKey), but
/// `openssl pkey -in <file> -text -noout` accepts the framing
/// and reports "unable to load Private Key" on the body
/// (FORMAT check passes; cryptographic check fails — Level A
/// per §12 Q5, exactly the operator-controlled shape).
fn derive_pem_body(seed: &str, field: &str) -> String {
    let mut buf = Vec::with_capacity(64 * 30);
    for i in 0..15 {
        buf.extend_from_slice(&derive_bytes(seed, &format!("{field}/{i}")));
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
fn derive_basic_auth(seed: &str, field: &str) -> String {
    let user = format!("deploy-{}", short_id(seed));
    let pass = derive_base64ish(seed, field, 32);
    B64.encode(format!("{user}:{pass}").as_bytes())
}

/// Short 8-hex-char identifier used in human-readable names
/// (`deploy-<short>`). External audit DEC-008: hashed from the
/// seed, never a prefix of it — the seed used to start with the
/// operator key fingerprint, which this printed into the decoy.
fn short_id(seed: &str) -> String {
    derive_hex(seed, "short_id", 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Stable seed for deterministic-output assertions (a real one is
    /// 64 hex chars from [`new_content_seed`]).
    const TEST_ID: &str = "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3";

    const FAMILIES: [CredFamily; 5] = [
        CredFamily::Aws,
        CredFamily::Azure,
        CredFamily::Gcp,
        CredFamily::Docker,
        CredFamily::Generic,
    ];

    /// What would tell an attacker the file is a canary, or whose.
    const MARKERS: [&str; 5] = ["northnarrow", "canary", "do not use", "decoy", "nn-l-"];

    fn assert_no_marker(what: &str, body: &str) {
        let lower = body.to_lowercase();
        for m in MARKERS {
            assert!(!lower.contains(m), "{what} carries {m:?}: {body}");
        }
    }

    /// External audit DEC-007: no template, built in or rendered, names
    /// the product or says what the file is.
    #[test]
    fn credential_templates_have_no_product_marker() {
        for family in FAMILIES {
            assert_no_marker(family.as_wire(), family.builtin_template());
            for seed in [TEST_ID, "0", "deadbeef:/home/u/.aws/credentials"] {
                let body = render(family, seed, None).expect("render");
                assert_no_marker(family.as_wire(), &body);
                assert!(!body.contains("{{"), "{family:?} left a placeholder");
            }
        }
    }

    /// External audit DEC-007: the File canary body carries no marker and
    /// no fingerprint, and neither its content nor its size is the same on
    /// every decoy.
    #[test]
    fn file_canary_body_has_no_marker_or_fingerprint() {
        let a = render_file_body(&new_content_seed());
        let b = render_file_body(&new_content_seed());
        for body in [&a, &b] {
            assert!((512..4096).contains(&body.len()));
            assert_no_marker("file body", &String::from_utf8_lossy(body));
            assert!(!String::from_utf8_lossy(body).contains("deadbeef"));
        }
        assert_ne!(a, b, "two deploys, two bodies");
        let seed = "5a".repeat(32);
        assert_eq!(render_file_body(&seed), render_file_body(&seed));
    }

    /// External audit DEC-008: the seed used to be `<operator fp>:<path>`
    /// and `short_id` its first 8 characters, so the fingerprint was
    /// printed into the azure, gcp and docker decoys.
    #[test]
    fn short_id_never_contains_the_operator_fp() {
        let fp = "deadbeef";
        let seed = format!("{fp}:/home/u/.config/creds.json");
        assert_ne!(short_id(&seed), fp);
        for family in FAMILIES {
            let body = render(family, &seed, None).expect("render");
            let decoded: String = body
                .split('"')
                .filter_map(|t| B64.decode(t).ok())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .collect();
            assert!(
                !body.contains(fp) && !decoded.contains(fp),
                "{family:?} carries the operator fingerprint"
            );
        }
    }

    /// External audit DEC-008: every deploy draws its own seed.
    #[test]
    fn content_seeds_are_fresh() {
        let (a, b) = (new_content_seed(), new_content_seed());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        for family in FAMILIES {
            assert_ne!(
                render(family, &a, None).unwrap(),
                render(family, &b, None).unwrap()
            );
        }
    }

    /// External audit DEC-007: an upgraded host keeps the template copied
    /// under `/etc` by an earlier release when install.sh did not replace
    /// it; that one named the product, and the built-in one is used.
    #[test]
    fn a_superseded_shipped_template_on_disk_is_not_used() {
        let old_aws = "[default]\naws_access_key_id = {{access_key_id}}\naws_secret_access_key = \
                       {{secret_access_key}}\nregion = us-east-1\n\n# Canary credential \u{2014} DO NOT \
                       USE. NorthNarrow XDR sovereign\n# deception layer. Any access to this file is, \
                       by construction,\n# evidence of intrusion (see \
                       docs/operator/TAPPA9_5_CANARY_*.md).\n";
        assert!(is_superseded(CredFamily::Aws, old_aws), "the shipped bytes");
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("aws.tmpl"), old_aws).unwrap();
        let body = render(CredFamily::Aws, TEST_ID, Some(dir.path())).unwrap();
        assert_no_marker("aws", &body);
        assert_eq!(body, render(CredFamily::Aws, TEST_ID, None).unwrap());
        // an operator's edit of it is the operator's
        std::fs::write(dir.path().join("aws.tmpl"), format!("{old_aws}# edited\n")).unwrap();
        let body = render(CredFamily::Aws, TEST_ID, Some(dir.path())).unwrap();
        assert!(body.contains("# edited"));
    }

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
        // The Docker Hub entry `docker login` writes.
        let registry = auths
            .get("https://index.docker.io/v1/")
            .expect("Docker Hub entry present");
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

    /// The same seed renders identical bytes across calls, so a
    /// decoy can be re-rendered from the seed its registry row
    /// records (disaster recovery).
    #[test]
    fn render_with_same_seed_is_deterministic() {
        for family in [
            CredFamily::Aws,
            CredFamily::Azure,
            CredFamily::Gcp,
            CredFamily::Docker,
            CredFamily::Generic,
        ] {
            let a = render(family, TEST_ID, None).expect("render");
            let b = render(family, TEST_ID, None).expect("render");
            assert_eq!(a, b, "{family:?} must be deterministic on the seed");
            // Different seed → different content.
            let c = render(family, "deadbeefcafebabe1234567890abcdef", None).expect("render");
            assert_ne!(
                a, c,
                "{family:?} must produce different content for different seeds"
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

    /// External audit DEC-017 (lab PR 178): an unclosed placeholder used
    /// to pass — the check needed a `}}` after the `{{` — and went into the
    /// decoy.
    #[test]
    fn unclosed_placeholder_is_an_error() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("generic.tmpl"),
            "API_TOKEN={{bearer_token}}\nTENANT_ID={{tenant_id\n",
        )
        .unwrap();
        match render(CredFamily::Generic, TEST_ID, Some(dir.path())) {
            Err(RenderError::UnresolvedPlaceholder(p)) => assert_eq!(p, "tenant_id\\n"),
            other => panic!("expected UnresolvedPlaceholder, got {other:?}"),
        }
        // the name shown is bounded, closed or not
        let long = format!("X={{{{{}}}}}\n", "a".repeat(5000));
        std::fs::write(dir.path().join("generic.tmpl"), long).unwrap();
        match render(CredFamily::Generic, TEST_ID, Some(dir.path())) {
            Err(RenderError::UnresolvedPlaceholder(p)) => assert_eq!(p, "a".repeat(32)),
            other => panic!("expected UnresolvedPlaceholder, got {other:?}"),
        }
    }

    /// External audit DEC-017 (lab PR 178): a JSON family's template must
    /// render a JSON document; the built-in ones do.
    #[test]
    fn operator_json_template_must_render_json() {
        for family in [CredFamily::Azure, CredFamily::Gcp, CredFamily::Docker] {
            let body = render(family, TEST_ID, None).expect("built-in renders");
            serde_json::from_str::<serde_json::Value>(&body).expect("built-in is JSON");
            let dir = TempDir::new().unwrap();
            std::fs::write(
                dir.path().join(format!("{}.tmpl", family.as_wire())),
                "{\"id\": \"{{short_id}}\",\n",
            )
            .unwrap();
            assert!(
                matches!(
                    render(family, TEST_ID, Some(dir.path())),
                    Err(RenderError::MalformedOutput { .. })
                ),
                "{family:?}"
            );
        }
        // the ini / env families are not JSON
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("aws.tmpl"), "{ key = {{access_key_id}}\n").unwrap();
        assert!(render(CredFamily::Aws, TEST_ID, Some(dir.path())).is_ok());
    }

    /// External audit DEC-016 (lab PR 178): the templates are write-allowed
    /// at run time; one grown in place was read whole at the next deploy.
    #[test]
    fn oversized_operator_template_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("aws.tmpl");
        let mut body = "aws_access_key_id = {{access_key_id}}\n".to_string();
        std::fs::write(&path, &body).unwrap();
        assert!(render(CredFamily::Aws, TEST_ID, Some(dir.path())).is_ok());
        body.push_str(&"#".repeat(1024 * 1024));
        std::fs::write(&path, &body).unwrap();
        match render(CredFamily::Aws, TEST_ID, Some(dir.path())) {
            Err(RenderError::TemplateRead { path: p, source }) => {
                assert_eq!(p, path);
                assert!(source.to_string().contains("larger than"), "{source}");
            }
            other => panic!("expected TemplateRead, got {other:?}"),
        }
        // at the cap: read
        std::fs::write(&path, "#".repeat(MAX_TEMPLATE_BYTES as usize)).unwrap();
        assert!(render(CredFamily::Aws, TEST_ID, Some(dir.path())).is_ok());
    }

    /// External audit DEC-016 (lab PR 178): a link at a template's name
    /// (`/dev/zero`, or a file elsewhere) is not read through, and refuses
    /// the render instead of falling back to the built-in one.
    #[test]
    fn symlinked_template_is_refused() {
        let dir = TempDir::new().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, "aws_access_key_id = {{access_key_id}}\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join("aws.tmpl")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join("gcp.tmpl")).unwrap();
        for family in [CredFamily::Aws, CredFamily::Gcp] {
            match render(family, TEST_ID, Some(dir.path())) {
                Err(RenderError::TemplateRead { source, .. }) => {
                    assert!(source.to_string().contains("symbolic link"), "{source}")
                }
                other => panic!("expected TemplateRead, got {other:?}"),
            }
        }
        // a directory at the name is refused too
        std::fs::create_dir(dir.path().join("docker.tmpl")).unwrap();
        assert!(matches!(
            render(CredFamily::Docker, TEST_ID, Some(dir.path())),
            Err(RenderError::TemplateRead { .. })
        ));
    }

    /// External audit DEC-016 (lab PR 178): a FIFO at a template's name used
    /// to block the deploy (and its admin connection) until a writer came.
    #[test]
    fn fifo_template_does_not_block() {
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("aws.tmpl");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: mkfifo on a NUL-terminated path in our temp dir.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let template_dir = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(render(CredFamily::Aws, TEST_ID, Some(&template_dir)).is_err());
        });
        let refused = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the render returns instead of blocking on the FIFO");
        assert!(refused, "a FIFO is not a template");
    }

    /// A template that is not UTF-8 is refused, as before.
    #[test]
    fn non_utf8_template_is_refused() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("aws.tmpl"), b"\xff\xfe{{access_key_id}}\n").unwrap();
        assert!(matches!(
            render(CredFamily::Aws, TEST_ID, Some(dir.path())),
            Err(RenderError::TemplateRead { .. })
        ));
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
