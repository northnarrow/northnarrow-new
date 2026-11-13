//! Lot 341 (alpha 2/4): the observe-only `alpha` profile is one more input
//! of the agent's ONE no-enforcement gate. The gate used to be resolved in
//! three places (the integrity phase, the attach's exec quarantine and its
//! exec policy, the capability check each read `--detect-only` and the
//! environment themselves): a new input added in one of them would have
//! left the others enforcing. The inputs are read in one resolver now, and
//! every response path and deny switch the start arms takes its value.

mod support;

use support::{product_code, repo_root};

/// The one place the gate's inputs are read.
const RESOLVER: &str = "agent/src/boot/integrity.rs";

/// The body of `fn name` in `code` (to its matching brace).
fn body<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = start + code[start..].find('{').expect("a body");
    let len = support::matching_brace(&code[open..]);
    &code[open..open + len]
}

/// The parameters of `fn name` (up to its body).
fn signature<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let open = start + code[start..].find('{').expect("a body");
    &code[start..open]
}

/// Named: the gate's inputs — the command line's `--detect-only`, the
/// detect-only variables, the profile's overlay and the install manifest's
/// profile — are read by the resolver only, in the whole product.
#[test]
fn the_no_enforcement_gate_is_resolved_in_one_place() {
    let code = product_code(&repo_root());
    let mut found = Vec::new();
    for (rel, text) in &code {
        for needle in [
            "detect_only_env(",
            "cli.detect_only",
            "ExecutorConfig::from_env(",
            "install_profile(",
            "OverlayKind::Profile,",
        ] {
            let allowed = match needle {
                // the definitions
                "detect_only_env(" => {
                    rel == RESOLVER || rel == "crates/nn-core/src/response/config.rs"
                }
                "ExecutorConfig::from_env(" => {
                    rel == "crates/nn-core/src/response/config.rs"
                        || rel == "crates/nn-linux/src/response/executor.rs"
                }
                "install_profile(" => {
                    rel == RESOLVER || rel == "crates/nn-linux/src/install_manifest.rs"
                }
                "OverlayKind::Profile," => {
                    rel == RESOLVER || rel == "crates/nn-proto/src/admin_signed_payload.rs"
                }
                _ => rel == RESOLVER,
            };
            if text.contains(needle) && !allowed {
                found.push(format!("{rel}: {needle}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "the no-enforcement gate's inputs read outside {RESOLVER}: {found:#?}"
    );
    // and the resolver reads each of them, once, in one function
    let integrity = &code[RESOLVER];
    let resolver = body(integrity, "resolve_gate_with");
    for needle in [
        "overlay_gate.verified(OverlayKind::Profile,",
        "install_profile(&cli.install_manifest,",
        "prof::detect_only_gate(cli.detect_only, env, &profile)",
    ] {
        assert!(resolver.contains(needle), "the resolver lacks {needle}");
    }
    assert!(body(integrity, "resolve_gate").contains("detect_only_env()"));
    // the executor's config and the capability gate take its value
    let check = body(integrity, "check");
    assert!(check.contains("let (profile, gate) = resolve_gate(cli, overlay_gate);"));
    assert!(check.contains("let exec_cfg = executor_config(&gate);"));
    assert!(check.contains("checks::capabilities(boot, detect_only)"));
    assert!(body(integrity, "executor_config").contains("dry_run: gate.on,"));
}

/// Named: every response path and deny switch the start arms takes the one
/// gate — the exec quarantine's holds, the exec policy's denies, the kernel
/// connect deny, the exploit guard, the COMBAT ladder — and the attach no
/// longer recomputes it; the module-load judge takes none.
#[test]
fn every_enforcing_switch_takes_the_resolved_gate() {
    let code = product_code(&repo_root());
    let at = |rel: &str| {
        code.get(rel)
            .unwrap_or_else(|| panic!("{rel} not found"))
            .as_str()
    };
    let attach = at("agent/src/boot/attach.rs");
    let load = body(attach, "load");
    assert!(
        signature(attach, "load").contains("detect_only: bool,"),
        "attach::load takes the gate"
    );
    assert!(load.contains("cli.execq_config(detect_only)"));
    assert!(load.contains("execpol_mode(cli.exec_policy, detect_only)"));
    assert!(body(attach, "execpol_mode").contains("Mode::Enforce if detect_only => Mode::Audit"));
    let boot = at("agent/src/boot/mod.rs");
    assert!(
        boot.contains("export_loaded.on().is_some(),\n        detect_only,\n    )"),
        "the start hands attach::load the resolved gate"
    );
    let policy = at("agent/src/boot/policy.rs");
    assert!(policy.contains("arming(cli.net_connect_deny, detect_only)"));
    let response = at("agent/src/boot/response.rs");
    assert!(response.contains("effective_response(requested, detect_only)"));
    // the module-load judge takes NO gate (the review of #550, F2/F7): an
    // untrusted module is refused under every profile, as kexec is
    let tasks = at("agent/src/boot/tasks.rs");
    assert!(tasks.contains("module_trust::start(module_kernel)"));
    assert!(!tasks.contains("observe_only"));
    let module = at("agent/src/module_trust/mod.rs");
    assert!(signature(module, "kernel_mode").contains("(want: u64, deny_ok: bool)"));
    assert!(body(module, "look").contains("kernel_mode(want.mode, self.deny_ok)"));
    // the COMBAT ladder and the response build take the start's value
    assert!(boot.contains("&isolator,\n        detect_only,\n        &audit_log,"));
    // the exec quarantine's controller kills only when it enforces — a kill
    // an enforcing run before it owed included
    let ctl = at("agent/src/execq/controller.rs");
    assert!(body(ctl, "recover").contains("let kill = owed_kill && self.s.policy.enforce;"));
    assert!(body(ctl, "release_unreported").contains("let kill = kill && self.s.policy.enforce;"));
}

/// Named: a suppressed response says which action would have run.
#[test]
fn a_suppressed_response_says_what_would_have_run() {
    let code = product_code(&repo_root());
    let store = &code["agent/src/detection_store.rs"];
    let describe = body(store, "describe_response");
    assert!(describe.contains("nn_core::response::profile::would_have("));
    assert!(!describe.contains("\"suppressed (detect-only)\""));
}

/// Named (lot 341, the review of #550 F8): the start signs an unsigned
/// downgrade — after its own `agent_boot`, from the chain's previous boot
/// and the resolved profile — and the profile reaches the attest phase.
#[test]
fn the_start_signs_an_unsigned_downgrade_to_alpha() {
    let code = product_code(&repo_root());
    let at = |rel: &str| {
        code.get(rel)
            .unwrap_or_else(|| panic!("{rel} not found"))
            .as_str()
    };
    let evidence = at("agent/src/boot/evidence.rs");
    assert!(signature(evidence, "attest")
        .contains("profile: &nn_core::response::profile::ResolvedProfile,"));
    let attest = body(evidence, "attest");
    let probe = attest
        .find("match log.boot_probe(")
        .expect("the boot's row");
    let check = attest
        .find("nn_core::response::profile::unsigned_downgrade(\n                            log.previous_boot_enforced(),\n                            profile,\n                        )")
        .expect("the downgrade judged from the chain and the profile");
    let sign = attest
        .find("log.attest_profile_downgrade(&detail)")
        .expect("and signed");
    assert!(probe < check && check < sign);
    let boot = at("agent/src/boot/mod.rs");
    assert!(boot.contains("        &detect_only_source,\n        &profile,\n        integrity,"));
}
