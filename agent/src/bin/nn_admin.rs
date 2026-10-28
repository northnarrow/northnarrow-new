//! `nn-admin`, the operator's client: nn-admin's command line on the agent's
//! host (Wave 4 restructure, R10, lab PR 259). The logic is nn-admin's
//! (`crates/nn-admin`); the binary stays in the agent package, which binds it
//! to the host (`CARGO_BIN_EXE_nn-admin`, the SBOMs, the release).

fn main() -> std::process::ExitCode {
    nn_admin::main(&northnarrow_agent::admin_host::AgentAdminHost)
}
