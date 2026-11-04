//! The `export` worker's life (lot 276): `northnarrow-agent --worker export
//! --ipc-fd 3`, started by the core as `northnarrow-worker`. Its sandbox
//! first (`nn_linux::sandbox::Profile::export`: Landlock with its one
//! directory, the seccomp allowlist of its sinks), then each request
//! answered by nn-export's worker state — the only process where rows are
//! parsed as JSON, mapped to OCSF, and TLS runs.

use std::path::Path;

use nn_linux::sandbox;
use nn_linux::worker::serve::{self, Args};
use nn_proto::ipc::{Answer, Refusal, Request, EXPORT_DIR};

/// The worker's whole life; its exit status.
pub fn main(a: &Args) -> i32 {
    let profile = sandbox::Profile::export(
        a.ipc_fd,
        nn_export::net::SOCK_FLAGS,
        nn_export::jsonl::OPEN_FLAGS,
    );
    let mut w = nn_export::worker::ExportWorker::new(Path::new(EXPORT_DIR));
    serve::run(a, &profile, &mut |req| answer(&mut w, req))
}

/// One request's answer (the bounds checked again on this side: a request
/// out of them is refused, never served).
fn answer(w: &mut nn_export::worker::ExportWorker, req: &Request) -> Answer {
    if req.check().is_err() {
        return Answer::Refused(Refusal::OutOfBounds);
    }
    match req {
        Request::Ping => Answer::Pong,
        Request::ExportSetup(s) => Answer::ExportSetup(w.setup(s, &mut |port| {
            sandbox::pin_tcp_connect(port, nn_export::net::SOCK_FLAGS)
        })),
        Request::ExportRows(r) => Answer::ExportRows(w.rows(r)),
        // the parse worker's requests, and the lab's faults (the parse
        // worker's): never asked of this one
        Request::DnsNames(_)
        | Request::TlsClientHello(_)
        | Request::DnsAnswers(_)
        | Request::DebugCrash
        | Request::DebugHang => Answer::Refused(Refusal::OutOfBounds),
    }
}
