// ── Tappa 10 N7 — net admin dispatches ────────────────────────────
//
// Four dispatches mirroring the FIM C6 + canary K6 shape:
//   * Auth via `verify_signed_payload_quorum` (1-of-N per §13 Q6).
//   * Op-extra-variant defensive check.
//   * Emit audit-grade `info!` line with the matched signer fp.
//   * External audit NN-AUD-081: every verb answers from the
//     chained logs the net drain writes (`netflow.jsonl`,
//     `netflow_listeners.jsonl`, at the paths in
//     [`AdminReadPaths`]); none answers an empty Success
//     without having read them.

/// Default on-disk location of the chained NetFlow log (design
/// §4.4 + §10). The Tappa 10 N8 deploy commit drops a zero-byte
/// placeholder here via `install.sh` + `bootstrap_netflow_log` at
/// agent startup. `dispatch_net_flows` tolerates the file being
/// absent — returns empty body + 0 count without erroring.
pub const DEFAULT_NETFLOW_JSONL_PATH: &str = "/var/lib/northnarrow/netflow.jsonl";

/// `net flows`: the newest rows of the netflow log at
/// `--netflow-file` (external audit NN-AUD-082), active file then
/// archives, newest first (NN-AUD-080).
fn dispatch_net_flows(
    req: NetFlowsRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> NetFlowsResponse {
    use nn_proto::admin_signed_payload::NetFlowsExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::NetRead],
        OperationCode::NetFlows,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return NetFlowsResponse {
                result: map_admin_auth_error(e, "net-flows"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;

    let since = match &req.payload.extra {
        OperationExtra::NetFlows(NetFlowsExtra { since_unix_ts }) => *since_unix_ts,
        _ => {
            warn!("net-flows payload extra is not NetFlows variant");
            return NetFlowsResponse {
                result: AdminResult::UnknownOperation,
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };

    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.netflow, since, None, usize::MAX);
    info!(
        target: "admin.net_flows",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        entries = entries_count,
        truncated = entries_truncated,
        "net flows served"
    );
    NetFlowsResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// `net listeners`: the newest rows of the listener log at
/// `--netflow-listeners-file` — one row per `listen()` the agent saw
/// (`inet_csk_listen_start`), newest first. Listen events, not a snapshot
/// of the sockets open now: a closed listener stays in the log. External
/// audit NN-AUD-081: this verb answered Success with an empty body while
/// the log was being written.
fn dispatch_net_listeners(
    req: NetListenersRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> NetListenersResponse {
    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::NetRead],
        OperationCode::NetListeners,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return NetListenersResponse {
                result: map_admin_auth_error(e, "net-listeners"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;

    if !matches!(&req.payload.extra, OperationExtra::NetListeners(_)) {
        warn!("net-listeners payload extra is not NetListeners variant");
        return NetListenersResponse {
            result: AdminResult::UnknownOperation,
            entries_jsonl: String::new(),
            entries_count: 0,
            entries_truncated: false,
        };
    }

    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.netflow_listeners, None, None, usize::MAX);
    info!(
        target: "admin.net_listeners",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        entries = entries_count,
        truncated = entries_truncated,
        "net listeners served"
    );
    NetListenersResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}

/// The fields of a netflow row the `net resolve` / `net fingerprint`
/// filters look at (serde ignores the others).
#[derive(serde::Deserialize)]
struct NetflowRowView {
    #[serde(default)]
    ts: String,
    #[serde(default)]
    flow_id: String,
    #[serde(default)]
    dst_addr: String,
    resolved_hostname: Option<String>,
}

fn netflow_row_view(line: &str) -> Option<NetflowRowView> {
    serde_json::from_str(line).ok()
}

/// `net resolve <ip>`: the hostname the agent attributed (DNS cache, same
/// process) to the newest retained netflow row whose destination is `ip`,
/// and when that row was written. External audit NN-AUD-081: this verb
/// answered Success with no name without reading anything; it now answers
/// from the netflow log, and `qname: None` means no retained flow to that
/// address carries a name. An address that does not parse is refused.
fn dispatch_net_resolve(
    req: NetResolveRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> NetResolveResponse {
    use nn_proto::admin_signed_payload::NetResolveExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::NetRead],
        OperationCode::NetResolve,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return NetResolveResponse {
                result: map_admin_auth_error(e, "net-resolve"),
                qname: None,
                queried_at_unix_ts: None,
            };
        }
    };
    *fps_out = matched_fps;

    let refused = NetResolveResponse {
        result: AdminResult::UnknownOperation,
        qname: None,
        queried_at_unix_ts: None,
    };
    let ip_query = match &req.payload.extra {
        OperationExtra::NetResolve(NetResolveExtra { ip }) => ip.clone(),
        _ => {
            warn!("net-resolve payload extra is not NetResolve variant");
            return refused;
        }
    };
    let Ok(target) = ip_query.trim().parse::<std::net::IpAddr>() else {
        warn!(ip = %ip_query, "net-resolve: not an IP address");
        return refused;
    };
    let target = target.to_canonical();
    // Substring pre-filter, then the parsed check (an IPv4 target also
    // matches an IPv4-mapped IPv6 destination).
    let needle = target.to_string();
    let keep = |line: &str| {
        line.contains(&needle)
            && netflow_row_view(line).is_some_and(|r| {
                r.dst_addr
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|a| a.to_canonical() == target)
                    && r.resolved_hostname
                        .as_deref()
                        .is_some_and(|h| !h.is_empty())
            })
    };
    let (body, _, _) = read_tail_jsonl(&read_paths.netflow, None, Some(&keep), 1);
    let newest = body.lines().next().and_then(netflow_row_view);
    let qname = newest.as_ref().and_then(|r| r.resolved_hostname.clone());
    let queried_at_unix_ts = newest.as_ref().and_then(|r| {
        chrono::DateTime::parse_from_rfc3339(&r.ts)
            .ok()
            .and_then(|t| u64::try_from(t.timestamp()).ok())
    });
    info!(
        target: "admin.net_resolve",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        ip = %target,
        found = qname.is_some(),
        "net resolve served"
    );
    NetResolveResponse {
        result: AdminResult::Success,
        qname,
        queried_at_unix_ts,
    }
}

/// `net fingerprint <flow_id>`: the netflow rows of that flow (active
/// file and archives, newest first), with their `ja3` / `ja4` / `sni`.
/// External audit NN-AUD-081: this verb answered Success with an empty
/// body without reading anything. The rows are returned whether or not
/// they carry a fingerprint: the ClientHello capture that fills those
/// fields is not wired (`FlowTracker::attach_tls`), so a filter on them
/// would always answer empty. A null field says "not captured"; an empty
/// body says the flow is not in the retained log. A flow id that is not
/// 1 to 64 hex digits is refused.
fn dispatch_net_fingerprint(
    req: NetFingerprintRequest,
    auth: &ConnAuth<'_>,
    read_paths: &AdminReadPaths,
    fps_out: &mut Vec<String>,
) -> NetFingerprintResponse {
    use nn_proto::admin_signed_payload::NetFingerprintExtra;

    let server_now = now_unix_secs();
    let sigs: Vec<[u8; 64]> = req.signatures.iter().map(|s| s.signature).collect();
    let (_token, matched_fps) = match auth.verify_signed_payload_quorum(
        &req.payload,
        &sigs,
        1,
        &[Role::NetRead],
        OperationCode::NetFingerprint,
        server_now,
    ) {
        Ok(t) => t,
        Err(e) => {
            return NetFingerprintResponse {
                result: map_admin_auth_error(e, "net-fingerprint"),
                entries_jsonl: String::new(),
                entries_count: 0,
                entries_truncated: false,
            };
        }
    };
    *fps_out = matched_fps;

    let refused = NetFingerprintResponse {
        result: AdminResult::UnknownOperation,
        entries_jsonl: String::new(),
        entries_count: 0,
        entries_truncated: false,
    };
    let flow_id = match &req.payload.extra {
        OperationExtra::NetFingerprint(NetFingerprintExtra { flow_id }) => flow_id.clone(),
        _ => {
            warn!("net-fingerprint payload extra is not NetFingerprint variant");
            return refused;
        }
    };
    let flow_id = flow_id.trim().to_ascii_lowercase();
    if flow_id.is_empty() || flow_id.len() > 64 || !flow_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        warn!(flow_id = %flow_id, "net-fingerprint: flow id is not hex");
        return refused;
    }
    let keep = |line: &str| {
        line.contains(&flow_id) && netflow_row_view(line).is_some_and(|r| r.flow_id == flow_id)
    };
    let (entries_jsonl, entries_count, entries_truncated) =
        read_tail_jsonl(&read_paths.netflow, None, Some(&keep), usize::MAX);
    info!(
        target: "admin.net_fingerprint",
        signer_fp = %fps_out.first().map(String::as_str).unwrap_or(""),
        flow_id = %flow_id,
        entries = entries_count,
        truncated = entries_truncated,
        "net fingerprint served"
    );
    NetFingerprintResponse {
        result: AdminResult::Success,
        entries_jsonl,
        entries_count,
        entries_truncated,
    }
}
