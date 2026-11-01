//! The core's way to nn-parse's parsers (Wave 4 restructure, R14b — plan
//! §3.1, §3.5): through the `parse` worker, never in the core's process.
//!
//! [`ParseClient`] batches a pass's DNS names into requests whose worst
//! answer fits a frame (`nn_proto::ipc::worst_answer`), sends them with a
//! deadline ([`NAMES_TIMEOUT`]) and returns one decode per name, checked by
//! the supervisor against its request (`nn_proto::ipc::check_response`).
//! When the worker does not answer — not started yet, restarting, disabled,
//! out of time, killed for a violation — a name has no decode (`None`): the
//! caller does without (an event with no name), and the core does not parse
//! the bytes instead (plan §5). Those names are counted, and said at most
//! every [`UNPARSED_LOG_EVERY`] in the journal; the worker's failures are
//! the supervisor's signed degradations.
//!
//! The TLS ClientHello and the DNS answers have no producer in this build
//! (no sensor captures them: `nn_core::net::blocklist::TLS_FINGERPRINT_PRODUCER`);
//! [`ParseClient::client_hello`] and [`ParseClient::dns_answers`] are the one
//! way a future one reaches their parsers.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use nn_proto::ipc::{
    worst_answer, Answer, QnameIn, QnameOut, Request, TlsOut, WorkerKind, FRAME_MARGIN, MAX_BATCH,
    MAX_FRAME,
};
use tracing::warn;

use super::{WorkerError, Workers};

/// A batch of names' deadline: the DNS pump waits at most this for a
/// pass's decode (a hung worker is killed at it, and the next batches find
/// it restarting).
pub const NAMES_TIMEOUT: Duration = Duration::from_millis(250);
/// A ClientHello's or a DNS answer's deadline.
pub const ONE_TIMEOUT: Duration = Duration::from_millis(250);
/// The names left without a decode are said at most this often.
pub const UNPARSED_LOG_EVERY: Duration = Duration::from_secs(10);

/// The core's handle on the parse worker. `None` workers: there is no
/// worker in this run (a test, a tool): every decode is `None`.
#[derive(Debug, Default)]
pub struct ParseClient {
    workers: Option<Workers>,
    /// Names asked for and decoded, and left without a decode.
    pub decoded: u64,
    pub unparsed: u64,
    unparsed_since_log: u64,
    last_log: Option<Instant>,
    last_why: String,
}

impl ParseClient {
    pub fn new(workers: Option<Workers>) -> Self {
        Self {
            workers,
            ..Self::default()
        }
    }

    /// One decode per input, in order (`None`: not decoded).
    pub fn names(&mut self, inputs: Vec<QnameIn>) -> Vec<Option<QnameOut>> {
        let n = inputs.len();
        let mut out: Vec<Option<QnameOut>> = Vec::with_capacity(n);
        for batch in batches(inputs) {
            let len = batch.len();
            match self.ask_names(batch) {
                Ok(decoded) => {
                    self.decoded += len as u64;
                    out.extend(decoded.into_iter().map(Some));
                }
                Err(why) => {
                    self.unparsed += len as u64;
                    self.unparsed_since_log += len as u64;
                    self.last_why = why;
                    out.extend(std::iter::repeat_n(None, len));
                }
            }
        }
        self.maybe_log();
        out
    }

    fn ask_names(&self, batch: Vec<QnameIn>) -> Result<Vec<QnameOut>, String> {
        let Some(w) = &self.workers else {
            return Err("no parse worker in this run".to_string());
        };
        match w.request(WorkerKind::Parse, &Request::DnsNames(batch), NAMES_TIMEOUT) {
            Ok(Answer::DnsNames(v)) => Ok(v),
            Ok(Answer::Refused(why)) => Err(format!("the worker refused the batch: {why}")),
            Ok(_) => Err("an answer of another kind".to_string()),
            Err(e) => Err(describe(&e)),
        }
    }

    fn maybe_log(&mut self) {
        if self.unparsed_since_log == 0 {
            return;
        }
        let now = Instant::now();
        if self
            .last_log
            .is_some_and(|t| now.duration_since(t) < UNPARSED_LOG_EVERY)
        {
            return;
        }
        warn!(
            names = self.unparsed_since_log,
            total = self.unparsed,
            why = %self.last_why,
            "DNS names left without a decode: the parse worker did not answer; their events carry no name (the core does not parse them itself)"
        );
        self.unparsed_since_log = 0;
        self.last_log = Some(now);
    }

    /// A TLS ClientHello's fingerprint (`None`: the worker did not answer).
    pub fn client_hello(&self, bytes: &[u8]) -> Option<TlsOut> {
        let w = self.workers.as_ref()?;
        match w.request(
            WorkerKind::Parse,
            &Request::TlsClientHello(bytes.to_vec()),
            ONE_TIMEOUT,
        ) {
            Ok(Answer::Tls(t)) => Some(t),
            _ => None,
        }
    }

    /// A DNS response's A and AAAA answers (`None`: the worker did not
    /// answer).
    pub fn dns_answers(&self, bytes: &[u8]) -> Option<(Vec<Ipv4Addr>, Vec<Ipv6Addr>)> {
        let w = self.workers.as_ref()?;
        match w.request(
            WorkerKind::Parse,
            &Request::DnsAnswers(bytes.to_vec()),
            ONE_TIMEOUT,
        ) {
            Ok(Answer::DnsAnswers { a, aaaa }) => Some((
                a.into_iter().map(Ipv4Addr::from).collect(),
                aaaa.into_iter().map(Ipv6Addr::from).collect(),
            )),
            _ => None,
        }
    }
}

fn describe(e: &WorkerError) -> String {
    format!("{e}")
}

/// `inputs` cut into requests the protocol takes: at most [`MAX_BATCH`]
/// names, their worst answer within a frame. A name longer than any frame
/// could answer is not possible (`MAX_QNAME_IN`'s worst answer is far
/// below it).
pub fn batches(inputs: Vec<QnameIn>) -> Vec<Vec<QnameIn>> {
    let room = MAX_FRAME - FRAME_MARGIN;
    let mut out: Vec<Vec<QnameIn>> = Vec::new();
    let mut cur: Vec<QnameIn> = Vec::new();
    let mut used = 0usize;
    for q in inputs {
        let need = worst_answer(q.bytes.len());
        if !cur.is_empty() && (cur.len() == MAX_BATCH || used + need > room) {
            out.push(std::mem::take(&mut cur));
            used = 0;
        }
        used += need;
        cur.push(q);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_proto::ipc::{QnameForm, MAX_QNAME_IN};

    fn q(n: usize) -> QnameIn {
        QnameIn {
            bytes: vec![b'a'; n],
            form: QnameForm::Wire,
        }
    }

    #[test]
    fn a_pass_is_cut_into_requests_the_protocol_takes() {
        // short names: by count
        let b = batches((0..1200).map(|_| q(20)).collect());
        assert_eq!(b.iter().map(Vec::len).collect::<Vec<_>>(), [512, 512, 176]);
        // the longest names: by the answer's frame
        let b = batches((0..200).map(|_| q(MAX_QNAME_IN)).collect());
        assert!(b.len() > 1);
        for batch in &b {
            assert!(Request::DnsNames(batch.clone()).check().is_ok());
        }
        assert_eq!(b.iter().map(Vec::len).sum::<usize>(), 200);
        assert!(batches(Vec::new()).is_empty());
        // the order kept
        let b = batches(
            (1..=600)
                .map(q)
                .map(|mut x| {
                    x.bytes.truncate(x.bytes.len().min(300));
                    x
                })
                .collect(),
        );
        let lens: Vec<usize> = b.iter().flatten().map(|x| x.bytes.len()).collect();
        assert_eq!(lens.len(), 600);
        assert!(lens.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn without_a_worker_nothing_is_decoded_and_it_is_counted() {
        let mut c = ParseClient::new(None);
        let got = c.names(vec![q(5), q(6)]);
        assert_eq!(got, vec![None, None]);
        assert_eq!((c.decoded, c.unparsed), (0, 2));
        assert!(c.client_hello(&[0x16]).is_none());
        assert!(c.dns_answers(&[0; 12]).is_none());
    }
}
