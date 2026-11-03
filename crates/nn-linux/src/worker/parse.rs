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
//! Lot 275: the TLS ClientHello sensor's pump fingerprints each hello through
//! [`ParseClient::client_hello`], the DNS response sensor's pump decodes each
//! response through [`ParseClient::dns_answers`] — the one way their bytes
//! reach a parser.

use std::time::{Duration, Instant};

use nn_proto::ipc::{
    worst_answer, Answer, DnsAnswersOut, QnameIn, QnameOut, Request, TlsOut, WorkerKind,
    FRAME_MARGIN, MAX_BATCH, MAX_FRAME,
};
use tracing::warn;

use super::{WorkerError, Workers};

/// A batch of names' deadline: the DNS pump waits at most this for a
/// pass's decode (a hung worker is killed at it, and the next batches find
/// it restarting). Review of #481 (R14b-2): well under the connects' wait
/// for the DNS pass (`net::dns_ingest::INGEST_WAIT`, 250 ms; a quarter at
/// most, pinned by a test) — a worker slower than this is a hang, signed,
/// never a pass slowed to the connects' wait in silence. The honest round
/// trip is about a millisecond.
pub const NAMES_TIMEOUT: Duration = Duration::from_millis(50);
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
    /// Records of a DNS pass paired with no entry of `names` (never, by
    /// its contract: one entry per name; counted if it ever happened).
    pub mismatched: u64,
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
            let got = self.ask_names(batch);
            self.fill(&mut out, len, got);
        }
        debug_assert_eq!(out.len(), n);
        self.maybe_log();
        out
    }

    /// One batch's decodes into `out`: exactly `len` entries whatever came
    /// back (review of #481, R14b-5: a short answer never drops a name's
    /// event — the supervisor refuses one already; this holds without it).
    fn fill(
        &mut self,
        out: &mut Vec<Option<QnameOut>>,
        len: usize,
        got: Result<Vec<QnameOut>, String>,
    ) {
        let got = match got {
            Ok(v) if v.len() == len => Ok(v),
            Ok(v) => Err(format!("{} decodes for {len} names", v.len())),
            Err(why) => Err(why),
        };
        match got {
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

    fn ask_names(&self, batch: Vec<QnameIn>) -> Result<Vec<QnameOut>, String> {
        let Some(w) = &self.workers else {
            return Err("no parse worker in this run".to_string());
        };
        // a refusal or an answer of another kind is the supervisor's
        // violation (the worker killed, signed) before it gets here
        match w.request(WorkerKind::Parse, &Request::DnsNames(batch), NAMES_TIMEOUT) {
            Ok(Answer::DnsNames(v)) => Ok(v),
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
            why = %nn_model::log_escape::Escaped(self.last_why.as_str()),
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

    /// Lot 275: a DNS response's question and A, AAAA and CNAME records
    /// (`None`: the worker did not answer; `Some(None)`: the bytes are no
    /// DNS response).
    pub fn dns_answers(&self, bytes: &[u8]) -> Option<Option<DnsAnswersOut>> {
        let w = self.workers.as_ref()?;
        match w.request(
            WorkerKind::Parse,
            &Request::DnsAnswers(bytes.to_vec()),
            ONE_TIMEOUT,
        ) {
            Ok(Answer::DnsAnswers(out)) => Some(out),
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

    /// Review of #481 (R14b-5, RB2): a batch answered with fewer or more
    /// decodes than names leaves every name of it without a decode — one
    /// entry per name, counted — never a shorter list whose pairing with
    /// the records would drop events.
    #[test]
    fn a_short_or_long_answer_never_drops_a_name() {
        let mut c = ParseClient::new(None);
        let name = |s: &str| QnameOut {
            name: s.into(),
            end: None,
        };
        let mut out = Vec::new();
        c.fill(&mut out, 3, Ok(vec![name("a")]));
        c.fill(&mut out, 1, Ok(vec![name("b"), name("c")]));
        c.fill(&mut out, 2, Ok(Vec::new()));
        assert_eq!(out, vec![None; 6]);
        assert_eq!((c.decoded, c.unparsed), (0, 6));
        assert!(
            c.last_why.contains("0 decodes for 2 names"),
            "{}",
            c.last_why
        );
        c.fill(&mut out, 2, Ok(vec![name("d"), name("e")]));
        assert_eq!(out.len(), 8);
        assert_eq!(out[6].as_ref().map(|q| q.name.as_str()), Some("d"));
        assert_eq!((c.decoded, c.unparsed), (2, 6));
    }
}
