//! Lot 275 (C07 1→2): a DNS response as the DNS response sensor reads it —
//! the question, the response code and the answer section's A, AAAA and
//! CNAME records with their TTLs, names decoded through compression
//! pointers ([`parse_response`]).
//!
//! The bytes are what a process received from port 53: written by whoever
//! answers, and cut at the sensor's 512 bytes. Every read is bounded by the
//! message; a compression pointer must point back, before the name that
//! uses it (RFC 1035 §4.1.4 points at "a prior occurrence"), so a walk
//! cannot loop; a name is at most 255 octets on the wire and its labels at
//! most 63; the records kept are at most [`MAX_RECORDS`]. A message that
//! ends inside the answer section — the sensor's cut — gives the records
//! before the cut, [`DnsResponse::complete`] false. The walk is fuzzed
//! (`fuzz/fuzz_targets/dns_records.rs`).

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

const HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// The header's TC bit: the server truncated the response.
const FLAG_TC: u16 = 0x0200;
/// RFC 1035 §2.3.4: a name's wire form, its root label included.
const MAX_NAME_WIRE: usize = 255;
/// Pointers one name may follow: more than a legal name needs (each pointer
/// goes strictly back, and a name has at most 127 labels).
const MAX_HOPS: usize = 128;

/// The most records a response gives (the IPC answer's bound: each name may
/// decode to four characters a byte).
pub const MAX_RECORDS: usize = 24;

/// One kept record of the answer section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerRecord {
    A {
        name: String,
        ttl: u32,
        addr: Ipv4Addr,
    },
    Aaaa {
        name: String,
        ttl: u32,
        addr: Ipv6Addr,
    },
    Cname {
        name: String,
        ttl: u32,
        target: String,
    },
}

impl AnswerRecord {
    /// The record's owner name.
    pub fn name(&self) -> &str {
        match self {
            AnswerRecord::A { name, .. }
            | AnswerRecord::Aaaa { name, .. }
            | AnswerRecord::Cname { name, .. } => name,
        }
    }
}

/// What [`parse_response`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    /// The question's name, in the presentation form of
    /// [`crate::dns_qname::decode_dns_qname`] (no trailing dot).
    pub qname: String,
    pub qtype: u16,
    /// The header's RCODE (0 no error, 3 the name does not exist).
    pub rcode: u8,
    /// The A, AAAA and CNAME records of class IN, in the message's order;
    /// other records are stepped over.
    pub answers: Vec<AnswerRecord>,
    /// Every answer was read: the server did not truncate it (TC), the
    /// message did not end inside the answer section, held no malformed
    /// record (an A or AAAA of another length included) before its end, and
    /// had no more than [`MAX_RECORDS`] kept records.
    pub complete: bool,
}

/// `bytes` as a DNS response: `None` when they are no response — shorter
/// than a header, a query (QR bit clear), not exactly one question, or a
/// question that does not read.
pub fn parse_response(bytes: &[u8]) -> Option<DnsResponse> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    let flags = be16(bytes, 2)?;
    if flags & 0x8000 == 0 {
        return None;
    }
    let qdcount = be16(bytes, 4)?;
    let ancount = be16(bytes, 6)?;
    if qdcount != 1 {
        return None;
    }
    let (qname, mut pos) = read_name(bytes, HEADER_LEN)?;
    let qtype = be16(bytes, pos)?;
    pos += 4; // type, class
    if pos > bytes.len() {
        return None;
    }
    let mut out = DnsResponse {
        qname,
        qtype,
        rcode: (flags & 0x000f) as u8,
        answers: Vec::new(),
        // review of #495, D1: the TC bit — the server cut the response
        // itself (the client asks again over TCP, which is not read)
        complete: flags & FLAG_TC == 0,
    };
    for _ in 0..ancount {
        let Some((name, after)) = read_name(bytes, pos) else {
            out.complete = false;
            break;
        };
        let (Some(rtype), Some(class), Some(ttl), Some(rdlen)) = (
            be16(bytes, after),
            be16(bytes, after + 2),
            be32(bytes, after + 4),
            be16(bytes, after + 8),
        ) else {
            out.complete = false;
            break;
        };
        let rdata_at = after + 10;
        let rdlen = usize::from(rdlen);
        let Some(rdata) = bytes.get(rdata_at..rdata_at + rdlen) else {
            out.complete = false;
            break;
        };
        pos = rdata_at + rdlen;
        if class != CLASS_IN {
            continue;
        }
        let record = match (rtype, rdata) {
            (TYPE_A, [a, b, c, d]) => AnswerRecord::A {
                name,
                ttl,
                addr: Ipv4Addr::new(*a, *b, *c, *d),
            },
            (TYPE_AAAA, r) if r.len() == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(r);
                AnswerRecord::Aaaa {
                    name,
                    ttl,
                    addr: Ipv6Addr::from(o),
                }
            }
            (TYPE_CNAME, _) => {
                // the target is read in the whole message (it may point
                // back) and must end inside its RDATA
                match read_name(bytes, rdata_at) {
                    Some((target, end)) if end == pos => AnswerRecord::Cname { name, ttl, target },
                    _ => {
                        out.complete = false;
                        break;
                    }
                }
            }
            // a malformed A or AAAA (D1): stepped over, the response not whole
            (TYPE_A | TYPE_AAAA, _) => {
                out.complete = false;
                continue;
            }
            // another type: stepped over
            _ => continue,
        };
        if out.answers.len() == MAX_RECORDS {
            out.complete = false;
            break;
        }
        out.answers.push(record);
    }
    Some(out)
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// The name at `start`, decoded, and where the bytes after it begin (after
/// its root label, or after its first pointer). `None` for a name that does
/// not read: past the message, a reserved length octet, a label over 63, a
/// pointer that does not point back, a name over 255 octets.
pub fn read_name(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut wire = 0usize;
    // a pointer must point before the label run it ends
    let mut floor = start;
    for _ in 0..MAX_HOPS {
        loop {
            let len = *bytes.get(pos)?;
            match len & 0xC0 {
                0x00 => {
                    let len = usize::from(len);
                    wire += 1 + len;
                    if wire > MAX_NAME_WIRE {
                        return None;
                    }
                    if len == 0 {
                        return Some((out, end.unwrap_or(pos + 1)));
                    }
                    let label = bytes.get(pos + 1..pos + 1 + len)?;
                    if !out.is_empty() {
                        out.push('.');
                    }
                    for &b in label {
                        if (32..=126).contains(&b) && b != b'.' && b != b'\\' {
                            out.push(char::from(b));
                        } else {
                            out.push('\\');
                            out.push(char::from(b'0' + b / 100));
                            out.push(char::from(b'0' + (b / 10) % 10));
                            out.push(char::from(b'0' + b % 10));
                        }
                    }
                    pos += 1 + len;
                }
                0xC0 => {
                    let lo = *bytes.get(pos + 1)?;
                    let target = (usize::from(len & 0x3F) << 8) | usize::from(lo);
                    if target >= floor {
                        return None;
                    }
                    if end.is_none() {
                        end = Some(pos + 2);
                    }
                    floor = target;
                    pos = target;
                    break;
                }
                _ => return None,
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::vec;

    fn header(p: &mut Vec<u8>, flags: u16, qd: u16, an: u16) {
        p.extend_from_slice(&0x1234u16.to_be_bytes());
        p.extend_from_slice(&flags.to_be_bytes());
        p.extend_from_slice(&qd.to_be_bytes());
        p.extend_from_slice(&an.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]);
    }

    fn name(p: &mut Vec<u8>, n: &str) {
        for l in n.split('.') {
            p.push(l.len() as u8);
            p.extend_from_slice(l.as_bytes());
        }
        p.push(0);
    }

    fn rr(p: &mut Vec<u8>, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) {
        p.extend_from_slice(owner);
        p.extend_from_slice(&rtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&ttl.to_be_bytes());
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend_from_slice(rdata);
    }

    /// `www.example.com CNAME edge.cdn.net; edge.cdn.net A 192.0.2.7, A
    /// 192.0.2.8; AAAA 2001:db8::7`, with pointers: the CNAME's owner is
    /// the question (offset 12), the A records' owner its target.
    fn cdn_response() -> Vec<u8> {
        let mut p = Vec::new();
        header(&mut p, 0x8180, 1, 4);
        name(&mut p, "www.example.com");
        p.extend_from_slice(&[0, 1, 0, 1]);
        let mut target = Vec::new();
        name(&mut target, "edge.cdn.net");
        let cname_rdata_at = p.len() + 12;
        rr(&mut p, &[0xC0, 12], TYPE_CNAME, 300, &target);
        let ptr = [0xC0, cname_rdata_at as u8];
        rr(&mut p, &ptr, TYPE_A, 20, &[192, 0, 2, 7]);
        rr(&mut p, &ptr, TYPE_A, 30, &[192, 0, 2, 8]);
        let v6: Ipv6Addr = "2001:db8::7".parse().unwrap();
        rr(&mut p, &ptr, TYPE_AAAA, 40, &v6.octets());
        p
    }

    #[test]
    fn a_cdn_answer_reads_with_its_chain_and_ttls() {
        let r = parse_response(&cdn_response()).expect("a response");
        assert_eq!(r.qname, "www.example.com");
        assert_eq!((r.qtype, r.rcode), (1, 0));
        assert!(r.complete);
        assert_eq!(
            r.answers,
            vec![
                AnswerRecord::Cname {
                    name: "www.example.com".into(),
                    ttl: 300,
                    target: "edge.cdn.net".into()
                },
                AnswerRecord::A {
                    name: "edge.cdn.net".into(),
                    ttl: 20,
                    addr: Ipv4Addr::new(192, 0, 2, 7)
                },
                AnswerRecord::A {
                    name: "edge.cdn.net".into(),
                    ttl: 30,
                    addr: Ipv4Addr::new(192, 0, 2, 8)
                },
                AnswerRecord::Aaaa {
                    name: "edge.cdn.net".into(),
                    ttl: 40,
                    addr: "2001:db8::7".parse().unwrap()
                },
            ]
        );
        assert_eq!(r.answers[1].name(), "edge.cdn.net");
    }

    /// The sensor's 512-byte cut: the records before it are kept.
    #[test]
    fn a_cut_message_gives_the_records_before_the_cut() {
        let full = cdn_response();
        for cut in HEADER_LEN..full.len() {
            let Some(r) = parse_response(&full[..cut]) else {
                // only a cut inside the question reads as no response
                assert!(cut < HEADER_LEN + 17 + 4, "cut {cut}");
                continue;
            };
            assert!(!r.complete || cut == full.len(), "cut {cut}");
            assert!(r.answers.len() <= 4);
        }
        // cut inside the last AAAA: three records, incomplete
        let r = parse_response(&full[..full.len() - 3]).unwrap();
        assert_eq!(r.answers.len(), 3);
        assert!(!r.complete);
    }

    #[test]
    fn queries_and_odd_messages_are_no_response() {
        let mut q = cdn_response();
        q[2] &= 0x7f; // QR clear
        assert_eq!(parse_response(&q), None);
        let mut two = cdn_response();
        two[5] = 2; // qdcount 2
        assert_eq!(parse_response(&two), None);
        assert_eq!(parse_response(&[0u8; 11]), None);
    }

    #[test]
    fn nxdomain_and_other_types_and_classes() {
        let mut p = Vec::new();
        header(&mut p, 0x8183, 1, 3);
        name(&mut p, "nope.example");
        p.extend_from_slice(&[0, 28, 0, 1]);
        rr(&mut p, &[0xC0, 12], 16, 5, b"\x03txt"); // TXT: stepped over
                                                    // CH class A: stepped over
        p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 3, 0, 0, 0, 5, 0, 4, 1, 2, 3, 4]);
        rr(&mut p, &[0xC0, 12], TYPE_A, 9, &[1, 2, 3]); // a 3-byte A: stepped over
        let r = parse_response(&p).unwrap();
        assert!(r.answers.is_empty());
        assert!(!r.complete, "the 3-byte A: not whole (D1)");
        // AAAA data of 15 and of 17 bytes: stepped over
        let mut p = Vec::new();
        header(&mut p, 0x8180, 1, 2);
        name(&mut p, "odd.example");
        p.extend_from_slice(&[0, 28, 0, 1]);
        rr(&mut p, &[0xC0, 12], TYPE_AAAA, 9, &[7; 15]);
        rr(&mut p, &[0xC0, 12], TYPE_AAAA, 9, &[7; 17]);
        let odd = parse_response(&p).unwrap();
        // review of #495, D1: stepped over, the response not whole
        assert!(odd.answers.is_empty() && !odd.complete);
        let mut p = Vec::new();
        header(&mut p, 0x8183, 1, 3);
        name(&mut p, "nope.example");
        p.extend_from_slice(&[0, 28, 0, 1]);
        rr(&mut p, &[0xC0, 12], 16, 5, b"\x03txt");
        p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 3, 0, 0, 0, 5, 0, 4, 1, 2, 3, 4]);
        rr(&mut p, &[0xC0, 12], TYPE_A, 9, &[1, 2, 3]);
        let r = parse_response(&p).unwrap();
        assert_eq!(
            (r.qname.as_str(), r.qtype, r.rcode),
            ("nope.example", 28, 3)
        );
        assert!(r.answers.is_empty());
        // the 3-byte A: not whole (review of #495, D1)
        assert!(!r.complete);
        // NXDOMAIN with a TXT and a CH-class record only: whole
        let mut p = Vec::new();
        header(&mut p, 0x8183, 1, 2);
        name(&mut p, "nope.example");
        p.extend_from_slice(&[0, 28, 0, 1]);
        rr(&mut p, &[0xC0, 12], 16, 5, b"\x03txt");
        p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 3, 0, 0, 0, 5, 0, 4, 1, 2, 3, 4]);
        let r = parse_response(&p).unwrap();
        assert!(r.answers.is_empty() && r.complete);
    }

    /// A pointer must point back: to itself, forward, or into a loop it is
    /// refused, and the walk ends.
    #[test]
    fn pointers_must_point_back() {
        // the question's name is a pointer to itself
        let mut p = Vec::new();
        header(&mut p, 0x8180, 1, 0);
        p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert_eq!(parse_response(&p), None);
        // a CNAME target pointing forward, to the next record
        let mut p = Vec::new();
        header(&mut p, 0x8180, 1, 1);
        name(&mut p, "a.example");
        p.extend_from_slice(&[0, 1, 0, 1]);
        let fwd = (p.len() + 12 + 2) as u8;
        rr(&mut p, &[0xC0, 12], TYPE_CNAME, 1, &[0xC0, fwd]);
        let r = parse_response(&p).unwrap();
        assert!(r.answers.is_empty() && !r.complete);
        // read_name directly: a pointer back to its own label run loops
        assert_eq!(read_name(&[1, b'a', 0xC0, 0], 0), None);
        // a pointer to a prior name reads, the bytes after the pointer next
        assert_eq!(read_name(&[1, b'a', 0, 0xC0, 0], 3), Some(("a".into(), 5)));
    }

    /// A CNAME whose target runs past its RDATA is malformed.
    #[test]
    fn a_cname_target_ends_in_its_rdata() {
        let mut p = Vec::new();
        header(&mut p, 0x8180, 1, 1);
        name(&mut p, "a.example");
        p.extend_from_slice(&[0, 1, 0, 1]);
        let mut target = Vec::new();
        name(&mut target, "b.example");
        // RDLENGTH one short of the target
        p.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 1]);
        p.extend_from_slice(&((target.len() - 1) as u16).to_be_bytes());
        p.extend_from_slice(&target);
        let r = parse_response(&p).unwrap();
        assert!(r.answers.is_empty() && !r.complete);
    }

    #[test]
    fn names_are_bounded_and_escaped() {
        // a label of 64 is reserved
        let mut b = vec![64u8];
        b.extend(core::iter::repeat_n(b'a', 64));
        b.push(0);
        assert_eq!(read_name(&b, 0), None);
        // 256 wire octets is one too many: 4 labels of 63 + root = 257
        let mut b = Vec::new();
        for _ in 0..4 {
            b.push(63);
            b.extend(core::iter::repeat_n(b'a', 63));
        }
        b.push(0);
        assert_eq!(read_name(&b, 0), None);
        // 3 labels of 63 and one of 62: 255
        let mut b = Vec::new();
        for n in [63usize, 63, 63, 61] {
            b.push(n as u8);
            b.extend(core::iter::repeat_n(b'a', n));
        }
        b.push(0);
        assert!(read_name(&b, 0).is_some());
        // and one of 62 more: 256, one too many
        let mut b = Vec::new();
        for n in [63usize, 63, 63, 62] {
            b.push(n as u8);
            b.extend(core::iter::repeat_n(b'a', n));
        }
        b.push(0);
        assert_eq!(read_name(&b, 0), None);
        // a dot, a backslash and a control byte inside a label
        let b = [3u8, b'a', b'.', b'\\', 1, 7, 0];
        assert_eq!(read_name(&b, 0), Some(("a\\046\\092.\\007".into(), 7)));
    }

    /// The records kept are bounded: past them the answer is incomplete.
    #[test]
    fn at_most_max_records_are_kept() {
        let mut p = Vec::new();
        header(&mut p, 0x8180, 1, 40);
        name(&mut p, "many.example");
        p.extend_from_slice(&[0, 1, 0, 1]);
        for i in 0..40u8 {
            rr(&mut p, &[0xC0, 12], TYPE_A, 60, &[198, 51, 100, i]);
        }
        let r = parse_response(&p).unwrap();
        assert_eq!(r.answers.len(), MAX_RECORDS);
        assert!(!r.complete);
    }

    /// Review of #495, D1 (probe P2, which passed on the PR's first head:
    /// the TC bit was not read): a response the server truncated is not
    /// complete; nor is one with a malformed A record, which is stepped
    /// over.
    #[test]
    fn a_truncated_or_malformed_response_is_not_complete() {
        let mut m = alloc::vec![0x12, 0x34, 0x83, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]; // QR|TC|RD|RA
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        let r = parse_response(&m).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert!(!r.complete, "TC=1");
        // the same without TC: whole
        m[2] = 0x81;
        assert!(parse_response(&m).unwrap().complete);
        // an A of 3 bytes, then a good one: stepped over, not whole
        let mut m = alloc::vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 3, 192, 0, 2]);
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 8]);
        let r = parse_response(&m).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert!(!r.complete, "a malformed A");
        // an AAAA of 15 bytes
        let mut m = alloc::vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x1c\x00\x01");
        m.extend_from_slice(&[0xC0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 15]);
        m.extend_from_slice(&[0u8; 15]);
        let r = parse_response(&m).unwrap();
        assert!(r.answers.is_empty() && !r.complete, "a malformed AAAA");
    }

    /// Review of #495, RA1: each pointer must point before the previous
    /// one's target, not only before the name's start — a second pointer
    /// forward of the first target (still before the start) is refused.
    #[test]
    fn a_pointer_forward_of_the_previous_target_is_refused() {
        let mut b = alloc::vec![0u8; 42];
        // at 30: the label "c", then a pointer to 35 (forward of 30)
        b[30..34].copy_from_slice(&[1, b'c', 0xC0, 35]);
        b[35] = 0;
        // at 40: a pointer to 30
        b[40..42].copy_from_slice(&[0xC0, 30]);
        assert_eq!(read_name(&b, 40), None);
        // the same chain pointing back each time reads
        b[32..34].copy_from_slice(&[0xC0, 20]);
        b[20] = 0;
        assert_eq!(read_name(&b, 40).map(|(n, _)| n), Some("c".into()));
    }
}
