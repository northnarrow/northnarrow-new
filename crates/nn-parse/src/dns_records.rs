//! DNS response messages (RFC 1035 §4.1): the A and AAAA answers they
//! carry ([`parse_a_records`], [`parse_aaaa_records`]).
//!
//! The bytes are written by whoever answers a query: any process on the
//! host, any server it asks. Every read is bounded by the message, names
//! are held to RFC 1035, and the walk is fuzzed
//! (`fuzz/fuzz_targets/dns_records.rs`). It was the agent's
//! `net::dns_cache` reply parser until R06 of the Wave 4 restructure (lab
//! PR 242), where the agent re-exports it.

use std::net::{Ipv4Addr, Ipv6Addr};

// ── DNS reply parser (forward-compat utility for V1.1) ───────────────
//
// RFC 1035 wire format walker. V1.0 doesn't have a DNS-response
// observer; these parsers ship now as a standalone utility so the
// V1.1 commit that wires up the observer is a pure plumbing change.
// Kept, not deleted, though nothing in production calls it (external
// audit NET-013, NET-015): the `dns_records` fuzz target exercises it,
// and it now reads names as the system resolver does, so the observer
// that lands on it inherits a conforming parser.
//
// We handle:
//   * the 12-byte header,
//   * a single QUESTION section (compressed-name + qtype + qclass),
//   * the ANSWER section with name (label OR pointer per §4.1.4),
//     16-bit TYPE / CLASS, 32-bit TTL, 16-bit RDLENGTH, RDATA.
//
// Names are held to RFC 1035: a length octet is a label (top bits
// `00`, so at most 63 bytes) or a pointer (`11`) into the message; `01`
// and `10` are reserved and refused; a name is at most 255 octets on
// the wire (external audit NET-015, NN-AUD-334). Read past, they would
// shift the walk off the records the resolver applies.
//
// We DON'T handle:
//   * Multi-question messages (V1.0+ resolvers always send 1
//     question per query; observed real-world traffic is 100%
//     single-question).
//   * Recursive name decompression (we only need to SKIP names
//     in answers — A/AAAA RDATA is positional, no name decoding
//     required).
//   * EDNS / DNSSEC RR types (out of V1.0 scope per design §6.3).

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_HEADER_LEN: usize = 12;
/// Compressed-name pointer marker — RFC 1035 §4.1.4: the top
/// two bits of a label-length byte are set when the byte +
/// next byte together encode a 14-bit offset to elsewhere in
/// the message.
const DNS_NAME_POINTER_MASK: u8 = 0xC0;
/// The top two bits of a length octet: `00` label, `11` pointer, `01`
/// and `10` reserved (RFC 1035 §4.1.4; the `01` extended labels of
/// RFC 2671 are deprecated by RFC 6891 §5).
const DNS_LABEL_KIND_MASK: u8 = 0xC0;
/// RFC 1035 §2.3.4 / §3.1: a name is at most 255 octets in wire form,
/// its length octets and the root label included.
const DNS_MAX_NAME_WIRE_LEN: usize = 255;
/// The shortest resource record: a one-octet name (the root, or half of
/// nothing — a pointer is two) and TYPE, CLASS, TTL, RDLENGTH.
const DNS_MIN_RR_LEN: usize = 1 + 2 + 2 + 4 + 2;

/// Parser cursor + state. Wraps the byte stream so the
/// `advance_*` helpers stay bounded — every helper rejects
/// reads past `bytes.len()` instead of panicking on slice OOB.
struct DnsPacket<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DnsPacket<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Bytes left after `pos`. The bounds are `need > remaining()`, as in
    /// the TLS parser's cursor: `pos + need` can wrap (external audit
    /// NET-015).
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_u16(&mut self) -> Option<u16> {
        if 2 > self.remaining() {
            return None;
        }
        let v = u16::from_be_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    fn read_u32(&mut self) -> Option<u32> {
        if 4 > self.remaining() {
            return None;
        }
        let v = u32::from_be_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            return None;
        }
        let b = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Some(b)
    }

    /// Skip a DNS name in-place. Names are either:
    ///   * a sequence of length-prefixed labels terminated by
    ///     a zero byte, OR
    ///   * a 2-byte pointer (top 2 bits == 11) referencing an
    ///     earlier name in the message — consumes 2 bytes and
    ///     advances no further (we don't follow the pointer
    ///     because we don't need the decoded name for A/AAAA
    ///     RDATA), but it must point inside the message.
    ///
    /// `None` for a reserved length octet (`0x40..=0xBF`: a label over
    /// 63 bytes or the `01` / `10` prefixes), a name over 255 octets, or
    /// a read past the message (external audit NET-015, NN-AUD-334).
    fn skip_name(&mut self) -> Option<()> {
        let mut wire_len = 0usize;
        loop {
            let b = *self.bytes.get(self.pos)?;
            match b & DNS_LABEL_KIND_MASK {
                0x00 => {
                    // Label: 1-byte length (at most 63 by its prefix) +
                    // that many bytes; the zero length is the root.
                    let label_len = b as usize;
                    wire_len += 1 + label_len;
                    if wire_len > DNS_MAX_NAME_WIRE_LEN || 1 + label_len > self.remaining() {
                        return None;
                    }
                    self.pos += 1 + label_len;
                    if label_len == 0 {
                        return Some(());
                    }
                }
                DNS_NAME_POINTER_MASK => {
                    // 2-byte pointer; we don't follow it.
                    let lo = *self.bytes.get(self.pos + 1)?;
                    let offset = (usize::from(b & !DNS_LABEL_KIND_MASK) << 8) | usize::from(lo);
                    if offset >= self.bytes.len() {
                        return None;
                    }
                    self.pos += 2;
                    return Some(());
                }
                _ => return None,
            }
        }
    }
}

/// Parse `packet` as a DNS response message and return every
/// IPv4 address found in an A-record answer. Returns an empty
/// `Vec` on any parse failure — defensive callers can treat
/// "no A records" + "malformed packet" the same way (both mean
/// "no v4 attribution available"). For surfacing parse errors,
/// the test suite uses [`try_parse_answers`].
pub fn parse_a_records(packet: &[u8]) -> Vec<Ipv4Addr> {
    let answers = try_parse_answers(packet).unwrap_or_default();
    answers
        .into_iter()
        .filter_map(|a| match a {
            DnsAnswer::A(ip) => Some(ip),
            _ => None,
        })
        .collect()
}

/// Parse `packet` and return IPv6 AAAA-record addresses. Same
/// "Vec on success, empty Vec on failure" contract as
/// [`parse_a_records`].
pub fn parse_aaaa_records(packet: &[u8]) -> Vec<Ipv6Addr> {
    let answers = try_parse_answers(packet).unwrap_or_default();
    answers
        .into_iter()
        .filter_map(|a| match a {
            DnsAnswer::Aaaa(ip) => Some(ip),
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DnsAnswer {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME, MX, TXT, etc. — preserved so the parser can step
    /// over the RDATA correctly, but not exposed in the
    /// caller-visible API.
    Other,
}

/// Parser entry-point — surfaces None on any malformed-packet
/// failure. The public [`parse_a_records`] + [`parse_aaaa_records`]
/// flatten this to an empty Vec; tests use `try_parse_answers`
/// directly to distinguish "no records" from "parse error."
fn try_parse_answers(packet: &[u8]) -> Option<Vec<DnsAnswer>> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let mut p = DnsPacket::new(packet);
    // Header: id(2) + flags(2) + qdcount(2) + ancount(2) +
    // nscount(2) + arcount(2). We need the qd + an counts.
    let _id = p.read_u16()?;
    let _flags = p.read_u16()?;
    let qdcount = p.read_u16()?;
    let ancount = p.read_u16()?;
    let _nscount = p.read_u16()?;
    let _arcount = p.read_u16()?;
    // Skip QUESTION section(s).
    for _ in 0..qdcount {
        p.skip_name()?;
        let _qtype = p.read_u16()?;
        let _qclass = p.read_u16()?;
    }
    // Parse ANSWER section. External audit NET-013 (NN-AUD-332):
    // `ancount` comes off the wire; sized by it, a 12-byte message
    // reserved over a megabyte.
    let mut out = Vec::with_capacity(answer_capacity(ancount, p.remaining()));
    for _ in 0..ancount {
        p.skip_name()?;
        let rtype = p.read_u16()?;
        let _class = p.read_u16()?;
        let _ttl = p.read_u32()?;
        let rdlen = p.read_u16()? as usize;
        let rdata = p.read_bytes(rdlen)?;
        out.push(match rtype {
            DNS_TYPE_A if rdlen == 4 => {
                DnsAnswer::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
            }
            DNS_TYPE_AAAA if rdlen == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                DnsAnswer::Aaaa(Ipv6Addr::from(b))
            }
            _ => DnsAnswer::Other,
        });
    }
    Some(out)
}

/// The answers `remaining` bytes can hold, at most `ancount`.
fn answer_capacity(ancount: u16, remaining: usize) -> usize {
    usize::from(ancount).min(remaining / DNS_MIN_RR_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N4 test #4 — parser extracts A records from a real
    /// DNS response packet (`example.com → 93.184.216.34`).
    /// Wire bytes hand-built per RFC 1035 so the test isn't
    /// dependent on an external resolver.
    #[test]
    fn dns_query_parser_extracts_a_record_responses() {
        let pkt = build_response_a("example.com", Ipv4Addr::new(93, 184, 216, 34));
        let ips = parse_a_records(&pkt);
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
        // AAAA parser on the same packet returns empty (no
        // AAAA answers).
        assert!(parse_aaaa_records(&pkt).is_empty());
    }

    /// N4 test #5 — parser extracts AAAA records. Same shape
    /// as test #4 with a v6 target.
    #[test]
    fn dns_query_parser_handles_aaaa_v6_responses() {
        let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946);
        let pkt = build_response_aaaa("example.com", v6);
        assert_eq!(parse_aaaa_records(&pkt), vec![v6]);
        assert!(parse_a_records(&pkt).is_empty());
    }

    /// A response for `1.2.3.4` whose question and answer names are
    /// `name_wire` (raw wire bytes, root label included).
    fn response_with_name(name_wire: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        write_header(&mut p, 1);
        p.extend_from_slice(name_wire);
        p.extend_from_slice(&1u16.to_be_bytes()); // qtype=A
        p.extend_from_slice(&1u16.to_be_bytes()); // qclass=IN
        p.extend_from_slice(name_wire);
        p.extend_from_slice(&1u16.to_be_bytes()); // type=A
        p.extend_from_slice(&1u16.to_be_bytes()); // class=IN
        p.extend_from_slice(&60u32.to_be_bytes()); // ttl
        p.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        p.extend_from_slice(&[1, 2, 3, 4]);
        p
    }

    /// Wire form of labels of the given lengths (filled with `a`), then
    /// the root label.
    fn name_of_labels(lengths: &[u8]) -> Vec<u8> {
        let mut n = Vec::new();
        for &len in lengths {
            n.push(len);
            n.extend(std::iter::repeat_n(b'a', usize::from(len)));
        }
        n.push(0);
        n
    }

    /// External audit NET-015 (NN-AUD-334): a length octet with the
    /// reserved prefixes `01` and `10` is refused, not read as a label of
    /// up to 191 bytes — the walk would leave the records the resolver
    /// applies. The same packet with a legal label parses.
    #[test]
    fn reserved_label_prefix_is_rejected() {
        let ok = response_with_name(&name_of_labels(&[7, 3]));
        assert_eq!(parse_a_records(&ok), vec![Ipv4Addr::new(1, 2, 3, 4)]);
        for prefix in [0x41u8, 0x7F, 0x80, 0xBF] {
            let name = name_of_labels(&[prefix]);
            let pkt = response_with_name(&name);
            assert!(parse_a_records(&pkt).is_empty(), "{prefix:#04x}");
            assert!(try_parse_answers(&pkt).is_none(), "{prefix:#04x}");
        }
    }

    /// External audit NET-015: a label is at most 63 bytes (64 is the
    /// first value of the reserved `01` prefix) and a name at most 255
    /// octets on the wire.
    #[test]
    fn label_over_63_is_rejected() {
        let max_label = response_with_name(&name_of_labels(&[63]));
        assert_eq!(parse_a_records(&max_label).len(), 1);
        let over = response_with_name(&name_of_labels(&[64]));
        assert!(parse_a_records(&over).is_empty());

        // 3 × (1 + 63) + (1 + 62) + 1 = 256 octets; one byte less is 255.
        let too_long = response_with_name(&name_of_labels(&[63, 63, 63, 62]));
        assert!(parse_a_records(&too_long).is_empty());
        let longest = response_with_name(&name_of_labels(&[63, 63, 63, 61]));
        assert_eq!(parse_a_records(&longest).len(), 1);
    }

    /// A compressed answer name (`0xC00C`, the question's name: the usual
    /// response form) parses; a pointer outside the message does not.
    #[test]
    fn answer_name_pointers_must_point_inside_the_message() {
        let mut pkt = build_response_a("example.com", Ipv4Addr::new(9, 9, 9, 9));
        let answer_at = DNS_HEADER_LEN + "example.com".len() + 2 + 4;
        let rest = pkt.split_off(answer_at + "example.com".len() + 2);
        pkt.truncate(answer_at);
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&rest);
        assert_eq!(parse_a_records(&pkt), vec![Ipv4Addr::new(9, 9, 9, 9)]);
        pkt[answer_at..answer_at + 2].copy_from_slice(&[0xFF, 0xFF]);
        assert!(parse_a_records(&pkt).is_empty());
    }

    /// External audit NET-013 (NN-AUD-332): the answer vector is sized by
    /// what the message can hold, not by `ancount`. A 12-byte header
    /// claiming 65,535 answers reserves nothing; a short message claiming
    /// them is malformed.
    #[test]
    fn huge_ancount_in_a_short_packet_allocates_little() {
        assert_eq!(answer_capacity(u16::MAX, 0), 0);
        assert_eq!(answer_capacity(u16::MAX, 3 * DNS_MIN_RR_LEN + 10), 3);
        assert_eq!(answer_capacity(2, 4096), 2);

        let mut header_only = vec![0u8; DNS_HEADER_LEN];
        header_only[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(parse_a_records(&header_only).is_empty());
        assert!(try_parse_answers(&header_only).is_none());

        let mut one_answer = build_response_a("example.com", Ipv4Addr::new(1, 1, 1, 1));
        one_answer[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(parse_a_records(&one_answer).is_empty());
    }

    /// Lab PR 242 (R06 of the Wave 4 restructure): what the reply parser
    /// makes of bytes, pinned on `main` before it moved from the agent to
    /// nn-parse and unchanged after — on the `dns_records` fuzz seeds and
    /// regression the answers each holds, and on a corpus of hostile inputs
    /// (every prefix and mutants of those and of this module's responses) a
    /// SHA-256 over everything each input parses to.
    mod output_pins {
        use super::*;
        use sha2::{Digest as _, Sha256};

        /// The fuzz job's inputs for `dns_records`: a response with A, AAAA
        /// and CNAME answers, the QNAME a sensor copies, and the NN-AUD-185
        /// regression (a dot inside a label).
        const INPUTS: [(&str, &[u8]); 3] = [
            (
                "seeds/response-a-aaaa-cname",
                include_bytes!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/fuzz/seeds/dns_records/response-a-aaaa-cname.bin"
                )),
            ),
            (
                "seeds/sensor-qname-then-type",
                include_bytes!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/fuzz/seeds/dns_records/sensor-qname-then-type.bin"
                )),
            ),
            (
                "regressions/nn-aud-185-dot-inside-label",
                include_bytes!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/fuzz/regressions/dns_records/nn-aud-185-dot-inside-label.bin"
                )),
            ),
        ];

        /// Everything the parser makes of `bytes`: the answers (or the
        /// refusal) and what the two public parsers return.
        fn render(bytes: &[u8]) -> String {
            format!(
                "{:?} a={:?} aaaa={:?}",
                try_parse_answers(bytes),
                parse_a_records(bytes),
                parse_aaaa_records(bytes)
            )
        }

        /// Protects: the fuzz inputs parse to the same answers wherever the
        /// parser lives.
        #[test]
        fn the_fuzz_inputs_parse_to_the_pinned_answers() {
            let want = [
                concat!(
                    "Some([A(93.184.216.34), Aaaa(2606:2800:220:1:248:1893:25c8:1946), Other]) ",
                    "a=[93.184.216.34] aaaa=[2606:2800:220:1:248:1893:25c8:1946]"
                ),
                "None a=[] aaaa=[]",
                "None a=[] aaaa=[]",
            ];
            for ((name, bytes), want) in INPUTS.iter().zip(want) {
                assert_eq!(render(bytes), want, "{name}");
            }
        }

        /// Every prefix of each fuzz input and of this module's responses
        /// (A, AAAA, the longest name, a compressed answer name), then 500
        /// mutants of each: one to four bytes set to 0x00, 0xFF, 0xC0 or a
        /// random value, a third of them then cut short — from a fixed
        /// xorshift stream.
        fn hostile_corpus() -> Vec<Vec<u8>> {
            let mut bases: Vec<Vec<u8>> = INPUTS.iter().map(|(_, b)| b.to_vec()).collect();
            bases.push(build_response_a(
                "example.com",
                Ipv4Addr::new(93, 184, 216, 34),
            ));
            bases.push(build_response_aaaa(
                "example.com",
                Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946),
            ));
            bases.push(response_with_name(&name_of_labels(&[63, 63, 63, 61])));
            let mut compressed = build_response_a("example.com", Ipv4Addr::new(9, 9, 9, 9));
            let answer_at = DNS_HEADER_LEN + "example.com".len() + 2 + 4;
            let rest = compressed.split_off(answer_at + "example.com".len() + 2);
            compressed.truncate(answer_at);
            compressed.extend_from_slice(&[0xC0, 0x0C]);
            compressed.extend_from_slice(&rest);
            bases.push(compressed);
            let mut state = 0x9E37_79B9_7F4A_7C15u64;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let mut out = Vec::new();
            for base in &bases {
                out.extend((0..=base.len()).map(|n| base[..n].to_vec()));
                for _ in 0..500 {
                    let mut m = base.clone();
                    for _ in 0..(1 + next() % 4) {
                        let at = (next() as usize) % m.len();
                        m[at] = match next() % 5 {
                            0 => 0x00,
                            1 => 0xFF,
                            2 => 0xC0,
                            _ => next() as u8,
                        };
                    }
                    if next() % 3 == 0 {
                        let keep = (next() as usize) % m.len();
                        m.truncate(keep);
                    }
                    out.push(m);
                }
            }
            out
        }

        /// Protects: hostile bytes parse to the same answers wherever the
        /// parser lives — the corpus's renderings in order, hashed; the
        /// counts say refusals, empty and non-empty answers are covered.
        #[test]
        fn a_hostile_corpus_parses_to_the_pinned_digest() {
            let mut all = String::new();
            let (mut refused, mut empty, mut answered) = (0usize, 0usize, 0usize);
            for input in hostile_corpus() {
                match try_parse_answers(&input) {
                    None => refused += 1,
                    Some(a) if a.is_empty() => empty += 1,
                    Some(_) => answered += 1,
                }
                all.push_str(&render(&input));
                all.push('\n');
            }
            assert_eq!((refused, empty, answered), (3186, 8, 1160));
            assert_eq!(
                hex::encode(Sha256::digest(all.as_bytes())),
                "f57c8bf29ddfbb0e042c11dac53d985d1bfe32f1abcacbc6ff3e1b63209de873"
            );
        }
    }

    // ── DNS wire-format test helpers ───────────────────────────────

    /// Build a minimal DNS response packet containing one A
    /// record for `qname` → `ip`. RFC 1035 wire format:
    /// header(12) + question + answer.
    fn build_response_a(qname: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut p = Vec::new();
        write_header(&mut p, 1);
        write_name(&mut p, qname);
        p.extend_from_slice(&1u16.to_be_bytes()); // qtype=A
        p.extend_from_slice(&1u16.to_be_bytes()); // qclass=IN
                                                  // Answer
        write_name(&mut p, qname);
        p.extend_from_slice(&1u16.to_be_bytes()); // type=A
        p.extend_from_slice(&1u16.to_be_bytes()); // class=IN
        p.extend_from_slice(&60u32.to_be_bytes()); // ttl
        p.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        p.extend_from_slice(&ip.octets());
        p
    }

    /// Same as [`build_response_a`] but emits a single AAAA
    /// (qtype=28) answer.
    fn build_response_aaaa(qname: &str, ip: Ipv6Addr) -> Vec<u8> {
        let mut p = Vec::new();
        write_header(&mut p, 1);
        write_name(&mut p, qname);
        p.extend_from_slice(&28u16.to_be_bytes()); // qtype=AAAA
        p.extend_from_slice(&1u16.to_be_bytes()); // qclass=IN
        write_name(&mut p, qname);
        p.extend_from_slice(&28u16.to_be_bytes()); // type=AAAA
        p.extend_from_slice(&1u16.to_be_bytes()); // class=IN
        p.extend_from_slice(&60u32.to_be_bytes()); // ttl
        p.extend_from_slice(&16u16.to_be_bytes()); // rdlen
        p.extend_from_slice(&ip.octets());
        p
    }

    /// DNS header: id=0, flags=0x8180 (standard query response,
    /// no error), 1 question, `ancount` answers, 0 ns, 0 ar.
    fn write_header(p: &mut Vec<u8>, ancount: u16) {
        p.extend_from_slice(&0u16.to_be_bytes()); // id
        p.extend_from_slice(&0x8180u16.to_be_bytes()); // flags
        p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        p.extend_from_slice(&ancount.to_be_bytes()); // ancount
        p.extend_from_slice(&0u16.to_be_bytes()); // nscount
        p.extend_from_slice(&0u16.to_be_bytes()); // arcount
    }

    /// Encode a domain name as a sequence of length-prefixed
    /// labels terminated by a zero byte. No compression — the
    /// parser handles pointer-form names too but the test
    /// fixtures emit fully-spelled-out names so the wire bytes
    /// are dead-simple to reason about.
    fn write_name(p: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
    }
}
