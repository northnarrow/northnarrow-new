//! Syslog messages (RFC 5424) in TLS frames (RFC 5425's octet counting).
//!
//! A message is `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG`:
//! the facility of the configuration and the record's severity, its time
//! in RFC 3339 (milliseconds, UTC), the host's name, `northnarrow`, no
//! process id, the record's OCSF class as its MSGID, no structured data,
//! and the record as its MSG — one line of JSON in ASCII
//! (`ocsf::to_line`), so it needs no BOM. A frame is `MSG-LEN SP MSG`.
//! [`FrameReader`] is the receiving side (the lab's receiver, the tests).

/// RFC 5424's APP-NAME.
pub const APP_NAME: &str = "northnarrow";

/// The largest message a reader takes (RFC 5425 lets a receiver bound it;
/// a record is at most a row twice over).
pub const MAX_MESSAGE: usize = 256 * 1024;

/// OCSF's `severity_id` as a syslog severity.
pub fn severity(ocsf: u8) -> u8 {
    match ocsf {
        6 => 1, // Fatal: alert
        5 => 2, // Critical: crit
        4 => 3, // High: err
        3 => 4, // Medium: warning
        2 => 5, // Low: notice
        _ => 6, // Informational, Unknown, Other: info
    }
}

/// OCSF's `class_uid` as the MSGID (at most 32 printable characters).
pub fn msgid(class_uid: u64) -> &'static str {
    match class_uid {
        2004 => "detection_finding",
        1007 => "process_activity",
        1001 => "file_activity",
        4001 => "network_activity",
        7001 => "remediation_activity",
        7002 => "file_remediation",
        7003 => "process_remediation",
        7004 => "network_remediation",
        _ => "base_event",
    }
}

/// Milliseconds since the epoch as RFC 3339 (`2026-11-03T20:00:00.123Z`);
/// 0 or less: RFC 5424's NILVALUE.
pub fn timestamp(ms: i64) -> String {
    if ms <= 0 {
        return "-".into();
    }
    let secs = ms.div_euclid(1000);
    let frac = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // civil from days (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:03}Z",
        tod / 3600,
        (tod / 60) % 60,
        tod % 60
    )
}

/// One RFC 5424 message.
pub fn message(
    facility: u8,
    ocsf_severity: u8,
    time_ms: i64,
    hostname: &str,
    class_uid: u64,
    msg: &[u8],
) -> Vec<u8> {
    let pri = u16::from(facility.min(23)) * 8 + u16::from(severity(ocsf_severity));
    let mut out = format!(
        "<{pri}>1 {} {} {APP_NAME} - {} - ",
        timestamp(time_ms),
        if hostname.is_empty() { "-" } else { hostname },
        msgid(class_uid)
    )
    .into_bytes();
    out.extend_from_slice(msg);
    out
}

/// RFC 5425: `MSG-LEN SP SYSLOG-MSG`.
pub fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = format!("{} ", msg.len()).into_bytes();
    out.extend_from_slice(msg);
    out
}

/// Why a stream is not RFC 5425 frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// MSG-LEN is not digits, starts with 0, or is followed by no space.
    Length,
    /// MSG-LEN above [`MAX_MESSAGE`].
    TooLong(usize),
}

/// Frames from a byte stream, as they arrive.
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole message, `None` until one is.
    pub fn next_message(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let Some(sp) = self.buf.iter().position(|b| *b == b' ') else {
            if self.buf.len() > 7 || !self.buf.iter().all(u8::is_ascii_digit) {
                return Err(FrameError::Length);
            }
            return Ok(None);
        };
        let digits = &self.buf[..sp];
        if digits.is_empty()
            || digits.len() > 7
            || digits[0] == b'0'
            || !digits.iter().all(u8::is_ascii_digit)
        {
            return Err(FrameError::Length);
        }
        let n: usize = std::str::from_utf8(digits)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(FrameError::Length)?;
        if n > MAX_MESSAGE {
            return Err(FrameError::TooLong(n));
        }
        if self.buf.len() < sp + 1 + n {
            return Ok(None);
        }
        let msg = self.buf[sp + 1..sp + 1 + n].to_vec();
        self.buf.drain(..sp + 1 + n);
        Ok(Some(msg))
    }
}

/// A received message's header and its MSG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<'a> {
    pub pri: u16,
    pub timestamp: &'a str,
    pub hostname: &'a str,
    pub app: &'a str,
    pub msgid: &'a str,
    pub msg: &'a [u8],
}

/// Split an RFC 5424 message written by [`message`] (no structured data).
pub fn parse(m: &[u8]) -> Option<Parsed<'_>> {
    let rest = m.strip_prefix(b"<")?;
    let gt = rest.iter().position(|b| *b == b'>')?;
    let pri: u16 = std::str::from_utf8(&rest[..gt]).ok()?.parse().ok()?;
    let rest = rest[gt + 1..].strip_prefix(b"1 ")?;
    let mut fields = Vec::with_capacity(6);
    let mut at = 0;
    for _ in 0..6 {
        let sp = rest[at..].iter().position(|b| *b == b' ')? + at;
        fields.push(std::str::from_utf8(&rest[at..sp]).ok()?);
        at = sp + 1;
    }
    if fields[5] != "-" || fields[3] != "-" {
        return None;
    }
    Some(Parsed {
        pri,
        timestamp: fields[0],
        hostname: fields[1],
        app: fields[2],
        msgid: fields[4],
        msg: &rest[at..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_is_rfc5424_and_its_frame_rfc5425() {
        let m = message(13, 4, 1_780_920_000_123, "lab-host", 2004, b"{\"a\":1}");
        assert_eq!(
            m,
            b"<107>1 2026-06-08T12:00:00.123Z lab-host northnarrow - detection_finding - {\"a\":1}"
                .to_vec()
        );
        assert!(frame(&m).starts_with(format!("{} <107>1 ", m.len()).as_bytes()));
        let p = parse(&m).unwrap();
        assert_eq!(p.pri, 107);
        assert_eq!(p.hostname, "lab-host");
        assert_eq!(p.msgid, "detection_finding");
        assert_eq!(p.msg, b"{\"a\":1}");
        // no time: the NILVALUE; the facility bounded
        let m = message(99, 0, 0, "", 0, b"x");
        assert_eq!(m, b"<190>1 - - northnarrow - base_event - x".to_vec());
        assert!(msgid(7004).len() <= 32);
    }

    #[test]
    fn timestamps_round_trip_the_ocsf_time() {
        for ts in [
            "1970-01-01T00:00:00.001Z",
            "2000-02-29T23:59:59.999Z",
            "2026-11-03T20:47:07.000Z",
            "2100-03-01T00:00:00.500Z",
        ] {
            let ms = crate::ocsf::time_ms(ts).unwrap();
            assert_eq!(timestamp(ms), ts);
        }
        assert_eq!(timestamp(-5), "-");
    }

    #[test]
    fn frames_are_read_as_they_arrive() {
        let a = frame(b"hello");
        let b = frame(&[b'x'; 300]);
        let mut stream = a.clone();
        stream.extend_from_slice(&b);
        let mut r = FrameReader::default();
        let mut got = Vec::new();
        for chunk in stream.chunks(3) {
            r.push(chunk);
            while let Some(m) = r.next_message().unwrap() {
                got.push(m);
            }
        }
        assert_eq!(got, vec![b"hello".to_vec(), vec![b'x'; 300]]);
        for bad in [&b"0 x"[..], b"a1 x", b" x", b"12345678 x", b"123456789"] {
            let mut r = FrameReader::default();
            r.push(bad);
            assert!(r.next_message().is_err(), "{bad:?}");
        }
        let mut r = FrameReader::default();
        r.push(format!("{} ", MAX_MESSAGE + 1).as_bytes());
        assert_eq!(r.next_message(), Err(FrameError::TooLong(MAX_MESSAGE + 1)));
    }

    #[test]
    fn severities_and_classes() {
        assert_eq!(
            (0..=6).map(severity).collect::<Vec<_>>(),
            vec![6, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(severity(99), 6);
        assert_eq!(msgid(1001), "file_activity");
        assert_eq!(msgid(7002), "file_remediation");
        assert_eq!(msgid(7003), "process_remediation");
        assert_eq!(msgid(4001), "network_activity");
        assert_eq!(msgid(7001), "remediation_activity");
        assert_eq!(msgid(1007), "process_activity");
        assert_eq!(msgid(12), "base_event");
    }
}
