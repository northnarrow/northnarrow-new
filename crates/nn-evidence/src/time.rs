//! Lot 1.6 (F11): the wall-clock time the agent writes and reads as text —
//! the signed chains' `ts`, the protocol's and the exports' times, the
//! command line's — on jiff ([`Timestamp`]), with the text chrono 0.4 gave
//! kept byte for byte.
//!
//! The text is this module's, not a library's default. Each format below is
//! written field by field from jiff's UTC calendar, and [`parse_rfc3339`] is
//! the grammar of chrono 0.4's `DateTime::parse_from_rfc3339`, so the bytes
//! signed, hashed and exported before the move are the bytes after it, and
//! a time read before is read the same. `tests/time_chrono_corpus.rs` pins
//! every function against what chrono 0.4.45 wrote and read on a corpus of
//! edge times (`tests/data/time-chrono-0.4.45.jsonl`).
//!
//! Ranges. A jiff [`Timestamp`] spans the years -9999 to 9999 (chrono's,
//! ±262143); every time stamped here is the host's clock (Linux keeps it
//! before 2262) or a test's. A time read from text keeps chrono's range —
//! four-digit years, with any offset — as an [`Rfc3339`], not a jiff value:
//! a verifier still compares, and writes back, a row stamped `9999-12-31`
//! or in chrono's leap second (`23:59:60`, which jiff does not have). The
//! text of a time in any year is chrono's: the calendar repeats every 400
//! years, so a time beyond jiff's calendar is written from the same time
//! 400 years nearer, its year moved back.

use std::fmt::Write as _;
use std::time::SystemTime;

use jiff::tz::Offset;
pub use jiff::{SignedDuration, Timestamp, civil};

const NANOS_PER_SEC: u32 = 1_000_000_000;
const SECS_PER_DAY: i64 = 86_400;
/// 400 Gregorian years: 146,097 days, the calendar's period.
const PERIOD_SECS: i64 = 146_097 * SECS_PER_DAY;
const EPOCH_DATE: civil::Date = civil::date(1970, 1, 1);
const EPOCH: civil::DateTime = EPOCH_DATE.at(0, 0, 0, 0);

/// `t` on the UTC calendar.
pub fn utc(t: Timestamp) -> civil::DateTime {
    Offset::UTC.to_datetime(t)
}

/// The UTC calendar time `dt` as a [`Timestamp`] (`None` past jiff's
/// range).
pub fn from_utc(dt: civil::DateTime) -> Option<Timestamp> {
    Offset::UTC.to_timestamp(dt).ok()
}

/// A [`SystemTime`] as a [`Timestamp`]: the host's clock, or a file's time
/// the agent set itself. One past jiff's range (year 9999) is held at its
/// end (chrono's conversion panicked past its own).
pub fn from_system_time(t: SystemTime) -> Timestamp {
    Timestamp::try_from(t).unwrap_or(if t < SystemTime::UNIX_EPOCH {
        Timestamp::MIN
    } else {
        Timestamp::MAX
    })
}

// Writing to a String cannot fail: the `fmt::Result`s below are dropped.

/// chrono's `%Y`: four digits in 0..=9999, else the sign and at least four
/// digits (`-0001`, `+10000`).
fn push_year(out: &mut String, y: i64) {
    let _ = if (0..10_000).contains(&y) {
        write!(out, "{y:04}")
    } else {
        write!(out, "{y:+05}")
    };
}

/// chrono's `%Y-%m-%dT%H:%M:%S` of the UTC time `secs` seconds after the
/// Unix epoch, for any `secs`.
fn push_unix(out: &mut String, secs: i64) {
    let (periods, rest) = (secs.div_euclid(PERIOD_SECS), secs.rem_euclid(PERIOD_SECS));
    // `rest` is under 400 years after 1970: inside jiff's calendar
    let dt = EPOCH
        .checked_add(SignedDuration::from_secs(rest))
        .unwrap_or(EPOCH);
    push_year(out, i64::from(dt.year()) + 400 * periods);
    let _ = write!(
        out,
        "-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
}

/// The chains' stamp, `2026-01-01T00:00:00.123456Z`: UTC, the microseconds
/// truncated (chrono's `%Y-%m-%dT%H:%M:%S%.6fZ`).
pub fn format_micros(t: Timestamp) -> String {
    Rfc3339::from(t).format_micros()
}

/// The chains' stamp of the host's clock now ([`format_micros`] of
/// [`Timestamp::now`]): every chain writer's and the records' `ts`.
pub fn now_micros() -> String {
    format_micros(Timestamp::now())
}

/// To the second, `2026-01-01T00:00:00Z` (chrono's `%Y-%m-%dT%H:%M:%SZ`,
/// and `to_rfc3339_opts(SecondsFormat::Secs, true)`).
pub fn format_secs(t: Timestamp) -> String {
    let mut out = String::with_capacity(20);
    push_unix(&mut out, Rfc3339::from(t).secs);
    out.push('Z');
    out
}

/// chrono's `to_rfc3339()` of a UTC time: `+00:00`, and the fraction in
/// as few of 0, 3, 6 or 9 digits as hold it exactly
/// (`2026-01-01T00:00:00.120+00:00`).
pub fn format_rfc3339_offset(t: Timestamp) -> String {
    let t = Rfc3339::from(t);
    let mut out = String::with_capacity(35);
    push_unix(&mut out, t.secs);
    let nano = t.frac;
    let _ = if nano == 0 {
        Ok(())
    } else if nano % 1_000_000 == 0 {
        write!(out, ".{:03}", nano / 1_000_000)
    } else if nano % 1_000 == 0 {
        write!(out, ".{:06}", nano / 1_000)
    } else {
        write!(out, ".{nano:09}")
    };
    out.push_str("+00:00");
    out
}

/// A UTC day, `2026-01-01` (chrono's `%Y-%m-%d`).
pub fn format_date(d: civil::Date) -> String {
    let mut out = String::with_capacity(10);
    push_year(&mut out, i64::from(d.year()));
    let _ = write!(out, "-{:02}-{:02}", d.month(), d.day());
    out
}

/// The UTC time `secs` seconds after the Unix epoch, to the second and
/// without a zone, `2026-01-01T00:00:00`: chrono's `%Y-%m-%dT%H:%M:%S` of
/// `Utc.timestamp_opt(secs, 0)`, in any year (chrono had none past ±262143;
/// a year of five digits or more is written with its sign, as chrono did).
pub fn format_unix_date_time(secs: i64) -> String {
    let mut out = String::with_capacity(19);
    push_unix(&mut out, secs);
    out
}

/// A time read from RFC 3339 text by [`parse_rfc3339`], as chrono 0.4 held
/// the `DateTime<Utc>` its `parse_from_rfc3339` gave: whole seconds since
/// the Unix epoch, UTC, and the nanoseconds past them — 1e9 or more in a
/// leap second (`23:59:60`), which counts as the second before it. Two are
/// ordered as chrono ordered them: a leap second after the second before
/// it, before the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rfc3339 {
    secs: i64,
    frac: u32,
}

impl Rfc3339 {
    /// Seconds since the Unix epoch (chrono's `timestamp()`; a leap second
    /// is the second before it).
    pub fn unix_seconds(self) -> i64 {
        self.secs
    }

    /// The nanoseconds past [`Self::unix_seconds`] (chrono's
    /// `timestamp_subsec_nanos()`: 1e9 or more in a leap second).
    pub fn subsec_nanos(self) -> u32 {
        self.frac
    }

    /// The whole seconds from `earlier` to `self`, truncated toward zero
    /// (chrono's `(self - earlier).num_seconds()`, a leap second counted
    /// as chrono's `NaiveDateTime::signed_duration_since` counts it).
    pub fn whole_seconds_since(self, earlier: Rfc3339) -> i64 {
        let (days, sod) = (
            self.secs.div_euclid(SECS_PER_DAY),
            self.secs.rem_euclid(SECS_PER_DAY),
        );
        let (e_days, e_sod) = (
            earlier.secs.div_euclid(SECS_PER_DAY),
            earlier.secs.rem_euclid(SECS_PER_DAY),
        );
        let leap = i64::from(NANOS_PER_SEC);
        let mut secs = sod - e_sod;
        let frac = i64::from(self.frac) - i64::from(earlier.frac);
        // the time of day's difference may hold a leap second yet to count
        if sod > e_sod && i64::from(earlier.frac) >= leap {
            secs += 1;
        } else if sod < e_sod && i64::from(self.frac) >= leap {
            secs -= 1;
        }
        let secs = (days - e_days) * SECS_PER_DAY + secs + frac.div_euclid(leap);
        let nanos = frac.rem_euclid(leap);
        if secs < 0 && nanos > 0 {
            secs + 1
        } else {
            secs
        }
    }

    /// chrono's `%Y-%m-%dT%H:%M:%S%.6fZ` of this time: a leap second's
    /// second is `60`, a year beyond 9999 has its sign (`+10000`).
    pub fn format_micros(self) -> String {
        let mut out = String::with_capacity(27);
        push_unix(&mut out, self.secs);
        if self.frac >= NANOS_PER_SEC {
            // a leap second is at second 59 (offsets are whole minutes)
            out.truncate(out.len() - 2);
            out.push_str("60");
        }
        let _ = write!(out, ".{:06}Z", self.frac % NANOS_PER_SEC / 1_000);
        out
    }

    /// The same instant as a [`Timestamp`]: `None` for a leap second, and
    /// past jiff's range (a time chrono read in year 9999 after
    /// `9999-12-30T22:00:00Z`).
    pub fn to_timestamp(self) -> Option<Timestamp> {
        if self.frac >= NANOS_PER_SEC {
            return None;
        }
        // frac < 1e9: it fits an i32
        Timestamp::new(self.secs, i32::try_from(self.frac).ok()?).ok()
    }
}

impl From<Timestamp> for Rfc3339 {
    fn from(t: Timestamp) -> Self {
        let ns = t.as_nanosecond();
        let per = i128::from(NANOS_PER_SEC);
        // jiff's range keeps the seconds in an i64, the remainder below 1e9
        Self {
            secs: i64::try_from(ns.div_euclid(per)).unwrap_or(i64::MAX),
            frac: u32::try_from(ns.rem_euclid(per)).unwrap_or(0),
        }
    }
}

/// Reads an RFC 3339 time exactly as chrono 0.4's
/// `DateTime::parse_from_rfc3339` did:
///
/// `YYYY-MM-DD` (a real day), `T`, `t` or a space, `hh:mm:ss` (hour 00–23,
/// minute 00–59, second 00–60: 60 is a leap second), an optional `.` and
/// one or more digits (the first nine are read, the rest skipped), then
/// `Z`, `z` or an offset `±hh:mm` (`+`, `-` or U+2212 `−`; up to 23:59),
/// and nothing after it. `None` for anything else.
pub fn parse_rfc3339(s: &str) -> Option<Rfc3339> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let digit = |i: usize| b[i].is_ascii_digit().then(|| i64::from(b[i] - b'0'));
    let two = |i: usize| Some(digit(i)? * 10 + digit(i + 1)?);
    let year = two(0)? * 100 + two(2)?;
    let month = two(5)?;
    let day = two(8)?;
    if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (hour, min, sec) = (two(11)?, two(14)?, two(17)?);
    // chrono: second 60 is a leap second, 59 and a nanosecond of 1e9 more
    let (sec, mut frac) = if sec == 60 {
        (59, NANOS_PER_SEC)
    } else {
        (sec, 0)
    };
    if hour >= 24 || min >= 60 || sec >= 60 {
        return None;
    }
    let mut rest = &b[19..];
    if let Some(after_dot) = rest.strip_prefix(b".") {
        let n = after_dot.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        let mut nanos = 0u32;
        for (i, c) in after_dot.iter().take(n.min(9)).enumerate() {
            nanos += u32::from(c - b'0') * 10u32.pow(8 - i as u32);
        }
        frac += nanos;
        rest = &after_dot[n..];
    }
    let offset = parse_offset(&mut rest)?;
    if !rest.is_empty() {
        return None;
    }
    let date = civil::Date::new(
        i16::try_from(year).ok()?,
        i8::try_from(month).ok()?,
        i8::try_from(day).ok()?,
    )
    .ok()?;
    let day_secs = date.duration_since(EPOCH_DATE).as_secs();
    Some(Rfc3339 {
        secs: day_secs + hour * 3600 + min * 60 + sec - offset,
        frac,
    })
}

/// [`parse_rfc3339`] as a [`Timestamp`]: `None` also for a leap second and
/// past jiff's range ([`Rfc3339::to_timestamp`]). The clocks of the tests
/// and of the replays.
pub fn parse_timestamp(s: &str) -> Option<Timestamp> {
    parse_rfc3339(s)?.to_timestamp()
}

/// `Z`, `z` or `±hh:mm` (minutes 00–59, under 24 hours): the offset's
/// seconds east of UTC, `rest` moved past it.
fn parse_offset(rest: &mut &[u8]) -> Option<i64> {
    const MINUS_SIGN: &[u8] = "\u{2212}".as_bytes();
    let r = *rest;
    if let Some((b'Z' | b'z', after)) = r.split_first() {
        *rest = after;
        return Some(0);
    }
    let (negative, r) = if let Some(after) = r.strip_prefix(b"+") {
        (false, after)
    } else if let Some(after) = r.strip_prefix(b"-") {
        (true, after)
    } else {
        (true, r.strip_prefix(MINUS_SIGN)?)
    };
    let [h1, h2, b':', m1, m2, after @ ..] = r else {
        return None;
    };
    if !(h1.is_ascii_digit() && h2.is_ascii_digit()) {
        return None;
    }
    if !((b'0'..=b'5').contains(m1) && m2.is_ascii_digit()) {
        return None;
    }
    let hours = i64::from((h1 - b'0') * 10 + (h2 - b'0'));
    let minutes = i64::from((m1 - b'0') * 10 + (m2 - b'0'));
    let secs = hours * 3600 + minutes * 60;
    if secs >= SECS_PER_DAY {
        return None;
    }
    *rest = after;
    Some(if negative { -secs } else { secs })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64, nanos: i32) -> Timestamp {
        Timestamp::new(secs, nanos).unwrap()
    }

    /// Named (lot 1.6): a host time converts exactly; one past jiff's range
    /// is held at its nearer end; a UTC calendar time is its instant.
    #[test]
    fn host_and_calendar_times_convert() {
        use std::time::{Duration, UNIX_EPOCH};
        let t = UNIX_EPOCH + Duration::new(1_767_225_720, 123_456_789);
        assert_eq!(from_system_time(t), ts(1_767_225_720, 123_456_789));
        let before = UNIX_EPOCH - Duration::new(1, 500_000_000);
        assert_eq!(from_system_time(before), ts(-2, 500_000_000));
        let far = Duration::from_secs(400_000_000_000);
        assert_eq!(from_system_time(UNIX_EPOCH + far), Timestamp::MAX);
        assert_eq!(from_system_time(UNIX_EPOCH - far), Timestamp::MIN);
        let midnight = from_utc(civil::date(2026, 11, 14).at(0, 0, 0, 0)).unwrap();
        assert_eq!(midnight, ts(1_794_614_400, 0));
        assert_eq!(utc(midnight).date(), civil::date(2026, 11, 14));
        assert_eq!(from_utc(civil::date(9999, 12, 31).at(0, 0, 0, 0)), None);
        assert!(now_micros().ends_with('Z') && now_micros().len() == 27);
    }

    /// Named (lot 1.6): the chains' stamp truncates to the microsecond and
    /// says `Z`; the second's stamp drops the fraction.
    #[test]
    fn the_stamps_keep_chronos_text() {
        let t = ts(1_767_225_720, 123_456_789);
        assert_eq!(format_micros(t), "2026-01-01T00:02:00.123456Z");
        assert_eq!(format_secs(t), "2026-01-01T00:02:00Z");
        assert_eq!(
            format_rfc3339_offset(t),
            "2026-01-01T00:02:00.123456789+00:00"
        );
        assert_eq!(
            format_rfc3339_offset(ts(0, 120_000_000)),
            "1970-01-01T00:00:00.120+00:00"
        );
        assert_eq!(format_rfc3339_offset(ts(0, 0)), "1970-01-01T00:00:00+00:00");
        assert_eq!(
            format_micros(ts(-1, 999_999_999)),
            "1969-12-31T23:59:59.999999Z"
        );
        assert_eq!(format_secs(Timestamp::MIN), "-9999-01-02T01:59:59Z");
        assert_eq!(format_date(civil::date(-1, 3, 4)), "-0001-03-04");
        assert_eq!(format_date(civil::date(0, 3, 4)), "0000-03-04");
        assert_eq!(
            format_unix_date_time(253_402_300_799),
            "9999-12-31T23:59:59"
        );
        assert_eq!(
            format_unix_date_time(253_402_300_800),
            "+10000-01-01T00:00:00"
        );
        assert_eq!(
            format_unix_date_time(-62_167_219_201),
            "-0001-12-31T23:59:59"
        );
    }

    /// Named (lot 1.6): chrono's grammar, no more and no less.
    #[test]
    fn rfc3339_is_chronos_grammar() {
        let unix = |s: &str| parse_rfc3339(s).map(Rfc3339::unix_seconds);
        assert_eq!(unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix("1970-01-01t00:00:00z"), Some(0));
        assert_eq!(unix("1970-01-01 00:00:00-00:00"), Some(0));
        assert_eq!(unix("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(unix("1969-12-31T23:00:00\u{2212}01:00"), Some(0));
        assert_eq!(unix("9999-12-31T23:59:59Z"), Some(253_402_300_799));
        for bad in [
            "1970-01-01T00:00:00",
            "1970-01-01T00:00:00+0000",
            "1970-01-01T00:00:00+00",
            "1970-01-01T00:00:00.Z",
            "1970-01-01T00:00:00,5Z",
            "1970-01-01T00:00:00Z ",
            " 1970-01-01T00:00:00Z",
            "1970-01-01T24:00:00Z",
            "1970-01-01T00:00:61Z",
            "1970-02-30T00:00:00Z",
            "1970-01-01T00:00:00+24:00",
            "1970-01-01T00:00:00+00:60",
            "+1970-01-01T00:00:00Z",
            "19700101T000000Z",
            "1970-01-01T00:00:00Z[UTC]",
            "1970-01-01T00:00:00+0;:00",
            "1970-01-01T00:00:00+;0:00",
            "1970-01-01T00:00:00+00:0;",
            "1970-01-01T00:00:00+0/:00",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad:?}");
        }
        let p = parse_rfc3339("2026-01-01T00:00:00.1234567891234Z").unwrap();
        assert_eq!(p.subsec_nanos(), 123_456_789);
        let leap = parse_rfc3339("2016-12-31T23:59:60.5Z").unwrap();
        assert_eq!(leap.unix_seconds(), 1_483_228_799);
        assert_eq!(leap.subsec_nanos(), 1_500_000_000);
        assert_eq!(leap.to_timestamp(), None);
        let on_the_leap = parse_rfc3339("2016-12-31T23:59:60Z").unwrap();
        assert_eq!(on_the_leap.subsec_nanos(), 1_000_000_000);
        assert_eq!(on_the_leap.to_timestamp(), None);
        assert_eq!(leap.format_micros(), "2016-12-31T23:59:60.500000Z");
        let late = parse_rfc3339("9999-12-31T23:59:59.25-23:59").unwrap();
        assert_eq!(late.format_micros(), "+10000-01-01T23:58:59.250000Z");
    }
}
