//! External audit EBPF-001: what systemd reports the host as
//! (`SystemState`: `running`, `degraded`, `stopping`, …), asked from the
//! agent's own process over systemd's private socket — one D-Bus
//! `org.freedesktop.DBus.Properties.Get` call, the one `systemctl
//! is-system-running` makes.
//!
//! Not a child `systemctl`: a child runs in the agent's cgroup, which the
//! very stop job or `systemctl kill` being judged signals — the lab saw the
//! child SIGKILLed before it answered. The private socket (root only) is
//! also the one that still answers while a shutdown has stopped the system
//! bus. Its server must be PID 1 (`SO_PEERCRED`), or the answer is not
//! systemd's.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// systemd's private socket (what `systemctl` uses as root).
pub const PRIVATE_SOCKET: &str = "/run/systemd/private";

const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";

/// D-Bus message types.
const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;

/// Header field codes.
const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SIGNATURE: u8 = 8;

/// A reply larger than this is not systemd answering one property.
const MAX_MESSAGE: usize = 64 * 1024;

/// `SystemState` as systemd reports it, through `socket` (normally
/// [`PRIVATE_SOCKET`]), each read and write bounded by `timeout`.
pub fn system_state(socket: &Path, timeout: Duration) -> io::Result<String> {
    let mut s = UnixStream::connect(socket)?;
    // Only systemd itself answers: a socket mounted over the private one
    // by root would otherwise make the agent believe the host is stopping
    // (and stand its active response down).
    let peer = peer_pid(&s)?;
    if peer != 1 {
        return Err(other(format!(
            "{} is served by pid {peer}, not systemd",
            socket.display()
        )));
    }
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    // SASL EXTERNAL: the server checks the uid against the socket's peer
    // credentials.
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let hex: String = uid
        .to_string()
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    s.write_all(b"\0")?;
    s.write_all(format!("AUTH EXTERNAL {hex}\r\n").as_bytes())?;
    let line = read_line(&mut s)?;
    if !line.starts_with("OK ") {
        return Err(other(format!("D-Bus authentication refused: {line}")));
    }
    // systemd answers nothing on a connection that did not negotiate fd
    // passing, as `systemctl` does (lab: no reply without it).
    s.write_all(b"NEGOTIATE_UNIX_FD\r\n")?;
    let line = read_line(&mut s)?;
    if line != "AGREE_UNIX_FD" {
        return Err(other(format!("D-Bus: fd passing not agreed: {line}")));
    }
    s.write_all(b"BEGIN\r\n")?;
    const SERIAL: u32 = 1;
    s.write_all(&get_property_call(SERIAL, MANAGER_INTERFACE, "SystemState"))?;
    loop {
        let msg = read_message(&mut s)?;
        if let Some(state) = parse_reply(&msg, SERIAL)? {
            return Ok(state);
        }
    }
}

/// The pid of the process that created the listening end (`SO_PEERCRED`).
fn peer_pid(s: &UnixStream) -> io::Result<i32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid out-pointers sized for SO_PEERCRED.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.pid)
}

fn other(msg: String) -> io::Error {
    io::Error::other(msg)
}

fn read_line(s: &mut impl Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while !line.ends_with(b"\r\n") {
        if line.len() > 512 {
            return Err(other("D-Bus authentication line too long".into()));
        }
        s.read_exact(&mut b)?;
        line.push(b[0]);
    }
    line.truncate(line.len() - 2);
    Ok(String::from_utf8_lossy(&line).into_owned())
}

fn pad(buf: &mut Vec<u8>, align: usize) {
    while !buf.len().is_multiple_of(align) {
        buf.push(0);
    }
}

/// A string (`s`) or object path (`o`): aligned to 4, u32 length, bytes,
/// NUL. `buf` must start at an 8-aligned offset of the message.
fn put_string(buf: &mut Vec<u8>, v: &str) {
    pad(buf, 4);
    buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
    buf.extend_from_slice(v.as_bytes());
    buf.push(0);
}

/// A signature (`g`): u8 length, bytes, NUL — no alignment.
fn put_signature(buf: &mut Vec<u8>, v: &str) {
    buf.push(v.len() as u8);
    buf.extend_from_slice(v.as_bytes());
    buf.push(0);
}

/// One header field: a struct (aligned to 8) of the code and a variant.
fn put_field(fields: &mut Vec<u8>, code: u8, sig: char, value: &str) {
    pad(fields, 8);
    fields.push(code);
    put_signature(fields, &sig.to_string());
    match sig {
        'g' => put_signature(fields, value),
        _ => put_string(fields, value),
    }
}

/// `Properties.Get(interface, property)` on systemd's manager object, in
/// little-endian D-Bus wire format. The header fields array starts at
/// offset 16, which is 8-aligned, so alignment inside `fields` and `body`
/// can be counted from their own start.
fn get_property_call(serial: u32, interface: &str, property: &str) -> Vec<u8> {
    let mut fields = Vec::new();
    put_field(&mut fields, FIELD_PATH, 'o', MANAGER_PATH);
    put_field(&mut fields, FIELD_INTERFACE, 's', PROPERTIES_INTERFACE);
    put_field(&mut fields, FIELD_MEMBER, 's', "Get");
    put_field(
        &mut fields,
        FIELD_DESTINATION,
        's',
        "org.freedesktop.systemd1",
    );
    put_field(&mut fields, FIELD_SIGNATURE, 'g', "ss");
    let mut body = Vec::new();
    put_string(&mut body, interface);
    put_string(&mut body, property);

    let mut msg = vec![b'l', METHOD_CALL, 0, 1];
    msg.extend_from_slice(&(body.len() as u32).to_le_bytes());
    msg.extend_from_slice(&serial.to_le_bytes());
    msg.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    msg.extend_from_slice(&fields);
    pad(&mut msg, 8);
    msg.extend_from_slice(&body);
    msg
}

/// One whole message from the stream.
fn read_message(s: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut msg = vec![0u8; 16];
    s.read_exact(&mut msg)?;
    let le = match msg[0] {
        b'l' => true,
        b'B' => false,
        other_byte => return Err(other(format!("D-Bus: bad endianness byte {other_byte:#x}"))),
    };
    let body_len = u32_at(&msg, 4, le) as usize;
    let fields_len = u32_at(&msg, 12, le) as usize;
    let header_end = (16 + fields_len).div_ceil(8) * 8;
    let total = header_end + body_len;
    if total > MAX_MESSAGE {
        return Err(other(format!("D-Bus: {total}-byte message refused")));
    }
    msg.resize(total, 0);
    s.read_exact(&mut msg[16..])?;
    Ok(msg)
}

fn u32_at(buf: &[u8], at: usize, le: bool) -> u32 {
    let b: [u8; 4] = buf[at..at + 4].try_into().expect("4 bytes");
    if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }
}

/// A bounds-checked reader over one message; `pos` is the absolute offset
/// (alignment is absolute in D-Bus).
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    le: bool,
}

impl Cursor<'_> {
    fn align(&mut self, n: usize) {
        self.pos = self.pos.div_ceil(n) * n;
    }
    fn byte(&mut self) -> io::Result<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| other("D-Bus: truncated".into()))?;
        self.pos += 1;
        Ok(b)
    }
    fn u32(&mut self) -> io::Result<u32> {
        self.align(4);
        if self.pos + 4 > self.buf.len() {
            return Err(other("D-Bus: truncated".into()));
        }
        let v = u32_at(self.buf, self.pos, self.le);
        self.pos += 4;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> io::Result<&[u8]> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.buf.len());
        let end = end.ok_or_else(|| other("D-Bus: truncated".into()))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn signature(&mut self) -> io::Result<String> {
        let n = self.byte()? as usize;
        let s = String::from_utf8_lossy(self.bytes(n)?).into_owned();
        self.byte()?; // NUL
        Ok(s)
    }
    fn string(&mut self) -> io::Result<String> {
        let n = self.u32()? as usize;
        let s = String::from_utf8_lossy(self.bytes(n)?).into_owned();
        self.byte()?; // NUL
        Ok(s)
    }
}

/// The string a `METHOD_RETURN` to `serial` carries in its variant body;
/// `None` for any other message (a signal, a reply to something else); an
/// error for an `ERROR` reply to `serial`.
fn parse_reply(msg: &[u8], serial: u32) -> io::Result<Option<String>> {
    let le = msg[0] == b'l';
    let kind = msg[1];
    let fields_len = u32_at(msg, 12, le) as usize;
    let mut c = Cursor {
        buf: msg,
        pos: 16,
        le,
    };
    let fields_end = 16 + fields_len;
    let mut reply_serial = None;
    let mut signature = String::new();
    while c.pos < fields_end {
        c.align(8);
        if c.pos >= fields_end {
            break;
        }
        let code = c.byte()?;
        let sig = c.signature()?;
        match sig.as_str() {
            "u" => {
                let v = c.u32()?;
                if code == FIELD_REPLY_SERIAL {
                    reply_serial = Some(v);
                }
            }
            "s" | "o" => {
                c.string()?;
            }
            "g" => {
                let v = c.signature()?;
                if code == FIELD_SIGNATURE {
                    signature = v;
                }
            }
            other_sig => {
                return Err(other(format!(
                    "D-Bus: unexpected header field type {other_sig:?}"
                )))
            }
        }
    }
    if reply_serial != Some(serial) {
        return Ok(None);
    }
    c.pos = fields_end.div_ceil(8) * 8;
    match kind {
        METHOD_RETURN if signature == "v" => {
            let inner = c.signature()?;
            if inner != "s" {
                return Err(other(format!(
                    "D-Bus: SystemState is {inner:?}, not a string"
                )));
            }
            Ok(Some(c.string()?))
        }
        METHOD_RETURN => Err(other(format!("D-Bus: reply signature {signature:?}"))),
        ERROR => Err(other("D-Bus: systemd answered with an error".into())),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply as systemd builds it: `METHOD_RETURN`, REPLY_SERIAL and
    /// SIGNATURE `v`, body a variant holding `value`.
    fn reply(serial: u32, kind: u8, value: &str) -> Vec<u8> {
        let mut fields = Vec::new();
        pad(&mut fields, 8);
        fields.push(FIELD_REPLY_SERIAL);
        put_signature(&mut fields, "u");
        pad(&mut fields, 4);
        fields.extend_from_slice(&serial.to_le_bytes());
        put_field(&mut fields, FIELD_SIGNATURE, 'g', "v");
        let mut body = Vec::new();
        put_signature(&mut body, "s");
        put_string(&mut body, value);
        let mut msg = vec![b'l', kind, 1, 1];
        msg.extend_from_slice(&(body.len() as u32).to_le_bytes());
        msg.extend_from_slice(&7u32.to_le_bytes());
        msg.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        msg.extend_from_slice(&fields);
        pad(&mut msg, 8);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn the_call_is_a_well_formed_properties_get() {
        let msg = get_property_call(1, MANAGER_INTERFACE, "SystemState");
        assert_eq!(&msg[..4], &[b'l', METHOD_CALL, 0, 1]);
        let fields_len = u32_at(&msg, 12, true) as usize;
        let body_start = (16 + fields_len).div_ceil(8) * 8;
        assert_eq!(msg.len() - body_start, u32_at(&msg, 4, true) as usize);
        let mut c = Cursor {
            buf: &msg,
            pos: 16,
            le: true,
        };
        let mut seen = Vec::new();
        while c.pos < 16 + fields_len {
            c.align(8);
            let code = c.byte().unwrap();
            let sig = c.signature().unwrap();
            let value = if sig == "g" {
                c.signature().unwrap()
            } else {
                c.string().unwrap()
            };
            seen.push((code, value));
        }
        assert_eq!(
            seen,
            vec![
                (FIELD_PATH, MANAGER_PATH.to_string()),
                (FIELD_INTERFACE, PROPERTIES_INTERFACE.to_string()),
                (FIELD_MEMBER, "Get".to_string()),
                (FIELD_DESTINATION, "org.freedesktop.systemd1".to_string()),
                (FIELD_SIGNATURE, "ss".to_string()),
            ]
        );
        c.pos = body_start;
        assert_eq!(c.string().unwrap(), MANAGER_INTERFACE);
        assert_eq!(c.string().unwrap(), "SystemState");
        assert_eq!(c.pos, msg.len());
    }

    #[test]
    fn the_reply_to_our_call_yields_the_state() {
        let msg = reply(1, METHOD_RETURN, "stopping");
        let mut stream = &msg[..];
        let read = read_message(&mut stream).unwrap();
        assert_eq!(read, msg);
        assert_eq!(parse_reply(&read, 1).unwrap().as_deref(), Some("stopping"));
    }

    #[test]
    fn other_messages_are_skipped_and_errors_reported() {
        assert_eq!(
            parse_reply(&reply(9, METHOD_RETURN, "running"), 1).unwrap(),
            None
        );
        assert!(parse_reply(&reply(1, ERROR, "x"), 1).is_err());
    }

    #[test]
    fn a_truncated_or_oversized_message_is_refused() {
        let msg = reply(1, METHOD_RETURN, "running");
        let mut short = &msg[..msg.len() - 3];
        assert!(read_message(&mut short).is_err());
        let mut huge = msg.clone();
        huge[4..8].copy_from_slice(&(1u32 << 30).to_le_bytes());
        let mut stream = &huge[..];
        assert!(read_message(&mut stream).is_err());
    }
}
