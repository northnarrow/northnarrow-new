//! The `sd_notify(3)` datagram, without `libsystemd`: one Unix datagram to
//! the socket `$NOTIFY_SOCKET` names. Shared by the agent and the watchdog,
//! which each kept a copy that sent to the value as a filesystem path.
//!
//! External audit MAIN-016: systemd may hand a unit a socket in the Linux
//! abstract namespace, written with a leading `@` (`sd_notify(3)`: "If the
//! first character of `$NOTIFY_SOCKET` is `/` or `@`, the string is
//! understood as an `AF_UNIX` or Linux abstract namespace socket"). Sent to
//! as a path, `@name` names a file that does not exist: `READY=1` never
//! arrived and the `Type=notify` unit timed out. A value that is set but
//! not UTF-8 read as unset, so nothing was sent and nothing said why.
//!
//! Not supported, and reported as an error rather than skipped: the
//! `vsock:` addresses of systemd 254 for virtual machines, and any value
//! that is neither an absolute path nor `@name`.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Send `message` (`READY=1\n`, `STATUS=…\n`) to the socket
/// `$NOTIFY_SOCKET` names. `Ok(None)` when the variable is unset: the
/// process does not run under `Type=notify` (a shell, the tests), and
/// there is nothing to tell. `Ok(Some(value))` once the datagram is sent.
pub fn notify(message: &[u8]) -> io::Result<Option<OsString>> {
    let Some(value) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(None);
    };
    send(&value, message)?;
    Ok(Some(value))
}

/// Send `message` to the socket `notify_socket` names: an absolute path,
/// or `@name` for `name` in the abstract namespace.
pub fn send(notify_socket: &OsStr, message: &[u8]) -> io::Result<()> {
    let addr = address(notify_socket)?;
    let sock = UnixDatagram::unbound()?;
    let sent = sock.send_to_addr(message, &addr)?;
    if sent != message.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("sd_notify: {sent} of {} bytes sent", message.len()),
        ));
    }
    Ok(())
}

/// The socket address a `$NOTIFY_SOCKET` value names.
pub fn address(notify_socket: &OsStr) -> io::Result<SocketAddr> {
    let bytes = notify_socket.as_bytes();
    match bytes.first() {
        Some(b'@') => SocketAddr::from_abstract_name(&bytes[1..]),
        Some(b'/') => SocketAddr::from_pathname(notify_socket),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "NOTIFY_SOCKET={} is neither an absolute path nor an abstract name (@name)",
                notify_socket.to_string_lossy()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn unique(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("nn-sd-notify-{tag}-{}-{nanos}", std::process::id())
    }

    fn receive(sock: &UnixDatagram) -> Vec<u8> {
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 256];
        let n = sock.recv(&mut buf).expect("a datagram");
        buf[..n].to_vec()
    }

    /// External audit MAIN-016: `@name` reaches the abstract socket `name`.
    #[test]
    fn an_abstract_socket_receives_the_message() {
        let name = unique("abstract");
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixDatagram::bind_addr(&addr).unwrap();
        send(OsStr::new(&format!("@{name}")), b"READY=1\n").unwrap();
        assert_eq!(receive(&listener), b"READY=1\n");
        // No file of that name was involved.
        assert!(!std::path::Path::new(&format!("@{name}")).exists());
    }

    #[test]
    fn a_path_socket_receives_the_message() {
        let path = std::env::temp_dir().join(unique("path"));
        let listener = UnixDatagram::bind(&path).unwrap();
        let sent = send(path.as_os_str(), b"STATUS=holding\n");
        let got = receive(&listener);
        let _ = std::fs::remove_file(&path);
        sent.unwrap();
        assert_eq!(got, b"STATUS=holding\n");
    }

    /// A socket that is not there is an error, not a silent success.
    #[test]
    fn a_missing_socket_is_an_error() {
        let name = unique("missing");
        assert!(send(OsStr::new(&format!("@{name}")), b"READY=1\n").is_err());
        let path = std::env::temp_dir().join(name);
        assert!(send(path.as_os_str(), b"READY=1\n").is_err());
    }

    #[test]
    fn values_systemd_does_not_send_are_refused() {
        for value in ["", "relative/notify", "vsock:2:1234"] {
            let e = address(OsStr::new(value)).expect_err(value);
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{value}");
        }
        assert!(address(OsStr::new("@x")).unwrap().as_abstract_name() == Some(&b"x"[..]));
        assert!(address(OsStr::new("/run/systemd/notify"))
            .unwrap()
            .as_pathname()
            .is_some());
    }
}
