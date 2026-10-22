#![no_main]
//! Lab PR 224: `/etc/resolv.conf` and systemd-resolved's
//! `/run/systemd/resolve/resolv.conf`, rewritten by DHCP and VPN clients,
//! name the resolvers whose DNS port a staged image may reach. Beyond
//! "never panics": every resolver parsed is the address of a `nameserver`
//! line of the text (its zone index dropped), in canonical form, listed
//! once, at most sixteen; the text of the parsed list parses back to it.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::net::resolvers::parse_resolv_conf;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let got = parse_resolv_conf(text);
    assert!(got.len() <= 16, "{} resolvers", got.len());
    for (i, ip) in got.iter().enumerate() {
        assert!(!got[..i].contains(ip), "{ip} twice");
        assert_eq!(nn_model::netaddr::canonical(*ip), *ip);
        let named = text.lines().any(|l| {
            let mut w = l.split_whitespace();
            w.next() == Some("nameserver")
                && w.next().is_some_and(|a| {
                    a.split('%')
                        .next()
                        .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                        .is_some_and(|a| nn_model::netaddr::canonical(a) == *ip)
                })
        });
        assert!(named, "{ip} is no nameserver line of the text");
    }
    let rendered: String = got.iter().map(|ip| format!("nameserver {ip}\n")).collect();
    assert_eq!(parse_resolv_conf(&rendered), got);
});
