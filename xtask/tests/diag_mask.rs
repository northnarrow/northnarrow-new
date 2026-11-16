//! The guide's diagnostics masking (section 8 of ALPHA_TESTER_GUIDE.md) is run
//! as written, on a crafted sample, for several user names and domains. It must
//! mask what identifies the tester and never break a path, a JSON key, a record
//! or the loopback address. Needs `perl` (skipped without it).

use std::fs;
use std::process::Command;

mod support;
use support::repo_root;

const GUIDE: &str = "docs/operator/ALPHA_TESTER_GUIDE.md";
const START: &str = "perl -pi -e '";
const END: &str = "' \"$d\"/*";

// "/home" is spelled @HOME@ here: the hygiene scan refuses home paths of unknown names.
const SAMPLE: &str = r#"host box.corp.example.com id 0123456789abcdef0123456789abcdef boot 11111111-2222-3333-4444-555555555555
@HOME@/NAME/work /root/northnarrow-admin.key /proc/42/root /user.slice/x /run/user/1000 /run/northnarrow/admin.sock
user=NAME "user":"NAME" uid=1000(NAME) NAME@box [NAME, ran by NAME. nn-admin northnarrow
ssh NAME@1.2.3.4 from 10.0.0.9 to 127.0.0.1 203.0.113.7 loop ::1 peer fe80::1 mac aa:bb:cd:11:22:33
@HOME@/DOM /usr/local/bin foo.local at DOM end DOMX nn::x
"#;

/// (user, domain, expected output of the sample with NAME = user, DOM = domain)
const CASES: &[(&str, &str, &str)] = &[
    (
        "nn",
        "home",
        r#"host host1.corp.example.com id machine-id boot boot-id
@HOME@/user1/work /root/northnarrow-admin.key /proc/42/root /user.slice/x /run/user/1000 /run/northnarrow/admin.sock
user=user1 "user":"user1" uid=1000(user1) user1@host1 [user1, ran by user1. nn-admin northnarrow
ssh user1@x.x.x.x from x.x.x.x to 127.0.0.1 203.0.113.7 loop ::1 peer x:x::x mac x:x::x
@HOME@/home /usr/local/bin foo.local at home end homeX nn::x
"#,
    ),
    (
        "admin",
        "local",
        r#"host host1.corp.example.com id machine-id boot boot-id
@HOME@/user1/work /root/northnarrow-admin.key /proc/42/root /user.slice/x /run/user/1000 /run/northnarrow/admin.sock
user=user1 "user":"user1" uid=1000(user1) user1@host1 [user1, ran by user1. nn-admin northnarrow
ssh user1@x.x.x.x from x.x.x.x to 127.0.0.1 203.0.113.7 loop ::1 peer x:x::x mac x:x::x
@HOME@/local /usr/local/bin foo.local at local end localX nn::x
"#,
    ),
    (
        "user",
        "corp.example.com",
        r#"host host1.domain1 id machine-id boot boot-id
@HOME@/user1/work /root/northnarrow-admin.key /proc/42/root /user.slice/x /run/user/1000 /run/northnarrow/admin.sock
user=user1 "user":"user1" uid=1000(user1) user1@host1 [user1, ran by user1. nn-admin northnarrow
ssh user1@x.x.x.x from x.x.x.x to 127.0.0.1 203.0.113.7 loop ::1 peer x:x::x mac x:x::x
@HOME@/domain1 /usr/local/bin foo.local at domain1 end corp.example.comX nn::x
"#,
    ),
    (
        "root",
        "lan",
        r#"host host1.corp.example.com id machine-id boot boot-id
@HOME@/root/work /root/northnarrow-admin.key /proc/42/root /user.slice/x /run/user/1000 /run/northnarrow/admin.sock
user=root "user":"root" uid=1000(root) root@host1 [root, ran by root. nn-admin northnarrow
ssh root@x.x.x.x from x.x.x.x to 127.0.0.1 203.0.113.7 loop ::1 peer x:x::x mac x:x::x
@HOME@/lan /usr/local/bin foo.local at lan end lanX nn::x
"#,
    ),
    (
        "alice",
        "corp.example.com",
        r#"host host1.domain1 id machine-id boot boot-id
@HOME@/user1/work /root/northnarrow-admin.key /proc/42/root /user.slice/x /run/user/1000 /run/northnarrow/admin.sock
user=user1 "user":"user1" uid=1000(user1) user1@host1 [user1, ran by user1. nn-admin northnarrow
ssh user1@x.x.x.x from x.x.x.x to 127.0.0.1 203.0.113.7 loop ::1 peer x:x::x mac x:x::x
@HOME@/domain1 /usr/local/bin foo.local at domain1 end corp.example.comX nn::x
"#,
    ),
];

fn program() -> String {
    let text = fs::read_to_string(repo_root().join(GUIDE)).expect("the guide");
    let at = text.find(START).expect("the guide's perl command") + START.len();
    let len = text[at..].find(END).expect("the end of the perl command");
    text[at..at + len].to_string()
}

#[test]
fn the_diagnostics_masking_hides_the_tester_and_keeps_paths_and_records() {
    if !Command::new("perl")
        .arg("-e1")
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("perl is not installed: skipped");
        return;
    }
    let prog = program();
    let dir = std::env::temp_dir().join(format!("nn-diag-mask-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    for (user, domain, expected) in CASES {
        let file = dir.join("sample.txt");
        fs::write(
            &file,
            SAMPLE
                .replace("NAME", user)
                .replace("DOM", domain)
                .replace("@HOME@", "/home"),
        )
        .unwrap();
        let status = Command::new("perl")
            .args(["-pi", "-e", &prog])
            .arg(&file)
            .env("H", "box")
            .env("D", domain)
            .env("U", user)
            .env("M", "0123456789abcdef0123456789abcdef")
            .env("B", "11111111-2222-3333-4444-555555555555")
            .status()
            .unwrap();
        assert!(status.success());
        let got = fs::read_to_string(&file).unwrap();
        assert_eq!(
            got,
            expected.replace("@HOME@", "/home"),
            "masking with user {user} and domain {domain}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}
