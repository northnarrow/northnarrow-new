//! External bug hunt (edition 1.3), BUG55: the zone a DNS tunnel's queries
//! share — NN-L-NET-014's corroboration key.
//!
//! A tunnel (iodine, dnscat2, an exfiltration script) needs its queries to
//! reach a name server it runs, so every query ends in one zone it controls;
//! that zone lies at or below a *registrable domain* (a public suffix and
//! one label: `evil.example`, `evil.co.uk`). The payload is whatever comes
//! before: one label, or several (iodine and dnscat2 cut it every 57 to 63
//! characters), and a random label more is free. NN-L-NET-014 keyed its
//! corroboration on everything after the first label, so a payload over two
//! labels, or one label more, gave a new "parent" per query and the kill
//! never came. The key is now the registrable domain ([`tunnel_zone`]).
//!
//! The repository holds no Public Suffix List. [`MULTI_LABEL_SUFFIXES`] is a
//! curated list instead: the ICANN second-level registries of the common
//! country codes (`co.uk`, `com.au`, `co.jp` …) and the zones of the large
//! cloud platforms whose every name the platform's own DNS serves
//! (`s3.amazonaws.com`, `azurewebsites.net` …). A name under a suffix the
//! list lacks is keyed one level coarser (`co.xx` for `evil.co.xx`): more
//! names add up, never fewer — the error is on the side of the detection,
//! and an entry only ever makes a key finer. An entry must never be a name
//! someone can register (`com.de` is a domain like any other): the zone of
//! its owner would then lie above the entry, and a tunnel there would key
//! each query on its own subdomain again. Each entry is a registry's or a
//! platform's.
//!
//! Two shapes keep the key of before ([`tunnel_zone`]): a name whose first
//! label is itself the registrable label (`<label>.com`: a new domain per
//! query is no tunnel, and the key stays the suffix, as it was), and a name
//! under a zone no query leaves the site for (`.local`, `.internal`,
//! `home.arpa` …: no name server of the attacker's can answer it). So the
//! key of every name is its old key or a suffix of it, label for label: the
//! corroboration counts at least what it counted before.

/// Public suffixes of two labels or more, lower case, sorted (a test checks
/// it). See the module's note for what an entry must be.
pub const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "a.run.app",
    "ac.ae",
    "ac.at",
    "ac.be",
    "ac.cn",
    "ac.cy",
    "ac.id",
    "ac.il",
    "ac.in",
    "ac.jp",
    "ac.ke",
    "ac.kr",
    "ac.nz",
    "ac.th",
    "ac.uk",
    "ac.vn",
    "ac.za",
    "ad.jp",
    "amazonaws.com",
    "app.br",
    "appspot.com",
    "art.br",
    "asn.au",
    "asso.fr",
    "av.tr",
    "azure-api.net",
    "azurecr.io",
    "azureedge.net",
    "azurefd.net",
    "azurestaticapps.net",
    "azurewebsites.net",
    "bel.tr",
    "biz.id",
    "biz.pl",
    "biz.tr",
    "biz.vn",
    "blob.core.windows.net",
    "blog.br",
    "cloudapp.azure.com",
    "cloudapp.net",
    "cloudfront.net",
    "cloudfunctions.net",
    "co.ae",
    "co.at",
    "co.cl",
    "co.hu",
    "co.id",
    "co.il",
    "co.in",
    "co.jp",
    "co.ke",
    "co.kr",
    "co.nz",
    "co.th",
    "co.uk",
    "co.za",
    "com.ar",
    "com.au",
    "com.br",
    "com.cn",
    "com.co",
    "com.cy",
    "com.ec",
    "com.eg",
    "com.es",
    "com.fr",
    "com.gr",
    "com.hk",
    "com.lk",
    "com.mt",
    "com.mx",
    "com.my",
    "com.ng",
    "com.pe",
    "com.ph",
    "com.pk",
    "com.pl",
    "com.pt",
    "com.ro",
    "com.sa",
    "com.sg",
    "com.tr",
    "com.tw",
    "com.ua",
    "com.uy",
    "com.ve",
    "com.vn",
    "cri.nz",
    "database.windows.net",
    "dev.br",
    "dfs.core.windows.net",
    "digitaloceanspaces.com",
    "eco.br",
    "ed.jp",
    "edu.ar",
    "edu.au",
    "edu.br",
    "edu.cn",
    "edu.co",
    "edu.ec",
    "edu.eg",
    "edu.es",
    "edu.gr",
    "edu.hk",
    "edu.in",
    "edu.it",
    "edu.lk",
    "edu.mt",
    "edu.mx",
    "edu.my",
    "edu.ng",
    "edu.pe",
    "edu.ph",
    "edu.pk",
    "edu.pl",
    "edu.pt",
    "edu.sa",
    "edu.sg",
    "edu.tr",
    "edu.tw",
    "edu.ua",
    "edu.uy",
    "edu.ve",
    "edu.vn",
    "edu.za",
    "elasticbeanstalk.com",
    "elb.amazonaws.com",
    "emp.br",
    "eng.br",
    "es.kr",
    "file.core.windows.net",
    "firebaseapp.com",
    "firebaseio.com",
    "firm.in",
    "fly.dev",
    "geek.nz",
    "gen.in",
    "gen.nz",
    "gen.tr",
    "github.io",
    "githubusercontent.com",
    "go.id",
    "go.jp",
    "go.ke",
    "go.kr",
    "go.th",
    "gob.ar",
    "gob.cl",
    "gob.ec",
    "gob.es",
    "gob.mx",
    "gob.pe",
    "gob.ve",
    "googleapis.com",
    "googleusercontent.com",
    "gouv.fr",
    "gov.ae",
    "gov.ar",
    "gov.au",
    "gov.br",
    "gov.cl",
    "gov.cn",
    "gov.co",
    "gov.cy",
    "gov.ec",
    "gov.eg",
    "gov.gr",
    "gov.hk",
    "gov.ie",
    "gov.il",
    "gov.in",
    "gov.it",
    "gov.lk",
    "gov.mt",
    "gov.my",
    "gov.ng",
    "gov.ph",
    "gov.pk",
    "gov.pl",
    "gov.pt",
    "gov.ru",
    "gov.sa",
    "gov.sg",
    "gov.tr",
    "gov.tw",
    "gov.ua",
    "gov.uk",
    "gov.ve",
    "gov.vn",
    "gov.za",
    "govt.nz",
    "gr.jp",
    "gub.uy",
    "gv.at",
    "health.nz",
    "health.vn",
    "herokuapp.com",
    "hs.kr",
    "id.au",
    "idf.il",
    "idv.hk",
    "idv.tw",
    "in.th",
    "in.ua",
    "ind.br",
    "ind.in",
    "inf.br",
    "info.pl",
    "info.tr",
    "info.vn",
    "int.ar",
    "int.pt",
    "int.ru",
    "int.vn",
    "iwi.nz",
    "jus.br",
    "k12.il",
    "k12.tr",
    "kg.kr",
    "kiwi.nz",
    "leg.br",
    "lg.jp",
    "log.br",
    "ltd.uk",
    "maori.nz",
    "me.uk",
    "med.sa",
    "mi.th",
    "mil.ae",
    "mil.ar",
    "mil.br",
    "mil.cl",
    "mil.cn",
    "mil.co",
    "mil.id",
    "mil.in",
    "mil.kr",
    "mil.my",
    "mil.nz",
    "mil.pe",
    "mil.ph",
    "mil.ru",
    "mil.tw",
    "mil.uy",
    "ms.kr",
    "muni.il",
    "my.id",
    "name.my",
    "name.vn",
    "ne.jp",
    "ne.ke",
    "ne.kr",
    "net.ae",
    "net.ar",
    "net.au",
    "net.br",
    "net.cn",
    "net.co",
    "net.cy",
    "net.ec",
    "net.eg",
    "net.gr",
    "net.hk",
    "net.id",
    "net.il",
    "net.in",
    "net.lk",
    "net.mt",
    "net.mx",
    "net.my",
    "net.ng",
    "net.nz",
    "net.pe",
    "net.ph",
    "net.pk",
    "net.pl",
    "net.pt",
    "net.sa",
    "net.sg",
    "net.th",
    "net.tr",
    "net.tw",
    "net.ua",
    "net.uk",
    "net.uy",
    "net.ve",
    "net.vn",
    "net.za",
    "netlify.app",
    "ngo.ph",
    "nhs.uk",
    "nic.in",
    "nom.br",
    "nom.co",
    "nom.es",
    "nom.fr",
    "nom.pe",
    "nom.za",
    "nome.pt",
    "onrender.com",
    "or.at",
    "or.id",
    "or.jp",
    "or.ke",
    "or.kr",
    "or.th",
    "org.ae",
    "org.ar",
    "org.au",
    "org.br",
    "org.cn",
    "org.co",
    "org.cy",
    "org.ec",
    "org.eg",
    "org.es",
    "org.gr",
    "org.hk",
    "org.il",
    "org.in",
    "org.lk",
    "org.mt",
    "org.mx",
    "org.my",
    "org.ng",
    "org.nz",
    "org.pe",
    "org.ph",
    "org.pk",
    "org.pl",
    "org.pt",
    "org.ro",
    "org.sa",
    "org.sg",
    "org.tr",
    "org.tw",
    "org.ua",
    "org.uk",
    "org.uy",
    "org.ve",
    "org.vn",
    "org.za",
    "pages.dev",
    "parliament.nz",
    "pe.kr",
    "per.sg",
    "plc.uk",
    "police.uk",
    "prd.fr",
    "pro.vn",
    "pub.sa",
    "publ.pt",
    "queue.core.windows.net",
    "r2.cloudflarestorage.com",
    "r2.dev",
    "re.kr",
    "res.in",
    "run.app",
    "s3.amazonaws.com",
    "sc.ke",
    "sc.kr",
    "sch.ae",
    "sch.id",
    "sch.sa",
    "sch.uk",
    "school.nz",
    "servicebus.windows.net",
    "storage.googleapis.com",
    "table.core.windows.net",
    "tec.br",
    "tm.fr",
    "trafficmanager.net",
    "tur.ar",
    "tv.br",
    "vault.azure.net",
    "vercel.app",
    "web.app",
    "web.core.windows.net",
    "web.id",
    "web.tr",
    "web.za",
    "wiki.br",
    "workers.dev",
];

/// Zones no query leaves the site for: special-use names (RFC 6761, 6762,
/// 8375; `.internal`, reserved by ICANN for private use) and the names
/// ICANN will not delegate (`.corp`, `.home`), with the home routers'
/// `.lan` and `.localdomain`. No name server of an attacker's answers them.
const LOCAL_ONLY_ZONES: &[&str] = &[
    "corp",
    "home",
    "home.arpa",
    "internal",
    "lan",
    "local",
    "localdomain",
    "localhost",
];

/// `name` without its trailing dot.
fn trim(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

/// The last `n` labels of `name` (all of it when it has `n` or fewer).
fn last_labels(name: &str, n: usize) -> &str {
    match name.rmatch_indices('.').nth(n.saturating_sub(1)) {
        Some((i, _)) if n > 0 => &name[i + 1..],
        _ if n == 0 => "",
        _ => name,
    }
}

fn labels(name: &str) -> usize {
    name.split('.').count()
}

fn is_listed(list: &[&str], suffix: &str) -> bool {
    list.iter().any(|e| e.eq_ignore_ascii_case(suffix))
}

/// The registrable domain of `name` (a slice of it, its case kept, no
/// trailing dot): its public suffix — the longest entry of
/// [`MULTI_LABEL_SUFFIXES`] it ends in, else its last label — and one label
/// more. A name that is a public suffix, or shorter, is itself.
pub fn registrable_domain(name: &str) -> &str {
    let name = trim(name);
    let n = labels(name);
    let suffix = (2..=4)
        .rev()
        .filter(|k| *k < n)
        .find(|k| is_listed(MULTI_LABEL_SUFFIXES, last_labels(name, *k)))
        .unwrap_or(1);
    last_labels(name, suffix + 1)
}

/// The name is under a zone no query leaves the site for
/// ([`LOCAL_ONLY_ZONES`]).
pub fn is_local_only(name: &str) -> bool {
    let name = trim(name);
    [1, 2]
        .iter()
        .any(|k| is_listed(LOCAL_ONLY_ZONES, last_labels(name, *k)))
}

/// NN-L-NET-014's corroboration key of `name` (bug hunt 1.3, BUG55): its
/// registrable domain, when the first label lies below it; else — the first
/// label is the registrable label, or the name is under a zone no query
/// leaves the site for — everything after the first label, as before. Always
/// the old key or a suffix of it, label for label.
pub fn tunnel_zone(name: &str) -> &str {
    let name = trim(name);
    let rest = name.split_once('.').map_or("", |(_, r)| r);
    if is_local_only(name) {
        return rest;
    }
    let zone = registrable_domain(name);
    if zone.len() < name.len() {
        zone
    } else {
        rest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_suffix_list_is_sorted_lower_case_and_multi_label() {
        for w in MULTI_LABEL_SUFFIXES.windows(2) {
            assert!(w[0] < w[1], "not sorted or a duplicate: {w:?}");
        }
        for e in MULTI_LABEL_SUFFIXES {
            assert_eq!(*e, e.to_ascii_lowercase(), "{e}");
            assert!((2..=4).contains(&labels(e)), "{e}");
            assert!(e.split('.').all(|l| !l.is_empty()), "{e}");
        }
    }

    #[test]
    fn the_registrable_domain_is_the_suffix_and_one_label() {
        for (name, want) in [
            ("p1.p2.t.evil.example", "evil.example"),
            ("p1.p2.t.evil.example.", "evil.example"),
            ("p1.p2.evil.co.uk", "evil.co.uk"),
            ("p1.P2.Evil.CO.UK", "Evil.CO.UK"),
            ("x.evil.com.au", "evil.com.au"),
            ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
            ("a.b.bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
            (
                "lb.eu-west-1.elb.amazonaws.com",
                "eu-west-1.elb.amazonaws.com",
            ),
            (
                "x.bucket.s3.eu-west-1.amazonaws.com",
                "eu-west-1.amazonaws.com",
            ),
            ("acct.blob.core.windows.net", "acct.blob.core.windows.net"),
            ("svc-abc.a.run.app", "svc-abc.a.run.app"),
            ("evil.example", "evil.example"),
            ("co.uk", "co.uk"),
            ("uk", "uk"),
            ("", ""),
        ] {
            assert_eq!(registrable_domain(name), want, "{name}");
        }
    }

    #[test]
    fn local_only_zones() {
        for name in [
            "pod.svc.cluster.local",
            "x.corp",
            "db.internal",
            "printer.home.arpa",
            "nas.lan",
            "localhost",
            "a.b.LOCAL.",
        ] {
            assert!(is_local_only(name), "{name}");
        }
        for name in ["evil.example", "local.example", "x.arpa", "lan.evil.com"] {
            assert!(!is_local_only(name), "{name}");
        }
    }

    /// The tunnel's zone: the registrable domain below it, the old key
    /// otherwise; never a key finer than the old one.
    #[test]
    fn the_tunnel_zone_is_never_finer_than_the_old_key() {
        for (name, want) in [
            // the payload over two labels, a random label more, a ccTLD
            ("p1.p2.t.evil.example", "evil.example"),
            ("p1.r4nd.t.evil.example", "evil.example"),
            ("p1.p2.evil.co.uk", "evil.co.uk"),
            // the first label is the registrable one: the suffix, as before
            ("q7v3k9x2m4p8r6t1w5y0z3b7c9d2.com", "com"),
            ("hash.s3.amazonaws.com", "s3.amazonaws.com"),
            ("single", ""),
            // zones no query leaves: as before
            (
                "pod-x2kq9.payments.svc.cluster.local",
                "payments.svc.cluster.local",
            ),
            ("p1.p2.db.internal", "p2.db.internal"),
        ] {
            assert_eq!(tunnel_zone(name), want, "{name}");
        }
        for name in [
            "a.b.c.d.e.example.com",
            "x.y.evil.co.uk",
            "lb.eu-west-1.elb.amazonaws.com",
            "a.b.bucket.s3.amazonaws.com",
            "my-company-prod-backups.s3.amazonaws.com",
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.exfil.example.com",
            "x.co.uk",
            "x.y.z.cluster.local",
            "co.uk",
            "com",
            "a.b.",
        ] {
            let old = trim(name).split_once('.').map_or("", |(_, r)| r);
            let zone = tunnel_zone(name);
            assert!(
                old == zone || old.ends_with(&format!(".{zone}")),
                "{name}: {zone:?} is not {old:?} or a suffix of it"
            );
        }
    }
}
