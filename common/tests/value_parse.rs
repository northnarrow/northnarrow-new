//! The review of #547 (F1, F7): the loader variables' values as the eBPF
//! program judges them (`value_parse`, run byte by byte over the kernel's
//! reads of the value). Here, not in the module: its inputs name `/proc`
//! and `/dev/fd` paths, which the product-code ratchet
//! (`xtask/tests/proc_links.rs`) counts.

use northnarrow_common::wire::execpol::value_parse::*;

/// The review of #547 (F1): each loader entry judged as the loader parses
/// the list, over the normalised path, wherever it starts in the value.
/// The reviewer's forms each passed: 120 spaces then `/tmp/x` (the entry
/// started past the first 119 bytes of the 128-byte capture), `//tmp/`,
/// `/./tmp/`, `/var/../tmp/`, a tab (musl), a relative path.
#[test]
fn every_loader_entry_is_judged_as_the_loader_reads_it() {
    let preload = |v: &[u8]| judge(KIND_PRELOAD, v);
    let mut padded = vec![b' '; 120];
    padded.extend_from_slice(b"/tmp/x");
    for (v, what) in [
        (&b"/tmp/x.so"[..], "plain"),
        (&padded[..], "120 spaces"),
        (b"//tmp/x.so", "a doubled slash"),
        (b"/./tmp/x.so", "a dot component"),
        (b"/var/../tmp/x.so", "a dot-dot"),
        (b"/usr/lib/../../tmp/x.so", "two dot-dots"),
        (b"\t/tmp/x.so", "a leading tab"),
        (b"/usr/lib/a.so\t/tmp/x.so", "a tab between (musl)"),
        (b"/usr/lib/a.so:/var/tmp/y/x.so", "the second entry"),
        (b"/dev/shm/x", "/dev/shm"),
        (b"/proc/self/fd/3", "/proc"),
        (b"/dev/fd/3", "/dev/fd"),
    ] {
        assert_ne!(
            preload(v) & STAGING,
            0,
            "{what}: {}",
            String::from_utf8_lossy(v)
        );
    }
    for v in [
        &b"/usr/lib/x86_64-linux-gnu/libjemalloc.so.2"[..],
        b"/usr//lib/./libx.so",
        b"/tmpx/a.so",
        b"/var/tmpx/a.so",
        b"/tmp",
        b"/var/tmp/../lib/a.so",
        b"/dev/shmx/a",
    ] {
        assert_eq!(preload(v) & STAGING, 0, "{}", String::from_utf8_lossy(v));
    }
    // relative paths: where they resolve is not in the string
    for v in [&b"./x.so"[..], b"lib/x.so", b"../tmp/x.so"] {
        assert_ne!(preload(v) & RELATIVE, 0, "{}", String::from_utf8_lossy(v));
    }
    // a bare name is searched in the library path
    assert_eq!(preload(b"libjemalloc.so.2"), BARE);
    // LD_AUDIT splits on colons only; LD_LIBRARY_PATH's directories
    assert_ne!(judge(KIND_AUDIT, b"/usr/lib/a.so:/tmp/au.so") & STAGING, 0);
    assert_ne!(judge(KIND_LIBPATH, b"/opt/lib:/tmp") & STAGING, 0);
    assert_ne!(judge(KIND_LIBPATH, b"/var/tmp") & STAGING, 0);
    assert_ne!(judge(KIND_LIBPATH, b"lib") & RELATIVE, 0);
    assert_eq!(judge(KIND_LIBPATH, b"/usr/lib:/opt/x/lib"), 0);
    // the Steam overlay (two clean entries, 131 bytes): clean
    assert_eq!(
        preload(
            b"/home/alice/.local/share/Steam/ubuntu12_32/gameoverlayrenderer.so:/home/alice/.local/share/Steam/ubuntu12_64/gameoverlayrenderer.so"
        ),
        0
    );
    // long clean values (a desktop's overlays, a runtime's library path):
    // clean, however long (the review of #547, F7: a clean value past its
    // 128-byte capture was refused)
    let entry = b"/opt/runtime/usr/lib/x86_64-linux-gnu/libsteam_overlay.so";
    let mut long = Vec::new();
    for _ in 0..60 {
        long.extend_from_slice(entry);
        long.push(b':');
    }
    assert!(long.len() > 3000);
    assert_eq!(preload(&long), 0);
    assert_eq!(judge(KIND_LIBPATH, &long[..long.len() - 1]), 0);
    // (with its trailing `:`, a library path ends with an empty element:
    // the caller's directory — the re-check of #547, G2)
    assert_eq!(judge(KIND_LIBPATH, &long), IRREGULAR);
    // and a staging entry at its end is still seen
    long.extend_from_slice(b"/tmp/x.so");
    assert_ne!(preload(&long) & STAGING, 0);
    // fed in pieces (the kernel's reads), the same
    let v = b"/usr/lib/a.so /var/./../tmp/b/x.so";
    for cut in 0..v.len() {
        let mut p = ValueParse::zeroed();
        for &b in &v[..cut] {
            byte(&mut p, KIND_PRELOAD, b);
        }
        for &b in &v[cut..] {
            byte(&mut p, KIND_PRELOAD, b);
        }
        end_value(&mut p, KIND_PRELOAD);
        assert_ne!(p.found & STAGING, 0, "cut at {cut}");
    }
}

/// The re-check of #547 (G1–G4, the reviewer's probe
/// `rev547-recheck-value-parse-probe.rs`): what the loader does with a
/// control byte, an empty library-path element or a `$` token is not in
/// the string as the parser reads it — each is `IRREGULAR` (refused at a
/// protected or set-id target). glibc 2.39 loaded the marker in G1–G3.
#[test]
fn an_irregular_loader_value_is_never_clean() {
    let irregular = |kind: u32, v: &[u8]| judge(kind, v) & IRREGULAR != 0;
    for (kind, v, what) in [
        // G1: glibc splits LD_PRELOAD on " :" only — one entry, relative
        (
            KIND_PRELOAD,
            &b"lib\t/x.so"[..],
            "a tab inside an LD_PRELOAD entry",
        ),
        (KIND_PRELOAD, b"/usr/lib/a.so\n/tmp/x.so", "a newline"),
        (
            KIND_AUDIT,
            b"/usr/lib/a.so\x0b/x.so",
            "a vertical tab in LD_AUDIT",
        ),
        // G2: an empty element is the caller's directory
        (KIND_LIBPATH, b":", "a lone separator"),
        (KIND_LIBPATH, b":/usr/lib", "a leading empty element"),
        (KIND_LIBPATH, b"/usr/lib:", "a trailing empty element"),
        (
            KIND_LIBPATH,
            b"/usr/lib::/opt/x",
            "an empty element between two",
        ),
        (
            KIND_LIBPATH,
            b"/usr/lib;;/opt/x",
            "an empty element, semicolons",
        ),
        // G3: dynamic string tokens
        (KIND_PRELOAD, b"/tmp/$LIB/../../x.so", "$LIB"),
        (KIND_PRELOAD, b"$ORIGIN/../../tmp/x.so", "$ORIGIN"),
        (KIND_PRELOAD, b"/opt/${PLATFORM}/x.so", "${PLATFORM}"),
        (KIND_AUDIT, b"/opt/$LIB/audit.so", "$LIB in LD_AUDIT"),
        (KIND_LIBPATH, b"/tmp/$LIB/../..", "$LIB in LD_LIBRARY_PATH"),
        // G4: musl splits its library path on a newline
        (
            KIND_LIBPATH,
            b"/usr/lib\n/tmp",
            "a newline in LD_LIBRARY_PATH",
        ),
        (KIND_LIBPATH, b"/usr/lib\x7f", "DEL"),
    ] {
        assert!(irregular(kind, v), "{what}: {}", String::from_utf8_lossy(v));
    }
    // and the newline still splits musl's path: its staging entry is seen
    assert_ne!(judge(KIND_LIBPATH, b"/usr/lib\n/tmp") & STAGING, 0);
    // the controls: regular values stay clean
    for (kind, v) in [
        (
            KIND_PRELOAD,
            &b"/usr/lib/x86_64-linux-gnu/libjemalloc.so.2"[..],
        ),
        (KIND_PRELOAD, b"/usr/lib/a.so /usr/lib/b.so:/usr/lib/c.so"),
        (KIND_AUDIT, b"/usr/lib/a.so:/usr/lib/b.so"),
        (KIND_LIBPATH, b"/usr/lib:/opt/x/lib;/usr/local/lib"),
        (KIND_LIBPATH, b""),
        (KIND_PRELOAD, b""),
    ] {
        assert_eq!(
            judge(kind, v) & IRREGULAR,
            0,
            "{}",
            String::from_utf8_lossy(v)
        );
    }
    // an empty element of LD_PRELOAD or LD_AUDIT is skipped by the loader
    assert_eq!(
        judge(KIND_PRELOAD, b"/usr/lib/a.so::/usr/lib/b.so") & IRREGULAR,
        0
    );
    // fed in pieces, the same (the state carried across the kernel's reads)
    let v = b"/usr/lib:";
    let mut p = ValueParse::zeroed();
    for &b in v {
        byte(&mut p, KIND_LIBPATH, b);
    }
    end_value(&mut p, KIND_LIBPATH);
    assert_ne!(p.found & IRREGULAR, 0);
}
