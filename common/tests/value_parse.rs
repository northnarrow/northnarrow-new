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
    assert_eq!(judge(KIND_LIBPATH, &long), 0);
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
        end_entry(&mut p, KIND_PRELOAD);
        assert_ne!(p.found & STAGING, 0, "cut at {cut}");
    }
}
