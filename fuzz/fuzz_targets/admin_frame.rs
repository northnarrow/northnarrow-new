#![no_main]
//! Admin socket frames arrive from a local client that may be hostile
//! (a compromised root shell talks to the same socket). Beyond "never
//! panics" (reject, or ask for more bytes):
//! - a decoded frame consumed exactly its length prefix, within what was
//!   given, and an accepted envelope's version is one this agent speaks;
//! - the decoded message encodes again and decodes to the same message,
//!   in the v1 envelope and the v0 body alike: the agent acts on a value
//!   it would itself send, whatever bytes spelled it.
use libfuzzer_sys::fuzz_target;
use northnarrow_common::wire::admin_protocol::{
    decode_frame, decode_versioned_frame, decode_versioned_or_legacy_frame, encode_frame,
    encode_versioned_frame, PROTOCOL_VERSION,
};

fn framed_len(data: &[u8]) -> usize {
    4 + u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize
}

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((envelope, used))) = decode_versioned_or_legacy_frame(data) {
        assert_eq!(used, framed_len(data));
        assert!(used <= data.len());
        assert!(envelope.version <= PROTOCOL_VERSION);
        if envelope.version == 0 {
            let again = encode_frame(&envelope.message).expect("a decoded body re-encodes");
            let (back, _) = decode_frame(&again).unwrap().unwrap();
            assert_eq!(back, envelope.message);
        } else {
            let again = encode_versioned_frame(&envelope).expect("a decoded body re-encodes");
            let (back, _) = decode_versioned_frame(&again).unwrap().unwrap();
            assert_eq!(back, envelope);
        }
    }
    if let Ok(Some((message, used))) = decode_frame(data) {
        assert_eq!(used, framed_len(data));
        let again = encode_frame(&message).expect("a decoded body re-encodes");
        assert_eq!(decode_frame(&again).unwrap().unwrap().0, message);
    }
});
