#![no_main]
//! Fuzz the HAProxy PROXY protocol (v1 text + v2 binary) header decoder.
//!
//! Two invariants: (1) `parse` never panics on arbitrary bytes; (2) a header
//! that decodes and re-encodes to v2 round-trips back to the same value with
//! the same consumed length (encode/decode symmetry).

use libfuzzer_sys::fuzz_target;
use zentinel_common::proxy_protocol::{parse, ProxyHeader};

fuzz_target!(|data: &[u8]| {
    if let Ok((header, consumed)) = parse(data) {
        // The decoder must never claim to have consumed more than it was given.
        assert!(consumed <= data.len(), "consumed past end of input");

        // v2 is total (LOCAL + all inet families), so every decoded header
        // re-encodes and must decode again to an identical value.
        let reencoded = header.encode_v2();
        let (redecoded, reconsumed) =
            parse(&reencoded).expect("a re-encoded v2 header must decode again");
        assert_eq!(header, redecoded, "encode/decode is not stable");
        assert_eq!(reconsumed, reencoded.len(), "v2 re-encode has trailing bytes");

        // A LOCAL header must survive the infallible v2 encode as LOCAL.
        if matches!(header, ProxyHeader::Local) {
            assert!(matches!(redecoded, ProxyHeader::Local));
        }
    }
});
