#![no_main]
//! Fuzz the agent-protocol v2 `BinaryRequestHeaders` frame decoder.
//!
//! Two invariants: (1) never panic on arbitrary bytes (a decoder panic on
//! crafted input is a denial-of-service vector); (2) a successfully decoded
//! frame round-trips — re-encoding then decoding yields identical bytes
//! (encode/decode symmetry; encoding is deterministic).

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use zentinel_agent_protocol::binary::BinaryRequestHeaders;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = BinaryRequestHeaders::decode(Bytes::copy_from_slice(data)) {
        let encoded = decoded.encode();
        let redecoded = BinaryRequestHeaders::decode(encoded.clone())
            .expect("a re-encoded frame must decode again");
        assert_eq!(encoded, redecoded.encode(), "encode/decode is not stable");
    }
});
