#![no_main]
//! Fuzz the agent-protocol v2 `BinaryAgentResponse` frame decoder.
//!
//! Two invariants: (1) never panic on arbitrary bytes; (2) a successfully
//! decoded frame round-trips (encode/decode symmetry).

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use zentinel_agent_protocol::binary::BinaryAgentResponse;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = BinaryAgentResponse::decode(Bytes::copy_from_slice(data)) {
        let encoded = decoded.encode();
        let redecoded = BinaryAgentResponse::decode(encoded.clone())
            .expect("a re-encoded frame must decode again");
        assert_eq!(encoded, redecoded.encode(), "encode/decode is not stable");
    }
});
