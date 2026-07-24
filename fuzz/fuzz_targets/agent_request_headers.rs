#![no_main]
//! Fuzz the agent-protocol v2 `BinaryRequestHeaders` frame decoder.
//!
//! This is a network-facing binary decoder: the invariant is that it must never
//! panic on arbitrary bytes — malformed input must produce an `Err`, not a
//! crash (a decoder panic on crafted input is a denial-of-service vector).

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use zentinel_agent_protocol::binary::BinaryRequestHeaders;

fuzz_target!(|data: &[u8]| {
    let _ = BinaryRequestHeaders::decode(Bytes::copy_from_slice(data));
});
