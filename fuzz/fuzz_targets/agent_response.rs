#![no_main]
//! Fuzz the agent-protocol v2 `BinaryAgentResponse` frame decoder.
//!
//! Network-facing binary decoder: the invariant is that it must never panic on
//! arbitrary bytes — malformed input must produce an `Err`, not a crash.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use zentinel_agent_protocol::binary::BinaryAgentResponse;

fuzz_target!(|data: &[u8]| {
    let _ = BinaryAgentResponse::decode(Bytes::copy_from_slice(data));
});
