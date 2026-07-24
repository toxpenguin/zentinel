#![no_main]
//! Fuzz the KDL configuration parser.
//!
//! `Config::from_kdl` accepts untrusted-ish operator input with a complex
//! grammar. It must never panic on arbitrary input — it should return an error
//! instead.

use libfuzzer_sys::fuzz_target;
use zentinel_config::Config;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Only invariant: never panic. Parse errors are expected and fine.
        let _ = Config::from_kdl(text);
    }
});
