#![no_main]
//! Fuzz the RFC 9578 token wire parser. Invariants:
//! - never panics on arbitrary input;
//! - anything accepted re-encodes to exactly the input (canonical roundtrip).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(tok) = eat_pass_core::Token::from_bytes(data) {
        assert_eq!(tok.to_bytes(), data);
    }
});
