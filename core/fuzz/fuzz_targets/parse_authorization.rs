#![no_main]
//! Fuzz the RFC 9577 `Authorization: PrivateToken` header parser against
//! arbitrary (possibly non-UTF8) bytes. Must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = eat_pass_core::http::parse_authorization(s);
    }
});
