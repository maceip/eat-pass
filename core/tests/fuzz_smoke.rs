//! Deterministic "fuzz smoke" for the untrusted-input parsers (m3 hardening).
//!
//! The real fuzzers live in `core/fuzz/` (libFuzzer via `cargo fuzz run`); this
//! is the always-on CI guard: a reproducible xorshift PRNG drives a large batch
//! of random and structured inputs through [`Token::from_bytes`] and
//! [`http::parse_authorization`], asserting they (a) never panic and (b) hold
//! the roundtrip invariant for anything they accept. No nightly toolchain
//! required, so it runs in the normal `cargo test` matrix on every platform.

use eat_pass_core::{http, Token};

/// Tiny deterministic PRNG (xorshift64*) — reproducible across platforms so a
/// failure is replayable from the seed.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
    fn len(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % (max + 1)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

#[test]
fn token_from_bytes_never_panics_and_roundtrips() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..50_000 {
        // Bias toward the boundary around the 98-byte fixed prefix.
        let n = match rng.next_u64() % 4 {
            0 => rng.len(8),       // far too short
            1 => 90 + rng.len(20), // straddles the 99-byte minimum
            _ => rng.len(512),     // arbitrary
        };
        let buf = rng.bytes(n);
        match Token::from_bytes(&buf) {
            Ok(tok) => {
                // Accepted ⇒ the canonical encoding must reproduce the input
                // exactly (the parser keeps the whole tail as authenticator).
                assert_eq!(tok.to_bytes(), buf, "roundtrip mismatch for len {n}");
            }
            Err(_) => {
                // Anything < 99 bytes must be rejected, never accepted.
                assert!(buf.len() < 99, "short buffer should have been rejected");
            }
        }
    }
}

#[test]
fn parse_authorization_never_panics() {
    let mut rng = Rng(0x0fed_cba9_8765_4321);
    let pieces = [
        "PrivateToken token=",
        "PrivateToken token=\"",
        "PrivateToken ",
        "Bearer ",
        "token=",
        "=,\"",
        "AAAABBBB____----",
        "  ",
    ];
    for _ in 0..50_000 {
        // Assemble a header from random literal pieces + random bytes rendered
        // as a (possibly invalid) base64url-ish string.
        let mut s = String::new();
        let parts = 1 + (rng.next_u64() as usize % 4);
        for _ in 0..parts {
            let p = pieces[rng.next_u64() as usize % pieces.len()];
            s.push_str(p);
            let extra_len = rng.len(40);
            let extra = rng.bytes(extra_len);
            for b in extra {
                // Keep it ASCII-ish so we also exercise the b64 decoder.
                s.push((0x21 + (b % 0x5d)) as char);
            }
        }
        // Must not panic; result is don't-care.
        let _ = http::parse_authorization(&s);
    }
}

#[test]
fn authorization_roundtrips_for_arbitrary_tokens() {
    // Any byte string ≥ 99 bytes is a valid Token wire form; rendering it as an
    // RFC 9577 header and parsing it back must recover the same token.
    let mut rng = Rng(0xa5a5_5a5a_dead_beef);
    for _ in 0..10_000 {
        let tail = rng.len(300);
        let buf = rng.bytes(99 + tail);
        let tok = Token::from_bytes(&buf).expect("≥99 bytes parses");
        let header = http::authorization(&tok);
        let back = http::parse_authorization(&header).expect("our own header parses");
        assert_eq!(back.to_bytes(), buf);
    }
}
