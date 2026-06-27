//! End-to-end test of the eat-pass roles wired together: attest → blind-sign
//! through the gate → finalize → present (RFC 9577 header) → spend → reject
//! replay. Uses small keys for speed; the demo path also JSON-roundtrips the
//! `/sign` envelope so the wire format is exercised.

use eat_pass_cli::demo;

#[test]
fn demo_runs_end_to_end() {
    // 2048-bit keys keep the test fast; mint a batch of 3.
    let minted = demo::run_in_process(2048, 3).expect("end-to-end demo should succeed");
    assert_eq!(minted, 3);
}

#[test]
fn demo_single_token() {
    let minted = demo::run_in_process(2048, 1).expect("single-token demo should succeed");
    assert_eq!(minted, 1);
}
