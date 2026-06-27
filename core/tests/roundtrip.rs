use eat_pass_core::gate::{
    issue_gated, issue_gated_with_limit, DevAttester, DevVerifier, GateError, Measurement,
    MeasurementClass,
};
use eat_pass_core::ratelimit::InMemoryRateLimiter;
use eat_pass_core::{
    binding_of, check_key_consistency, http, Client, Issuer, IssuerPublicKey, SignResponse, Token,
    TokenChallenge, Verifier,
};

// 2048-bit keys keep tests fast; production default is 3072.
const TEST_BITS: usize = 2048;

fn issuer() -> Issuer {
    Issuer::generate(1, TEST_BITS).expect("keygen")
}

fn challenge() -> TokenChallenge {
    TokenChallenge::new("issuer.example", "origin.example")
}

#[test]
fn happy_path_issue_finalize_verify() {
    let issuer = issuer();
    let pk = issuer.public();
    let ch = challenge();

    let (req, pending) = Client::begin(&pk, &ch, 3).unwrap();
    assert_eq!(pending.len(), 3);
    let resp = issuer.blind_sign(&req).unwrap();
    let tokens = pending.finalize(&pk, &resp).unwrap();
    assert_eq!(tokens.len(), 3);

    let verifier = Verifier::new(pk);
    for t in &tokens {
        let nonce = verifier.verify(t, &ch).unwrap();
        assert_eq!(nonce, t.nonce);
    }
}

#[test]
fn tokens_are_unlinkable_to_blinded_messages() {
    let issuer = issuer();
    let pk = issuer.public();
    let ch = challenge();

    let (req, pending) = Client::begin(&pk, &ch, 2).unwrap();
    let resp = issuer.blind_sign(&req).unwrap();
    let tokens = pending.finalize(&pk, &resp).unwrap();

    assert_ne!(tokens[0].nonce, tokens[1].nonce);
    let blinded0: &[u8] = req.blinded[0].as_ref();
    let auth0: &[u8] = tokens[0].authenticator.as_ref();
    assert_ne!(blinded0, auth0);
}

#[test]
fn tampered_token_fails() {
    let issuer = issuer();
    let pk = issuer.public();
    let ch = challenge();

    let (req, pending) = Client::begin(&pk, &ch, 1).unwrap();
    let resp = issuer.blind_sign(&req).unwrap();
    let mut token = pending.finalize(&pk, &resp).unwrap().pop().unwrap();

    let verifier = Verifier::new(pk);
    token.nonce[0] ^= 0x01;
    assert!(verifier.verify(&token, &ch).is_err());
}

#[test]
fn wrong_challenge_fails() {
    let issuer = issuer();
    let pk = issuer.public();
    let minted = TokenChallenge::new("issuer.example", "origin-a.example");
    let presented = TokenChallenge::new("issuer.example", "origin-b.example");

    let (req, pending) = Client::begin(&pk, &minted, 1).unwrap();
    let resp = issuer.blind_sign(&req).unwrap();
    let token = pending.finalize(&pk, &resp).unwrap().pop().unwrap();

    let verifier = Verifier::new(pk);
    assert!(verifier.verify(&token, &presented).is_err());
}

#[test]
fn token_key_id_pins_the_issuer_key() {
    // A token minted by issuer A must not verify against issuer B's key — the
    // token_key_id pin (E.4) catches a swapped/split issuer key.
    let issuer_a = issuer();
    let issuer_b = issuer();
    let pk_a = issuer_a.public();
    let ch = challenge();

    let (req, pending) = Client::begin(&pk_a, &ch, 1).unwrap();
    let resp = issuer_a.blind_sign(&req).unwrap();
    let token = pending.finalize(&pk_a, &resp).unwrap().pop().unwrap();

    let verifier_b = Verifier::new(issuer_b.public());
    assert!(verifier_b.verify(&token, &ch).is_err());
}

#[test]
fn key_consistency_check() {
    let issuer = issuer();
    let pk = issuer.public();
    let pinned = pk.token_key_id().unwrap();
    assert!(check_key_consistency(&pinned, &pk).is_ok());

    let other = Issuer::generate(1, TEST_BITS).unwrap().public();
    assert!(check_key_consistency(&pinned, &other).is_err());
}

#[test]
fn token_bytes_roundtrip() {
    let issuer = issuer();
    let pk = issuer.public();
    let ch = challenge();
    let (req, pending) = Client::begin(&pk, &ch, 1).unwrap();
    let resp = issuer.blind_sign(&req).unwrap();
    let token = pending.finalize(&pk, &resp).unwrap().pop().unwrap();

    let bytes = token.to_bytes();
    let back = Token::from_bytes(&bytes).unwrap();
    assert_eq!(back.token_type, token.token_type);
    assert_eq!(back.nonce, token.nonce);
    assert_eq!(back.challenge_digest, token.challenge_digest);
    assert_eq!(back.token_key_id, token.token_key_id);
    let a: &[u8] = back.authenticator.as_ref();
    let b: &[u8] = token.authenticator.as_ref();
    assert_eq!(a, b);

    Verifier::new(pk).verify(&back, &ch).unwrap();
}

#[test]
fn http_authorization_roundtrip() {
    let issuer = issuer();
    let pk = issuer.public();
    let ch = challenge();
    let (req, pending) = Client::begin(&pk, &ch, 1).unwrap();
    let resp = issuer.blind_sign(&req).unwrap();
    let token = pending.finalize(&pk, &resp).unwrap().pop().unwrap();

    // RFC 9577 WWW-Authenticate (origin → client) carries the challenge + key.
    let www = http::www_authenticate(&ch.to_bytes(), &pk).unwrap();
    assert!(www.starts_with("PrivateToken challenge="));

    // RFC 9577 Authorization (client → origin) carries the token.
    let header = http::authorization(&token);
    let parsed = http::parse_authorization(&header).unwrap();
    Verifier::new(pk).verify(&parsed, &ch).unwrap();
}

#[test]
fn gate_happy_path() {
    let issuer = issuer();
    let pk = issuer.public();
    let ch = challenge();

    let attester = DevAttester::generate().unwrap();
    let measurement = Measurement::new("dev", vec![7u8; 32]);
    let verifier_gate =
        DevVerifier::new(attester.verifying_key(), [measurement.value_x.clone()]).unwrap();

    let (req, pending) = Client::begin(&pk, &ch, 2).unwrap();
    let binding = binding_of(&req.blinded);
    let eat = attester.attest(&measurement, &binding);

    let resp = issue_gated(&issuer, &verifier_gate, &req, &eat).unwrap();
    let tokens = pending.finalize(&pk, &resp).unwrap();

    let verifier = Verifier::new(pk);
    assert_eq!(tokens.len(), 2);
    for t in &tokens {
        verifier.verify(t, &ch).unwrap();
    }
}

#[test]
fn gate_rejects_wrong_binding() {
    let issuer = issuer();
    let pk = issuer.public();
    let attester = DevAttester::generate().unwrap();
    let measurement = Measurement::new("dev", vec![7u8; 32]);
    let gate = DevVerifier::new(attester.verifying_key(), [measurement.value_x.clone()]).unwrap();

    let (req, _pending) = Client::begin(&pk, &challenge(), 1).unwrap();
    let eat = attester.attest(&measurement, &[0u8; 32]);
    let err = issue_gated(&issuer, &gate, &req, &eat).unwrap_err();
    assert_eq!(err, GateError::BindingMismatch);
}

#[test]
fn gate_rejects_unallowed_measurement() {
    let issuer = issuer();
    let pk = issuer.public();
    let attester = DevAttester::generate().unwrap();
    let gate = DevVerifier::new(attester.verifying_key(), [vec![1u8; 32]]).unwrap();

    let (req, _pending) = Client::begin(&pk, &challenge(), 1).unwrap();
    let binding = binding_of(&req.blinded);
    let eat = attester.attest(&Measurement::new("dev", vec![9u8; 32]), &binding);
    let err = issue_gated(&issuer, &gate, &req, &eat).unwrap_err();
    assert_eq!(err, GateError::MeasurementNotAllowed);
}

#[test]
fn gate_rejects_forged_attester() {
    let issuer = issuer();
    let pk = issuer.public();
    let real = DevAttester::generate().unwrap();
    let forger = DevAttester::generate().unwrap();
    let measurement = Measurement::new("dev", vec![7u8; 32]);
    let gate = DevVerifier::new(real.verifying_key(), [measurement.value_x.clone()]).unwrap();

    let (req, _pending) = Client::begin(&pk, &challenge(), 1).unwrap();
    let binding = binding_of(&req.blinded);
    let eat = forger.attest(&measurement, &binding);
    let err = issue_gated(&issuer, &gate, &req, &eat).unwrap_err();
    assert!(matches!(err, GateError::AttestationInvalid(_)));
}

#[test]
fn gate_on_measurement_class() {
    // E.5: gate on a named class containing several builds, not an exact value.
    let issuer = issuer();
    let pk = issuer.public();
    let attester = DevAttester::generate().unwrap();
    let build_a = vec![1u8; 32];
    let build_b = vec![2u8; 32];
    let class = MeasurementClass::new("accepted-builds", 1, [build_a.clone(), build_b.clone()]);
    assert_eq!(class.policy_label(), "accepted-builds@v1");
    let gate = DevVerifier::new_for_class(attester.verifying_key(), class).unwrap();

    let (req, _pending) = Client::begin(&pk, &challenge(), 1).unwrap();
    let binding = binding_of(&req.blinded);
    // build_b is in the class even though we didn't name it exactly
    let eat = attester.attest(&Measurement::new("dev", build_b), &binding);
    assert!(issue_gated(&issuer, &gate, &req, &eat).is_ok());
}

#[test]
fn rate_limit_gate_blocks_over_quota() {
    // E.7: the same attested build can only mint up to the per-epoch quota.
    let issuer = issuer();
    let pk = issuer.public();
    let attester = DevAttester::generate().unwrap();
    let m = Measurement::new("dev", vec![7u8; 32]);
    let gate = DevVerifier::new(attester.verifying_key(), [m.value_x.clone()]).unwrap();
    let limiter = InMemoryRateLimiter::new(2, 3600);

    // First batch of 2 consumes the whole quota.
    let (req1, _p1) = Client::begin(&pk, &challenge(), 2).unwrap();
    let eat1 = attester.attest(&m, &binding_of(&req1.blinded));
    assert!(issue_gated_with_limit(&issuer, &gate, &req1, &eat1, &limiter).is_ok());

    // Next request from the same build is over quota.
    let (req2, _p2) = Client::begin(&pk, &challenge(), 1).unwrap();
    let eat2 = attester.attest(&m, &binding_of(&req2.blinded));
    let err = issue_gated_with_limit(&issuer, &gate, &req2, &eat2, &limiter).unwrap_err();
    assert_eq!(err, GateError::QuotaExceeded);
}

#[test]
fn json_wire_roundtrip() {
    let issuer = issuer();
    let pk = issuer.public();
    let ch = challenge();

    let pk_json = serde_json::to_string(&pk).unwrap();
    let pk2: IssuerPublicKey = serde_json::from_str(&pk_json).unwrap();

    let (req, pending) = Client::begin(&pk2, &ch, 1).unwrap();
    let req_json = serde_json::to_string(&req).unwrap();
    let req2: eat_pass_core::SignRequest = serde_json::from_str(&req_json).unwrap();

    let resp = issuer.blind_sign(&req2).unwrap();
    let resp_json = serde_json::to_string(&resp).unwrap();
    let resp2: SignResponse = serde_json::from_str(&resp_json).unwrap();

    let token = pending.finalize(&pk2, &resp2).unwrap().pop().unwrap();
    let token_json = serde_json::to_string(&token).unwrap();
    let token2: Token = serde_json::from_str(&token_json).unwrap();

    let verifier = Verifier::new(pk);
    verifier.verify(&token2, &ch).unwrap();
}
