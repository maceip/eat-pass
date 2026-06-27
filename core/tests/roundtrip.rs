use eat_pass_core::gate::{issue_gated, DevAttester, DevVerifier, GateError, Measurement};
use eat_pass_core::{
    binding_of, Client, Issuer, IssuerPublicKey, SignResponse, Token, UseCase, Verifier,
};

// 2048-bit keys keep tests fast; production default is 3072.
const TEST_BITS: usize = 2048;

fn issuer() -> Issuer {
    Issuer::generate(1, TEST_BITS).expect("keygen")
}

#[test]
fn happy_path_issue_finalize_verify() {
    let issuer = issuer();
    let pk = issuer.public();
    let uc = UseCase::new("login");

    let (req, pending) = Client::begin(&pk, &uc, 3).unwrap();
    assert_eq!(pending.len(), 3);
    let resp = issuer.blind_sign(&req).unwrap();
    let tokens = pending.finalize(&pk, &resp).unwrap();
    assert_eq!(tokens.len(), 3);

    let verifier = Verifier::new(pk);
    for t in &tokens {
        let nonce = verifier.verify(t, &uc).unwrap();
        assert_eq!(nonce, t.nonce);
    }
}

#[test]
fn tokens_are_unlinkable_to_blinded_messages() {
    // The bytes the issuer saw (blinded messages) must not appear in the token,
    // and distinct tokens carry distinct nonces.
    let issuer = issuer();
    let pk = issuer.public();
    let uc = UseCase::new("infer");

    let (req, pending) = Client::begin(&pk, &uc, 2).unwrap();
    let resp = issuer.blind_sign(&req).unwrap();
    let tokens = pending.finalize(&pk, &resp).unwrap();

    assert_ne!(tokens[0].nonce, tokens[1].nonce);
    let blinded0: &[u8] = req.blinded[0].as_ref();
    let sig0: &[u8] = tokens[0].sig.as_ref();
    assert_ne!(blinded0, sig0);
}

#[test]
fn tampered_token_fails() {
    let issuer = issuer();
    let pk = issuer.public();
    let uc = UseCase::new("login");

    let (req, pending) = Client::begin(&pk, &uc, 1).unwrap();
    let resp = issuer.blind_sign(&req).unwrap();
    let mut token = pending.finalize(&pk, &resp).unwrap().pop().unwrap();

    let verifier = Verifier::new(pk);
    // flip a nonce bit
    token.nonce[0] ^= 0x01;
    assert!(verifier.verify(&token, &uc).is_err());
}

#[test]
fn wrong_use_case_fails() {
    let issuer = issuer();
    let pk = issuer.public();
    let minted = UseCase::new("login");
    let presented = UseCase::new("admin");

    let (req, pending) = Client::begin(&pk, &minted, 1).unwrap();
    let resp = issuer.blind_sign(&req).unwrap();
    let token = pending.finalize(&pk, &resp).unwrap().pop().unwrap();

    let verifier = Verifier::new(pk);
    assert!(verifier.verify(&token, &presented).is_err());
}

#[test]
fn gate_happy_path() {
    let issuer = issuer();
    let pk = issuer.public();
    let uc = UseCase::new("infer");

    let attester = DevAttester::generate().unwrap();
    let measurement = Measurement::new("dev", vec![7u8; 32]);
    let verifier_gate =
        DevVerifier::new(attester.verifying_key(), [measurement.value_x.clone()]).unwrap();

    let (req, pending) = Client::begin(&pk, &uc, 2).unwrap();
    // attester commits to the real binding of this request
    let binding = binding_of(&req.blinded);
    let eat = attester.attest(&measurement, &binding);

    let resp = issue_gated(&issuer, &verifier_gate, &req, &eat).unwrap();
    let tokens = pending.finalize(&pk, &resp).unwrap();

    let verifier = Verifier::new(pk);
    assert_eq!(tokens.len(), 2);
    for t in &tokens {
        verifier.verify(t, &uc).unwrap();
    }
}

#[test]
fn gate_rejects_wrong_binding() {
    let issuer = issuer();
    let pk = issuer.public();
    let attester = DevAttester::generate().unwrap();
    let measurement = Measurement::new("dev", vec![7u8; 32]);
    let gate = DevVerifier::new(attester.verifying_key(), [measurement.value_x.clone()]).unwrap();

    let (req, _pending) = Client::begin(&pk, &UseCase::new("infer"), 1).unwrap();
    // attest a *different* binding than the request's
    let eat = attester.attest(&measurement, &[0u8; 32]);
    let err = issue_gated(&issuer, &gate, &req, &eat).unwrap_err();
    assert_eq!(err, GateError::BindingMismatch);
}

#[test]
fn gate_rejects_unallowed_measurement() {
    let issuer = issuer();
    let pk = issuer.public();
    let attester = DevAttester::generate().unwrap();
    // allowlist contains a different measurement
    let gate = DevVerifier::new(attester.verifying_key(), [vec![1u8; 32]]).unwrap();

    let (req, _pending) = Client::begin(&pk, &UseCase::new("infer"), 1).unwrap();
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
    // verifier trusts `real`, but the eat is signed by `forger`
    let gate = DevVerifier::new(real.verifying_key(), [measurement.value_x.clone()]).unwrap();

    let (req, _pending) = Client::begin(&pk, &UseCase::new("infer"), 1).unwrap();
    let binding = binding_of(&req.blinded);
    let eat = forger.attest(&measurement, &binding);
    let err = issue_gated(&issuer, &gate, &req, &eat).unwrap_err();
    assert!(matches!(err, GateError::AttestationInvalid(_)));
}

#[test]
fn json_wire_roundtrip() {
    let issuer = issuer();
    let pk = issuer.public();
    let uc = UseCase::new("login");

    // IssuerPublicKey survives a JSON round trip and still verifies tokens.
    let pk_json = serde_json::to_string(&pk).unwrap();
    let pk2: IssuerPublicKey = serde_json::from_str(&pk_json).unwrap();

    let (req, pending) = Client::begin(&pk2, &uc, 1).unwrap();
    let req_json = serde_json::to_string(&req).unwrap();
    let req2: eat_pass_core::SignRequest = serde_json::from_str(&req_json).unwrap();

    let resp = issuer.blind_sign(&req2).unwrap();
    let resp_json = serde_json::to_string(&resp).unwrap();
    let resp2: SignResponse = serde_json::from_str(&resp_json).unwrap();

    let token = pending.finalize(&pk2, &resp2).unwrap().pop().unwrap();
    let token_json = serde_json::to_string(&token).unwrap();
    let token2: Token = serde_json::from_str(&token_json).unwrap();

    let verifier = Verifier::new(pk);
    verifier.verify(&token2, &uc).unwrap();
}
