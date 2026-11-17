extern crate std;

use crate::{Error, PqAccount, PqAccountClient, SIGNING_CONTEXT};
use ml_dsa::{Keypair, MlDsa65, SigningKey};
use soroban_sdk::{testutils::BytesN as _, vec, BytesN, Env, InvokeError, IntoVal};
use std::vec::Vec;

/// Deterministic test key from a one-byte seed.
fn keypair(seed: u8) -> SigningKey<MlDsa65> {
    SigningKey::<MlDsa65>::from_seed(&[seed; 32].into())
}

fn public_key_bytes(env: &Env, sk: &SigningKey<MlDsa65>) -> BytesN<1952> {
    let encoded = sk.verifying_key().encode();
    BytesN::from_array(env, &encoded.into())
}

fn sign(env: &Env, sk: &SigningKey<MlDsa65>, msg: &[u8], ctx: &[u8]) -> BytesN<3309> {
    let sig = sk.expanded_key().sign_deterministic(msg, ctx).unwrap();
    BytesN::from_array(env, &sig.encode().into())
}

fn setup(seed: u8) -> (Env, soroban_sdk::Address, SigningKey<MlDsa65>) {
    let env = Env::default();
    let sk = keypair(seed);
    let pk = public_key_bytes(&env, &sk);
    let id = env.register(PqAccount, (pk,));
    (env, id, sk)
}

fn check_auth(
    env: &Env,
    account: &soroban_sdk::Address,
    payload: &BytesN<32>,
    sig: &BytesN<3309>,
) -> Result<(), Result<Error, InvokeError>> {
    env.try_invoke_contract_check_auth::<Error>(account, payload, sig.into_val(env), &vec![env])
}

#[test]
fn constructor_stores_public_key() {
    let (env, id, sk) = setup(1);
    let client = PqAccountClient::new(&env, &id);
    assert_eq!(client.public_key(), public_key_bytes(&env, &sk));
}

#[test]
fn accepts_valid_signature() {
    let (env, id, sk) = setup(2);
    let payload = BytesN::<32>::random(&env);
    let sig = sign(&env, &sk, &payload.to_array(), SIGNING_CONTEXT);
    assert_eq!(check_auth(&env, &id, &payload, &sig), Ok(()));
}

#[test]
fn rejects_signature_from_another_key() {
    let (env, id, _) = setup(3);
    let attacker = keypair(4);
    let payload = BytesN::<32>::random(&env);
    let sig = sign(&env, &attacker, &payload.to_array(), SIGNING_CONTEXT);
    assert!(check_auth(&env, &id, &payload, &sig).is_err());
}

#[test]
fn rejects_changed_payload() {
    let (env, id, sk) = setup(5);
    let payload = BytesN::<32>::random(&env);
    let sig = sign(&env, &sk, &payload.to_array(), SIGNING_CONTEXT);
    let mut other = payload.to_array();
    other[0] ^= 1;
    let other = BytesN::from_array(&env, &other);
    assert!(check_auth(&env, &id, &other, &sig).is_err());
}

#[test]
fn rejects_one_flipped_signature_bit() {
    let (env, id, sk) = setup(6);
    let payload = BytesN::<32>::random(&env);
    let sig = sign(&env, &sk, &payload.to_array(), SIGNING_CONTEXT);
    let mut raw = sig.to_array();
    raw[100] ^= 0x01;
    let bad = BytesN::from_array(&env, &raw);
    assert!(check_auth(&env, &id, &payload, &bad).is_err());
}

#[test]
fn rejects_wrong_context() {
    let (env, id, sk) = setup(7);
    let payload = BytesN::<32>::random(&env);
    // Signed with an empty context instead of the account's context.
    let sig = sign(&env, &sk, &payload.to_array(), b"");
    assert!(check_auth(&env, &id, &payload, &sig).is_err());
}

#[test]
fn check_auth_cost_is_reported() {
    let (env, id, sk) = setup(8);
    let payload = BytesN::<32>::random(&env);
    let sig = sign(&env, &sk, &payload.to_array(), SIGNING_CONTEXT);
    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    assert_eq!(check_auth(&env, &id, &payload, &sig), Ok(()));
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    std::println!("__check_auth CPU instructions: {cpu}");
    // ML-DSA-65 verify is about 2.5M instructions at Protocol 30 costs.
    assert!(cpu < 10_000_000, "unexpectedly expensive: {cpu}");
}

/// Interop: a signature made in the browser by @noble/post-quantum must pass
/// the same host check. The fixture is written by `npm run fixture`.
#[test]
fn accepts_noble_browser_signature() {
    let raw = include_str!("../fixtures/noble-mldsa65.json");
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    let hex_field = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
    let pk: Vec<u8> = hex_field("publicKey");
    let payload: Vec<u8> = hex_field("payload");
    let sig: Vec<u8> = hex_field("signature");
    assert_eq!(v["context"].as_str().unwrap().as_bytes(), SIGNING_CONTEXT);

    let env = Env::default();
    let pk = BytesN::<1952>::from_array(&env, &pk.try_into().unwrap());
    let id = env.register(PqAccount, (pk,));
    let payload = BytesN::<32>::from_array(&env, &payload.try_into().unwrap());
    let sig = BytesN::<3309>::from_array(&env, &sig.try_into().unwrap());
    assert_eq!(check_auth(&env, &id, &payload, &sig), Ok(()));
}
