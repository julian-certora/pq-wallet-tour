extern crate std;

use crate::{Ed25519Account, Ed25519AccountClient, Error};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{testutils::BytesN as _, vec, BytesN, Env, InvokeError, IntoVal};

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn setup(seed: u8) -> (Env, soroban_sdk::Address, SigningKey) {
    let env = Env::default();
    let sk = keypair(seed);
    let pk = BytesN::from_array(&env, &sk.verifying_key().to_bytes());
    let id = env.register(Ed25519Account, (pk,));
    (env, id, sk)
}

fn sign(env: &Env, sk: &SigningKey, msg: &[u8]) -> BytesN<64> {
    BytesN::from_array(env, &sk.sign(msg).to_bytes())
}

fn check_auth(
    env: &Env,
    account: &soroban_sdk::Address,
    payload: &BytesN<32>,
    sig: &BytesN<64>,
) -> Result<(), Result<Error, InvokeError>> {
    env.try_invoke_contract_check_auth::<Error>(account, payload, sig.into_val(env), &vec![env])
}

#[test]
fn constructor_stores_public_key() {
    let (env, id, sk) = setup(1);
    let client = Ed25519AccountClient::new(&env, &id);
    assert_eq!(client.public_key().to_array(), sk.verifying_key().to_bytes());
}

#[test]
fn accepts_valid_signature() {
    let (env, id, sk) = setup(2);
    let payload = BytesN::<32>::random(&env);
    let sig = sign(&env, &sk, &payload.to_array());
    assert_eq!(check_auth(&env, &id, &payload, &sig), Ok(()));
}

#[test]
fn rejects_signature_from_another_key() {
    let (env, id, _) = setup(3);
    let payload = BytesN::<32>::random(&env);
    let sig = sign(&env, &keypair(4), &payload.to_array());
    assert!(check_auth(&env, &id, &payload, &sig).is_err());
}

#[test]
fn rejects_one_flipped_signature_bit() {
    let (env, id, sk) = setup(5);
    let payload = BytesN::<32>::random(&env);
    let mut raw = sign(&env, &sk, &payload.to_array()).to_array();
    raw[10] ^= 0x01;
    assert!(check_auth(&env, &id, &payload, &BytesN::from_array(&env, &raw)).is_err());
}

#[test]
fn check_auth_cost_is_reported() {
    let (env, id, sk) = setup(6);
    let payload = BytesN::<32>::random(&env);
    let sig = sign(&env, &sk, &payload.to_array());
    let mut budget = env.cost_estimate().budget();
    budget.reset_default();
    assert_eq!(check_auth(&env, &id, &payload, &sig), Ok(()));
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    std::println!("__check_auth CPU instructions: {cpu}");
}
