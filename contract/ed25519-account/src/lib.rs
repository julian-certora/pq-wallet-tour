//! The control wallet for the tour.
//!
//! This contract is the same as `pq-account` in every way but one: it holds
//! an Ed25519 public key and checks the signature with the `ed25519_verify`
//! host function. Both wallets run their check inside `__check_auth`, so the
//! tour can compare the two signature schemes like for like.
//!
//! This is a teaching example. It approves anything its key signs. It has no
//! spending limits, no recovery path, and no upgrade function.

#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Bytes, BytesN, Env, Vec,
};

#[cfg(test)]
mod test;

/// Ed25519 public key length (RFC 8032).
pub const PUBLIC_KEY_LEN: u32 = 32;
/// Ed25519 signature length (RFC 8032).
pub const SIGNATURE_LEN: u32 = 64;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    PublicKey,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The account has no public key. This cannot happen after deployment,
    /// because the constructor always sets it.
    MissingPublicKey = 1,
}

#[contract]
pub struct Ed25519Account;

#[contractimpl]
impl Ed25519Account {
    /// Runs once, at deployment. Stores the account's Ed25519 public key.
    pub fn __constructor(env: Env, public_key: BytesN<32>) {
        env.storage()
            .instance()
            .set(&DataKey::PublicKey, &public_key);
    }

    /// Returns the account's Ed25519 public key.
    pub fn public_key(env: Env) -> Result<BytesN<32>, Error> {
        env.storage()
            .instance()
            .get(&DataKey::PublicKey)
            .ok_or(Error::MissingPublicKey)
    }
}

#[contractimpl]
impl CustomAccountInterface for Ed25519Account {
    type Signature = BytesN<64>;
    type Error = Error;

    /// `ed25519_verify` traps on a bad signature, so a wrong key or a changed
    /// payload aborts the whole transaction.
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: BytesN<64>,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let public_key: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::PublicKey)
            .ok_or(Error::MissingPublicKey)?;

        let message: Bytes = signature_payload.to_bytes().into();
        env.crypto().ed25519_verify(&public_key, &message, &signature);

        Ok(())
    }
}
pub mod sanity;
use cvlr::nondet::Nondet;
use cvlr_soroban_derive::rule;
use cvlr_soroban::*;



impl Nondet for DataKey {
    fn nondet() -> Self { 
        {
            DataKey::PublicKey
	}
    }
}

impl Nondet for Error {
    fn nondet() -> Self { 
        {
            Error::MissingPublicKey
	}
    }
}

