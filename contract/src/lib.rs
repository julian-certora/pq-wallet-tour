//! A minimal post-quantum smart account for Stellar.
//!
//! The account holds one ML-DSA-65 (FIPS 204) public key. Any action the
//! account takes, such as a token transfer, must carry an ML-DSA-65 signature
//! over the Soroban authorization payload. The network checks the signature
//! with the CAP-87 host function `verify_sig_ml_dsa_65` (Protocol 30, "Bell").
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

/// ML-DSA-65 encoded verifying key length (FIPS 204, Table 2).
pub const PUBLIC_KEY_LEN: u32 = 1952;
/// ML-DSA-65 encoded signature length (FIPS 204, Table 2).
pub const SIGNATURE_LEN: u32 = 3309;

/// FIPS 204 context string for domain separation. A signature made for this
/// account cannot be replayed into another protocol that uses the same key
/// with a different context. Wallets must sign with exactly these bytes.
pub const SIGNING_CONTEXT: &[u8] = b"stellar-pq-account:v1";

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
pub struct PqAccount;

#[contractimpl]
impl PqAccount {
    /// Runs once, at deployment. Stores the account's ML-DSA-65 public key.
    pub fn __constructor(env: Env, public_key: BytesN<1952>) {
        env.storage()
            .instance()
            .set(&DataKey::PublicKey, &public_key);
    }

    /// Returns the account's ML-DSA-65 public key.
    pub fn public_key(env: Env) -> Result<BytesN<1952>, Error> {
        env.storage()
            .instance()
            .get(&DataKey::PublicKey)
            .ok_or(Error::MissingPublicKey)
    }
}

#[contractimpl]
impl CustomAccountInterface for PqAccount {
    type Signature = BytesN<3309>;
    type Error = Error;

    /// The network calls this when something needs this account's approval.
    /// `signature_payload` is the 32-byte hash of the authorization entry. It
    /// already binds the network passphrase, a nonce, an expiry ledger, and
    /// the exact call tree, so the signature cannot be replayed elsewhere.
    ///
    /// `verify_sig_ml_dsa_65` traps on a bad signature, so a wrong key, a
    /// changed payload, or a different context aborts the whole transaction.
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: BytesN<3309>,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let public_key: BytesN<1952> = env
            .storage()
            .instance()
            .get(&DataKey::PublicKey)
            .ok_or(Error::MissingPublicKey)?;

        let message: Bytes = signature_payload.to_bytes().into();
        let context = Bytes::from_slice(&env, SIGNING_CONTEXT);

        env.crypto()
            .ml_dsa_65_verify(&public_key, &message, &signature, &context);

        Ok(())
    }
}
