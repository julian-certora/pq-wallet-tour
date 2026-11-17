// ML-DSA-65 (FIPS 204) keys and signatures, made with @noble/post-quantum.
// The on-chain account checks these with the CAP-87 host function
// `verify_sig_ml_dsa_65` (Stellar Protocol 30, "Bell").
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

/** Must match `SIGNING_CONTEXT` in contract/src/lib.rs exactly. */
export const SIGNING_CONTEXT = 'stellar-pq-account:v1';
const CONTEXT_BYTES = new TextEncoder().encode(SIGNING_CONTEXT);

/** FIPS 204, Table 2 (ML-DSA-65). */
export const ML_DSA_65 = { publicKey: 1952, secretKey: 4032, signature: 3309 } as const;
/** RFC 8032 (Ed25519), for comparison. */
export const ED25519 = { publicKey: 32, secretKey: 32, signature: 64 } as const;

export interface PqKeys {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Makes a new ML-DSA-65 key pair. Pass a 32-byte seed only in tests. */
export function makePqKeys(seed: Uint8Array = randomBytes(32)): PqKeys {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  return ml_dsa65.keygen(seed);
}

/** Signs a message with the account's domain-separation context. */
export function pqSign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey, { context: CONTEXT_BYTES });
}

export function pqVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  return ml_dsa65.verify(signature, message, publicKey, { context: CONTEXT_BYTES });
}

/** Returns a copy with one bit flipped. Used to show a forged signature fail. */
export function flipOneBit(bytes: Uint8Array, index = 100): Uint8Array {
  const copy = bytes.slice();
  copy[index] ^= 0x01;
  return copy;
}

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
