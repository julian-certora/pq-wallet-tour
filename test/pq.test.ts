import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ML_DSA_65, SIGNING_CONTEXT, flipOneBit, makePqKeys, pqSign, pqVerify, toHex } from '../src/lib/pq.ts';
import { formatXlm, hexToBytes } from '../src/lib/stellar.ts';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const seed = (n: number) => new Uint8Array(32).fill(n);
const msg = new Uint8Array(32).fill(7);

describe('ML-DSA-65 keys and signatures', () => {
  it('has FIPS 204 sizes', () => {
    const k = makePqKeys(seed(1));
    expect(k.publicKey.length).toBe(ML_DSA_65.publicKey);
    expect(k.secretKey.length).toBe(ML_DSA_65.secretKey);
    expect(pqSign(msg, k.secretKey).length).toBe(ML_DSA_65.signature);
  });

  it('is deterministic for a seed and different across seeds', () => {
    expect(toHex(makePqKeys(seed(2)).publicKey)).toBe(toHex(makePqKeys(seed(2)).publicKey));
    expect(toHex(makePqKeys(seed(2)).publicKey)).not.toBe(toHex(makePqKeys(seed(3)).publicKey));
  });

  it('rejects bad seeds', () => {
    expect(() => makePqKeys(new Uint8Array(31))).toThrow();
  });

  it('verifies a good signature', () => {
    const k = makePqKeys(seed(4));
    expect(pqVerify(pqSign(msg, k.secretKey), msg, k.publicKey)).toBe(true);
  });

  it('rejects a flipped bit, another key, another message', () => {
    const k = makePqKeys(seed(5));
    const other = makePqKeys(seed(6));
    const sig = pqSign(msg, k.secretKey);
    expect(pqVerify(flipOneBit(sig), msg, k.publicKey)).toBe(false);
    expect(pqVerify(sig, msg, other.publicKey)).toBe(false);
    expect(pqVerify(sig, flipOneBit(msg, 0), k.publicKey)).toBe(false);
  });

  it('binds the context: a signature with no context fails', () => {
    const k = makePqKeys(seed(7));
    const noCtx = ml_dsa65.sign(msg, k.secretKey);
    expect(pqVerify(noCtx, msg, k.publicKey)).toBe(false);
  });

  it('flipOneBit does not change its input', () => {
    const a = new Uint8Array(200);
    const b = flipOneBit(a);
    expect(a[100]).toBe(0);
    expect(b[100]).toBe(1);
  });
});

describe('contract and client agree', () => {
  const rust = readFileSync(new URL('../contract/src/lib.rs', import.meta.url), 'utf8');
  it('uses the same signing context', () => {
    expect(rust).toContain(`b"${SIGNING_CONTEXT}"`);
  });
  it('uses the same key and signature lengths', () => {
    expect(rust).toContain(`BytesN<${ML_DSA_65.publicKey}>`);
    expect(rust).toContain(`BytesN<${ML_DSA_65.signature}>`);
  });
});

describe('helpers', () => {
  it('formats stroops', () => {
    expect(formatXlm(10_000n * 10_000_000n)).toBe('10,000');
    expect(formatXlm(111_452n)).toBe('0.0111452');
    expect(formatXlm(1n)).toBe('0.0000001');
    expect(formatXlm(-15_000_000n)).toBe('-1.5');
  });
  it('round-trips hex', () => {
    const b = new Uint8Array([0, 1, 254, 255]);
    expect(toHex(hexToBytes(toHex(b)))).toBe('0001feff');
  });
});
