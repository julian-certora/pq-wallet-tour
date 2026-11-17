// Writes contract/fixtures/noble-mldsa65.json: an ML-DSA-65 signature made by
// @noble/post-quantum (the same library the browser app uses). The Rust test
// `accepts_noble_browser_signature` checks it with the CAP-87 host function.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CONTEXT = 'stellar-pq-account:v1';
const hex = (b) => Buffer.from(b).toString('hex');

const { publicKey, secretKey } = ml_dsa65.keygen(randomBytes(32));
const payload = randomBytes(32);
const context = new TextEncoder().encode(CONTEXT);
const signature = ml_dsa65.sign(payload, secretKey, { context });

if (!ml_dsa65.verify(signature, payload, publicKey, { context })) {
  throw new Error('noble could not verify its own signature');
}

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'contract', 'fixtures', 'noble-mldsa65.json');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(
  out,
  JSON.stringify(
    { context: CONTEXT, publicKey: hex(publicKey), payload: hex(payload), signature: hex(signature) },
    null,
    2,
  ) + '\n',
);
console.log(`wrote ${out} (pk ${publicKey.length} B, sig ${signature.length} B)`);
