// Full tour flow against the real Stellar testnet, from Node.
// Uses the same library as the browser page: src/lib/stellar.ts.
//   npm run e2e:testnet
import { readFileSync } from 'node:fs';
import { Keypair } from '@stellar/stellar-sdk';
import { makePqKeys, pqVerify } from '../src/lib/pq.ts';
import { StellarTour, contractUrl, formatXlm, txUrl } from '../src/lib/stellar.ts';

const wasm = new Uint8Array(readFileSync(new URL('../public/pq_account.wasm', import.meta.url)));
const edWasm = new Uint8Array(readFileSync(new URL('../public/ed25519_account.wasm', import.meta.url)));
const t0 = Date.now();
const step = (s: string) => console.log(`\n[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s}`);
const assert = (ok: unknown, msg: string) => {
  if (!ok) throw new Error(`ASSERT: ${msg}`);
  console.log(`  ok  ${msg}`);
};

const tour = new StellarTour();

step('1. fund the Ed25519 fee payer with friendbot');
console.log('  fee payer', tour.feePayer.publicKey());
console.log('  tx', txUrl(await tour.fund(tour.feePayer.publicKey())));

step('2. make ML-DSA-65 keys for Alice and Bob, and an Ed25519 key for Carol');
const alice = makePqKeys();
const bob = makePqKeys();
const carol = Keypair.random();
assert(alice.publicKey.length === 1952 && bob.publicKey.length === 1952, 'public keys are 1952 bytes');

step('3. upload wasm (if needed), deploy two PQ accounts and one Ed25519 account');
const { wasmHash, uploadTx } = await tour.ensureWasm(wasm);
console.log('  pq wasm', wasmHash, uploadTx ? `uploaded ${txUrl(uploadTx.hash)}` : 'already on testnet');
const ed = await tour.ensureWasm(edWasm);
console.log('  ed wasm', ed.wasmHash, ed.uploadTx ? `uploaded ${txUrl(ed.uploadTx.hash)}` : 'already on testnet');
const a = await tour.deployAccount(wasmHash, alice.publicKey);
const b = await tour.deployAccount(wasmHash, bob.publicKey);
const c = await tour.deployAccount(ed.wasmHash, carol.rawPublicKey());
console.log('  alice', contractUrl(a.contractId), `fee ${a.feeCharged}`);
console.log('  bob  ', contractUrl(b.contractId), `fee ${b.feeCharged}`);
console.log('  carol', contractUrl(c.contractId), `fee ${c.feeCharged}`);
assert([a, b, c].every((x) => x.contractId.startsWith('C')), 'all accounts have C addresses');

step('4. fund Alice and Carol with friendbot');
console.log('  tx', txUrl(await tour.fund(a.contractId)));
console.log('  tx', txUrl(await tour.fund(c.contractId)));
const aliceStart = await tour.balance(a.contractId);
const bobStart = await tour.balance(b.contractId);
console.log(`  alice ${formatXlm(aliceStart)} XLM, bob ${formatXlm(bobStart)} XLM`);
assert(aliceStart > 0n, 'Alice has XLM');

step('5. Alice pays Bob 100 XLM, approved with ML-DSA-65');
const amount = 100n * 10_000_000n;
const pay = await tour.pqTransfer(a.contractId, b.contractId, amount, alice);
console.log('  tx', txUrl(pay.hash));
console.log(`  payload ${pay.payloadHex}`);
console.log(`  signature ${pay.signature.length} B, envelope ${pay.envelopeBytes} B, cpu ${pay.cpuInstructions}, fee ${pay.feeCharged} stroops`);
assert(pay.signature.length === 3309, 'signature is 3309 bytes');
assert(pqVerify(pay.signature, Uint8Array.from(Buffer.from(pay.payloadHex, 'hex')), alice.publicKey), 'signature verifies locally');
const aliceAfter = await tour.balance(a.contractId);
const bobAfter = await tour.balance(b.contractId);
assert(aliceStart - aliceAfter === amount, 'Alice balance fell by exactly 100 XLM (fees came from the fee payer)');
assert(bobAfter - bobStart === amount, 'Bob balance rose by exactly 100 XLM');

step('5b. baseline: Carol pays Bob 100 XLM from the Ed25519 smart wallet');
const carolStart = await tour.balance(c.contractId);
const base = await tour.ed25519WalletTransfer(c.contractId, b.contractId, amount, carol);
console.log('  tx', txUrl(base.hash));
console.log(`  signature ${base.signature.length} B, envelope ${base.envelopeBytes} B, cpu ${base.cpuInstructions}, fee ${base.feeCharged} stroops`);
assert(base.signature.length === 64, 'signature is 64 bytes');
assert(carolStart - (await tour.balance(c.contractId)) === amount, 'Carol balance fell by exactly 100 XLM');
const x = (p: number | bigint, q: number | bigint) => (Number(p) / Number(q)).toFixed(2);
console.log(`  ML-DSA / Ed25519: envelope x${x(pay.envelopeBytes, base.envelopeBytes)}, cpu x${x(pay.cpuInstructions, base.cpuInstructions)}, fee x${x(pay.feeCharged, base.feeCharged)}`);
assert(pay.envelopeBytes > base.envelopeBytes * 2, 'PQ envelope is over 2x the Ed25519 wallet envelope');
assert(pay.cpuInstructions > base.cpuInstructions, 'PQ transfer uses more CPU than the Ed25519 wallet transfer');

step('6. forged signature (one bit flipped) must fail on chain');
const forged = await tour.forgedTransfer(a.contractId, b.contractId, amount, alice);
console.log('  tx', txUrl(forged.hash), forged.resultCode, forged.opResult, `fee ${forged.feeCharged}`);
assert(forged.resultCode === 'txFailed', 'transaction failed');
assert((await tour.balance(a.contractId)) === aliceAfter, 'Alice balance did not change');

step(`done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
