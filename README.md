# Post-quantum Stellar · a live tour

A client-side guided tour of Stellar Protocol 30 ("Bell"). In about a minute, it
makes two ML-DSA-65 smart wallets on the real Stellar testnet, sends XLM between
them with a post-quantum signature, sends the same payment from an Ed25519 smart
wallet to compare the cost, shows a one-bit forgery fail on chain, and then
explains the trade-offs and the road ahead.

There is no backend. The browser talks straight to `soroban-testnet.stellar.org`
and friendbot. Keys live only in the tab's memory.

## How it works

| Part | Where |
| --- | --- |
| Wallet contract: stores one ML-DSA-65 public key; `__check_auth` calls `env.crypto().ml_dsa_65_verify` (CAP-87) with context `stellar-pq-account:v1` | `contract/src/lib.rs` |
| Control wallet (Carol): the same contract, but it stores an Ed25519 key and calls `env.crypto().ed25519_verify`. This makes the cost table like for like | `contract/ed25519-account/src/lib.rs` |
| ML-DSA keys and signatures in the browser (`@noble/post-quantum`) | `src/lib/pq.ts` |
| Testnet flow: friendbot, wasm upload, deploy with constructor, wallet-signed SAC transfer (ML-DSA or Ed25519 signer), forged transfer | `src/lib/stellar.ts` |
| Tour copy, sources, and step actions | `src/steps.ts` |
| Tour engine and ledger panel | `src/main.ts` |

The PQ signature is attached with `authorizeEntry(entry, cb)` from
`@stellar/stellar-sdk` 17.4, where the callback returns
`{ signatureScVal: scvBytes(mlDsaSignature) }`. The signed transaction is then
re-simulated in `enforce` mode, so its footprint and CPU budget include the real
ML-DSA check. An ephemeral Ed25519 account pays all fees.

## Commands

```sh
npm install
npm run dev              # local dev server (Vite + Cloudflare plugin)
npm test                 # unit tests (vitest)
npm run contract:test    # contract tests for both wallets, incl. a noble-made signature checked by the host
npm run e2e:testnet      # full flow against the live testnet, from Node
bash scripts/browser-tour.sh http://localhost:5199/ 1440 900 light   # full flow in Chrome
npx cf deploy            # deploy the static build to Cloudflare
```

Building the contract needs Stellar CLI 30 or later (soroban-sdk 30 refuses
older CLIs): `STELLAR=/path/to/stellar npm run contract:build`. It writes
`public/pq_account.wasm` and `public/ed25519_account.wasm`.
`npm run fixture` regenerates the browser-signature fixture for the contract test.

## Limits

This is a teaching demo. The wallet approves anything its key signs and has no
limits, recovery, or upgrade path. Testnet only.

## Contract license

The Rust example contracts are licensed under [Apache-2.0](contract/LICENSE).
