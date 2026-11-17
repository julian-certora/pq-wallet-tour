// The tour: nine steps. Each step has copy, an optional testnet action, and
// a view of the results. Copy cites its sources at the end of each step.
import { ED25519, ML_DSA_65, makePqKeys, toHex } from './lib/pq.ts';
import { Keypair } from '@stellar/stellar-sdk';
import { FORGED_BYTE, StellarTour, accountUrl, contractUrl, ed25519Signer, formatXlm, pqSigner, txUrl, type PreparedTransfer } from './lib/stellar.ts';
import type { State, StepContext, Step } from './types.ts';

// ------------------------------------------------------------------ helpers

export const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const ext = (url: string, text: string) =>
  `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${text}</a>`;
export const short = (s: string, head = 6, tail = 6) => (s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s);
const n = (x: number | bigint) => x.toLocaleString('en-US');
const times = (a: number | bigint, b: number | bigint) => {
  const r = Number(a) / Number(b);
  return r >= 10 ? `${Math.round(r)}` : r.toFixed(1);
};
const ratio = (a: number | bigint, b: number | bigint) => `×${times(a, b)}`;

const src = {
  nist8547: ['NIST IR 8547, Transition to Post-Quantum Cryptography Standards (2026)', 'https://csrc.nist.gov/pubs/ir/8547/final'],
  fips204: ['NIST FIPS 204, Module-Lattice-Based Digital Signature Standard', 'https://csrc.nist.gov/pubs/fips/204/final'],
  gidney: ['Gidney, How to factor 2048 bit RSA integers with less than a million noisy qubits (2025)', 'https://arxiv.org/abs/2505.15917'],
  babbush: ['Babbush et al., resource estimates for 256-bit elliptic curves, PRX Quantum (2026)', 'https://journals.aps.org/prxquantum/abstract/10.1103/j3xf-bw18'],
  qpp: ['Stellar Development Foundation, Introducing the Quantum Preparedness Plan (2026)', 'https://stellar.org/blog/foundation-news/introducing-the-quantum-preparedness-plan'],
  bell: ['Introducing Bell, Protocol 30 on Stellar', 'https://stellar.org/blog/developers/introducing-bell-protocol-30-on-stellar'],
  bellGuide: ['Bell (Protocol 30) upgrade guide', 'https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide'],
  cap87: ['CAP-87: ML-DSA signature verification host functions', 'https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md'],
  cryptoHost: ['soroban-sdk docs: Crypto::ed25519_verify', 'https://docs.rs/soroban-sdk/latest/soroban_sdk/crypto/struct.Crypto.html#method.ed25519_verify'],
  customAccounts: ['Stellar docs: custom accounts and __check_auth', 'https://developers.stellar.org/docs/build/guides/contract-accounts'],
  authPayload: ['Stellar docs: Soroban authorization', 'https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization'],
  friendbot: ['Stellar docs: networks and friendbot', 'https://developers.stellar.org/docs/learn/fundamentals/networks'],
  fees: ['Stellar docs: fees and resource limits', 'https://developers.stellar.org/docs/learn/fundamentals/fees-resource-limits-metering'],
  noble: ['@noble/post-quantum (JavaScript ML-DSA used by this page)', 'https://github.com/paulmillr/noble-post-quantum'],
  cryptokit: ['Apple CryptoKit: MLDSA65', 'https://developer.apple.com/documentation/cryptokit/mldsa65'],
  awsKms: ['AWS Security Blog: post-quantum ML-DSA signatures with AWS KMS', 'https://aws.amazon.com/blogs/security/how-to-create-post-quantum-signatures-using-aws-kms-and-ml-dsa/'],
  chrome: ['Chrome Platform Status: Algorithm Updates in WebCrypto (ML-DSA, ships in Chrome 155)', 'https://chromestatus.com/feature/5198951632470016'],
  onepassword: ['1Password: Launching post-quantum safe passkeys (October 2026)', 'https://1password.com/blog/post-quantum-passkeys'],
  yubico: ['Yubico: post-quantum YubiKey beta program (November 2026)', 'https://www.yubico.com/pqc-beta-program/'],
  meeting: ['Stellar protocol meeting, 17 September 2026', 'https://developers.stellar.org/meetings/2026/09/17/protocol'],
  mldsaCrate: ['RustCrypto ml-dsa changelog (security fixes)', 'https://github.com/RustCrypto/signatures/blob/master/ml-dsa/CHANGELOG.md'],
  oz: ['OpenZeppelin Stellar contracts (smart accounts)', 'https://github.com/OpenZeppelin/stellar-contracts'],
} as const;
type SrcKey = keyof typeof src;

const sources = (...keys: SrcKey[]) => `
  <footer class="sources">
    <h2>Sources</h2>
    <ol>${keys.map((k) => `<li>${ext(src[k][1], esc(src[k][0]))}</li>`).join('')}</ol>
  </footer>`;

const head = (eyebrow: string, title: string) => `<p class="eyebrow">${eyebrow}</p><h1>${title}</h1>`;

const ICON = {
  pending: `<svg class="task-icon" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-dasharray="2.5 3"/></svg>`,
  running: `<svg class="task-icon spin" viewBox="0 0 20 20" aria-hidden="true"><path d="M10 3.5a6.5 6.5 0 1 1-6.5 6.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`,
  done: `<svg class="task-icon" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="7.5" fill="currentColor" opacity=".14"/><path d="m6.5 10.2 2.4 2.4 4.6-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  error: `<svg class="task-icon" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="7.5" fill="currentColor" opacity=".14"/><path d="m7.3 7.3 5.4 5.4m0-5.4-5.4 5.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`,
};
const STATUS_TEXT = { pending: 'Waiting', running: 'Working', done: 'Done', error: 'Failed' };

/** The live well: task checklist, then results, then any error. */
function live(ctx: StepContext, results = ''): string {
  if (!ctx.tasks.length && !results) return '';
  const tasks = ctx.tasks.length
    ? `<ul class="tasks">${ctx.tasks
        .map(
          (t, i) => `<li class="task ${t.status}">
            ${ICON[t.status]}
            <span class="task-label"><span class="sr-only">${STATUS_TEXT[t.status]}: </span>${t.label}</span>
            <span class="task-meta" data-task-meta="${i}">${t.meta ?? ''}</span>
          </li>`,
        )
        .join('')}</ul>`
    : '';
  const error = ctx.error
    ? `<div class="error-box" role="alert">
        <strong>That step did not finish.</strong>
        <p class="muted">${esc(ctx.error)}</p>
        <p class="muted">The test network or its faucet can be busy. Try the step again.</p>
        <button type="button" class="btn-secondary" data-action="retry">Try this step again</button>
      </div>`
    : '';
  return `<section class="live" aria-label="Live results">${tasks}${results}${error}</section>`;
}

const kv = (rows: [string, string][]) =>
  `<dl class="kv">${rows.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join('')}</dl>`;

function cells(bytes: number, pq: boolean) {
  const count = Math.ceil(bytes / 32);
  return `<div class="cells${pq ? ' pq' : ''}" role="img" aria-label="${n(bytes)} bytes, about ${count} squares">${'<i></i>'.repeat(count)}</div>`;
}

function hexPreview(bytes: Uint8Array, show = 24) {
  const h = toHex(bytes);
  return `<span class="hex"><b>${h.slice(0, show)}</b>…${h.slice(-8)}</span>`;
}

// --------------------------------------------------------------------- steps

export function freshState(): State {
  return { activity: [] };
}

export const STEPS: Step[] = [
  // 0 -----------------------------------------------------------------------
  {
    id: 'intro',
    short: 'Why quantum matters',
    next: 'Start the tour',
    view: () => `
      ${head('A live tour of Stellar Protocol 30, “Bell”', 'Send money with a signature that a quantum computer cannot forge.')}
      <p class="lede">Every Stellar account is protected by an Ed25519 signature. A large enough quantum computer could run Shor’s algorithm, work out a private key from its public key, and then sign anything as that account.</p>
      <p>On Stellar, your <code>G…</code> address <em>is</em> your Ed25519 public key, written in another alphabet. So every account has already published the one value that such an attacker needs.</p>
      <p>Bell lets Stellar smart contracts check ML-DSA signatures. ML-DSA is the NIST standard for post-quantum signatures. In the next minute, you will make two post-quantum wallets on the real Stellar test network and send money between them. A third wallet that uses Ed25519 runs the same payment, so you can compare the cost. You do not need a wallet, an account, or any software.</p>
      <dl class="facts">
        <div><dt>2030</dt><dd>NIST deprecates quantum-vulnerable signatures such as Ed25519.</dd></div>
        <div><dt>2035</dt><dd>NIST disallows them in systems that follow its standards.</dd></div>
        <div><dt>&lt;500,000</dt><dd>Physical qubits to break 256-bit curves, in a 2026 estimate. None exist yet.</dd></div>
      </dl>
      ${sources('nist8547', 'babbush', 'gidney', 'bell', 'fips204')}`,
  },

  // 1 -----------------------------------------------------------------------
  {
    id: 'fee-payer',
    short: 'The fee payer',
    next: 'Make post-quantum keys',
    tasks: ['Make a throwaway Ed25519 key pair', 'Ask friendbot for 10,000 test XLM'],
    async run(s, t) {
      await t(0, async () => {
        s.tour = new StellarTour();
        return short(s.tour.feePayer.publicKey(), 4, 4);
      });
      await t(1, async () => {
        const hash = await s.tour!.fund(s.tour!.feePayer.publicKey());
        s.activity.push({ label: 'Friendbot funds the fee payer', hash, ok: true });
      });
    },
    view: (ctx) => {
      const s = ctx.state;
      const results = s.tour && ctx.done
        ? kv([
            ['Fee payer', ext(accountUrl(s.tour.feePayer.publicKey()), `<span class="mono">${short(s.tour.feePayer.publicKey(), 8, 8)}</span>`)],
            ['Signs with', 'Ed25519, 64-byte signatures'],
          ])
        : '';
      return `
        ${head('Step 1 · The fee payer', 'First, someone has to pay the network fee.')}
        <p class="lede">Every Stellar transaction has a source account. That account pays the fee and signs the outer envelope of the transaction with Ed25519. Bell does not change this.</p>
        <p>So the tour makes a throwaway Ed25519 account and asks friendbot, the test network’s faucet, to fund it. This account pays every fee in the tour.</p>
        ${live(ctx, results)}
        <p class="note">Keep this in mind. The post-quantum wallets never pay a fee, and they never sign the envelope. They only approve what happens to their own money. This split is the first trade-off of the post-quantum world.</p>
        ${sources('friendbot', 'fees')}`;
    },
  },

  // 2 -----------------------------------------------------------------------
  {
    id: 'keys',
    short: 'Post-quantum keys',
    next: 'Deploy the wallets',
    tasks: ['Make Alice’s ML-DSA-65 key pair', 'Make Bob’s ML-DSA-65 key pair', 'Make Carol’s Ed25519 key pair, to compare'],
    async run(s, t) {
      await t(0, async () => {
        const t0 = performance.now();
        s.alice = makePqKeys();
        return `${Math.max(1, Math.round(performance.now() - t0))} ms`;
      });
      await t(1, async () => {
        const t0 = performance.now();
        s.bob = makePqKeys();
        return `${Math.max(1, Math.round(performance.now() - t0))} ms`;
      });
      await t(2, async () => {
        const t0 = performance.now();
        s.carol = Keypair.random();
        return `${Math.max(1, Math.round(performance.now() - t0))} ms`;
      });
    },
    view: (ctx) => {
      const s = ctx.state;
      const results = s.alice && s.bob && s.carol
        ? kv([
            ['Alice’s public key', hexPreview(s.alice.publicKey)],
            ['Bob’s public key', hexPreview(s.bob.publicKey)],
            ['Carol’s public key', hexPreview(s.carol.rawPublicKey())],
            ['Secret keys', 'In this tab’s memory only. Reload the page and they are gone.'],
          ])
        : '';
      return `
        ${head('Step 2 · Keys', 'Make two post-quantum key pairs, right here in your browser.')}
        <p class="lede">Alice and Bob each get an ML-DSA-65 key pair. The keys come from <code>@noble/post-quantum</code>, an open-source JavaScript library, and they never leave this tab.</p>
        <p>Carol gets an Ed25519 key pair. She is the control: later, her wallet makes the same payment as Alice’s, so you can see what the post-quantum signature costs.</p>
        <p>Stellar accepts three ML-DSA levels: 44, 65, and 87. This tour uses 65, the middle level (NIST security category 3). It is a common choice: Apple CryptoKit supports ML-DSA-65 and ML-DSA-87, and AWS KMS supports all three.</p>
        ${live(ctx, results)}
        <h2>The price of quantum safety is size</h2>
        <figure class="bytes">
          <div class="byte-row"><h3>Ed25519 public key<span>${ED25519.publicKey} bytes</span></h3>${cells(ED25519.publicKey, false)}</div>
          <div class="byte-row"><h3>ML-DSA-65 public key<span>${n(ML_DSA_65.publicKey)} bytes</span></h3>${cells(ML_DSA_65.publicKey, true)}</div>
          <div class="byte-row"><h3>Ed25519 signature<span>${ED25519.signature} bytes</span></h3>${cells(ED25519.signature, false)}</div>
          <div class="byte-row"><h3>ML-DSA-65 signature<span>${n(ML_DSA_65.signature)} bytes</span></h3>${cells(ML_DSA_65.signature, true)}</div>
          <figcaption>Each square is 32 bytes. An ML-DSA-65 signature is about 52 times larger than an Ed25519 signature.</figcaption>
        </figure>
        ${sources('fips204', 'noble', 'cryptokit', 'awsKms')}`;
    },
  },

  // 3 -----------------------------------------------------------------------
  {
    id: 'wallets',
    short: 'Smart wallets',
    next: 'Fund the wallets',
    tasks: ['Find the wallet code on testnet', 'Deploy Alice’s wallet', 'Deploy Bob’s wallet', 'Deploy Carol’s Ed25519 wallet'],
    async run(s, t) {
      await t(0, async () => {
        // One at a time: both uploads would use the fee payer's sequence number.
        let uploaded = 0;
        for (const [file, label, key] of [
          ['/pq_account.wasm', 'Upload the ML-DSA wallet code', 'wasmHash'],
          ['/ed25519_account.wasm', 'Upload the Ed25519 wallet code', 'edWasmHash'],
        ] as const) {
          const res = await fetch(file);
          if (!res.ok) throw new Error(`Could not load the wallet code (${res.status}).`);
          const { wasmHash, uploadTx } = await s.tour!.ensureWasm(new Uint8Array(await res.arrayBuffer()));
          s[key] = wasmHash;
          if (uploadTx) {
            s.activity.push({ label, hash: uploadTx.hash, ok: true });
            uploaded++;
          }
        }
        return uploaded ? 'uploaded' : 'already there';
      });
      await t(1, async () => {
        const d = await s.tour!.deployAccount(s.wasmHash!, s.alice!.publicKey);
        s.aliceId = d.contractId;
        s.activity.push({ label: 'Deploy Alice’s wallet', hash: d.hash, ok: true });
        return short(d.contractId, 4, 4);
      });
      await t(2, async () => {
        const d = await s.tour!.deployAccount(s.wasmHash!, s.bob!.publicKey);
        s.bobId = d.contractId;
        s.activity.push({ label: 'Deploy Bob’s wallet', hash: d.hash, ok: true });
        return short(d.contractId, 4, 4);
      });
      await t(3, async () => {
        const d = await s.tour!.deployAccount(s.edWasmHash!, s.carol!.rawPublicKey());
        s.carolId = d.contractId;
        s.activity.push({ label: 'Deploy Carol’s Ed25519 wallet', hash: d.hash, ok: true });
        return short(d.contractId, 4, 4);
      });
    },
    view: (ctx) => {
      const s = ctx.state;
      const rows: [string, string][] = [];
      if (s.aliceId) rows.push(['Alice’s wallet', ext(contractUrl(s.aliceId), `<span class="mono">${short(s.aliceId, 8, 8)}</span>`)]);
      if (s.bobId) rows.push(['Bob’s wallet', ext(contractUrl(s.bobId), `<span class="mono">${short(s.bobId, 8, 8)}</span>`)]);
      if (s.carolId) rows.push(['Carol’s wallet', ext(contractUrl(s.carolId), `<span class="mono">${short(s.carolId, 8, 8)}</span>`)]);
      return `
        ${head('Step 3 · Wallets', 'Turn each key into a smart wallet on the test network.')}
        <p class="lede">On Stellar, a contract can act as an account. When anything needs that account’s approval, the network calls the contract’s <code>__check_auth</code> function and passes it the signature.</p>
        <p>Our wallet contract stores one ML-DSA-65 public key. Its check is one call to a new Bell host function. The network runs the math natively, so the whole contract is only 4.4 KB.</p>
        <figure class="code">
        <pre class="code" aria-label="The wallet's approval check, in Rust"><code>fn __check_auth(env, payload: Hash&lt;32&gt;, signature: BytesN&lt;3309&gt;, …) {
    let public_key = env.storage().instance().get(&amp;PublicKey)?;
    <span class="hl">env.crypto().ml_dsa_65_verify(</span>
        <span class="hl">&amp;public_key, &amp;payload, &amp;signature, &amp;"stellar-pq-account:v1")</span>;
    Ok(())   // a bad signature traps and aborts the transaction
}</code></pre>
        <figcaption>Simplified from the wallet contract (Rust, soroban-sdk 30). The highlighted call is new in Bell.</figcaption>
        </figure>
        <p>Carol’s wallet is the same contract with one change. It stores a 32-byte Ed25519 key, and its check calls <code>ed25519_verify</code>, a host function that Stellar has had since smart contracts launched.</p>
        ${live(ctx, rows.length ? kv(rows) : '')}
        <p class="muted">Each wallet gets a <code>C…</code> address. Like a <code>G…</code> address, it can hold XLM and any other Stellar asset. Unlike a <code>G…</code> address, it does not reveal an Ed25519 key.</p>
        ${sources('cap87', 'cryptoHost', 'customAccounts', 'bellGuide')}`;
    },
  },

  // 4 -----------------------------------------------------------------------
  {
    id: 'fund',
    short: 'Fund the wallets',
    next: 'Send 100 XLM to Bob',
    tasks: ['Ask friendbot to fund Alice’s wallet', 'Ask friendbot to fund Carol’s wallet', 'Read the balances'],
    async run(s, t) {
      await t(0, async () => {
        const hash = await s.tour!.fund(s.aliceId!);
        s.activity.push({ label: 'Friendbot funds Alice', hash, ok: true });
      });
      await t(1, async () => {
        const hash = await s.tour!.fund(s.carolId!);
        s.activity.push({ label: 'Friendbot funds Carol', hash, ok: true });
      });
      await t(2, async () => {
        const [a, b, c] = await Promise.all([
          s.tour!.balance(s.aliceId!),
          s.tour!.balance(s.bobId!),
          s.tour!.balance(s.carolId!),
        ]);
        s.balances = { ...s.balances, alice: a, bob: b, carol: c };
        s.aliceStart = a;
        s.bobStart = b;
      });
    },
    view: (ctx) => {
      const s = ctx.state;
      const results = s.aliceStart !== undefined
        ? kv([
            ['Alice', `${formatXlm(s.aliceStart)} XLM`],
            ['Bob', `${formatXlm(s.bobStart ?? 0n)} XLM`],
            ...(s.balances?.carol !== undefined ? ([['Carol', `${formatXlm(s.balances.carol)} XLM`]] as [string, string][]) : []),
          ])
        : '';
      return `
        ${head('Step 4 · Funding', 'Give Alice and Carol some test XLM.')}
        <p class="lede">Friendbot can fund contract addresses too. Alice and Carol each get 10,000 test XLM. Bob starts with nothing.</p>
        <p>Test XLM has no value. Everything else is real: real validators, real ledgers, and real transactions that anyone can look up.</p>
        ${live(ctx, results)}
        ${sources('friendbot')}`;
    },
  },

  // 5 -----------------------------------------------------------------------
  {
    id: 'pay',
    short: 'Alice pays Bob',
    next: 'Try to forge a payment',
    tasks: [
      'Build the transfer and sign Alice’s approval with ML-DSA',
      'Submit it and wait for a ledger',
      'Carol sends Bob 100 XLM from her Ed25519 wallet, to compare',
      'Read the balances',
    ],
    async run(s, t) {
      let prepared: PreparedTransfer | undefined;
      await t(0, async () => {
        prepared = await s.tour!.prepareTransfer(s.aliceId!, s.bobId!, 100n * 10_000_000n, pqSigner(s.alice!));
        return `${n(prepared.signature.length)} B signature`;
      });
      await t(1, async () => {
        const pay = await s.tour!.submitTransfer(prepared!);
        s.pay = pay;
        s.activity.push({ label: 'Alice pays Bob 100 XLM (ML-DSA)', hash: pay.hash, ok: true });
      });
      await t(2, async () => {
        const base = await s.tour!.submitTransfer(
          await s.tour!.prepareTransfer(s.carolId!, s.bobId!, 100n * 10_000_000n, ed25519Signer(s.carol!)),
        );
        s.base = base;
        s.activity.push({ label: 'Carol pays Bob 100 XLM (Ed25519)', hash: base.hash, ok: true });
      });
      await t(3, async () => {
        const [a, b, c] = await Promise.all([
          s.tour!.balance(s.aliceId!),
          s.tour!.balance(s.bobId!),
          s.tour!.balance(s.carolId!),
        ]);
        s.balances = { ...s.balances, alice: a, bob: b, carol: c };
        s.aliceAfterPay = a;
      });
    },
    view: (ctx) => {
      const s = ctx.state;
      let results = '';
      if (s.pay) {
        results += kv([
          ['What Alice signed', `<span class="hex"><b>${s.pay.payloadHex.slice(0, 32)}<br />${s.pay.payloadHex.slice(32)}</b></span>`],
          ['Her signature', `${hexPreview(s.pay.signature)}<br /><span class="muted">${n(s.pay.signature.length)} bytes</span>`],
          ['Valid until', `Ledger ${n(s.pay.validUntilLedger)}, about 8 minutes`],
          ['Transaction', ext(txUrl(s.pay.hash), `<span class="mono">${short(s.pay.hash, 8, 8)}</span>`)],
        ]);
      }
      if (s.pay && s.base) {
        results += `
          <div class="table-scroll">
          <table class="metrics">
            <caption>The same 100 XLM transfer from two smart wallets that differ only in their signature check. Live numbers from this run.</caption>
            <thead><tr><th scope="col"><span class="sr-only">Measure</span></th><th scope="col">Ed25519 wallet</th><th scope="col">ML-DSA wallet</th><th scope="col"><span class="sr-only">Ratio</span></th></tr></thead>
            <tbody>
              <tr><th scope="row">Signature</th><td>${n(s.base.signature.length)} B</td><td>${n(s.pay.signature.length)} B</td><td class="x">${ratio(s.pay.signature.length, s.base.signature.length)}</td></tr>
              <tr><th scope="row">Transaction size</th><td>${n(s.base.envelopeBytes)} B</td><td>${n(s.pay.envelopeBytes)} B</td><td class="x">${ratio(s.pay.envelopeBytes, s.base.envelopeBytes)}</td></tr>
              <tr><th scope="row">CPU budget</th><td>${n(s.base.cpuInstructions)}</td><td>${n(s.pay.cpuInstructions)}</td><td class="x">${ratio(s.pay.cpuInstructions, s.base.cpuInstructions)}</td></tr>
              <tr><th scope="row">Fee paid, XLM</th><td>${formatXlm(s.base.feeCharged, 5)}</td><td>${formatXlm(s.pay.feeCharged, 5)}</td><td class="x">${ratio(s.pay.feeCharged, s.base.feeCharged)}</td></tr>
            </tbody>
          </table>
          </div>
          <p class="muted small">Both wallets check their signature inside <code>__check_auth</code> with a host function, so both checks are in the CPU budget. In both transactions, the fee payer signs the envelope with Ed25519, and the network checks that signature before any contract runs.</p>`;
      }
      if (s.aliceAfterPay !== undefined && s.balances?.bob !== undefined) {
        results += kv([
          ['Alice now', `${formatXlm(s.aliceAfterPay)} XLM <span class="muted">(exactly 100 less: she paid no fee)</span>`],
          ['Bob now', `${formatXlm(s.balances.bob)} XLM <span class="muted">(100 from Alice, 100 from Carol)</span>`],
        ]);
      }
      return `
        ${head('Step 5 · The payment', 'Alice pays Bob, and approves it with ML-DSA.')}
        <p class="lede">The page builds a transfer of 100 XLM from Alice to Bob. A simulation returns the exact approval that Alice must give. The page hashes that approval into 32 bytes, and Alice signs those bytes with her ML-DSA key.</p>
        <p>The 32 bytes commit to the network, a one-time nonce, an expiry ledger, and the full call: who sends, who receives, and how much. Validators run <code>verify_sig_ml_dsa_65</code> on them before any money moves.</p>
        <p>Then Carol sends Bob the same 100 XLM from her Ed25519 wallet. The two transactions are the same except for the signature, so the difference in cost is the price of the post-quantum check.</p>
        ${live(ctx, results)}
        ${sources('authPayload', 'cap87', 'cryptoHost', 'fees')}`;
    },
  },

  // 6 -----------------------------------------------------------------------
  {
    id: 'forge',
    short: 'Try to forge it',
    next: 'See the trade-offs',
    tasks: ['Sign a second payment, then flip 1 of its 26,472 signature bits', 'Submit the forged payment', 'Check Alice’s balance'],
    async run(s, t) {
      let prepared: PreparedTransfer | undefined;
      await t(0, async () => {
        prepared = await s.tour!.prepareTransfer(s.aliceId!, s.bobId!, 100n * 10_000_000n, pqSigner(s.alice!), FORGED_BYTE);
        return `byte ${FORGED_BYTE}, bit 0`;
      });
      await t(1, async () => {
        const f = await s.tour!.submitForged(prepared!);
        s.forged = f;
        s.activity.push({ label: 'Forged payment rejected', hash: f.hash, ok: false });
        return 'rejected';
      });
      await t(2, async () => {
        const a = await s.tour!.balance(s.aliceId!);
        s.balances = { ...s.balances, alice: a };
        s.aliceAfterForge = a;
        if (a !== s.aliceAfterPay) throw new Error('Alice’s balance changed. This must not happen.');
        return 'unchanged';
      });
    },
    view: (ctx) => {
      const s = ctx.state;
      const results = s.forged
        ? kv([
            ['Network verdict', `<strong>Rejected</strong> <span class="mono muted">${esc(s.forged.resultCode)} · ${esc(s.forged.opResult)}</span>`],
            ['Transaction', ext(txUrl(s.forged.hash), `<span class="mono">${short(s.forged.hash, 8, 8)}</span>`)],
            ['Fee payer lost', `${formatXlm(s.forged.feeCharged)} XLM in fees`],
            ...(s.aliceAfterForge !== undefined ? ([['Alice still has', `${formatXlm(s.aliceAfterForge)} XLM`]] as [string, string][]) : []),
          ])
        : '';
      return `
        ${head('Step 6 · The attack', 'Now try to cheat by changing one bit.')}
        <p class="lede">ML-DSA is built so that nobody can make a valid signature without Alice’s secret key, even with a quantum computer. To show it, the page signs a second payment, flips one bit in the signature, and sends it to the network anyway.</p>
        <p>The validators reject it. The transaction goes into a ledger as failed, the fee payer loses the fee, and Alice keeps every lumen.</p>
        ${live(ctx, results)}
        ${sources('cap87', 'fips204')}`;
    },
  },

  // 7 -----------------------------------------------------------------------
  {
    id: 'tradeoffs',
    short: 'The trade-offs',
    next: 'See what comes next',
    view: (ctx) => {
      const s = ctx.state;
      const live1 = s.pay && s.base
        ? ` In this run, compared with Carol’s Ed25519 wallet, Alice’s transaction was ${times(s.pay.envelopeBytes, s.base.envelopeBytes)} times larger, used ${times(s.pay.cpuInstructions, s.base.cpuInstructions)} times the CPU, and paid a fee ${times(s.pay.feeCharged, s.base.feeCharged)} times higher (${formatXlm(s.pay.feeCharged)} XLM against ${formatXlm(s.base.feeCharged)} XLM).`
        : '';
      const items: [string, string][] = [
        ['Everything is bigger.', `Signatures are about 52 times larger and public keys 61 times larger than Ed25519.${live1} Bigger transactions cost more and leave less room in each ledger.`],
        ['The fee payer is still Ed25519.', 'Every transaction envelope is still signed by a classic account. A quantum attacker could not move Alice’s money, but it could spend the fee payer’s XLM and submit transactions as it. The Quantum Preparedness Plan targets post-quantum signers for classic accounts in 2027.'],
        ['Few passkeys sign ML-DSA yet, and this tour does not use one.', 'In this tour, the key lives in browser memory, which is the weakest place for a key. 1Password started to make ML-DSA passkeys in October 2026, for sites that ask for them. A YubiKey with ML-DSA passkeys is in public beta. Apple and Google passkeys do not use ML-DSA yet, and Ledger and Trezor do not sign transactions with it. Chrome 155 added ML-DSA to WebCrypto, but those keys are software keys in the page. Core developers warn against giving up hardware or passkey protection just to get post-quantum safety.'],
        ['The code is young.', 'The Rust ML-DSA library that validators use had three security fixes in 2026, all before the version that Bell ships. CAP-87 asks for an independent review. New cryptography needs time and many eyes.'],
        ['This demo wallet is not a real wallet.', 'It approves anything its key signs. It has no spending limits, no recovery, and no upgrade path. Lose the key and the money is gone. Real smart wallets add these controls.'],
        ['Old accounts do not upgrade themselves.', 'Accounts whose owners are gone, or who never act, keep their exposed Ed25519 keys. The plan names dormant accounts as an open problem.'],
        ['Mainnet is not live yet.', 'Bell runs on the test network from 3 November 2026. Validators vote on the mainnet upgrade on 23 November 2026 at 17:00 UTC.'],
      ];
      return `
        ${head('Step 7 · The trade-offs', 'It works. Here is what it costs.')}
        <p class="lede">Post-quantum signatures solve one problem and create several smaller ones. You should know all of them before you build on this.</p>
        <dl class="tradeoffs">${items.map(([k, v], i) => `<div><span class="n">0${i + 1}</span><dt>${k}</dt><dd>${v}</dd></div>`).join('')}</dl>
        ${sources('qpp', 'onepassword', 'yubico', 'chrome', 'meeting', 'mldsaCrate', 'cap87', 'oz', 'bellGuide')}`;
    },
  },

  // 8 -----------------------------------------------------------------------
  {
    id: 'future',
    short: 'What comes next',
    next: 'Run the tour again',
    view: () => `
      ${head('Step 8 · The road ahead', 'Stellar has a plan, and Bell is the first step.')}
      <p class="lede">You just used something few blockchains have today: a native, standardized post-quantum signature check that any account contract can call.</p>
      <ol class="timeline">
        <li class="now"><span class="when">2026 · STAGE 1</span><strong>ML-DSA for contract accounts</strong><p>Bell (Protocol 30). On testnet now. Mainnet vote on 23 November.</p></li>
        <li><span class="when">2027 · STAGE 2</span><strong>Post-quantum signers for classic accounts</strong><p>A planned proposal to add a post-quantum signer to a <code>G…</code> account through <code>set_options</code>, with no change of address.</p></li>
        <li><span class="when">2030</span><strong>NIST deprecates quantum-vulnerable signatures</strong><p>Ed25519, ECDSA, and RSA signatures start to leave regulated systems.</p></li>
        <li><span class="when">STAGE 3</span><strong>Ed25519 deprecation on Stellar</strong><p>Timed to the real threat, not to a fixed date.</p></li>
        <li><span class="when">2035</span><strong>NIST disallows them</strong><p>Systems that follow NIST must use post-quantum signatures.</p></li>
      </ol>
      <h2>What you can build on Bell</h2>
      <ul class="build-list">
        <li><strong>Hybrid wallets</strong> that need a passkey signature and an ML-DSA signature, so you keep today’s hardware security and add quantum safety</li>
        <li><strong>Post-quantum vaults</strong> for treasuries and cold storage, with time locks and recovery keys</li>
        <li><strong>Spending policies</strong> where small payments need one signer and large ones need an ML-DSA approval</li>
        <li><strong>Migration tools</strong> that move funds from an exposed <code>G…</code> account into a post-quantum wallet</li>
      </ul>
      <p class="note">Everything in this tour ran in your browser. The page has no backend, no database, and no analytics. Your browser talked straight to the Stellar test network. The page ships with source maps, so you can read its code in your browser’s developer tools.</p>
      ${sources('qpp', 'nist8547', 'cap87', 'bell', 'oz')}`,
  },
];
