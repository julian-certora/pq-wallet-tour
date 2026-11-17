// Testnet flow for the tour. It runs the same way in the browser and in Node
// (scripts/e2e-testnet.ts), so the end-to-end test proves what the page does.
import {
  Address,
  Asset,
  BASE_FEE,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
  authorizeEntry,
  hash,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
  type Transaction,
} from '@stellar/stellar-sdk';
import { flipOneBit, pqSign, toHex, type PqKeys } from './pq.ts';

export const TESTNET = {
  rpcUrl: 'https://soroban-testnet.stellar.org',
  friendbotUrl: 'https://friendbot.stellar.org',
  passphrase: Networks.TESTNET,
  explorer: 'https://stellar.expert/explorer/testnet',
} as const;

export const XLM_SAC = Asset.native().contractId(TESTNET.passphrase);
export const STROOPS_PER_XLM = 10_000_000n;

/** The signature byte that the forgery demo changes. */
export const FORGED_BYTE = 100;

/** About 8 minutes at 5-second ledgers. */
const AUTH_VALID_LEDGERS = 100;

export const txUrl = (h: string) => `${TESTNET.explorer}/tx/${h}`;
export const contractUrl = (id: string) => `${TESTNET.explorer}/contract/${id}`;
export const accountUrl = (id: string) => `${TESTNET.explorer}/account/${id}`;

export interface TxReport {
  hash: string;
  /** Total fee the fee payer paid, in stroops. */
  feeCharged: bigint;
  /** CPU instructions the transaction reserved (from simulation). */
  cpuInstructions: number;
  /** Size of the signed transaction envelope, in bytes. */
  envelopeBytes: number;
}

export interface TransferReport extends TxReport {
  /** The 32-byte Soroban authorization payload that Alice signed. */
  payloadHex: string;
  signature: Uint8Array;
  validUntilLedger: number;
}

export interface FailedTransferReport {
  hash: string;
  feeCharged: bigint;
  /** Result code, such as `txFailed`. */
  resultCode: string;
  /** Inner operation result, such as `invokeHostFunctionTrapped`. */
  opResult: string;
  flippedByte: number;
}

/** Signs a 32-byte Soroban authorization payload for a wallet contract. */
export type Signer = (payload: Uint8Array) => Uint8Array;

/** ML-DSA-65 signer for `pq_account.wasm`. */
export const pqSigner = (keys: PqKeys): Signer => (payload) => pqSign(payload, keys.secretKey);

/** Ed25519 signer for `ed25519_account.wasm`, the control wallet. */
export const ed25519Signer = (kp: Keypair): Signer => (payload) => kp.sign(payload);

export interface PreparedTransfer {
  /** Signed by the fee payer, ready to send. */
  tx: Transaction;
  payloadHex: string;
  /** The real signature (before any forgery change). */
  signature: Uint8Array;
  validUntil: number;
  cpuInstructions: number;
  flippedByte?: number;
}

export class TourError extends Error {
  readonly detail?: unknown;
  constructor(message: string, detail?: unknown) {
    super(message);
    this.detail = detail;
    this.name = 'TourError';
  }
}

export class StellarTour {
  readonly server: rpc.Server;
  readonly feePayer: Keypair;

  constructor(feePayer: Keypair = Keypair.random(), rpcUrl: string = TESTNET.rpcUrl) {
    this.server = new rpc.Server(rpcUrl);
    this.feePayer = feePayer;
  }

  /** Asks friendbot for 10,000 test XLM. Works for G and C addresses. */
  async fund(address: string): Promise<string> {
    const res = await this.server.fundAddress(address, TESTNET.friendbotUrl);
    return res.txHash;
  }

  /** Uploads the wasm if testnet does not have it yet. */
  async ensureWasm(wasm: Uint8Array): Promise<{ wasmHash: string; uploadTx?: TxReport }> {
    const wasmHash = toHex(hash(wasm));
    try {
      await this.server.getContractWasmByHash(wasmHash, 'hex');
      return { wasmHash };
    } catch {
      const uploadTx = await this.submit(Operation.uploadContractWasm({ wasm }));
      return { wasmHash, uploadTx };
    }
  }

  /**
   * Deploys one wallet contract and passes the public key to its constructor.
   * Works for both wallets: ML-DSA-65 (1,952 bytes) and Ed25519 (32 bytes).
   */
  async deployAccount(wasmHash: string, publicKey: Uint8Array): Promise<TxReport & { contractId: string }> {
    const op = Operation.createCustomContract({
      address: Address.fromString(this.feePayer.publicKey()),
      wasmHash: hexToBytes(wasmHash),
      salt: crypto.getRandomValues(new Uint8Array(32)),
      constructorArgs: [xdr.ScVal.scvBytes(publicKey)],
    });
    const { report, returnValue } = await this.submitWithResult(op);
    if (!returnValue) throw new TourError('Deploy returned no contract address');
    return { ...report, contractId: Address.fromScVal(returnValue).toString() };
  }

  /** Reads an XLM balance (in stroops) through the native asset contract. */
  async balance(address: string): Promise<bigint> {
    const op = Operation.invokeContractFunction({
      contract: XLM_SAC,
      function: 'balance',
      args: [Address.fromString(address).toScVal()],
    });
    const sim = await this.server.simulateTransaction(await this.build(op));
    if (!rpc.Api.isSimulationSuccess(sim) || !sim.result) {
      throw new TourError('Balance read failed', sim);
    }
    return BigInt(scValToNative(sim.result.retval));
  }

  /**
   * Moves XLM from one PQ account to another. The PQ account approves the
   * transfer with an ML-DSA-65 signature. The fee payer only pays the fee.
   */
  async pqTransfer(from: string, to: string, stroops: bigint, keys: PqKeys): Promise<TransferReport> {
    return this.submitTransfer(await this.prepareTransfer(from, to, stroops, pqSigner(keys)));
  }

  /**
   * The same transfer from the Ed25519 control wallet. The wallet contract is
   * the same except that `__check_auth` calls `ed25519_verify`. This is the
   * like-for-like cost baseline.
   */
  async ed25519WalletTransfer(from: string, to: string, stroops: bigint, kp: Keypair): Promise<TransferReport> {
    return this.submitTransfer(await this.prepareTransfer(from, to, stroops, ed25519Signer(kp)));
  }

  /** Submits a prepared transfer and waits for its ledger. */
  async submitTransfer(p: PreparedTransfer): Promise<TransferReport> {
    const report = await this.send(p.tx, p.cpuInstructions);
    return { ...report, payloadHex: p.payloadHex, signature: p.signature, validUntilLedger: p.validUntil };
  }

  /**
   * Signs a real transfer, then flips one bit of the ML-DSA signature and
   * submits it. The network must reject it on chain.
   */
  async forgedTransfer(from: string, to: string, stroops: bigint, keys: PqKeys): Promise<FailedTransferReport> {
    return this.submitForged(await this.prepareTransfer(from, to, stroops, pqSigner(keys), FORGED_BYTE));
  }

  /** Submits a transfer whose signature was changed. Expects a failure. */
  async submitForged(p: PreparedTransfer): Promise<FailedTransferReport> {
    if (p.flippedByte === undefined) throw new TourError('This transfer was not forged');
    const sent = await this.server.sendTransaction(p.tx);
    if (sent.status === 'ERROR') {
      throw new TourError('The network refused the forged transaction before it reached a ledger', sent);
    }
    const res = await this.server.pollTransaction(sent.hash, { attempts: 40 });
    if (res.status === rpc.Api.GetTransactionStatus.SUCCESS) {
      throw new TourError('DANGER: a forged signature was accepted', res);
    }
    if (res.status !== rpc.Api.GetTransactionStatus.FAILED) {
      throw new TourError(`Forged transaction status: ${res.status}`, res);
    }
    const result = res.resultXdr;
    return {
      hash: sent.hash,
      feeCharged: result.feeCharged,
      resultCode: result.result.type,
      opResult: firstOpResult(result),
      flippedByte: p.flippedByte,
    };
  }

  // ---------------------------------------------------------------- internals

  private async build(op: xdr.Operation): Promise<Transaction> {
    const source = await this.server.getAccount(this.feePayer.publicKey());
    return new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: TESTNET.passphrase })
      .addOperation(op)
      .setTimeout(120)
      .build();
  }

  /**
   * Builds a transfer, signs its auth entry with the wallet's signer, and
   * re-simulates in enforcing mode so the footprint and CPU include
   * `__check_auth`.
   * With `flipByte`, the signature is changed after the good simulation.
   */
  async prepareTransfer(
    from: string,
    to: string,
    stroops: bigint,
    sign: Signer,
    flipByte?: number,
  ): Promise<PreparedTransfer> {
    const call = {
      contract: XLM_SAC,
      function: 'transfer',
      args: [
        Address.fromString(from).toScVal(),
        Address.fromString(to).toScVal(),
        nativeToScVal(stroops, { type: 'i128' }),
      ],
    };
    const recorded = await this.server.simulateTransaction(await this.build(Operation.invokeContractFunction(call)));
    if (!rpc.Api.isSimulationSuccess(recorded) || !recorded.result) {
      throw new TourError(simError('Transfer simulation failed', recorded), recorded);
    }

    const latest = await this.server.getLatestLedger();
    const validUntil = latest.sequence + AUTH_VALID_LEDGERS;
    let payload: Uint8Array = new Uint8Array();
    let signature: Uint8Array = new Uint8Array();

    // Signs every contract-account auth entry. `mutate` can change the signature bytes.
    const signAll = (mutate: (sig: Uint8Array) => Uint8Array) =>
      Promise.all(
        recorded.result!.auth.map((entry) => {
          if (entry.credentials.type === 'sorobanCredentialsSourceAccount') return entry;
          return authorizeEntry(
            entry,
            async (_preimage, signaturePayload) => {
              payload = new Uint8Array(signaturePayload);
              signature = sign(payload);
              return { signatureScVal: xdr.ScVal.scvBytes(mutate(signature)) };
            },
            validUntil,
            TESTNET.passphrase,
          );
        }),
      );

    const auth = await signAll((sig) => sig);
    if (signature.length === 0) throw new TourError('No wallet auth entry was found to sign');

    // Enforcing simulation runs the real signature check, so it measures it.
    const enforced = await this.server.simulateTransaction(
      await this.build(Operation.invokeContractFunction({ ...call, auth })),
      undefined,
      'enforce',
    );
    if (!rpc.Api.isSimulationSuccess(enforced)) {
      throw new TourError(simError('Signed transfer simulation failed', enforced), enforced);
    }

    // For the forgery demo: same payload and expiry, one bit changed.
    const finalAuth = flipByte === undefined ? auth : await signAll((sig) => flipOneBit(sig, flipByte));

    // assembleTransaction keeps auth entries that are already present.
    const tx = rpc
      .assembleTransaction(await this.build(Operation.invokeContractFunction({ ...call, auth: finalAuth })), enforced)
      .build();
    tx.sign(this.feePayer);
    const cpuInstructions = enforced.transactionData.build().resources.instructions;
    return { tx, payloadHex: toHex(payload), signature, validUntil, cpuInstructions, flippedByte: flipByte };
  }

  private async submit(op: xdr.Operation): Promise<TxReport> {
    return (await this.submitWithResult(op)).report;
  }

  private async submitWithResult(op: xdr.Operation): Promise<{ report: TxReport; returnValue?: xdr.ScVal }> {
    const raw = await this.build(op);
    const sim = await this.server.simulateTransaction(raw);
    if (!rpc.Api.isSimulationSuccess(sim)) throw new TourError(simError('Simulation failed', sim), sim);
    const tx = rpc.assembleTransaction(raw, sim).build();
    tx.sign(this.feePayer);
    const cpu = sim.transactionData.build().resources.instructions;
    return this.sendWithResult(tx, cpu);
  }

  private async send(tx: Transaction, cpuInstructions: number): Promise<TxReport> {
    return (await this.sendWithResult(tx, cpuInstructions)).report;
  }

  private async sendWithResult(tx: Transaction, cpuInstructions: number) {
    const sent = await this.server.sendTransaction(tx);
    if (sent.status === 'ERROR' || sent.status === 'TRY_AGAIN_LATER') {
      throw new TourError(`Send failed: ${sent.status}`, sent);
    }
    const res = await this.server.pollTransaction(sent.hash, { attempts: 40 });
    if (res.status !== rpc.Api.GetTransactionStatus.SUCCESS) {
      throw new TourError(`Transaction ${res.status}: ${sent.hash}`, res);
    }
    const report: TxReport = {
      hash: sent.hash,
      feeCharged: res.resultXdr.feeCharged,
      cpuInstructions,
      envelopeBytes: tx.toEnvelope().toXDR().length,
    };
    return { report, returnValue: res.returnValue };
  }
}

function firstOpResult(result: xdr.TransactionResult): string {
  const r = result.result;
  if (r.type !== 'txFailed' && r.type !== 'txSuccess') return 'none';
  const op = r.results[0];
  if (!op || op.type !== 'opInner') return op?.type ?? 'none';
  return op.tr.type === 'invokeHostFunction' ? op.tr.invokeHostFunctionResult.type : op.tr.type;
}

function simError(prefix: string, sim: rpc.Api.SimulateTransactionResponse): string {
  return rpc.Api.isSimulationError(sim) ? `${prefix}: ${sim.error}` : prefix;
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function formatXlm(stroops: bigint, digits = 7): string {
  const neg = stroops < 0n;
  const abs = neg ? -stroops : stroops;
  const whole = abs / STROOPS_PER_XLM;
  const frac = (abs % STROOPS_PER_XLM).toString().padStart(7, '0').slice(0, digits).replace(/0+$/, '');
  return `${neg ? '-' : ''}${whole.toLocaleString('en-US')}${frac ? '.' + frac : ''}`;
}
