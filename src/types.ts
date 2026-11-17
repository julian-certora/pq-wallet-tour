import type { Keypair } from '@stellar/stellar-sdk';
import type { PqKeys } from './lib/pq.ts';
import type { FailedTransferReport, StellarTour, TransferReport } from './lib/stellar.ts';

export interface Activity {
  label: string;
  hash: string;
  ok: boolean;
}

export interface State {
  tour?: StellarTour;
  alice?: PqKeys;
  bob?: PqKeys;
  /** Ed25519 key for Carol's control wallet. */
  carol?: Keypair;
  wasmHash?: string;
  edWasmHash?: string;
  aliceId?: string;
  bobId?: string;
  carolId?: string;
  balances?: { feePayer?: bigint; alice?: bigint; bob?: bigint; carol?: bigint };
  aliceStart?: bigint;
  bobStart?: bigint;
  aliceAfterPay?: bigint;
  aliceAfterForge?: bigint;
  pay?: TransferReport;
  /** Carol's transfer from the Ed25519 control wallet. */
  base?: TransferReport;
  forged?: FailedTransferReport;
  activity: Activity[];
}

export type TaskStatus = 'pending' | 'running' | 'done' | 'error';

export interface Task {
  label: string;
  status: TaskStatus;
  meta?: string;
}

export interface StepContext {
  state: State;
  tasks: Task[];
  done: boolean;
  error?: string;
}

/** Runs task `i`. The function may return a short note shown beside it. */
export type TaskRunner = (i: number, fn: () => Promise<string | void>) => Promise<void>;

export interface Step {
  id: string;
  /** Short name for the progress label. */
  short: string;
  /** Primary button text: what happens when you press it. */
  next: string;
  tasks?: string[];
  run?: (state: State, task: TaskRunner) => Promise<void>;
  view: (ctx: StepContext) => string;
}
