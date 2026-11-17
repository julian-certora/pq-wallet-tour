import './style.css';
import { accountUrl, contractUrl, formatXlm, txUrl } from './lib/stellar.ts';
import { STEPS, esc, freshState, short } from './steps.ts';
import type { State, StepContext, Task } from './types.ts';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const article = $('step');
const ledger = $('ledger');
const nextBtn = $<HTMLButtonElement>('next');
const backBtn = $<HTMLButtonElement>('back');
const hint = $('hint');
const progress = $('progress');
const progressLabel = $('progress-label');

interface StepRun {
  tasks: Task[];
  done: boolean;
  running: boolean;
  error?: string;
}

let state: State = freshState();
let index = 0;
let runs: StepRun[] = STEPS.map(newRun);
let ticker: number | undefined;

function newRun(step: (typeof STEPS)[number]): StepRun {
  return {
    tasks: (step.tasks ?? []).map((label) => ({ label, status: 'pending' as const })),
    done: !step.run,
    running: false,
  };
}

const ctx = (i: number): StepContext => ({ state, tasks: runs[i].tasks, done: runs[i].done, error: runs[i].error });

// ------------------------------------------------------------------ render

function render(animate = false) {
  const step = STEPS[index];
  const run = runs[index];
  article.innerHTML = step.view(ctx(index));
  if (animate) {
    article.classList.remove('enter');
    void article.offsetWidth;
    article.classList.add('enter');
  }
  document.title = index === 0 ? 'Post-quantum Stellar · a live tour' : `${step.short} · Post-quantum Stellar`;

  progress.innerHTML = STEPS.map((_, i) => `<li class="${i < index ? 'done' : i === index ? 'current' : ''}"></li>`).join('');
  const total = STEPS.length - 1;
  progressLabel.innerHTML =
    index === 0
      ? `<span class="pl-long">${total} steps · about a minute</span><span class="pl-short">About 1 min</span>`
      : `<span class="pl-long">Step ${index} of ${total} · ${esc(step.short)}</span><span class="pl-short">Step ${index} of ${total}</span>`;

  backBtn.hidden = index === 0;
  const last = index === STEPS.length - 1;
  nextBtn.disabled = run.running;
  nextBtn.innerHTML = run.running
    ? `<svg class="spin" viewBox="0 0 20 20" aria-hidden="true"><path d="M10 3.5a6.5 6.5 0 1 1-6.5 6.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>Working on testnet`
    : `${esc(step.next)}${last ? '' : ARROW}`;
  hint.textContent = run.running ? 'Real transactions take about 5 seconds per ledger.' : run.error ? 'Try the step again, or go back.' : '';
  renderLedger();
}

const ARROW = `<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10h11m-4.5-4.5L15 10l-4.5 4.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

function renderLedger() {
  const b = state.balances ?? {};
  const fp = state.tour?.feePayer.publicKey();
  const wallet = (name: string, scheme: string, pq: boolean, addr: string | undefined, url: string | undefined, bal: bigint | undefined) => `
    <li class="wallet${addr ? '' : ' empty'}">
      <span class="wallet-name">${name}</span>
      <span class="wallet-scheme${pq ? ' pq' : ''}">${scheme}</span>
      <span class="wallet-addr">${addr && url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(short(addr, 6, 6))}</a>` : 'Not created yet'}</span>
      <span class="wallet-bal">${bal !== undefined ? `${formatXlm(bal, 2)} XLM` : ''}</span>
    </li>`;

  const acts = state.activity
    .map(
      (a) => `<li><span class="dot${a.ok ? '' : ' bad'}" aria-hidden="true"></span><span>${esc(a.label)}${a.ok ? '' : ' <span class="sr-only">(failed)</span>'}</span>
        <a href="${esc(txUrl(a.hash))}" target="_blank" rel="noopener noreferrer" aria-label="View transaction for ${esc(a.label)}">${esc(short(a.hash, 4, 4))}</a></li>`,
    )
    .join('');

  ledger.innerHTML = `
    <section>
      <h2>On testnet now</h2>
      <ul class="wallets">
        ${wallet('Fee payer', 'Ed25519', false, fp, fp && accountUrl(fp), b.feePayer)}
        ${wallet('Alice', 'ML-DSA-65', true, state.aliceId, state.aliceId && contractUrl(state.aliceId), b.alice)}
        ${wallet('Bob', 'ML-DSA-65', true, state.bobId, state.bobId && contractUrl(state.bobId), b.bob)}
        ${wallet('Carol', 'Ed25519', false, state.carolId, state.carolId && contractUrl(state.carolId), b.carol)}
      </ul>
    </section>
    <section>
      <h2>Transactions</h2>
      ${acts ? `<ul class="activity">${acts}</ul>` : '<p>Real transactions show here as the tour runs. Each one links to a public block explorer.</p>'}
    </section>`;
}

// -------------------------------------------------------------------- run

async function runStep(i: number) {
  const step = STEPS[i];
  const run = runs[i];
  if (!step.run || run.done || run.running) return;
  run.running = true;
  run.error = undefined;
  run.tasks.forEach((t) => {
    if (t.status !== 'done') t.status = 'pending';
  });
  render();

  const runner = async (ti: number, fn: () => Promise<string | void>) => {
    const task = run.tasks[ti];
    if (task.status === 'done') return; // keep finished work on a retry
    task.status = 'running';
    task.meta = '';
    const started = performance.now();
    startTicker(i, ti, started);
    if (i === index) render();
    try {
      const note = await fn();
      task.status = 'done';
      const secs = (performance.now() - started) / 1000;
      task.meta = note ? String(note) : secs >= 1 ? `${secs.toFixed(1)} s` : '';
    } catch (e) {
      task.status = 'error';
      task.meta = '';
      throw e;
    } finally {
      stopTicker();
      if (i === index) render();
    }
  };

  try {
    await step.run(state, runner);
    run.done = true;
    await refreshBalances();
  } catch (e) {
    console.error('[tour]', e, (e as { detail?: unknown }).detail);
    run.error = friendly(e);
  } finally {
    run.running = false;
    if (i === index) render();
  }
}

function friendly(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (/fetch|network|Failed to fetch|NetworkError|load failed/i.test(msg)) return 'The page could not reach the Stellar test network.';
  if (/friendbot/i.test(msg)) return 'Friendbot, the test network faucet, did not answer.';
  return msg.length > 220 ? `${msg.slice(0, 220)}…` : msg;
}

function startTicker(stepIndex: number, taskIndex: number, started: number) {
  stopTicker();
  ticker = window.setInterval(() => {
    if (stepIndex !== index) return;
    const el = article.querySelector<HTMLElement>(`[data-task-meta="${taskIndex}"]`);
    const secs = (performance.now() - started) / 1000;
    if (el && secs >= 1) el.textContent = `${secs.toFixed(0)} s`;
  }, 500);
}

function stopTicker() {
  if (ticker !== undefined) window.clearInterval(ticker);
  ticker = undefined;
}

async function refreshBalances() {
  const tour = state.tour;
  if (!tour) return;
  const read = (addr?: string) => (addr ? tour.balance(addr).catch(() => undefined) : Promise.resolve(undefined));
  const [feePayer, alice, bob, carol] = await Promise.all([
    read(tour.feePayer.publicKey()),
    read(state.aliceId),
    read(state.bobId),
    read(state.carolId),
  ]);
  state.balances = {
    feePayer: feePayer ?? state.balances?.feePayer,
    alice: alice ?? state.balances?.alice,
    bob: bob ?? state.balances?.bob,
    carol: carol ?? state.balances?.carol,
  };
  renderLedger();
}

// --------------------------------------------------------------- navigate

function go(to: number) {
  if (to < 0 || to >= STEPS.length) return;
  index = to;
  render(true);
  window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior });
  article.focus({ preventScroll: true });
  void runStep(index);
}

function next() {
  if (runs[index].running) return;
  if (runs[index].error) return void runStep(index);
  if (index === STEPS.length - 1) return restart();
  go(index + 1);
}

function restart() {
  state = freshState();
  runs = STEPS.map(newRun);
  go(1);
}

nextBtn.addEventListener('click', next);
backBtn.addEventListener('click', () => go(index - 1));
article.addEventListener('click', (e) => {
  const el = (e.target as HTMLElement).closest<HTMLElement>('[data-action="retry"]');
  if (el) void runStep(index);
});
document.addEventListener('keydown', (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const target = e.target as HTMLElement;
  if (target.closest('a, button, input, textarea, select')) return;
  if (e.key === 'ArrowRight') next();
  if (e.key === 'ArrowLeft' && index > 0 && !runs[index].running) go(index - 1);
});
window.addEventListener('beforeunload', (e) => {
  if (runs.some((r) => r.running)) e.preventDefault();
});

render();
