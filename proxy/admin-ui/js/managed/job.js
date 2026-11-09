// The job of a change of the managed configuration. A change is answered at once and its order runs on in the admin
// process as a job, so the screen reads the job until it ends (`Watch`) and then tells how it ended: the name of the
// result, what happened and what to do next (`RESULTS`, with `REFUSED` and `BUSY` for the words of the proxy). A word
// that the tables do not hold is told as a result that is not known, with the word as it came. Nothing runs when the
// module is loaded.

import { ApiError } from '../api.js';
import { badge, el, notice, result } from '../dom.js';
import { lazy, t, w } from '../i18n.js';
import { fingerprintView, isFingerprint, kv, panel, row, timeView } from '../parts.js';

// The next read comes this long after the answer to the one before.
const ASK_AFTER_MS = 1000;
// The third read in a row that gives nothing readable ends the watch.
const MISSES = 3;
// The admin process answers a read of the job with these kinds when it may answer the next one: the watch goes on.
const READ_AGAIN = new Set(['unavailable', 'unknown', 'limited']);

// The longest a job takes is three tries of the time of the lookup of the names and a margin (7 s) each, and a rest for
// the question about the state and for the last read. Without a time that was read, the limit of the setting is used.
const TRY_MARGIN_MS = 7000;
const LAST_MS = 20000;
const RESOLVE_LIMIT_MS = 3600 * 1000;

/** A number of milliseconds that the setting of the time of the lookup can hold, or null. */
function resolveTime(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= RESOLVE_LIMIT_MS ? value : null;
}

/** How long a job may stay `running` before the screen stops waiting for it, from what `GET /api/status` and `GET /api/config` gave. */
export function watchLimit(status, file) {
  const resolve = resolveTime(status?.proxy?.resolve_timeout_ms) ?? resolveTime(file?.resolveMs) ?? RESOLVE_LIMIT_MS;
  return 3 * (resolve + TRY_MARGIN_MS) + LAST_MS;
}

/** Whether `value` is a job as the API gives one: its two versions are names, and its state is one of the two. */
export function isJob(value) {
  return value !== null && typeof value === 'object' && (value.state === 'running' || value.state === 'ended') && isFingerprint(value.from) && isFingerprint(value.to);
}

export const sameJob = (a, b) => a.kind === b.kind && a.actor === b.actor && a.to === b.to && a.started === b.started;

/**
 * Reads the job until it ends, one read at a time, a second after the answer to the one before. `ask` reads the job,
 * and `report` hears what happens: `{ type: 'progress', job, other }` when the job has changed; and at the end, once,
 * `{ type: 'ended', job, other }`, `{ type: 'gone' }` (the admin process has no job), `{ type: 'lost' }` (three reads in
 * a row gave nothing readable, or the job ran past its limit), or `{ type: 'refused', error }`. `other` says that the
 * job is not the one this page sent: the place of the job holds only the last one.
 */
export class Watch {
  #ask;
  #report;
  #active = false;
  #timer = null;
  #own = null;
  #other = false;
  #shown = '';
  #misses = 0;
  #limit = 0;
  #since = 0;

  constructor(ask, report) {
    this.#ask = ask;
    this.#report = report;
  }

  get active() {
    return this.#active;
  }

  /** Starts watching `job`, of which the limit is `limit` from now, unless a watch is under way. `own`: this page sent it. */
  start(job, own, limit) {
    if (this.#active) return;
    this.#active = true;
    this.#own = own ? job : null;
    this.#other = false;
    this.#shown = JSON.stringify(job);
    this.#misses = 0;
    this.#limit = limit;
    this.#since = Date.now();
    this.#later();
  }

  stop() {
    this.#active = false;
    clearTimeout(this.#timer);
    this.#timer = null;
  }

  #later() {
    this.#timer = setTimeout(() => this.#read(), ASK_AFTER_MS);
  }

  #end(event) {
    this.stop();
    this.#report(event);
  }

  #miss() {
    this.#misses += 1;
    if (this.#misses >= MISSES) this.#end({ type: 'lost' });
    else this.#later();
  }

  #failed(error) {
    if (!(error instanceof ApiError) || READ_AGAIN.has(error.kind)) this.#miss();
    else this.#end({ type: 'refused', error });
  }

  async #read() {
    this.#timer = null;
    let answer;
    try {
      answer = await this.#ask();
    } catch (error) {
      if (this.#active) this.#failed(error);
      return;
    }
    if (!this.#active) return;
    const job = answer?.job;
    if (job === null) {
      this.#end({ type: 'gone' });
      return;
    }
    if (!isJob(job)) {
      this.#miss();
      return;
    }
    this.#misses = 0;
    if (this.#own !== null && !sameJob(job, this.#own)) this.#other = true;
    if (job.state === 'ended') {
      this.#end({ type: 'ended', job, other: this.#other });
      return;
    }
    const key = JSON.stringify(job);
    if (key !== this.#shown) {
      this.#shown = key;
      this.#report({ type: 'progress', job, other: this.#other });
    }
    if (Date.now() - this.#since > this.#limit) this.#end({ type: 'lost' });
    else this.#later();
  }
}

// ---- how a job ended ----

const KINDS = {
  apply: () => t('managed.kind.apply'),
  activate: () => t('managed.kind.activate'),
  rollback: () => t('managed.kind.rollback'),
};

/** The words of what a change asked for, by the word the API gives. */
export function kindText(kind) {
  return Object.hasOwn(KINDS, kind) ? KINDS[kind]() : String(kind);
}

// For each result: the tone, the short name, what happened, and what to do next (null for nothing).
export const RESULTS = {
  applied: ['ok', () => w('managed.result.applied'), () => w('managed.out.applied'), null],
  refused: ['bad', () => w('managed.result.refused'), () => w('managed.out.refused'), (job) => refusedNext(job)],
  busy: ['warn', () => w('managed.result.busy'), () => w('managed.out.busy'), () => w('managed.next.busy')],
  'current changed': ['warn', () => w('managed.result.current_changed'), () => w('managed.out.current_changed'), () => w('managed.next.current_changed')],
  'no version': ['bad', () => w('managed.result.no_version'), () => w('managed.out.no_version'), () => w('managed.next.no_version')],
  unmanaged: ['bad', () => w('managed.result.unmanaged'), () => w('managed.out.unmanaged'), () => w('managed.next.unmanaged')],
  store: ['bad', () => w('managed.result.store'), () => w('managed.out.store'), () => w('managed.next.store')],
  audit: ['bad', () => w('managed.result.audit'), () => w('managed.out.audit'), () => w('managed.next.audit')],
  error: ['bad', () => w('managed.result.error'), () => w('managed.out.error'), () => w('managed.next.error')],
  unreachable: ['bad', () => w('managed.result.unreachable'), () => w('managed.out.unreachable'), () => w('managed.next.unreachable')],
  failed: ['bad', () => w('managed.result.failed'), () => w('managed.out.failed'), () => w('managed.next.failed')],
  unconfirmed: ['warn', () => w('managed.result.unconfirmed'), () => w('managed.out.unconfirmed'), () => w('managed.next.unconfirmed')],
  'not recorded': ['warn', () => w('managed.result.not_recorded'), () => w('managed.out.not_recorded'), () => w('managed.next.not_recorded')],
};

// For each part of the proxy that can refuse: what was refused, and what to do next.
export const REFUSED = {
  configuration: [() => w('managed.refused.configuration'), () => w('managed.refused.configuration_next')],
  version: [() => w('managed.refused.version'), () => w('managed.refused.version_next')],
  store: [() => w('managed.refused.store'), () => w('managed.refused.store_next')],
  upstream: [() => w('managed.refused.upstream'), () => w('managed.refused.upstream_next')],
  tls: [() => w('managed.refused.tls'), () => w('managed.refused.tls_next')],
  fixed: [() => w('managed.refused.fixed'), () => w('managed.refused.fixed_next')],
  listener: [() => w('managed.refused.listener'), () => w('managed.refused.listener_next')],
  thread: [() => w('managed.refused.thread'), () => w('managed.refused.thread_next')],
  unmanaged: [() => w('managed.out.unmanaged'), () => w('managed.next.unmanaged')],
};

// For each word of `busy`: why nothing was changed.
export const BUSY = {
  'store in use': () => w('managed.busy.store_in_use'),
  'proxy busy': () => w('managed.busy.proxy_busy'),
  'reload under way': () => w('managed.busy.reload_under_way'),
  starting: () => w('managed.busy.starting'),
  'too many orders': () => w('managed.busy.too_many_orders'),
  stopping: () => w('managed.busy.stopping'),
};

function refusedNext(job) {
  return Object.hasOwn(REFUSED, job.reason) ? REFUSED[job.reason][1]() : null;
}

/** What the words of a job add to what happened: the word of its reason and the fixed sentence of its detail, as they came. */
function reasonOf(job) {
  const mono = (text) => el('code', {}, String(text));
  const parts = [];
  if (typeof job.reason === 'string') {
    if (job.result === 'refused' && Object.hasOwn(REFUSED, job.reason)) parts.push(' ', REFUSED[job.reason][0](), ' ', mono(job.reason));
    else if (job.result === 'busy' && Object.hasOwn(BUSY, job.reason)) parts.push(' ', BUSY[job.reason]());
    else parts.push(' ', mono(job.reason));
  }
  if (typeof job.detail === 'string') parts.push(' ', mono(job.detail));
  return parts;
}

/** Whether a job changed the configuration file in force as well: the file was changed while the proxy kept running. */
function fileChanged(job) {
  return isFingerprint(job.config_before) && isFingerprint(job.config_after) && job.config_before !== job.config_after;
}

/** The box that tells how the ended job `job` came out, and what to do next. */
export function jobResult(job) {
  if (typeof job.result !== 'string' || !Object.hasOwn(RESULTS, job.result)) {
    return notice('warn', el('span', { class: 'tc-notice__title' }, w('managed.result.unknown')), ' ', el('code', {}, String(job.result)));
  }
  const [tone, name, what, next] = RESULTS[job.result];
  const box = result(tone, name(), [what(), reasonOf(job)], next === null ? null : next(job));
  if (job.result === 'applied' && fileChanged(job)) box.append(el('span', { class: 'tc-notice__next' }, w('managed.out.file_changed')));
  if (job.history === false) box.append(el('span', { class: 'tc-notice__next' }, w('managed.out.history_unwritten')));
  return box;
}

/**
 * The panel of a job: what it does and who asked for it, and how it ended or that it runs. `stopped` is what to show
 * instead when the screen stopped watching before the job ended, so that the panel does not say that it still runs.
 */
export function jobPanel(job, stopped = null) {
  const running = job.state === 'running' && stopped === null;
  return panel(
    w('managed.job.title'),
    running ? [badge('info', w('managed.job.running'))] : [],
    kv(
      row(w('managed.job.kind'), lazy(() => kindText(job.kind))),
      row(w('managed.job.by'), String(job.actor)),
      row(w('managed.job.from'), fingerprintView(job.from, { copy: false })),
      row(w('managed.job.to'), fingerprintView(job.to, { copy: false })),
      row(w('managed.job.started'), timeView(job.started, 's')),
      job.state === 'ended' ? row(w('managed.job.ended'), timeView(job.ended, 's')) : null,
    ),
    stopped ?? (running ? notice('info', el('span', { class: 'tc-running' }, el('span', { class: 'tc-spinner', 'aria-hidden': 'true' }), w('managed.job.working'))) : jobResult(job)),
  );
}

/** The badge of a result in a table of the history; a word that is not known is shown as it came. */
export function resultBadge(word) {
  return Object.hasOwn(RESULTS, word) ? badge(RESULTS[word][0], RESULTS[word][1]()) : badge('muted', String(word));
}

/** The text of the badge of a result (see `resultBadge`). */
export function resultText(word) {
  return Object.hasOwn(RESULTS, word) ? RESULTS[word][1]().text() : String(word);
}
