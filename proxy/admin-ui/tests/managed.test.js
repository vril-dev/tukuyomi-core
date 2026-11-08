import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { mock, test } from 'node:test';

import { ApiError } from '../js/api.js';
import { dictionaries } from '../js/i18n.js';
import { BUSY, REFUSED, RESULTS, Watch, isJob, watchLimit } from '../js/managed/job.js';
import { cardState, differs, versionActions } from '../js/managed/managed.js';
import { mayRollBack } from '../js/managed/history.js';

const FP = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);

test('every result, every word of a refusal and every word of busy has its words', () => {
  const results = ['applied', 'refused', 'busy', 'current changed', 'no version', 'unmanaged', 'store', 'audit', 'error', 'unreachable', 'failed', 'unconfirmed', 'not recorded'];
  assert.deepEqual(Object.keys(RESULTS).sort(), [...results].sort());
  const refused = ['configuration', 'version', 'store', 'upstream', 'tls', 'fixed', 'listener', 'thread', 'unmanaged'];
  assert.deepEqual(Object.keys(REFUSED).sort(), [...refused].sort());
  const busy = ['store in use', 'proxy busy', 'reload under way', 'starting', 'too many orders', 'stopping'];
  assert.deepEqual(Object.keys(BUSY).sort(), [...busy].sort());
  assert.equal(Object.hasOwn(dictionaries.en, 'managed.result.unknown'), true);
});

test('a job is read only in its form, and how long it may run follows the time of the lookup of the names', () => {
  const job = { state: 'running', from: FP, to: OTHER };
  assert.equal(isJob(job), true);
  for (const odd of [null, {}, { ...job, state: 'lost' }, { ...job, from: 'x' }, { ...job, to: 7 }]) assert.equal(isJob(odd), false);
  // Three tries of the time and 7 s each, and 20 s for the rest.
  assert.equal(watchLimit({ proxy: { resolve_timeout_ms: 1000 } }, null), 3 * 8000 + 20000);
  // A proxy that does not tell its time is told by the file; without either, the limit of the setting is used.
  assert.equal(watchLimit({ proxy: {} }, { resolveMs: 2000 }), 3 * 9000 + 20000);
  assert.equal(watchLimit(null, null), 3 * (3_600_000 + 7000) + 20000);
});

/** A watch whose reads are answered by the test, on the timers of the test. */
function watched() {
  mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000_000 });
  const asked = [];
  const events = [];
  const watch = new Watch(
    () =>
      new Promise((resolve, reject) => {
        asked.push({ resolve, reject });
      }),
    (event) => events.push(event),
  );
  return { asked, events, watch };
}

const job = (state, result = null) => ({ kind: 'activate', actor: 'ann', from: FP, to: OTHER, started: 100, state, result });
/** Lets the code that waits for an answer run. */
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('the second read waits for the answer to the first, and the watch ends when the job has ended', async () => {
  const { asked, events, watch } = watched();
  watch.start(job('running'), true, 60_000);
  assert.equal(watch.active, true);
  mock.timers.tick(1000);
  assert.equal(asked.length, 1);
  // A second goes by and the answer has not come: no second read.
  mock.timers.tick(5000);
  assert.equal(asked.length, 1);
  asked[0].resolve({ job: job('running') });
  await settle();
  mock.timers.tick(1000);
  assert.equal(asked.length, 2);
  asked[1].resolve({ job: job('ended', 'applied') });
  await settle();
  assert.deepEqual(events.map((event) => event.type), ['ended']);
  assert.equal(watch.active, false);
  mock.timers.tick(5000);
  assert.equal(asked.length, 2);
  mock.timers.reset();
});

test('the screen that is gone reads nothing more', async () => {
  const { asked, watch } = watched();
  watch.start(job('running'), true, 60_000);
  watch.stop();
  mock.timers.tick(5000);
  assert.equal(asked.length, 0);
  mock.timers.reset();
  // Nor does an answer that comes after it stopped go on reading.
  const late = watched();
  late.watch.start(job('running'), true, 60_000);
  mock.timers.tick(1000);
  late.watch.stop();
  late.asked[0].resolve({ job: job('running') });
  await settle();
  mock.timers.tick(5000);
  assert.equal(late.asked.length, 1);
  assert.deepEqual(late.events, []);
  mock.timers.reset();
});

test('two reads in a row that give nothing go on, and the third ends the watch', async () => {
  const { asked, events, watch } = watched();
  watch.start(job('running'), true, 60_000);
  mock.timers.tick(1000);
  asked[0].reject(new ApiError('unavailable', 503, ''));
  await settle();
  mock.timers.tick(1000);
  asked[1].resolve({});
  await settle();
  mock.timers.tick(1000);
  assert.equal(asked.length, 3);
  assert.equal(events.length, 0);
  asked[2].reject(new ApiError('unknown', 0, ''));
  await settle();
  assert.deepEqual(events.map((event) => event.type), ['lost']);
  assert.equal(watch.active, false);
  mock.timers.reset();
});

test('a refused read ends the watch with its reason, and one answer that is read counts the misses from zero again', async () => {
  const { asked, events, watch } = watched();
  watch.start(job('running'), true, 60_000);
  mock.timers.tick(1000);
  asked[0].reject(new ApiError('unavailable', 503, ''));
  await settle();
  mock.timers.tick(1000);
  asked[1].resolve({ job: job('running') });
  await settle();
  mock.timers.tick(1000);
  asked[2].reject(new ApiError('conflict', 409, 'the configuration has no managed object'));
  await settle();
  assert.deepEqual(events.map((event) => event.type), ['refused']);
  assert.equal(events[0].error.status, 409);
  mock.timers.reset();
});

test('a job that runs at its limit is read once more, and one past it ends the watch', async () => {
  const { asked, events, watch } = watched();
  watch.start(job('running'), true, 2000);
  mock.timers.tick(1000);
  asked[0].resolve({ job: job('running') });
  await settle();
  mock.timers.tick(1000);
  // The answer comes exactly at the limit, and the job is read once more.
  asked[1].resolve({ job: job('running') });
  await settle();
  assert.equal(watch.active, true);
  assert.deepEqual(events, []);
  mock.timers.tick(1000);
  // This one comes past the limit, so the watch ends with no further read.
  asked[2].resolve({ job: job('running') });
  await settle();
  assert.deepEqual(events.map((event) => event.type), ['lost']);
  mock.timers.tick(5000);
  assert.equal(asked.length, 3);
  mock.timers.reset();
});

test('another job than the one this page sent is told as such', async () => {
  const { asked, events, watch } = watched();
  watch.start(job('running'), true, 60_000);
  mock.timers.tick(1000);
  asked[0].resolve({ job: { ...job('running'), actor: 'bob' } });
  await settle();
  assert.deepEqual(events.map((event) => [event.type, event.other]), [['progress', true]]);
  mock.timers.reset();
});

test('a job of null ends the watch: the admin process has no job to tell of', async () => {
  const { asked, events, watch } = watched();
  watch.start(job('running'), true, 60_000);
  mock.timers.tick(1000);
  asked[0].resolve({ job: null });
  await settle();
  assert.deepEqual(events.map((event) => event.type), ['gone']);
  assert.equal(watch.active, false);
  mock.timers.tick(5000);
  assert.equal(asked.length, 1);
  mock.timers.reset();
});

test('a viewer gets no change and no content of a version, an operator what applies to the version', () => {
  const version = { name: FP, current: false };
  assert.deepEqual(versionActions('viewer', version, OTHER), { open: false, apply: false });
  assert.deepEqual(versionActions('operator', version, OTHER), { open: true, apply: true });
  assert.deepEqual(versionActions('owner', { ...version, current: true }, FP), { open: true, apply: false });
  // No version is selected, so the request has nothing to expect; a name that is not one of ours gets no way in.
  assert.deepEqual(versionActions('operator', version, null), { open: true, apply: false });
  assert.deepEqual(versionActions('operator', { name: 'x' }, OTHER), { open: false, apply: false });
  const state = { current: FP, rollback_to: OTHER };
  assert.equal(mayRollBack('viewer', state), false);
  assert.equal(mayRollBack('operator', state), true);
  assert.equal(mayRollBack('operator', { ...state, rollback_to: null }), false);
});

test('a difference is told only when no job runs and the proxy is not reading its configuration again', () => {
  const state = { current: FP, serving: OTHER, reachable: true, reloading: false };
  assert.equal(differs(state, false), true);
  assert.equal(differs(state, true), false);
  assert.equal(differs({ ...state, reloading: true }, false), false);
  assert.equal(differs({ ...state, serving: FP }, false), false);
  assert.equal(differs({ ...state, serving: null }, false), false);
  assert.equal(cardState(state), 'differ');
  assert.equal(cardState({ ...state, serving: FP }), 'same');
  assert.equal(cardState({ ...state, reachable: false, reloading: null, serving: null }), 'unknown');
  assert.equal(cardState({ ...state, reloading: null, serving: null }), 'unknown');
  assert.equal(cardState({ ...state, serving: null }), 'unmanaged');
  assert.equal(cardState({ ...state, current: null }), 'none');
  assert.equal(cardState({ ...state, job: { state: 'running', from: FP, to: OTHER } }), 'job');
});

test('the scripts of the managed configuration never write to the storage of the browser, the address or the history', () => {
  const STORES = [
    ['localStorage', /localStorage/],
    ['sessionStorage', /sessionStorage/],
    ['indexedDB', /indexedDB/],
    ['a cookie', /document\s*\.\s*cookie/],
    ['the history', /\bhistory\s*\.\s*(push|replace)State/],
    ['the address', /\blocation\s*\.\s*(hash|href|search|assign|replace)\b/],
    ['the cache', /\bcaches\s*\./],
    ['a form of the address', /new\s+URL\b|URLSearchParams/],
  ];
  const scripts = new URL('../js/managed/', import.meta.url);
  for (const name of readdirSync(scripts)) {
    const source = readFileSync(new URL(name, scripts), 'utf8');
    for (const [what, pattern] of STORES) assert.doesNotMatch(source, pattern, `${name}: ${what}`);
  }
});
