import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ApiError } from '../js/api.js';
import { actionsOf } from '../js/generations.js';
import { Ended, LIMITS, checkFiles, checkRoutes, importBody, toBase64, trialBlocked } from '../js/import.js';
import { canChange, generationState, shortOf, switchOutcome, utc } from '../js/parts.js';
import { Pager, buildQuery, decodeText, summaryOf } from '../js/records.js';

const file = (name, size) => ({ name, size });
const codes = (check) => check.problems.map((problem) => problem.code);

test('the files of an import are counted against the limits, at the limit and one past it', () => {
  const many = (n) => Array.from({ length: n }, (_, at) => file(`r${at}.conf`, 1));
  assert.deepEqual(codes(checkFiles({ rules: many(128), data: [], crs: false })), []);
  assert.deepEqual(codes(checkFiles({ rules: many(127), data: [file('d.data', 1)], crs: false })), []);
  assert.deepEqual(codes(checkFiles({ rules: many(129), data: [], crs: false })), ['count']);
  assert.deepEqual(codes(checkFiles({ rules: many(128), data: [file('d.data', 1)], crs: false })), ['count']);

  assert.deepEqual(codes(checkFiles({ rules: [file('a.conf', LIMITS.file)], data: [], crs: false })), []);
  assert.deepEqual(codes(checkFiles({ rules: [file('a.conf', LIMITS.file + 1)], data: [], crs: false })), ['size']);

  const four = [file('a', LIMITS.file), file('b', LIMITS.file), file('c', LIMITS.file), file('d', LIMITS.file)];
  assert.deepEqual(codes(checkFiles({ rules: four, data: [], crs: false })), []);
  const over = [...four.slice(0, 3), file('d', LIMITS.file - 1), file('e', 2)];
  const check = checkFiles({ rules: over, data: [], crs: false });
  assert.equal(check.bytes, LIMITS.total + 1);
  assert.deepEqual(codes(check), ['total']);
  assert.equal(check.largest, LIMITS.file);
  assert.equal(check.files, 5);
});

test('a file name must be a name the API takes, once, and some rule file or the CRS must be chosen', () => {
  for (const bad of ['.hidden', 'a/b.conf', 'sp ace.conf', 'ü.conf', '', 'a'.repeat(129)]) {
    assert.deepEqual(codes(checkFiles({ rules: [file(bad, 1)], data: [], crs: false })), ['name'], bad);
  }
  assert.deepEqual(codes(checkFiles({ rules: [file('a'.repeat(128), 1)], data: [], crs: false })), []);
  assert.deepEqual(codes(checkFiles({ rules: [file('a.conf', 1)], data: [file('a.conf', 1)], crs: false })), ['twice']);
  assert.deepEqual(codes(checkFiles({ rules: [], data: [], crs: false })), ['none']);
  assert.deepEqual(codes(checkFiles({ rules: [], data: [], crs: true })), []);
  // Data files alone are no rules.
  assert.deepEqual(codes(checkFiles({ rules: [], data: [file('a.data', 1)], crs: false })), ['none']);
});

test('the routes are checked as JSON of the form of a file of routes before they are sent', () => {
  assert.deepEqual(checkRoutes('  '), { value: null, count: 0, problem: null });
  const route = { host: 'a.example.com', path: '/x', action: 'bypass' };
  assert.deepEqual(checkRoutes(JSON.stringify([route, { path: '/y', action: 'bypass' }])).count, 2);
  assert.equal(checkRoutes('[').problem, 'json');
  assert.equal(checkRoutes('{}').problem, 'list');
  assert.equal(checkRoutes('[]').problem, 'list');
  const list = (n) => JSON.stringify(Array.from({ length: n }, (_, at) => ({ path: `/p${at}`, action: 'bypass' })));
  assert.equal(checkRoutes(list(LIMITS.routes)).problem, null);
  assert.equal(checkRoutes(list(LIMITS.routes + 1)).problem, 'many');
  for (const odd of [
    [{ path: '/x' }],
    [{ path: '/x', action: 'allow' }],
    [{ path: 7, action: 'bypass' }],
    [{ path: '/x', action: 'bypass', host: 7 }],
    [{ path: '/x', action: 'bypass', extra: 1 }],
    ['/x'],
    [null],
  ]) {
    assert.equal(checkRoutes(JSON.stringify(odd)).problem, 'form', JSON.stringify(odd));
  }
});

test('the bytes of a file go as the standard base64 with padding, and the body leaves out what is empty', () => {
  for (const size of [0, 1, 2, 3, 4, 5, 24575, 24576, 24577, 3 * 8192 * 2 + 2]) {
    const bytes = Uint8Array.from({ length: size }, (_, at) => (at * 31 + 7) % 256);
    assert.equal(toBase64(bytes), Buffer.from(bytes).toString('base64'), String(size));
  }
  const part = { name: 'a.conf', data: 'eA==' };
  const plain = { rules: [part], data: [], crs: false, crsOff: ['x.conf'], routes: null, detectOnly: false, acceptBlock: false };
  assert.deepEqual(importBody(plain), { rules: [part] });
  assert.deepEqual(importBody({ ...plain, crs: true, detectOnly: true, routes: [{ path: '/x', action: 'bypass' }] }), {
    rules: [part],
    crs: true,
    crs_off: ['x.conf'],
    routes: [{ path: '/x', action: 'bypass' }],
    detect_only: true,
  });
  assert.equal(importBody({ ...plain, acceptBlock: true }).accept_block, true);
});

test('a trial that failed because a rule blocked a probe is told from the other failures', () => {
  const failed = (failure) => ({ error: 'the trial failed', trial: { passed: false, failure } });
  assert.equal(trialBlocked(failed('probe: blocked by rule 942100 in phase 2, status 403')), true);
  assert.equal(trialBlocked(failed('probe: blocked by rule -1 in phase 1, status 403')), true);
  assert.equal(trialBlocked(failed('probe: no verdict in time')), false);
  assert.equal(trialBlocked(failed('the inspector was not ready in time')), false);
  assert.equal(trialBlocked({ trial: { passed: true } }), false);
  assert.equal(trialBlocked(null), false);
});

test('how an import ended waits for the screen that is shown, is told once, and is dropped with the sign-in', () => {
  const end = (fingerprint) => ({ body: { fingerprint }, error: null, request: { rules: [] } });
  const holder = new Ended();
  assert.equal(holder.take(), null);

  // A screen that is shown takes the end at once, so a second screen does not tell it again.
  const told = [];
  const stop = holder.watch(() => told.push(holder.take()));
  const first = end('a'.repeat(64));
  holder.put(first);
  assert.deepEqual(told, [first]);
  assert.equal(holder.take(), null);

  // With no screen to tell it (it was left, or the language was switched), the end waits for the next one.
  stop();
  const second = end('b'.repeat(64));
  holder.put(second);
  assert.equal(told.length, 1);
  assert.equal(holder.take(), second);
  assert.equal(holder.take(), null);

  // A newer end takes the place of an older one that nobody took, and the end of a sign-in drops it.
  holder.put(first);
  holder.put(second);
  assert.equal(holder.take(), second);
  holder.put(first);
  holder.clear();
  assert.equal(holder.take(), null);
});

test('a user who may only look is offered no action, and an operator only those the store allows', () => {
  const state = { hasChosen: true, rollbackTo: 'c'.repeat(64), servingKnown: true };
  const other = { fingerprint: 'a'.repeat(64), current: false, serving: false };
  const chosen = { fingerprint: 'b'.repeat(64), current: true, serving: true };
  const target = { fingerprint: 'c'.repeat(64), current: false, serving: false };
  for (const role of ['viewer', 'nobody', undefined]) {
    assert.deepEqual(actionsOf(role, other, state), { choose: null, remove: false, kept: null }, String(role));
  }
  for (const role of ['operator', 'owner']) {
    assert.deepEqual(actionsOf(role, other, state), { choose: 'choose', remove: true, kept: null });
    assert.deepEqual(actionsOf(role, chosen, state), { choose: null, remove: false, kept: 'chosen' });
    assert.deepEqual(actionsOf(role, target, state), { choose: 'choose', remove: false, kept: 'rollback' });
  }
  // Chosen but not served: the proxy is told to switch to it. Served but not chosen: kept as well.
  assert.equal(actionsOf('operator', { ...chosen, serving: false }, state).choose, 'apply');
  // A proxy that did not say what it serves (busy, or out of reach) gives no ground to tell it to switch.
  assert.equal(actionsOf('operator', { ...chosen, serving: false }, { ...state, servingKnown: false }).choose, null);
  assert.equal(actionsOf('operator', other, { ...state, servingKnown: false }).choose, 'choose');
  assert.equal(actionsOf('operator', { ...other, serving: true }, state).kept, 'serving');
  // Without a chosen generation no request to choose can say what it expects.
  assert.equal(actionsOf('operator', other, { hasChosen: false, rollbackTo: null, servingKnown: true }).choose, null);
  assert.equal(canChange('owner') && canChange('operator') && !canChange('viewer'), true);
});

test('a proxy that is busy or out of reach is neither the same nor different: its generation is unknown', () => {
  const id = (digit) => digit.repeat(64);
  assert.equal(generationState({ current: id('a'), proxy: null }), 'unknown');
  assert.equal(generationState({ current: id('a'), proxy: 'busy' }), 'unknown');
  assert.equal(generationState(undefined), 'unknown');
  assert.equal(generationState({ current: id('a'), proxy: { generation: id('a'), switching: false } }), 'same');
  assert.equal(generationState({ current: id('a'), proxy: { generation: id('b'), switching: true } }), 'switching');
  assert.equal(generationState({ current: id('a'), proxy: { generation: id('b'), switching: false } }), 'differ');
});

test('the end of a switch is told by the proxy’s own word, whatever the status that carried it', () => {
  const ids = { from: 'a'.repeat(64), generation: 'b'.repeat(64) };
  const fail = (kind, status, sentence, body) => ({ body: null, error: new ApiError(kind, status, sentence, body) });
  const word = (result) => switchOutcome(result).word;

  assert.equal(word({ body: { result: 'switched', ...ids, chosen: true }, error: null }), 'switched');
  assert.equal(word({ body: { result: 'unchanged', ...ids, chosen: true }, error: null }), 'unchanged');
  assert.equal(word(fail('conflict', 409, 'x', { result: 'refused', ...ids, chosen: true })), 'refused');
  assert.equal(word(fail('unknown', 502, 'x', { result: 'failed', ...ids, chosen: true })), 'failed');
  assert.equal(word(fail('unavailable', 503, 'x', { result: 'unreachable', ...ids, chosen: false })), 'unreachable');
  const unconfirmed = switchOutcome(fail('unavailable', 503, 'x', { result: 'unconfirmed', ...ids, chosen: true, history: 'not written' }));
  assert.equal(unconfirmed.word, 'unconfirmed');
  assert.equal(unconfirmed.chosen, true);
  assert.equal(unconfirmed.unwritten, true);
  assert.equal(unconfirmed.ids.to, ids.generation);

  // Without a word of the proxy's, the kind of the error says how to go on.
  assert.equal(word(fail('unavailable', 503, 'the proxy is busy', { error: 'the proxy is busy' })), 'busy');
  assert.equal(word(fail('unavailable', 503, 'unavailable', { error: 'unavailable' })), 'unavailable');
  assert.equal(word(fail('conflict', 409, 'the chosen generation is not the one that was expected', {})), 'conflict');
  assert.equal(word(fail('unknown', 504, '', null)), 'lost');
  assert.equal(word(fail('unknown', 0, '', null)), 'lost');
  assert.equal(word(fail('forbidden', 403, 'forbidden', {})), 'forbidden');
  assert.equal(word(fail('limited', 429, 'too many tries', {})), 'limited');
  assert.equal(word({ body: {}, error: null }), 'lost');
  assert.equal(word({ body: null, error: new Error('x') }), 'other');
});

test('a search is a query of the filters that are filled in, in the form the API takes', () => {
  assert.deepEqual(buildQuery({}), { query: '', problems: [] });
  const found = buildQuery({ from: '2026-10-28T09:00:00Z', type: 'request', status: ' 403 ', rule: '-5', class: '' });
  assert.equal(found.query, 'from=2026-10-28T09%3A00%3A00Z&type=request&status=403&rule=-5');
  assert.deepEqual(found.problems, []);
  const bad = buildQuery({ from: '2026-10-28 09:00', type: 'x', status: '1000', client: 'a b', generation: 'abc' });
  assert.deepEqual(bad.problems, ['from', 'type', 'status', 'client', 'generation']);
  assert.equal(bad.query, '');
  assert.deepEqual(buildQuery({ generation: 'a'.repeat(16) }).problems, []);
  assert.deepEqual(buildQuery({ generation: 'a'.repeat(64) }).problems, []);
  assert.deepEqual(buildQuery({ generation: 'a'.repeat(63) }).problems, ['generation']);
  assert.equal(buildQuery({ id: 'abc-1' }, { file: 2, offset: 4096, inode: '123' }).query, 'id=abc-1&file=2&offset=4096&inode=123');
});

test('the pages of a search can be gone through forward and back, and a new search starts over', () => {
  const [a, b, c] = [{ file: 0, offset: 100, inode: '1' }, { file: 0, offset: 50, inode: '1' }, { file: 1, offset: 9, inode: '2' }];
  const pager = new Pager();
  assert.deepEqual([pager.start, pager.page, pager.hasNewer, pager.hasOlder], [null, 1, false, false]);
  assert.equal(pager.older(), false);
  assert.equal(pager.newer(), false);

  pager.arrived(a);
  assert.equal(pager.hasOlder, true);
  assert.equal(pager.older(), true);
  assert.deepEqual([pager.start, pager.page, pager.hasNewer, pager.hasOlder], [a, 2, true, false]);
  pager.arrived(b);
  assert.equal(pager.older(), true);
  assert.deepEqual([pager.start, pager.page], [b, 3]);
  pager.arrived(null);
  assert.equal(pager.older(), false);

  // Back to the page before: it is read again with the start it had, and its answer says where the next one starts.
  assert.equal(pager.newer(), true);
  assert.deepEqual([pager.start, pager.page, pager.hasOlder], [a, 2, false]);
  pager.arrived(c);
  assert.equal(pager.older(), true);
  assert.deepEqual([pager.start, pager.page], [c, 3]);
  assert.equal(pager.newer() && pager.newer(), true);
  assert.deepEqual([pager.start, pager.hasNewer], [null, false]);

  pager.arrived(a);
  pager.reset();
  assert.deepEqual([pager.start, pager.page, pager.hasOlder], [null, 1, false]);
});

test('a decoded view reads the %XX bytes as UTF-8 and shows control characters, and the rest stays as written', () => {
  assert.equal(decodeText('/a%20b'), '/a b');
  assert.equal(decodeText('%E3%81%82%E3%81%84'), 'あい');
  // Bytes that are not UTF-8 stay as they were written, and so does a stray percent sign.
  assert.equal(decodeText('/x%80y'), '/x%80y');
  assert.equal(decodeText('100%'), '100%');
  assert.equal(decodeText('%E3%81'), '%E3%81');
  // A line break, a null and the mark that turns the direction of text are made visible.
  assert.equal(decodeText('a%0D%0Ab'), 'a\\x0D\\x0Ab');
  assert.equal(decodeText('%00'), '\\x00');
  assert.equal(decodeText('x%E2%80%AEy'), 'x\\u{202E}y');
  // The byte order mark is shown, at the start of the bytes of a run and inside it, and not dropped.
  assert.equal(decodeText('/%EF%BB%BFadmin'), '/\\u{FEFF}admin');
  assert.equal(decodeText('/a%EF%BB%BFb'), '/a\\u{FEFF}b');
  assert.equal(decodeText('%EF%BB%BF'), '\\u{FEFF}');
  assert.equal(decodeText('<img src=x onerror=1>'), '<img src=x onerror=1>');
});

test('a value is shown as text, and a record says what it is about in one line', () => {
  assert.equal(summaryOf({ type: 'request', method: 'GET', host: 'h', path: '/a%20b' }), 'GET h/a%20b');
  assert.equal(summaryOf({ type: 'line', line: 'start: listening' }), 'start: listening');
  assert.equal(summaryOf({ type: 'audit', action: 'login', result: 'ok' }), 'login ok');
  assert.equal(summaryOf({ type: 'dropped', count: 4 }), '4');
  assert.equal(summaryOf({ type: 'other' }), '');
  assert.equal(shortOf('0123456789abcdef'.repeat(4)), '0123456789ab');
  assert.equal(shortOf('not a fingerprint'), 'not a fingerprint');
  assert.equal(utc(0), '1970-01-01 00:00:00Z');
  assert.equal(utc(1_795_000_000), '2026-11-18 11:06:40Z');
  assert.equal(utc('x'), 'x');
});

test('every key that a script asks for is named in the call itself, so that the dictionary test sees it', () => {
  const scripts = new URL('../js/', import.meta.url);
  for (const name of readdirSync(scripts).filter((file) => file !== 'i18n.js')) {
    const source = readFileSync(new URL(name, scripts), 'utf8');
    assert.ok(!/\bt\(\s*[^'\s]/.test(source), `${name}: a key that is not a plain string`);
  }
});
