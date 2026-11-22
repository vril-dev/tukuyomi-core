import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ApiError } from '../js/api.js';
import { actionsOf, screens as generationScreens } from '../js/waf/generations.js';
import { setLanguage, w } from '../js/i18n.js';
import { Ended, LIMITS, checkFiles, checkRouteList, importBody, routesOfRows, toBase64, trialBlocked } from '../js/waf/import.js';
import { ENGINE_IDS, instantOf, canChange, clock, defaultEngine, engineName, engineStates, generationState, hashOf, oldProxy, shortOf, switchOutcome, timeCellText, timeLabel, timeText } from '../js/parts.js';
import { parseRoute } from '../js/app.js';
import { PAGE_SIZE, filterRows, nextDirection, pageOf, sortRows } from '../js/table.js';
import { countOf, uptimeText } from '../js/waf/waf.js';
import { Pager, buildQuery, decodeText, screens as recordScreens, summaryOf } from '../js/waf/records.js';

const file = (name, size) => ({ name, size });
const codes = (check) => check.problems.map((problem) => problem.code);

const id = (digit) => digit.repeat(64);

/**
 * An answer of `GET /api/status` of this version. `chosen` and `rollback` are what the rules store says, by engine;
 * `running` is the generation that the proxy serves for each engine that it runs (`null`: a proxy that does not report
 * its engines); `proxy` is `null` for a proxy that cannot be reached, or what it says besides.
 */
function statusOf({ chosen = {}, rollback = {}, running = {}, proxy = {}, name = 'coraza' }) {
  const engines = ENGINE_IDS.map((engine) => ({ engine, current: chosen[engine] ?? null, rollback_to: rollback[engine] ?? null }));
  const ran = running === null ? null : Object.entries(running).map(([engine, generation]) => ({ engine, generation, mode: 'block', phase: 'ready' }));
  const base = { generation: id('0'), mode: 'block', engine: name, phase: 'ready', switching: false, ready: true, engines: ran };
  return { current: chosen[name] ?? null, reachable: proxy !== null, rollback_to: rollback[name] ?? null, default_engine: name, engines, proxy: proxy === null || typeof proxy === 'string' ? proxy : { ...base, ...proxy }, crs: { available: false, files: [] } };
}

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

test('the routes are checked in the form of a file of routes before they are sent, and the lines of the table make them', () => {
  const route = { host: 'a.example.com', path: '/x', action: 'bypass' };
  assert.equal(checkRouteList([route, { path: '/y', action: 'bypass' }]).count, 2);
  assert.equal(checkRouteList({}).problem, 'list');
  assert.equal(checkRouteList([]).problem, 'list');
  const list = (n) => Array.from({ length: n }, (_, at) => ({ path: `/p${at}`, action: 'bypass' }));
  assert.equal(checkRouteList(list(LIMITS.routes)).problem, null);
  assert.equal(checkRouteList(list(LIMITS.routes + 1)).problem, 'many');
  for (const odd of [
    [{ path: '/x' }],
    [{ path: '/x', action: 'allow' }],
    [{ path: 7, action: 'bypass' }],
    [{ path: '/x', action: 'bypass', host: 7 }],
    [{ path: '/x', action: 'bypass', extra: 1 }],
    ['/x'],
    [null],
  ]) {
    assert.equal(checkRouteList(odd).problem, 'form', JSON.stringify(odd));
  }
  // A line with neither a host nor a path is left out; one with a host and no path is named; a host may be left out.
  const lines = [{ host: ' ', path: '' }, { host: 'a.example.com', path: '' }, { host: '', path: ' /y ' }, { host: 'b.example.com', path: '/z' }];
  assert.deepEqual(routesOfRows(lines), {
    routes: [{ path: '/y', action: 'bypass' }, { host: 'b.example.com', path: '/z', action: 'bypass' }],
    missing: [1],
  });
  assert.deepEqual(routesOfRows([]), { routes: [], missing: [] });
});

test('the bytes of a file go as the standard base64 with padding, and the body leaves out what is empty', () => {
  for (const size of [0, 1, 2, 3, 4, 5, 24575, 24576, 24577, 3 * 8192 * 2 + 2]) {
    const bytes = Uint8Array.from({ length: size }, (_, at) => (at * 31 + 7) % 256);
    assert.equal(toBase64(bytes), Buffer.from(bytes).toString('base64'), String(size));
  }
  const part = { name: 'a.conf', data: 'eA==' };
  const plain = { engine: 'coraza', rules: [part], data: [], crs: false, crsOff: ['x.conf'], routes: null, detectOnly: false, acceptBlock: false };
  // The engine goes in every body, the default one as well.
  assert.deepEqual(importBody(plain), { engine: 'coraza', rules: [part] });
  assert.deepEqual(importBody({ ...plain, engine: 'modsecurity', crs: true, detectOnly: true, routes: [{ path: '/x', action: 'bypass' }] }), {
    engine: 'modsecurity',
    rules: [part],
    crs: true,
    crs_off: ['x.conf'],
    routes: [{ path: '/x', action: 'bypass' }],
    detect_only: true,
  });
  assert.equal(importBody({ ...plain, acceptBlock: true }).accept_block, true);
  assert.throws(() => importBody({ ...plain, engine: undefined }), RangeError);
  assert.throws(() => importBody({ ...plain, engine: 'Coraza' }), RangeError);
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

test('a user who may only look is offered no action, and an operator only those the store allows for the engine of the generation', () => {
  const [a, b, c, d, m, n] = ['a', 'b', 'c', 'd', 'e', 'f'].map(id);
  const gen = (fingerprint, engine, flags = {}) => ({ fingerprint, engine, current: false, serving: false, ...flags });
  const both = { chosen: { coraza: b, modsecurity: m }, rollback: { coraza: c, modsecurity: n }, running: { coraza: b, modsecurity: m } };
  const state = (status) => ({ engines: engineStates(status), legacy: oldProxy(status) });
  const ready = state(statusOf(both));
  for (const role of ['viewer', 'nobody', undefined]) {
    assert.deepEqual(actionsOf(role, gen(a, 'coraza'), ready), { choose: null, remove: false, kept: null }, String(role));
  }
  for (const role of ['operator', 'owner']) {
    assert.deepEqual(actionsOf(role, gen(a, 'coraza'), ready), { choose: 'choose', remove: true, kept: null });
    assert.deepEqual(actionsOf(role, gen(b, 'coraza', { current: true, serving: true }), ready), { choose: null, remove: false, kept: 'chosen' });
  }
  // The target of a rollback of either engine is kept, and a generation of the other engine may still be chosen.
  assert.deepEqual(actionsOf('operator', gen(c, 'coraza'), ready), { choose: 'choose', remove: false, kept: 'rollback' });
  assert.deepEqual(actionsOf('operator', gen(n, 'modsecurity'), ready), { choose: 'choose', remove: false, kept: 'rollback' });
  assert.equal(actionsOf('operator', gen(a, 'coraza', { serving: true }), ready).kept, 'serving');
  // Chosen but another one serves: the proxy is told to switch. Chosen and the engine does not run: it is started.
  assert.equal(actionsOf('operator', gen(b, 'coraza', { current: true }), state(statusOf({ ...both, running: { coraza: a, modsecurity: m } }))).choose, 'apply');
  assert.equal(actionsOf('operator', gen(m, 'modsecurity', { current: true }), state(statusOf({ ...both, running: { coraza: b } }))).choose, 'start');
  // A switch that is under way (the engine is being started) leaves the button to start it, not to apply.
  assert.equal(actionsOf('operator', gen(m, 'modsecurity', { current: true }), state(statusOf({ ...both, running: { coraza: b }, proxy: { switching: true } }))).choose, 'start');
  assert.equal(actionsOf('operator', gen(b, 'coraza', { current: true }), state(statusOf({ ...both, running: { coraza: a, modsecurity: m }, proxy: { switching: true } }))).choose, 'apply');
  // An engine that has none chosen can be given one; each engine is asked for what it has, not what the other has.
  assert.equal(actionsOf('operator', gen(d, 'modsecurity'), state(statusOf({ chosen: { coraza: b }, running: { coraza: b } }))).choose, 'choose');
  // A generation whose engine is not one of ours (its manifest could not be read) is not chosen or started.
  assert.equal(actionsOf('operator', gen(a, 'unknown'), ready).choose, null);
  // A proxy that cannot be reached or is busy gives no ground to tell it to switch; one of an older version cannot be told.
  const away = state(statusOf({ ...both, proxy: null }));
  assert.equal(actionsOf('operator', gen(a, 'coraza'), away).choose, 'choose');
  assert.equal(actionsOf('operator', gen(b, 'coraza', { current: true }), away).choose, null);
  const old = state(statusOf({ ...both, running: null }));
  assert.deepEqual(actionsOf('operator', gen(a, 'coraza'), old), { choose: null, remove: true, kept: null });
  assert.equal(canChange('owner') && canChange('operator') && !canChange('viewer'), true);
});

test('each engine is in one state, from what the store chooses for it and what the proxy runs, and the bar tells a difference of any', () => {
  const [a, b] = [id('a'), id('b')];
  const states = (status) => Object.fromEntries(engineStates(status).map((one) => [one.engine, one.state]));
  assert.deepEqual(states(statusOf({ chosen: { coraza: a }, running: { coraza: a } })), { coraza: 'same', modsecurity: 'idle' });
  assert.deepEqual(states(statusOf({ chosen: { coraza: a, modsecurity: b }, running: { coraza: a, modsecurity: a } })), { coraza: 'same', modsecurity: 'differ' });
  // The switch of the proxy is one flag for all engines: an engine that is not what it is to be is under way, the others stay.
  assert.deepEqual(states(statusOf({ chosen: { coraza: a, modsecurity: b }, running: { coraza: a, modsecurity: a }, proxy: { switching: true } })), { coraza: 'same', modsecurity: 'switching' });
  // Chosen and not run is `unstarted`, and the start that is under way is not told as a difference. Run and not chosen is `unchosen`.
  assert.deepEqual(states(statusOf({ chosen: { coraza: a, modsecurity: b }, running: { coraza: a } })), { coraza: 'same', modsecurity: 'unstarted' });
  assert.equal(states(statusOf({ chosen: { coraza: a, modsecurity: b }, running: { coraza: a }, proxy: { switching: true } })).modsecurity, 'switching');
  assert.deepEqual(states(statusOf({ chosen: {}, running: { coraza: a } })), { coraza: 'unchosen', modsecurity: 'idle' });
  // What the proxy did not say is unknown for every engine, the default one too (an older proxy runs one engine, whose name is not the default).
  for (const odd of [{ proxy: null }, { running: null }, { proxy: 'busy' }]) {
    assert.deepEqual(states(statusOf({ chosen: { coraza: a }, ...odd })), { coraza: 'unknown', modsecurity: 'unknown' }, JSON.stringify(odd));
  }
  const one = engineStates(statusOf({ chosen: { modsecurity: b }, rollback: { modsecurity: a }, running: { modsecurity: b }, name: 'modsecurity' }));
  assert.deepEqual(one[1], { engine: 'modsecurity', current: b, rollbackTo: a, serving: b, mode: 'block', phase: 'ready', running: true, isDefault: true, state: 'same' });
  assert.deepEqual([one[0].running, engineStates(statusOf({ proxy: null }))[0].running], [false, null]);
  assert.equal(one[0].isDefault, false);
  // The bar: a difference or an engine that is chosen and not run; an engine that runs with none chosen is no difference.
  assert.equal(generationState(statusOf({ chosen: { coraza: a }, running: { coraza: a } })), 'same');
  assert.equal(generationState(statusOf({ chosen: { coraza: a, modsecurity: b }, running: { coraza: a, modsecurity: a } })), 'differ');
  assert.equal(generationState(statusOf({ chosen: { coraza: a, modsecurity: b }, running: { coraza: a } })), 'differ');
  assert.equal(generationState(statusOf({ chosen: { coraza: a }, running: { coraza: b }, proxy: { switching: true } })), 'switching');
  assert.equal(generationState(statusOf({ chosen: {}, running: { coraza: a } })), 'same');
  assert.equal(generationState(statusOf({ chosen: { coraza: a }, proxy: null })), 'unknown');
  assert.equal(generationState(statusOf({ chosen: { coraza: a }, running: null })), 'unknown');
  assert.equal(generationState(undefined), 'unknown');
});

test('the default engine is the one that the admin process names, and none is named when the proxy runs another', () => {
  const named = (name, proxy = {}, running = {}) => defaultEngine(statusOf({ name, running, proxy }));
  assert.deepEqual(named('modsecurity'), { name: 'modsecurity', differs: false });
  assert.deepEqual(named('coraza', { engine: 'modsecurity' }), { name: null, differs: true });
  // A proxy of an older version names the engine that it runs, which is no default; a proxy that is out of reach names none.
  assert.deepEqual(named('coraza', { engine: 'modsecurity' }, null), { name: 'coraza', differs: false });
  assert.deepEqual(named('coraza', null), { name: 'coraza', differs: false });
  assert.deepEqual(defaultEngine({ default_engine: 'Coraza' }), { name: null, differs: false });
  assert.deepEqual(defaultEngine(undefined), { name: null, differs: false });
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
  // The engine is the one that the proxy names in its answer, else the one that the request was for.
  assert.equal(switchOutcome({ body: { result: 'switched', engine: 'modsecurity', ...ids, chosen: true }, error: null }, 'coraza').engine, 'modsecurity');
  assert.equal(switchOutcome(fail('unknown', 504, '', null), 'coraza').engine, 'coraza');

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
  // The engine is one of the two names as the API takes them, in lower case.
  assert.deepEqual(buildQuery({ engine: 'modsecurity' }), { query: 'engine=modsecurity', problems: [] });
  assert.deepEqual(buildQuery({ engine: 'Coraza' }), { query: '', problems: ['engine'] });
  assert.deepEqual(buildQuery({ engine: 'modsec' }).problems, ['engine']);
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
});

test('every key that a script asks for is named in the call itself, so that the dictionary test sees it', () => {
  const scripts = new URL('../js/', import.meta.url);
  const files = readdirSync(scripts, { recursive: true }).filter((file) => file.endsWith('.js') && file !== 'i18n.js' && !file.endsWith('/words.js'));
  for (const name of files) {
    const source = readFileSync(new URL(name, scripts), 'utf8');
    assert.ok(!/(?<![\w.])[tw]\(\s*[^'\s]/.test(source), `${name}: a key that is not a plain string`);
  }
});

test('the import form offers Coraza, the default, and ModSecurity, each by its name in both languages', () => {
  assert.deepEqual(ENGINE_IDS, ['coraza', 'modsecurity']);
  for (const language of ['en', 'ja']) {
    setLanguage(language);
    assert.deepEqual(ENGINE_IDS.map(engineName), ['Coraza', 'ModSecurity']);
  }
  setLanguage('en');
});

test('an engine is shown by its name in the language, and a word that is not one of ours as it was given', () => {
  setLanguage('en');
  assert.equal(engineName('coraza'), 'Coraza');
  assert.equal(engineName('modsecurity'), 'ModSecurity');
  setLanguage('ja');
  assert.equal(engineName('modsecurity'), 'ModSecurity');
  // A name from the prototype of an object is no engine, and a value that is no word is text.
  assert.equal(engineName('constructor'), 'constructor');
  assert.equal(engineName(undefined), 'undefined');
  setLanguage('en');
});

test('a time is written one way, in the zone of the user or in UTC, from seconds, milliseconds or a text', () => {
  assert.equal(instantOf(1_795_000_000, 's'), 1_795_000_000_000);
  assert.equal(instantOf(1_795_000_000_000), 1_795_000_000_000);
  assert.equal(instantOf('2026-11-18T11:06:40.000Z'), 1_795_000_000_000);
  for (const odd of [null, undefined, 'x', NaN, Infinity, {}, '2026-13-45T00:00:00Z']) assert.equal(instantOf(odd), null, String(odd));
  setLanguage('ja');
  assert.equal(timeText(1_795_000_000_000, true), '2026-11-18 11:06:40（UTC）');
  assert.equal(timeText(0, true), '1970-01-01 00:00:00（UTC）');
  assert.match(timeText(1_795_000_000_000, false), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}（.+）$/);
  setLanguage('en');
  assert.equal(timeText(1_795_000_000_000, true), '2026-11-18 11:06:40 (UTC)');
  // In a table the name of the column says the zone once, and a cell in that zone does not repeat it.
  clock.utc = true;
  assert.equal(timeLabel(w('col.time')).text(), 'Time (UTC)');
  assert.equal(timeCellText(1_795_000_000_000), '2026-11-18 11:06:40');
  clock.utc = false;
});

test('rows are sorted by a column, filtered by text and cut into pages, at the edges of each', () => {
  const rows = [
    { n: 10, name: 'b' },
    { n: 9, name: 'a' },
    { n: null, name: 'c' },
    { n: 9, name: 'd' },
  ];
  const column = { value: (row) => row.n };
  // Numbers are read as numbers, equal values keep their order, and a missing value is last in either direction.
  assert.deepEqual(sortRows(rows, column, 'ascending').map((row) => row.name), ['a', 'd', 'b', 'c']);
  assert.deepEqual(sortRows(rows, column, 'descending').map((row) => row.name), ['b', 'a', 'd', 'c']);
  assert.deepEqual(rows.map((row) => row.name), ['b', 'a', 'c', 'd']);
  assert.equal(nextDirection(undefined), 'ascending');
  assert.equal(nextDirection('ascending'), 'descending');
  assert.equal(nextDirection('descending'), 'ascending');

  const columns = [{ value: (row) => row.name }, { value: (row) => row.n, filter: false }];
  assert.deepEqual(filterRows(rows, columns, ' B ').map((row) => row.name), ['b']);
  assert.deepEqual(filterRows(rows, columns, '10'), []);
  assert.equal(filterRows(rows, columns, '   ').length, 4);
  // A column whose cell shows other words than its value is looked in by what it shows, not by what it is sorted by.
  const shown = [{ value: (row) => row.n * 1000, text: (row) => `#${row.name}` }];
  assert.deepEqual(filterRows(rows, shown, '#a').map((row) => row.name), ['a']);
  assert.deepEqual(filterRows(rows, shown, '9000'), []);

  assert.equal(PAGE_SIZE, 50);
  assert.deepEqual(pageOf(0, 50, 0), { page: 0, pages: 1, from: 0, to: 0 });
  assert.deepEqual(pageOf(50, 50, 0), { page: 0, pages: 1, from: 1, to: 50 });
  assert.deepEqual(pageOf(51, 50, 1), { page: 1, pages: 2, from: 51, to: 51 });
  // A page past the end, or before the start, is kept in range.
  assert.deepEqual(pageOf(120, 50, 9), { page: 2, pages: 3, from: 101, to: 120 });
  assert.deepEqual(pageOf(120, 50, -1), { page: 0, pages: 3, from: 1, to: 50 });
});

test('a value in the address is used only in the form its screen takes, and what is not is dropped and named', () => {
  const known = { generations: generationScreens[0].route, records: recordScreens[0].route, history: {} };
  const fp = 'a'.repeat(64);
  assert.deepEqual(parseRoute(`#/generations/${fp}`, known), { screen: 'generations', id: fp, query: {}, invalid: [] });
  assert.deepEqual(parseRoute(`#/generations/${fp.slice(1)}`, known), { screen: 'generations', id: null, query: {}, invalid: ['id'] });
  assert.equal(parseRoute(`#/generations/${fp.toUpperCase()}`, known).id, null);
  assert.deepEqual(parseRoute(`#/generations/${fp}/more`, known).invalid, ['path']);
  assert.deepEqual(parseRoute('#/records/0186af5443bddbd9-1?status=403&client=192.0.2.1', known), {
    screen: 'records',
    id: '0186af5443bddbd9-1',
    query: { status: '403', client: '192.0.2.1' },
    invalid: [],
  });
  // A key that is not a filter, a value that is not of its form and a key given twice are dropped (the name of a key that
  // is not known is not kept); a blank value is no filter.
  const odd = parseRoute('#/records?status=40x&nokey=1&rule=5&rule=6&class=', known);
  assert.deepEqual(odd.query, { rule: '5' });
  assert.deepEqual(odd.invalid, ['status', 'key', 'rule']);
  assert.equal(parseRoute('#/records/%E0%A4', known).id, null);
  assert.deepEqual(parseRoute('#/history/x', known).invalid, ['id']);
  // A screen that is not ours is none; the page then shows its first screen.
  for (const hash of ['', '#', '#/', '#/nothing', '#/__proto__', '#/constructor/x']) assert.equal(parseRoute(hash, known).screen, null, hash);
  // The address of what was found is the one that was read, and it reads back the same.
  const engine = parseRoute('#/records?engine=modsecurity&status=403', known);
  assert.deepEqual(engine.query, { engine: 'modsecurity', status: '403' });
  const wrong = parseRoute('#/records?engine=Coraza', known);
  assert.deepEqual([wrong.query, wrong.invalid], [{}, ['engine']]);
  const again = parseRoute(hashOf('records', { id: 'abc-1', query: { generation: fp.slice(0, 16), client: 'a b' } }), known);
  assert.deepEqual(again.query, { generation: fp.slice(0, 16) });
  assert.deepEqual(again.invalid, ['client']);
});

test('the numbers of the overview are numbers only when the proxy gave them, and a time of running is told in its two largest units', () => {
  assert.equal(countOf({ proxy: { requests: 0 } }, 'requests'), 0);
  for (const odd of [{ proxy: { requests: null } }, { proxy: {} }, { proxy: null }, null, { proxy: { requests: -1 } }, { proxy: { requests: '5' } }]) {
    assert.equal(countOf(odd, 'requests'), null);
  }
  setLanguage('en');
  assert.equal(uptimeText(35_999), '35 s');
  assert.equal(uptimeText(60_000), '1 min 0 s');
  assert.equal(uptimeText(3_600_000), '1 h 0 min');
  assert.equal(uptimeText(86_400_000 + 4 * 3_600_000), '1 d 4 h');
});
