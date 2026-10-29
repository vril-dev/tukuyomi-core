import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Api, ApiError, gateOf, kindOf, requestOf } from '../js/api.js';
import { describe } from '../js/app.js';
import { sentence, setLanguage, t } from '../js/i18n.js';
import { generationState } from '../js/waf.js';

/**
 * A fetch that answers from a list, in order, and keeps what it was asked. A reply is `[status, body, fields]`: the
 * fields are the header fields it carries, by lower-case name; its body is JSON.
 */
function fake(replies) {
  const asked = [];
  const fetchFunction = async (path, init) => {
    asked.push({ path, method: init.method, headers: { ...init.headers }, body: init.body, init });
    const [status, body, fields = {}] = replies.shift();
    const get = (name) => (name.toLowerCase() === 'content-type' ? 'application/json' : (fields[name.toLowerCase()] ?? null));
    return { status, headers: { get }, json: async () => body };
  };
  return { asked, fetchFunction };
}

test('the gate comes from the answer of the sign-in or of the session', () => {
  assert.equal(gateOf({ mfa: 'off', must_change: false }), 'open');
  assert.equal(gateOf({ state: 'active', mfa: true, must_change: false }), 'open');
  assert.equal(gateOf({ mfa: 'verify', must_change: true }), 'mfa');
  assert.equal(gateOf({ mfa: 'off', must_change: true }), 'password');
  assert.equal(gateOf({ state: 'must_change', mfa: false, must_change: true }), 'password');
  // When both are due, the password comes first.
  assert.equal(gateOf({ mfa: 'setup', must_change: true }), 'password');
  assert.equal(gateOf({ mfa: 'setup', must_change: false }), 'setup');
  assert.equal(gateOf({ state: 'mfa_setup', must_change: false }), 'setup');
  // Nothing is opened on an answer that is not understood.
  for (const odd of [null, undefined, {}, 'open', { mfa: 'on' }, { state: 'other' }]) {
    assert.equal(gateOf(odd), 'login', JSON.stringify(odd));
  }
});

test('a status says how to go on', () => {
  const kinds = [[401, 'session'], [403, 'forbidden'], [409, 'conflict'], [429, 'limited'], [503, 'unavailable']];
  for (const [status, kind] of kinds) assert.equal(kindOf(status), kind, String(status));
  assert.equal(kindOf(502), 'unknown');
  assert.equal(kindOf(504), 'unknown');
  assert.equal(kindOf(400), 'refused');
  assert.equal(kindOf(500), 'failed');
});

test('the CSRF token goes with every call but GET and HEAD', async () => {
  const { asked, fetchFunction } = fake([[200, { csrf: 'token-1' }], [200, {}], [200, {}], [200, {}]]);
  const api = new Api(fetchFunction);
  await api.call('POST', '/api/login', { name: 'a', password: 'b' }, { auth: false });
  assert.equal(api.csrf, 'token-1');
  await api.call('GET', '/api/status');
  await api.call('PUT', '/api/account/password', { current: 'a', new: 'b' });
  await api.call('DELETE', '/api/account/mfa');
  assert.equal(asked[0].headers['X-CSRF-Token'], undefined);
  assert.equal(asked[1].headers['X-CSRF-Token'], undefined);
  assert.equal(asked[2].headers['X-CSRF-Token'], 'token-1');
  assert.equal(asked[3].headers['X-CSRF-Token'], 'token-1');
  assert.equal(asked[2].headers['Content-Type'], 'application/json');
});

test('a change refused with 403 is tried once more when the session has a new CSRF token, and not otherwise', async () => {
  const forbidden = [403, { error: 'forbidden' }];
  const renewed = fake([forbidden, [200, { csrf: 'new' }], [200, {}]]);
  const api = new Api(renewed.fetchFunction);
  api.csrf = 'old';
  await api.call('POST', '/api/rollback', { expect: 'x' });
  assert.deepEqual(renewed.asked.map((a) => a.method), ['POST', 'GET', 'POST']);
  assert.equal(renewed.asked[2].headers['X-CSRF-Token'], 'new');
  assert.equal(api.csrf, 'new');

  // The same token: the refusal stands, and the change is sent once.
  const same = fake([forbidden, [200, { csrf: 'old' }]]);
  const other = new Api(same.fetchFunction);
  other.csrf = 'old';
  await assert.rejects(other.call('POST', '/api/rollback', { expect: 'x' }), (e) => e.kind === 'forbidden' && e.sentence === 'forbidden');
  assert.equal(same.asked.length, 2);
});

test('a 401 ends the session for a call that needs one, and is a plain refusal for a sign-in', async () => {
  let lost = 0;
  const { fetchFunction } = fake([[401, { error: 'unauthorized' }], [401, { error: 'invalid credentials' }], [502, null]]);
  const api = new Api(fetchFunction);
  api.csrf = 'token';
  api.onSessionLost = () => {
    lost += 1;
  };
  await assert.rejects(api.call('GET', '/api/status'), (e) => e instanceof ApiError && e.kind === 'session');
  assert.equal(lost, 1);
  assert.equal(api.csrf, null);
  await assert.rejects(api.call('POST', '/api/login', {}, { auth: false }), (e) => e.status === 401 && e.sentence === 'invalid credentials');
  assert.equal(lost, 1);
  await assert.rejects(api.call('POST', '/api/activate', {}), (e) => e.kind === 'unknown' && e.status === 502);
});

test('a call sets no mode and no referrer policy, so that a browser sends the real Origin with a change', async () => {
  const { asked, fetchFunction } = fake([[200, {}], [200, {}]]);
  const api = new Api(fetchFunction);
  await api.call('POST', '/api/rollback', { expect: 'x' });
  await api.call('GET', '/api/status');
  assert.equal(asked.length, 2);
  for (const { init } of asked) {
    assert.ok(!('mode' in init) && !('referrerPolicy' in init), init.method);
  }
});

test('the number of a request is kept only in the form the proxy gives, at its limits and one past them', () => {
  const prefix = '0123456789abcdef';
  for (const good of [`${prefix}-0`, `${prefix}-14c`, `${prefix}-${'f'.repeat(16)}`]) assert.equal(requestOf(good), good, good);
  const bad = [
    null, undefined, '', 17, `${prefix}`, `${prefix}-`, `${prefix}-${'f'.repeat(17)}`, `${prefix.slice(1)}-1`, `${prefix}0-1`,
    `${prefix.toUpperCase()}-1`, `${prefix}-1F`, `${prefix}-1g`, ` ${prefix}-1`, `${prefix}-1 `, `${prefix}-1\n`,
    `${prefix}-1, ${prefix}-2`, `${prefix}_1`, '<b>0123456789abcdef-1</b>',
  ];
  for (const odd of bad) assert.equal(requestOf(odd), '', JSON.stringify(odd));
});

test('an answer with no sentence shows the number of its request, and one with a sentence shows only the sentence', async () => {
  setLanguage('en');
  const id = '9f3a51c0e2b47d18-14c';
  const fail = async (reply, options) => {
    const api = new Api(fake([reply]).fetchFunction);
    const error = await api.call('GET', '/api/status').catch((caught) => caught);
    assert.ok(error instanceof ApiError);
    return { error, words: describe(error, options) };
  };
  const blocked = await fail([403, null, { 'x-request-id': id }]);
  assert.equal(blocked.error.request, id);
  assert.equal(blocked.words, `${t('error.generic')} ${t('error.request', { id })}`);
  assert.ok(blocked.words.includes(id));

  // The proxy that gave up says so with an empty answer too, and its words are kept.
  const gaveUp = await fail([502, null, { 'x-request-id': id }], { change: true });
  assert.equal(gaveUp.words, `${t('error.unknown_result')} ${t('error.request', { id })}`);

  // A value that is not of the form is dropped, and so is a missing one.
  for (const fields of [{ 'x-request-id': '9F3A51C0E2B47D18-14c' }, { 'x-request-id': '<b>x</b>' }, {}]) {
    const plain = await fail([403, null, fields]);
    assert.equal(plain.error.request, '');
    assert.equal(plain.words, t('error.generic'));
  }

  // An answer with a sentence is shown as it was: the number is not added.
  const said = await fail([403, { error: 'forbidden' }, { 'x-request-id': id }]);
  assert.equal(said.error.request, id);
  assert.equal(said.words, sentence('forbidden'));
  assert.ok(!said.words.includes(id));

  // An error that the page makes itself, and any other error, are worded as before.
  assert.equal(describe(new ApiError('refused', 400, '', null, id)), `${t('error.generic')} ${t('error.request', { id })}`);
  assert.equal(describe(new Error('x')), t('error.generic'));
});

test('a sign-out ends only on the word of the server, and a failure keeps the session as it was', async () => {
  let lost = 0;
  const signedIn = (fetchFunction) => {
    const api = new Api(fetchFunction);
    api.csrf = 'token';
    api.onSessionLost = () => {
      lost += 1;
    };
    return api;
  };
  const ended = signedIn(fake([[200, {}]]).fetchFunction);
  await ended.logout();
  assert.equal(ended.csrf, null);

  // No answer, a proxy that gave up and a refusal: the page cannot say that the session is ended.
  const refused = fake([[403, { error: 'forbidden' }], [200, {}]]);
  for (const api of [
    signedIn(async () => {
      throw new TypeError('network');
    }),
    signedIn(fake([[502, null]]).fetchFunction),
    signedIn(refused.fetchFunction),
  ]) {
    await assert.rejects(api.logout(), (e) => e instanceof ApiError && e.kind !== 'session');
    assert.equal(api.csrf, 'token');
  }
  assert.equal(lost, 0);

  // A 401: the session was gone already.
  const gone = signedIn(fake([[401, { error: 'unauthorized' }]]).fetchFunction);
  await assert.rejects(gone.logout(), (e) => e.kind === 'session');
  assert.equal(lost, 1);
});

test('a call that gets no answer has an unknown result', async () => {
  const api = new Api(async () => {
    throw new TypeError('network');
  });
  await assert.rejects(api.call('POST', '/api/activate', {}), (e) => e.kind === 'unknown' && e.status === 0);
});

test('the chosen and the serving generation are compared only when the proxy said which it serves', () => {
  const [a, b] = ['a'.repeat(64), 'b'.repeat(64)];
  assert.equal(generationState({ current: a, proxy: { generation: a, switching: false } }), 'same');
  assert.equal(generationState({ current: a, proxy: { generation: b, switching: false } }), 'differ');
  assert.equal(generationState({ current: a, proxy: { generation: b, switching: true } }), 'switching');
  assert.equal(generationState({ current: null, proxy: { generation: b, switching: false } }), 'differ');
  assert.equal(generationState({ current: a, proxy: null }), 'unknown');
});
