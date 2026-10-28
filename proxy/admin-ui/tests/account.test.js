import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ApiError } from '../js/api.js';
import { Enrollment, Held, ROLES, codeToSend, inGroups, passwordProblem, rolesUpTo, tokenProblem, when } from '../js/account.js';
import { userActions, userProblem } from '../js/users.js';

const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const CODES = ['ABCDEFGHIJKLMNOP', 'QRSTUVWXYZ234567'];

test('a token can be given the role of its maker or a lower one, and no higher', () => {
  assert.deepEqual(rolesUpTo('viewer'), ['viewer']);
  assert.deepEqual(rolesUpTo('operator'), ['viewer', 'operator']);
  assert.deepEqual(rolesUpTo('owner'), ['viewer', 'operator', 'owner']);
  assert.deepEqual(rolesUpTo('root'), []);
  assert.deepEqual(rolesUpTo('owner'), ROLES);
  const token = { name: 'ci', role: 'operator', days: '30' };
  assert.equal(tokenProblem(token, 'operator'), null);
  assert.equal(tokenProblem(token, 'owner'), null);
  assert.equal(tokenProblem(token, 'viewer'), 'role');
  assert.equal(tokenProblem({ ...token, role: 'admin' }, 'owner'), 'role');
});

test('the name and the days of a token are checked at the limit and one past it', () => {
  const base = { name: 'ci', role: 'viewer', days: '1' };
  for (const days of ['1', '365', '30']) assert.equal(tokenProblem({ ...base, days }, 'viewer'), null, days);
  for (const days of ['0', '366', '', '-1', '1.5', '1e2', ' 5', '1000', 'x']) assert.equal(tokenProblem({ ...base, days }, 'viewer'), 'days', days);
  assert.equal(tokenProblem({ ...base, name: 'a'.repeat(64) }, 'viewer'), null);
  assert.equal(tokenProblem({ ...base, name: 'a'.repeat(65) }, 'viewer'), 'name');
  assert.equal(tokenProblem({ ...base, name: 'a b ~' }, 'viewer'), null);
  for (const name of ['', 'ü', 'tab\there', 'new\nline', 'del\x7f']) assert.equal(tokenProblem({ ...base, name }, 'viewer'), 'name', JSON.stringify(name));
});

test('a password is counted in bytes, 12 to 128, and must differ from the old one', () => {
  assert.equal(passwordProblem('old password 1', 'a'.repeat(12), 'a'.repeat(12)), null);
  assert.equal(passwordProblem('old password 1', 'a'.repeat(11), 'a'.repeat(11)), 'length');
  assert.equal(passwordProblem('old password 1', 'a'.repeat(128), 'a'.repeat(128)), null);
  assert.equal(passwordProblem('old password 1', 'a'.repeat(129), 'a'.repeat(129)), 'length');
  // Four characters of three bytes are 12 bytes; 43 of them are 129.
  assert.equal(passwordProblem('x', 'あ'.repeat(4), 'あ'.repeat(4)), null);
  assert.equal(passwordProblem('x', 'あ'.repeat(43), 'あ'.repeat(43)), 'length');
  assert.equal(passwordProblem('old password 1', 'a'.repeat(12), 'a'.repeat(13)), 'mismatch');
  assert.equal(passwordProblem('a'.repeat(12), 'a'.repeat(12), 'a'.repeat(12)), 'same');
});

test('the code of the second factor is sent as six digits, or as a recovery code in capitals without spaces', () => {
  assert.equal(codeToSend(' 123 456 '), '123456');
  assert.equal(codeToSend('abcd efgh ijkl mnop'), 'ABCDEFGHIJKLMNOP');
  assert.equal(codeToSend('12345'), '12345');
  assert.equal(codeToSend('1234567'), '1234567');
  assert.equal(inGroups('ABCDEFGHIJKLMNOP'), 'ABCD EFGH IJKL MNOP');
  assert.equal(inGroups('ABCDEFGHIJ'), 'ABCD EFGH IJ');
  assert.equal(inGroups(''), '');
});

test('the times of accounts are milliseconds', () => {
  assert.equal(when(1_700_000_000_000), '2023-11-14 22:13:20Z');
  assert.equal(when(0), '1970-01-01 00:00:00Z');
  assert.equal(when(null), 'null');
});

test('the secret and the recovery codes live in the state of the setup only, and are gone when it is cleared', () => {
  const setup = new Enrollment();
  assert.equal(setup.step, 'start');
  // An answer that lacks the secret or the address starts nothing and keeps nothing.
  for (const answer of [null, {}, { secret: SECRET }, { uri: 'otpauth://x' }, { secret: 7, uri: 'otpauth://x' }, { secret: '', uri: 'otpauth://x' }]) {
    assert.equal(setup.begin(answer), false);
    assert.deepEqual([setup.step, setup.secret, setup.uri, setup.codes], ['start', null, null, null]);
  }
  assert.equal(setup.begin({ secret: SECRET, uri: `otpauth://totp/x?secret=${SECRET}` }), true);
  assert.deepEqual([setup.step, setup.secret], ['scan', SECRET]);
  // Codes that are missing, empty or not text change nothing.
  for (const answer of [null, {}, { recovery: [] }, { recovery: 'ABCD' }, { recovery: ['ABCD', 7] }, { recovery: [''] }]) {
    assert.equal(setup.finish(answer), false);
    assert.equal(setup.step, 'scan');
  }
  assert.equal(setup.finish({ recovery: CODES }), true);
  // The codes take the place of the secret and of the address.
  assert.deepEqual([setup.step, setup.secret, setup.uri, setup.codes], ['codes', null, null, CODES]);
  setup.clear();
  assert.deepEqual([setup.step, setup.secret, setup.uri, setup.codes], ['start', null, null, null]);
  const text = JSON.stringify(setup);
  for (const secret of [SECRET, ...CODES]) assert.ok(!text.includes(secret));
});

test('the recovery codes of a confirmation on its way are kept when the screen that sent it is gone, and dropped when the sign-in ends', async () => {
  const later = () => {
    const call = { resolve: null, reject: null, sent: [] };
    const promise = new Promise((resolve, reject) => Object.assign(call, { resolve, reject }));
    return { api: { call: (...args) => (call.sent.push(args), promise) }, call };
  };
  const begun = () => {
    const held = new Held();
    held.enrollment.begin({ secret: SECRET, uri: `otpauth://totp/x?secret=${SECRET}` });
    return held;
  };

  // The screen is left while the code is on its way: what it showed is given up, the answer is not lost.
  const held = begun();
  const asked = later();
  const sent = held.confirm(asked.api, '123456');
  assert.deepEqual(asked.call.sent, [['POST', '/api/account/mfa/confirm', { code: '123456' }]]);
  assert.notEqual(held.confirming, null);
  held.clear();
  assert.equal(held.enrollment.step, 'start');
  asked.call.resolve({ recovery: CODES });
  assert.deepEqual(await sent, { error: null, kept: true });
  assert.deepEqual([held.enrollment.step, held.enrollment.codes, held.confirming], ['codes', CODES, null]);
  // Once they are shown and the user is done, they leave the holder.
  held.clear();
  assert.deepEqual([held.enrollment.step, held.enrollment.codes], ['start', null]);

  // The sign-in ends while the code is on its way: the answer reaches nobody, and the next sign-in finds nothing.
  const gone = begun();
  const late = later();
  const lost = gone.confirm(late.api, '123456');
  gone.forget();
  assert.equal(gone.confirming, null);
  late.call.resolve({ recovery: CODES });
  assert.equal(await lost, null);
  assert.deepEqual([gone.enrollment.step, gone.enrollment.codes], ['start', null]);
  for (const code of CODES) assert.ok(!JSON.stringify(gone).includes(code));

  // A refusal keeps nothing, and an answer without codes is told as such.
  const refused = begun();
  const no = later();
  const failed = refused.confirm(no.api, '000000');
  no.call.reject(new ApiError('conflict', 409, 'mfa setup was not started or has run out'));
  const end = await failed;
  assert.equal(end.error.kind, 'conflict');
  assert.equal(end.kept, false);
  assert.deepEqual([refused.enrollment.step, refused.enrollment.codes, refused.confirming], ['scan', null, null]);
  assert.deepEqual(await refused.confirm({ call: async () => ({}) }, '123456'), { error: null, kept: false });
});

test('the scripts of the account never write to the storage of the browser, the address or the history', () => {
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
  for (const name of ['account.js', 'users.js', 'qr.js']) {
    const source = readFileSync(new URL(`../js/${name}`, import.meta.url), 'utf8');
    for (const [what, pattern] of STORES) assert.doesNotMatch(source, pattern, `${name}: ${what}`);
  }
});

test('an owner is offered no change to its own account, and a user is offered what applies to it', () => {
  const user = (fields) => ({ name: 'bob', role: 'viewer', disabled: false, mfa: false, must_change: false, ...fields });
  assert.deepEqual(userActions(user({ name: 'alice', role: 'owner', mfa: true }), 'alice'), {
    self: true,
    role: false,
    toggle: null,
    password: false,
    resetMfa: false,
  });
  assert.deepEqual(userActions(user({}), 'alice'), { self: false, role: true, toggle: 'disable', password: true, resetMfa: false });
  assert.deepEqual(userActions(user({ disabled: true, mfa: true }), 'alice'), { self: false, role: true, toggle: 'enable', password: true, resetMfa: true });
});

test('a new user needs a name the API takes, a known role and a password of 12 to 128 bytes', () => {
  const fields = { name: 'bob', role: 'viewer', password: 'a'.repeat(12) };
  assert.equal(userProblem(fields), null);
  assert.equal(userProblem({ ...fields, name: 'a'.repeat(32) }), null);
  assert.equal(userProblem({ ...fields, name: 'a'.repeat(33) }), 'name');
  for (const name of ['', 'Bob', 'bob smith', 'bob/x', 'bóg']) assert.equal(userProblem({ ...fields, name }), 'name', name);
  assert.equal(userProblem({ ...fields, name: 'a.b_c-d9' }), null);
  assert.equal(userProblem({ ...fields, role: 'admin' }), 'role');
  assert.equal(userProblem({ ...fields, password: 'a'.repeat(11) }), 'password');
  assert.equal(userProblem({ ...fields, password: 'a'.repeat(129) }), 'password');
});
