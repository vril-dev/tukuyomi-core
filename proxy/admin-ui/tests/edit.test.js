import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mock, test } from 'node:test';

import { ApiError } from '../js/api.js';
import { lazy, setLanguage } from '../js/i18n.js';
import { BODY_MAX, EditScreen, FILES_MAX, bodySize, checkFinding } from '../js/managed/edit/bar.js';
import { Screen } from '../js/managed/screen.js';
import { changesBetween } from '../js/managed/edit/changes.js';
import { Draft, caKey, forgetDraft, heldDraft, holdDraft, isOwnJob, readableVersion, savingRuns, settleSaving, settleSent, syncDraft } from '../js/managed/edit/draft.js';
import { barFault as barFaultOf, faultAt, locate } from '../js/managed/edit/locate.js';
import { PEM_MAX, pemFromBytes, pickPem } from '../js/managed/edit/pem.js';

const FP = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);

// A draft that holds changes makes the page ask before it goes away: node has no such thing, so the handlers land here.
const beforeunload = new Set();
globalThis.addEventListener = (type, handler) => {
  if (type === 'beforeunload') beforeunload.add(handler);
};
globalThis.removeEventListener = (type, handler) => {
  if (type === 'beforeunload') beforeunload.delete(handler);
};

/** A version with what the drafts of these tests carry: a site, two groups (one with TLS), an empty list and a key left out. */
function sampleVersion() {
  return {
    sites: [{ name: 'main', hosts: ['a.example'], certificate: { acme: { renew_before_days: 30 } } }],
    upstreams: {
      app: { servers: [{ address: '127.0.0.1:8080', weight: 1, max_fails: 1, fail_timeout_ms: 10000, backup: false }] },
      api: {
        servers: [
          { address: 'api.internal:443', weight: 5, max_fails: 0, fail_timeout_ms: 5000, backup: true },
          { address: 'api2.internal:443', weight: 1, max_fails: 1, fail_timeout_ms: 10000, backup: false },
        ],
        tls: { ca: 'c'.repeat(64), server_name: 'api.internal' },
      },
    },
    routes: [{ path: '/', upstream: 'app', rewrite: { request_headers: { set: [{ name: 'x-token', value: 'TOP-SECRET' }] } } }],
    default_upstream: 'app',
    access: { allow_cidrs: ['10.0.0.0/8'], deny_countries: [] },
  };
}

const draftOf = (version, more = {}) => new Draft({ base: FP, baseVersion: version, source: version, ...more });
const describeError = (error) => lazy(() => error.sentence);
const groupNamed = (draft, name) => draft.groups.find((group) => group.name === name);

test('a draft with no change gives the version it was made from, with its empty list and what was left out', () => {
  const version = sampleVersion();
  assert.deepEqual(draftOf(version).build().version, version);
  // A list that was written stays even when it is empty, and an optional key that was not written is not added.
  const built = draftOf(version).build().version;
  assert.deepEqual(built.access.deny_countries, []);
  assert.equal(Object.hasOwn(built.access, 'deny_cidrs'), false);
  assert.equal(Object.hasOwn(built, 'rate_limit'), false);
  const bare = { ...version };
  delete bare.access;
  bare.rate_limit = { rate: 10, burst: 5, keys: 2048 };
  const carried = draftOf(bare).build().version;
  assert.equal(Object.hasOwn(carried, 'access'), false);
  assert.equal(Object.hasOwn(carried.rate_limit, 'exempt_cidrs'), false);
  assert.deepEqual(carried, bare);
});

test('a draft from a version and a new base leave the sites and the routes as the draft carried them', () => {
  const source = sampleVersion();
  source.routes.push({ path: '/other/', upstream: 'api' });
  const baseVersion = sampleVersion();
  const draft = new Draft({ base: FP, baseVersion, source, fromVersion: true });
  assert.equal(draft.changed, true);
  assert.deepEqual(draft.build().version.sites, source.sites);
  assert.deepEqual(draft.build().version.routes, source.routes);
  const newest = sampleVersion();
  newest.sites = [];
  draft.rebase(OTHER, newest);
  assert.equal(draft.base, OTHER);
  assert.equal(draft.baseVersion, newest);
  assert.deepEqual(draft.build().version.sites, source.sites);
  assert.deepEqual(draft.build().version.routes, source.routes);
});

test('a group named __proto__ is read and written like any other', () => {
  const server = { address: '127.0.0.1:1', weight: 1, max_fails: 1, fail_timeout_ms: 1, backup: false };
  const text = `{"sites":[],"upstreams":{"__proto__":{"servers":[${JSON.stringify(server)}]}},"routes":[{"upstream":"__proto__"}],"default_upstream":"__proto__"}`;
  const version = JSON.parse(text);
  const draft = draftOf(version);
  const [group] = draft.groups;
  assert.equal(group.name, '__proto__');
  assert.equal(draft.uses(group.cid).routes, 1);
  const built = draft.build();
  assert.equal(JSON.stringify(built.version), text);
  assert.equal(Object.getPrototypeOf(built.version.upstreams), Object.prototype);
  assert.equal(built.map.groups.get('__proto__').cid, group.cid);
});

test('a route and the default follow their group through a rename, and through a name that another group had for a while', () => {
  const version = { sites: [], upstreams: { a: sampleVersion().upstreams.app, b: sampleVersion().upstreams.app }, routes: [{ upstream: 'a' }, { upstream: 'b' }], default_upstream: 'b' };
  const passing = draftOf(version);
  passing.write(groupNamed(passing, 'a'), 'name', 'b');
  passing.write(passing.groups[0], 'name', 'bc');
  const renamed = passing.build().version;
  assert.deepEqual(renamed.routes.map((route) => route.upstream), ['bc', 'b']);
  assert.equal(renamed.default_upstream, 'b');
  const swapped = draftOf(version);
  const [a, b] = swapped.groups;
  swapped.write(a, 'name', 'x');
  swapped.write(b, 'name', 'a');
  swapped.write(a, 'name', 'b');
  const built = swapped.build().version;
  assert.deepEqual(built.routes.map((route) => route.upstream), ['b', 'a']);
  assert.equal(built.default_upstream, 'a');
  assert.deepEqual(Object.keys(built.upstreams).sort(), ['a', 'b']);
});

test('a group that a route or the default uses, and the last group, cannot be taken away', () => {
  const draft = draftOf(sampleVersion());
  const app = groupNamed(draft, 'app');
  const api = groupNamed(draft, 'api');
  // `app` is the route's and the default's.
  assert.equal(draft.mayRemove(app.cid), false);
  assert.equal(draft.removeGroup(app.cid), false);
  // `api` is used by neither, and goes.
  assert.equal(draft.removeGroup(api.cid), true);
  assert.equal(draft.groups.length, 1);
  // A group that is left alone is the last one, even with nothing using it.
  const lone = draftOf({ sites: [], upstreams: { z: sampleVersion().upstreams.app }, routes: [], default_upstream: '' });
  assert.equal(lone.mayRemove(lone.groups[0].cid), false);
});

test('what is not in its form is told at its field and nothing is built, and the first fault opens its panel', () => {
  setLanguage('ja');
  const draft = draftOf(sampleVersion());
  const [app, api] = draft.groups;
  draft.write(api.servers[1], 'weight', 'ten');
  draft.write(api.servers[0], 'max_fails', '1234567890');
  draft.write(api, 'name', 'app');
  draft.write(draft.access, 'deny_cidrs', '10.0.0.0/8\n\nnot-a-network');
  const { faults, version } = draft.build();
  assert.equal(version, undefined);
  const about = (field) => faults.find((one) => one.field === field);
  assert.equal(about('name').cid, api.cid);
  assert.equal(about('weight').cid, api.servers[1].cid);
  // Ten digits of a u32 are told as a number that is too long; nine go on to the check of the API.
  assert.equal(about('max_fails').cid, api.servers[0].cid);
  draft.write(api.servers[0], 'max_fails', '123456789');
  assert.equal(draft.build().faults.some((one) => one.field === 'max_fails'), false);
  // The line of the list is told from 1, counting the lines of the box.
  assert.match(String(about('deny_cidrs').words), /^3 行目/);
  draft.putFaults(faults);
  assert.equal(draft.firstFault('upstreams').cid, api.cid);
  assert.equal(draft.openGroup, api.cid);
  assert.notEqual(draft.openGroup, app.cid);
  // Writing the field takes its fault away, and leaves the others.
  draft.write(api, 'name', 'fine');
  assert.equal(draft.faults.some((one) => one.field === 'name'), false);
  assert.equal(draft.faults.length, faults.length - 1);
  setLanguage('en');
});

test('a place in a refusal is found in the request as it was sent', () => {
  setLanguage('ja');
  const draft = draftOf(sampleVersion());
  const [app, api] = draft.groups;
  draft.write(app, 'tls', true);
  draft.useCa(app, { sha256: 'd'.repeat(64), text: 'pem', name: 'ca.pem', size: 3 });
  const { map } = draft.build();
  assert.deepEqual(locate('upstreams.api.servers[1].address', map), { screen: 'upstreams', group: api.cid, cid: api.servers[1].cid, field: 'address' });
  assert.deepEqual(locate('upstreams.app', map), { screen: 'upstreams', group: app.cid, cid: app.cid, field: 'name' });
  assert.deepEqual(locate('rate_limit.keys', map), { screen: 'policy', group: null, cid: 'rate', field: 'keys' });
  assert.deepEqual(locate('files[0]', map), { screen: 'upstreams', group: app.cid, cid: app.cid, field: 'ca' });
  assert.equal(locate('files[1]', map), null);
  // What the table does not hold is for the band, with the sentence alone; a route is told by its number from 1.
  const sentence = lazy(() => 'refused');
  assert.equal(String(faultAt('routes[3].path', map, sentence).words), '経路の 4 番目: refused');
  assert.equal(String(faultAt('routes', map, sentence).words), 'refused');
  assert.equal(String(faultAt(null, map, sentence).words), 'refused');
  assert.equal(faultAt('routes[3].path', map, sentence).screen, null);
  // The name of a group is looked for only among the names that were sent: what every object has is no group.
  assert.equal(locate('upstreams.__proto__.servers[0].address', map), null);
  assert.equal(locate('upstreams.constructor', map), null);
  // A line that was taken away after the request does not shift what the answer means.
  const kept = api.servers[1].cid;
  draft.removeServer(api, api.servers[0].cid);
  assert.equal(locate('upstreams.api.servers[1].address', map).cid, kept);
  setLanguage('en');
});

test('the answer of a check is put on no field when the draft has moved on since it was asked', () => {
  const draft = draftOf(sampleVersion());
  const asked = { revision: draft.revision, map: draft.build().map };
  const refused = new ApiError('refused', 400, 'a server port is 0', { at: 'upstreams.app.servers[0].address' });
  assert.equal(checkFinding(draft, asked, { answer: { version: OTHER }, error: null }, describeError).kind, 'passed');
  assert.equal(checkFinding(draft, asked, { answer: { version: FP }, error: null }, describeError).kind, 'same');
  const finding = checkFinding(draft, asked, { answer: null, error: refused }, describeError);
  assert.equal(finding.kind, 'refused');
  assert.equal(finding.fault.field, 'address');
  draft.edited();
  assert.equal(checkFinding(draft, asked, { answer: { version: OTHER }, error: null }, describeError).kind, 'stale');
  assert.equal(checkFinding(draft, asked, { answer: null, error: refused }, describeError).kind, 'stale');
  assert.deepEqual(draft.faults, []);
  forgetDraft();
});

test('the size of a body stops it only past the limits of the admin process', () => {
  const frame = JSON.stringify({ version: '', files: [] }).length;
  const fits = { version: 'x'.repeat(BODY_MAX - frame), files: [] };
  assert.equal(bodySize(fits, null).tooLarge, false);
  assert.equal(bodySize({ version: `${fits.version}x`, files: [] }, null).tooLarge, true);
  // A body over the limit of the proxy in front is told and sent, for the page may be connected past the proxy.
  assert.deepEqual([bodySize(fits, BODY_MAX - 1).overProxy, bodySize(fits, BODY_MAX - 1).tooLarge], [true, false]);
  assert.equal(bodySize(fits, BODY_MAX).overProxy, false);
  assert.equal(bodySize({ version: '', files: Array(FILES_MAX).fill('') }, null).tooMany, false);
  assert.equal(bodySize({ version: '', files: Array(FILES_MAX + 1).fill('') }, null).tooMany, true);
});

test('a file of PEM is named by its text, with or without a byte order mark, and one that is not UTF-8 is refused', async () => {
  const text = '-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n';
  const bytes = new TextEncoder().encode(text);
  const marked = new Uint8Array([0xef, 0xbb, 0xbf, ...bytes]);
  const expected = createHash('sha256').update(text).digest('hex');
  assert.deepEqual(await pemFromBytes(bytes), { text, sha256: expected });
  assert.deepEqual(await pemFromBytes(marked), { text, sha256: expected });
  assert.equal(await pemFromBytes(new Uint8Array([0xff, 0xfe])), null);
  const draft = draftOf(sampleVersion());
  holdDraft(draft);
  const read = async () => bytes;
  const atLimit = await pickPem(draft, 'k', { name: 'ca.pem', size: PEM_MAX }, read);
  assert.equal(atLimit.pem.sha256, expected);
  assert.deepEqual(await pickPem(draft, 'k', { name: 'ca.pem', size: PEM_MAX + 1 }, read), { problem: 'size' });
  forgetDraft();
});

test('a reading that a new choice or the end of the draft has passed by is dropped, and buttons wait while files are read', async () => {
  const draft = draftOf(sampleVersion());
  holdDraft(draft);
  const key = caKey(draft.groups[0].cid);
  let finish;
  const slow = pickPem(draft, key, { name: 'old.pem', size: 3 }, () => new Promise((resolve) => (finish = resolve)));
  assert.equal(draft.reading, 1);
  const chosen = await pickPem(draft, key, { name: 'new.pem', size: 3 }, async () => new TextEncoder().encode('new'));
  assert.equal(chosen.pem.name, 'new.pem');
  finish(new TextEncoder().encode('old'));
  assert.equal(await slow, null);
  assert.equal(draft.reading, 0);
  // The draft is given up while a file is read.
  const dropped = pickPem(draft, key, { name: 'x.pem', size: 3 }, () => new Promise((resolve) => (finish = resolve)));
  forgetDraft();
  finish(new TextEncoder().encode('x'));
  assert.equal(await dropped, null);
});

test('only the files that the version names are sent, and a content chosen twice goes once', () => {
  const version = sampleVersion();
  delete version.upstreams.api.tls;
  const draft = draftOf(version);
  const [app, api] = draft.groups;
  const pem = { sha256: 'd'.repeat(64), text: 'pem', name: 'ca.pem', size: 3 };
  draft.write(app, 'tls', true);
  draft.useCa(app, pem);
  draft.write(api, 'tls', true);
  draft.useCa(api, pem);
  assert.equal(draft.files.size, 1);
  const twice = draft.build();
  assert.deepEqual(twice.files, ['pem']);
  // The file is told at the first field that chose it.
  assert.equal(twice.map.files[0].cid, app.cid);
  // A file that the version does not name stays in the draft and is not sent.
  draft.write(app, 'tls', false);
  draft.write(api, 'tls', false);
  assert.deepEqual(draft.build().files, []);
  assert.equal(draft.files.size, 1);
});

test('how a saving ended is told by what a read of the state finds', () => {
  const sent = { to: OTHER, revision: 3, prior: null };
  const mine = { kind: 'apply', actor: 'ann', from: FP, to: OTHER, started: 100, state: 'ended', result: 'applied' };
  const after = (job, current = OTHER, revision = 3) => settleSent({ sent, revision, current, job, user: 'ann', workingName: null });
  assert.equal(after(mine), 'took');
  assert.equal(after({ ...mine, result: 'refused' }, FP), 'failed');
  // No job to see: the state alone tells, and only for the same draft.
  assert.equal(after(null), 'took');
  assert.equal(after(null, OTHER, 4), 'failed');
  assert.equal(after(null, FP), 'failed');
  assert.equal(after({ ...mine, state: 'running', result: null }, FP), 'waits');
  assert.equal(settleSent({ sent, revision: 3, current: FP, job: null, user: 'ann', workingName: 'managed-apply' }), 'waits');
  // A job that was known before the saving was sent is not its job, even with the same version.
  const known = { kind: 'apply', actor: 'ann', to: OTHER, started: 100 };
  assert.equal(isOwnJob(mine, { ...sent, prior: known }, 'ann'), false);
  assert.equal(isOwnJob({ ...mine, started: 200 }, { ...sent, prior: known }, 'ann'), true);
  assert.equal(isOwnJob(mine, sent, 'bob'), false);
});

test('a draft with no change follows the selected version, one with changes stays and cannot be saved until it is told what to do', () => {
  const version = sampleVersion();
  assert.equal(syncDraft(FP, version, null), 'made');
  const draft = heldDraft();
  const cid = draft.groups[0].cid;
  // Reading the same version again keeps the numbers of the items.
  assert.equal(syncDraft(FP, version, null), 'same');
  assert.equal(heldDraft().groups[0].cid, cid);
  const newer = sampleVersion();
  assert.equal(syncDraft(OTHER, newer, null), 'made');
  const remade = heldDraft();
  assert.equal(remade.base, OTHER);
  remade.write(remade.groups[0], 'name', 'renamed');
  assert.equal(syncDraft(FP, version, null), 'moved');
  assert.equal(heldDraft(), remade);
  const screen = { busy: () => false, data: { state: { current: FP } } };
  assert.equal(EditScreen.prototype.maySave.call(screen, remade), false);
  assert.equal(EditScreen.prototype.moved.call(screen, remade), true);
  // A new base takes in the selected version; the draft keeps what it holds.
  const held = remade.groups.map((group) => group.name);
  remade.rebase(FP, version);
  assert.equal(remade.base, FP);
  assert.deepEqual(remade.groups.map((group) => group.name), held);
  assert.equal(EditScreen.prototype.maySave.call(screen, remade), true);
  forgetDraft();
});

test('forgetting the draft says whether it held changes, and the page asks before it goes away only while it does', () => {
  assert.equal(forgetDraft(), false);
  const draft = draftOf(sampleVersion());
  holdDraft(draft);
  assert.equal(beforeunload.size, 0);
  assert.equal(forgetDraft(), false);
  holdDraft(draft);
  draft.edited();
  assert.equal(beforeunload.size, 1);
  assert.equal(forgetDraft(), true);
  assert.equal(beforeunload.size, 0);
  assert.equal(heldDraft(), null);
});

test('an edit keeps the session alive at most once in 30 seconds, and a time without edits asks for nothing', () => {
  mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  let asked = 0;
  const draft = draftOf(sampleVersion(), {
    session: () => {
      asked += 1;
      return Promise.resolve({});
    },
  });
  holdDraft(draft);
  draft.edited();
  assert.equal(asked, 0);
  mock.timers.tick(29_999);
  draft.edited();
  assert.equal(asked, 0);
  mock.timers.tick(1);
  draft.edited();
  assert.equal(asked, 1);
  mock.timers.tick(60_000);
  assert.equal(asked, 1);
  draft.edited();
  assert.equal(asked, 2);
  forgetDraft();
  mock.timers.reset();
});

test('the lines of what a change does name the items and no value, and the order of the keys is no change', () => {
  const before = sampleVersion();
  const reordered = JSON.parse(JSON.stringify(before));
  const { servers, tls } = reordered.upstreams.api;
  reordered.upstreams.api = { tls, servers };
  reordered.routes[0] = { rewrite: reordered.routes[0].rewrite, upstream: 'app', path: '/' };
  assert.deepEqual(changesBetween(before, reordered), []);
  const after = JSON.parse(JSON.stringify(before));
  after.routes[0].rewrite.request_headers.set[0].value = 'ANOTHER-SECRET';
  after.upstreams.renamed = after.upstreams.api;
  delete after.upstreams.api;
  after.default_upstream = 'renamed';
  delete after.access;
  const lines = changesBetween(before, after);
  assert.deepEqual(lines.map((line) => [line.area, line.action, line.label]), [
    ['upstream', 'remove', 'api'],
    ['upstream', 'add', 'renamed'],
    ['default', 'change', ''],
    ['access', 'remove', ''],
    ['route', 'change', '* /'],
  ]);
  assert.doesNotMatch(JSON.stringify(lines), /SECRET/);
});

test('a reading that fails ends like any other, so that the buttons that wait for it come back', async () => {
  const draft = draftOf(sampleVersion());
  holdDraft(draft);
  const key = caKey(draft.groups[0].cid);
  const file = { name: 'ca.pem', size: 3 };
  const failedRead = await pickPem(draft, key, file, async () => {
    throw new Error('the file is gone');
  });
  assert.deepEqual(failedRead, { problem: 'read' });
  assert.equal(draft.reading, 0);
  const digest = mock.method(globalThis.crypto.subtle, 'digest', async () => {
    throw new Error('no digest');
  });
  const failedDigest = await pickPem(draft, key, file, async () => new TextEncoder().encode('pem'));
  digest.mock.restore();
  assert.deepEqual(failedDigest, { problem: 'read' });
  assert.equal(draft.reading, 0);
  forgetDraft();
});

test('a version whose lists are not lists of objects is not edited', () => {
  assert.equal(readableVersion(sampleVersion()), true);
  assert.equal(readableVersion({ ...sampleVersion(), sites: ['main'] }), false);
  assert.equal(readableVersion({ ...sampleVersion(), routes: [null] }), false);
  assert.equal(readableVersion(null), false);
});

test('a saving that a read finds ended is taken off the draft, whichever screen read it', () => {
  const job = { kind: 'apply', actor: 'ann', from: FP, to: OTHER, started: 100, state: 'ended', result: 'applied' };
  const sent = { to: OTHER, revision: 0, prior: null };
  const heldWith = () => {
    const draft = draftOf(sampleVersion());
    draft.sent = { ...sent };
    holdDraft(draft);
    return draft;
  };
  assert.equal(settleSaving({ current: OTHER, job: null }, 'ann', null), 'none');
  heldWith();
  assert.equal(settleSaving({ current: OTHER, job }, 'ann', null), 'seen');
  assert.equal(heldDraft(), null);
  heldWith();
  assert.equal(settleSaving({ current: OTHER, job: null }, 'ann', null), 'unseen');
  assert.equal(heldDraft(), null);
  const refused = heldWith();
  assert.equal(settleSaving({ current: FP, job: { ...job, result: 'refused' } }, 'ann', null), 'failed');
  assert.equal(heldDraft(), refused);
  assert.equal(refused.sent, null);
  const running = heldWith();
  assert.equal(settleSaving({ current: FP, job: { ...job, state: 'running' } }, 'ann', null), 'waits');
  assert.notEqual(running.sent, null);
  forgetDraft();
});

test('a read that began before a saving left no longer counts, and leaves the button that reads again free', async () => {
  let finish;
  let followed = 0;
  const screen = {
    alive: true,
    reads: 0,
    loading: false,
    data: null,
    error: null,
    read: () => new Promise((resolve) => (finish = resolve)),
    showRunning() {},
    drawBody() {},
    afterLoad() {},
    follow() {
      followed += 1;
    },
  };
  const load = Screen.prototype.load.call(screen);
  assert.equal(screen.loading, true);
  const draft = draftOf(sampleVersion());
  EditScreen.prototype.noteSending.call(screen, draft, { to: OTHER }, null);
  assert.deepEqual(draft.sent, { to: OTHER, revision: 0, prior: null });
  assert.equal(screen.loading, false);
  finish({ state: { managed: true, current: FP, job: null } });
  await load;
  assert.equal(followed, 0);
  assert.equal(screen.data, null);
  assert.notEqual(draft.sent, null);
});

test('saving and checking are off in each state that holds them, and a saving runs only while it is this user\'s', () => {
  const draft = draftOf(sampleVersion());
  holdDraft(draft);
  const free = { busy: () => false, locked: () => false, data: { state: { current: FP } } };
  const maySave = (screen) => EditScreen.prototype.maySave.call(screen, draft);
  const mayCheck = (screen) => EditScreen.prototype.mayCheck.call(screen, draft);
  assert.equal(maySave(free), false);
  draft.edited();
  assert.equal(maySave(free), true);
  assert.equal(maySave({ ...free, busy: () => true }), false);
  assert.equal(maySave({ ...free, data: { state: { current: OTHER } } }), false);
  assert.equal(mayCheck(free), true);
  assert.equal(mayCheck({ ...free, locked: () => true }), false);
  draft.setChecking(true);
  assert.deepEqual([maySave(free), mayCheck(free)], [false, false]);
  draft.setChecking(false);
  const mark = draft.startReading('k');
  assert.deepEqual([maySave(free), mayCheck(free)], [false, false]);
  draft.endReading('k', mark);
  assert.deepEqual([maySave(free), mayCheck(free)], [true, true]);
  const job = { kind: 'apply', actor: 'ann', from: FP, to: OTHER, started: 5, state: 'running' };
  const runs = (workingName, watching, seen) => savingRuns({ workingName, watching, job: seen, user: 'ann' });
  assert.equal(runs('managed-apply', false, null), true);
  assert.equal(runs(null, true, job), false);
  draft.sent = { to: OTHER, revision: draft.revision, prior: null };
  assert.equal(runs(null, true, job), true);
  assert.equal(runs(null, false, job), false);
  assert.equal(runs(null, true, { ...job, actor: 'bob' }), false);
  assert.equal(runs('managed-activate', false, null), false);
  forgetDraft();
});

test('what is hidden or about the old base is told no more', () => {
  const draft = draftOf(sampleVersion());
  const words = lazy(() => 'wrong');
  draft.putFaults([barFaultOf(words), { screen: 'policy', group: null, cid: 'rate', field: 'keys', words }, { screen: 'policy', group: null, cid: 'access', field: 'deny_cidrs', words }]);
  draft.clearFaultsOf('rate');
  assert.deepEqual(draft.faults.map((one) => one.cid), [null, 'access']);
  draft.rebase(OTHER, sampleVersion());
  assert.deepEqual(draft.faults.map((one) => one.cid), ['access']);
  // A fault of a field takes the place of the one before it.
  draft.putFault({ screen: 'policy', group: null, cid: 'access', field: 'deny_cidrs', words: lazy(() => 'newer') });
  assert.equal(draft.faults.length, 1);
  assert.equal(String(draft.faults[0].words), 'newer');
});

