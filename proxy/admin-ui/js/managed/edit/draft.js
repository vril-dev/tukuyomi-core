// The draft of the managed configuration: what the user has changed on the screens of the upstreams and of the policy,
// and has not saved. There is one, kept here and only in the memory of this page: nothing of it goes to the storage of
// the browser, the address or the history. A draft with no change is dropped when the screens are left, and one with
// changes stays while the user is signed in (`forgetDraft` gives it up with the sign-in). The fields hold the text
// that was typed, and `build` is the one place that makes a version of it: what no form has touched is carried over
// from the version the draft was made from, as it was. The items of the draft have numbers of their own (`cid`) that
// never leave the page. Nothing runs when the module is loaded.

import { w } from '../../i18n.js';
import { emptyField } from '../../parts.js';
import { isJob, sameJob } from '../job.js';

/** A name of a group of upstreams, as the API takes it. */
const NAME = /^[A-Za-z0-9_-]{1,64}$/;
// A number of the kind `u32` is written with at most 9 digits, and any other with at most 15: a number past what the
// API can read is refused about the whole item, so it is told here at its field.
const U32 = /^[0-9]{1,9}$/;
const WIDE = /^[0-9]{1,15}$/;
// The forms of a line of a list; what is in a line that has the form is for the check of the API.
const NETWORK = /^[0-9A-Fa-f:.]+\/[0-9]{1,3}$/;
const COUNTRY = /^([A-Z]{2}|UNKNOWN)$/;

// An edit of a draft with changes that comes this long after the last request keeps the session alive: an edit is use.
const TOUCH_MS = 30_000;

const SERVER_NUMBERS = [
  ['weight', U32, 9],
  ['max_fails', U32, 9],
  ['fail_timeout_ms', WIDE, 15],
];
const RATE_NUMBERS = [
  ['rate', U32, 9],
  ['burst', U32, 9],
  ['keys', WIDE, 15],
];
const networkLine = (line) => w('edit.fault.network', { line });
const countryLine = (line) => w('edit.fault.country', { line });
const ACCESS_LISTS = [
  ['deny_cidrs', NETWORK, networkLine],
  ['allow_cidrs', NETWORK, networkLine],
  ['deny_countries', COUNTRY, countryLine],
  ['allow_countries', COUNTRY, countryLine],
];

const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

let serial = 0;

function nextCid() {
  serial += 1;
  return serial;
}

function serverOf(raw) {
  return {
    cid: nextCid(),
    address: String(raw.address ?? ''),
    weight: String(raw.weight ?? ''),
    max_fails: String(raw.max_fails ?? ''),
    fail_timeout_ms: String(raw.fail_timeout_ms ?? ''),
    backup: raw.backup === true,
    raw,
  };
}

/** A new server: the values of a server of nginx that says nothing else. */
function newServer() {
  return { cid: nextCid(), address: '', weight: '1', max_fails: '1', fail_timeout_ms: '10000', backup: false, raw: {} };
}

/** What a group holds as text, to tell whether it has changed since the draft was made. */
function snapshot(group) {
  const servers = group.servers.map((server) => [server.address, server.weight, server.max_fails, server.fail_timeout_ms, server.backup]);
  return JSON.stringify([group.name, group.tls, group.ca, group.server_name, servers]);
}

function groupOf(name, raw) {
  const tls = Object.hasOwn(raw, 'tls') ? raw.tls : {};
  const group = {
    cid: nextCid(),
    fresh: false,
    name,
    servers: raw.servers.map(serverOf),
    tls: Object.hasOwn(raw, 'tls'),
    ca: typeof tls.ca === 'string' ? tls.ca : '',
    server_name: typeof tls.server_name === 'string' ? tls.server_name : '',
    raw,
  };
  group.origin = snapshot(group);
  return group;
}

function newGroup() {
  return { cid: nextCid(), fresh: true, name: '', servers: [newServer()], tls: false, ca: '', server_name: '', raw: {} };
}

const linesText = (list) => (Array.isArray(list) ? list.join('\n') : '');

function accessOf(raw) {
  return {
    cid: 'access',
    on: raw !== undefined,
    deny_cidrs: linesText(raw?.deny_cidrs),
    allow_cidrs: linesText(raw?.allow_cidrs),
    deny_countries: linesText(raw?.deny_countries),
    allow_countries: linesText(raw?.allow_countries),
    raw: raw ?? {},
  };
}

function rateOf(raw) {
  return {
    cid: 'rate',
    on: raw !== undefined,
    rate: String(raw?.rate ?? ''),
    burst: String(raw?.burst ?? ''),
    keys: String(raw?.keys ?? ''),
    exempt_cidrs: linesText(raw?.exempt_cidrs),
    raw: raw ?? {},
  };
}

/**
 * Whether `version` has the form that a draft is made from: the API has checked its content, and a version that is not
 * in this form is not edited.
 */
export function readableVersion(version) {
  const group = (raw) => plain(raw) && Array.isArray(raw.servers) && raw.servers.every(plain) && (!Object.hasOwn(raw, 'tls') || plain(raw.tls));
  const optional = (key) => !Object.hasOwn(version, key) || plain(version[key]);
  return (
    plain(version) &&
    plain(version.upstreams) &&
    Object.values(version.upstreams).every(group) &&
    Array.isArray(version.sites) &&
    version.sites.every(plain) &&
    Array.isArray(version.routes) &&
    version.routes.every(plain) &&
    typeof version.default_upstream === 'string' &&
    optional('access') &&
    optional('rate_limit')
  );
}

/** The lines of a list as it was typed, without what is blank, each with its number in the box (from 1). */
function linesOf(text) {
  return text
    .split('\n')
    .map((line, at) => ({ text: line.trim(), line: at + 1 }))
    .filter((entry) => entry.text !== '');
}

/** The number that `text` holds, or 0 with the fault told to `report`. */
function numberOf(text, pattern, digits, report) {
  const value = text.trim();
  if (value === '') {
    report(emptyField());
    return 0;
  }
  if (!pattern.test(value)) {
    report(w('edit.fault.number', { digits }));
    return 0;
  }
  return Number(value);
}

/** A fault of a field: the screen, the group whose panel holds it (null: none), the item and the field it is about, and its words. */
const fault = (screen, group, cid, field, words) => ({ screen, group, cid, field, words });

// ---- the draft ----

export class Draft {
  #session;
  #touched;

  /**
   * `base` is the version that a saving expects to be selected and `baseVersion` its content, which is only compared
   * with; `source` is the content that is carried over (of another version, for a draft made from a version:
   * `fromVersion`). `session` asks the admin process for something, which keeps the session alive.
   */
  constructor({ base, baseVersion, source, fromVersion = false, session = null }) {
    this.base = base;
    this.baseVersion = baseVersion;
    this.source = source;
    this.fromVersion = fromVersion;
    this.#session = session;
    this.#touched = Date.now();
    /** Grows with every change of the draft: an answer about an older revision is not shown. */
    this.revision = 0;
    /** The change on its way, `{ to, revision, prior }`, until a read of the state tells how it ended. */
    this.sent = null;
    /** What is wrong and shown, each with the place it is shown at (see `locate.js`). */
    this.faults = [];
    /** What the band says of the last check, `{ tone, words }`. */
    this.said = [];
    /** The group whose panel is open. */
    this.openGroup = null;
    this.checking = false;
    /** How many files are being read, and the reading of each field that still counts. */
    this.reading = 0;
    this.readings = new Map();
    /** The files that were chosen: SHA-256 to `{ text, name, size }`. */
    this.files = new Map();
    this.groups = Object.entries(source.upstreams).map(([name, raw]) => groupOf(name, raw));
    const cids = new Map(this.groups.map((group) => [group.name, group.cid]));
    const refOf = (name) => (cids.has(name) ? { cid: cids.get(name) } : { text: name });
    this.defaultRef = refOf(source.default_upstream);
    this.routes = source.routes.map((raw) => ({ raw, ref: refOf(raw.upstream) }));
    this.access = accessOf(source.access);
    this.rate = rateOf(source.rate_limit);
  }

  /** Whether the draft holds something that a saving would keep: an edit, or the version that it was made from. */
  get changed() {
    return this.revision > 0 || this.fromVersion;
  }

  /** The user changed something in the draft. */
  edited() {
    this.revision += 1;
    if (this.said.length > 0) this.said = [];
    this.#touch();
    guard();
    tell();
  }

  /** An edit is use of the session, so it keeps the session alive: at most one request in `TOUCH_MS`. The answer is not looked at. */
  #touch() {
    if (this.#session === null) return;
    const now = Date.now();
    if (now - this.#touched < TOUCH_MS) return;
    this.#touched = now;
    this.#session().catch(() => {});
  }

  /** The user wrote `value` to the field `key` of `item`, and what was wrong with the field is told no more. */
  write(item, key, value) {
    item[key] = value;
    this.clearFault(item.cid, key);
    this.clearFault(item.cid, 'notice');
    this.edited();
  }

  clearFault(cid, field) {
    const kept = this.faults.filter((one) => one.cid !== cid || one.field !== field);
    if (kept.length === this.faults.length) return;
    this.faults = kept;
    tell();
  }

  /** What is wrong with the item `cid` is told no more: a part that was turned off has no field to tell it at. */
  clearFaultsOf(cid) {
    const kept = this.faults.filter((one) => one.cid !== cid);
    if (kept.length === this.faults.length) return;
    this.faults = kept;
    tell();
  }

  /** Tells `one` in the place of what was told at its field. */
  putFault(one) {
    this.putFaults([...this.faults.filter((other) => other.cid !== one.cid || other.field !== one.field), one]);
  }

  /** Puts `faults` in the place of those that are shown. */
  putFaults(faults) {
    this.faults = faults;
    tell();
  }

  /** Puts what the band says of the last check in the place of what it said. */
  putSaid(lines) {
    this.said = lines;
    tell();
  }

  setChecking(on) {
    this.checking = on;
    tell();
  }

  /** The first fault of the screen `screen`, whose panel is the one to open, or null. */
  firstFault(screen) {
    const first = this.faults.find((one) => one.screen === screen) ?? null;
    if (first !== null && first.group !== null) this.openGroup = first.group;
    return first;
  }

  /** The version that is selected now becomes the base of this draft; what the draft holds stays as it is, and what the band said of the old base goes. */
  rebase(base, baseVersion) {
    this.base = base;
    this.baseVersion = baseVersion;
    this.said = [];
    this.faults = this.faults.filter((one) => one.screen !== null);
    tell();
  }

  // ---- the groups of upstreams ----

  group(cid) {
    return this.groups.find((one) => one.cid === cid) ?? null;
  }

  /** How many routes use the group `cid`, and whether it is the default one. */
  uses(cid) {
    return { routes: this.routes.filter((route) => route.ref.cid === cid).length, isDefault: this.defaultRef.cid === cid };
  }

  /** Whether the group `cid` may go: not the last one, and no route or default that would be left pointing at no group. */
  mayRemove(cid) {
    const { routes, isDefault } = this.uses(cid);
    return this.groups.length > 1 && routes === 0 && !isDefault;
  }

  /** Whether a group of the draft differs from what it was when the draft was made; a new group is told as new. */
  groupChanged(group) {
    return !group.fresh && snapshot(group) !== group.origin;
  }

  addGroup() {
    const group = newGroup();
    this.groups.push(group);
    this.openGroup = group.cid;
    this.clearFault('groups', 'notice');
    this.edited();
    return group;
  }

  /** Takes the group `cid` away, with what is told of it and the file it is reading. False when it may not go. */
  removeGroup(cid) {
    if (!this.mayRemove(cid)) return false;
    this.groups = this.groups.filter((one) => one.cid !== cid);
    this.readings.delete(caKey(cid));
    if (this.openGroup === cid) this.openGroup = null;
    this.putFaults(this.faults.filter((one) => one.group !== cid));
    this.clearFault('groups', 'notice');
    this.edited();
    return true;
  }

  addServer(group) {
    const server = newServer();
    group.servers.push(server);
    this.clearFault(group.cid, 'servers');
    this.edited();
    return server;
  }

  removeServer(group, cid) {
    group.servers = group.servers.filter((one) => one.cid !== cid);
    this.putFaults(this.faults.filter((one) => one.cid !== cid));
    this.clearFault(group.cid, 'servers');
    this.edited();
  }

  /** The default group is the group whose `cid` is `value` (the value of the choice of the form), or none. */
  setDefault(value) {
    const group = this.groups.find((one) => String(one.cid) === String(value));
    this.defaultRef = group === undefined ? { text: '' } : { cid: group.cid };
    this.clearFault('default', 'default');
    this.edited();
  }

  // ---- the files ----

  /** Starts a reading for the field `key`: a reading of it that runs on no longer counts. Gives the mark of this one. */
  startReading(key) {
    const mark = {};
    this.readings.set(key, mark);
    this.reading += 1;
    tell();
    return mark;
  }

  /** A reading has ended. True when what it found still counts: the field was not chosen again or taken away, and this is the draft of the page. */
  endReading(key, mark) {
    this.reading -= 1;
    const counts = this.readings.get(key) === mark && held === this;
    if (this.readings.get(key) === mark) this.readings.delete(key);
    tell();
    return counts;
  }

  /** The file `pem` is the authority of `group`; a file of the same content is held once. */
  useCa(group, pem) {
    this.files.set(pem.sha256, { text: pem.text, name: pem.name, size: pem.size });
    this.write(group, 'ca', pem.sha256);
  }

  // ---- a version from the draft ----

  #nameOf(ref) {
    return ref.cid === undefined ? ref.text : this.group(ref.cid).name.trim();
  }

  #builtServer(group, server, faults) {
    const report = (key) => (words) => faults.push(fault('upstreams', group.cid, server.cid, key, words));
    const built = { ...server.raw, address: server.address.trim(), backup: server.backup };
    if (built.address === '') report('address')(emptyField());
    for (const [key, pattern, digits] of SERVER_NUMBERS) built[key] = numberOf(server[key], pattern, digits, report(key));
    return built;
  }

  /** The `tls` of a group, or undefined when the group does not use TLS. */
  #builtTls(group, faults) {
    if (!group.tls) return undefined;
    if (group.ca === '') faults.push(fault('upstreams', group.cid, group.cid, 'ca', w('edit.fault.ca')));
    const built = { ...group.raw.tls, ca: group.ca };
    const name = group.server_name.trim();
    if (name === '') delete built.server_name;
    else built.server_name = name;
    return built;
  }

  /** The values of the list under `key`, with a fault at the first line that is not in the form of its list. */
  #builtList(item, key, pattern, problem, faults) {
    const lines = linesOf(item[key]);
    const wrong = lines.find((entry) => !pattern.test(entry.text));
    if (wrong !== undefined) faults.push(fault('policy', null, item.cid, key, problem(wrong.line)));
    return lines.map((entry) => entry.text);
  }

  /** The object of `item` with its list under `key`: a key that was written stays when the list is empty, and one that was not is written for lines only. */
  #withList(built, item, key, values) {
    if (values.length > 0 || Object.hasOwn(item.raw, key)) built[key] = values;
  }

  #builtAccess(faults) {
    const { access } = this;
    if (!access.on) return undefined;
    const built = { ...access.raw };
    for (const [key, pattern, problem] of ACCESS_LISTS) this.#withList(built, access, key, this.#builtList(access, key, pattern, problem, faults));
    return built;
  }

  #builtRate(faults) {
    const { rate } = this;
    if (!rate.on) return undefined;
    const built = { ...rate.raw };
    for (const [key, pattern, digits] of RATE_NUMBERS) {
      built[key] = numberOf(rate[key], pattern, digits, (words) => faults.push(fault('policy', null, rate.cid, key, words)));
    }
    this.#withList(built, rate, 'exempt_cidrs', this.#builtList(rate, 'exempt_cidrs', NETWORK, networkLine, faults));
    return built;
  }

  /**
   * The draft as what a request carries: `{ version, files, map }`, or `{ faults }` when a field is not in its form. `map`
   * says what the numbers and the names of the request stand for: `groups` a `Map` from a name to `{ cid, servers }`
   * (the numbers of its servers by their place), and `files` the place of the field that chose each file of `files`. It
   * is a copy of that moment: an answer speaks of the request as it was sent.
   */
  build() {
    const faults = [];
    const pairs = [];
    const seen = new Set();
    const named = new Set();
    const files = [];
    const map = { groups: new Map(), files: [] };
    for (const group of this.groups) {
      const name = group.name.trim();
      const nameFault = (words) => faults.push(fault('upstreams', group.cid, group.cid, 'name', words));
      if (name === '') nameFault(emptyField());
      else if (!NAME.test(name)) nameFault(w('edit.fault.group_name'));
      else if (seen.has(name)) nameFault(w('edit.fault.group_twice'));
      seen.add(name);
      const built = { ...group.raw, servers: group.servers.map((server) => this.#builtServer(group, server, faults)) };
      const tls = this.#builtTls(group, faults);
      if (tls === undefined) {
        delete built.tls;
      } else {
        built.tls = tls;
        if (this.files.has(tls.ca) && !named.has(tls.ca)) {
          named.add(tls.ca);
          files.push(this.files.get(tls.ca).text);
          map.files.push({ screen: 'upstreams', group: group.cid, cid: group.cid, field: 'ca' });
        }
      }
      pairs.push([name, built]);
      map.groups.set(name, { cid: group.cid, servers: group.servers.map((server) => server.cid) });
    }
    const access = this.#builtAccess(faults);
    const rate = this.#builtRate(faults);
    if (faults.length > 0) return { faults };
    const version = {
      ...this.source,
      upstreams: Object.fromEntries(pairs),
      routes: this.routes.map((route) => ({ ...route.raw, upstream: this.#nameOf(route.ref) })),
      default_upstream: this.#nameOf(this.defaultRef),
    };
    delete version.access;
    delete version.rate_limit;
    if (access !== undefined) version.access = access;
    if (rate !== undefined) version.rate_limit = rate;
    return { version, files, map };
  }
}

/** The key of the reading of the file of the authority of the group `cid`. */
export function caKey(cid) {
  return `ca:${cid}`;
}

// ---- the one draft of the page ----

let held = null;
const watchers = new Set();

function tell() {
  for (const watcher of [...watchers]) watcher();
}

function onLeave(event) {
  event.preventDefault();
  event.returnValue = '';
}

let guarding = false;

/** The browser asks before the page goes away, while the draft holds what is not saved. */
function guard() {
  const on = held !== null && held.changed;
  if (on === guarding) return;
  guarding = on;
  if (on) globalThis.addEventListener('beforeunload', onLeave);
  else globalThis.removeEventListener('beforeunload', onLeave);
}

/** The draft of the page, or null. */
export function heldDraft() {
  return held;
}

export function holdDraft(draft) {
  held = draft;
  guard();
  tell();
}

/** Gives the draft up; true when it held what was not saved. */
export function forgetDraft() {
  const unsaved = held !== null && held.changed;
  held = null;
  guard();
  tell();
  return unsaved;
}

/** Calls `watcher` whenever the draft changes in a way that the screens show; gives back a function that stops that. */
export function watchDraft(watcher) {
  watchers.add(watcher);
  return () => watchers.delete(watcher);
}

/**
 * Brings the draft in step with the version `current` that the store selects, whose content is `version`: makes the
 * draft when there is none, and again for a draft with no change whose base is no longer selected. A draft that is
 * still on `current` is left as it is. Gives `moved` for a draft with changes whose base is no longer selected, the
 * user's to decide; else `made` or `same`.
 */
export function syncDraft(current, version, session) {
  if (held !== null && held.base === current) return 'same';
  if (held !== null && held.changed) return 'moved';
  holdDraft(new Draft({ base: current, baseVersion: version, source: version, session }));
  return 'made';
}

/** Makes the draft of the page from the version with the content `source`, on top of the selected version `base`; it holds changes from the start. */
export function draftFromVersion(base, baseVersion, source, session) {
  holdDraft(new Draft({ base, baseVersion, source, fromVersion: true, session }));
}

/** Whether `job` is the job of the saving `sent` of `user`, and not one that was known before it was sent. */
export function isOwnJob(job, sent, user) {
  return isJob(job) && job.kind === 'apply' && job.actor === user && job.to === sent.to && (sent.prior === null || !sameJob(job, sent.prior));
}

/**
 * Matches the saving of the draft with what a read found (`state`, the answer of `GET /api/managed`): gives the draft up
 * when the saving took effect, and ends the saving when it did not. Gives `none` (no saving was sent), `waits`, `failed`,
 * `seen` (it took effect, and its job is there to tell it) or `unseen` (it took effect, and the screen is to say so).
 */
export function settleSaving(state, user, workingName) {
  if (held === null || held.sent === null) return 'none';
  const { sent } = held;
  const verdict = settleSent({ sent, revision: held.revision, current: state.current, job: state.job, user, workingName });
  if (verdict === 'waits') return 'waits';
  if (verdict === 'took') {
    const seen = isOwnJob(state.job, sent, user);
    forgetDraft();
    return seen ? 'seen' : 'unseen';
  }
  held.sent = null;
  tell();
  return 'failed';
}

/** Whether this user's saving of the draft runs: its request has no answer yet, or its job runs and the screen watches it. */
export function savingRuns({ workingName, watching, job, user }) {
  if (workingName === 'managed-apply') return true;
  return watching && held !== null && held.sent !== null && isOwnJob(job, held.sent, user);
}

/**
 * What a read of the state says of the saving `sent`, with the state as `{ current, job }`: `waits` (its request has
 * no answer yet, or its job runs), `took` (the version that it sent is selected and the draft has not changed since) or
 * `failed` (anything else: the draft stays, and it may be sent again).
 */
export function settleSent({ sent, revision, current, job, user, workingName }) {
  if (workingName === 'managed-apply' || (isOwnJob(job, sent, user) && job.state === 'running')) return 'waits';
  return current === sent.to && revision === sent.revision ? 'took' : 'failed';
}
