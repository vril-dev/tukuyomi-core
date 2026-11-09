// The draft of the managed configuration: what the user has changed on the screens that edit it, and has not saved.
// There is one, kept here and only in the memory of this page: nothing of it goes to the storage of the browser, the
// address or the history. A draft with no change is dropped when the screens are left, and one with changes stays while
// the user is signed in (`forgetDraft` gives it up with the sign-in). The fields hold the text that was typed, and
// `build` is the one place that makes a version of it: what no form has touched is carried over from the version the
// draft was made from, as it was. Nothing runs when the module is loaded.

import { w } from '../../i18n.js';
import { emptyField } from '../../parts.js';
import { isJob, sameJob } from '../job.js';
import { NAME, accessOf, builtAccess, builtRate, builtServer, builtSite, builtTls, fault, groupOf, linesOf, newGroup, newServer, newSite, plain, rateOf, readableSite, siteOf, siteText, snapshot } from './items.js';
import { builtRoute, makeForm, newRoute, readableRoute, routeChanged, routeLine, routeOf } from './route-items.js';

// An edit of a draft with changes that comes this long after the last request keeps the session alive: an edit is use.
const TOUCH_MS = 30_000;

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
    version.sites.every(readableSite) &&
    Array.isArray(version.routes) &&
    version.routes.every(readableRoute) &&
    typeof version.default_upstream === 'string' &&
    optional('access') &&
    optional('rate_limit')
  );
}

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
    /** The item whose panel is open, by the screens that have panels. */
    this.openPanels = { upstreams: null, sites: null, routes: null };
    this.checking = false;
    /** How many files are being read, and the reading of each field that still counts. */
    this.reading = 0;
    this.readings = new Map();
    /** The files that were chosen: SHA-256 to `{ text, name, size }`. */
    this.files = new Map();
    /** Grows with every change that the list of the routes shows, so that the list need not look at every route to know. */
    this.routeList = 0;
    this.groups = Object.entries(source.upstreams).map(([name, raw]) => groupOf(name, raw));
    const cids = new Map(this.groups.map((group) => [group.name, group.cid]));
    const refOf = (name) => (cids.has(name) ? { cid: cids.get(name) } : { text: name });
    this.defaultRef = refOf(source.default_upstream);
    this.routes = source.routes.map((raw) => routeOf(raw, refOf(raw.upstream)));
    this.sites = source.sites.map(siteOf);
    this.access = accessOf(source.access, 'access');
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
    this.#prune();
    this.#touch();
    guard();
    tell();
  }

  /** Lets go of the files that no field names any more: a private key stays no longer than something uses it. The file of the authorities of a group that has TLS turned off is still named, and comes back with TLS. */
  #prune() {
    const named = new Set();
    for (const group of this.groups) named.add(group.ca);
    for (const site of this.sites) {
      if (site.kind !== 'file') continue;
      named.add(site.chain);
      named.add(site.key);
    }
    for (const sha256 of this.files.keys()) {
      if (!named.has(sha256)) this.files.delete(sha256);
    }
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
    if (first !== null && first.panel !== null) this.openPanels[screen] = first.panel;
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
    this.openPanels.upstreams = group.cid;
    this.clearFault('groups', 'notice');
    this.edited();
    return group;
  }

  /** Takes the group `cid` away, with what is told of it and the file it is reading. False when it may not go. */
  removeGroup(cid) {
    if (!this.mayRemove(cid)) return false;
    this.groups = this.groups.filter((one) => one.cid !== cid);
    this.readings.delete(caKey(cid));
    if (this.openPanels.upstreams === cid) this.openPanels.upstreams = null;
    this.putFaults(this.faults.filter((one) => one.panel !== cid));
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

  // ---- the sites ----

  site(cid) {
    return this.sites.find((one) => one.cid === cid) ?? null;
  }

  /** Whether a site differs from what it was when the draft was made; a new site is told as new. */
  siteChanged(site) {
    return !site.fresh && siteText(site) !== site.origin;
  }

  addSite() {
    const site = newSite();
    this.sites.push(site);
    this.openPanels.sites = site.cid;
    this.clearFault('sites', 'notice');
    this.edited();
    return site;
  }

  /** Takes the site `cid` away, with what is told of it and the files it is reading. Nothing refers to a site, so any may go. */
  removeSite(cid) {
    this.sites = this.sites.filter((one) => one.cid !== cid);
    this.readings.delete(siteFileKey(cid, 'chain'));
    this.readings.delete(siteFileKey(cid, 'key'));
    if (this.openPanels.sites === cid) this.openPanels.sites = null;
    this.putFaults(this.faults.filter((one) => one.panel !== cid));
    this.clearFault('sites', 'notice');
    this.edited();
  }

  /**
   * The certificate of `site` is of the kind `kind` (`file` or `acme`). To `acme`, the chain and the key are dropped with
   * what is being read for them, so that the key of a site that no longer uses it does not stay in the draft; back to
   * `file`, the site names the files of the version it was read from, if it had any.
   */
  setSiteKind(site, kind) {
    if (site.kind === kind) return;
    site.kind = kind;
    this.readings.delete(siteFileKey(site.cid, 'chain'));
    this.readings.delete(siteFileKey(site.cid, 'key'));
    const was = kind === 'file' && Object.hasOwn(site.raw.certificate ?? {}, 'chain') ? site.raw.certificate : null;
    site.chain = was === null ? '' : was.chain;
    site.key = was === null ? '' : was.key;
    for (const field of ['chain', 'key', 'renew_before_days', 'certificate', 'notice']) this.clearFault(site.cid, field);
    this.edited();
  }

  // ---- the routes ----

  route(cid) {
    return this.routes.find((one) => one.cid === cid) ?? null;
  }

  addRoute() {
    const route = newRoute();
    this.routes.push(route);
    this.openPanels.routes = route.cid;
    this.routeList += 1;
    this.clearFault('routes', 'notice');
    this.edited();
    return route;
  }

  /** Takes the route `cid` away, with what is told of it. Nothing refers to a route, so any may go. */
  removeRoute(cid) {
    this.routes = this.routes.filter((one) => one.cid !== cid);
    if (this.openPanels.routes === cid) this.openPanels.routes = null;
    this.routeList += 1;
    this.putFaults(this.faults.filter((one) => one.panel !== cid));
    this.clearFault('routes', 'notice');
    this.edited();
  }

  /** The user wrote to a field `key` of `item`, the form of `route` or one of its parts. The list of the routes is told only when a line of it would change. */
  writeRoute(route, item, key, value) {
    const before = routeLine(route);
    item[key] = value;
    if (routeLine(route) !== before) this.routeList += 1;
    this.write(item, key, value);
  }

  /** The group of `route` is the group whose `cid` is `value` (the value of the choice of the form), or none. */
  setRouteUpstream(route, value) {
    const group = this.groups.find((one) => String(one.cid) === String(value));
    route.ref = group === undefined ? { text: '' } : { cid: group.cid };
    this.routeList += 1;
    this.clearFault(route.cid, 'upstream');
    this.clearFault(route.cid, 'notice');
    this.edited();
  }

  /** The form of `route`, made the first time its panel is opened. Making it is no edit: nothing is told of it, and the draft does not change. */
  routeForm(route) {
    if (route.form === null) makeForm(route);
    return route.form;
  }

  /** Whether a route differs from what it was when its form was made. */
  routeChanged(route) {
    return routeChanged(route);
  }

  /** Whether a file of a certificate chain was chosen in this draft, for a confirmation to say what a check does not look at. */
  choseChain() {
    return this.sites.some((site) => site.kind === 'file' && this.files.has(site.chain));
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

  /** The file `pem` is what the field `field` of `item` names (the authority of a group, the chain or the key of a site); a file of the same content is held once. */
  useFile(item, field, pem) {
    this.files.set(pem.sha256, { text: pem.text, name: pem.name, size: pem.size });
    this.write(item, field, pem.sha256);
  }

  // ---- a version from the draft ----

  /** The name of the group that `ref` stands for, as it is written now; a name that no group has stays as it was read. */
  nameOf(ref) {
    return ref.cid === undefined ? ref.text : this.group(ref.cid).name.trim();
  }

  /**
   * The draft as what a request carries: `{ version, files, map }`, or `{ faults }` when a field is not in its form. `map`
   * says what the numbers and the names of the request stand for: `groups` a `Map` from a name to `{ cid, servers }`
   * (the numbers of its servers by their place), `files` the place of the field that chose each file of `files`, `sites`
   * `{ cid, hostLines }` by their place (the line of the box of each host), and `routes` the number of each route. It is
   * a copy of that moment: an answer speaks of the request as it was sent.
   */
  build() {
    const faults = [];
    const pairs = [];
    const seen = new Set();
    const named = new Set();
    const files = [];
    const map = { groups: new Map(), files: [] };
    // A file goes once, with the place of the first field that names it, and only when the draft holds it.
    const nameFile = (sha256, place) => {
      if (!this.files.has(sha256) || named.has(sha256)) return;
      named.add(sha256);
      files.push(this.files.get(sha256).text);
      map.files.push(place);
    };
    for (const group of this.groups) {
      const name = group.name.trim();
      const nameFault = (words) => faults.push(fault('upstreams', group.cid, group.cid, 'name', words));
      if (name === '') nameFault(emptyField());
      else if (!NAME.test(name)) nameFault(w('edit.fault.group_name'));
      else if (seen.has(name)) nameFault(w('edit.fault.group_twice'));
      seen.add(name);
      const built = { ...group.raw, servers: group.servers.map((server) => builtServer(group, server, faults)) };
      const tls = builtTls(group, faults);
      if (tls === undefined) {
        delete built.tls;
      } else {
        built.tls = tls;
        nameFile(tls.ca, { screen: 'upstreams', panel: group.cid, cid: group.cid, field: 'ca' });
      }
      pairs.push([name, built]);
      map.groups.set(name, { cid: group.cid, servers: group.servers.map((server) => server.cid) });
    }
    const sites = this.sites.map((site) => builtSite(site, faults));
    for (const site of this.sites) {
      if (site.kind !== 'file') continue;
      nameFile(site.chain, { screen: 'sites', panel: site.cid, cid: site.cid, field: 'chain' });
      nameFile(site.key, { screen: 'sites', panel: site.cid, cid: site.cid, field: 'key' });
    }
    const routes = this.routes.map((route) => builtRoute(route, this.nameOf(route.ref), faults));
    const access = builtAccess(this.access, 'policy', null, faults);
    const rate = builtRate(this.rate, faults);
    if (faults.length > 0) return { faults };
    const version = {
      ...this.source,
      sites,
      upstreams: Object.fromEntries(pairs),
      routes,
      default_upstream: this.nameOf(this.defaultRef),
    };
    delete version.access;
    delete version.rate_limit;
    if (access !== undefined) version.access = access;
    if (rate !== undefined) version.rate_limit = rate;
    map.sites = this.sites.map((site) => ({ cid: site.cid, hostLines: linesOf(site.hosts).map((entry) => entry.line) }));
    map.routes = this.routes.map((route) => route.cid);
    return { version, files, map };
  }
}

/** The key of the reading of the file of the authority of the group `cid`. */
export function caKey(cid) {
  return `ca:${cid}`;
}

/** The key of the reading of the chain or the key (`field`) of the site `cid`. */
export function siteFileKey(cid, field) {
  return `${field}:${cid}`;
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
