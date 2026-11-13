// The base of the screens of the managed configuration: the layers, the reads that count, the change that runs, the
// job that it starts, and the confirmation that asks first. A change is answered when its job starts, so the screen
// watches the job (see `job.js`) until it ends. What the state of a screen says of the proxy is here too, and what the
// managed store holds of the certificates of the sites of a version. Nothing runs when the module is loaded.

import { ApiError } from '../api.js';
import { badge, button, el, mount, notice, result } from '../dom.js';
import { t, w } from '../i18n.js';
import { canChange, confirmChange, diffView, fingerprintView, hashOf, isFingerprint, kv, pageHead, panel, perform, restoreFocus, row, runningNotice, setBusy, shortOf, timeCell, working } from '../parts.js';
import { Watch, isJob, jobPanel, watchLimit } from './job.js';

/**
 * What `GET /api/managed` says of the proxy: `unreachable`; `silent` (it can be reached but had no place to answer
 * about its state); `unmanaged` (it answered and serves no version: its configuration has no `managed`); `reloading`;
 * or `ok`.
 */
export function proxyOf(state) {
  if (state.reachable !== true) return 'unreachable';
  if (typeof state.reloading !== 'boolean') return 'silent';
  if (!isFingerprint(state.serving)) return 'unmanaged';
  return state.reloading ? 'reloading' : 'ok';
}

/** The version that `GET /api/managed` says the proxy serves, in words when it cannot say. */
export function servingView(state) {
  const proxy = proxyOf(state);
  if (proxy === 'ok' || proxy === 'reloading') return fingerprintView(state.serving);
  return proxy === 'unmanaged' ? w('managed.proxy.unmanaged_short') : w('managed.unknown');
}

/** The numbers of a version that a confirmation and the detail of a version show; none of its text but the name of the default group. */
export function countsOf(version) {
  const object = version !== null && typeof version === 'object' ? version : {};
  const length = (value) => (Array.isArray(value) ? value.length : null);
  const groups = object.upstreams !== null && typeof object.upstreams === 'object' && !Array.isArray(object.upstreams) ? Object.keys(object.upstreams).length : null;
  const has = (value) => value !== undefined && value !== null;
  return {
    sites: length(object.sites),
    upstreams: groups,
    routes: length(object.routes),
    defaultUpstream: typeof object.default_upstream === 'string' ? object.default_upstream : null,
    access: has(object.access),
    rateLimit: has(object.rate_limit),
  };
}

/** How a confirmation and the content of a version tell the default group `name`: null is what could not be read, and the empty name is no group. */
export function defaultGroupView(name) {
  if (name === null) return '—';
  return name === '' ? w('managed.diff.unset') : name;
}

/**
 * The lines of a confirmation for the versions `from` and `to` with their numbers (`null`: that version could not be
 * read). `gone`: the version `from` is removed, so every line after it says that it is gone, and `to` and `after` are
 * not read.
 */
export function diffRows(from, to, before, after, { gone = false } = {}) {
  const number = (counts, key) => (counts === null || counts[key] === null ? '—' : String(counts[key]));
  const present = (counts, key) => {
    if (counts === null) return '—';
    return counts[key] ? w('managed.diff.set') : w('managed.diff.unset');
  };
  const short = (value) => el('span', { class: 'tc-mono' }, `${shortOf(value)}…`);
  const counted = (label, key, value) => ({
    label,
    now: value(before, key),
    after: gone ? w('managed.confirm.gone') : value(after, key),
    changed: gone || (before === null || after === null ? false : before[key] !== after[key]),
  });
  return [
    { label: w('managed.col.version'), now: short(from), after: gone ? w('managed.confirm.gone') : short(to), changed: gone || from !== to },
    counted(w('managed.diff.sites'), 'sites', number),
    counted(w('managed.diff.upstreams'), 'upstreams', number),
    counted(w('managed.diff.routes'), 'routes', number),
    counted(w('managed.diff.default'), 'defaultUpstream', (counts, key) => (counts === null ? '—' : defaultGroupView(counts[key]))),
    counted(w('managed.diff.access'), 'access', present),
    counted(w('managed.diff.rate_limit'), 'rateLimit', present),
  ];
}

/** The notice for a configuration with no managed object, with the way to the configuration file for those who may see it. */
export function unusedNotice(role) {
  return notice('info', w('managed.unused'), canChange(role) ? [' ', el('a', { class: 'tc-link', href: hashOf('config') }, w('managed.unused_link'))] : null);
}

/**
 * The states of a certificate in the managed store, by the word that `GET /api/managed/certificates/<name>` gives:
 * the tone of the badge, its words and the same words as text.
 */
const CERTIFICATE_STATES = {
  present: { tone: 'ok', words: () => w('managed.cert.present'), text: () => t('managed.cert.present') },
  missing: { tone: 'bad', words: () => w('managed.cert.missing'), text: () => t('managed.cert.missing') },
  issued: { tone: 'ok', words: () => w('managed.cert.issued'), text: () => t('managed.cert.issued') },
  waiting: { tone: 'warn', words: () => w('managed.cert.waiting'), text: () => t('managed.cert.waiting') },
  unreadable: { tone: 'bad', words: () => w('managed.cert.unreadable'), text: () => t('managed.cert.unreadable') },
  unparsed: { tone: 'warn', words: () => w('managed.cert.unparsed'), text: () => t('managed.cert.unparsed') },
};

/** The badge of the state `state` of a certificate; a word that this page does not know is shown as it came. */
export function certificateBadge(state) {
  if (!Object.hasOwn(CERTIFICATE_STATES, state)) return badge('muted', String(state));
  return badge(CERTIFICATE_STATES[state].tone, CERTIFICATE_STATES[state].words());
}

/** The words of `certificateBadge` as text. */
export function certificateText(state) {
  return Object.hasOwn(CERTIFICATE_STATES, state) ? CERTIFICATE_STATES[state].text() : String(state);
}

/** When the certificate of the site `site` of an answer expires, in seconds, and whether the admin process says that is past; null and false when it gave no time. */
export function certificateExpiry(site) {
  const notAfter = typeof site.not_after === 'number' && Number.isFinite(site.not_after) ? site.not_after : null;
  return { notAfter, expired: notAfter !== null && site.expired === true };
}

/** A cell of a table for the expiry `{ notAfter, expired }` (see `certificateExpiry`), with the badge `more` after it; a dash when there is nothing to show. */
export function expiryCell({ notAfter, expired }, more = null) {
  const parts = [notAfter === null ? null : timeCell(notAfter, 's'), expired ? badge('bad', w('managed.cert.expired')) : null, more].filter((part) => part !== null);
  return parts.length === 0 ? '—' : el('span', { class: 'tc-badges' }, parts);
}

export class Screen {
  constructor(ctx, root, title, intro) {
    this.ctx = ctx;
    this.root = root;
    this.alive = true;
    /** This screen has sent the change that runs, and tells its end itself. */
    this.mine = false;
    this.reads = 0;
    this.loading = false;
    this.data = null;
    this.error = null;
    /** The job that the screen shows, as it was read last, and its text, so that it is drawn only when it changes. */
    this.job = null;
    this.jobText = '';
    this.otherTold = false;
    this.asking = false;
    this.watch = new Watch(
      () => ctx.api.call('GET', '/api/managed/job'),
      (event) => this.onWatch(event),
    );
    this.reloadButton = button('', w('screen.reload'), () => this.load());
    this.running = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    this.results = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    this.jobBox = el('div');
    this.body = el('div', { class: 'tc-stack tc-stack--wide' });
    this.layer = el('div');
    mount(root, pageHead(title, this.reloadButton), el('p', { class: 'tc-intro' }, intro), this.running, this.results, this.jobBox, this.body, this.layer);
    this.unwatch = working.watch((name) => this.onWorking(name));
    this.showRunning();
  }

  stop() {
    this.alive = false;
    this.unwatch();
    this.watch.stop();
  }

  showRunning() {
    mount(this.running, runningNotice());
    setBusy(this.reloadButton, this.loading || working.name !== null);
  }

  onWorking(name) {
    if (!this.alive) return;
    this.showRunning();
    if (this.data !== null) this.drawBody();
    // A change that another drawing of this screen sent (the user went to another screen and came back while it ran) has ended.
    if (name === null && !this.mine) this.load();
  }

  async load() {
    const asked = (this.reads += 1);
    this.loading = true;
    this.showRunning();
    this.drawBody();
    let data = null;
    let error = null;
    try {
      data = await this.read();
    } catch (failure) {
      error = failure;
    }
    if (!this.alive || asked !== this.reads) return;
    this.loading = false;
    if (data !== null) this.data = data;
    this.error = error;
    // The job goes first: the buttons and the notices of the drawing below depend on whether one runs.
    if (error === null) this.follow(this.data?.state?.job ?? null);
    this.showRunning();
    this.drawBody();
    this.afterLoad();
  }

  afterLoad() {
    restoreFocus(this.root, this.root.querySelector('h1'));
  }

  /** Shows the job that a read found, and watches it when it runs and no watch is under way. */
  follow(job) {
    if (this.watch.active) return;
    const shown = isJob(job) ? job : null;
    this.showJob(shown);
    if (shown !== null && shown.state === 'running') this.watch.start(shown, false, this.limit());
  }

  /** How long a job may run before the screen stops waiting, from what the last read found. */
  limit() {
    return watchLimit(this.data?.status, this.data?.file);
  }

  /** Whether no change can be asked for now: one that this page sent has no answer yet, or the screen watches a job. */
  busy() {
    return working.name !== null || this.watch.active;
  }

  showJob(job) {
    const text = job === null ? '' : JSON.stringify(job);
    if (text === this.jobText) return;
    this.jobText = text;
    this.job = job;
    mount(this.jobBox, job === null ? null : jobPanel(job));
  }

  /**
   * The watch stopped before the job ended: the panel says that its result could not be confirmed, and the buttons come
   * back (the API refuses a change while a job runs). The next job that is read is drawn, even when it is this one.
   */
  showStopped(...more) {
    if (this.job !== null) mount(this.jobBox, jobPanel(this.job, notice('warn', w('managed.job.unconfirmed'), ...more)));
    this.jobText = null;
    this.drawBody();
  }

  onWatch(event) {
    if (!this.alive) return;
    if (event.job !== undefined) this.showJob(event.job);
    if (event.other === true && !this.otherTold) {
      this.otherTold = true;
      mount(this.results, notice('warn', w('managed.job.other')));
    }
    if (event.type === 'progress') {
      this.drawBody();
    } else if (event.type === 'ended') {
      this.ctx.refreshStatus();
      this.load();
    } else if (event.type === 'gone') {
      mount(this.results, notice('warn', w('managed.job.unconfirmed')));
      this.findings();
    } else if (event.type === 'lost') {
      this.showStopped(' ', button('small', w('screen.reload'), () => this.load()));
    } else {
      mount(this.results, notice('bad', this.ctx.describe(event.error)));
      this.showStopped();
    }
  }

  /** The job is gone: reads the state again and shows the two versions side by side, then the screen. */
  async findings() {
    this.ctx.refreshStatus();
    let state = null;
    try {
      state = await this.ctx.api.call('GET', '/api/managed');
    } catch {
      state = null;
    }
    if (!this.alive) return;
    this.results.append(
      panel(
        w('managed.found.title'),
        [],
        state === null || state.managed !== true
          ? notice('bad', w('managed.found.failed'))
          : kv(row(w('managed.selected'), isFingerprint(state.current) ? fingerprintView(state.current) : w('managed.none_selected')), row(w('managed.running'), servingView(state))),
      ),
    );
    await this.load();
  }

  /**
   * Sends a change and gives its `{ body, error }`, or null when none was sent or the screen is gone. `heard`, when it
   * is given, receives the `{ body, error }` first, whether the screen is still there or not.
   */
  async change(name, call, heard = null) {
    this.mine = true;
    const outcome = await perform(name, call);
    this.mine = false;
    this.ctx.refreshStatus();
    if (heard !== null && !outcome.skipped) heard(outcome);
    return outcome.skipped || !this.alive ? null : outcome;
  }

  /**
   * Sends a change to `path`: watches the job it started, or says why none started and reads the screen again. `heard`
   * (see `change`) takes over telling a refusal; `sending` runs right before the request leaves, and not at all for a
   * change that does not start.
   */
  async send(name, path, body, heard = null, sending = null) {
    this.otherTold = false;
    const done = await this.change(
      name,
      () => {
        sending?.();
        return this.ctx.api.call('POST', path, body);
      },
      heard,
    );
    if (done === null) return;
    if (done.error === null) {
      if (isJob(done.body?.job)) {
        mount(this.results);
        this.showJob(done.body.job);
        if (done.body.job.state === 'running') this.watch.start(done.body.job, true, this.limit());
        this.drawBody();
        if (done.body.job.state !== 'running') await this.load();
        return;
      }
      mount(this.results, this.resultLost());
      await this.load();
      return;
    }
    const kind = done.error instanceof ApiError ? done.error.kind : 'other';
    if (kind === 'unknown') mount(this.results, this.resultLost());
    else if (heard === null) mount(this.results, notice(kind === 'conflict' ? 'warn' : 'bad', this.ctx.describe(done.error, { change: true })));
    else mount(this.results);
    await this.load();
  }

  /** No answer to a change came, so its job may have started or not: the state and the job read after it tell. */
  resultLost() {
    return result('warn', w('managed.lost.title'), w('managed.lost.what'), w('managed.lost.next'));
  }

  /** The numbers of the version `name`, or null when it cannot be read; its content is not kept. */
  async versionCounts(name) {
    try {
      const answer = await this.ctx.api.call('GET', `/api/managed/versions/${name}`);
      return countsOf(answer.version);
    } catch {
      return null;
    }
  }

  /**
   * What the managed store holds of the certificates of the sites of the version `name` (the answer of `GET
   * /api/managed/certificates/<name>`), or null when it cannot be read or is not in the form of one: a screen adds
   * nothing for a read that failed.
   */
  async certificatesOf(name) {
    if (!isFingerprint(name)) return null;
    try {
      const answer = await this.ctx.api.call('GET', `/api/managed/certificates/${name}`);
      const sites = answer?.sites;
      return answer?.name === name && Array.isArray(sites) && sites.every((site) => site !== null && typeof site === 'object') ? answer : null;
    } catch {
      return null;
    }
  }

  /** Whether the configuration file has been changed and the running proxy has not read it yet. */
  fileWaits() {
    const file = this.data?.file?.sha256;
    const read = this.data?.status?.proxy?.config;
    return isFingerprint(file) && isFingerprint(read) && file !== read;
  }

  /**
   * Asks for a confirmation of the change `name` to `path` with `body`, with the numbers of the versions `from` and `to`
   * read just before, and sends it when the user confirms. `note` says what else the change does; `tone` is that of
   * `confirmChange`.
   */
  async propose({ title, what, note = null, from, to, confirm, tone = 'primary', name, path, body }) {
    if (this.asking || !isFingerprint(from) || !isFingerprint(to)) return;
    this.asking = true;
    let counts;
    try {
      counts = await Promise.all([this.versionCounts(from), this.versionCounts(to)]);
    } finally {
      this.asking = false;
    }
    if (!this.alive) return;
    const [before, after] = counts;
    const yes = await confirmChange(this.layer, {
      title,
      lines: [
        el('p', {}, what),
        note === null ? null : el('p', { class: 'tc-muted tc-small' }, note),
        before === null || after === null ? el('p', { class: 'tc-muted tc-small' }, w('managed.confirm.unread')) : null,
        this.fileWaits() ? notice('warn', w('managed.file_waits')) : null,
        el('p', { class: 'tc-muted tc-small' }, w('managed.confirm.groups_reset')),
      ],
      diff: diffView([w('managed.confirm.now'), w('managed.confirm.after')], diffRows(from, to, before, after)),
      confirm,
      tone,
    });
    if (!yes || !this.alive) return;
    await this.send(name, path, body);
  }

  failure(words) {
    return notice('bad', words, ' ', this.ctx.describe(this.error));
  }

  /** What every read of these screens adds to the state: `/api/status` and, for one who may change it, the configuration file. */
  async readAround() {
    const { api, user } = this.ctx;
    const [status, file] = await Promise.all([api.call('GET', '/api/status').catch(() => null), canChange(user.role) ? this.readFile() : null]);
    return { status, file };
  }

  /**
   * The values of the configuration file that the screens use (its SHA-256, the time of the lookup of the names, the
   * limit of a body of the proxy, whether it names a country database, an ACME account and records, and the host of the
   * route to this admin screen; `geo`, `acme`, `records` and `adminHost` are null when the file could not be read), or
   * why it was refused (a 409): its other values are not kept.
   */
  async readFile() {
    try {
      const answer = await this.ctx.api.call('GET', '/api/config');
      const present = (value) => value !== undefined && value !== null;
      return { sha256: answer.sha256, resolveMs: answer.forward?.resolve_timeout_ms, maxBody: answer.proxy?.max_body, geo: present(answer.geo), acme: present(answer.acme), records: present(answer.records), adminHost: answer.admin?.route?.host ?? null, refused: null };
    } catch (error) {
      return { sha256: null, resolveMs: null, maxBody: null, geo: null, acme: null, records: null, adminHost: null, refused: error instanceof ApiError && error.status === 409 ? error : null };
    }
  }
}

/** Mounts a screen of the kind `Kind` and reads it, as a screen of the shell mounts and stops it. */
export function mountScreen(Kind) {
  return (ctx, root, route) => {
    const screen = new Kind(ctx, root, route);
    screen.load();
    return { stop: () => screen.stop(), show: (next) => screen.show?.(next) };
  };
}
