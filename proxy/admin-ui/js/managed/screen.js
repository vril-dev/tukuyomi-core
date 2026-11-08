// The base of the screens of the managed configuration: the layers, the reads that count, the change that runs, the
// job that it starts, and the confirmation that asks first. A change is answered when its job starts, so the screen
// watches the job (see `job.js`) until it ends. What the state of a screen says of the proxy is here too. Nothing runs
// when the module is loaded.

import { ApiError } from '../api.js';
import { button, el, mount, notice, result } from '../dom.js';
import { w } from '../i18n.js';
import { canChange, confirmChange, diffView, fingerprintView, hashOf, isFingerprint, kv, pageHead, panel, perform, restoreFocus, row, runningNotice, setBusy, shortOf, working } from '../parts.js';
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

/** The lines of a confirmation for the versions `from` and `to` with their numbers (`null`: that version could not be read). */
function diffRows(from, to, before, after) {
  const number = (counts, key) => (counts === null || counts[key] === null ? '—' : String(counts[key]));
  const present = (counts, key) => {
    if (counts === null) return '—';
    return counts[key] ? w('managed.diff.set') : w('managed.diff.unset');
  };
  const short = (value) => el('span', { class: 'tc-mono' }, `${shortOf(value)}…`);
  const counted = (label, key, value) => ({
    label,
    now: value(before, key),
    after: value(after, key),
    changed: before === null || after === null ? false : before[key] !== after[key],
  });
  return [
    { label: w('managed.col.version'), now: short(from), after: short(to), changed: from !== to },
    counted(w('managed.diff.sites'), 'sites', number),
    counted(w('managed.diff.upstreams'), 'upstreams', number),
    counted(w('managed.diff.routes'), 'routes', number),
    counted(w('managed.diff.default'), 'defaultUpstream', number),
    counted(w('managed.diff.access'), 'access', present),
    counted(w('managed.diff.rate_limit'), 'rateLimit', present),
  ];
}

/** The notice for a configuration with no managed object, with the way to the configuration file for those who may see it. */
export function unusedNotice(role) {
  return notice('info', w('managed.unused'), canChange(role) ? [' ', el('a', { class: 'tc-link', href: hashOf('config') }, w('managed.unused_link'))] : null);
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

  /** Sends a change and gives its `{ body, error }`, or null when none was sent or the screen is gone. */
  async change(name, call) {
    this.mine = true;
    const outcome = await perform(name, call);
    this.mine = false;
    this.ctx.refreshStatus();
    return outcome.skipped || !this.alive ? null : outcome;
  }

  /** Sends a change to `path`: watches the job it started, or says why none started and reads the screen again. */
  async send(name, path, body) {
    this.otherTold = false;
    const done = await this.change(name, () => this.ctx.api.call('POST', path, body));
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
    else mount(this.results, notice(kind === 'conflict' ? 'warn' : 'bad', this.ctx.describe(done.error, { change: true })));
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

  /** The two values of the configuration file that the screens use, or why it was refused (a 409): its other values are not kept. */
  async readFile() {
    try {
      const answer = await this.ctx.api.call('GET', '/api/config');
      return { sha256: answer.sha256, resolveMs: answer.forward?.resolve_timeout_ms, refused: null };
    } catch (error) {
      return { sha256: null, resolveMs: null, refused: error instanceof ApiError && error.status === 409 ? error : null };
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
