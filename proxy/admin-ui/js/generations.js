// The screens of the rule generations: the list with its detail and the actions that choose and remove a generation,
// and the history of the switches with the rollback. A change of the rules asks first (a confirmation that shows the
// generation before and after), holds the buttons while it runs, and tells how it ended: the words of the proxy's
// answer (see `switchOutcome`), and when no answer came, what the status and the history show now. A screen is
// `{ id, title, least, mount }`; `mount(ctx, root)` draws into `root` and gives back a function that undoes what it
// set up. Nothing runs when the module is loaded.

import { badge, el, mount, notice } from './dom.js';
import { t } from './i18n.js';
import {
  bytesText,
  canChange,
  changeLines,
  confirmChange,
  findingsView,
  fingerprint,
  generationState,
  handoff,
  openSheet,
  outcomeView,
  pageHead,
  perform,
  row,
  runningNotice,
  shortOf,
  switchOutcome,
  table,
  utc,
  working,
  wordBadge,
} from './parts.js';

const MODES = {
  block: () => t('mode.block'),
  detect: () => t('mode.detect'),
};
const KINDS = {
  activate: () => t('history.kind.activate'),
  rollback: () => t('history.kind.rollback'),
};
const KEPT = {
  chosen: () => t('gen.kept.chosen'),
  serving: () => t('gen.kept.serving'),
  rollback: () => t('gen.kept.rollback'),
};

function modeBadge(mode) {
  return badge('muted', Object.hasOwn(MODES, mode) ? MODES[mode]() : String(mode));
}

/**
 * What a user may do with a generation, from the role and from `state`: `hasChosen` (the rules store chooses one;
 * without it no request to choose can name what it expects), `rollbackTo` (the generation a rollback would choose)
 * and `servingKnown` (the proxy said which generation it serves; when it did not, nothing shows that the chosen
 * generation is not served). `choose` is `choose`, `apply` (it is chosen but the proxy does not serve it, so the
 * proxy is told to switch to it) or null; `remove` says whether the store may remove it; `kept` says why not (the
 * chosen generation, the one that a proxy serves and the target of a rollback are kept). A viewer may do none of it.
 */
export function actionsOf(role, generation, { hasChosen, rollbackTo, servingKnown }) {
  const none = { choose: null, remove: false, kept: null };
  if (!canChange(role)) return none;
  let kept = null;
  if (generation.current === true) kept = 'chosen';
  else if (generation.serving === true) kept = 'serving';
  else if (generation.fingerprint === rollbackTo) kept = 'rollback';
  let choose = null;
  if (hasChosen && generation.current !== true) choose = 'choose';
  if (hasChosen && servingKnown && generation.current === true && generation.serving !== true) choose = 'apply';
  return { choose, remove: kept === null, kept };
}

/** The base of both screens: the layers, the reads, the change that runs and its end. */
class Screen {
  constructor(ctx, root, title, intro) {
    this.ctx = ctx;
    this.alive = true;
    /** This screen has sent the change that runs, and tells its end itself. */
    this.mine = false;
    this.reads = 0;
    this.loading = false;
    this.data = null;
    this.error = null;
    this.reloadButton = el('button', { type: 'button', class: 'btn', on: { click: () => this.load() } }, t('screen.reload'));
    this.running = el('div', { class: 'stack', 'aria-live': 'polite' });
    this.results = el('div', { class: 'stack' });
    this.body = el('div', { class: 'stack' });
    this.layer = el('div');
    mount(root, el('div', { class: 'stack' }, pageHead(title, this.reloadButton), el('p', { class: 'muted' }, intro), this.running, this.results, this.body), this.layer);
    this.unwatch = working.watch((name) => this.onWorking(name));
    this.showRunning();
  }

  stop() {
    this.alive = false;
    this.unwatch();
  }

  showRunning() {
    mount(this.running, runningNotice());
    this.reloadButton.disabled = this.loading || working.name !== null;
  }

  onWorking(name) {
    if (!this.alive) return;
    this.showRunning();
    if (this.data !== null) this.drawBody();
    // A change that another drawing of this screen sent (the language was switched while it ran) has ended.
    if (name === null && !this.mine) this.load();
  }

  async load() {
    const asked = (this.reads += 1);
    this.loading = true;
    this.showRunning();
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
    this.showRunning();
    this.drawBody();
    this.afterLoad();
  }

  afterLoad() {}

  /** Sends a change and gives its `{ body, error }`, or null when none was sent or the screen is gone. */
  async change(name, call) {
    this.mine = true;
    const result = await perform(name, call);
    this.mine = false;
    this.ctx.refreshStatus();
    return result.skipped || !this.alive ? null : result;
  }

  /** A request to switch: shows how it ended, then reads again, whatever the end was. */
  async switch(name, call) {
    const result = await this.change(name, call);
    if (result === null) return;
    const outcome = switchOutcome(result);
    mount(this.results, outcomeView(outcome, this.ctx.describe));
    if (outcome.word === 'lost') {
      await this.findings();
      if (!this.alive) return;
    }
    await this.load();
  }

  /** No answer came: reads the status and the history and shows what they say. */
  async findings() {
    let status = null;
    let history = null;
    try {
      const [state, lines] = await Promise.all([this.ctx.api.call('GET', '/api/status'), this.ctx.api.call('GET', '/api/history')]);
      status = state;
      history = Array.isArray(lines.entries) ? lines.entries : null;
    } catch {
      status = null;
    }
    if (this.alive) this.results.append(findingsView(status, history));
  }

  failure(words) {
    return notice('bad', words, ' ', this.ctx.describe(this.error));
  }
}

class GenerationsScreen extends Screen {
  constructor(ctx, root) {
    super(ctx, root, t('gen.title'), t('gen.intro'));
  }

  async read() {
    const [list, status] = await Promise.all([this.ctx.api.call('GET', '/api/generations'), this.ctx.api.call('GET', '/api/status')]);
    return { list, status };
  }

  /** The generations of the list, the newest first. */
  items() {
    return Array.isArray(this.data?.list?.generations) ? this.data.list.generations : [];
  }

  /** The state that `actionsOf` asks for, from what was read last. */
  state() {
    const rollbackTo = this.data?.status?.rollback_to;
    return {
      hasChosen: this.chosen() !== null,
      rollbackTo: typeof rollbackTo === 'string' ? rollbackTo : null,
      servingKnown: generationState(this.data?.status) !== 'unknown',
    };
  }

  /** The generation that the rules store chooses, as the list showed it, which a request to choose must expect. */
  chosen() {
    return this.items().find((item) => item.current === true)?.fingerprint ?? null;
  }

  afterLoad() {
    const asked = handoff.take();
    if (asked !== null && this.items().some((item) => item.fingerprint === asked)) this.openDetail(asked);
  }

  drawBody() {
    if (this.data === null) {
      mount(this.body, this.error === null ? notice('info', t('gen.loading')) : this.failure(t('gen.failed')));
      return;
    }
    const items = this.items();
    const chosen = this.chosen();
    const reachable = this.data.list.reachable === true;
    // A proxy that is busy answers the list but does not say what it serves, so no generation is marked as served.
    const mismatch = reachable && this.state().servingKnown && chosen !== null && !items.some((item) => item.serving === true);
    mount(
      this.body,
      this.error === null ? null : this.failure(t('gen.failed')),
      reachable ? null : notice('warn', t('gen.unreachable')),
      mismatch ? notice('warn', t('status.differ')) : null,
      canChange(this.ctx.user.role) && chosen === null && items.length > 0 ? notice('warn', t('gen.nochosen')) : null,
      items.length === 0
        ? notice('info', t('gen.empty'))
        : table(
            [t('col.fingerprint'), t('col.made'), t('col.mode'), t('col.routes'), t('col.state'), t('col.actions')],
            items.map((item) => this.rowOf(item)),
            t('gen.caption'),
            { tight: [1, 3] },
          ),
    );
  }

  rowOf(item) {
    const states = [
      item.current === true ? badge('ok', t('badge.chosen')) : null,
      item.serving === true ? badge('ok', t('badge.serving')) : null,
      item.fingerprint === this.data.status?.rollback_to ? badge('muted', t('badge.rollback')) : null,
    ].filter((state) => state !== null);
    return [
      fingerprint(item.fingerprint),
      utc(item.made),
      modeBadge(item.mode),
      String(item.routes),
      states.length === 0 ? '' : el('span', { class: 'badges' }, states),
      this.actions(item, () => {}),
    ];
  }

  /** The buttons of a generation; `before` runs before an action starts (the sheet that holds them closes). */
  actions(item, before, inSheet = false) {
    const can = actionsOf(this.ctx.user.role, item, this.state());
    const busy = working.name !== null;
    const act = (run) => () => {
      before();
      run();
    };
    return el(
      'div',
      { class: 'row-actions' },
      inSheet ? null : el('button', { type: 'button', class: 'btn', on: { click: act(() => this.openDetail(item.fingerprint)) } }, t('gen.details')),
      can.choose === null
        ? null
        : el(
            'button',
            { type: 'button', class: 'btn btn-primary', disabled: busy, on: { click: act(() => this.choose(item)) } },
            can.choose === 'apply' ? t('gen.apply') : t('gen.choose'),
          ),
      can.remove
        ? el('button', { type: 'button', class: 'btn btn-danger', disabled: busy, on: { click: act(() => this.remove(item)) } }, t('gen.remove'))
        : null,
      can.kept === null ? null : el('p', { class: 'muted small' }, KEPT[can.kept]()),
    );
  }

  async openDetail(fingerprintHex) {
    const sheet = openSheet(this.layer, t('gen.detail'), notice('info', t('gen.loading')));
    let detail;
    try {
      detail = await this.ctx.api.call('GET', `/api/generations/${fingerprintHex}`);
    } catch (error) {
      if (this.alive) mount(sheet.body, notice('bad', t('gen.detail_failed'), ' ', this.ctx.describe(error)));
      return;
    }
    if (!this.alive) return;
    const files = Array.isArray(detail.files) ? detail.files : [];
    const load = Array.isArray(detail.load) ? detail.load : [];
    const routes = Array.isArray(detail.routes) ? detail.routes : [];
    mount(
      sheet.body,
      el(
        'dl',
        { class: 'kv' },
        row(t('col.fingerprint'), el('code', { class: 'fp' }, detail.fingerprint)),
        row(t('col.made'), utc(detail.made)),
        row(t('col.mode'), modeBadge(detail.mode)),
        row(
          t('col.state'),
          detail.current === true || detail.serving === true
            ? el('span', { class: 'badges' }, detail.current === true ? badge('ok', t('badge.chosen')) : null, detail.serving === true ? badge('ok', t('badge.serving')) : null)
            : el('span', { class: 'muted' }, t('status.none')),
        ),
      ),
      el('h3', {}, t('gen.files')),
      table(
        [t('col.path'), t('col.size'), t('col.sha256')],
        files.map((file) => [String(file.path), bytesText(file.size), el('code', { class: 'fp' }, String(file.sha256))]),
        t('gen.files'),
      ),
      el('h3', {}, t('gen.load')),
      load.length === 0 ? el('p', { class: 'muted' }, t('status.none')) : el('ol', { class: 'plain-list' }, load.map((path) => el('li', {}, String(path)))),
      el('h3', {}, t('gen.routes')),
      routes.length === 0
        ? el('p', { class: 'muted' }, t('gen.no_routes'))
        : table(
            [t('col.host'), t('col.path'), t('col.action')],
            routes.map((route) => [route.host === undefined ? el('span', { class: 'muted' }, t('gen.any_host')) : String(route.host), String(route.path), String(route.action)]),
            t('gen.routes'),
          ),
      this.actions({ ...detail, fingerprint: fingerprintHex }, () => sheet.close(), true),
    );
  }

  async choose(item) {
    const expect = this.chosen();
    if (expect === null) return;
    const proxy = this.data.status?.proxy;
    const serving = proxy !== null && typeof proxy === 'object' ? proxy.generation : null;
    const lines = [el('p', {}, expect === item.fingerprint ? t('gen.choose.same') : t('gen.choose.what')), ...changeLines(expect, item.fingerprint)];
    if (typeof serving === 'string' && serving !== expect) lines.push(el('p', { class: 'small' }, t('gen.choose.serving', { serving: shortOf(serving) })));
    const yes = await confirmChange(this.layer, { title: t('gen.choose.title'), lines, confirm: t('gen.choose.confirm') });
    if (!yes || !this.alive) return;
    await this.switch('activate', () => this.ctx.api.call('POST', '/api/activate', { generation: item.fingerprint, expect }));
  }

  async remove(item) {
    const lines = [
      el('p', {}, t('gen.remove.what')),
      el('dl', { class: 'kv' }, row(t('col.fingerprint'), el('code', { class: 'fp' }, item.fingerprint)), row(t('col.made'), utc(item.made)), row(t('col.mode'), modeBadge(item.mode))),
    ];
    const yes = await confirmChange(this.layer, { title: t('gen.remove.title'), lines, confirm: t('gen.remove'), tone: 'danger' });
    if (!yes || !this.alive) return;
    const result = await this.change('remove', () => this.ctx.api.call('DELETE', `/api/generations/${item.fingerprint}`));
    if (result === null) return;
    mount(
      this.results,
      result.error === null
        ? notice('ok', t('gen.removed', { id: shortOf(item.fingerprint) }))
        : notice(result.error.kind === 'conflict' || result.error.kind === 'unknown' ? 'warn' : 'bad', this.ctx.describe(result.error, { change: true })),
    );
    await this.load();
  }
}

class HistoryScreen extends Screen {
  constructor(ctx, root) {
    super(ctx, root, t('history.title'), t('history.intro'));
  }

  async read() {
    const [status, lines] = await Promise.all([this.ctx.api.call('GET', '/api/status'), this.ctx.api.call('GET', '/api/history')]);
    return { status, entries: Array.isArray(lines.entries) ? lines.entries : [] };
  }

  drawBody() {
    if (this.data === null) {
      mount(this.body, this.error === null ? notice('info', t('gen.loading')) : this.failure(t('history.failed')));
      return;
    }
    const { status, entries } = this.data;
    mount(
      this.body,
      this.error === null ? null : this.failure(t('history.failed')),
      this.targetCard(status),
      entries.length === 0
        ? notice('info', t('history.empty'))
        : table(
            [t('col.time'), t('col.by'), t('col.kind'), t('col.from'), t('col.to'), t('col.result')],
            entries.map((entry) => [
              String(entry.ts),
              String(entry.actor),
              Object.hasOwn(KINDS, entry.kind) ? KINDS[entry.kind]() : String(entry.kind),
              fingerprint(entry.from),
              fingerprint(entry.to),
              wordBadge(entry.result),
            ]),
            t('history.caption'),
            { tight: [0, 1, 2] },
          ),
    );
  }

  targetCard(status) {
    const target = status.rollback_to;
    const may = canChange(this.ctx.user.role) && typeof target === 'string' && typeof status.current === 'string';
    return el(
      'section',
      { class: 'card' },
      el('h2', {}, t('status.rollback')),
      typeof target === 'string' ? el('p', {}, fingerprint(target)) : el('p', { class: 'muted' }, t('status.rollback_none')),
      typeof target === 'string' ? el('p', { class: 'muted small' }, t('status.rollback_note')) : null,
      may
        ? el('div', { class: 'actions' }, el('button', { type: 'button', class: 'btn btn-primary', disabled: working.name !== null, on: { click: () => this.rollback(status) } }, t('history.rollback')))
        : null,
    );
  }

  async rollback(status) {
    const { current, rollback_to: target } = status;
    const lines = [el('p', {}, t('history.rollback.what')), ...changeLines(current, target)];
    const yes = await confirmChange(this.layer, { title: t('history.rollback.title'), lines, confirm: t('history.rollback') });
    if (!yes || !this.alive) return;
    await this.switch('rollback', () => this.ctx.api.call('POST', '/api/rollback', { expect: current }));
  }
}

function mountScreen(Kind) {
  return (ctx, root) => {
    const screen = new Kind(ctx, root);
    screen.load();
    return () => screen.stop();
  };
}

export const screens = [
  { id: 'generations', title: () => t('nav.generations'), least: 'viewer', mount: mountScreen(GenerationsScreen) },
  { id: 'history', title: () => t('nav.history'), least: 'viewer', mount: mountScreen(HistoryScreen) },
];
