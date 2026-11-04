// The screens of the rule generations: the list with the detail of one generation (which has an address of its own,
// `#/generations/<fingerprint>`) and the actions that choose and remove a generation, and the history of the switches
// with the rollback. A change of the rules asks first (a confirmation that shows the generation before and after),
// holds the buttons while it runs, and tells how it ended: the words of the proxy's answer (see `switchOutcome`), and
// when no answer came, what the status and the history show now. A screen is `{ id, title, least, mount }`;
// `mount(ctx, root, route)` draws into `root` and gives back `{ stop, show }`; `show(route)` is called when the
// address changes inside the screen. Nothing runs when the module is loaded.

import { badge, button, buttonClass, el, mount, notice, result } from './dom.js';
import { lazy, t, w } from './i18n.js';
import {
  bytesText,
  canChange,
  confirmChange,
  diffView,
  engineBadge,
  engineName,
  findingsView,
  fingerprintView,
  generationState,
  hashOf,
  isFingerprint,
  kv,
  modeBadge,
  modeName,
  outcomeView,
  pageHead,
  panelWith,
  perform,
  restoreFocus,
  row,
  runningNotice,
  shortOf,
  switchOutcome,
  timeView,
  instantOf,
  wordBadge,
  working,
} from './parts.js';
import { Table } from './table.js';

const KINDS = {
  activate: () => t('history.kind.activate'),
  rollback: () => t('history.kind.rollback'),
};
const KEPT = {
  chosen: () => w('gen.kept.chosen'),
  serving: () => w('gen.kept.serving'),
  rollback: () => w('gen.kept.rollback'),
};
/** The states of a generation that the list shows: the tone of the badge, its words and the same words as text. */
const STATES = {
  chosen: { tone: 'info', words: () => w('badge.chosen'), text: () => t('badge.chosen') },
  serving: { tone: 'ok', words: () => w('badge.serving'), text: () => t('badge.serving') },
  rollback: { tone: 'muted', words: () => w('badge.rollback'), text: () => t('badge.rollback') },
};

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

/** The lines of the table that a confirmation shows for a generation before and after: the fingerprint, the mode, the engine and the number of routes that are not inspected. */
export function diffRows(now, after, { gone = false } = {}) {
  const same = (key) => now?.[key] === after?.[key];
  const text = (item, key, show) => (item === null || item === undefined || item[key] === undefined ? '—' : show(item[key]));
  const fp = (value) => `${shortOf(value)}…`;
  const lines = [
    [() => w('col.fingerprint'), 'fingerprint', fp],
    [() => w('col.mode'), 'mode', (value) => lazy(() => modeName(value))],
    [() => w('col.engine'), 'engine', (value) => lazy(() => engineName(value))],
    [() => w('gen.routes'), 'routes', (value) => String(Array.isArray(value) ? value.length : value)],
  ];
  return lines.map(([label, key, show]) => ({
    label: label(),
    now: text(now, key, show),
    after: gone ? w('confirm.gone') : text(after, key, show),
    changed: gone || !same(key),
  }));
}

/** The base of the screens of the rules: the layers, the reads, the change that runs and its end. */
class Screen {
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
    this.reloadButton = button('', w('screen.reload'), () => this.load());
    this.running = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    this.results = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    this.body = el('div', { class: 'tc-stack tc-stack--wide' });
    this.layer = el('div');
    mount(root, pageHead(title, this.reloadButton), el('p', { class: 'tc-intro' }, intro), this.running, this.results, this.body, this.layer);
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
    this.showRunning();
    this.drawBody();
    this.afterLoad();
  }

  afterLoad() {
    restoreFocus(this.root, this.root.querySelector('h1'));
  }

  /** Sends a change and gives its `{ body, error }`, or null when none was sent or the screen is gone. */
  async change(name, call) {
    this.mine = true;
    const outcome = await perform(name, call);
    this.mine = false;
    this.ctx.refreshStatus();
    return outcome.skipped || !this.alive ? null : outcome;
  }

  /** A request to switch: shows how it ended, then reads again, whatever the end was. */
  async switch(name, call) {
    const done = await this.change(name, call);
    if (done === null) return;
    const outcome = switchOutcome(done);
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

// ---- the generations ----

class GenerationsScreen extends Screen {
  constructor(ctx, root, route) {
    super(ctx, root, w('nav.generations'), w('gen.intro'));
    this.route = route;
    /** The detail that is open: `{ fingerprint, data, error, panel }`, or null. */
    this.detail = null;
    this.notes = el('div', { class: 'tc-stack' });
    this.detailBox = el('div');
    this.detailStates = el('span');
    this.detailActions = el('div', { class: 'tc-panel__foot' });
    this.table = new Table({
      caption: w('gen.caption'),
      rowKey: (item) => item.fingerprint,
      empty: {
        title: w('gen.empty'),
        hint: canChange(ctx.user.role) ? w('gen.empty_hint') : null,
        action: canChange(ctx.user.role) ? el('a', { class: buttonClass('small'), href: hashOf('import') }, w('nav.import')) : null,
      },
      columns: [
        {
          key: 'fingerprint',
          label: w('col.fingerprint'),
          value: (item) => item.fingerprint,
          mono: true,
          cell: (item) => el('a', { class: 'tc-link tc-mono', href: hashOf('generations', { id: item.fingerprint }), title: item.fingerprint }, `${shortOf(item.fingerprint)}…`),
        },
        { key: 'made', label: w('col.made'), value: (item) => item.made, tight: true, cell: (item) => timeView(item.made, 's') },
        { key: 'mode', label: w('col.mode'), value: (item) => item.mode, cell: (item) => modeBadge(item.mode) },
        { key: 'engine', label: w('col.engine'), value: (item) => item.engine, cell: (item) => engineBadge(item.engine) },
        { key: 'routes', label: w('col.routes'), value: (item) => item.routes, num: true },
        { key: 'state', label: w('col.state'), value: (item) => this.stateWords(item).map((name) => STATES[name].text()).join(' '), cell: (item) => this.stateBadges(item) },
        { key: 'actions', label: w('col.actions'), value: () => '', sortable: false, filter: false, cell: (item) => this.actions(item) },
      ],
    });
    mount(this.body, this.notes, this.detailBox, this.table.node);
    this.show(route, true);
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

  async read() {
    const [list, status] = await Promise.all([this.ctx.api.call('GET', '/api/generations'), this.ctx.api.call('GET', '/api/status')]);
    return { list, status };
  }

  // ---- the address ----

  /** The address changed inside the screen: opens the detail it names, or closes the one that is open. */
  show(route, first = false) {
    const previous = this.detail?.fingerprint ?? null;
    this.route = route;
    if (route.id === null) {
      this.detail = null;
      mount(this.detailBox);
      this.table.update({ selected: null });
      if (!first && previous !== null && !this.table.focusRow(previous)) this.root.querySelector('h1')?.focus();
      return;
    }
    if (route.id !== previous) this.openDetail(route.id, !first);
  }

  async openDetail(fingerprint, focus) {
    const detail = { fingerprint, data: null, error: null };
    this.detail = detail;
    this.table.update({ selected: fingerprint });
    this.drawDetail(false);
    try {
      detail.data = await this.ctx.api.call('GET', `/api/generations/${fingerprint}`);
    } catch (error) {
      detail.error = error;
    }
    if (!this.alive || this.detail !== detail) return;
    this.drawDetail(focus);
  }

  drawDetail(focus) {
    const detail = this.detail;
    if (detail === null) return;
    const close = el('a', { class: buttonClass('quiet small'), href: hashOf('generations') }, w('gen.back'));
    if (detail.data === null) {
      const waiting = detail.error === null ? notice('info', w('gen.loading')) : notice('bad', w('gen.detail_failed'), ' ', this.ctx.describe(detail.error));
      mount(this.detailBox, panelWith(w('gen.detail'), [close], waiting).node);
      return;
    }
    const item = detail.data;
    const files = Array.isArray(item.files) ? item.files : [];
    const load = Array.isArray(item.load) ? item.load : [];
    const routes = Array.isArray(item.routes) ? item.routes : [];
    const filesTable = new Table({
      caption: w('gen.files'),
      rowKey: (file) => String(file.path),
      empty: { title: w('status.none') },
      columns: [
        { key: 'path', label: w('col.path'), value: (file) => String(file.path), mono: true },
        { key: 'size', label: w('col.size'), value: (file) => file.size, num: true, tight: true, cell: (file) => bytesText(file.size) },
        { key: 'sha256', label: w('col.sha256'), value: (file) => String(file.sha256), mono: true },
      ],
    });
    filesTable.update({ rows: files });
    const routesTable = new Table({
      caption: w('gen.routes'),
      rowKey: (route, at) => String(at),
      filter: false,
      empty: { title: w('gen.no_routes') },
      columns: [
        { key: 'host', label: w('col.host'), value: (route) => route.host ?? '', cell: (route) => (route.host === undefined ? el('span', { class: 'tc-muted' }, w('gen.any_host')) : String(route.host)) },
        { key: 'path', label: w('col.path'), value: (route) => String(route.path), mono: true },
        { key: 'action', label: w('col.action'), value: (route) => String(route.action) },
      ],
    });
    routesTable.update({ rows: routes });
    const { node, heading } = panelWith(
      w('gen.detail'),
      [this.detailStates, close],
      kv(
        row(w('col.fingerprint'), fingerprintView(item.fingerprint, { whole: true })),
        row(w('col.made'), timeView(item.made, 's')),
        row(w('col.mode'), modeBadge(item.mode)),
        row(w('col.engine'), engineBadge(item.engine)),
      ),
      el('h3', {}, w('gen.files')),
      filesTable.node,
      el('h3', {}, w('gen.load')),
      load.length === 0 ? el('p', { class: 'tc-muted' }, w('status.none')) : el('ol', { class: 'tc-list tc-mono' }, load.map((path) => el('li', {}, String(path)))),
      el('h3', {}, w('gen.routes')),
      routesTable.node,
      this.detailActions,
    );
    mount(this.detailBox, node);
    this.drawDetailLive();
    if (focus) heading.focus();
  }

  /** The part of the detail that follows the list: the states of the generation and the buttons, as the list shows them now. */
  drawDetailLive() {
    const detail = this.detail;
    if (detail === null || detail.data === null) return;
    const item = { ...(this.itemOf(detail.fingerprint) ?? detail.data), fingerprint: detail.fingerprint };
    mount(this.detailStates, this.stateBadges(item));
    mount(this.detailActions, this.actions(item, true));
  }

  // ---- the list ----

  stateWords(item) {
    const names = [];
    if (item.current === true) names.push('chosen');
    if (item.serving === true) names.push('serving');
    if (item.fingerprint === this.data?.status?.rollback_to) names.push('rollback');
    return names;
  }

  stateBadges(item) {
    const names = this.stateWords(item);
    return names.length === 0 ? null : el('span', { class: 'tc-badges' }, names.map((name) => badge(STATES[name].tone, STATES[name].words())));
  }

  drawBody() {
    const items = this.items();
    const chosen = this.chosen();
    const reachable = this.data?.list?.reachable === true;
    // A proxy that is busy answers the list but does not say what it serves, so no generation is marked as served.
    const mismatch = this.data !== null && reachable && this.state().servingKnown && chosen !== null && !items.some((item) => item.serving === true);
    mount(
      this.notes,
      this.error === null ? null : this.failure(w('gen.failed')),
      this.data === null || reachable ? null : notice('warn', w('gen.unreachable')),
      mismatch ? notice('warn', w('status.differ')) : null,
      this.data !== null && canChange(this.ctx.user.role) && chosen === null && items.length > 0 ? notice('warn', w('gen.nochosen')) : null,
    );
    this.table.node.hidden = this.data === null && this.error !== null;
    this.table.update({ rows: items, loading: this.data === null && this.error === null });
    this.drawDetailLive();
  }

  /** The buttons of a generation; the choosing one is the main button of a detail, and in a row it is an ordinary one. */
  actions(item, inDetail = false) {
    if (this.data === null) return null;
    const can = actionsOf(this.ctx.user.role, item, this.state());
    const busy = working.name !== null;
    const buttons = [
      can.choose === null ? null : button(inDetail ? 'primary' : 'small', can.choose === 'apply' ? w('gen.apply') : w('gen.choose'), () => this.choose(item), { disabled: busy }),
      can.remove ? el('span', { class: 'tc-actions--apart' }, button(inDetail ? 'danger' : 'small danger', w('gen.remove'), () => this.remove(item), { disabled: busy })) : null,
      can.kept === null ? null : el('span', { class: 'tc-muted tc-small' }, KEPT[can.kept]()),
    ];
    return buttons.every((one) => one === null) ? null : el('div', { class: 'tc-actions' }, buttons);
  }

  itemOf(fingerprint) {
    return this.items().find((item) => item.fingerprint === fingerprint) ?? null;
  }

  async choose(item) {
    const expect = this.chosen();
    if (expect === null) return;
    const proxy = this.data.status?.proxy;
    const serving = proxy !== null && typeof proxy === 'object' ? proxy.generation : null;
    const lines = [el('p', {}, expect === item.fingerprint ? w('gen.choose.same') : w('gen.choose.what'))];
    if (typeof serving === 'string' && serving !== expect) lines.push(el('p', { class: 'tc-muted tc-small' }, w('gen.choose.serving', { serving: shortOf(serving) })));
    const yes = await confirmChange(this.layer, {
      title: w('gen.choose.title'),
      lines,
      diff: diffView([w('confirm.now'), w('confirm.after_choose')], diffRows(this.itemOf(expect), this.itemOf(item.fingerprint) ?? item)),
      confirm: w('gen.choose.confirm'),
    });
    if (!yes || !this.alive) return;
    await this.switch('activate', () => this.ctx.api.call('POST', '/api/activate', { generation: item.fingerprint, expect }));
  }

  async remove(item) {
    const target = this.itemOf(item.fingerprint) ?? item;
    const yes = await confirmChange(this.layer, {
      title: w('gen.remove.title'),
      lines: [el('p', {}, w('gen.remove.what'))],
      diff: diffView([w('confirm.now'), w('confirm.after_remove')], diffRows(target, null, { gone: true })),
      confirm: w('gen.remove'),
      tone: 'danger',
    });
    if (!yes || !this.alive) return;
    const done = await this.change('remove', () => this.ctx.api.call('DELETE', `/api/generations/${item.fingerprint}`));
    if (done === null) return;
    mount(
      this.results,
      done.error === null
        ? result('ok', w('gen.removed_title'), w('gen.removed', { id: shortOf(item.fingerprint) }))
        : notice(done.error.kind === 'conflict' || done.error.kind === 'unknown' ? 'warn' : 'bad', this.ctx.describe(done.error, { change: true })),
    );
    // The generation is gone, and so is its address.
    if (done.error === null && this.route.id === item.fingerprint) this.ctx.navigate(hashOf('generations'));
    await this.load();
  }
}

// ---- the history ----

class HistoryScreen extends Screen {
  constructor(ctx, root) {
    super(ctx, root, w('nav.history'), w('history.intro'));
    this.target = el('div');
    const fp = (key) => (entry) => (isFingerprint(entry[key]) ? el('a', { class: 'tc-link tc-mono', href: hashOf('generations', { id: entry[key] }), title: entry[key] }, `${shortOf(entry[key])}…`) : fingerprintView(entry[key], { copy: false }));
    this.table = new Table({
      caption: w('history.caption'),
      rowKey: (entry, at) => String(at),
      empty: { title: w('history.empty') },
      columns: [
        { key: 'ts', label: w('col.time'), value: (entry) => instantOf(entry.ts), tight: true, cell: (entry) => timeView(entry.ts) },
        { key: 'actor', label: w('col.by'), value: (entry) => String(entry.actor) },
        { key: 'kind', label: w('col.kind'), value: (entry) => (Object.hasOwn(KINDS, entry.kind) ? KINDS[entry.kind]() : String(entry.kind)) },
        { key: 'from', label: w('col.from'), value: (entry) => entry.from ?? '', mono: true, cell: fp('from') },
        { key: 'to', label: w('col.to'), value: (entry) => entry.to ?? '', mono: true, cell: fp('to') },
        { key: 'result', label: w('col.result'), value: (entry) => String(entry.result), cell: (entry) => wordBadge(entry.result) },
      ],
    });
    mount(this.body, this.target, this.table.node);
  }

  async read() {
    const [status, lines, list] = await Promise.all([
      this.ctx.api.call('GET', '/api/status'),
      this.ctx.api.call('GET', '/api/history'),
      // The list only fills the confirmation of a rollback with the mode and the engine of the two generations.
      this.ctx.api.call('GET', '/api/generations').catch(() => null),
    ]);
    return { status, entries: Array.isArray(lines.entries) ? lines.entries : [], generations: Array.isArray(list?.generations) ? list.generations : [] };
  }

  drawBody() {
    if (this.data === null) {
      mount(this.target, this.error === null ? notice('info', w('gen.loading')) : this.failure(w('history.failed')));
      this.table.node.hidden = this.error !== null;
      this.table.update({ rows: [], loading: this.error === null });
      return;
    }
    mount(this.target, this.error === null ? null : this.failure(w('history.failed')), this.targetPanel(this.data.status));
    this.table.node.hidden = false;
    this.table.update({ rows: this.data.entries, loading: false });
  }

  targetPanel(status) {
    const target = status.rollback_to;
    const may = canChange(this.ctx.user.role) && typeof target === 'string' && typeof status.current === 'string';
    return panelWith(
      w('status.rollback'),
      [],
      typeof target === 'string' ? fingerprintView(target) : el('p', { class: 'tc-muted' }, w('status.rollback_none')),
      typeof target === 'string' ? el('p', { class: 'tc-muted tc-small' }, w('status.rollback_note')) : null,
      may ? el('div', { class: 'tc-actions' }, button('', w('history.rollback'), () => this.rollback(status), { disabled: working.name !== null })) : null,
    ).node;
  }

  async rollback(status) {
    const { current, rollback_to: target } = status;
    const find = (fingerprint) => this.data.generations.find((item) => item.fingerprint === fingerprint) ?? { fingerprint };
    const yes = await confirmChange(this.layer, {
      title: w('history.rollback.title'),
      lines: [el('p', {}, w('history.rollback.what'))],
      diff: diffView([w('confirm.now'), w('confirm.after_rollback')], diffRows(find(current), find(target))),
      confirm: w('history.rollback'),
      tone: 'danger',
    });
    if (!yes || !this.alive) return;
    await this.switch('rollback', () => this.ctx.api.call('POST', '/api/rollback', { expect: current }));
  }
}

function mountScreen(Kind) {
  return (ctx, root, route) => {
    const screen = new Kind(ctx, root, route);
    screen.load();
    return { stop: () => screen.stop(), show: (next) => screen.show?.(next) };
  };
}

export const screens = [
  { id: 'generations', title: w('nav.generations'), least: 'viewer', route: { id: isFingerprint }, mount: mountScreen(GenerationsScreen) },
  { id: 'history', title: w('nav.history'), least: 'viewer', mount: mountScreen(HistoryScreen) },
];
