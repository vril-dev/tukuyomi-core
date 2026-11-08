// The screen of the versions of the managed configuration: the state of the store and of the proxy (the version that
// is selected, the one that runs, and whether they differ), the job of a change, the list of the versions, the content
// of one version for an operator (with an address of its own, `#/managed/<fingerprint>`), and the change that applies
// a version by its name. The content of a version may hold secrets, so it stays in this page's memory only while it is
// open. The small card of the overview is here too. Nothing runs when the module is loaded.

import { badge, button, buttonClass, el, mount, notice } from '../dom.js';
import { t, w } from '../i18n.js';
import { canChange, fingerprintText, fingerprintView, hashOf, isFingerprint, kv, panel, panelWith, row, shortOf, timeCell, timeCellText, timeLabel, timeView } from '../parts.js';
import { Table } from '../table.js';
import { screens as historyScreens } from './history.js';
import { isJob } from './job.js';
import { Screen, countsOf, mountScreen, proxyOf, servingView, unusedNotice } from './screen.js';

// The tone and the short words of what `proxyOf` says.
const PROXY = {
  ok: ['ok', () => w('managed.proxy.ok')],
  unreachable: ['bad', () => w('managed.proxy.unreachable_short')],
  silent: ['warn', () => w('managed.proxy.silent_short')],
  unmanaged: ['bad', () => w('managed.proxy.unmanaged_short')],
  reloading: ['warn', () => w('managed.proxy.reloading_short')],
};

/** The states of a version that the list shows: the tone of the badge, its words and the same words as text. */
const STATES = {
  selected: { tone: 'info', words: () => w('managed.badge.selected'), text: () => t('managed.badge.selected') },
  running: { tone: 'ok', words: () => w('managed.badge.running'), text: () => t('managed.badge.running') },
};

/**
 * What a user may do with a version of the list: see its content (`open`) and apply it by its name (`apply`), which
 * needs a version that is selected (the store has one, which the request must expect) and is not this one. A version
 * whose name is not one of ours gets neither, and a viewer neither.
 */
export function versionActions(role, version, selected) {
  if (!canChange(role) || !isFingerprint(version?.name)) return { open: false, apply: false };
  return { open: true, apply: isFingerprint(selected) && version.current !== true };
}

/** Whether what the state says is a difference to correct: the screen is not watching a job, the proxy is not reading again, and the two versions are named and differ. */
export function differs(state, watching) {
  return !watching && state.reloading !== true && isFingerprint(state.current) && isFingerprint(state.serving) && state.current !== state.serving;
}

class VersionsScreen extends Screen {
  constructor(ctx, root, route) {
    super(ctx, root, w('nav.managed'), w('managed.intro'));
    /** The detail that is open: `{ name, data, error }`, or null. */
    this.detail = null;
    this.notes = el('div', { class: 'tc-stack' });
    this.stateBox = el('div');
    this.detailBox = el('div');
    this.detailStates = el('span');
    this.detailActions = el('div', { class: 'tc-panel__foot' });
    this.table = new Table({
      caption: w('managed.caption'),
      rowKey: (item, at) => (isFingerprint(item.name) ? item.name : String(at)),
      empty: { title: w('managed.empty') },
      columns: [
        { key: 'name', label: w('managed.col.version'), value: (item) => String(item.name), text: (item) => fingerprintText(item.name), mono: true, cell: (item) => this.nameCell(item) },
        { key: 'made', label: timeLabel(w('managed.col.made')), value: (item) => item.made, text: (item) => timeCellText(item.made, 's'), tight: true, cell: (item) => timeCell(item.made, 's') },
        { key: 'state', label: w('col.state'), value: (item) => this.stateNames(item).map((name) => STATES[name].text()).join(' '), cell: (item) => this.stateBadges(item) },
        { key: 'actions', label: w('col.actions'), value: () => '', sortable: false, filter: false, cell: (item) => this.actions(item) },
      ],
    });
    mount(this.body, this.notes, this.stateBox, this.detailBox, this.table.node);
    this.show(route, true);
  }

  stop() {
    super.stop();
    this.detail = null;
    this.clearDetail();
  }

  /**
   * Takes the panel of the detail off the screen. The two parts that follow the list live from one drawing to the next,
   * so they are taken out of the panel too: else they would still reach the content of the version that it holds.
   */
  clearDetail() {
    this.detailStates.remove();
    this.detailActions.remove();
    mount(this.detailBox);
  }

  async read() {
    const state = await this.ctx.api.call('GET', '/api/managed');
    if (state.managed === false) return { state };
    if (state.managed !== true) throw new Error('not an answer of the managed state');
    const [list, around] = await Promise.all([this.ctx.api.call('GET', '/api/managed/versions'), this.readAround()]);
    return { state, list, ...around };
  }

  /** The version that the store selects, as the last read found it. */
  selected() {
    const current = this.data?.state?.current;
    return isFingerprint(current) ? current : null;
  }

  /** The versions of the list, the newest first. */
  items() {
    return Array.isArray(this.data?.list?.versions) ? this.data.list.versions : [];
  }

  // ---- the address ----

  /** The address changed inside the screen: opens the detail it names, or closes the one that is open. A viewer may not see the content of a version. */
  show(route, first = false) {
    let next = route;
    if (next.id !== null && !canChange(this.ctx.user.role)) {
      this.ctx.dropId();
      next = { ...next, id: null };
    }
    const previous = this.detail?.name ?? null;
    if (next.id === null) {
      this.detail = null;
      this.clearDetail();
      this.table.update({ selected: null });
      if (!first && previous !== null && !this.table.focusRow(previous)) this.root.querySelector('h1')?.focus();
      return;
    }
    if (next.id !== previous) this.openDetail(next.id, !first);
  }

  async openDetail(name, focus) {
    const detail = { name, data: null, error: null };
    this.detail = detail;
    this.table.update({ selected: name });
    this.drawDetail(false);
    try {
      detail.data = await this.ctx.api.call('GET', `/api/managed/versions/${name}`);
    } catch (error) {
      detail.error = error;
    }
    if (!this.alive || this.detail !== detail) return;
    this.drawDetail(focus);
  }

  detailFailure(error) {
    if (error.status === 404) return notice('bad', w('managed.detail.none'));
    if (error.status === 500) return notice('bad', w('managed.detail.unreadable'), ' ', this.ctx.describe(error));
    return notice('bad', w('managed.detail.failed'), ' ', this.ctx.describe(error));
  }

  drawDetail(focus) {
    const detail = this.detail;
    if (detail === null) return;
    this.clearDetail();
    const close = el('a', { class: buttonClass('quiet small'), href: hashOf('managed') }, w('managed.detail.back'));
    if (detail.data === null) {
      const waiting = detail.error === null ? notice('info', w('managed.loading')) : this.detailFailure(detail.error);
      mount(this.detailBox, panelWith(w('managed.detail.title'), [close], waiting).node);
      return;
    }
    const item = detail.data;
    const counts = countsOf(item.version);
    const number = (value) => (value === null ? '—' : String(value));
    const present = (value) => (value ? w('managed.diff.set') : w('managed.diff.unset'));
    const { node, heading } = panelWith(
      w('managed.detail.title'),
      [this.detailStates, close],
      kv(
        row(w('managed.col.version'), fingerprintView(item.name, { whole: true })),
        row(w('managed.col.made'), timeView(item.made, 's')),
        row(w('managed.diff.sites'), number(counts.sites)),
        row(w('managed.diff.upstreams'), number(counts.upstreams)),
        row(w('managed.diff.routes'), number(counts.routes)),
        row(w('managed.diff.default'), number(counts.defaultUpstream)),
        row(w('managed.diff.access'), present(counts.access)),
        row(w('managed.diff.rate_limit'), present(counts.rateLimit)),
      ),
      el('details', { class: 'tc-details' }, el('summary', {}, w('managed.detail.json')), el('pre', { class: 'tc-raw tc-mono tc-raw--tall' }, JSON.stringify(item.version, null, 2))),
      this.detailActions,
    );
    mount(this.detailBox, node);
    this.drawDetailLive();
    if (focus) heading.focus();
  }

  /** The part of the detail that follows the list: the states of the version and its button, as the list shows them now. */
  drawDetailLive() {
    const detail = this.detail;
    if (detail === null || detail.data === null) return;
    const item = this.items().find((one) => one.name === detail.name) ?? { name: detail.name, current: detail.data.current, serving: detail.data.serving };
    mount(this.detailStates, this.stateBadges(item));
    mount(this.detailActions, this.actions(item, true));
  }

  // ---- the list ----

  nameCell(item) {
    if (!versionActions(this.ctx.user.role, item, this.selected()).open) return fingerprintView(item.name, { copy: false });
    return el('a', { class: 'tc-link tc-mono', href: hashOf('managed', { id: item.name }), title: item.name }, `${shortOf(item.name)}…`);
  }

  stateNames(item) {
    const names = [];
    if (item.current === true) names.push('selected');
    if (item.serving === true) names.push('running');
    return names;
  }

  stateBadges(item) {
    const names = this.stateNames(item);
    return names.length === 0 ? null : el('span', { class: 'tc-badges' }, names.map((name) => badge(STATES[name].tone, STATES[name].words())));
  }

  /** The button of a version; it is the main button of a detail, and in a row it is an ordinary one. */
  actions(item, inDetail = false) {
    if (this.error !== null || !versionActions(this.ctx.user.role, item, this.selected()).apply) return null;
    return el('div', { class: 'tc-actions' }, button(inDetail ? 'primary' : 'small', w('managed.apply'), () => this.activate(item.name), { disabled: this.busy() }));
  }

  drawBody() {
    if (this.error !== null) {
      mount(this.notes, this.failure(w('managed.failed')));
      mount(this.stateBox);
      this.table.node.hidden = true;
      this.drawDetailLive();
      return;
    }
    if (this.data === null) {
      mount(this.notes, notice('info', w('managed.loading')));
      mount(this.stateBox);
      this.table.node.hidden = true;
      return;
    }
    if (this.data.state.managed !== true) {
      mount(this.notes, unusedNotice(this.ctx.user.role));
      mount(this.stateBox);
      this.table.node.hidden = true;
      this.drawDetailLive();
      return;
    }
    mount(this.notes, this.stateNotes());
    mount(this.stateBox, this.statePanel());
    this.table.node.hidden = false;
    this.table.update({ rows: this.items(), loading: false });
    this.drawDetailLive();
  }

  /** The notices of the state, each for one state of the store or of the proxy that the user should know of. */
  stateNotes() {
    const { state, file } = this.data;
    const proxy = proxyOf(state);
    return [
      this.selected() === null ? notice('warn', w('managed.none_selected_hint')) : null,
      proxy === 'unreachable' ? notice('bad', w('managed.proxy.unreachable')) : null,
      proxy === 'silent' ? notice('warn', w('managed.proxy.silent')) : null,
      proxy === 'unmanaged' ? notice('bad', w('managed.proxy.unmanaged')) : null,
      proxy === 'reloading' ? notice('info', w('managed.proxy.reloading')) : null,
      differs(state, this.watch.active) ? this.differNotice() : null,
      this.fileWaits() ? notice('warn', w('managed.file_waits')) : null,
      file?.refused ? notice('bad', w('managed.file_refused'), ' ', this.ctx.describe(file.refused)) : null,
    ];
  }

  differNotice() {
    const busy = this.busy();
    const may = canChange(this.ctx.user.role);
    return notice(
      'warn',
      w('managed.differ'),
      may
        ? [
            el('span', { class: 'tc-notice__next' }, w('managed.differ_next')),
            el(
              'div',
              { class: 'tc-actions' },
              button('small', w('managed.repair.apply'), () => this.repair('apply'), { disabled: busy }),
              button('small', w('managed.repair.choose'), () => this.repair('choose'), { disabled: busy }),
            ),
          ]
        : null,
    );
  }

  statePanel() {
    const { state } = this.data;
    const [tone, words] = PROXY[proxyOf(state)];
    const target = state.rollback_to;
    return panel(
      w('managed.state'),
      [],
      kv(
        row(w('managed.selected'), this.selected() === null ? w('managed.none_selected') : fingerprintView(state.current)),
        row(w('managed.running'), servingView(state)),
        row(w('managed.proxy'), badge(tone, words())),
        row(w('managed.rollback_to'), isFingerprint(target) ? [fingerprintView(target), ' ', el('a', { class: 'tc-link', href: hashOf('managed-history') }, w('managed.rollback_open'))] : w('managed.rollback_none')),
      ),
    );
  }

  // ---- the changes ----

  activate(name) {
    const selected = this.selected();
    this.propose({
      title: w('managed.apply.title'),
      what: w('managed.apply.what'),
      from: selected,
      to: name,
      confirm: w('managed.apply'),
      name: 'managed-activate',
      path: '/api/managed/activate',
      body: { expect: selected, version: name },
    });
  }

  /** Corrects a difference: `apply` puts the selected version in force again, `choose` selects the version that runs. */
  repair(mode) {
    const { current, serving } = this.data.state;
    const version = mode === 'apply' ? current : serving;
    this.propose({
      title: mode === 'apply' ? w('managed.repair.apply') : w('managed.repair.choose'),
      what: w('managed.repair.what'),
      note: mode === 'apply' ? w('managed.repair.apply_note') : w('managed.repair.choose_note'),
      from: serving,
      to: version,
      confirm: mode === 'apply' ? w('managed.repair.apply') : w('managed.repair.choose'),
      name: 'managed-activate',
      path: '/api/managed/activate',
      body: { expect: current, version },
    });
  }
}

// ---- the card of the overview ----

/** What the card of the overview says, from the answer of `GET /api/managed`, or `failed` when it could not be read. */
export function cardState(state) {
  if (state === null) return 'failed';
  if (isJob(state.job) && state.job.state === 'running') return 'job';
  if (!isFingerprint(state.current)) return 'none';
  const proxy = proxyOf(state);
  if (proxy === 'unmanaged') return 'unmanaged';
  if (proxy !== 'ok') return 'unknown';
  return state.current === state.serving ? 'same' : 'differ';
}

const CARD = {
  failed: ['bad', () => w('managed.card.failed')],
  job: ['info', () => w('managed.card.job')],
  none: ['warn', () => w('managed.none_selected')],
  unmanaged: ['bad', () => w('managed.card.unmanaged')],
  unknown: ['warn', () => w('managed.card.unknown')],
  same: ['ok', () => w('managed.card.same')],
  differ: ['warn', () => w('managed.card.differ')],
};

/**
 * The card of the overview: what the managed configuration is doing, read when the overview is opened and when it is
 * read again. `node` is the box that holds it, which the overview keeps when it draws itself again; the box is hidden
 * for a configuration without a managed object, and for an answer that is not understood.
 */
export function managedCard(ctx) {
  const node = el('div');
  node.hidden = true;
  let reads = 0;
  let alive = true;
  const draw = (state, failed) => {
    const shown = failed ? 'failed' : cardState(state);
    const [tone, words] = CARD[shown];
    mount(
      node,
      panel(
        w('managed.card.title'),
        [badge(tone, words())],
        failed ? null : kv(row(w('managed.selected'), isFingerprint(state.current) ? fingerprintView(state.current) : w('managed.none_selected')), row(w('managed.running'), servingView(state))),
        el('a', { class: 'tc-link', href: hashOf('managed') }, w('managed.card.open')),
      ),
    );
    node.hidden = false;
  };
  return {
    node,
    stop: () => {
      alive = false;
    },
    async read() {
      const asked = (reads += 1);
      let state = null;
      let failed = false;
      try {
        state = await ctx.api.call('GET', '/api/managed');
      } catch {
        failed = true;
      }
      if (!alive || asked !== reads) return;
      if (failed || state?.managed === true) {
        draw(state, failed);
      } else {
        mount(node);
        node.hidden = true;
      }
    },
  };
}

export const screens = [{ id: 'managed', title: w('nav.managed'), least: 'viewer', route: { id: isFingerprint }, mount: mountScreen(VersionsScreen) }, ...historyScreens];
