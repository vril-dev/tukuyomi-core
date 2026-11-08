// The history of the changes of the managed configuration, with the rollback, and the values of the configuration
// file. The values are the file as it is now, as the API shows it (its paths only say whether they are written), and
// may hold secrets of the upstreams, so they stay in this page's memory only while the screen is open. Nothing runs
// when the module is loaded.

import { badge, button, el, mount, notice } from '../dom.js';
import { lazy, w } from '../i18n.js';
import { canChange, fingerprintText, fingerprintView, hashOf, instantOf, isFingerprint, kv, panel, panelWith, row, shortOf, timeCell, timeCellText, timeLabel } from '../parts.js';
import { Table } from '../table.js';
import { kindText, resultBadge, resultText } from './job.js';
import { Screen, mountScreen, unusedNotice } from './screen.js';

/** Whether a user may roll back: the state names a version to go back to and a version that is selected, which the request must expect. */
export function mayRollBack(role, state) {
  return canChange(role) && isFingerprint(state?.rollback_to) && isFingerprint(state?.current);
}

class HistoryScreen extends Screen {
  constructor(ctx, root) {
    super(ctx, root, w('nav.managed_history'), w('managed.history.intro'));
    this.target = el('div');
    const may = canChange(ctx.user.role);
    const version = (key) => (entry) => {
      if (!isFingerprint(entry[key])) return fingerprintView(entry[key], { copy: false });
      return may ? el('a', { class: 'tc-link tc-mono', href: hashOf('managed', { id: entry[key] }), title: entry[key] }, `${shortOf(entry[key])}…`) : fingerprintView(entry[key], { copy: false });
    };
    this.table = new Table({
      caption: w('managed.history.caption'),
      rowKey: (entry, at) => String(at),
      empty: { title: w('managed.history.empty') },
      columns: [
        { key: 'ts', label: timeLabel(w('managed.col.time')), value: (entry) => instantOf(entry.ts), text: (entry) => timeCellText(entry.ts), tight: true, cell: (entry) => timeCell(entry.ts) },
        { key: 'kind', label: w('managed.col.kind'), value: (entry) => kindText(entry.kind), cell: (entry) => this.kindCell(entry) },
        { key: 'actor', label: w('managed.col.by'), value: (entry) => String(entry.actor) },
        { key: 'from', label: w('managed.col.from'), value: (entry) => entry.from ?? '', text: (entry) => fingerprintText(entry.from), mono: true, cell: version('from') },
        { key: 'to', label: w('managed.col.to'), value: (entry) => entry.to ?? '', text: (entry) => fingerprintText(entry.to), mono: true, cell: version('to') },
        { key: 'result', label: w('managed.col.result'), value: (entry) => String(entry.result), text: (entry) => resultText(entry.result), cell: (entry) => this.resultCell(entry) },
        { key: 'file', label: w('managed.col.file'), value: (entry) => (this.fileChanged(entry) ? 1 : 0), filter: false, cell: (entry) => (this.fileChanged(entry) ? badge('muted', w('managed.history.file_changed')) : '—') },
      ],
    });
    mount(this.body, this.target, this.table.node);
  }

  kindCell(entry) {
    return lazy(() => kindText(entry.kind));
  }

  resultCell(entry) {
    return el('span', { class: 'tc-actions' }, resultBadge(entry.result), typeof entry.reason === 'string' ? el('code', {}, entry.reason) : null);
  }

  fileChanged(entry) {
    return isFingerprint(entry.config_before) && isFingerprint(entry.config_after) && entry.config_before !== entry.config_after;
  }

  async read() {
    const { api } = this.ctx;
    const [state, lines, around] = await Promise.all([
      api.call('GET', '/api/managed').catch((error) => ({ failed: error })),
      api.call('GET', '/api/managed/history').catch((error) => ({ failed: error })),
      this.readAround(),
    ]);
    return { state: state.failed === undefined ? state : null, stateError: state.failed ?? null, lines, ...around };
  }

  /** Whether the configuration has no managed object: the state says so, or the history refused (the only 409 it gives). */
  unused() {
    return this.data.state?.managed === false || this.data.lines.failed?.status === 409;
  }

  drawBody() {
    if (this.data === null) {
      mount(this.target, notice('info', w('managed.loading')));
      this.table.update({ rows: [], loading: true });
      return;
    }
    if (this.unused()) {
      mount(this.target, unusedNotice(this.ctx.user.role));
      this.table.node.hidden = true;
      return;
    }
    const { lines } = this.data;
    if (lines.failed !== undefined) {
      mount(this.target, notice('bad', w('managed.history.failed'), ' ', this.ctx.describe(lines.failed)));
      this.table.node.hidden = true;
      return;
    }
    mount(this.target, this.stateNote());
    this.table.node.hidden = false;
    this.table.update({ rows: Array.isArray(lines.entries) ? lines.entries : [], loading: false });
  }

  /** The panel of the rollback, or why the state could not be read. */
  stateNote() {
    const { state, stateError } = this.data;
    if (stateError !== null) return notice('bad', w('managed.failed'), ' ', this.ctx.describe(stateError));
    return this.targetPanel(state);
  }

  targetPanel(state) {
    const target = state.rollback_to;
    return panelWith(
      w('managed.rollback.title'),
      [],
      isFingerprint(target) ? fingerprintView(target) : el('p', { class: 'tc-muted' }, w('managed.rollback_none')),
      isFingerprint(target) ? el('p', { class: 'tc-muted tc-small' }, w('managed.rollback.note')) : null,
      mayRollBack(this.ctx.user.role, state) ? el('div', { class: 'tc-actions' }, button('', w('managed.rollback.do'), () => this.rollback(state), { disabled: this.busy() })) : null,
    ).node;
  }

  rollback(state) {
    this.propose({
      title: w('managed.rollback.title'),
      what: w('managed.rollback.what'),
      from: state.current,
      to: state.rollback_to,
      confirm: w('managed.rollback.do'),
      tone: 'danger',
      name: 'managed-rollback',
      path: '/api/managed/rollback',
      body: { expect: state.current },
    });
  }
}

// ---- the values of the configuration file ----

// The tone and the words of how the file on the disk compares with what the running proxy has read.
const COMPARED = {
  same: ['ok', () => w('managed.config.same')],
  waits: ['warn', () => w('managed.config.waits')],
  unknown: ['muted', () => w('managed.unknown')],
};

/** The depth of the values that is drawn; what is deeper is shown as `…`. */
const TREE_DEPTH = 16;

/**
 * The drawing of a value of the configuration file: an object as a list of its keys and values, an array as a list
 * numbered from 1 (which is how the refusals of the proxy number a place in the file), a text in monospace, `null` as
 * a dash. `depth` counts the steps down from the value that was given.
 */
export function valueTree(value, depth = 1) {
  if (depth > TREE_DEPTH) return el('span', { class: 'tc-muted' }, '…');
  if (value === null || value === undefined) return el('span', { class: 'tc-muted' }, '—');
  if (Array.isArray(value)) {
    return value.length === 0 ? el('code', {}, '[]') : kv(value.map((entry, at) => row(String(at + 1), valueTree(entry, depth + 1))));
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value);
    return keys.length === 0 ? el('code', {}, '{}') : kv(keys.map((key) => row(el('code', {}, key), valueTree(value[key], depth + 1))));
  }
  return el('code', {}, String(value));
}

class ConfigScreen extends Screen {
  constructor(ctx, root) {
    super(ctx, root, w('nav.config'), w('managed.config.intro'));
  }

  stop() {
    super.stop();
    this.data = null;
    mount(this.body);
  }

  async read() {
    const { api } = this.ctx;
    const [file, status] = await Promise.all([api.call('GET', '/api/config'), api.call('GET', '/api/status').catch(() => null)]);
    return { file, status };
  }

  /** How the file on the disk compares with what the running proxy has read: `same`, `waits` or `unknown`. */
  compared() {
    const { file, status } = this.data;
    const read = status?.proxy?.config;
    if (!isFingerprint(file.sha256) || !isFingerprint(read)) return 'unknown';
    return file.sha256 === read ? 'same' : 'waits';
  }

  drawBody() {
    if (this.error !== null) {
      mount(this.body, this.failure(w('managed.config.failed')));
      return;
    }
    if (this.data === null) {
      mount(this.body, notice('info', w('managed.loading')));
      return;
    }
    const { file } = this.data;
    const [tone, words] = COMPARED[this.compared()];
    mount(
      this.body,
      panel(
        w('managed.config.title'),
        [],
        kv(
          row(w('managed.config.sha'), fingerprintView(file.sha256)),
          row(w('managed.config.compare'), badge(tone, words())),
          row(w('managed.config.managed'), file.managed === true ? w('managed.config.managed_yes') : w('managed.config.managed_no')),
        ),
        el('p', { class: 'tc-muted tc-small' }, w('managed.config.paths')),
      ),
      Object.keys(file)
        .filter((key) => key !== 'sha256' && key !== 'managed')
        .map((key) => panel(key, [], valueTree(file[key]))),
    );
  }
}

export const screens = [
  { id: 'managed-history', title: w('nav.managed_history'), least: 'viewer', mount: mountScreen(HistoryScreen) },
  { id: 'config', title: w('nav.config'), least: 'operator', mount: mountScreen(ConfigScreen) },
];
