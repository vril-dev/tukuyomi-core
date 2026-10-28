// The screens of the lines that the proxy and the admin process write: the records of the proxy, which the user
// searches by filters and reads page after page, and the audit log. Every value of a line is shown as text, as the
// API gives it: what came from a request is still in the `%XX` form the proxy wrote, and a decoded view is a second
// text beside it, with every control character made visible. The screens read when they are opened and when the
// user asks; nothing is polled. A screen is `{ id, title, least, mount }`; `mount(ctx, root)` draws into `root` and
// gives back a function that undoes what it set up. Nothing runs when the module is loaded.

import { badge, el, mount, notice } from './dom.js';
import { t } from './i18n.js';
import { labelled, nextId, openSheet, pageHead, row, table } from './parts.js';

/** The types of record there are. */
export const TYPES = ['request', 'connection', 'tunnel', 'line', 'audit', 'dropped'];
const FIELDS = ['from', 'to', 'type', 'class', 'status', 'rule', 'id', 'client', 'generation'];
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
/** The names of the filters, for the screen. */
const LABELS = {
  from: () => t('records.f.from'),
  to: () => t('records.f.to'),
  type: () => t('records.f.type'),
  class: () => t('records.f.class'),
  status: () => t('records.f.status'),
  rule: () => t('records.f.rule'),
  id: () => t('records.f.id'),
  client: () => t('records.f.client'),
  generation: () => t('records.f.generation'),
};
/** The forms of the filters, as the API takes them (it checks them again, and the dates in full). */
const CHECKS = {
  from: (value) => TIME.test(value),
  to: (value) => TIME.test(value),
  type: (value) => TYPES.includes(value),
  class: (value) => /^[a-z0-9_-]{1,32}$/.test(value),
  status: (value) => /^\d{1,3}$/.test(value),
  rule: (value) => /^-?\d{1,19}$/.test(value),
  id: (value) => /^[0-9a-f-]{1,40}$/.test(value),
  client: (value) => value.length <= 45 && /^[0-9a-fA-F:.]+$/.test(value),
  generation: (value) => /^([0-9a-f]{16}|[0-9a-f]{64})$/.test(value),
};

/**
 * The query of a search: `values` are the filters as the user typed them (blank ones are left out), `start` is the
 * continuation of an earlier answer (`{ file, offset, inode }`) or null. Gives `{ query, problems }`: the query
 * string, and the names of the filters whose form is wrong (then the query must not be sent).
 */
export function buildQuery(values, start = null) {
  const parts = [];
  const problems = [];
  for (const field of FIELDS) {
    const value = String(values[field] ?? '').trim();
    if (value === '') continue;
    if (CHECKS[field](value)) parts.push(`${field}=${encodeURIComponent(value)}`);
    else problems.push(field);
  }
  if (start !== null) {
    for (const field of ['file', 'offset', 'inode']) parts.push(`${field}=${encodeURIComponent(String(start[field]))}`);
  }
  return { query: parts.join('&'), problems };
}

/**
 * Where the pages of one search start. An answer that stopped at a limit before the records ended gives the
 * continuation, where the next page starts; the pager keeps the start of every page it went through, so the user can
 * go back (`newer`) as well as on (`older`). The first page has no start.
 */
export class Pager {
  #starts = [null];
  #at = 0;
  #next = null;

  /** The continuation to ask the current page with, or null for the first page. */
  get start() {
    return this.#starts[this.#at];
  }

  /** The number of the current page, from 1. */
  get page() {
    return this.#at + 1;
  }

  get hasNewer() {
    return this.#at > 0;
  }

  get hasOlder() {
    return this.#next !== null;
  }

  /** The current page was read; `next` is the continuation its answer gave (null or undefined for none). */
  arrived(next) {
    this.#next = next ?? null;
  }

  /** Goes to the page after the current one; false when the answer gave no continuation. */
  older() {
    if (this.#next === null) return false;
    this.#starts[this.#at + 1] = this.#next;
    this.#starts.length = this.#at + 2;
    this.#at += 1;
    this.#next = null;
    return true;
  }

  /** Goes back to the page before the current one; false on the first page. */
  newer() {
    if (this.#at === 0) return false;
    this.#at -= 1;
    this.#next = null;
    return true;
  }

  reset() {
    this.#starts = [null];
    this.#at = 0;
    this.#next = null;
  }
}

/** The text of any value of a line: a string as it is, a number or a flag by its digits or word, the rest as JSON. */
export function textOf(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

/**
 * `value` with every run of `%XX` read as the bytes of UTF-8 text, as a URL is decoded. A run that is not UTF-8 stays
 * as it was written. Control and format characters (line breaks, the marks that turn the direction of the text, and
 * the like) are written as `\xNN` or `\u{NNNN}`, so that what is shown cannot be made to look like something else.
 */
export function decodeText(value) {
  // The byte order mark is kept in the text, so that it is shown like the other format characters and not dropped.
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const decoded = value.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    const bytes = Uint8Array.from(run.match(/[0-9A-Fa-f]{2}/g), (pair) => Number.parseInt(pair, 16));
    try {
      return decoder.decode(bytes);
    } catch {
      return run;
    }
  });
  return decoded.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (char) => {
    const code = char.codePointAt(0);
    return code < 256 ? `\\x${code.toString(16).toUpperCase().padStart(2, '0')}` : `\\u{${code.toString(16).toUpperCase()}}`;
  });
}

/** One line of text that says what a record is about. */
export function summaryOf(record) {
  const text = (key) => textOf(record[key]);
  switch (record.type) {
    case 'request':
      return `${text('method')} ${text('host')}${text('path')}`.trim();
    case 'line':
      return text('line');
    case 'audit':
      return [text('action'), text('result'), text('target')].filter((word) => word !== '').join(' ');
    case 'tunnel':
      return text('end');
    case 'connection':
      return text('reason');
    case 'dropped':
      return text('count');
    default:
      return '';
  }
}

function ruleOf(record) {
  if (record.rule !== undefined) return textOf(record.rule);
  return Array.isArray(record.rules) ? record.rules.join(', ') : '';
}

const RESULTS = { ok: 'ok', denied: 'warn', failed: 'bad' };

class RecordsScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.alive = true;
    this.reads = 0;
    this.pager = new Pager();
    /** The filters of the search that is shown, which paging and reloading keep. */
    this.applied = {};
    this.loading = false;
    this.inputs = {};
    const typeSelect = el('select', {}, [el('option', { value: '' }, t('records.any')), ...TYPES.map((type) => el('option', { value: type }, type))]);
    this.inputs.type = typeSelect;
    const fields = FIELDS.map((field) => {
      const control = field === 'type' ? typeSelect : el('input', { class: 'input', type: 'text', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
      this.inputs[field] = control;
      return labelled(LABELS[field](), control, field === 'from' || field === 'to' ? t('records.time_hint') : null);
    });
    this.problems = el('div', { 'aria-live': 'polite' });
    this.search = el('button', { type: 'submit', class: 'btn btn-primary' }, t('records.search'));
    this.reload = el('button', { type: 'button', class: 'btn', on: { click: () => this.load() } }, t('screen.reload'));
    this.clear = el('button', { type: 'button', class: 'btn', on: { click: () => this.clearFilters() } }, t('records.clear'));
    this.body = el('div', { class: 'stack' });
    this.layer = el('div');
    const form = el(
      'form',
      {
        class: 'stack',
        on: {
          submit: (event) => {
            event.preventDefault();
            this.find();
          },
        },
      },
      el('div', { class: 'filters' }, fields),
      this.problems,
      el('div', { class: 'actions' }, this.search, this.clear),
    );
    mount(root, el('div', { class: 'stack' }, pageHead(t('records.title'), this.reload), el('p', { class: 'muted' }, t('records.intro')), form, this.body), this.layer);
  }

  stop() {
    this.alive = false;
  }

  values() {
    return Object.fromEntries(FIELDS.map((field) => [field, this.inputs[field].value]));
  }

  clearFilters() {
    for (const field of FIELDS) this.inputs[field].value = '';
    mount(this.problems);
  }

  /** A new search with the filters as they are typed now, from the newest record. */
  find() {
    const { problems } = buildQuery(this.values());
    if (problems.length > 0) {
      mount(this.problems, notice('bad', t('records.bad_filters', { names: problems.map((field) => LABELS[field]()).join(', ') })));
      return;
    }
    mount(this.problems);
    this.applied = this.values();
    this.pager.reset();
    this.load();
  }

  async load() {
    const asked = (this.reads += 1);
    const { query } = buildQuery(this.applied, this.pager.start);
    this.loading = true;
    this.sync();
    let answer = null;
    let error = null;
    try {
      answer = await this.ctx.api.call('GET', query === '' ? '/api/records' : `/api/records?${query}`);
    } catch (failure) {
      error = failure;
    }
    if (!this.alive || asked !== this.reads) return;
    this.loading = false;
    this.pager.arrived(error === null && typeof answer.next === 'object' ? answer.next : null);
    this.sync();
    this.draw(answer, error);
  }

  sync() {
    this.reload.disabled = this.loading;
    this.search.disabled = this.loading;
    this.reload.setAttribute('aria-busy', String(this.loading));
    if (this.loading) mount(this.body, notice('info', t('records.loading')));
  }

  go(move) {
    if (move()) this.load();
  }

  draw(answer, error) {
    if (error !== null) {
      const gone = error.kind === 'conflict';
      mount(
        this.body,
        notice(gone ? 'warn' : error.status === 404 ? 'info' : 'bad', this.ctx.describe(error)),
        gone
          ? el('div', { class: 'actions' }, el('button', { type: 'button', class: 'btn', on: { click: () => this.find() } }, t('records.restart')))
          : null,
      );
      return;
    }
    const records = Array.isArray(answer.records) ? answer.records : [];
    const more = this.pager.hasOlder;
    mount(
      this.body,
      this.pagerView(records.length),
      records.length === 0
        ? notice('info', more ? t('records.searched') : t('records.empty'))
        : table(
            [t('col.time'), LABELS.type(), LABELS.client(), LABELS.class(), LABELS.status(), LABELS.rule(), t('records.summary'), t('col.actions')],
            records.map((record) => this.rowOf(record)),
            t('records.title'),
            { tight: [0, 1, 2, 3, 4, 5], wide: [6] },
          ),
      records.length === 0 ? null : this.pagerView(records.length),
    );
  }

  pagerView(count) {
    return el(
      'div',
      { class: 'pager' },
      el('span', { class: 'muted' }, t('records.page', { page: this.pager.page, n: count })),
      el('button', { type: 'button', class: 'btn', disabled: !this.pager.hasNewer, on: { click: () => this.go(() => this.pager.newer()) } }, t('records.newer')),
      el('button', { type: 'button', class: 'btn', disabled: !this.pager.hasOlder, on: { click: () => this.go(() => this.pager.older()) } }, t('records.older')),
    );
  }

  rowOf(record) {
    const open = el('button', { type: 'button', class: 'btn btn-small', on: { click: () => this.openDetail(record) } }, t('records.open'));
    return [
      textOf(record.ts),
      textOf(record.type),
      textOf(record.client),
      textOf(record.class),
      textOf(record.status),
      ruleOf(record),
      summaryOf(record),
      open,
    ];
  }

  /** The sheet of one line: every field as text, and on request the text with the `%XX` read. */
  openDetail(record) {
    const list = el('div');
    const draw = (decoded) => {
      mount(
        list,
        el(
          'dl',
          { class: 'kv' },
          Object.entries(record).map(([key, value]) => {
            const text = textOf(value);
            const readable = decoded && typeof value === 'string' ? decodeText(text) : text;
            return row(key, [text, readable === text ? null : el('div', { class: 'muted small' }, t('records.decoded'), ' ', readable)]);
          }),
        ),
      );
    };
    const id = nextId('w');
    const toggle = el('input', { id, type: 'checkbox', on: { change: () => draw(toggle.checked) } });
    openSheet(
      this.layer,
      t('records.detail'),
      el('label', { class: 'check', for: id }, toggle, el('span', {}, t('records.decode'))),
      list,
      el('details', {}, el('summary', {}, t('records.json')), el('pre', { class: 'raw' }, JSON.stringify(record, null, 2))),
    );
    draw(false);
  }
}

class AuditScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.alive = true;
    this.reads = 0;
    this.reload = el('button', { type: 'button', class: 'btn', on: { click: () => this.load() } }, t('screen.reload'));
    this.body = el('div', { class: 'stack' });
    mount(root, el('div', { class: 'stack' }, pageHead(t('audit.title'), this.reload), el('p', { class: 'muted' }, t('audit.intro')), this.body));
  }

  stop() {
    this.alive = false;
  }

  async load() {
    const asked = (this.reads += 1);
    this.reload.disabled = true;
    mount(this.body, notice('info', t('records.loading')));
    let entries = null;
    let error = null;
    try {
      const answer = await this.ctx.api.call('GET', '/api/audit');
      entries = Array.isArray(answer.entries) ? answer.entries : [];
    } catch (failure) {
      error = failure;
    }
    if (!this.alive || asked !== this.reads) return;
    this.reload.disabled = false;
    if (error !== null) {
      mount(this.body, notice('bad', t('audit.failed'), ' ', this.ctx.describe(error)));
      return;
    }
    mount(
      this.body,
      entries.length === 0
        ? notice('info', t('audit.empty'))
        : table(
            [t('col.time'), t('col.by'), t('audit.action'), t('audit.target'), t('col.result'), LABELS.client(), t('audit.change'), t('audit.request')],
            entries.map((entry) => [
              textOf(entry.ts),
              textOf(entry.actor),
              textOf(entry.action),
              textOf(entry.target),
              el('span', {}, badge(Object.hasOwn(RESULTS, entry.result) ? RESULTS[entry.result] : 'muted', textOf(entry.result)), entry.reason === undefined ? null : [' ', textOf(entry.reason)]),
              textOf(entry.client),
              entry.before === undefined && entry.after === undefined ? '' : `${textOf(entry.before)} → ${textOf(entry.after)}`,
              textOf(entry.id),
            ]),
            t('audit.title'),
            { tight: [0, 1, 2, 4, 5], wide: [3, 6, 7] },
          ),
    );
  }
}

function mountWith(Kind) {
  return (ctx, root) => {
    const screen = new Kind(ctx, root);
    screen.load();
    return () => screen.stop();
  };
}

export const screens = [
  { id: 'records', title: () => t('nav.records'), least: 'viewer', mount: mountWith(RecordsScreen) },
  { id: 'audit', title: () => t('nav.audit'), least: 'operator', mount: mountWith(AuditScreen) },
];
