// The screens of the lines that the proxy and the admin process write: the records of the proxy, which the user
// searches by filters and reads page after page, and the audit log. Every value of a line is shown as text, as the
// API gives it: what came from a request is still in the `%XX` form the proxy wrote, and a decoded view is a second
// text beside it, with every control character made visible. A search and one record have addresses of their own
// (`#/records?status=403`, `#/records/<request number>`). The screens read when they are opened and when the user asks;
// nothing is polled. A screen is `{ id, title, least, mount }`; `mount(ctx, root, route)` draws into `root` and gives
// back `{ stop, show }`. Nothing runs when the module is loaded.

import { badge, button, buttonClass, el, mount, notice } from './dom.js';
import { w } from './i18n.js';
import { Field, checkFields, checkbox, choice, fingerprintView, hashOf, instantOf, kv, pageHead, panelWith, restoreFocus, row, textInput, timeView } from './parts.js';
import { Table } from './table.js';

/** The types of record there are. */
export const TYPES = ['request', 'connection', 'tunnel', 'line', 'audit', 'dropped'];
const FIELDS = ['from', 'to', 'type', 'class', 'status', 'rule', 'id', 'client', 'generation'];
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
/** The names of the filters, for the screen. */
const LABELS = {
  from: () => w('records.f.from'),
  to: () => w('records.f.to'),
  type: () => w('records.f.type'),
  class: () => w('records.f.class'),
  status: () => w('records.f.status'),
  rule: () => w('records.f.rule'),
  id: () => w('records.f.id'),
  client: () => w('records.f.client'),
  generation: () => w('records.f.generation'),
};
/** What to write when a filter is not of its form. */
const PROBLEMS = {
  from: () => w('records.p_time'),
  to: () => w('records.p_time'),
  type: () => w('records.p_type'),
  class: () => w('records.p_class'),
  status: () => w('records.p_status'),
  rule: () => w('records.p_rule'),
  id: () => w('records.p_id'),
  client: () => w('records.p_client'),
  generation: () => w('records.p_generation'),
};
/** The forms of the filters, as the API takes them (it checks them again, and the dates in full). */
export const CHECKS = {
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
/** The words of each class of a request record, and the tone of its badge. A class that is not here is shown as the API gave it. */
const CLASSES = {
  forwarded: ['ok', () => w('records.class.forwarded')],
  blocked: ['bad', () => w('records.class.blocked')],
  rejected: ['warn', () => w('records.class.rejected')],
  redirected: ['muted', () => w('records.class.redirected')],
  answered: ['muted', () => w('records.class.answered')],
  failed: ['bad', () => w('records.class.failed')],
  closed: ['muted', () => w('records.class.closed')],
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

/** The class of a record as a badge: in words, with the tone of what it came to. Nothing for a record that has none. */
function classBadge(record) {
  if (record.class === undefined) return null;
  const known = Object.hasOwn(CLASSES, record.class);
  return badge(known ? CLASSES[record.class][0] : 'muted', known ? CLASSES[record.class][1]() : textOf(record.class));
}

const sameQuery = (a, b) => FIELDS.every((field) => (a[field] ?? '') === (b[field] ?? ''));

class RecordsScreen {
  constructor(ctx, root, route) {
    this.ctx = ctx;
    this.root = root;
    this.alive = true;
    this.reads = 0;
    this.pager = new Pager();
    /** The filters of the search that is shown, which paging and reloading keep. */
    this.applied = {};
    this.route = { id: null, query: {} };
    this.records = [];
    this.loaded = false;
    this.loading = false;
    this.error = null;
    /** The record that is open: `{ id, record, error }`, or null. */
    this.open = null;
    /** Where the table lands when a part of the records that the user paged to arrives: `first` or `last`. */
    this.edgeFrom = null;

    const typeSelect = el('select', { class: 'tc-select', name: 'type' }, [el('option', { value: '' }, w('records.any')), ...TYPES.map((type) => el('option', { value: type }, type))]);
    this.fields = Object.fromEntries(
      FIELDS.map((field) => {
        const control = field === 'type' ? typeSelect : textInput({ name: field, autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
        return [field, new Field(LABELS[field](), control, { hint: field === 'from' || field === 'to' ? w('records.time_hint') : null })];
      }),
    );
    this.reload = button('', w('screen.reload'), () => this.load());
    this.search = button('primary', w('records.search'), null, { type: 'submit' });
    this.terms = el('span', { class: 'tc-terms' });
    this.filters = el(
      'details',
      { class: 'tc-panel tc-details' },
      el('summary', {}, w('records.filters'), ' ', this.terms),
      el(
        'form',
        {
          class: 'tc-stack',
          novalidate: true,
          on: {
            submit: (event) => {
              event.preventDefault();
              this.submit();
            },
          },
        },
        el('div', { class: 'tc-filters' }, FIELDS.map((field) => this.fields[field].node)),
        el('div', { class: 'tc-actions' }, this.search, button('quiet', w('records.clear'), () => this.clear())),
      ),
    );
    this.notes = el('div', { class: 'tc-stack' });
    this.detailBox = el('div');
    this.table = new Table({
      caption: w('records.title'),
      rowKey: (record, at) => String(at),
      empty: { title: w('records.empty') },
      columns: [
        { key: 'ts', label: w('col.time'), value: (record) => instantOf(record.ts), tight: true, cell: (record) => timeView(record.ts) },
        { key: 'type', label: LABELS.type(), value: (record) => textOf(record.type) },
        { key: 'class', label: w('col.result'), value: (record) => textOf(record.class), cell: classBadge },
        { key: 'status', label: LABELS.status(), value: (record) => (typeof record.status === 'number' ? record.status : null), num: true, cell: (record) => textOf(record.status) },
        { key: 'rule', label: LABELS.rule(), value: (record) => ruleOf(record), mono: true },
        { key: 'client', label: LABELS.client(), value: (record) => textOf(record.client), mono: true },
        { key: 'summary', label: w('records.summary'), value: (record) => summaryOf(record), mono: true },
        { key: 'id', label: LABELS.id(), value: (record) => textOf(record.id), sortable: false, mono: true, cell: (record) => this.openLink(record) },
      ],
    });
    mount(root, pageHead(w('records.title'), this.reload), el('p', { class: 'tc-intro' }, w('records.intro')), this.filters, this.notes, this.detailBox, this.table.node);
    this.drawTerms();
    this.show(route, true);
  }

  stop() {
    this.alive = false;
  }

  // ---- the address ----

  /** The address changed inside the screen: a new search if the filters differ, and the record it names, if any. */
  show(route, first = false) {
    const searched = first || !sameQuery(route.query, this.applied);
    const previous = this.open?.id ?? null;
    this.route = route;
    if (searched) {
      this.applied = route.query;
      for (const field of FIELDS) {
        this.fields[field].control.value = route.query[field] ?? '';
        this.fields[field].valid();
      }
      this.drawTerms();
      this.pager.reset();
      this.load();
    }
    if (route.id === null) {
      this.open = null;
      mount(this.detailBox);
      this.table.update({ selected: null });
      if (!first && previous !== null && !this.table.focusRow(this.rowOf(previous))) this.root.querySelector('h1')?.focus();
    } else if (route.id !== previous) {
      this.openRecord(route.id, !first);
    }
  }

  /** The place in the list of the first record with the request number `id`, as the key of its row. */
  rowOf(id) {
    return String(this.records.findIndex((record) => record.id === id));
  }

  openLink(record) {
    if (typeof record.id !== 'string' || !CHECKS.id(record.id)) {
      return button('small', w('records.open'), () => this.showLocal(record));
    }
    return el('a', { class: 'tc-link tc-mono', href: hashOf('records', { id: record.id, query: this.applied }) }, record.id);
  }

  /** A record that has no request number has no address, so it is opened here only. */
  showLocal(record) {
    this.open = { id: null, record, error: null };
    this.table.update({ selected: String(this.records.indexOf(record)) });
    this.drawDetail(true);
  }

  /** Closes a record that has no address: no change of the address says so, so the screen does. `focus` puts the focus back on its row. */
  closeLocal(focus = true) {
    const key = this.table.selected;
    this.open = null;
    mount(this.detailBox);
    this.table.update({ selected: null });
    if (focus && (key === null || !this.table.focusRow(key))) this.root.querySelector('h1')?.focus();
  }

  async openRecord(id, focus) {
    const open = { id, record: this.records.find((record) => record.id === id) ?? null, error: null };
    this.open = open;
    this.table.update({ selected: this.rowOf(id) });
    if (open.record === null) {
      this.drawDetail(false);
      try {
        const answer = await this.ctx.api.call('GET', `/api/records?${buildQuery({ id }).query}`);
        open.record = Array.isArray(answer.records) && answer.records.length > 0 ? answer.records[0] : null;
        open.missing = open.record === null;
      } catch (error) {
        open.error = error;
      }
      if (!this.alive || this.open !== open) return;
    }
    this.drawDetail(focus);
  }

  // ---- the search ----

  submit() {
    const values = Object.fromEntries(FIELDS.map((field) => [field, this.fields[field].control.value.trim()]));
    const entries = FIELDS.map((field) => [this.fields[field], values[field] === '' || CHECKS[field](values[field]) ? null : PROBLEMS[field]()]);
    if (!checkFields(entries)) return;
    const query = Object.fromEntries(FIELDS.filter((field) => values[field] !== '').map((field) => [field, values[field]]));
    this.go(hashOf('records', { query }));
  }

  clear() {
    this.go(hashOf('records'));
  }

  /** Goes to the address of a search; when the user is there already, the search is made again. */
  go(hash) {
    if (hash === hashOf('records', { id: this.route.id, query: this.route.query })) {
      this.pager.reset();
      this.load();
    } else {
      this.ctx.navigate(hash);
    }
  }

  drawTerms() {
    const entries = FIELDS.filter((field) => (this.applied[field] ?? '') !== '');
    mount(this.terms, entries.map((field) => el('span', { class: 'tc-badge tc-badge--plain' }, LABELS[field](), '=', this.applied[field])));
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
    this.loaded = true;
    this.error = error;
    this.pager.arrived(error === null && typeof answer.next === 'object' ? answer.next : null);
    this.records = error === null && Array.isArray(answer.records) ? answer.records : [];
    // A record that has no address is not among the rows that were read now: what it showed is old.
    if (this.open?.id === null) this.closeLocal(false);
    this.sync(this.edgeFrom ?? 'first');
    this.edgeFrom = null;
    if (this.open?.id) this.table.update({ selected: this.rowOf(this.open.id) });
    restoreFocus(this.root, this.root.querySelector('h1'));
  }

  sync(landOn = null) {
    this.reload.disabled = this.loading;
    this.search.disabled = this.loading;
    this.reload.setAttribute('aria-busy', String(this.loading));
    const more = this.pager.hasOlder;
    this.table.empty = { title: more ? w('records.searched_title') : w('records.empty'), hint: more ? w('records.searched') : w('records.empty_hint') };
    this.table.update({
      rows: this.records,
      loading: this.loading && !this.loaded,
      landOn,
      edges: {
        before: this.pager.hasNewer ? () => this.page(() => this.pager.newer(), 'last') : null,
        after: more ? () => this.page(() => this.pager.older(), 'first') : null,
        note: more ? w('records.more') : null,
      },
    });
    this.drawNotes();
  }

  drawNotes() {
    const error = this.error;
    if (error === null) {
      mount(this.notes);
      return;
    }
    const gone = error.kind === 'conflict';
    mount(
      this.notes,
      notice(gone ? 'warn' : error.status === 404 ? 'info' : 'bad', this.ctx.describe(error)),
      gone ? button('', w('records.restart'), () => this.restart()) : null,
    );
  }

  restart() {
    this.pager.reset();
    this.load();
  }

  /** Reads the next or the previous part of the records; the table lands on its first or last page. */
  page(move, landOn) {
    if (this.loading || !move()) return;
    this.edgeFrom = landOn;
    this.load();
  }

  // ---- one record ----

  /** What a record is about, first: its result, the rule, the score, the time, the client and the way. */
  summary(record) {
    const lines = [];
    if (record.class !== undefined || record.status !== undefined) {
      lines.push(row(w('col.result'), el('span', { class: 'tc-actions' }, classBadge(record), record.status === undefined ? null : el('span', { class: 'tc-mono' }, textOf(record.status)), record.reason === undefined ? null : el('span', { class: 'tc-muted' }, textOf(record.reason)))));
    }
    if (ruleOf(record) !== '') lines.push(row(w('records.f.rule'), el('span', { class: 'tc-mono' }, ruleOf(record))));
    if (record.score !== undefined) lines.push(row(w('records.score'), el('span', { class: 'tc-mono' }, textOf(record.score))));
    lines.push(row(w('col.time'), timeView(record.ts)));
    if (record.client !== undefined) lines.push(row(w('records.f.client'), el('span', { class: 'tc-mono' }, textOf(record.client))));
    if (record.method !== undefined || record.path !== undefined) {
      lines.push(row(w('records.way'), el('span', { class: 'tc-mono' }, `${textOf(record.method)} ${textOf(record.host)}${textOf(record.path)}`.trim())));
    } else if (summaryOf(record) !== '') {
      lines.push(row(w('records.summary'), el('span', { class: 'tc-mono' }, summaryOf(record))));
    }
    if (typeof record.generation === 'string') lines.push(row(w('records.f.generation'), fingerprintView(record.generation, { copy: false })));
    return lines;
  }

  drawDetail(focus) {
    const open = this.open;
    if (open === null) return;
    const close =
      open.id === null
        ? button('quiet small', w('records.back'), () => this.closeLocal())
        : el('a', { class: buttonClass('quiet small'), href: hashOf('records', { query: this.applied }) }, w('records.back'));
    if (open.record === null) {
      const words = open.error !== null ? notice('bad', this.ctx.describe(open.error)) : open.missing ? notice('warn', w('records.missing')) : notice('info', w('records.loading'));
      mount(this.detailBox, panelWith(w('records.detail'), [close], words).node);
      return;
    }
    const record = open.record;
    const list = el('div');
    const draw = (decoded) => {
      mount(
        list,
        kv(
          ...Object.entries(record).map(([key, value]) => {
            const text = textOf(value);
            const readable = decoded && typeof value === 'string' ? decodeText(text) : text;
            return row(key, [text, readable === text ? null : el('div', { class: 'tc-muted tc-small' }, w('records.decoded'), ' ', readable)]);
          }),
        ),
      );
    };
    const toggle = checkbox((checked) => draw(checked));
    const { node, heading } = panelWith(
      w('records.detail'),
      [close],
      kv(...this.summary(record)),
      el(
        'details',
        { class: 'tc-details' },
        el('summary', {}, w('records.all')),
        el('div', { class: 'tc-stack' }, choice(w('records.decode'), toggle), list),
      ),
      el('details', { class: 'tc-details' }, el('summary', {}, w('records.json')), el('pre', { class: 'tc-raw' }, JSON.stringify(record, null, 2))),
    );
    draw(false);
    mount(this.detailBox, node);
    if (focus) heading.focus();
  }
}

// ---- the audit log ----

const RESULTS = { ok: 'ok', denied: 'warn', failed: 'bad' };

class AuditScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.root = root;
    this.alive = true;
    this.reads = 0;
    this.reload = button('', w('screen.reload'), () => this.load());
    this.notes = el('div', { class: 'tc-stack' });
    this.table = new Table({
      caption: w('audit.title'),
      rowKey: (entry, at) => String(at),
      empty: { title: w('audit.empty') },
      columns: [
        { key: 'ts', label: w('col.time'), value: (entry) => instantOf(entry.ts), tight: true, cell: (entry) => timeView(entry.ts) },
        { key: 'actor', label: w('col.by'), value: (entry) => textOf(entry.actor) },
        { key: 'action', label: w('audit.action'), value: (entry) => textOf(entry.action), mono: true },
        { key: 'target', label: w('audit.target'), value: (entry) => textOf(entry.target), mono: true },
        {
          key: 'result',
          label: w('col.result'),
          value: (entry) => `${textOf(entry.result)} ${textOf(entry.reason)}`,
          cell: (entry) => el('span', { class: 'tc-actions' }, badge(Object.hasOwn(RESULTS, entry.result) ? RESULTS[entry.result] : 'muted', textOf(entry.result)), entry.reason === undefined ? null : el('span', {}, textOf(entry.reason))),
        },
        { key: 'client', label: w('records.f.client'), value: (entry) => textOf(entry.client), mono: true },
        { key: 'change', label: w('audit.change'), value: (entry) => (entry.before === undefined && entry.after === undefined ? '' : `${textOf(entry.before)} → ${textOf(entry.after)}`) },
        { key: 'id', label: w('audit.request'), value: (entry) => textOf(entry.id), mono: true },
      ],
    });
    mount(root, pageHead(w('audit.title'), this.reload), el('p', { class: 'tc-intro' }, w('audit.intro')), this.notes, this.table.node);
  }

  stop() {
    this.alive = false;
  }

  async load() {
    const asked = (this.reads += 1);
    this.reload.disabled = true;
    this.table.update({ loading: true });
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
    mount(this.notes, error === null ? null : notice('bad', w('audit.failed'), ' ', this.ctx.describe(error)));
    this.table.update({ rows: entries ?? [], loading: false });
    this.table.node.hidden = error !== null;
  }
}

function mountWith(Kind) {
  return (ctx, root, route) => {
    const screen = new Kind(ctx, root, route);
    if (Kind !== RecordsScreen) screen.load();
    return { stop: () => screen.stop(), show: (next) => screen.show?.(next) };
  };
}

export const screens = [
  { id: 'records', title: w('nav.records'), least: 'viewer', route: { id: CHECKS.id, query: CHECKS }, mount: mountWith(RecordsScreen) },
  { id: 'audit', title: w('nav.audit'), least: 'operator', mount: mountWith(AuditScreen) },
];
