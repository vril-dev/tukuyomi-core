// The table that every list of the page uses: sorting by a column, filtering by text on the screen, paging the rows
// that were received 50 at a time, a state for an empty list and one for a list that is being read, and on a narrow
// screen a row that is one box (the cells are named by `data-label`). The rules of sorting, filtering and paging are
// plain functions, `sortRows`, `filterRows` and `pageOf`; `Table` draws what they give. A list that the server reads
// in parts (the records) hangs the buttons that read the parts on the ends of the pager (`edges`: each gives the
// promise of its read). Nothing runs when the module is loaded.

import { button, el, mount } from './dom.js';
import { formatNumber, lazy, t, w } from './i18n.js';

/** The rows of a page. */
export const PAGE_SIZE = 50;

const missing = (value) => value === null || value === undefined || value === '' || (typeof value === 'number' && Number.isNaN(value));

/** Which of two values comes first: numbers by size, anything else by its text (by code unit, whatever the language is). */
export function compare(a, b) {
  if (typeof a === 'number' && typeof b === 'number') return a < b ? -1 : a > b ? 1 : 0;
  const x = String(a);
  const y = String(b);
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * `rows` ordered by the value of `column` (`column.value(row)`), `ascending` or `descending`. Rows with an equal value
 * keep the order they had, and rows with no value come last in either direction. The rows given are not changed.
 */
export function sortRows(rows, column, direction) {
  const sign = direction === 'descending' ? -1 : 1;
  return rows
    .map((row, at) => ({ row, at, key: column.value(row) }))
    .sort((a, b) => {
      if (missing(a.key) || missing(b.key)) return missing(a.key) === missing(b.key) ? a.at - b.at : missing(a.key) ? 1 : -1;
      return sign * compare(a.key, b.key) || a.at - b.at;
    })
    .map((item) => item.row);
}

/**
 * The rows that hold every word of `query` (words are told by spaces, case does not matter) in the text that some
 * column shows: `column.text(row)` for a column whose cell shows other words than its value (a time, a state in words),
 * else the value. A column with `filter: false` is not looked in. A blank query keeps all the rows.
 */
export function filterRows(rows, columns, query) {
  const terms = query.toLowerCase().split(/\s+/).filter((term) => term !== '');
  if (terms.length === 0) return rows;
  const looked = columns.filter((column) => column.filter !== false);
  return rows.filter((row) => {
    const text = looked.map((column) => String((column.text ?? column.value)(row) ?? '')).join('\n').toLowerCase();
    return terms.every((term) => text.includes(term));
  });
}

/** The page `page` (from 0) of `count` rows in pages of `size`: the page kept in range, the number of pages, and the first and last row (from 1; 0 when there are none). */
export function pageOf(count, size, page) {
  const pages = Math.max(1, Math.ceil(count / size));
  const at = Math.min(Math.max(0, Math.trunc(page) || 0), pages - 1);
  return { page: at, pages, from: count === 0 ? 0 : at * size + 1, to: Math.min(count, (at + 1) * size) };
}

/**
 * The next direction of a column when its name is pressed: ascending first, then descending, then ascending again.
 */
export function nextDirection(direction) {
  return direction === 'ascending' ? 'descending' : 'ascending';
}

// The tables that hold a filter that was typed in, weakly: a change of the language or of the way times are written
// changes the text of the cells, and `refilter` applies the filter again to the new text.
const filtered = new Set();
const dropped = new FinalizationRegistry((ref) => filtered.delete(ref));

/** Applies the filter of every table that has one again, after the text of the cells changed (see `retranslate` in `dom.js`). */
export function refilter() {
  for (const ref of filtered) {
    const table = ref.deref();
    if (table === undefined) filtered.delete(ref);
    else table.draw();
  }
}

export class Table {
  /**
   * `columns` are `{ key, label, value(row), cell(row)?, text(row)?, sortable?, num?, mono?, tight?, long?, filter? }`:
   * `value` is what is sorted, `cell` is what is shown (the value as text when there is none), and the filter looks in
   * `text`, the text of the cell, when it is not the value (see `filterRows`); `long` is for a long value with no space
   * in it (a path), which may break anywhere. `rowKey(row, index)` names a row (`index` is its place in the rows that
   * were given); `empty` is `{ title, hint?, action? }` for a list with no rows; `sort` is the starting `{ key, direction }`;
   * `dense` draws the cells closer, for a table of many columns.
   */
  constructor({ caption, columns, rowKey, empty, filter = true, size = PAGE_SIZE, sort = null, dense = false }) {
    this.columns = columns;
    this.rowKey = rowKey;
    this.empty = empty;
    this.size = size;
    this.rows = [];
    this.indexes = new Map();
    this.loading = false;
    this.selected = null;
    this.edges = null;
    this.query = '';
    this.sort = sort;
    this.page = 0;
    this.headers = new Map();
    /** The element of each column that holds its name, which is written again with each drawing (the name of a column of times says the zone). */
    this.labels = new Map();

    this.input = el('input', { class: 'tc-input', type: 'search', autocomplete: 'off', spellcheck: 'false', 'aria-label': w('table.filter'), placeholder: w('table.filter') });
    this.ref = new WeakRef(this);
    dropped.register(this, this.ref);
    this.input.addEventListener('input', () => {
      this.query = this.input.value;
      this.page = 0;
      this.follow();
      this.draw();
    });
    this.count = el('span', { class: 'tc-muted tc-small', role: 'status' });
    this.body = el('tbody');
    this.table = el(
      'table',
      { class: dense ? 'tc-table tc-table--dense' : 'tc-table' },
      el('caption', {}, caption),
      el('thead', {}, el('tr', {}, columns.map((column) => this.header(column)))),
      this.body,
    );
    this.notes = el('div');
    // The buttons of the pager are made once, so that the focus stays on the one that was pressed; what they do is set when the pager is drawn.
    this.moves = { before: null, after: null };
    // The line that says which rows are shown takes the focus when neither button of the pager can.
    this.range = el('span', { role: 'status', tabindex: '-1' });
    this.before = button('small', w('table.prev'), () => this.move('before'));
    this.after = button('small', w('table.next'), () => this.move('after'));
    this.pager = el('div', { class: 'tc-pager' }, this.range, el('span', { class: 'tc-actions' }, this.before, this.after));
    this.bar = el('div', { class: 'tc-table-bar' }, filter ? this.input : el('span'), this.count);
    this.node = el('div', { class: 'tc-table-wrap' }, this.bar, this.table, this.notes, this.pager);
    this.draw();
  }

  header(column) {
    const th = el('th', { scope: 'col', class: column.num ? 'tc-num' : null });
    if (column.sortable === false) {
      mount(th, column.label);
      this.labels.set(column.key, th);
    } else {
      const sort = button('', column.label, () => this.sortBy(column.key), { class: 'tc-sort' });
      mount(th, sort);
      this.labels.set(column.key, sort);
    }
    this.headers.set(column.key, th);
    return th;
  }

  /** Changes what the table shows: `rows`, `loading`, `selected` (a row key), `edges` and `landOn` (`first` or `last` page of new rows). */
  update(patch) {
    if ('rows' in patch) {
      this.rows = patch.rows;
      this.indexes = new Map(patch.rows.map((row, at) => [row, at]));
      if (patch.landOn === 'first') this.page = 0;
      if (patch.landOn === 'last') this.page = Number.MAX_SAFE_INTEGER;
    }
    if ('loading' in patch) this.loading = patch.loading;
    if ('selected' in patch) this.selected = patch.selected;
    if ('edges' in patch) this.edges = patch.edges;
    this.draw();
  }

  /** Keeps this table among those whose filter `refilter` applies again while a filter is typed in. */
  follow() {
    if (this.query.trim() === '') filtered.delete(this.ref);
    else filtered.add(this.ref);
  }

  sortBy(key) {
    const direction = this.sort?.key === key ? nextDirection(this.sort.direction) : 'ascending';
    this.sort = { key, direction };
    this.page = 0;
    this.draw();
  }

  /** The rows in the order and the filter that are shown now, all pages. */
  view() {
    let rows = filterRows(this.rows, this.columns, this.query);
    if (this.sort !== null) {
      const column = this.columns.find((item) => item.key === this.sort.key);
      if (column !== undefined) rows = sortRows(rows, column, this.sort.direction);
    }
    return rows;
  }

  /** Puts the focus on the line of the row with `key`; false when it is not on the page. */
  focusRow(key) {
    const line = [...this.body.querySelectorAll('[data-row]')].find((item) => item.getAttribute('data-row') === key);
    line?.focus();
    return line !== undefined;
  }

  draw() {
    const rows = this.view();
    const page = pageOf(rows.length, this.size, this.page);
    this.page = page.page;
    for (const [key, th] of this.headers) {
      if (this.sort?.key === key) th.setAttribute('aria-sort', this.sort.direction);
      else th.removeAttribute('aria-sort');
    }
    // The names are worked out with the cells, so that a name that says the zone of the times says the one the cells use.
    for (const column of this.columns) mount(this.labels.get(column.key), column.label);
    this.node.setAttribute('aria-busy', String(this.loading));
    this.drawCount(rows.length);
    mount(this.body, rows.slice(page.from === 0 ? 0 : page.from - 1, page.to).map((row) => this.line(row)));
    const none = this.rows.length === 0;
    const shown = rows.length > 0;
    this.table.hidden = !shown;
    this.bar.hidden = none;
    mount(this.notes, shown ? null : this.emptyView(none));
    this.drawPager(page, rows.length);
  }

  drawCount(shown) {
    const total = this.rows.length;
    mount(
      this.count,
      shown === total
        ? lazy(() => t('table.count', { n: formatNumber(total) }))
        : lazy(() => t('table.count_of', { shown: formatNumber(shown), total: formatNumber(total) })),
    );
  }

  line(row) {
    const key = String(this.rowKey(row, this.indexes.get(row)));
    return el(
      'tr',
      { 'data-row': key, tabindex: '-1', 'aria-selected': this.selected === key ? 'true' : null },
      this.columns.map((column) =>
        el(
          'td',
          { 'data-label': column.label, class: [column.num ? 'tc-num' : '', column.mono ? 'tc-mono' : '', column.tight ? 'tc-tight' : '', column.long ? 'tc-long' : ''].filter(Boolean).join(' ') || null },
          column.cell === undefined ? String(column.value(row) ?? '') : column.cell(row),
        ),
      ),
    );
  }

  emptyView(none) {
    if (this.loading) {
      return el('div', { class: 'tc-empty', role: 'status' }, el('strong', {}, w('table.loading')));
    }
    if (!none) {
      return el(
        'div',
        { class: 'tc-empty' },
        el('strong', {}, w('table.no_match')),
        button('small', w('table.clear'), () => {
          this.input.value = '';
          this.query = '';
          this.follow();
          this.draw();
          this.input.focus();
        }),
      );
    }
    const { title, hint = null, action = null } = this.empty;
    return el('div', { class: 'tc-empty' }, el('strong', {}, title), hint === null ? null : el('span', {}, hint), action);
  }

  drawPager(page, count) {
    const edges = this.edges;
    this.pager.hidden = page.pages === 1 && edges === null;
    if (this.pager.hidden) return;
    this.moves = {
      before: page.page > 0 ? () => this.go(page.page - 1) : edges?.before ?? null,
      after: page.page < page.pages - 1 ? () => this.go(page.page + 1) : edges?.after ?? null,
    };
    this.before.disabled = this.moves.before === null;
    this.after.disabled = this.moves.after === null;
    mount(
      this.range,
      // With no row there is no range to name: the count alone.
      count === 0
        ? lazy(() => t('table.count', { n: formatNumber(0) }))
        : lazy(() => t('table.range', { from: formatNumber(page.from), to: formatNumber(page.to), total: formatNumber(count) })),
      edges?.note === undefined || edges?.note === null ? null : [' ', edges.note],
    );
  }

  /**
   * Goes to the page before or after, or reads the part of the records that comes before or after (`edges`). Nothing
   * happens while a read is under way. A button that the move turned off cannot keep the focus: it goes to the other
   * button, or to the line that says which rows are shown. While a part is read, the focus waits on that line, and
   * when the read ends it goes back to the button that was pressed, else to the other one.
   */
  move(side) {
    if (this.loading) return;
    const [pressed, other] = side === 'before' ? [this.before, this.after] : [this.after, this.before];
    const landing = () => (pressed.disabled ? (other.disabled ? this.range : other) : pressed).focus();
    const read = this.moves[side]?.();
    if (typeof read?.then !== 'function') {
      if (pressed.disabled) landing();
      return;
    }
    this.range.focus();
    read.then(() => {
      // The user may have gone elsewhere meanwhile; then the focus stays there.
      const active = globalThis.document.activeElement;
      if (active === this.range || active === null || active === globalThis.document.body) landing();
    });
  }

  go(page) {
    this.page = page;
    this.draw();
  }
}
