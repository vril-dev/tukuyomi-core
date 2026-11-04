// The table that every list of the page uses: sorting by a column, filtering by text on the screen, paging the rows
// that were received 50 at a time, a state for an empty list and one for a list that is being read, and on a narrow
// screen a row that is one box (the cells are named by `data-label`). The rules of sorting, filtering and paging are
// plain functions, `sortRows`, `filterRows` and `pageOf`; `Table` draws what they give. A list that the server reads
// in parts (the records) hangs the buttons that read the parts on the ends of the pager (`edges`). Nothing runs when
// the module is loaded.

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
 * The rows that hold every word of `query` (words are told by spaces, case does not matter) in the value of some
 * column. A column with `filter: false` is not looked in. A blank query keeps all the rows.
 */
export function filterRows(rows, columns, query) {
  const terms = query.toLowerCase().split(/\s+/).filter((term) => term !== '');
  if (terms.length === 0) return rows;
  const looked = columns.filter((column) => column.filter !== false);
  return rows.filter((row) => {
    const text = looked.map((column) => String(column.value(row) ?? '')).join('\n').toLowerCase();
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

export class Table {
  /**
   * `columns` are `{ key, label, value(row), cell(row)?, sortable?, num?, mono?, tight?, filter? }`: `value` is what
   * is sorted and looked in, `cell` is what is shown (the value as text when there is none). `rowKey(row, index)` names
   * a row (`index` is its place in the rows that were given); `empty` is `{ title, hint?, action? }` for a list with no rows; `sort` is the starting `{ key, direction }`.
   */
  constructor({ caption, columns, rowKey, empty, filter = true, size = PAGE_SIZE, sort = null }) {
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

    this.input = el('input', { class: 'tc-input', type: 'search', autocomplete: 'off', spellcheck: 'false', 'aria-label': w('table.filter'), placeholder: w('table.filter') });
    this.input.addEventListener('input', () => {
      this.query = this.input.value;
      this.page = 0;
      this.draw();
    });
    this.count = el('span', { class: 'tc-muted tc-small', role: 'status' });
    this.body = el('tbody');
    this.table = el(
      'table',
      { class: 'tc-table' },
      el('caption', {}, caption),
      el('thead', {}, el('tr', {}, columns.map((column) => this.header(column)))),
      this.body,
    );
    this.notes = el('div');
    // The buttons of the pager are made once, so that the focus stays on the one that was pressed; what they do is set when the pager is drawn.
    this.moves = { before: null, after: null };
    this.range = el('span', { role: 'status' });
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
    } else {
      mount(th, button('', column.label, () => this.sortBy(column.key), { class: 'tc-sort' }));
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
          { 'data-label': column.label, class: [column.num ? 'tc-num' : '', column.mono ? 'tc-mono' : '', column.tight ? 'tc-tight' : ''].filter(Boolean).join(' ') || null },
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
      lazy(() => t('table.range', { from: formatNumber(page.from), to: formatNumber(page.to), total: formatNumber(count) })),
      edges?.note === undefined || edges?.note === null ? null : [' ', edges.note],
    );
  }

  /** Goes to the page before or after, or reads the part of the records that comes before or after (`edges`). Nothing happens while a read is under way. */
  move(side) {
    if (!this.loading) this.moves[side]?.();
  }

  go(page) {
    this.page = page;
    this.draw();
  }
}
