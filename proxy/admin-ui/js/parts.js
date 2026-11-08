// Parts that the screens share: who may change the rules, how a generation and a time are shown, the face of a screen
// (its head, a panel, a number), the fields of a form with their errors, the dialogs that confirm a change, the state
// of a change that is under way, and what a switch of the proxy answers and what it means for the user. Texts that have
// words of the page in them are `Words` (see `dom.js`). Nothing runs when the module is loaded.

import { ApiError } from './api.js';
import { badge, button, buttonClass, el, mount, notice, result } from './dom.js';
import { language, lazy, t, w } from './i18n.js';

/** Whether a user of this role may import, choose, roll back and remove (the API checks it again). */
export function canChange(role) {
  return role === 'operator' || role === 'owner';
}

// ---- generations, sizes and times ----

const FINGERPRINT = /^[0-9a-f]{64}$/;
const SHORT = 12;

export function isFingerprint(value) {
  return typeof value === 'string' && FINGERPRINT.test(value);
}

/** The first digits of a generation's fingerprint, which is enough to tell the generations of a store apart. */
export function shortOf(value) {
  if (typeof value !== 'string') return '?';
  return isFingerprint(value) ? value.slice(0, SHORT) : value;
}

/** A size in bytes as text, in the unit that reads best. */
export function bytesText(size) {
  if (typeof size !== 'number' || !Number.isFinite(size) || size < 0) return String(size);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MiB`;
}

/** How times are written: in the time of the user's own place (the default), or in UTC. The bar of the page switches it. */
export const clock = { utc: false };

/**
 * Milliseconds since the epoch of a time given as a number (`unit` is `ms`, or `s` for seconds) or as a text of the
 * form of RFC 3339; null when the value is no time.
 */
export function instantOf(value, unit = 'ms') {
  let ms = null;
  if (typeof value === 'number') ms = unit === 's' ? value * 1000 : value;
  else if (typeof value === 'string') ms = Date.parse(value);
  return ms !== null && Number.isFinite(new Date(ms).getTime()) ? ms : null;
}

const pad = (number) => String(number).padStart(2, '0');

function zoneName(date) {
  try {
    const part = new Intl.DateTimeFormat(language() === 'ja' ? 'ja-JP' : 'en-US', { timeZoneName: 'short' })
      .formatToParts(date)
      .find((item) => item.type === 'timeZoneName');
    if (part !== undefined) return part.value;
  } catch {
    // The place has no name for its zone here: the offset says it.
  }
  const offset = -date.getTimezoneOffset();
  return `UTC${offset < 0 ? '-' : '+'}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
}

/** `2026-11-04 16:33:56`: the date and the time of `date` in UTC, or in the time of the user's place. */
function stampOf(date, utc) {
  const part = utc
    ? [date.getUTCFullYear(), date.getUTCMonth() + 1, date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()]
    : [date.getFullYear(), date.getMonth() + 1, date.getDate(), date.getHours(), date.getMinutes(), date.getSeconds()];
  const [year, month, day, hour, minute, second] = part;
  return `${year}-${pad(month)}-${pad(day)} ${pad(hour)}:${pad(minute)}:${pad(second)}`;
}

/** `text` with the name of a zone after it, as the language writes it: `時刻（JST）`, `Time (JST)`. */
function zoned(text, zone) {
  return language() === 'ja' ? `${text}（${zone}）` : `${text} (${zone})`;
}

/** The one way a time is written: `2026-11-04 16:33:56（JST）`, or with `（UTC）` when `utc` is true. */
export function timeText(ms, utc) {
  const date = new Date(ms);
  return zoned(stampOf(date, utc), utc ? 'UTC' : zoneName(date));
}

/** The zone that the times of a table are written in: UTC, or the zone of the user's place now. */
function tableZone() {
  return clock.utc ? 'UTC' : zoneName(new Date());
}

/** The name of a column of times: `words`, and the zone that the cells are written in (see `timeCell`). */
export function timeLabel(words) {
  return lazy(() => zoned(words.text(), tableZone()));
}

/**
 * The text of a time in a table: written the way the bar says, without the zone, which the name of the column says
 * (see `timeLabel`). A time of the year when the place is in another zone (summer time) keeps its own. A value that is
 * no time is text.
 */
export function timeCellText(value, unit = 'ms') {
  const ms = instantOf(value, unit);
  if (ms === null) return String(value ?? '');
  const date = new Date(ms);
  const zone = clock.utc ? 'UTC' : zoneName(date);
  return zone === tableZone() ? stampOf(date, clock.utc) : zoned(stampOf(date, clock.utc), zone);
}

/** A time for a screen: written the way the bar says, and the other way as its title. A value that is no time is text. */
export function timeView(value, unit = 'ms') {
  const ms = instantOf(value, unit);
  if (ms === null) return el('span', {}, String(value ?? ''));
  return el(
    'time',
    { datetime: new Date(ms).toISOString(), title: lazy(() => timeText(ms, !clock.utc)) },
    lazy(() => timeText(ms, clock.utc)),
  );
}

/** A time for a cell of a table (see `timeCellText`), with the other way, and the zone, as its title. */
export function timeCell(value, unit = 'ms') {
  const ms = instantOf(value, unit);
  if (ms === null) return el('span', {}, String(value ?? ''));
  return el('time', { datetime: new Date(ms).toISOString(), title: lazy(() => timeText(ms, !clock.utc)) }, lazy(() => timeCellText(ms)));
}

/** The words of a time, for a place that takes words (not an element). */
export function timeWords(value, unit = 'ms') {
  const ms = instantOf(value, unit);
  return ms === null ? String(value ?? '') : lazy(() => timeText(ms, clock.utc));
}

// ---- the face of a screen ----

/** The hash of a screen, with the id and the query that it holds (`#/records/<id>?status=403`). */
export function hashOf(screen, { id = null, query = {} } = {}) {
  const pairs = Object.entries(query).filter(([, entry]) => entry !== '' && entry !== null && entry !== undefined);
  const search = pairs.map(([key, entry]) => `${encodeURIComponent(key)}=${encodeURIComponent(entry)}`).join('&');
  return `#/${screen}${id === null ? '' : `/${encodeURIComponent(id)}`}${search === '' ? '' : `?${search}`}`;
}

let serial = 0;

/** A new id for an element, so that a label can name its input and a dialog its title. */
export function nextId(prefix) {
  serial += 1;
  return `${prefix}-${serial}`;
}

/** The two nodes of a line of a list of names and values (`dl`). */
export function row(label, value) {
  return [el('dt', {}, label), el('dd', {}, value)];
}

/** A list of names and values; `rows` are made by `row`. */
export function kv(...rows) {
  return el('dl', { class: 'tc-kv' }, rows);
}

/** The head of a screen: its name, which a change of the screen moves the focus to, and what the user does there. */
export function pageHead(title, ...actions) {
  return el(
    'div',
    { class: 'tc-page-head' },
    el('h1', { tabindex: '-1' }, title),
    actions.length === 0 ? null : el('div', { class: 'tc-actions' }, ...actions),
  );
}

/**
 * A panel with a title, the state and the operations of the panel next to the title (`head`), and the content. Gives
 * `{ node, heading }`; the heading takes the focus when the panel is opened by a change of the address.
 */
export function panelWith(title, head, ...children) {
  const id = nextId('panel');
  const heading = el('h2', { class: 'tc-panel__title', id, tabindex: '-1' }, title);
  const node = el(
    'section',
    { class: 'tc-panel', 'aria-labelledby': id },
    el('div', { class: 'tc-panel__head' }, heading, head.length === 0 ? null : el('span', { class: 'tc-actions' }, ...head)),
    ...children,
  );
  return { node, heading };
}

export function panel(title, head, ...children) {
  return panelWith(title, head, ...children).node;
}

/** A number of the overview: its name, the number (or words that say why there is none) and a line below it. */
export function stat(label, value, sub = null) {
  return el(
    'div',
    { class: 'tc-stat' },
    el('span', { class: 'tc-stat__label' }, label),
    el('span', { class: 'tc-stat__value' }, value),
    sub === null ? null : el('span', { class: 'tc-stat__sub' }, sub),
  );
}

/** A check box with its words, and a line of help below them. */
export function choice(label, input, hint = null) {
  return el(
    'label',
    { class: 'tc-choice' },
    input,
    el('span', {}, label, hint === null ? null : el('span', { class: 'tc-hint' }, hint)),
  );
}

export function checkbox(onChange = null) {
  const input = el('input', { type: 'checkbox', class: 'tc-check' });
  if (onChange !== null) input.addEventListener('change', () => onChange(input.checked));
  return input;
}

/** The text input of a form. */
export function textInput(attributes = {}) {
  return el('input', { class: 'tc-input', type: 'text', ...attributes });
}

// ---- the fields of a form ----

/**
 * One field of a form: its name, the control, a line of help, and the place of the error. `invalid(words)` shows the
 * error under the control and ties it to the control (`aria-invalid`, `aria-describedby`); `valid()` takes it away.
 * `asButton` draws the name as a button, for a control that is hidden and that its name opens (a file input).
 */
export class Field {
  constructor(label, control, { hint = null, required = false, asButton = false } = {}) {
    const id = nextId('field');
    this.control = control;
    this.hintId = hint === null ? null : `${id}-hint`;
    this.errorId = `${id}-error`;
    control.setAttribute('id', id);
    if (required) control.setAttribute('aria-required', 'true');
    if (this.hintId !== null) control.setAttribute('aria-describedby', this.hintId);
    this.hint = hint === null ? null : el('span', { class: 'tc-hint', id: this.hintId }, hint);
    this.error = el('span', { class: 'tc-error', id: this.errorId });
    this.error.hidden = true;
    this.node = el(
      'div',
      { class: 'tc-field' },
      el('label', { class: asButton ? buttonClass('') : 'tc-label', for: id }, label, required ? el('span', { class: 'tc-req' }, w('field.required')) : null),
      control,
      this.hint,
      this.error,
    );
  }

  invalid(words) {
    mount(this.error, words);
    this.error.hidden = false;
    if (this.hint !== null) this.hint.hidden = true;
    this.control.setAttribute('aria-invalid', 'true');
    this.control.setAttribute('aria-describedby', this.errorId);
  }

  valid() {
    mount(this.error);
    this.error.hidden = true;
    if (this.hint !== null) this.hint.hidden = false;
    this.control.removeAttribute('aria-invalid');
    if (this.hintId === null) this.control.removeAttribute('aria-describedby');
    else this.control.setAttribute('aria-describedby', this.hintId);
  }
}

/**
 * Shows what is wrong with each field of a form and puts the focus on the first field that is wrong. `entries` are
 * `[field, words]`, with null for a field that is right. Gives true when none is wrong.
 */
export function checkFields(entries) {
  let first = null;
  for (const [field, words] of entries) {
    if (words === null) {
      field.valid();
    } else {
      field.invalid(words);
      first ??= field;
    }
  }
  if (first !== null) first.control.focus();
  return first === null;
}

/** The words for a field that is empty and must not be. */
export function emptyField() {
  return w('field.empty');
}

// ---- copying ----

/** A small button that puts `text()` on the clipboard and says in short words whether that worked; on a failure the text of `target` is selected. */
export function copyButton(text, target = null) {
  const status = el('span', { class: 'tc-small tc-muted', role: 'status' });
  const copy = button('small', w('copy.button'), async () => {
    try {
      await globalThis.navigator.clipboard.writeText(text());
      mount(status, w('copy.done'));
    } catch {
      if (target !== null) globalThis.getSelection?.()?.selectAllChildren(target);
      mount(status, w('copy.failed'));
    }
  });
  return el('span', { class: 'tc-actions' }, copy, status);
}

/** The text of the short form of a fingerprint (see `fingerprintView`): its first 12 digits and `…`. */
export function fingerprintText(value) {
  if (!isFingerprint(value)) return typeof value === 'string' ? value : t('status.none');
  return `${shortOf(value)}…`;
}

/** A fingerprint: its first 12 digits, and the whole of it as the title and by the copy button (`whole`: all of it is shown). */
export function fingerprintView(value, { whole = false, copy = true } = {}) {
  if (!isFingerprint(value)) {
    return typeof value === 'string' ? el('code', {}, value) : el('span', { class: 'tc-muted' }, w('status.none'));
  }
  const code = el('code', { title: value }, whole ? value : `${shortOf(value)}…`);
  return el('span', { class: 'tc-fp' }, code, copy ? copyButton(() => value, code) : null);
}

// ---- dialogs ----

// Where the focus was when a dialog was opened: the button, or the row that holds it.
const opener = { node: null, row: null };

function remember() {
  const active = globalThis.document.activeElement ?? null;
  const memo = { node: active, row: active?.closest?.('[data-row]')?.getAttribute('data-row') ?? null };
  // A dialog opened from inside another one leaves the place of the first: that is where the screen's focus goes back to.
  if (active?.closest?.('dialog') === null || active?.closest === undefined) {
    opener.node = memo.node;
    opener.row = memo.row;
  }
  return memo;
}

/** Forgets the place of a dialog that was closed with no change made: nothing is to be drawn again, so no focus is to be put back later. */
function forget(memo) {
  if (opener.node === memo.node && opener.row === memo.row) {
    opener.node = null;
    opener.row = null;
  }
}

/**
 * Puts the focus back where a dialog was opened, when the dialog is closed or the screen was drawn again after it: on
 * the button, or when that is gone on its row in `root`, or else on `fallback` (a heading).
 */
export function restoreFocus(root, fallback = null) {
  const { node, row: key } = opener;
  if (node === null && key === null) return;
  opener.node = null;
  opener.row = null;
  const active = globalThis.document.activeElement;
  if (active !== null && active !== globalThis.document.body && root.contains(active)) return;
  if (node !== null && node.isConnected) {
    node.focus();
    return;
  }
  const line = key === null ? null : [...root.querySelectorAll('[data-row]')].find((item) => item.getAttribute('data-row') === key);
  (line ?? fallback)?.focus();
}

/**
 * Puts the focus on `control` when it is nowhere: on no element, on the page itself, or on an element that is gone (the
 * browser moves the focus away from it only later). A button that the page turned off while it worked cannot keep the
 * focus, and gets it back so when it is turned on again.
 */
export function keepFocus(control) {
  const active = globalThis.document.activeElement;
  if (active === null || active === globalThis.document.body || !active.isConnected) control.focus();
}

// The buttons that had the focus when they were turned off while the page worked.
const held = new WeakSet();

/** Turns `control` off while `busy`, and on again after; a control that had the focus when it was turned off gets it back (see `keepFocus`). */
export function setBusy(control, busy) {
  if (busy && !control.disabled && globalThis.document.activeElement === control) held.add(control);
  control.disabled = busy;
  if (!busy && held.delete(control)) keepFocus(control);
}

function dialogOf(layer, heading, wide, body, foot) {
  const dialog = el(
    'dialog',
    { class: wide ? 'tc-dialog tc-dialog--wide' : 'tc-dialog', 'aria-labelledby': heading },
    el('div', { class: 'tc-dialog__body' }, body),
    el('div', { class: 'tc-dialog__foot' }, foot),
  );
  layer.append(dialog);
  return dialog;
}

/**
 * A grid of what a change turns from and to: `head` are the names of the two columns, and each of `rows` is `{ label,
 * now, after, changed }`; the value that changes is bold.
 */
export function diffView(head, rows) {
  return el(
    'div',
    { class: 'tc-diff' },
    el('span', { class: 'tc-diff__head' }),
    el('span', { class: 'tc-diff__head' }, head[0]),
    el('span', { class: 'tc-diff__head' }, head[1]),
    rows.map((line) => [
      el('span', { class: 'tc-muted' }, line.label),
      el('span', {}, line.now),
      el('span', { class: line.changed ? 'tc-diff__changed' : '' }, line.after),
    ]),
  );
}

/**
 * Asks the user to confirm a change before it is made. `lines` say what changes (nodes), `diff` is a `diffView`. It
 * gives true when the user confirms and false when the user cancels or presses Escape; the focus starts on the cancel
 * button, and a click beside the dialog does not cancel it. `tone` is `danger` for a change that cannot be undone.
 */
export function confirmChange(layer, { title, lines = [], diff = null, confirm, tone = 'primary' }) {
  return new Promise((resolve) => {
    const memo = remember();
    const heading = nextId('confirm');
    const cancel = button('', w('confirm.cancel'), () => dialog.close('no'), { autofocus: true });
    const yes = button(tone === 'danger' ? 'danger-solid' : 'primary', confirm, () => dialog.close('yes'));
    const dialog = dialogOf(layer, heading, false, [el('h2', { class: 'tc-dialog__title', id: heading }, title), ...lines, diff], [cancel, yes]);
    dialog.addEventListener('close', () => {
      const answer = dialog.returnValue === 'yes';
      dialog.remove();
      resolve(answer);
      if (!answer) forget(memo);
      if (memo.node !== null && memo.node.isConnected) memo.node.focus();
    });
    dialog.showModal();
    cancel.focus();
  });
}

/**
 * Opens a modal dialog in `layer` with `title` and `content` (nodes), for a thing that is done in more than one step.
 * The keyboard stays in it, and Escape or the button closes it. Gives `{ close, body }`: `close` is for the screen when what the dialog was for is done; `body` is where the content goes.
 */
export function openDialog(layer, title, ...content) {
  const memo = remember();
  const heading = nextId('dialog');
  const body = el('div', { class: 'tc-stack' }, ...content);
  const dialog = dialogOf(layer, heading, true, [el('h2', { class: 'tc-dialog__title', id: heading }, title), body], [button('', w('dialog.close'), () => dialog.close())]);
  dialog.addEventListener('close', () => {
    dialog.remove();
    // Closed by the button or Escape, nothing was changed; closed by the screen (`done`), the screen draws its list again and puts the focus back then.
    if (dialog.returnValue !== 'done') forget(memo);
    if (memo.node !== null && memo.node.isConnected) memo.node.focus();
  });
  dialog.showModal();
  return { close: () => dialog.close('done'), body };
}

// ---- a change that is under way ----

const WORKING = {
  activate: () => w('working.activate'),
  rollback: () => w('working.rollback'),
  remove: () => w('working.remove'),
  import: () => w('working.import'),
  'managed-activate': () => w('working.managed_activate'),
  'managed-rollback': () => w('working.managed_rollback'),
};

/**
 * Which change this page has sent and not yet had an answer to (of the rules, or of the managed configuration). The
 * page holds one at a time, whatever screen is shown (the server takes one at a time as well), and a screen that is
 * drawn while it runs finds it here.
 */
class Working {
  #name = null;
  #watchers = new Set();

  /** The name of the change that runs (a key of `WORKING`), or null. */
  get name() {
    return this.#name;
  }

  /** The words for the change that runs. */
  get words() {
    return this.#name !== null && Object.hasOwn(WORKING, this.#name) ? WORKING[this.#name]() : '';
  }

  start(name) {
    this.#name = name;
    this.#tell();
  }

  end() {
    this.#name = null;
    this.#tell();
  }

  /** Calls `watcher` whenever a change starts or ends; gives back a function that stops that. */
  watch(watcher) {
    this.#watchers.add(watcher);
    return () => this.#watchers.delete(watcher);
  }

  #tell() {
    for (const watcher of [...this.#watchers]) watcher(this.#name);
  }
}

export const working = new Working();

/**
 * Runs the call of a change that may take long (`name` is `activate`, `rollback`, `remove`, `import`,
 * `managed-activate` or `managed-rollback`). The answer or the error comes back as `{ body, error }`, never thrown, so
 * that the screen decides what it means. A call that would start while another runs does not start (`skipped`).
 */
export async function perform(name, call) {
  if (working.name !== null) return { body: null, error: null, skipped: true };
  working.start(name);
  try {
    return { body: await call(), error: null, skipped: false };
  } catch (error) {
    return { body: null, error, skipped: false };
  } finally {
    working.end();
  }
}

/** The banner that tells which change runs; empty when none does. */
export function runningNotice() {
  return working.name === null ? '' : notice('info', el('span', { class: 'tc-running' }, el('span', { class: 'tc-spinner', 'aria-hidden': 'true' }), working.words));
}

// ---- what a switch of the proxy answers ----

const SWITCH_WORDS = ['switched', 'unchanged', 'refused', 'failed', 'unreachable', 'unconfirmed'];
const BUSY = 'the proxy is busy';

/**
 * What an answer to a request to switch (choose a generation, roll back) comes to, from the `{ body, error }` that
 * `perform` gave. The word is one of `switched`, `unchanged`, `refused`, `failed`, `unreachable` and `unconfirmed`
 * (the proxy's own, named in the body of the answer whatever the status is), or `busy` (the proxy had no room for
 * the switch), `lost` (no answer: the result is not known), `conflict` (the state moved under the request),
 * `unavailable`, `forbidden`, `limited`, or `other`. `ids` are the generation before and the one asked for, `chosen`
 * says whether the rules store chooses the latter now, and `unwritten` that the history has no line for the request.
 */
export function switchOutcome({ body, error }) {
  const source = error === null ? body : error?.body;
  const detail = source !== null && typeof source === 'object' ? source : {};
  const base = {
    ids: { from: detail.from, to: detail.generation },
    chosen: detail.chosen === true,
    unwritten: detail.history === 'not written',
    error,
  };
  if (SWITCH_WORDS.includes(detail.result)) return { ...base, word: detail.result };
  if (error === null) return { ...base, word: 'lost' };
  if (!(error instanceof ApiError)) return { ...base, word: 'other' };
  if (error.kind === 'unknown') return { ...base, word: 'lost' };
  if (error.kind === 'conflict') return { ...base, word: 'conflict' };
  if (error.kind === 'unavailable') return { ...base, word: error.sentence === BUSY ? 'busy' : 'unavailable' };
  if (error.kind === 'forbidden') return { ...base, word: 'forbidden' };
  if (error.kind === 'limited') return { ...base, word: 'limited' };
  return { ...base, word: 'other' };
}

const ids = (outcome) => ({ from: shortOf(outcome.ids.from), to: shortOf(outcome.ids.to) });
const said = (outcome, describe) => describe(outcome.error, { change: true });

// For each word: the tone, the name, what happened, and what to do next (null for nothing).
const OUTCOMES = {
  switched: ['ok', () => w('word.switched'), (o) => w('out.switched', ids(o)), null],
  unchanged: ['ok', () => w('word.unchanged'), (o) => w('out.unchanged', ids(o)), null],
  refused: ['bad', () => w('word.refused'), (o) => w('out.refused', ids(o)), (o) => w('next.refused', ids(o))],
  failed: ['bad', () => w('word.failed'), (o) => w('out.failed', ids(o)), (o) => w('next.failed', ids(o))],
  unreachable: ['bad', () => w('word.unreachable'), () => w('out.unreachable'), () => w('next.unreachable')],
  unconfirmed: ['warn', () => w('word.unconfirmed'), (o) => w('out.unconfirmed', ids(o)), (o) => w('next.unconfirmed', ids(o))],
  busy: ['warn', () => w('word.busy'), () => w('out.busy'), () => w('next.busy')],
  lost: ['warn', () => w('word.lost'), () => w('out.lost'), () => w('next.lost')],
  conflict: ['warn', () => w('word.conflict'), said, () => w('next.conflict')],
  unavailable: ['bad', () => w('word.unavailable'), said, null],
  forbidden: ['bad', () => w('word.forbidden'), said, null],
  limited: ['warn', () => w('word.limited'), said, null],
  other: ['bad', () => w('word.other'), said, null],
};

// The names of the engines that inspect with the rules of a generation. A word that is not here is shown as the API
// gave it.
const ENGINES = {
  coraza: () => t('engine.coraza'),
  modsecurity: () => t('engine.modsecurity'),
};

/** The name of an engine, by the word the API gives. */
export function engineName(engine) {
  return Object.hasOwn(ENGINES, engine) ? ENGINES[engine]() : String(engine);
}

export function engineBadge(engine) {
  return badge('plain', lazy(() => engineName(engine)));
}

const MODES = {
  block: () => t('mode.block'),
  detect: () => t('mode.detect'),
};

/** The words of a mode of a generation or of the proxy, by the word the API gives. */
export function modeName(mode) {
  return Object.hasOwn(MODES, mode) ? MODES[mode]() : String(mode);
}

export function modeBadge(mode) {
  return badge('muted', lazy(() => modeName(mode)));
}

/** The tone of the badge of a word of the proxy's, for the history. */
export function wordBadge(word) {
  const known = Object.hasOwn(OUTCOMES, word) && SWITCH_WORDS.includes(word);
  return badge(known ? OUTCOMES[word][0] : 'muted', known ? OUTCOMES[word][1]() : String(word));
}

/** The text of the badge of a word of the proxy's (see `wordBadge`). */
export function wordText(word) {
  return Object.hasOwn(OUTCOMES, word) && SWITCH_WORDS.includes(word) ? OUTCOMES[word][1]().text() : String(word);
}

/** The box that tells how a request to switch ended and what to do next. `describe` words a failed call. */
export function outcomeView(outcome, describe) {
  const [tone, name, what, next] = OUTCOMES[outcome.word];
  const box = result(tone, name(), what(outcome, describe), next === null ? null : next(outcome));
  if (outcome.unwritten) box.append(el('span', { class: 'tc-notice__next' }, w('out.unwritten')));
  return box;
}

/**
 * How the generation that the rules store chooses compares with the one that the proxy serves, from the answer of
 * `GET /api/status`: `same`; `switching` (they differ while a switch is under way); `differ`; or `unknown` when the
 * proxy did not say which it serves (it cannot be reached, or has no room to answer).
 */
export function generationState(data) {
  const proxy = data?.proxy ?? null;
  if (proxy === null || typeof proxy !== 'object') return 'unknown';
  if (data.current === proxy.generation) return 'same';
  return proxy.switching === true ? 'switching' : 'differ';
}

/** What the screen found when it read the status and the history again: where the result of a request shows. */
export function findingsView(status, history) {
  const proxy = status?.proxy ?? null;
  const newest = Array.isArray(history) && history.length > 0 ? history[0] : null;
  return panel(
    w('found.title'),
    [],
    status === null || history === null
      ? notice('bad', w('found.failed'))
      : kv(
          row(w('status.chosen'), fingerprintView(status.current)),
          row(w('status.serving'), proxy !== null && typeof proxy === 'object' ? fingerprintView(proxy.generation) : w('status.unknown')),
          row(
            w('found.newest'),
            newest === null
              ? w('history.empty')
              : el('span', { class: 'tc-actions' }, timeView(newest.ts), String(newest.actor), wordBadge(newest.result), fingerprintView(newest.from, { copy: false }), '→', fingerprintView(newest.to, { copy: false })),
          ),
        ),
  );
}
