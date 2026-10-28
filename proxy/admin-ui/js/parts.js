// Parts that the screens of the WAF share: who may change the rules, how a generation is shown, the state of a change
// that is under way, what a switch of the proxy answers and what it means for the user, and the sheets and the
// confirmations that the screens open. Nothing runs when the module is loaded.

import { ApiError } from './api.js';
import { badge, el, notice, setText } from './dom.js';
import { t } from './i18n.js';

/** Whether a user of this role may import, choose, roll back and remove (the API checks it again). */
export function canChange(role) {
  return role === 'operator' || role === 'owner';
}

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

/** `seconds` since the epoch as UTC text (`2026-10-28 09:30:00Z`); the value as it is when it is not a time. */
export function utc(seconds) {
  const date = typeof seconds === 'number' ? new Date(seconds * 1000) : null;
  if (date === null || Number.isNaN(date.getTime())) return String(seconds);
  return `${date.toISOString().slice(0, 19).replace('T', ' ')}Z`;
}

/** A size in bytes as text, in the unit that reads best. */
export function bytesText(size) {
  if (typeof size !== 'number' || !Number.isFinite(size) || size < 0) return String(size);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MiB`;
}

/** The two nodes of a line of a list of names and values (`dl`). */
export function row(label, value) {
  return [el('dt', {}, label), el('dd', {}, value)];
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

/**
 * A generation that one screen asks the screen of the generations to open, when the user follows a link from
 * another screen. The hash of the page names a screen only, so the fingerprint waits here until the screen is drawn.
 */
class Handoff {
  #fingerprint = null;

  set(fingerprint) {
    this.#fingerprint = isFingerprint(fingerprint) ? fingerprint : null;
  }

  /** The fingerprint that was handed over, once. */
  take() {
    const fingerprint = this.#fingerprint;
    this.#fingerprint = null;
    return fingerprint;
  }
}

export const handoff = new Handoff();

let serial = 0;

/** A new id for an element, so that a label can name its input and a dialog its title. */
export function nextId(prefix) {
  serial += 1;
  return `${prefix}-${serial}`;
}

/** A labelled control: the row to place. `hint` is a line of help below the control. */
export function labelled(label, control, hint = null) {
  const id = nextId('w');
  control.setAttribute('id', id);
  return el(
    'div',
    { class: 'field' },
    el('label', { for: id }, label),
    control,
    hint === null ? null : el('p', { class: 'muted small' }, hint),
  );
}

/** A generation's fingerprint: its first digits, and the whole of it when the user asks. */
export function fingerprint(value) {
  if (!isFingerprint(value)) {
    return typeof value === 'string' ? el('code', { class: 'fp' }, value) : el('span', { class: 'muted' }, t('status.none'));
  }
  let whole = false;
  const code = el('code', { class: 'fp', title: value }, shortOf(value));
  const toggle = el(
    'button',
    {
      type: 'button',
      class: 'btn btn-link small',
      'aria-expanded': 'false',
      on: {
        click: () => {
          whole = !whole;
          setText(code, whole ? value : shortOf(value));
          setText(toggle, whole ? t('fp.short') : t('fp.whole'));
          toggle.setAttribute('aria-expanded', String(whole));
        },
      },
    },
    t('fp.whole'),
  );
  return el('span', { class: 'fp-view' }, code, toggle);
}

/** The head of a screen: its title and what the user does there (buttons). */
export function pageHead(title, ...actions) {
  return el('div', { class: 'page-head' }, el('h1', {}, title), actions.length === 0 ? null : el('div', { class: 'actions' }, ...actions));
}

/**
 * A table of `rows` (arrays of cells: nodes, text or numbers) under the `columns` (their names), with a `caption` for
 * a reader of the screen. The cells of the columns in `tight` are kept on one line; those of the columns in `wide`
 * are broken anywhere, which a long unbroken text needs. On a narrow screen each row is a block with the name of the
 * column before each cell, and a cell with nothing in it is left out.
 */
export function table(columns, rows, caption, { tight = [], wide = [] } = {}) {
  const kind = (at) => (tight.includes(at) ? 'tight' : wide.includes(at) ? 'wide' : null);
  return el(
    'div',
    { class: 'table-wrap' },
    el(
      'table',
      { class: 'grid' },
      el('caption', { class: 'sr' }, caption),
      el('thead', {}, el('tr', {}, columns.map((name) => el('th', { scope: 'col' }, name)))),
      el(
        'tbody',
        {},
        rows.map((cells) => el('tr', {}, cells.map((cell, at) => el('td', { 'data-label': columns[at], class: kind(at) }, cell)))),
      ),
    ),
  );
}

// ---- a change that is under way ----

const WORKING = {
  activate: () => t('working.activate'),
  rollback: () => t('working.rollback'),
  remove: () => t('working.remove'),
  import: () => t('working.import'),
};

/**
 * Which change of the rules this page has sent and not yet had an answer to. The page holds one at a time, whatever
 * screen is shown (the server takes one at a time as well), and a screen that is drawn again while it runs, for
 * example when the language is switched, finds it here.
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
 * Runs the call of a change that may take long (`name` is `activate`, `rollback`, `remove` or `import`). The answer
 * or the error comes back as `{ body, error }`, never thrown, so that the screen decides what it means. A call that
 * would start while another runs does not start (`skipped`).
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
  return working.name === null ? '' : notice('info', el('span', { class: 'spin', 'aria-hidden': 'true' }), ' ', working.words);
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
  switched: ['ok', () => t('word.switched'), (o) => t('out.switched', ids(o)), null],
  unchanged: ['ok', () => t('word.unchanged'), (o) => t('out.unchanged', ids(o)), null],
  refused: ['bad', () => t('word.refused'), (o) => t('out.refused', ids(o)), (o) => t('next.refused', ids(o))],
  failed: ['bad', () => t('word.failed'), (o) => t('out.failed', ids(o)), (o) => t('next.failed', ids(o))],
  unreachable: ['bad', () => t('word.unreachable'), () => t('out.unreachable'), () => t('next.unreachable')],
  unconfirmed: ['warn', () => t('word.unconfirmed'), (o) => t('out.unconfirmed', ids(o)), (o) => t('next.unconfirmed', ids(o))],
  busy: ['warn', () => t('word.busy'), () => t('out.busy'), () => t('next.busy')],
  lost: ['warn', () => t('word.lost'), () => t('out.lost'), () => t('next.lost')],
  conflict: ['warn', () => t('word.conflict'), said, () => t('next.conflict')],
  unavailable: ['bad', () => t('word.unavailable'), said, null],
  forbidden: ['bad', () => t('word.forbidden'), said, null],
  limited: ['warn', () => t('word.limited'), said, null],
  other: ['bad', () => t('word.other'), said, null],
};

/** The tone of the badge of a word of the proxy's, for the history. */
export function wordBadge(word) {
  const known = Object.hasOwn(OUTCOMES, word) && SWITCH_WORDS.includes(word);
  return badge(known ? OUTCOMES[word][0] : 'muted', known ? OUTCOMES[word][1]() : String(word));
}

/** The box that tells how a request to switch ended and what to do next. `describe` words a failed call. */
export function outcomeView(outcome, describe) {
  const [tone, name, what, next] = OUTCOMES[outcome.word];
  return notice(
    tone,
    el('p', {}, badge(tone, name()), ' ', what(outcome, describe)),
    outcome.unwritten ? el('p', { class: 'small' }, t('out.unwritten')) : null,
    next === null ? null : el('p', { class: 'small' }, next(outcome)),
  );
}

/** What the screen found when it read the status and the history again: where the result of a request shows. */
export function findingsView(status, history) {
  const proxy = status?.proxy ?? null;
  const newest = Array.isArray(history) && history.length > 0 ? history[0] : null;
  return el(
    'section',
    { class: 'card' },
    el('h2', {}, t('found.title')),
    status === null || history === null
      ? notice('bad', t('found.failed'))
      : el(
          'dl',
          { class: 'kv' },
          el('dt', {}, t('status.chosen')),
          el('dd', {}, fingerprint(status.current)),
          el('dt', {}, t('status.serving')),
          el('dd', {}, proxy !== null && typeof proxy === 'object' ? fingerprint(proxy.generation) : t('status.unknown')),
          el('dt', {}, t('found.newest')),
          el(
            'dd',
            {},
            newest === null
              ? t('history.empty')
              : el('span', {}, newest.ts, ' ', newest.actor, ' ', wordBadge(newest.result), ' ', fingerprint(newest.from), ' → ', fingerprint(newest.to)),
          ),
        ),
  );
}

// ---- sheets and confirmations ----

/**
 * Opens a sheet that comes in from the right, in `layer`, with `title` and `content` (nodes). It is a modal dialog:
 * the keyboard stays in it, and Escape or the button closes it. Gives `{ close, body }`; `body` is where the content
 * goes, so that it can be filled later.
 */
export function openSheet(layer, title, ...content) {
  const heading = nextId('sheet');
  const body = el('div', { class: 'stack' }, ...content);
  const dialog = el(
    'dialog',
    { class: 'sheet', 'aria-labelledby': heading },
    el(
      'div',
      { class: 'sheet-head' },
      el('h2', { id: heading }, title),
      el('button', { type: 'button', class: 'btn', on: { click: () => dialog.close() } }, t('sheet.close')),
    ),
    body,
  );
  dialog.addEventListener('close', () => dialog.remove());
  // A click on the dark part beside the sheet is a click on the dialog itself.
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) dialog.close();
  });
  layer.append(dialog);
  dialog.showModal();
  return { close: () => dialog.close(), body };
}

/**
 * Asks the user to confirm a change before it is made. `lines` say what changes (nodes). It gives true when the user
 * confirms and false when the user cancels or presses Escape; the focus starts on the cancel button, and a click
 * beside the dialog does not cancel it.
 */
export function confirmChange(layer, { title, lines, confirm, tone = 'primary' }) {
  return new Promise((resolve) => {
    const heading = nextId('confirm');
    const cancel = el('button', { type: 'button', class: 'btn', autofocus: true, on: { click: () => dialog.close('no') } }, t('confirm.cancel'));
    const yes = el(
      'button',
      { type: 'button', class: `btn btn-${tone}`, on: { click: () => dialog.close('yes') } },
      confirm,
    );
    const dialog = el(
      'dialog',
      { class: 'confirm', 'aria-labelledby': heading },
      el('h2', { id: heading }, title),
      el('div', { class: 'stack' }, ...lines),
      el('div', { class: 'actions confirm-actions' }, cancel, yes),
    );
    dialog.addEventListener('close', () => {
      const answer = dialog.returnValue === 'yes';
      dialog.remove();
      resolve(answer);
    });
    layer.append(dialog);
    dialog.showModal();
  });
}

/** The lines of a confirmation that show a generation before and after: `from` and `to` in full. */
export function changeLines(from, to) {
  return [
    el('dl', { class: 'kv' }, el('dt', {}, t('confirm.from')), el('dd', {}, el('code', { class: 'fp' }, from ?? '')), el('dt', {}, t('confirm.to')), el('dd', {}, el('code', { class: 'fp' }, to ?? ''))),
  ];
}
