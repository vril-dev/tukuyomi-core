// The import screen: the user chooses rule files and data files in the browser, says whether the CRS of the host is
// used (and which of its files are left out), writes the routes that are not inspected, and imports them as a new
// generation. The files are counted against the limits of the API before anything is sent. The API tries the new
// rules with an inspector first; a trial that reports a block is shown, and the user may accept the block through a
// second confirmation. The new generation is not chosen. How an import ended waits in `ended` for the screen that is
// shown, which may not be the one that sent it. Nothing runs when the module is loaded.

import { ApiError } from './api.js';
import { badge, el, mount, notice } from './dom.js';
import { t } from './i18n.js';
import {
  bytesText,
  confirmChange,
  fingerprint,
  handoff,
  labelled,
  pageHead,
  perform,
  row,
  runningNotice,
  shortOf,
  table,
  utc,
  working,
} from './parts.js';

/** The limits of the API: files in all, bytes of a file, bytes of all the files, routes. */
export const LIMITS = { files: 128, file: 2 * 1024 * 1024, total: 8 * 1024 * 1024, routes: 256 };
/** The name of a file as a bundle holds it: one name, no path, letters, digits and `._-`, not starting with a dot. */
const NAME = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const ROUTE_KEYS = ['host', 'path', 'action'];
/** How the trial reports a probe that the rules blocked (see `trialBlocked`). */
const BLOCKED = /: blocked by rule -?\d+ in phase \d+, status \d+$/;
/** The most problems that are shown at a time. */
const SHOWN = 10;

/**
 * The files chosen for an import (`rules` and `data`: lists of `{ name, size }`) counted against the limits of the
 * API: their number, their bytes, the largest, and what is wrong (`problems`, each with a `code`: `none`, `count`,
 * `total`, `size`, `name`, `twice`; the last three name the file). The files of the CRS count towards the limits as
 * well, but their sizes are not known here, so the API has the last word.
 */
export function checkFiles({ rules, data, crs }) {
  const files = [...rules, ...data];
  const problems = [];
  if (rules.length === 0 && !crs) problems.push({ code: 'none' });
  if (files.length > LIMITS.files) problems.push({ code: 'count' });
  const seen = new Set();
  let bytes = 0;
  let largest = 0;
  for (const file of files) {
    bytes += file.size;
    largest = Math.max(largest, file.size);
    if (!NAME.test(file.name)) problems.push({ code: 'name', name: file.name });
    else if (seen.has(file.name)) problems.push({ code: 'twice', name: file.name });
    seen.add(file.name);
    if (file.size > LIMITS.file) problems.push({ code: 'size', name: file.name });
  }
  if (bytes > LIMITS.total) problems.push({ code: 'total' });
  return { files: files.length, bytes, largest, problems };
}

/**
 * The routes that the user wrote, as the form of a file of routes: a JSON list of `{ "host"?, "path", "action":
 * "bypass" }`. Gives `{ value, count, problem }`: `value` is what to send (null for no routes), `problem` is null or
 * `json` (not JSON), `list` (not a list, or an empty one), `many` (over the limit) or `form` (an item is not a route).
 * The API checks the paths and hosts as well.
 */
export function checkRoutes(text) {
  const none = { value: null, count: 0, problem: null };
  const trimmed = text.trim();
  if (trimmed === '') return none;
  let value;
  try {
    value = JSON.parse(trimmed);
  } catch {
    return { ...none, problem: 'json' };
  }
  if (!Array.isArray(value) || value.length === 0) return { ...none, problem: 'list' };
  if (value.length > LIMITS.routes) return { ...none, problem: 'many' };
  for (const route of value) {
    const plain = route !== null && typeof route === 'object' && !Array.isArray(route);
    const fits =
      plain &&
      Object.keys(route).every((key) => ROUTE_KEYS.includes(key)) &&
      typeof route.path === 'string' &&
      route.action === 'bypass' &&
      (!Object.hasOwn(route, 'host') || typeof route.host === 'string');
    if (!fits) return { ...none, problem: 'form' };
  }
  return { value, count: value.length, problem: null };
}

/** `bytes` in the standard base64 with padding. */
export function toBase64(bytes) {
  // A multiple of 3 bytes at a time, so that the padding comes only at the end.
  const step = 3 * 8192;
  let out = '';
  for (let at = 0; at < bytes.length; at += step) {
    out += btoa(String.fromCharCode(...bytes.subarray(at, at + step)));
  }
  return out;
}

/** The body of the request to import. `rules` and `data` hold `{ name, data }` with the data in base64. */
export function importBody({ rules, data, crs, crsOff, routes, detectOnly, acceptBlock }) {
  const body = {};
  if (rules.length > 0) body.rules = rules;
  if (data.length > 0) body.data = data;
  if (crs) {
    body.crs = true;
    if (crsOff.length > 0) body.crs_off = crsOff;
  }
  if (routes !== null) body.routes = routes;
  if (detectOnly) body.detect_only = true;
  if (acceptBlock) body.accept_block = true;
  return body;
}

/** Whether the answer of a refused import says that the trial failed because a rule blocked one of its probes. */
export function trialBlocked(body) {
  const trial = body?.trial;
  return trial?.passed === false && typeof trial.failure === 'string' && BLOCKED.test(trial.failure);
}

/**
 * How the last import that this page sent ended, until a screen has told it: `{ body, error, request }`, the answer
 * or the error, and the request that was sent, which the user may send again with a block accepted. The screen that
 * sent the import can be gone when its answer comes (the language was switched, or the user went to another screen),
 * so the end waits here for the screen that is shown, and a screen that is drawn later finds it.
 */
export class Ended {
  #end = null;
  #watchers = new Set();

  /** Keeps the end of an import in place of an older one, and tells the watchers. */
  put(end) {
    this.#end = end;
    for (const watcher of [...this.#watchers]) watcher();
  }

  /** The end that waits, once; null when none does. */
  take() {
    const end = this.#end;
    this.#end = null;
    return end;
  }

  /** Gives up the end that waits. */
  clear() {
    this.#end = null;
  }

  /** Calls `watcher` whenever an end is put; gives back a function that stops that. */
  watch(watcher) {
    this.#watchers.add(watcher);
    return () => this.#watchers.delete(watcher);
  }
}

const ended = new Ended();

/** Gives up the end of an import that nobody has told: the sign-in has ended. */
export function forgetEnded() {
  ended.clear();
}

function readBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

const PROBLEMS = {
  none: () => t('import.p.none'),
  count: () => t('import.p.count'),
  total: () => t('import.p.total'),
  size: (problem) => t('import.p.size', { name: problem.name }),
  name: (problem) => t('import.p.name', { name: problem.name }),
  twice: (problem) => t('import.p.twice', { name: problem.name }),
};
const ROUTE_PROBLEMS = {
  json: () => t('import.r.json'),
  list: () => t('import.r.list'),
  many: () => t('import.r.many'),
  form: () => t('import.r.form'),
};
const RESULTS = {
  created: () => t('import.result.created'),
  existing: () => t('import.result.existing'),
  repaired: () => t('import.result.repaired'),
};
const KINDS = {
  block: () => t('import.kind.block'),
  detected: () => t('import.kind.detected'),
};

function checkbox(label, onChange, hint = null) {
  const input = el('input', { type: 'checkbox', on: { change: () => onChange(input.checked) } });
  return { input, row: el('label', { class: 'check' }, input, el('span', {}, label, hint === null ? null : el('span', { class: 'muted small block' }, hint))) };
}

/** What a trial says: whether it passed, why it did not, what it accepted. */
function trialView(trial) {
  const accepted = Array.isArray(trial.accepted) ? trial.accepted : [];
  return el(
    'div',
    { class: 'stack' },
    el('p', {}, trial.passed === true ? badge('ok', t('import.trial.passed')) : badge('bad', t('import.trial.failed'))),
    typeof trial.failure === 'string' ? el('p', {}, trial.failure) : null,
    typeof trial.detail === 'string' ? el('p', { class: 'small' }, t('import.trial.detail'), ' ', el('code', {}, trial.detail)) : null,
    accepted.length === 0
      ? null
      : table(
          [t('col.kind'), t('import.probe'), t('import.rule'), t('import.phase'), t('col.status')],
          accepted.map((item) => [
            Object.hasOwn(KINDS, item.kind) ? KINDS[item.kind]() : String(item.kind),
            String(item.probe),
            String(item.rule),
            item.phase === undefined ? '' : String(item.phase),
            String(item.status),
          ]),
          t('import.accepted'),
        ),
  );
}

class ImportScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.alive = true;
    this.mine = false;
    this.reading = false;
    /** The chosen files: `{ file, name, size }`. */
    this.rules = [];
    this.data = [];
    this.crsAvailable = false;
    this.crsFiles = [];
    this.crs = false;
    this.crsOff = new Set();
    this.detectOnly = false;
    /** The request that the last trial refused for a block, which the user may send again with the block accepted. */
    this.pending = null;

    this.running = el('div', { class: 'stack', 'aria-live': 'polite' });
    this.rulesBox = el('div');
    this.dataBox = el('div');
    this.crsBox = el('div', { class: 'stack' });
    this.routesBox = el('div', { 'aria-live': 'polite' });
    this.summary = el('div', { class: 'stack', 'aria-live': 'polite' });
    this.offer = el('div', { class: 'stack' });
    this.results = el('div', { class: 'stack', 'aria-live': 'polite' });
    this.layer = el('div');
    this.routes = el('textarea', { class: 'input mono', rows: '6', spellcheck: 'false', autocapitalize: 'none', on: { input: () => this.changed() } });
    this.detect = checkbox(t('import.detect'), (checked) => {
      this.detectOnly = checked;
      this.changed();
    }, t('import.detect_hint'));
    this.submit = el('button', { type: 'submit', class: 'btn btn-primary' }, t('import.submit'));

    const form = el(
      'form',
      {
        class: 'stack',
        on: {
          submit: (event) => {
            event.preventDefault();
            this.send(false);
          },
        },
      },
      this.group(t('import.rules'), t('import.rules_hint'), this.picker(this.rules), this.rulesBox),
      this.group(t('import.data'), t('import.data_hint'), this.picker(this.data), this.dataBox),
      this.group(t('import.crs'), null, this.crsBox),
      this.group(t('import.routes'), null, labelled(t('import.routes_label'), this.routes, t('import.routes_hint')), this.routesBox),
      this.detect.row,
      this.summary,
      el('div', { class: 'actions' }, this.submit),
    );
    mount(
      root,
      el('div', { class: 'stack' }, pageHead(t('import.title')), el('p', { class: 'muted' }, t('import.intro')), this.running, form, this.results, this.offer),
      this.layer,
    );
    this.unwatch = working.watch((name) => this.onWorking(name));
    this.unwatchEnded = ended.watch(() => this.tellEnd());
    this.onWorking(working.name);
    this.changed();
    this.tellEnd();
  }

  stop() {
    this.alive = false;
    this.unwatch();
    this.unwatchEnded();
  }

  group(title, hint, ...content) {
    return el('fieldset', { class: 'group' }, el('legend', {}, title), hint === null ? null : el('p', { class: 'muted small' }, hint), ...content);
  }

  /** The file input that adds to `list`. */
  picker(list) {
    const input = el('input', {
      type: 'file',
      multiple: true,
      class: 'input',
      'aria-label': t('import.choose'),
      on: {
        change: () => {
          for (const file of input.files) list.push({ file, name: file.name, size: file.size });
          // Cleared, so that the same file can be chosen again and the list is the only record of what is chosen.
          input.value = '';
          this.changed();
        },
      },
    });
    return input;
  }

  async start() {
    try {
      const status = await this.ctx.api.call('GET', '/api/status');
      if (!this.alive) return;
      const crs = status.crs;
      this.crsAvailable = crs?.available === true;
      this.crsFiles = Array.isArray(crs?.files) ? crs.files.filter((name) => typeof name === 'string') : [];
      this.drawCrs(null);
    } catch (error) {
      if (this.alive) this.drawCrs(error);
    }
  }

  onWorking(name) {
    if (!this.alive) return;
    mount(this.running, runningNotice());
    this.submit.disabled = name !== null || this.reading || this.problems().length > 0;
    this.submit.setAttribute('aria-busy', String(name === 'import' || this.reading));
  }

  problems() {
    return [...checkFiles({ rules: this.rules, data: this.data, crs: this.crs }).problems, ...(checkRoutes(this.routes.value).problem === null ? [] : [{ code: 'routes' }])];
  }

  /** The form changed: draws the lists, the counts and the problems again, and drops the request that waited. */
  changed() {
    this.pending = null;
    mount(this.offer);
    this.drawList(this.rulesBox, this.rules, true);
    this.drawList(this.dataBox, this.data, false);
    const check = checkFiles({ rules: this.rules, data: this.data, crs: this.crs });
    const routes = checkRoutes(this.routes.value);
    mount(
      this.routesBox,
      routes.problem === null
        ? routes.count === 0
          ? null
          : el('p', { class: 'muted small' }, t('import.r.count', { n: routes.count }))
        : notice('bad', ROUTE_PROBLEMS[routes.problem]()),
    );
    mount(
      this.summary,
      el('p', {}, t('import.summary', { files: check.files, bytes: bytesText(check.bytes), largest: bytesText(check.largest) })),
      el('p', { class: 'muted small' }, t('import.limits')),
      check.problems.length === 0
        ? null
        : notice(
            'bad',
            el('ul', { class: 'plain-list' }, check.problems.slice(0, SHOWN).map((problem) => el('li', {}, PROBLEMS[problem.code](problem)))),
            check.problems.length > SHOWN ? el('p', { class: 'small' }, t('import.p.more', { n: check.problems.length - SHOWN })) : null,
          ),
    );
    this.onWorking(working.name);
  }

  /** The files of `list`, each with the buttons that move or drop it (the order of the rule files is the order they load in). */
  drawList(box, list, ordered) {
    if (list.length === 0) {
      mount(box, el('p', { class: 'muted small' }, t('import.none_chosen')));
      return;
    }
    const move = (at, by) => {
      const [item] = list.splice(at, 1);
      list.splice(at + by, 0, item);
      this.changed();
    };
    mount(
      box,
      el(
        'ol',
        { class: 'files' },
        list.map((item, at) =>
          el(
            'li',
            {},
            el('span', { class: 'file-name' }, item.name),
            el('span', { class: 'muted small' }, bytesText(item.size)),
            el(
              'span',
              { class: 'actions' },
              ordered && at > 0 ? el('button', { type: 'button', class: 'btn btn-small', 'aria-label': t('import.up', { name: item.name }), on: { click: () => move(at, -1) } }, '↑') : null,
              ordered && at < list.length - 1 ? el('button', { type: 'button', class: 'btn btn-small', 'aria-label': t('import.down', { name: item.name }), on: { click: () => move(at, 1) } }, '↓') : null,
              el(
                'button',
                {
                  type: 'button',
                  class: 'btn btn-small',
                  'aria-label': t('import.drop', { name: item.name }),
                  on: {
                    click: () => {
                      list.splice(at, 1);
                      this.changed();
                    },
                  },
                },
                t('import.remove'),
              ),
            ),
          ),
        ),
      ),
    );
  }

  drawCrs(error) {
    if (error !== null) {
      mount(this.crsBox, notice('warn', t('import.crs_unknown'), ' ', this.ctx.describe(error)));
      return;
    }
    if (!this.crsAvailable) {
      mount(this.crsBox, el('p', { class: 'muted' }, t('import.crs_none')));
      return;
    }
    const use = checkbox(t('import.crs_use'), (checked) => {
      this.crs = checked;
      mount(off, checked ? offList : null);
      this.changed();
    }, t('import.crs_hint'));
    const offList = el(
      'fieldset',
      { class: 'group' },
      el('legend', {}, t('import.crs_off')),
      this.crsFiles.length === 0
        ? el('p', { class: 'muted small' }, t('import.crs_nofiles'))
        : el(
            'div',
            { class: 'checks' },
            this.crsFiles.map((name) => {
              const box = checkbox(name, (checked) => {
                if (checked) this.crsOff.add(name);
                else this.crsOff.delete(name);
                this.changed();
              });
              return box.row;
            }),
          ),
    );
    const off = el('div');
    mount(this.crsBox, use.row, off);
  }

  /** Reads the chosen files and gives the bodies of the request, or null with the notice of the file that failed. */
  async encode() {
    this.reading = true;
    this.onWorking(working.name);
    try {
      const read = async (list) => Promise.all(list.map(async (item) => ({ name: item.name, data: toBase64(await readBytes(item.file)) })));
      const rules = await read(this.rules);
      const data = await read(this.data);
      return importBody({
        rules,
        data,
        crs: this.crs,
        crsOff: this.crs ? [...this.crsOff] : [],
        routes: checkRoutes(this.routes.value).value,
        detectOnly: this.detectOnly,
        acceptBlock: false,
      });
    } catch {
      mount(this.results, notice('bad', t('import.read_failed')));
      return null;
    } finally {
      this.reading = false;
      if (this.alive) this.onWorking(working.name);
    }
  }

  async send(acceptBlock) {
    // The form is empty when the screen was drawn again after the trial; the request that waits was checked when sent.
    if ((!acceptBlock && this.problems().length > 0) || working.name !== null || this.reading) return;
    let body;
    if (acceptBlock) {
      body = { ...this.pending.body, accept_block: true };
    } else {
      body = await this.encode();
      if (body === null || !this.alive) return;
    }
    mount(this.offer);
    mount(this.results);
    this.mine = true;
    const result = await perform('import', () => this.ctx.api.call('POST', '/api/generations', body));
    this.mine = false;
    if (result.skipped) return;
    // Whichever screen is shown now tells the end, which may not be this one.
    ended.put({ body: result.body, error: result.error, request: body });
  }

  /** Tells the end of an import that waits, if one does. */
  async tellEnd() {
    if (!this.alive) return;
    const end = ended.take();
    if (end === null) return;
    this.pending = null;
    mount(this.offer);
    if (end.error === null) {
      this.done(end.body);
      return;
    }
    await this.refused(end.error, end.request);
  }

  done(answer) {
    const id = answer.fingerprint;
    this.ctx.refreshStatus();
    mount(
      this.results,
      notice(
        'ok',
        el('p', {}, badge('ok', Object.hasOwn(RESULTS, answer.result) ? RESULTS[answer.result]() : String(answer.result)), ' ', t('import.done', { id: shortOf(id) })),
        el('dl', { class: 'kv' }, row(t('col.fingerprint'), fingerprint(id))),
        typeof answer.trial === 'object' && answer.trial !== null ? trialView(answer.trial) : null,
        el('p', {}, t('import.notchosen')),
        el('p', {}, el('a', { class: 'btn', href: '#/generations', on: { click: () => handoff.set(id) } }, t('import.open'))),
      ),
    );
  }

  async refused(error, body) {
    if (!(error instanceof ApiError)) {
      mount(this.results, notice('bad', this.ctx.describe(error)));
      return;
    }
    const answer = error.body;
    if (error.kind === 'unknown') {
      mount(this.results, notice('warn', this.ctx.describe(error, { change: true })));
      await this.findNewest();
      return;
    }
    if (typeof answer?.trial === 'object' && answer.trial !== null) {
      mount(this.results, notice('bad', el('p', {}, this.ctx.describe(error)), trialView(answer.trial)));
      if (trialBlocked(answer)) this.offerAccept(answer.trial, body);
      return;
    }
    const subject = typeof answer?.subject === 'string' ? answer.subject : null;
    mount(
      this.results,
      notice(error.kind === 'conflict' ? 'warn' : 'bad', this.ctx.describe(error, { change: true }), subject === null ? null : [' ', el('code', {}, subject)]),
    );
  }

  /** The trial reported a block: the user may import the generation all the same, after a second confirmation. */
  offerAccept(trial, body) {
    this.pending = { body };
    mount(
      this.offer,
      notice(
        'warn',
        el('p', {}, t('import.blocked_hint')),
        el(
          'p',
          {},
          el('button', { type: 'button', class: 'btn btn-danger', disabled: working.name !== null, on: { click: () => this.accept(trial) } }, t('import.accept')),
        ),
      ),
    );
  }

  async accept(trial) {
    if (this.pending === null) return;
    const yes = await confirmChange(this.layer, {
      title: t('import.accept.title'),
      lines: [el('p', {}, t('import.accept.what')), el('p', {}, el('code', {}, String(trial.failure))), el('p', { class: 'small' }, t('import.accept.after'))],
      confirm: t('import.accept.confirm'),
      tone: 'danger',
    });
    if (!yes || !this.alive || this.pending === null) return;
    await this.send(true);
  }

  /** No answer came: reads the list of generations and shows the newest, which is the new one if the import ended. */
  async findNewest() {
    let list = null;
    try {
      list = await this.ctx.api.call('GET', '/api/generations');
    } catch {
      list = null;
    }
    if (!this.alive) return;
    const items = Array.isArray(list?.generations) ? list.generations.slice(0, 3) : null;
    this.results.append(
      items === null
        ? notice('bad', t('found.failed'))
        : el(
            'section',
            { class: 'card' },
            el('h2', {}, t('import.newest')),
            table(
              [t('col.fingerprint'), t('col.made')],
              items.map((item) => [fingerprint(item.fingerprint), utc(item.made)]),
              t('import.newest'),
            ),
            el('p', {}, el('a', { href: '#/generations' }, t('import.open_list'))),
          ),
    );
  }
}

function mountImport(ctx, root) {
  const screen = new ImportScreen(ctx, root);
  screen.start();
  return () => screen.stop();
}

export const screens = [{ id: 'import', title: () => t('nav.import'), least: 'operator', mount: mountImport }];
