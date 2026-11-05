// The import screen: the user chooses rule files and data files in the browser, says whether the CRS of the host is
// used (and which of its files are left out), lists the routes that are not inspected, and imports them as a new
// generation. The files are counted against the limits of the API before anything is sent. The API tries the new
// rules with an inspector first; a trial that reports a block is shown, and the user may accept the block through a
// second confirmation. The new generation is not chosen. How an import ended waits in `ended` for the screen that is
// shown, which may not be the one that sent it. Nothing runs when the module is loaded.

import { ApiError } from './api.js';
import { append, badge, button, buttonClass, el, mount, notice, result, setText } from './dom.js';
import { lazy, w } from './i18n.js';
import {
  Field,
  bytesText,
  checkbox,
  choice,
  confirmChange,
  engineName,
  fingerprintView,
  hashOf,
  isFingerprint,
  kv,
  pageHead,
  panelWith,
  perform,
  restoreFocus,
  row,
  runningNotice,
  shortOf,
  textInput,
  timeCell,
  timeLabel,
  working,
} from './parts.js';
import { Table } from './table.js';

/** The engines that an import can ask for, by the words the API takes. Coraza is first: it is the default. */
export const ENGINES = ['coraza', 'modsecurity'];
/** The limits of the API: files in all, bytes of a file, bytes of all the files, routes. */
export const LIMITS = { files: 128, file: 2 * 1024 * 1024, total: 8 * 1024 * 1024, routes: 256 };
/** The name of a file as a bundle holds it: one name, no path, letters, digits and `._-`, not starting with a dot. */
const NAME = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;
const ROUTE_KEYS = ['host', 'path', 'action'];
/** How the trial reports a probe that the rules blocked (see `trialBlocked`). */
const BLOCKED = /: blocked by rule -?\d+ in phase \d+, status \d+$/;

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
 * The routes that are not inspected, as the form of a file of routes: a list of `{ "host"?, "path", "action":
 * "bypass" }`. Gives `{ value, count, problem }`: `value` is what to send (null for no routes), `problem` is null or
 * `list` (not a list, or an empty one), `many` (over the limit) or `form` (an item is not a route). The API checks
 * the paths and hosts as well.
 */
export function checkRouteList(value) {
  const none = { value: null, count: 0, problem: null };
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

/**
 * The routes of the lines of the table of routes (`{ host, path }` as typed): a line with neither is left out, a line
 * with a host and no path is a problem (`missing`, the places of such lines), and the others are routes.
 */
export function routesOfRows(lines) {
  const routes = [];
  const missing = [];
  lines.forEach((line, at) => {
    const host = line.host.trim();
    const path = line.path.trim();
    if (host === '' && path === '') return;
    if (path === '') missing.push(at);
    else routes.push(host === '' ? { path, action: 'bypass' } : { host, path, action: 'bypass' });
  });
  return { routes, missing };
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
export function importBody({ engine, rules, data, crs, crsOff, routes, detectOnly, acceptBlock }) {
  // A missing engine would be left out of the JSON, and the server would take Coraza for it.
  if (!ENGINES.includes(engine)) throw new RangeError(`not an engine: ${engine}`);
  const body = { engine };
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
 * sent the import can be gone when its answer comes (the user went to another screen), so the end waits here for the
 * screen that is shown, and a screen that is drawn later finds it.
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

/** What to write for each problem of the files. */
const PROBLEMS = {
  none: () => w('import.p.none'),
  count: () => w('import.p.count'),
  total: () => w('import.p.total'),
  size: () => w('import.p.size'),
  name: () => w('import.p.name'),
  twice: () => w('import.p.twice'),
};
const ROUTE_PROBLEMS = {
  list: () => w('import.r.list'),
  many: () => w('import.r.many'),
  form: () => w('import.r.form'),
};
const RESULTS = {
  created: () => w('import.result.created'),
  existing: () => w('import.result.existing'),
  repaired: () => w('import.result.repaired'),
};
const KINDS = {
  block: () => w('import.kind.block'),
  detected: () => w('import.kind.detected'),
};

/** What a trial says: whether it passed, why it did not, what it accepted. */
function trialView(trial) {
  const accepted = Array.isArray(trial.accepted) ? trial.accepted : [];
  const table = new Table({
    caption: w('import.accepted'),
    rowKey: (item, at) => String(at),
    filter: false,
    empty: { title: w('import.accepted') },
    columns: [
      { key: 'kind', label: w('col.kind'), value: (item) => String(item.kind), cell: (item) => (Object.hasOwn(KINDS, item.kind) ? KINDS[item.kind]() : String(item.kind)) },
      { key: 'probe', label: w('import.probe'), value: (item) => String(item.probe), mono: true },
      { key: 'rule', label: w('import.rule'), value: (item) => String(item.rule), mono: true },
      { key: 'phase', label: w('import.phase'), value: (item) => (item.phase === undefined ? '' : item.phase), num: true },
      { key: 'status', label: w('col.status'), value: (item) => item.status, num: true },
    ],
  });
  table.update({ rows: accepted });
  return el(
    'div',
    { class: 'tc-stack' },
    el('p', {}, trial.passed === true ? badge('ok', w('import.trial.passed')) : badge('bad', w('import.trial.failed'))),
    typeof trial.failure === 'string' ? el('p', {}, trial.failure) : null,
    typeof trial.detail === 'string' ? el('p', { class: 'tc-small' }, w('import.trial.detail'), ' ', el('code', {}, trial.detail)) : null,
    accepted.length === 0 ? null : table.node,
  );
}

class ImportScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.root = root;
    this.alive = true;
    this.mine = false;
    this.reading = false;
    /** True once the user has tried to import: the missing rule files are told from then on. */
    this.tried = false;
    /** The chosen files: `{ file, name, size }`. */
    this.rules = [];
    this.data = [];
    this.crsAvailable = false;
    this.crsFiles = [];
    this.crs = false;
    this.crsOff = new Set();
    this.detectOnly = false;
    /** The lines of the table of routes: `{ host, path, fields }`, the typed text and the fields that show it. */
    this.lines = [];
    /** The request that the last trial refused for a block, which the user may send again with the block accepted. */
    this.pending = null;

    this.running = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    this.rulesBox = el('div');
    this.dataBox = el('div');
    this.crsBox = el('div', { class: 'tc-stack' });
    this.routesBox = el('div', { class: 'tc-rows' });
    this.routesNote = el('div', { 'aria-live': 'polite' });
    this.summary = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    this.offer = el('div', { class: 'tc-stack' });
    this.results = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    this.layer = el('div');
    this.engine = el(
      'select',
      { class: 'tc-select', name: 'engine' },
      ENGINES.map((name) => el('option', { value: name, selected: name === ENGINES[0] }, lazy(() => engineName(name)))),
    );
    this.engine.addEventListener('change', () => this.changed());
    this.rulesField = new Field(w('import.choose'), this.picker(this.rules), { hint: w('import.rules_hint'), asButton: true });
    this.dataField = new Field(w('import.choose'), this.picker(this.data), { hint: w('import.data_hint'), asButton: true });
    this.detect = checkbox((checked) => {
      this.detectOnly = checked;
      this.changed();
    });
    this.submit = button('primary', w('import.submit'), null, { type: 'submit' });

    const form = el(
      'form',
      {
        class: 'tc-stack tc-stack--wide',
        novalidate: true,
        on: {
          submit: (event) => {
            event.preventDefault();
            this.send(false);
          },
        },
      },
      panelWith(w('import.engine'), [], new Field(w('import.engine_label'), this.engine, { hint: w('import.engine_hint') }).node).node,
      panelWith(w('import.rules'), [], this.rulesField.node, this.rulesBox).node,
      panelWith(w('import.data'), [], this.dataField.node, this.dataBox).node,
      panelWith(w('import.crs'), [], this.crsBox).node,
      panelWith(w('import.routes'), [], el('p', { class: 'tc-muted tc-small' }, w('import.routes_hint')), this.routesBox, this.routesNote, el('div', { class: 'tc-actions' }, button('small', w('import.route_add'), () => this.addLine(true)))).node,
      panelWith(w('import.submit_title'), [], choice(w('import.detect'), this.detect, w('import.detect_hint')), this.summary, el('div', { class: 'tc-actions' }, this.submit)).node,
    );
    mount(root, pageHead(w('nav.import')), el('p', { class: 'tc-intro' }, w('import.intro')), this.running, this.results, this.offer, form, this.layer);
    this.unwatch = working.watch((name) => this.onWorking(name));
    this.unwatchEnded = ended.watch(() => this.tellEnd());
    this.addLine(false);
    this.onWorking(working.name);
    this.changed();
    this.tellEnd();
  }

  stop() {
    this.alive = false;
    this.unwatch();
    this.unwatchEnded();
  }

  /** The file input that adds to `list`. It is hidden, and the name of its field opens it: the list below says what is chosen, and the input itself says nothing. */
  picker(list) {
    const input = el('input', { type: 'file', multiple: true, class: 'tc-file' });
    input.addEventListener('change', () => {
      for (const file of input.files) list.push({ file, name: file.name, size: file.size });
      // Cleared, so that the same file can be chosen again and the list is the only record of what is chosen.
      input.value = '';
      this.changed();
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
    const busy = name === 'import' || this.reading;
    this.submit.disabled = name !== null || this.reading;
    this.submit.setAttribute('aria-busy', String(busy));
    setText(this.submit, busy ? w('import.busy') : w('import.submit'));
  }

  /** What the form holds now, counted: the files, and the routes of the table. */
  check() {
    const files = checkFiles({ rules: this.rules, data: this.data, crs: this.crs });
    const { routes, missing } = routesOfRows(this.lines.map((line) => ({ host: line.host.control.value, path: line.path.control.value })));
    return { files, routes: routes.length === 0 ? { value: null, count: 0, problem: null } : checkRouteList(routes), list: routes, missing };
  }

  /** The form changed: draws the lists, the counts and the problems again, and drops the request that waited. */
  changed() {
    this.pending = null;
    mount(this.offer);
    const check = this.check();
    this.drawList(this.rulesBox, this.rules, true, check);
    this.drawList(this.dataBox, this.data, false, check);
    const loud = check.files.problems.filter((problem) => problem.code !== 'name' && problem.code !== 'size' && problem.code !== 'twice');
    const first = loud.find((problem) => problem.code !== 'none' || this.tried);
    if (first === undefined) this.rulesField.valid();
    else this.rulesField.invalid(PROBLEMS[first.code]());
    this.drawRoutesNote(check);
    mount(
      this.summary,
      el('p', {}, w('import.summary', { files: check.files.files, bytes: bytesText(check.files.bytes), largest: bytesText(check.files.largest) })),
      el('p', { class: 'tc-muted tc-small' }, w('import.limits')),
    );
    this.onWorking(working.name);
  }

  /** Whether anything on the form is wrong, as the fields that say so, so that the first of them can take the focus. */
  problems() {
    const check = this.check();
    const fields = [];
    if (check.files.problems.length > 0) fields.push(this.rulesField.control);
    for (const at of check.missing) fields.push(this.lines[at].path.control);
    if (check.routes.problem !== null) fields.push(this.lines[0].host.control);
    return fields;
  }

  drawRoutesNote(check) {
    mount(
      this.routesNote,
      check.routes.problem === null && check.list.length > 0 ? el('p', { class: 'tc-muted tc-small' }, w('import.r.count', { n: check.routes.count })) : null,
      check.routes.problem !== null && check.list.length > 0 ? notice('bad', ROUTE_PROBLEMS[check.routes.problem]()) : null,
    );
    this.lines.forEach((line, at) => {
      if (check.missing.includes(at)) line.path.invalid(w('import.r.path'));
      else line.path.valid();
    });
  }

  // ---- the files ----

  /** The files of `list`, each with the buttons that move or drop it (the order of the rule files is the order they load in). */
  drawList(box, list, ordered, check) {
    if (list.length === 0) {
      mount(box, el('p', { class: 'tc-muted tc-small' }, w('import.none_chosen')));
      return;
    }
    const faults = (name) => check.files.problems.filter((problem) => problem.name === name);
    const move = (at, by) => {
      const [item] = list.splice(at, 1);
      list.splice(at + by, 0, item);
      this.changed();
    };
    mount(
      box,
      el(
        'ol',
        { class: 'tc-files' },
        list.map((item, at) =>
          el(
            'li',
            {},
            el('span', { class: 'tc-mono' }, item.name),
            el('span', { class: 'tc-muted tc-small' }, bytesText(item.size)),
            faults(item.name).map((problem) => el('span', { class: 'tc-error' }, PROBLEMS[problem.code]())),
            el(
              'span',
              { class: 'tc-actions' },
              ordered && at > 0 ? button('small quiet', '↑', () => move(at, -1), { 'aria-label': w('import.up', { name: item.name }) }) : null,
              ordered && at < list.length - 1 ? button('small quiet', '↓', () => move(at, 1), { 'aria-label': w('import.down', { name: item.name }) }) : null,
              button(
                'small quiet',
                w('import.remove'),
                () => {
                  list.splice(at, 1);
                  this.changed();
                },
                { 'aria-label': w('import.drop', { name: item.name }) },
              ),
            ),
          ),
        ),
      ),
    );
  }

  drawCrs(error) {
    if (error !== null) {
      mount(this.crsBox, notice('warn', w('import.crs_unknown'), ' ', this.ctx.describe(error)));
      return;
    }
    if (!this.crsAvailable) {
      mount(this.crsBox, el('p', { class: 'tc-muted' }, w('import.crs_none')));
      return;
    }
    const off = el('div');
    const use = checkbox((checked) => {
      this.crs = checked;
      mount(off, checked ? offList : null);
      this.changed();
    });
    const offList = el(
      'fieldset',
      { class: 'tc-stack' },
      el('legend', { class: 'tc-label' }, w('import.crs_off')),
      this.crsFiles.length === 0
        ? el('p', { class: 'tc-muted tc-small' }, w('import.crs_nofiles'))
        : el(
            'div',
            { class: 'tc-checks' },
            this.crsFiles.map((name) => {
              const box = checkbox((checked) => {
                if (checked) this.crsOff.add(name);
                else this.crsOff.delete(name);
                this.changed();
              });
              return choice(name, box);
            }),
          ),
    );
    mount(this.crsBox, choice(w('import.crs_use'), use, w('import.crs_hint')), off);
  }

  // ---- the routes that are not inspected ----

  /** Adds a line to the table of routes; `focus` puts the focus on its host. */
  addLine(focus) {
    const host = new Field(w('import.r.host'), textInput({ name: 'route-host', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', placeholder: 'admin.example.com' }));
    const path = new Field(w('import.r.path_label'), textInput({ name: 'route-path', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', placeholder: '/api/generations' }));
    const line = { host, path };
    for (const field of [host, path]) field.control.addEventListener('input', () => this.changed());
    const remove = button('small quiet', w('import.remove'), () => {
      this.lines.splice(this.lines.indexOf(line), 1);
      this.drawLines();
      this.changed();
    });
    line.node = el('div', { class: 'tc-rows__row' }, host.node, path.node, remove);
    this.lines.push(line);
    this.drawLines();
    if (focus) host.control.focus();
  }

  drawLines() {
    mount(this.routesBox, this.lines.map((line) => line.node));
  }

  // ---- sending ----

  /** Reads the chosen files and gives the bodies of the request, or null with the notice of the file that failed. */
  async encode() {
    this.reading = true;
    this.onWorking(working.name);
    try {
      const read = async (list) => Promise.all(list.map(async (item) => ({ name: item.name, data: toBase64(await readBytes(item.file)) })));
      const rules = await read(this.rules);
      const data = await read(this.data);
      return importBody({
        engine: this.engine.value,
        rules,
        data,
        crs: this.crs,
        crsOff: this.crs ? [...this.crsOff] : [],
        routes: this.check().routes.value,
        detectOnly: this.detectOnly,
        acceptBlock: false,
      });
    } catch {
      mount(this.results, notice('bad', w('import.read_failed')));
      return null;
    } finally {
      this.reading = false;
      if (this.alive) this.onWorking(working.name);
    }
  }

  async send(acceptBlock) {
    if (working.name !== null || this.reading) return;
    if (!acceptBlock) {
      this.tried = true;
      this.changed();
      const fields = this.problems();
      if (fields.length > 0) {
        fields[0].focus();
        return;
      }
    }
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
    const done = await perform('import', () => this.ctx.api.call('POST', '/api/generations', body));
    this.mine = false;
    if (done.skipped) return;
    // Whichever screen is shown now tells the end, which may not be this one.
    ended.put({ body: done.body, error: done.error, request: body });
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
    const box = result(
      'ok',
      w('import.done_title'),
      el('span', {}, badge('ok', Object.hasOwn(RESULTS, answer.result) ? RESULTS[answer.result]() : String(answer.result)), ' ', w('import.done', { id: shortOf(id) })),
      w('import.notchosen'),
    );
    // What the import made is told inside the box of its result.
    append(box, [
      kv(row(w('col.fingerprint'), fingerprintView(id))),
      typeof answer.trial === 'object' && answer.trial !== null ? trialView(answer.trial) : null,
      // The address of the generation is made only from a fingerprint: what the answer holds is checked before it is used.
      isFingerprint(id) ? el('div', { class: 'tc-actions' }, el('a', { class: buttonClass(''), href: hashOf('generations', { id }) }, w('import.open'))) : null,
    ]);
    mount(this.results, box);
    restoreFocus(this.root, this.root.querySelector('h1'));
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
      mount(this.results, append(result('bad', w('import.refused_title'), this.ctx.describe(error), null), [trialView(answer.trial)]));
      if (trialBlocked(answer)) this.offerAccept(answer.trial, body);
      return;
    }
    const subject = typeof answer?.subject === 'string' ? answer.subject : null;
    mount(this.results, notice(error.kind === 'conflict' ? 'warn' : 'bad', this.ctx.describe(error, { change: true }), subject === null ? null : [' ', el('code', {}, subject)]));
  }

  /** The trial reported a block: the user may import the generation all the same, after a second confirmation. */
  offerAccept(trial, body) {
    this.pending = { body };
    mount(
      this.offer,
      notice(
        'warn',
        el('span', {}, w('import.blocked_hint')),
        el('div', { class: 'tc-actions' }, button('danger', w('import.accept'), () => this.accept(trial), { disabled: working.name !== null })),
      ),
    );
  }

  async accept(trial) {
    if (this.pending === null) return;
    const yes = await confirmChange(this.layer, {
      title: w('import.accept.title'),
      lines: [el('p', {}, w('import.accept.what')), el('p', {}, el('code', {}, String(trial.failure))), el('p', { class: 'tc-muted tc-small' }, w('import.accept.after'))],
      confirm: w('import.accept.confirm'),
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
    if (items === null) {
      this.results.append(notice('bad', w('found.failed')));
      return;
    }
    const table = new Table({
      caption: w('import.newest'),
      rowKey: (item) => item.fingerprint,
      filter: false,
      empty: { title: w('gen.empty') },
      columns: [
        { key: 'fingerprint', label: w('col.fingerprint'), value: (item) => item.fingerprint, mono: true, cell: (item) => el('a', { class: 'tc-link tc-mono', href: hashOf('generations', { id: item.fingerprint }) }, `${shortOf(item.fingerprint)}…`) },
        { key: 'made', label: timeLabel(w('col.made')), value: (item) => item.made, cell: (item) => timeCell(item.made, 's') },
      ],
    });
    table.update({ rows: items });
    this.results.append(panelWith(w('import.newest'), [el('a', { class: buttonClass('quiet small'), href: hashOf('generations') }, w('import.open_list'))], table.node).node);
  }
}

function mountImport(ctx, root) {
  const screen = new ImportScreen(ctx, root);
  screen.start();
  return { stop: () => screen.stop() };
}

export const screens = [{ id: 'import', title: w('nav.import'), least: 'operator', mount: mountImport }];
