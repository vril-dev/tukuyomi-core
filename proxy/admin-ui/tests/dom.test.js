import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ApiError } from '../js/api.js';
import { bindAttribute, el, mount, retranslate, safeUrl, setText } from '../js/dom.js';
import { lazy, setLanguage, w } from '../js/i18n.js';
import { ENGINE_IDS, outcomeView } from '../js/parts.js';
import { draftFromVersion, forgetDraft, heldDraft } from '../js/managed/edit/draft.js';
import { screens as generationScreens } from '../js/waf/generations.js';
import { screens as wafScreens } from '../js/waf/waf.js';
import { screens as importScreens } from '../js/waf/import.js';
import { jobResult } from '../js/managed/job.js';
import { detectNotice } from '../js/managed/edit/bar.js';
import { removalView, screens as managedScreens } from '../js/managed/managed.js';
import { countsOf, defaultGroupView, diffRows } from '../js/managed/screen.js';
import { valueTree } from '../js/managed/history.js';
import { start } from '../js/app.js';

// `el` builds elements with the DOM of the page. A small stand-in is enough for what these tests look at: it keeps the
// tree, the attributes and the listeners, finds elements by a few selectors, and has the focus. Each
// test file runs in a process of its own, so this does not reach the other files.
class Node {
  constructor() {
    this.parent = null;
    this.children = [];
  }

  get childNodes() {
    return this.children;
  }

  get firstChild() {
    return this.children[0] ?? null;
  }

  get isConnected() {
    let node = this;
    while (node.parent !== null) node = node.parent;
    return node === globalThis.document;
  }

  get textContent() {
    return this.children.map((child) => child.textContent).join('');
  }

  append(...nodes) {
    for (const node of nodes) {
      node.parent?.children.splice(node.parent.children.indexOf(node), 1);
      node.parent = this;
      this.children.push(node);
    }
  }

  replaceChildren(...nodes) {
    for (const child of this.children) child.parent = null;
    this.children = [];
    this.append(...nodes);
  }

  remove() {
    this.parent?.children.splice(this.parent.children.indexOf(this), 1);
    this.parent = null;
  }

  contains(other) {
    for (let node = other; node !== null && node !== undefined; node = node.parent) if (node === this) return true;
    return false;
  }
}

class Text extends Node {
  constructor(data) {
    super();
    this.data = data;
  }

  get textContent() {
    return this.data;
  }
}

class Element extends Node {
  constructor(tag) {
    super();
    this.tag = tag;
    this.attributes = {};
    this.listeners = {};
    this.value = '';
  }

  // These two are properties that the page reads and sets, and attributes that a button or an element is made with.
  get disabled() {
    return this.attributes.disabled !== undefined;
  }

  set disabled(value) {
    if (value) this.attributes.disabled = '';
    else delete this.attributes.disabled;
  }

  get hidden() {
    return this.attributes.hidden !== undefined;
  }

  set hidden(value) {
    if (value) this.attributes.hidden = '';
    else delete this.attributes.hidden;
  }

  get className() {
    return this.attributes.class ?? '';
  }

  set className(value) {
    this.attributes.class = value;
  }

  get textContent() {
    return this.children.map((child) => child.textContent).join('');
  }

  set textContent(value) {
    this.replaceChildren(new Text(String(value)));
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return this.attributes[name] ?? null;
  }

  removeAttribute(name) {
    delete this.attributes[name];
  }

  addEventListener(type, handler) {
    (this.listeners[type] ??= []).push(handler);
  }

  dispatch(type, event = {}) {
    for (const handler of this.listeners[type] ?? []) handler({ type, target: this, preventDefault() {}, ...event });
  }

  focus() {
    globalThis.document.activeElement = this;
  }

  // A dialog opened by `confirmChange` or `openDialog`: it closes with the value of the button that closed it.
  showModal() {
    this.open = true;
  }

  close(value = '') {
    this.returnValue = value;
    this.open = false;
    this.dispatch('close');
  }

  matches(selector) {
    const attribute = /^\[([\w-]+)(?:="([^"]*)")?\]$/.exec(selector);
    if (attribute !== null) return this.getAttribute(attribute[1]) !== null && (attribute[2] === undefined || this.getAttribute(attribute[1]) === attribute[2]);
    return this.tag === selector;
  }

  querySelectorAll(selector) {
    const found = [];
    const walk = (node) => {
      for (const child of node.children) {
        if (child instanceof Element) {
          if (child.matches(selector)) found.push(child);
          walk(child);
        }
      }
    };
    walk(this);
    return found;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }
}

/** Starts the fake page: an empty document with the stand-ins in place. */
function fakePage() {
  const document = new Node();
  document.documentElement = new Element('html');
  document.documentElement.dataset = {};
  document.body = new Element('body');
  document.append(document.body);
  document.activeElement = document.body;
  document.addEventListener = () => {};
  document.removeEventListener = () => {};
  document.createElement = (tag) => new Element(tag);
  document.createElementNS = (space, tag) => new Element(tag);
  document.createTextNode = (data) => new Text(data);
  globalThis.Node = Node;
  globalThis.document = document;
  return document;
}

const document = fakePage();

test('a URL may name a part of this page or a file next to the scripts, and nothing else', () => {
  const file = new URL('../js/app.js', import.meta.url).href;
  for (const value of ['#/overview', '#', file]) assert.equal(safeUrl(value), true, value);
  for (const value of [
    'javascript:alert(1)',
    ' javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    '//host/ui/app.js',
    'https://host/ui/app.js',
    'data:text/html,x',
    '/api/logout',
    '/ui/app.js',
    '',
    null,
    undefined,
  ]) {
    assert.equal(safeUrl(value), false, String(value));
  }
});

test('an element refuses a javascript: URL, an attribute that starts with on, style and srcdoc', () => {
  for (const [tag, attributes] of [
    ['a', { href: 'javascript:alert(1)' }],
    ['a', { HREF: 'JavaScript:alert(1)' }],
    ['a', { href: '//host/x' }],
    ['img', { src: 'https://host/x.png' }],
    ['form', { action: 'javascript:alert(1)' }],
    ['button', { formaction: 'javascript:alert(1)' }],
    ['a', { onclick: 'alert(1)' }],
    ['a', { OnClick: 'alert(1)' }],
    ['img', { onerror: 'alert(1)' }],
    ['div', { style: 'color: red' }],
    ['div', { STYLE: 'color: red' }],
    ['iframe', { srcdoc: '<p>x</p>' }],
  ]) {
    assert.throws(() => el(tag, attributes), /not allowed/, JSON.stringify(attributes));
  }
  // An element that `el` did not make is bound to words under the same refusals.
  for (const name of ['onclick', 'style', 'href', 'srcdoc']) assert.throws(() => bindAttribute(el('a'), name, w('table.prev')), /not allowed/, name);
  // The attributes of the page itself pass, and the listeners go in through `on`.
  const link = el('a', { href: '#/overview', class: 'nav', 'aria-label': 'x', hidden: true, on: { click: () => {} } });
  assert.deepEqual(link.attributes, { href: '#/overview', class: 'nav', 'aria-label': 'x', hidden: '' });
});

test('a string given to an element is text and never markup', () => {
  const text = '<img src=x onerror=alert(1)>';
  const node = el('p', {}, text, 7, null, [false, 'b']);
  assert.deepEqual(node.children.map((child) => child.data), [text, '7', 'b']);
  assert.equal(node.children.length, 3);
});

test('words follow the language where they stand, and what was typed stays', () => {
  setLanguage('en');
  const input = el('input', { 'aria-label': w('table.filter') });
  input.value = 'typed text';
  const box = el('div', {}, el('p', {}, w('table.prev')), input, el('p', {}, w('table.count', { n: 7 })));
  document.body.append(box);
  assert.deepEqual([box.children[0].textContent, input.getAttribute('aria-label'), box.children[2].textContent], ['Previous', 'Filter this table', '7 rows']);
  setLanguage('ja');
  retranslate();
  assert.deepEqual([box.children[0].textContent, input.getAttribute('aria-label'), box.children[2].textContent], ['前へ', '表の中を絞り込む', '7 件']);
  // The same elements are in place, with the text the user typed.
  assert.equal(box.children[1], input);
  assert.equal(input.value, 'typed text');
  // Words that were put in the place of other words are not worked out any more where they were taken away.
  const label = el('p', {}, w('table.next'));
  setText(label, w('table.prev'));
  mount(box, label);
  setLanguage('en');
  retranslate();
  assert.equal(label.textContent, 'Previous');
  setLanguage('en');
});

const press = (node) => node.dispatch('click');
const wait = () => new Promise((resolve) => setTimeout(resolve, 0));

const FP = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);

/**
 * An answer of `GET /api/status` of this version. `chosen` and `rollback` are what the rules store says, by engine;
 * `running` is the generation that the proxy serves for each engine that it runs (`null`: a proxy that does not report
 * its engines); `proxy` is `null` for a proxy that cannot be reached, or what it says besides.
 */
function statusOf({ chosen = {}, rollback = {}, running = {}, proxy = {}, name = 'coraza' }) {
  const engines = ENGINE_IDS.map((engine) => ({ engine, current: chosen[engine] ?? null, rollback_to: rollback[engine] ?? null }));
  const ran = running === null ? null : Object.entries(running).map(([engine, generation]) => ({ engine, generation, mode: 'block', phase: 'ready' }));
  const base = { generation: FP, mode: 'block', engine: name, phase: 'ready', switching: false, ready: true, engines: ran };
  return { current: chosen[name] ?? null, reachable: proxy !== null, rollback_to: rollback[name] ?? null, default_engine: name, engines, proxy: proxy === null ? null : { ...base, ...proxy }, crs: { available: false, files: [] } };
}

test('the overview shows the numbers of the proxy, and a dash where the proxy gave none, with the reason said once', () => {
  setLanguage('en');
  const mountOverview = wafScreens[0].mount;
  const shown = (proxy) => {
    const data = statusOf({ chosen: { coraza: FP }, running: { coraza: FP }, proxy });
    const root = document.createElement('main');
    document.body.append(root);
    const api = { call: async () => ({ managed: false }) };
    mountOverview({ status: () => ({ data, error: null, at: new Date(0), busy: false }), onStatus: () => () => {}, refreshStatus() {}, describe: String, api }, root);
    return root.textContent;
  };
  const full = shown({ phase: 'ready', mode: 'block', engine: 'coraza', switching: false, generation: FP, uptime_ms: 3_700_000, requests: 12408, blocked: 31, policy_refused: 6, upstream_failures: 0, config: OTHER, config_reloads: { replaced: 3, refused: 1 } });
  for (const text of ['12,408', 'Up for 1 h 1 min', 'Refused 1', `${OTHER.slice(0, 12)}…`]) assert.equal(full.includes(text), true, text);
  assert.equal(full.includes('Not read'), false);
  const times = (text, part) => text.split(part).length - 1;
  // An old proxy gives none of the numbers; a number that is 0 is a number and is not confused with a missing one.
  const old = shown({ phase: 'ready', mode: 'block', engine: 'coraza', switching: false, generation: FP, requests: null, blocked: 0 });
  assert.equal(times(old, 'This proxy does not give the numbers of the overview that show —.'), 1);
  assert.equal(old.includes('—'), true);
  const away = shown(null);
  assert.equal(times(away, 'The proxy cannot be reached.'), 1);
  assert.equal(times(away, 'Not read'), 6);
});

test('the list of generations is a table, and the address of one generation opens its detail and closes it again', async () => {
  setLanguage('en');
  const item = (fingerprint, current) => ({ fingerprint, made: 1_795_000_000, mode: 'block', engine: 'coraza', routes: 2, current, serving: current });
  const calls = [];
  const api = {
    async call(method, path) {
      calls.push(path);
      if (path === '/api/generations') return { reachable: true, generations: [item(FP, true), item(OTHER, false)] };
      if (path === '/api/status') return statusOf({ chosen: { coraza: FP }, rollback: { coraza: OTHER }, running: { coraza: FP } });
      return { ...item(path.slice(-64), false), load: ['a.conf'], files: [{ path: 'a.conf', size: 10, sha256: 'c'.repeat(64) }], routes: [{ path: '/x', action: 'bypass' }] };
    },
  };
  const ctx = { user: { name: 'ann', role: 'operator' }, api, describe: String, refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = generationScreens[0].mount(ctx, root, { id: null, query: {} });
  await wait();
  assert.equal(root.querySelectorAll('[data-row]').length, 2);
  // The other generation can be chosen and deleted; the chosen one only says why it cannot be deleted.
  assert.equal(root.textContent.includes('Switch to this generation'), true);
  assert.equal(root.textContent.includes('It is chosen, so it cannot be removed.'), true);

  screen.show({ id: OTHER, query: {} });
  await wait();
  assert.equal(calls.includes(`/api/generations/${OTHER}`), true);
  assert.equal(root.textContent.includes(OTHER), true);
  assert.equal(root.querySelector('[data-row="' + OTHER + '"]').getAttribute('aria-selected'), 'true');
  screen.show({ id: null, query: {} });
  assert.equal(root.querySelector('[data-row="' + OTHER + '"]').getAttribute('aria-selected'), null);
  screen.stop();
});

const [C1, C2, M1, M2] = ['c', 'd', 'e', 'f'].map((digit) => digit.repeat(64));

/** A fake API for the screens of the generations and the history: the changes that are sent are kept in `sent`, and answered as the proxy does when it switches. */
function generationsApi(status, generations, sent) {
  return {
    async call(method, path, body) {
      if (method === 'POST') {
        sent.push([path, body]);
        const target = body.generation ?? body.engine;
        return { result: 'switched', engine: body.engine ?? generations.find((item) => item.fingerprint === body.generation).engine, from: body.expect ?? target, generation: target, chosen: true };
      }
      if (path === '/api/generations') return { reachable: true, generations };
      if (path === '/api/status') return status;
      if (path === '/api/history') return { entries: [] };
      throw new Error(path);
    },
  };
}

const generation = (fingerprint, engine, flags = {}) => ({ fingerprint, made: 1_795_000_000, mode: 'block', engine, routes: 0, current: false, serving: false, ...flags });

/** Mounts a screen of the generations (0) or of the history (1) over `status`, with `generations` listed; gives the screen, its root and what is sent. */
async function openGenerations(index, status, generations) {
  setLanguage('en');
  const sent = [];
  const ctx = { user: { name: 'ann', role: 'operator' }, api: generationsApi(status, generations, sent), describe: String, refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = generationScreens[index].mount(ctx, root, { id: null, query: {} });
  await wait();
  const buttons = (label, within = root) => within.querySelectorAll('button').filter((item) => item.textContent === label);
  /** What the confirmation says, and then the confirmation answered with the button `label`. */
  const confirm = async (label) => {
    const dialog = root.querySelector('dialog');
    const said = dialog.textContent;
    press(buttons(label, dialog)[0]);
    await wait();
    await wait();
    return said;
  };
  return { screen, root, sent, buttons, confirm };
}

test('a generation is chosen with the generation that is chosen for its engine, and with none for an engine that has none', async () => {
  // The list is the newest first: the generation of Coraza that is chosen comes before the ones of ModSecurity.
  const list = [generation(C1, 'coraza', { current: true, serving: true }), generation(M1, 'modsecurity', { current: true, serving: true }), generation(M2, 'modsecurity')];
  const both = statusOf({ chosen: { coraza: C1, modsecurity: M1 }, running: { coraza: C1, modsecurity: M1 } });
  const { screen, root, sent, buttons, confirm } = await openGenerations(0, both, list);
  const row = (fingerprint) => root.querySelector(`[data-row="${fingerprint}"]`);
  press(buttons('Switch to this generation', row(M2))[0]);
  await wait();
  assert.equal((await confirm('Switch')).includes('The rules store will choose the generation below'), true);
  assert.deepEqual(sent, [['/api/activate', { generation: M2, expect: M1 }]]);
  screen.stop();

  // No generation is chosen for ModSecurity: the request says so with a null, which is in the JSON, and the engine is started.
  const alone = await openGenerations(0, statusOf({ chosen: { coraza: C1 }, running: { coraza: C1 } }), [list[0], generation(M2, 'modsecurity')]);
  press(alone.buttons('Switch to this generation', alone.root.querySelector(`[data-row="${M2}"]`))[0]);
  await wait();
  const said = await alone.confirm('Start');
  for (const text of ['Start the engine?', 'No generation is chosen for ModSecurity yet', 'the whole proxy stops']) assert.equal(said.includes(text), true, text);
  assert.deepEqual(alone.sent, [['/api/activate', { generation: M2, expect: null }]]);
  assert.equal(JSON.stringify(alone.sent[0][1]).includes('"expect":null'), true);
  assert.equal(alone.root.textContent.includes('The ModSecurity engine of the proxy now serves generation'), true);
  alone.screen.stop();

  // Chosen and not run: the engine is started with the generation that is chosen, and the list says it does not run.
  const started = await openGenerations(0, statusOf({ chosen: { coraza: C1, modsecurity: M1 }, running: { coraza: C1 } }), [list[0], list[1]]);
  const chosenRow = started.root.querySelector(`[data-row="${M1}"]`);
  assert.equal(chosenRow.textContent.includes('Not running'), true);
  press(started.buttons('Start the engine', chosenRow)[0]);
  await wait();
  assert.equal((await started.confirm('Start')).includes('ModSecurity is not running in the proxy'), true);
  assert.deepEqual(started.sent, [['/api/activate', { generation: M1, expect: M1 }]]);
  started.screen.stop();
});

test('a refusal says what the proxy kept for the engine only as far as it was known before, and tells to choose the earlier generation again only when there is one', () => {
  setLanguage('en');
  const refused = (running, again) => outcomeView({ word: 'refused', ids: { from: again ? FP : OTHER, to: FP }, engine: 'modsecurity', running, chosen: true, unwritten: false, error: null }, String).textContent;
  const kept = refused(true, false);
  assert.equal(kept.includes('keeps serving its earlier generation for ModSecurity') && kept.includes('choose generation'), true);
  // An engine that did not run is still not run, and with the same generation before and after there is none to choose again.
  const fresh = refused(false, true);
  assert.equal(fresh.includes('refused to start ModSecurity') && fresh.includes('Check the state on the Overview screen.') && !fresh.includes('choose generation'), true);
  // What was not known before is not said.
  const unsure = refused(null, false);
  assert.equal(unsure.includes('refused to switch ModSecurity') && !unsure.includes('earlier generation') && !unsure.includes('does not run'), true);
  assert.equal(refused(true, true).includes('Check the state on the Overview screen.'), true);
});

test('a proxy that cannot be reached is not said to leave the engine not running: what is asked for is a switch, and no start is told', async () => {
  const list = [generation(C2, 'coraza', { current: true }), generation(C1, 'coraza')];
  const away = statusOf({ chosen: { coraza: C2 }, rollback: { coraza: C1 }, proxy: null });
  const told = async (index, press_) => {
    const { screen, root, sent, buttons, confirm } = await openGenerations(index, away, list);
    press(press_(root, buttons));
    await wait();
    const said = await confirm('Cancel');
    assert.deepEqual(sent, []);
    screen.stop();
    return said;
  };
  const choose = await told(0, (root, buttons) => buttons('Switch to this generation', root.querySelector(`[data-row="${C1}"]`))[0]);
  assert.equal(choose.includes('Switch to this generation?'), true);
  const back = await told(1, (root, buttons) => buttons('Roll back')[0]);
  assert.equal(back.includes('Roll back Coraza to the previous generation?'), true);
  for (const said of [choose, back]) for (const text of ['not running', 'will start', 'the whole proxy stops']) assert.equal(said.includes(text), false, text);
});

test('a rollback is of one engine: its button names the engine and what is chosen for it, and an engine with nothing to go back to has none', async () => {
  const list = [generation(C2, 'coraza', { current: true, serving: true }), generation(C1, 'coraza'), generation(M2, 'modsecurity', { current: true, serving: true }), generation(M1, 'modsecurity')];
  const state = statusOf({ chosen: { coraza: C2, modsecurity: M2 }, rollback: { coraza: C1, modsecurity: M1 }, running: { coraza: C2, modsecurity: M2 } });
  const { screen, sent, buttons, confirm } = await openGenerations(1, state, list);
  assert.equal(buttons('Roll back').length, 2);
  // The first is the default engine, and it still names it.
  press(buttons('Roll back')[0]);
  await wait();
  assert.equal((await confirm('Roll back')).includes('Roll back Coraza to the previous generation?'), true);
  press(buttons('Roll back')[1]);
  await wait();
  await confirm('Roll back');
  assert.deepEqual(sent, [['/api/rollback', { engine: 'coraza', expect: C2 }], ['/api/rollback', { engine: 'modsecurity', expect: M2 }]]);
  screen.stop();

  // ModSecurity has nothing to go back to, so only Coraza has a button.
  const one = await openGenerations(1, statusOf({ chosen: { coraza: C2, modsecurity: M2 }, rollback: { coraza: C1 }, running: { coraza: C2, modsecurity: M2 } }), list);
  assert.equal(one.buttons('Roll back').length, 1);
  one.screen.stop();
});

test('a proxy that does not report its engines is offered no change, and the screens say why', async () => {
  const list = [generation(C2, 'coraza', { current: true }), generation(C1, 'coraza')];
  const old = statusOf({ chosen: { coraza: C2 }, rollback: { coraza: C1 }, running: null });
  for (const index of [0, 1]) {
    const { screen, root, buttons } = await openGenerations(index, old, list);
    for (const label of ['Switch to this generation', 'Apply to the proxy', 'Start the engine', 'Roll back']) assert.equal(buttons(label).length, 0, label);
    assert.equal(root.textContent.includes('This proxy does not report the state of its engines.'), true);
    screen.stop();
  }
});

test('the overview shows each engine that has something chosen or that runs, the default one marked, and says when the two processes have another default', async () => {
  setLanguage('en');
  const shown = (status) => {
    const root = document.createElement('main');
    document.body.append(root);
    const api = { call: async () => ({ managed: false }) };
    wafScreens[0].mount({ status: () => ({ data: status, error: null, at: new Date(0), busy: false }), onStatus: () => () => {}, refreshStatus() {}, describe: String, api }, root);
    return root;
  };
  const marks = (root) => root.querySelectorAll('span').filter((item) => item.textContent === 'Default').length;
  // Nothing is chosen or run for ModSecurity: only Coraza, the default engine, is there.
  const one = shown(statusOf({ chosen: { coraza: FP }, running: { coraza: FP } }));
  assert.equal(one.textContent.includes('ModSecurity'), false);
  assert.equal(marks(one), 1);
  // The proxy does not report its engines: it is told once for the panel, and for each engine that what the proxy serves is not known.
  const old = shown(statusOf({ chosen: { coraza: FP }, running: null }));
  for (const text of ['This proxy does not report the state of its engines.', 'The generation that the proxy serves for this engine could not be read.']) assert.equal(old.textContent.includes(text), true, text);
  // ModSecurity has a generation chosen and the proxy does not run it: it is there, and the way to start it is said.
  const two = shown(statusOf({ chosen: { coraza: FP, modsecurity: OTHER }, running: { coraza: FP } }));
  assert.equal(two.textContent.includes('ModSecurity'), true);
  assert.equal(two.textContent.includes('A generation is chosen for this engine, but the proxy does not run it.'), true);
  // The proxy runs another default engine than the admin process names: neither is marked, and it is said.
  const apart = shown(statusOf({ chosen: { coraza: FP }, running: { coraza: FP }, proxy: { engine: 'modsecurity' } }));
  assert.equal(marks(apart), 0);
  assert.equal(apart.textContent.includes('The admin process and the proxy have different default engines.'), true);
  // An engine that runs with no generation chosen is told, and the bar is not told of a difference.
  const bare = shown(statusOf({ chosen: {}, running: { coraza: FP } }));
  assert.equal(bare.textContent.includes('No generation is chosen. If the proxy is restarted, this engine will not start.'), true);
});

test('the engine of an import starts as the default engine that the status names', async () => {
  setLanguage('en');
  const ctx = { user: { name: 'ann', role: 'operator' }, api: { call: async () => statusOf({ name: 'modsecurity', chosen: { modsecurity: FP }, running: { modsecurity: FP } }) }, describe: String, refreshStatus() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = importScreens[0].mount(ctx, root, { id: null, query: {} });
  await wait();
  assert.equal(root.querySelectorAll('select').find((item) => item.getAttribute('name') === 'engine').value, 'modsecurity');
  assert.equal(root.textContent.includes('different default engines'), false);
  screen.stop();
  // The two processes have another default engine: none is the default one (the engine of the proxy is not taken for it), and that is said.
  const apart = { ...ctx, api: { call: async () => statusOf({ name: 'coraza', chosen: { coraza: FP }, running: { coraza: FP }, proxy: { engine: 'modsecurity' } }) } };
  const other = document.createElement('main');
  document.body.append(other);
  const second = importScreens[0].mount(apart, other, { id: null, query: {} });
  await wait();
  assert.notEqual(other.querySelectorAll('select').find((item) => item.getAttribute('name') === 'engine').value, 'modsecurity');
  assert.equal(other.textContent.includes('The admin process and the proxy have different default engines.'), true);
  second.stop();
});

test('the page opens the shell for the role of the user, follows the address, and takes a new language without drawing again', async () => {
  const answer = (body) => ({ status: 200, headers: { get: (name) => (name === 'content-type' ? 'application/json' : null) }, json: async () => body });
  const asked = [];
  let role = 'viewer';
  globalThis.fetch = async (path) => {
    asked.push(path);
    if (path === '/api/session') return answer({ name: 'ann', role, state: 'active', csrf: 'tok', mfa: false });
    if (path === '/api/managed') return answer({ managed: false });
    if (path === '/api/status') return answer(statusOf({ chosen: { coraza: FP }, running: { coraza: FP } }));
    return answer({ reachable: true, generations: [], entries: [], records: [], next: null });
  };
  const hash = { handlers: [] };
  globalThis.location = { hash: '' };
  globalThis.history = { replaceState: (state, title, value) => (globalThis.location.hash = value) };
  globalThis.addEventListener = (type, handler) => hash.handlers.push(handler);
  globalThis.removeEventListener = (type, handler) => hash.handlers.splice(hash.handlers.indexOf(handler), 1);
  document.getElementById = () => app;
  setLanguage('en');
  const app = document.createElement('div');
  document.body.append(app);
  start(app);
  await wait();
  await wait();

  const links = () => app.querySelectorAll('a').filter((link) => link.getAttribute('data-screen') !== null);
  // A viewer is offered the screens that a viewer may open, and no others; the address is made right at the start.
  assert.deepEqual(links().map((link) => link.getAttribute('data-screen')), ['overview', 'generations', 'history', 'records', 'managed', 'managed-history', 'account']);
  assert.equal(globalThis.location.hash, '#/overview');
  assert.equal(links()[0].getAttribute('aria-current'), 'page');
  const main = app.querySelector('main');
  assert.equal(main.querySelector('h1').textContent, 'Overview');

  // The address changes: the screen of it is shown, and the menu says where the user is.
  globalThis.location.hash = '#/generations';
  hash.handlers.forEach((handler) => handler());
  await wait();
  assert.equal(main.querySelector('h1').textContent, 'Rule generations');
  assert.deepEqual(links().map((link) => link.getAttribute('aria-current')), [null, 'page', null, null, null, null, null]);
  // A value that is not of its form is dropped from the address and told.
  globalThis.location.hash = '#/generations/not-a-fingerprint';
  hash.handlers.forEach((handler) => handler());
  assert.equal(globalThis.location.hash, '#/generations');
  assert.equal(app.textContent.includes('Removed what was not valid in the address.'), true);
  // The content of a version is not for a viewer: its name is dropped from the address and told, and it is not asked for.
  globalThis.location.hash = `#/managed/${FP}`;
  hash.handlers.forEach((handler) => handler());
  await wait();
  await wait();
  assert.equal(globalThis.location.hash, '#/managed');
  assert.equal(app.textContent.includes('Removed what was not valid in the address.'), true);
  assert.equal(asked.includes(`/api/managed/versions/${FP}`), false);
  globalThis.location.hash = '#/generations';
  hash.handlers.forEach((handler) => handler());
  await wait();

  // The language is switched: the words change where they are, and the elements, and what was typed, stay.
  const filter = main.querySelector('input');
  filter.value = 'typed';
  const menu = links()[1];
  const select = app.querySelector('select');
  select.value = 'ja';
  select.dispatch('change');
  assert.equal(main.querySelector('h1').textContent, 'ルールの世代');
  assert.equal(links()[1], menu);
  assert.equal(menu.textContent, 'ルールの世代');
  assert.equal(main.querySelector('input'), filter);
  assert.equal(filter.value, 'typed');
  setLanguage('en');
  void role;
});

test('while a job runs, the screen of the versions holds its buttons and says nothing of a difference', async () => {
  setLanguage('en');
  const job = { kind: 'activate', actor: 'ann', from: FP, to: OTHER, started: 1, state: 'running' };
  const spare = 'c'.repeat(64);
  const api = {
    async call(method, path) {
      if (path === '/api/managed') return { managed: true, current: FP, serving: OTHER, reachable: true, reloading: false, rollback_to: null, job };
      if (path === '/api/managed/versions') return { reachable: true, versions: [{ name: FP, made: 1, current: true, serving: false }, { name: OTHER, made: 1, current: false, serving: true }, { name: spare, made: 1, current: false, serving: false }] };
      if (path === '/api/status') return { proxy: { config: 'c'.repeat(64) } };
      return { sha256: 'c'.repeat(64), forward: {} };
    },
  };
  const ctx = { user: { name: 'ann', role: 'operator' }, api, describe: String, refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = managedScreens[0].mount(ctx, root, { id: null, query: {} });
  await wait();
  await wait();
  await wait();
  const apply = root.querySelectorAll('button').filter((item) => item.textContent === 'Apply this version');
  assert.equal(apply.length, 2);
  assert.equal(apply.every((item) => item.disabled), true);
  // Only the version that is neither selected nor running may be removed, and not while the job runs.
  const remove = root.querySelectorAll('button').filter((item) => item.textContent === 'Remove this version');
  assert.equal(remove.length, 1);
  assert.equal(remove[0].disabled, true);
  assert.equal(root.textContent.includes('The selected version and the version that the proxy runs differ.'), false);
  screen.stop();
});

/** A fake API for the screen of the versions, where the two versions `FP` (selected) and `OTHER` (running) differ. */
function differingApi(asked = []) {
  return {
    async call(method, path) {
      asked.push(path);
      if (path === '/api/managed') return { managed: true, current: FP, serving: OTHER, reachable: true, reloading: false, rollback_to: null, job: null };
      if (path === '/api/managed/versions') return { reachable: true, versions: [{ name: FP, made: 1, current: true, serving: false }, { name: OTHER, made: 1, current: false, serving: true }] };
      if (path === '/api/status') return { proxy: { config: 'c'.repeat(64) } };
      if (path === `/api/managed/versions/${OTHER}`) return { name: OTHER, made: 1, current: false, serving: true, version: { sites: [], upstreams: {}, routes: [], default_upstream: 'a', secret: 'the secret' } };
      return { sha256: 'c'.repeat(64), forward: {} };
    },
  };
}

test('a viewer is not asked about the file, gets no way to correct a difference and no way to the content of a version', async () => {
  setLanguage('en');
  const asked = [];
  const ctx = { user: { name: 'ann', role: 'viewer' }, api: differingApi(asked), describe: String, refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = managedScreens[0].mount(ctx, root, { id: null, query: {} });
  await wait();
  await wait();
  await wait();
  assert.equal(root.textContent.includes('The selected version and the version that the proxy runs differ.'), true);
  assert.equal(asked.includes('/api/config'), false);
  assert.deepEqual(root.querySelectorAll('button').filter((item) => ['Apply the selected version again', 'Select the running version', 'Apply this version'].includes(item.textContent)), []);
  assert.deepEqual(root.querySelectorAll('a').filter((link) => /^#\/managed\/[0-9a-f]{64}$/.test(link.getAttribute('href'))), []);
  screen.stop();
});

test('an admin process that runs without the managed configuration is told so, with the steps that start it, on the screens of the versions, the history and the draft', async () => {
  setLanguage('en');
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  const api = {
    async call(method, path) {
      if (path === '/api/managed') return { managed: false };
      if (path === '/api/managed/history') throw new ApiError('conflict', 409, 'the configuration has no managed object');
      return {};
    },
  };
  const ctx = { user: { name: 'ann', role: 'operator' }, api, describe: String, refreshStatus() {}, navigate() {} };
  for (const id of ['managed', 'managed-history', 'routes']) {
    const root = document.createElement('main');
    document.body.append(root);
    const screen = managedScreens.find((item) => item.id === id).mount(ctx, root, { id: null, query: {} });
    await wait();
    await wait();
    assert.equal(root.textContent.includes('The admin process started without the managed configuration.'), true, id);
    assert.equal(root.textContent.includes('Create the first version from that JSON file with the commands managed import and managed activate.'), true, id);
    assert.equal(root.querySelectorAll('a').some((link) => link.getAttribute('href') === '#/config'), true, id);
    screen.stop();
  }
});

test('once the content of a version is closed, nothing that the screen keeps reaches it', async () => {
  setLanguage('en');
  const ctx = { user: { name: 'ann', role: 'operator' }, api: differingApi(), describe: String, refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = managedScreens[0].mount(ctx, root, { id: OTHER, query: {} });
  await wait();
  await wait();
  await wait();
  const pre = root.querySelector('pre');
  assert.equal(pre.textContent.includes('the secret'), true);
  let panel = pre;
  while (panel.tag !== 'section') panel = panel.parent;
  const foot = panel.querySelector('[class="tc-panel__foot"]');
  const states = panel.querySelector('[class="tc-actions"]').children[0];
  const apply = foot.querySelector('button');
  assert.equal(apply.textContent, 'Apply this version');
  screen.show({ id: null, query: {} });
  const top = (node) => {
    let at = node;
    while (at.parent !== null) at = at.parent;
    return at;
  };
  for (const node of [foot, states, apply]) assert.equal(top(node).querySelector('pre'), null);
  assert.equal(root.querySelector('pre'), null);
  screen.stop();
});

test('the outcome of a job with a result that this page does not know is told as such, with the word as it came', () => {
  setLanguage('en');
  const box = jobResult({ state: 'ended', result: 'a new word', from: FP, to: OTHER });
  assert.equal(box.textContent.includes('The result is not one that this page knows.'), true);
  assert.equal(box.textContent.includes('a new word'), true);
  // A word of an object's prototype is no result.
  assert.equal(jobResult({ state: 'ended', result: 'constructor', from: FP, to: OTHER }).textContent.includes('The result is not one that this page knows.'), true);
});

test('a removal that did not clean up says so, and one with a 503 or with no answer that names the version is not known', () => {
  setLanguage('en');
  const text = (body, error = null) => mount(document.createElement('div'), removalView(FP, { body, error }, (failure) => failure.sentence)).textContent;
  const unclean = 'The files that are no longer used could not all be cleaned up.';
  const lost = 'it is not known whether the version was removed';
  assert.equal(text({ removed: FP, cleaned: true }).includes(unclean), false);
  assert.equal(text({ removed: FP, cleaned: false }).includes(unclean), true);
  // A 503 also comes when the time of the answer is over and the removal goes on: it is not told as a refusal.
  assert.equal(text(null, new ApiError('unavailable', 503, 'unavailable')).includes(lost), true);
  assert.equal(text({ removed: OTHER, cleaned: true }).includes(lost), true);
  assert.equal(text(null, new ApiError('conflict', 409, 'the managed version is in use')), 'the managed version is in use');
});

test('the values of the configuration file number a list from 1 and stop drawing below sixteen levels', () => {
  const list = valueTree(['a', 'b']);
  assert.deepEqual(list.querySelectorAll('dt').map((node) => node.textContent), ['1', '2']);
  assert.equal(list.className, 'tc-kv tc-kv--tree tc-kv--numbered');
  // `nested(n)` is n objects, one in the other, with a value in the last: the value is at level n + 1.
  const nested = (n) => {
    let value = 'the end';
    for (let i = 0; i < n; i += 1) value = { a: value };
    return value;
  };
  assert.equal(valueTree(nested(15)).textContent.includes('the end'), true);
  const deep = valueTree(nested(16));
  assert.equal(deep.textContent.includes('the end'), false);
  assert.equal(deep.textContent.includes('…'), true);
});

test('a form that is sent with a field empty says which field and why, puts the focus on the first, and sends nothing', async () => {
  setLanguage('en');
  const sent = [];
  globalThis.fetch = async (path, init) => {
    sent.push(`${init.method} ${path}`);
    return { status: 401, headers: { get: () => 'application/json' }, json: async () => ({ error: 'unauthorized' }) };
  };
  const app = document.createElement('div');
  document.body.append(app);
  document.getElementById = () => app;
  start(app);
  await wait();
  await wait();
  const form = app.querySelector('form');
  const [name, password] = form.querySelectorAll('input');
  assert.equal(form.getAttribute('novalidate'), '');
  form.dispatch('submit');
  assert.equal(name.getAttribute('aria-invalid'), 'true');
  assert.equal(password.getAttribute('aria-invalid'), 'true');
  assert.equal(document.activeElement, name);
  const message = app.querySelector(`[id="${name.getAttribute('aria-describedby')}"]`);
  assert.equal(message.textContent, 'Fill in this field.');
  assert.deepEqual(sent, ['GET /api/session']);
  // Once the field is filled, the error goes.
  name.value = 'ann';
  password.value = 'secret secret';
  form.dispatch('submit');
  assert.equal(name.getAttribute('aria-invalid'), null);
  await wait();
  assert.deepEqual(sent, ['GET /api/session', 'POST /api/login']);
  assert.equal(password.value, '');
});

test('the import form tells a missing rule file at the field, a line of routes with a host and no path at the line, and sends neither', async () => {
  setLanguage('en');
  const ctx = {
    user: { name: 'ann', role: 'operator' },
    api: { call: async () => ({ crs: { available: false, files: [] } }) },
    describe: String,
    refreshStatus() {},
  };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = importScreens[0].mount(ctx, root, { id: null, query: {} });
  await wait();
  const buttons = (label) => root.querySelectorAll('button').filter((item) => item.textContent === label);
  press(buttons('Add a route')[0]);
  const hosts = root.querySelectorAll('input').filter((input) => input.getAttribute('name') === 'route-host');
  assert.equal(hosts.length, 2);
  hosts[0].value = 'a.example.com';
  hosts[0].dispatch('input');
  const form = root.querySelector('form');
  form.dispatch('submit');
  await wait();
  const rules = root.querySelectorAll('input').find((input) => input.getAttribute('type') === 'file');
  assert.equal(rules.getAttribute('aria-invalid'), 'true');
  const paths = root.querySelectorAll('input').filter((input) => input.getAttribute('name') === 'route-path');
  assert.equal(paths[0].getAttribute('aria-invalid'), 'true');
  assert.equal(paths[1].getAttribute('aria-invalid'), null);
  assert.equal(document.activeElement, rules);
  screen.stop();
});

test('the screen of the upstream groups makes a draft from the selected version, and a refusal of a check is told at its field', async () => {
  setLanguage('en');
  // A draft with changes makes the page ask before it goes away, and these are what the fake page has for that.
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  const server = { address: '127.0.0.1:8080', weight: 1, max_fails: 1, fail_timeout_ms: 10000, backup: false };
  const version = { sites: [], upstreams: { app: { servers: [server] } }, routes: [], default_upstream: '' };
  const sent = [];
  const api = {
    async call(method, path, body) {
      if (method === 'POST') {
        sent.push(path, body);
        throw new ApiError('refused', 400, 'a server port is 0', { error: 'a server port is 0', at: 'upstreams.app.servers[0].address' });
      }
      if (path === '/api/managed') return { managed: true, current: FP, serving: FP, reachable: true, reloading: false, rollback_to: null, job: null };
      if (path === `/api/managed/versions/${FP}`) return { name: FP, made: 1, current: true, serving: true, version };
      if (path === '/api/status') return { proxy: { config: 'c'.repeat(64) } };
      return { sha256: 'c'.repeat(64), forward: {}, proxy: { max_body: 1_000_000 } };
    },
  };
  const ctx = { user: { name: 'ann', role: 'operator' }, api, describe: (error) => lazy(() => error.sentence), refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = managedScreens.find((item) => item.id === 'upstreams').mount(ctx, root, { id: null, query: {} });
  await wait();
  await wait();
  await wait();
  assert.equal(heldDraft().base, FP);
  assert.equal(root.querySelectorAll('[data-row]').length, 1);
  assert.equal(root.querySelector('table').className, 'tc-table tc-table--fold');
  const pressed = (label) => press(root.querySelectorAll('button').find((item) => item.textContent === label));
  // The panel of the group opens and takes the focus; what is typed goes to the draft, and the field stays where it is.
  pressed('Edit');
  const addressOf = () => root.querySelectorAll('input').find((input) => input.value.startsWith('127.0.0.1'));
  const address = addressOf();
  assert.equal(address.isConnected, true);
  address.value = '127.0.0.1:0';
  address.dispatch('input');
  assert.equal(heldDraft().changed, true);
  assert.equal(heldDraft().revision, 1);
  assert.equal(address.isConnected, true);
  // The panel is closed, so the refusal of the check has to open it again.
  pressed('Close');
  assert.equal(addressOf(), undefined);
  pressed('Check');
  await wait();
  await wait();
  assert.equal(sent[0], '/api/managed/check');
  assert.equal(sent[1].expect, FP);
  assert.equal(sent[1].version.upstreams.app.servers[0].address, '127.0.0.1:0');
  assert.deepEqual(sent[1].files, []);
  const refused = addressOf();
  assert.equal(refused.value, '127.0.0.1:0');
  assert.equal(refused.getAttribute('aria-invalid'), 'true');
  assert.equal(root.querySelector(`[id="${refused.getAttribute('aria-describedby')}"]`).textContent, 'a server port is 0');
  assert.equal(document.activeElement, refused);
  // The list says where the error is, and the field that is corrected no longer says it.
  assert.equal(root.querySelector('[data-row]').textContent.includes('Has an error'), true);
  refused.value = '127.0.0.1:8081';
  refused.dispatch('input');
  assert.equal(refused.getAttribute('aria-invalid'), null);
  // Choosing the default group is told in the list, and the choice stays where it is, with the focus.
  const choice = root.querySelector('select');
  choice.focus();
  choice.value = String(heldDraft().groups[0].cid);
  choice.dispatch('change');
  assert.equal(heldDraft().defaultRef.cid, heldDraft().groups[0].cid);
  assert.equal(root.querySelector('select'), choice);
  assert.equal(document.activeElement, choice);
  assert.equal(root.querySelector('[data-row]').textContent.includes('Default'), true);
  screen.stop();
  assert.equal(forgetDraft(), true);
});

/**
 * A screen of the draft on the fake page, with an API that gives `version`, and answers a check with the 400 for `at` (and
 * `sentence`). `status` is the answer of `GET /api/status` and `config` what `GET /api/config` adds to its answer.
 */
async function editScreen(id, version, refusal, { status = { proxy: { config: 'c'.repeat(64) } }, config = {}, answer = null } = {}) {
  setLanguage('en');
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  const sent = [];
  const api = {
    async call(method, path, body) {
      if (method === 'POST') {
        sent.push(path, body);
        if (answer !== null) return answer;
        const { at, sentence } = refusal();
        throw new ApiError('refused', 400, sentence, { error: sentence, at });
      }
      if (path === '/api/managed') return { managed: true, current: FP, serving: FP, reachable: true, reloading: false, rollback_to: null, job: null };
      if (path === `/api/managed/versions/${FP}`) return { name: FP, made: 1, current: true, serving: true, version };
      if (path === '/api/status') return status;
      return { sha256: 'c'.repeat(64), forward: {}, proxy: { max_body: 1_000_000 }, ...config };
    },
  };
  const ctx = { user: { name: 'ann', role: 'operator' }, api, describe: (error) => lazy(() => error.sentence), refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = managedScreens.find((item) => item.id === id).mount(ctx, root, { id: null, query: {} });
  await wait();
  await wait();
  await wait();
  const pressed = (label) => press(root.querySelectorAll('button').find((item) => item.textContent === label));
  /** The control of the field whose name starts with `label`. */
  const control = (label) => {
    const name = root.querySelectorAll('label').find((item) => item.textContent.startsWith(label));
    return root.querySelector(`[id="${name.getAttribute('for')}"]`);
  };
  const errorOf = (input) => root.querySelector(`[id="${input.getAttribute('aria-describedby')}"]`).textContent;
  return { root, screen, sent, pressed, control, errorOf };
}

const groupOfOne = { app: { servers: [{ address: '127.0.0.1:8080', weight: 1, max_fails: 1, fail_timeout_ms: 10000, backup: false }] } };

test('the screen of the sites opens a site, and a refusal of a check names the line of the box of its host', async () => {
  const version = { sites: [{ name: 'main', hosts: ['a.example', 'b.example'], certificate: { chain: 'c'.repeat(64), key: 'd'.repeat(64) } }], upstreams: groupOfOne, routes: [], default_upstream: '' };
  const { root, screen, sent, pressed, control, errorOf } = await editScreen('sites', version, () => ({ at: 'sites[0].hosts[1]', sentence: 'a site host is written twice in the sites' }));
  assert.equal(heldDraft().sites.length, 1);
  assert.equal(root.querySelector('[data-row]').textContent.includes('a.example and 1 more'), true);
  pressed('Edit');
  const hosts = control('Hosts');
  assert.equal(hosts.value, 'a.example\nb.example');
  hosts.value = 'a.example\n\nc.example';
  hosts.dispatch('input');
  assert.equal(heldDraft().revision, 1);
  pressed('Close');
  pressed('Check');
  await wait();
  await wait();
  assert.equal(sent[0], '/api/managed/check');
  assert.deepEqual(sent[1].version.sites[0].hosts, ['a.example', 'c.example']);
  assert.deepEqual(sent[1].version.sites[0].certificate, { chain: 'c'.repeat(64), key: 'd'.repeat(64) });
  // The panel opens again for the fault; the number of the API is turned into the line that the box shows.
  const refused = control('Hosts');
  assert.equal(refused.getAttribute('aria-invalid'), 'true');
  assert.equal(errorOf(refused), 'Line 3: a site host is written twice in the sites');
  assert.equal(document.activeElement, refused);
  assert.equal(root.querySelector('[data-row]').textContent.includes('Has an error'), true);
  // What another screen is to correct is told in the band with the way there.
  heldDraft().putFaults([{ screen: 'routes', panel: null, cid: 'routes', field: 'notice', words: lazy(() => 'too many routes') }]);
  assert.equal(root.textContent.includes('Correct it on the routes screen'), true);
  screen.stop();
  assert.equal(forgetDraft(), true);
});

test('the screen of the routes makes a form when it opens, and a refusal of a field in a part that is closed opens the part', async () => {
  const version = { sites: [], upstreams: groupOfOne, routes: [{ path: '/', upstream: 'app' }], default_upstream: '' };
  let answer = { at: 'routes[0].rewrite.host', sentence: 'a rewrite host is malformed' };
  const { root, screen, sent, pressed, control, errorOf } = await editScreen('routes', version, () => answer);
  const route = heldDraft().routes[0];
  assert.equal(route.form, null);
  assert.equal(root.querySelector('[data-row]').textContent.includes('Any'), true);
  pressed('Edit');
  assert.notEqual(route.form, null);
  assert.equal(heldDraft().revision, 0);
  // The part of the rewrite holds nothing, so it stays closed.
  const details = () => root.querySelectorAll('details');
  assert.deepEqual(details().map((part) => part.open), [false, false, false]);
  const host = control('Host');
  host.value = 'a.example';
  host.dispatch('input');
  assert.equal(heldDraft().revision, 1);
  assert.equal(root.querySelector('[data-row]').textContent.includes('a.example'), true);
  pressed('Close');
  pressed('Check');
  await wait();
  await wait();
  assert.deepEqual(sent[1].version.routes, [{ path: '/', upstream: 'app', host: 'a.example' }]);
  // The panel opens, the closed part around the field opens, and the field has the focus.
  const refused = control('Host to rewrite to');
  assert.equal(refused.getAttribute('aria-invalid'), 'true');
  assert.equal(errorOf(refused), 'a rewrite host is malformed');
  assert.equal(document.activeElement, refused);
  assert.deepEqual(details().map((part) => part.open), [false, false, true]);
  // A refusal of a list as a whole is told above the lists of that part, which is opened for it.
  answer = { at: 'routes[0].stream', sentence: 'a stream idle_ms is above its total_ms' };
  pressed('Check');
  await wait();
  await wait();
  const stream = details()[1];
  assert.equal(stream.open, true);
  assert.equal(stream.textContent.includes('a stream idle_ms is above its total_ms'), true);
  // What another screen is to correct is told in the band with the way there.
  heldDraft().putFaults([{ screen: 'sites', panel: null, cid: 'sites', field: 'notice', words: lazy(() => 'too many sites') }]);
  assert.equal(root.textContent.includes('Correct it on the sites screen'), true);
  screen.stop();
  assert.equal(forgetDraft(), true);
});

test('typing in a field of a route draws the list again only when a line of it would change', async () => {
  const version = { sites: [], upstreams: groupOfOne, routes: [{ path: '/', upstream: 'app', stream: { idle_ms: 5, total_ms: 9, websocket: false } }], default_upstream: '' };
  const { root, screen, pressed, control } = await editScreen('routes', version, () => ({ at: null, sentence: 'refused' }));
  pressed('Edit');
  const line = () => root.querySelector('[data-row]');
  const type = (input, value) => {
    input.value = value;
    input.dispatch('input');
  };
  const idle = control('Idle limit');
  // The first change of the route is a change that the list shows.
  const unchanged = line();
  type(idle, '50');
  assert.notEqual(line(), unchanged);
  assert.equal(line().textContent.includes('Changed'), true);
  // Another keystroke changes nothing that the list shows: the line stays the same element.
  const drawn = line();
  const seen = heldDraft().routeList;
  type(idle, '500');
  assert.equal(line(), drawn);
  assert.equal(heldDraft().routeList, seen);
  // A field that the list shows draws it again.
  type(control('Path'), '/app/');
  assert.notEqual(line(), drawn);
  assert.equal(line().textContent.includes('/app/'), true);
  screen.stop();
  assert.equal(forgetDraft(), true);
});

test('a key file that is chosen for a site is named on the panel, and what is in it is shown nowhere', async () => {
  const secret = '-----BEGIN PRIVATE KEY-----\nSECRETKEYTEXT\n-----END PRIVATE KEY-----\n';
  // The fake page has no reader of files: this one gives the bytes that the test put on the file.
  globalThis.FileReader = class {
    readAsArrayBuffer(file) {
      this.result = file.content;
      this.onload();
    }
  };
  const version = { sites: [{ name: 'main', hosts: ['a.example'], certificate: { chain: 'c'.repeat(64), key: 'd'.repeat(64) } }], upstreams: groupOfOne, routes: [], default_upstream: '' };
  const { root, screen, pressed, control } = await editScreen('sites', version, () => ({ at: null, sentence: 'refused' }));
  pressed('Edit');
  const input = control('Choose the private key file');
  input.files = [{ name: 'key.pem', size: secret.length, content: new TextEncoder().encode(secret).buffer }];
  input.dispatch('change');
  for (let turns = 0; turns < 200 && heldDraft().files.size === 0; turns += 1) await wait();
  assert.equal(heldDraft().files.size, 1);
  assert.equal(root.textContent.includes('key.pem'), true);
  assert.equal(root.textContent.includes('SECRETKEYTEXT'), false);
  assert.equal(root.textContent.includes('BEGIN PRIVATE'), false);
  screen.stop();
  assert.equal(forgetDraft(), true);
  delete globalThis.FileReader;
});

test('the sites show the certificate of the store that each names, read for the version that the draft carries', async () => {
  setLanguage('en');
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  const chain = 'c'.repeat(64);
  const key = 'd'.repeat(64);
  const version = { sites: [{ name: 'main', hosts: ['a.example'], certificate: { chain, key } }, { name: 'auto', hosts: ['b.example'], certificate: { acme: { renew_before_days: 30 } } }], upstreams: groupOfOne, routes: [], default_upstream: '' };
  const files = { name: 'main', kind: 'files', chain, key, state: 'present', names: ['a.example', 'www.a.example'], more: 2, not_after: 2_000_000_000, expired: false };
  let carried = { name: OTHER, sites: [files, { name: 'auto', kind: 'acme', hosts: ['b.example'], state: 'waiting' }] };
  const asked = [];
  const api = {
    async call(method, path) {
      asked.push(path);
      if (path === '/api/managed') return { managed: true, current: FP, serving: FP, reachable: true, reloading: false, rollback_to: null, job: null };
      if (path === `/api/managed/versions/${FP}`) return { name: FP, made: 1, current: true, serving: true, version };
      // The selected version cannot be read: that adds nothing, and the screen goes on.
      if (path === `/api/managed/certificates/${FP}`) throw new ApiError('broken', 500, 'the managed version is not JSON');
      if (path === `/api/managed/certificates/${OTHER}`) return carried;
      if (path === '/api/status') return { proxy: { config: 'c'.repeat(64) } };
      return { sha256: 'c'.repeat(64), forward: {} };
    },
  };
  // The draft carries the version OTHER, as one made on the screen of the versions on top of the selected one.
  draftFromVersion(FP, version, OTHER, version, null);
  const ctx = { user: { name: 'ann', role: 'operator' }, api, describe: (error) => lazy(() => error.sentence), refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = managedScreens.find((item) => item.id === 'sites').mount(ctx, root, { id: null, query: {} });
  const settle = async () => {
    for (let turns = 0; turns < 3; turns += 1) await wait();
  };
  await settle();
  assert.equal(asked.includes(`/api/managed/certificates/${FP}`), true);
  assert.equal(asked.includes(`/api/managed/certificates/${OTHER}`), true);
  const lines = () => root.querySelectorAll('[data-row]');
  assert.notEqual(lines()[0].querySelector('time'), null);
  assert.equal(lines()[1].textContent.includes('Not issued'), true);
  press(root.querySelectorAll('button').find((item) => item.textContent === 'Edit'));
  assert.equal(root.textContent.includes('Host names in the certificate'), true);
  assert.equal(root.textContent.includes('a.example, www.a.example and 2 more'), true);
  // A read that finds the same values draws no line again, and one that finds other values does.
  const reload = () => press(root.querySelectorAll('button').find((item) => item.textContent === 'Reload'));
  const drawn = lines()[0];
  reload();
  await settle();
  assert.equal(lines()[0], drawn);
  carried = { ...carried, sites: [{ ...files, state: 'missing', expired: true }, carried.sites[1]] };
  reload();
  await settle();
  assert.notEqual(lines()[0], drawn);
  assert.equal(lines()[0].textContent.includes('Expired') && lines()[0].textContent.includes('Missing'), true);
  const panel = root.querySelectorAll('section').find((item) => item.textContent.startsWith('Edit the site'));
  assert.equal(panel.textContent.includes('Missing') && panel.textContent.includes('a.example, www.a.example and 2 more'), true);
  // A key chosen again keeps the expiry of the chain, and the state that the old key had is no longer told.
  heldDraft().write(heldDraft().sites[0], 'key', 'e'.repeat(64));
  assert.equal(lines()[0].textContent.includes('Expired'), true);
  assert.equal(lines()[0].textContent.includes('Missing'), false);
  assert.equal(root.textContent.includes('Missing'), false);
  screen.stop();
  assert.equal(forgetDraft(), true);
});

test('the content of a version shows the certificates of its sites row by row, or says that they could not be read', async () => {
  setLanguage('en');
  let answer = null;
  const versions = differingApi();
  const api = {
    async call(method, path) {
      if (path !== `/api/managed/certificates/${OTHER}`) return versions.call(method, path);
      if (answer === null) throw new ApiError('broken', 500, 'the managed version is not JSON');
      return answer;
    },
  };
  const ctx = { user: { name: 'ann', role: 'operator' }, api, describe: String, refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = managedScreens[0].mount(ctx, root, { id: OTHER, query: {} });
  await wait();
  await wait();
  await wait();
  assert.equal(root.textContent.includes('The certificate information could not be read.'), true);
  // Two sites of one name, as a version put in the store by hand may have, are two rows.
  answer = { name: OTHER, sites: [{ name: 'main', kind: 'files', chain: 'c'.repeat(64), key: 'd'.repeat(64), state: 'present', names: [], more: 0, not_after: 1, expired: true }, { name: 'main', kind: null, state: 'unreadable' }] };
  screen.show({ id: null, query: {} });
  screen.show({ id: OTHER, query: {} });
  await wait();
  await wait();
  const part = root.querySelectorAll('h3').find((item) => item.textContent === 'Certificates').parent;
  const rows = part.querySelectorAll('[data-row]').map((item) => item.textContent);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].includes('Files') && rows[0].includes('Expired') && rows[0].includes('Present'), true);
  assert.equal(rows[1].includes('Unknown') && rows[1].includes('Unreadable') && rows[1].includes('—'), true);
  assert.equal(root.textContent.includes('The certificate information could not be read.'), false);
  screen.stop();
});

test('no default upstream is told as such in a confirmation and in the content of a version', () => {
  setLanguage('en');
  const version = (name) => ({ sites: [], upstreams: {}, routes: [], default_upstream: name });
  const row = (before, after) => diffRows(FP, OTHER, before, after).find((one) => String(one.label) === 'Default upstream');
  const rows = row(countsOf(version('')), countsOf(version('a')));
  assert.equal(String(rows.now), 'Not set');
  assert.equal(rows.after, 'a');
  assert.equal(rows.changed, true);
  assert.equal(String(defaultGroupView('')), 'Not set');
  assert.equal(defaultGroupView('app'), 'app');
  assert.equal(defaultGroupView(null), '—');
});

test('the screen of the upstream groups chooses the engine of a group, says what is known of the engine before a saving, and tells a refusal at the choice', async () => {
  const version = { sites: [], upstreams: groupOfOne, routes: [], default_upstream: '' };
  const status = statusOf({ chosen: { coraza: FP }, running: { coraza: FP } });
  const { root, screen, sent, pressed, control, errorOf } = await editScreen('upstreams', version, () => ({ at: 'upstreams.app.engine', sentence: 'kernel.engines has no inspector for the engine of an upstream' }), { status });
  // The list says the engine that inspects the group, and that it is the default one.
  const line = root.querySelector('[data-row]').textContent;
  assert.equal(line.includes('Coraza') && line.includes('(default engine)'), true);
  pressed('Edit');
  const engine = control('Engine');
  assert.deepEqual(engine.querySelectorAll('option').map((option) => option.textContent), ['Default engine (Coraza)', 'Coraza', 'ModSecurity']);
  // The choice is written to the draft; what the status and the file say of the engine is told where the choice is, before a saving.
  engine.value = 'modsecurity';
  engine.dispatch('change');
  assert.equal(heldDraft().groups[0].engine, 'modsecurity');
  assert.equal(heldDraft().changed, true);
  for (const text of ['No generation is chosen for ModSecurity.', 'The configuration file has no inspector for ModSecurity']) assert.equal(root.textContent.includes(text), true, text);
  pressed('Close');
  pressed('Check');
  await wait();
  await wait();
  assert.equal(sent[1].version.upstreams.app.engine, 'modsecurity');
  // The refusal opens the group at its choice, and the choice is where the focus goes; changing the choice takes it away.
  const refused = control('Engine');
  assert.equal(refused.getAttribute('aria-invalid'), 'true');
  assert.equal(errorOf(refused), 'kernel.engines has no inspector for the engine of an upstream');
  assert.equal(document.activeElement, refused);
  refused.value = '';
  refused.dispatch('change');
  assert.equal(refused.getAttribute('aria-invalid'), null);
  assert.equal(Object.hasOwn(heldDraft().build().version.upstreams.app, 'engine'), false);
  assert.equal(root.textContent.includes('No generation is chosen for ModSecurity.'), false);
  // The choice is back to what the version had, so there is no change.
  assert.equal(heldDraft().changed, false);
  screen.stop();
  forgetDraft();
  // The default engine that the admin process names is not the one that the proxy runs: the choice does not name it, and the two are asked to be started again.
  const apart = await editScreen('upstreams', version, () => ({ at: null, sentence: 'x' }), { status: statusOf({ chosen: { coraza: FP }, running: { coraza: FP }, proxy: { engine: 'modsecurity' } }) });
  apart.pressed('Edit');
  assert.equal(apart.control('Engine').querySelectorAll('option')[0].textContent, 'Default engine');
  assert.equal(apart.root.textContent.includes('The admin process and the proxy have different default engines.'), true);
  apart.screen.stop();
  forgetDraft();
  // An engine that is not one of ours is kept in the choice, so that the choice does not read as the default one.
  const odd = await editScreen('upstreams', { ...version, upstreams: { app: { ...groupOfOne.app, engine: 'Coraza' } } }, () => ({ at: null, sentence: 'x' }), { status });
  odd.pressed('Edit');
  assert.equal(odd.control('Engine').value, 'Coraza');
  assert.equal(heldDraft().changed, false);
  odd.screen.stop();
  forgetDraft();
});

test('the confirmation of a saving names the groups whose engine changes, counts the groups by engine, and says which are inspected by a generation that only detects', async () => {
  const version = { sites: [], upstreams: groupOfOne, routes: [], default_upstream: '' };
  const status = statusOf({ chosen: { coraza: FP, modsecurity: OTHER }, running: { coraza: FP, modsecurity: OTHER } });
  // The check passes, and says that the group is inspected by a generation that only detects.
  const answer = { version: OTHER, detect: [{ upstream: 'app', engine: 'modsecurity' }] };
  const { root, screen, sent, pressed, control } = await editScreen('upstreams', version, () => null, { status, answer });
  pressed('Edit');
  const engine = control('Engine');
  engine.value = 'modsecurity';
  engine.dispatch('change');
  pressed('Close');
  pressed('Save and apply');
  await wait();
  await wait();
  assert.equal(sent[0], '/api/managed/check');
  const dialog = root.querySelector('dialog');
  assert.notEqual(dialog, null);
  const said = dialog.textContent;
  for (const text of ['Change Upstream engine app', '1 upstream(s) (app) are inspected by an engine whose generation only detects.', 'ModSecurity upstreams', 'Coraza upstreams']) assert.equal(said.includes(text), true, text);
  // The user does not confirm: nothing is sent but the check.
  press(dialog.querySelectorAll('button').find((item) => item.textContent === 'Cancel'));
  await wait();
  assert.equal(sent.length, 2);
  screen.stop();
  forgetDraft();
});

test('a version that is applied by its name is counted by engine in the confirmation with the engines that only detect, and a refusal that names an upstream says which', async () => {
  setLanguage('en');
  const spare = 'c'.repeat(64);
  const version = { sites: [], upstreams: { app: { servers: [], engine: 'modsecurity' }, api: { servers: [] } }, routes: [], default_upstream: 'app' };
  const sentence = 'no generation is chosen for the engine of an upstream';
  const status = statusOf({ chosen: { coraza: FP, modsecurity: OTHER }, running: { coraza: FP, modsecurity: OTHER } });
  status.proxy.engines[1].mode = 'detect';
  const sent = [];
  const api = {
    async call(method, path, body) {
      if (method === 'POST') {
        sent.push([path, body]);
        throw new ApiError('conflict', 409, sentence, { error: sentence, at: 'upstreams.app.engine' });
      }
      if (path === '/api/managed') return { managed: true, current: FP, serving: FP, reachable: true, reloading: false, rollback_to: null, job: null };
      if (path === '/api/managed/versions') return { reachable: true, versions: [{ name: FP, made: 1, current: true, serving: true }, { name: spare, made: 1, current: false, serving: false }] };
      if (path === '/api/status') return status;
      if (path.startsWith('/api/managed/versions/')) return { name: path.slice(-64), made: 1, version };
      return { sha256: 'c'.repeat(64), forward: {} };
    },
  };
  const ctx = { user: { name: 'ann', role: 'operator' }, api, describe: (error) => lazy(() => error.sentence), refreshStatus() {}, navigate() {} };
  const root = document.createElement('main');
  document.body.append(root);
  const screen = managedScreens[0].mount(ctx, root, { id: null, query: {} });
  await wait();
  await wait();
  await wait();
  const apply = (within) => within.querySelectorAll('button').filter((item) => item.textContent === 'Apply this version')[0];
  press(apply(root.querySelector(`[data-row="${spare}"]`)));
  await wait();
  await wait();
  const dialog = root.querySelector('dialog');
  // The groups are counted by the engine that inspects them (the default engine for the one that names none), and ModSecurity runs a generation of detection.
  const said = dialog.textContent;
  for (const text of ['Coraza upstreams', 'ModSecurity upstreams', 'Detect only now']) assert.equal(said.includes(text), true, text);
  press(apply(dialog));
  await wait();
  await wait();
  assert.deepEqual(sent, [['/api/managed/activate', { expect: FP, version: spare }]]);
  assert.equal(root.textContent.includes(`Upstream app: ${sentence}`), true);
  screen.stop();
});

test('a group whose engine the proxy does not run is told so before a saving, one that is starting is told to wait, and one that stopped or failed is not running', async () => {
  const version = { sites: [], upstreams: groupOfOne, routes: [], default_upstream: '' };
  for (const [phase, text] of [['absent', 'ModSecurity is not running in the proxy.'], ['starting', 'ModSecurity is starting.'], ['stopping', 'ModSecurity is not running in the proxy.'], ['failed', 'ModSecurity is not running in the proxy.'], ['ready', null]]) {
    const status = statusOf({ chosen: { coraza: FP, modsecurity: OTHER }, running: phase === 'absent' ? { coraza: FP } : { coraza: FP, modsecurity: OTHER } });
    if (phase !== 'absent') status.proxy.engines[1].phase = phase;
    const { root, screen, pressed, control } = await editScreen('upstreams', version, () => null, { status });
    pressed('Edit');
    const engine = control('Engine');
    engine.value = 'modsecurity';
    engine.dispatch('change');
    const told = ['is not running in the proxy.', 'is starting.'].filter((part) => root.textContent.includes(`ModSecurity ${part}`));
    assert.deepEqual(told, text === null ? [] : [text.slice('ModSecurity '.length)], phase);
    screen.stop();
    forgetDraft();
  }
});

test('the numbers of a version are by the engine that inspects its groups, and a line of an engine that only detects says so', () => {
  setLanguage('en');
  const group = (engine) => ({ servers: [], ...(engine === undefined ? {} : { engine }) });
  const version = { upstreams: { a: group(), b: group('coraza'), c: group('modsecurity') } };
  const pick = (counts) => [counts.coraza, counts.modsecurity, counts.pinned];
  assert.deepEqual(pick(countsOf(version, 'coraza')), [2, 1, 2]);
  assert.deepEqual(pick(countsOf(version, 'modsecurity')), [1, 2, 2]);
  assert.deepEqual(pick(countsOf(version, null)), [null, null, 2]);
  assert.deepEqual(pick(countsOf({ upstreams: 'x' }, 'coraza')), [null, null, null]);
  const labels = (lines) => lines.map((line) => String(line.label));
  const known = diffRows(FP, OTHER, countsOf(version, 'coraza'), countsOf({ upstreams: { a: group('modsecurity'), b: group('coraza') } }, 'coraza'));
  assert.equal(labels(known).includes('Coraza upstreams') && labels(known).includes('ModSecurity upstreams'), true);
  assert.equal(labels(known).includes('Upstreams that name an engine'), false);
  const line = (label, lines) => lines.find((one) => String(one.label) === label);
  assert.equal(line('Coraza upstreams', known).changed, true);
  assert.equal(line('ModSecurity upstreams', known).changed, false);
  // Without the default engine only the groups that name one are counted.
  const unknown = diffRows(FP, OTHER, countsOf(version, null), countsOf(version, null));
  assert.equal(labels(unknown).includes('Upstreams that name an engine'), true);
  assert.equal(labels(unknown).includes('Coraza upstreams'), false);
  // The proxy runs ModSecurity with a generation that only detects: the line of that engine says so, and the other does not.
  const detecting = diffRows(FP, OTHER, countsOf(version, 'coraza'), countsOf(version, 'coraza'), { detecting: ['modsecurity'] });
  assert.equal(Array.isArray(line('ModSecurity upstreams', detecting).after), true);
  assert.equal(typeof line('Coraza upstreams', detecting).after, 'string');
});

test('the groups that a generation of detection inspects are named, twenty of them and then how many more', () => {
  setLanguage('en');
  const names = (n) => Array.from({ length: n }, (_, at) => `g${at}`);
  assert.equal(detectNotice([]), null);
  const twenty = detectNotice(names(20)).textContent;
  assert.equal(twenty.includes('20 upstream(s)') && twenty.includes('g19') && !twenty.includes('more'), true);
  const more = detectNotice(names(21)).textContent;
  assert.equal(more.includes('g19') && !more.includes('g20') && more.includes('and 1 more'), true);
});
