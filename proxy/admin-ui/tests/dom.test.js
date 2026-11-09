import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ApiError } from '../js/api.js';
import { bindAttribute, el, mount, retranslate, safeUrl, setText } from '../js/dom.js';
import { lazy, setLanguage, w } from '../js/i18n.js';
import { forgetDraft, heldDraft } from '../js/managed/edit/draft.js';
import { screens as generationScreens } from '../js/waf/generations.js';
import { screens as wafScreens } from '../js/waf/waf.js';
import { screens as importScreens } from '../js/waf/import.js';
import { jobResult } from '../js/managed/job.js';
import { screens as managedScreens } from '../js/managed/managed.js';
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

test('the overview shows the numbers of the proxy, and a dash where the proxy gave none, with the reason said once', () => {
  setLanguage('en');
  const mountOverview = wafScreens[0].mount;
  const shown = (proxy, reachable = true) => {
    const data = { current: FP, reachable, proxy, rollback_to: null, crs: { available: false, files: [] } };
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
  const away = shown(null, false);
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
      if (path === '/api/status') return { current: FP, reachable: true, proxy: { generation: FP, switching: false }, rollback_to: OTHER };
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

test('the page opens the shell for the role of the user, follows the address, and takes a new language without drawing again', async () => {
  const answer = (body) => ({ status: 200, headers: { get: (name) => (name === 'content-type' ? 'application/json' : null) }, json: async () => body });
  const asked = [];
  let role = 'viewer';
  globalThis.fetch = async (path) => {
    asked.push(path);
    if (path === '/api/session') return answer({ name: 'ann', role, state: 'active', csrf: 'tok', mfa: false });
    if (path === '/api/managed') return answer({ managed: false });
    if (path === '/api/status') return answer({ current: FP, reachable: true, proxy: { generation: FP, mode: 'block', engine: 'coraza', phase: 'ready', switching: false }, rollback_to: null, crs: { available: false, files: [] } });
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
  assert.equal(main.querySelector('h1').textContent, 'Generations');
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
  assert.equal(main.querySelector('h1').textContent, '世代');
  assert.equal(links()[1], menu);
  assert.equal(menu.textContent, '世代');
  assert.equal(main.querySelector('input'), filter);
  assert.equal(filter.value, 'typed');
  setLanguage('en');
  void role;
});

test('while a job runs, the screen of the versions holds its buttons and says nothing of a difference', async () => {
  setLanguage('en');
  const job = { kind: 'activate', actor: 'ann', from: FP, to: OTHER, started: 1, state: 'running' };
  const api = {
    async call(method, path) {
      if (path === '/api/managed') return { managed: true, current: FP, serving: OTHER, reachable: true, reloading: false, rollback_to: null, job };
      if (path === '/api/managed/versions') return { reachable: true, versions: [{ name: FP, made: 1, current: true, serving: false }, { name: OTHER, made: 1, current: false, serving: true }] };
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
  assert.equal(apply.length, 1);
  assert.equal(apply[0].disabled, true);
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

test('the values of the configuration file number a list from 1 and stop drawing below sixteen levels', () => {
  const list = valueTree(['a', 'b']);
  assert.deepEqual(list.querySelectorAll('dt').map((node) => node.textContent), ['1', '2']);
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

/** A screen of the draft on the fake page, with an API that gives `version`, and answers a check with the 400 for `at` (and `sentence`). */
async function editScreen(id, version, refusal) {
  setLanguage('en');
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  const sent = [];
  const api = {
    async call(method, path, body) {
      if (method === 'POST') {
        sent.push(path, body);
        const { at, sentence } = refusal();
        throw new ApiError('refused', 400, sentence, { error: sentence, at });
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
  hosts.value = 'a.example\n\nb.example';
  hosts.dispatch('input');
  assert.equal(heldDraft().revision, 1);
  pressed('Close');
  pressed('Check');
  await wait();
  await wait();
  assert.equal(sent[0], '/api/managed/check');
  assert.deepEqual(sent[1].version.sites[0].hosts, ['a.example', 'b.example']);
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

test('no default group is told as such in a confirmation and in the content of a version', () => {
  setLanguage('en');
  const version = (name) => ({ sites: [], upstreams: {}, routes: [], default_upstream: name });
  const row = (before, after) => diffRows(FP, OTHER, before, after).find((one) => String(one.label) === 'Default group');
  const rows = row(countsOf(version('')), countsOf(version('a')));
  assert.equal(String(rows.now), 'Not set');
  assert.equal(rows.after, 'a');
  assert.equal(rows.changed, true);
  assert.equal(String(defaultGroupView('')), 'Not set');
  assert.equal(defaultGroupView('app'), 'app');
  assert.equal(defaultGroupView(null), '—');
});
