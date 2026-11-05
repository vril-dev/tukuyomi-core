import assert from 'node:assert/strict';
import { test } from 'node:test';

import { bindAttribute, el, mount, retranslate, safeUrl, setText } from '../js/dom.js';
import { setLanguage, w } from '../js/i18n.js';
import { screens as generationScreens } from '../js/generations.js';
import { screens as wafScreens } from '../js/waf.js';
import { screens as importScreens } from '../js/import.js';
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
    mountOverview({ status: () => ({ data, error: null, at: new Date(0), busy: false }), onStatus: () => () => {}, refreshStatus() {}, describe: String }, root);
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
  let role = 'viewer';
  globalThis.fetch = async (path) => {
    if (path === '/api/session') return answer({ name: 'ann', role, state: 'active', csrf: 'tok', mfa: false });
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
  assert.deepEqual(links().map((link) => link.getAttribute('data-screen')), ['overview', 'generations', 'history', 'records', 'account']);
  assert.equal(globalThis.location.hash, '#/overview');
  assert.equal(links()[0].getAttribute('aria-current'), 'page');
  const main = app.querySelector('main');
  assert.equal(main.querySelector('h1').textContent, 'Overview');

  // The address changes: the screen of it is shown, and the menu says where the user is.
  globalThis.location.hash = '#/generations';
  hash.handlers.forEach((handler) => handler());
  await wait();
  assert.equal(main.querySelector('h1').textContent, 'Generations');
  assert.deepEqual(links().map((link) => link.getAttribute('aria-current')), [null, 'page', null, null, null]);
  // A value that is not of its form is dropped from the address and told.
  globalThis.location.hash = '#/generations/not-a-fingerprint';
  hash.handlers.forEach((handler) => handler());
  assert.equal(globalThis.location.hash, '#/generations');
  assert.equal(app.textContent.includes('Removed what was not valid in the address.'), true);

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
