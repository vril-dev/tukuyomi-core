import assert from 'node:assert/strict';
import { test } from 'node:test';

import { el, safeUrl } from '../js/dom.js';

// `el` builds elements with the DOM of the page. A minimal stand-in is enough for what it refuses; each test file runs
// in a process of its own, so this does not reach the other files.
class Node {
  constructor(tag) {
    this.tag = tag;
    this.attributes = {};
    this.children = [];
  }

  setAttribute(name, value) {
    this.attributes[name] = value;
  }

  addEventListener() {}

  append(...children) {
    this.children.push(...children);
  }
}
globalThis.Node = Node;
globalThis.document = { createElement: (tag) => new Node(tag), createTextNode: (text) => ({ text }) };

test('a URL may name a part of this page or a file below /ui/, and nothing else', () => {
  for (const value of ['#/status', '#', '/ui/app.js']) assert.equal(safeUrl(value), true, value);
  for (const value of [
    'javascript:alert(1)',
    ' javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    '//host/ui/app.js',
    'https://host/ui/app.js',
    'data:text/html,x',
    '/api/logout',
    '/ui',
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
  // The attributes of the page itself pass, and the listeners go in through `on`.
  const link = el('a', { href: '#/status', class: 'nav', 'aria-label': 'x', hidden: true, on: { click: () => {} } });
  assert.deepEqual(link.attributes, { href: '#/status', 'aria-label': 'x', hidden: '' });
});

test('a string given to an element is text and never markup', () => {
  const text = '<img src=x onerror=alert(1)>';
  const node = el('p', {}, text, 7, null, [false, 'b']);
  assert.deepEqual(node.children, [{ text }, { text: '7' }, { text: 'b' }]);
});
