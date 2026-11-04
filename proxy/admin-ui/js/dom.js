// Small helpers that build elements. Text goes in as text nodes only: there is no way here to make markup from a
// string, so what the API or the user sends cannot become an element. A text that has words of the page in it is given
// as `Words` (see `w` and `lazy` in `i18n.js`): it is bound to its text node or attribute, and `retranslate` works it
// out again when the language or the way times are written changes, so that no screen is drawn again for that and what
// the user typed or chose stays. Nothing runs when the module is loaded.

import { Words } from './i18n.js';

// Attributes that are never set from here.
const REFUSED = new Set(['style', 'srcdoc']);
// Attributes that hold a URL; they may only point to a part of this page or to a file next to this script.
const URLS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href']);
// The folder of the scripts of the page, as the browser named it: the page's files are served below a version, so the
// address of a file of the page is made from this one and written nowhere.
const HERE = new URL('./', import.meta.url).href;

/** Whether `value` may be the value of a URL attribute: a part of this page, or a file of the folder of this script. */
export function safeUrl(value) {
  return typeof value === 'string' && (value.startsWith('#') || value.startsWith(HERE));
}

// ---- words that follow the language ----

// Each entry keeps its node weakly: a node that is gone from the page is collected, and its entry with it.
const bound = new Set();
const gone = new FinalizationRegistry((entry) => bound.delete(entry));

const writeText = (node, value) => {
  node.data = value;
};
const writeAttribute = (name) => (node, value) => node.setAttribute(name, value);

function bind(node, words, write) {
  write(node, words.text());
  const entry = { ref: new WeakRef(node), words, write };
  bound.add(entry);
  gone.register(node, entry);
}

/** Binds the attribute `name` of `node` (an element that `el` did not make, such as one of an SVG picture) to words. */
export function bindAttribute(node, name, words) {
  allowAttribute(name, words);
  bind(node, words, writeAttribute(name));
}

/** Works out every text and attribute that was given as words again, for the language that is chosen now. */
export function retranslate() {
  for (const entry of bound) {
    const node = entry.ref.deref();
    if (node === undefined) bound.delete(entry);
    else entry.write(node, entry.words.text());
  }
}

/** Adds the children (nodes, strings, numbers, words, arrays of them) to `parent`; null, undefined and booleans are skipped. */
export function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || typeof child === 'boolean') continue;
    if (child instanceof Words) {
      const node = globalThis.document.createTextNode('');
      bind(node, child, writeText);
      parent.append(node);
    } else {
      parent.append(child instanceof Node ? child : globalThis.document.createTextNode(String(child)));
    }
  }
  return parent;
}

/** Refuses an attribute that is never set from here: the name of an event, `style` and `srcdoc`, and a URL that is not ours (words are not a URL). */
function allowAttribute(name, value) {
  const key = name.toLowerCase();
  if (key.startsWith('on') || REFUSED.has(key)) throw new Error(`attribute not allowed: ${name}`);
  if (URLS.has(key) && !safeUrl(value)) throw new Error(`address not allowed: ${name}`);
}

/**
 * An element. `attributes` are set as attributes (`class` as the class name, `true` as an empty value, `false`, null
 * and undefined leave the attribute out, words are bound); the key `on` holds the listeners, `{ click: handler }`. The
 * names of event attributes, `style`, and a URL that is not ours are refused.
 */
export function el(tag, attributes = {}, ...children) {
  const node = globalThis.document.createElement(tag);
  for (const [name, value] of Object.entries(attributes ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    if (name.toLowerCase() === 'on') {
      for (const [type, handler] of Object.entries(value)) node.addEventListener(type, handler);
      continue;
    }
    allowAttribute(name, value);
    if (value instanceof Words) bind(node, value, writeAttribute(name));
    else if (name.toLowerCase() === 'class') node.className = String(value);
    else node.setAttribute(name, value === true ? '' : String(value));
  }
  return append(node, children);
}

/** Replaces what `parent` holds with the children. */
export function mount(parent, ...children) {
  parent.replaceChildren();
  return append(parent, children);
}

/** Sets the text of `node` (and nothing else of it) to a string or to words. */
export function setText(node, value) {
  return mount(node, value instanceof Words ? value : String(value));
}

// ---- small parts that every screen uses ----

const NOTICE_TONES = { ok: ' tc-notice--ok', warn: ' tc-notice--warn', bad: ' tc-notice--danger', info: '' };
const BADGE_TONES = { ok: ' tc-badge--ok', warn: ' tc-badge--warn', bad: ' tc-badge--danger', info: ' tc-badge--info', muted: '', plain: ' tc-badge--plain' };

/** A message box. `tone` is info, ok, warn or bad; a bad one is announced to a reader of the screen at once. */
export function notice(tone, ...children) {
  return el('div', { class: `tc-notice${NOTICE_TONES[tone] ?? ''}`, role: tone === 'bad' ? 'alert' : 'status' }, ...children);
}

/**
 * The result of an operation in the three parts of a notice: the name of the result, what happened, and what to do
 * next (null for nothing; it is written for a refusal and for a result that is not known).
 */
export function result(tone, title, what, next = null) {
  return notice(
    tone,
    el('span', { class: 'tc-notice__title' }, title),
    what === null ? null : el('span', {}, what),
    next === null ? null : el('span', { class: 'tc-notice__next' }, next),
  );
}

/** A small label that states a state in words. `tone` is ok, warn, bad, info, muted (a dot, no colour) or plain (no dot). */
export function badge(tone, label) {
  return el('span', { class: `tc-badge${BADGE_TONES[tone] ?? ''}` }, label);
}

/** The class of a button of the kinds named in `kinds`, as `primary small`: primary, danger, danger-solid, quiet, small. */
export function buttonClass(kinds = '') {
  return ['tc-btn', ...kinds.split(' ').filter((kind) => kind !== '').map((kind) => `tc-btn--${kind}`)].join(' ');
}

/** A button; `onClick` runs when it is pressed. `attributes` are those of the element (`type: 'submit'`, `disabled`, ...). */
export function button(kinds, label, onClick = null, attributes = {}) {
  return el('button', { type: 'button', class: buttonClass(kinds), on: onClick === null ? undefined : { click: onClick }, ...attributes }, label);
}
