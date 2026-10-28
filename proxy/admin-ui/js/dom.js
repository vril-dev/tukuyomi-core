// Small helpers that build elements. Text goes in as text nodes only: there is no way here to make markup from a
// string, so what the API or the user sends cannot become an element. Nothing runs when the module is loaded.

// Attributes that are never set from here.
const REFUSED = new Set(['style', 'srcdoc']);
// Attributes that hold a URL; they may only point to a part of this page or to a file it serves.
const URLS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href']);

/** Whether `value` may be the value of a URL attribute: a fragment of this page or a file below `/ui/`. */
export function safeUrl(value) {
  return typeof value === 'string' && (value.startsWith('#') || value.startsWith('/ui/'));
}

/** Adds the children (nodes, strings, numbers, arrays of them) to `parent`; null, undefined and booleans are skipped. */
export function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || typeof child === 'boolean') continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

/**
 * An element. `attributes` are set as attributes (`class` as the class name, `true` as an empty value, `false`, null
 * and undefined leave the attribute out); the key `on` holds the listeners, `{ click: handler }`. The names of event
 * attributes, `style`, and a URL that is not ours are refused.
 */
export function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    const key = name.toLowerCase();
    if (key === 'on') {
      for (const [type, handler] of Object.entries(value)) node.addEventListener(type, handler);
    } else if (key.startsWith('on') || REFUSED.has(key)) {
      throw new Error(`attribute not allowed: ${name}`);
    } else if (URLS.has(key) && !safeUrl(value)) {
      throw new Error(`address not allowed: ${name}`);
    } else if (key === 'class') {
      node.className = String(value);
    } else {
      node.setAttribute(name, value === true ? '' : String(value));
    }
  }
  return append(node, children);
}

/** Replaces what `parent` holds with the children. */
export function mount(parent, ...children) {
  parent.replaceChildren();
  return append(parent, children);
}

/** Sets the text of `node` (and nothing else of it). */
export function setText(node, value) {
  node.textContent = String(value);
  return node;
}

/** A message box. `tone` is info, ok, warn or bad; a bad one is announced to a reader of the screen at once. */
export function notice(tone, ...children) {
  return el('div', { class: `notice notice-${tone}`, role: tone === 'bad' ? 'alert' : 'status' }, ...children);
}

/** A small coloured label. `tone` is ok, warn, bad or muted. */
export function badge(tone, label) {
  return el('span', { class: `badge badge-${tone}` }, label);
}
