import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFileSync(new URL(path, root), 'utf8');
const scripts = readdirSync(new URL('js/', root)).map((name) => [`js/${name}`, read(`js/${name}`)]);

// What makes markup or code from a string. The page's CSP also refuses these at run time where the browser can.
const FORBIDDEN = [
  ['innerHTML', /innerHTML/],
  ['outerHTML', /outerHTML/],
  ['insertAdjacentHTML', /insertAdjacentHTML/],
  ['document.write', /document\s*\.\s*write/],
  ['eval', /\beval\s*\(/],
  ['new Function', /new\s+Function\b/],
  ['a string given to a timer', /set(Timeout|Interval)\s*\(\s*['"`]/],
  ['createContextualFragment', /createContextualFragment/],
  ['DOMParser', /DOMParser/],
  ['an event attribute set by name', /setAttribute\s*\(\s*['"]on/i],
];

test('the scripts use none of the APIs that make markup or code from a string', () => {
  assert.ok(scripts.length >= 5);
  for (const [name, source] of scripts) {
    for (const [what, pattern] of FORBIDDEN) assert.doesNotMatch(source, pattern, `${name}: ${what}`);
  }
});

test('the page has no inline script, style or event attribute, one stylesheet, and module scripts only', () => {
  const html = read('index.html');
  for (const script of html.matchAll(/<script\b([^>]*)>/gi)) {
    assert.match(script[1], /\bsrc="\/ui\/[^"]+"/, 'a script has a source');
    assert.match(script[1], /\btype="module"/, 'a script is a module');
  }
  assert.doesNotMatch(html, /<style\b/i);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
  assert.doesNotMatch(html, /javascript:/i);
  assert.equal([...html.matchAll(/<link\b[^>]*rel="stylesheet"/gi)].length, 1);
});

test('nothing in the page asks for an address outside it', () => {
  const sources = [...scripts, ['app.css', read('app.css')], ['index.html', read('index.html')]];
  for (const [name, source] of sources) assert.doesNotMatch(source, /https?:\/\//i, name);
  assert.doesNotMatch(read('app.css'), /@import|url\(/i);
});
