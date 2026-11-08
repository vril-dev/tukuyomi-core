// Run with `node --test` in the directory above; no package is needed (Node 22.7 or later reads these as modules).
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

import { dictionaries, pickLanguage, sentence, setLanguage, t } from '../js/i18n.js';

const scripts = new URL('../js/', import.meta.url);
const scriptNames = readdirSync(scripts, { recursive: true }).filter((name) => name.endsWith('.js'));
const isWords = (name) => name.endsWith('/words.js');

test('the two dictionaries have the same keys, and every text is filled', () => {
  assert.deepEqual(Object.keys(dictionaries.ja).sort(), Object.keys(dictionaries.en).sort());
  for (const [code, words] of Object.entries(dictionaries)) {
    for (const [key, text] of Object.entries(words)) {
      assert.ok(typeof text === 'string' && text.trim() !== '', `${code}: ${key}`);
    }
  }
});

test('a text has the same values to fill in, in both languages', () => {
  const names = (text) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
  for (const key of Object.keys(dictionaries.en)) {
    assert.deepEqual(names(dictionaries.ja[key]), names(dictionaries.en[key]), key);
  }
});

test('a key is written in one file of the dictionaries only', () => {
  const unquoted = (text) => text.replace(/\\(.)/g, '$1');
  const keysOf = (source) => new Set([...source.matchAll(/^ {2}(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"):/gm)].map((match) => unquoted(match[1] ?? match[2])));
  const seen = new Map();
  for (const name of scriptNames.filter((file) => file === 'i18n.js' || isWords(file))) {
    for (const key of keysOf(readFileSync(new URL(name, scripts), 'utf8'))) {
      assert.equal(seen.get(key), undefined, `${key}: in ${seen.get(key)} and in ${name}`);
      seen.set(key, name);
    }
  }
  // Every key of the dictionaries was seen above, so that a key that the reading above missed cannot pass.
  assert.equal(seen.size, Object.keys(dictionaries.en).length);
});

test('every key that a script asks for with t() or w() is in the dictionaries', () => {
  for (const name of scriptNames) {
    const source = readFileSync(new URL(name, scripts), 'utf8');
    for (const [, key] of source.matchAll(/(?<![\w.])[tw]\(\s*'([^']+)'/g)) {
      assert.ok(Object.hasOwn(dictionaries.en, key), `${name}: ${key}`);
    }
  }
});

test('the language is the saved one, else the first language of the browser that we have, else English', () => {
  assert.equal(pickLanguage('ja', ['en-US']), 'ja');
  assert.equal(pickLanguage(null, ['fr-FR', 'ja-JP']), 'ja');
  assert.equal(pickLanguage('xx', ['de']), 'en');
  assert.equal(pickLanguage(null, undefined), 'en');
});

test('a key gives its words with the values filled in, and a sentence that is not ours stays as it is', () => {
  setLanguage('ja');
  assert.equal(t('table.range', { from: 1, to: 50, total: 120 }), '1–50 件目（全 120 件）');
  assert.equal(sentence('invalid credentials'), dictionaries.ja['invalid credentials']);
  assert.equal(sentence('a sentence nobody knows'), 'a sentence nobody knows');
  assert.equal(sentence('constructor'), 'constructor');
  setLanguage('en');
  assert.equal(t('no.such.key'), 'no.such.key');
});

/** The text of the argument that starts at `at` in `source` and ends at the next `,` or `)` that is not inside a bracket or a string. */
function argumentAt(source, at) {
  let depth = 0;
  for (let i = at; i < source.length; i += 1) {
    const char = source[i];
    if (char === "'" || char === '"' || char === '`') {
      i += 1;
      while (source[i] !== char) i += source[i] === '\\' ? 2 : 1;
    } else if ('([{'.includes(char)) depth += 1;
    else if (')]}'.includes(char) && depth === 0) return source.slice(at, i);
    else if (')]}'.includes(char)) depth -= 1;
    else if (char === ',' && depth === 0) return source.slice(at, i);
  }
  return source.slice(at);
}

/** The names that an object written in the call gives (`null` when the call gives something else, or spreads another object). */
function givenNames(text) {
  const body = text.trim();
  if (!body.startsWith('{') || !body.endsWith('}')) return null;
  const names = [];
  let at = 1;
  while (at < body.length - 1) {
    const entry = argumentAt(body.slice(0, -1), at);
    const match = /^\s*(?:'([^']*)'|(\w+))/.exec(entry);
    if (entry.trim().startsWith('...') || match === null) return null;
    names.push(match[1] ?? match[2]);
    at += entry.length + 1;
  }
  return names;
}

test('a call of t() or w() that gives its values in the call gives all that the text of its key asks for', () => {
  const asked = (key) => [...new Set([...dictionaries.en[key].matchAll(/\{(\w+)\}/g)].map((m) => m[1]))];
  let checked = 0;
  for (const name of scriptNames.filter((file) => file !== 'i18n.js' && !isWords(file))) {
    const source = readFileSync(new URL(name, scripts), 'utf8');
    for (const match of source.matchAll(/(?<![\w.])[tw]\(\s*'([^']+)'/g)) {
      const wanted = asked(match[1]);
      const rest = source.slice(match.index + match[0].length);
      const second = rest.trimStart().startsWith(',') ? argumentAt(source, match.index + match[0].length + rest.indexOf(',') + 1) : null;
      const given = second === null ? [] : givenNames(second);
      // A call that passes a value made elsewhere (`w('out.switched', ids(outcome))`) cannot be read here.
      if (given === null) continue;
      checked += 1;
      assert.deepEqual(wanted.filter((value) => !given.includes(value)), [], `${name}: ${match[1]} is called without a value that its text asks for`);
    }
  }
  assert.ok(checked > 100);
});
