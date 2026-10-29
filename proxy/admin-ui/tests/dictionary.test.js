// Run with `node --test` in the directory above; no package is needed (Node 22.7 or later reads these as modules).
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

import { dictionaries, pickLanguage, sentence, setLanguage, t } from '../js/i18n.js';

const scripts = new URL('../js/', import.meta.url);

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

test('every key that a script asks for with t() is in the dictionaries', () => {
  for (const name of readdirSync(scripts)) {
    const source = readFileSync(new URL(name, scripts), 'utf8');
    for (const [, key] of source.matchAll(/\bt\(\s*'([^']+)'/g)) {
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
  assert.equal(t('status.read_at', { time: '12:00:00' }), '取得: 12:00:00');
  assert.equal(sentence('invalid credentials'), dictionaries.ja['invalid credentials']);
  assert.equal(sentence('a sentence nobody knows'), 'a sentence nobody knows');
  assert.equal(sentence('constructor'), 'constructor');
  setLanguage('en');
  assert.equal(t('no.such.key'), 'no.such.key');
});
