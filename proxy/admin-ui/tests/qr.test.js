import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { MAX_BYTES, darkRuns, encode } from '../js/qr.js';

// Matrices that an independent encoder made once for each text, in byte mode at level M with the smallest version
// that holds it: `rows` are the rows of the matrix, '1' for a dark module. They are data, not code. The texts run
// over the range of the versions (1 to 10, each at its largest size and the first size of the next), over all eight
// masks, over a UTF-8 text, and include the form of the address of a second factor.
const fixtures = JSON.parse(readFileSync(new URL('./qr.fixtures.json', import.meta.url), 'utf8'));

const rowsOf = ({ size, modules }) =>
  Array.from({ length: size }, (_, row) => Array.from(modules.subarray(row * size, (row + 1) * size)).join(''));

test('the matrix of each text equals the one the independent encoder made, with its version and mask', () => {
  assert.ok(fixtures.length >= 8);
  assert.deepEqual([...new Set(fixtures.map((fixture) => fixture.version))].sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.deepEqual([...new Set(fixtures.map((fixture) => fixture.mask))].sort((a, b) => a - b), [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.ok(fixtures.some((fixture) => fixture.text.startsWith('otpauth://totp/')));
  assert.ok(fixtures.some((fixture) => fixture.text.length === 1));
  for (const fixture of fixtures) {
    const code = encode(fixture.text);
    const label = `${fixture.bytes} bytes`;
    assert.equal(code.version, fixture.version, label);
    assert.equal(code.size, fixture.size, label);
    assert.equal(code.size, 17 + 4 * code.version, label);
    assert.equal(code.mask, fixture.mask, label);
    assert.deepEqual(rowsOf(code), fixture.rows, label);
  }
});

test('the version is the smallest that holds the bytes, at each limit and one past it', () => {
  // Bytes that fit in versions 1 to 10 in byte mode at level M.
  const limits = [14, 26, 42, 62, 84, 106, 122, 152, 180, 213];
  assert.equal(MAX_BYTES, limits.at(-1));
  limits.forEach((limit, at) => {
    assert.equal(encode('x'.repeat(limit)).version, at + 1, `${limit} bytes`);
    if (at + 1 < limits.length) assert.equal(encode('x'.repeat(limit + 1)).version, at + 2, `${limit + 1} bytes`);
  });
  // The bytes count, not the characters: 71 characters of three bytes are 213 bytes.
  assert.equal(encode('あ'.repeat(71)).version, 10);
});

test('an empty text and a text of more than the limit are refused', () => {
  assert.throws(() => encode(''), RangeError);
  assert.doesNotThrow(() => encode('x'.repeat(MAX_BYTES)));
  assert.throws(() => encode('x'.repeat(MAX_BYTES + 1)), RangeError);
  assert.throws(() => encode('あ'.repeat(72)), RangeError);
});

test('the runs of dark modules, put back, are the matrix and nothing else', () => {
  for (const fixture of [fixtures[0], fixtures[5], fixtures.at(-1)]) {
    const code = encode(fixture.text);
    const again = new Uint8Array(code.size * code.size);
    for (const { row, column, length } of darkRuns(code)) {
      assert.ok(length >= 1 && column + length <= code.size);
      for (let at = column; at < column + length; at++) {
        assert.equal(again[row * code.size + at], 0, 'a module is in one run only');
        again[row * code.size + at] = 1;
      }
    }
    assert.deepEqual(again, code.modules);
  }
});
