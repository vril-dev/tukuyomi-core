// A QR code encoder for short text such as the address of a second factor: byte mode, error correction level M,
// versions 1 to 10 (up to 213 bytes). It follows the QR Code specification: the text becomes bytes, the bytes become
// data codewords, Reed-Solomon codewords are added to each block, the blocks are interleaved, and the bits are placed
// among the function patterns (finders, timing, alignment, format and version information). Of the eight masks the
// one with the lowest penalty is used. `encode` gives the matrix of modules; drawing it is left to the caller. Nothing
// runs when the module is loaded.

/** The most bytes that one symbol of the supported versions holds. */
export const MAX_BYTES = 213;

// For each version (the first row is version 1): the error correction codewords of a block, the blocks with the
// smaller number of data codewords, the data codewords of such a block, and the blocks with one more data codeword.
const BLOCKS = [
  [10, 1, 16, 0],
  [16, 1, 28, 0],
  [26, 1, 44, 0],
  [18, 2, 32, 0],
  [24, 2, 43, 0],
  [16, 4, 27, 0],
  [18, 4, 31, 0],
  [22, 2, 38, 2],
  [22, 3, 36, 2],
  [26, 4, 43, 1],
];
// The rows and columns of the centres of the alignment patterns of each version.
const CENTRES = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
const PAD = [0xec, 0x11];
/** The bits of the format information that say level M. */
const LEVEL_M = 0;
const MASKS = 8;

const sizeOf = (version) => 17 + 4 * version;
const dataWords = ([, shorter, words, longer]) => shorter * words + longer * (words + 1);
/** The bits of the count of bytes: 8 up to version 9, 16 from version 10. */
const countBits = (version) => (version < 10 ? 8 : 16);

/** The most bytes that version `version` (1 to 10) holds. */
function capacity(version) {
  return Math.floor((8 * dataWords(BLOCKS[version - 1]) - 4 - countBits(version)) / 8);
}

/** The smallest version that holds `length` bytes; 0 when none of them does. */
function versionFor(length) {
  for (let version = 1; version <= BLOCKS.length; version++) {
    if (length <= capacity(version)) return version;
  }
  return 0;
}

// ---- Reed-Solomon over GF(256) with the polynomial x^8 + x^4 + x^3 + x^2 + 1 ----

function multiply(a, b) {
  let product = 0;
  for (let bit = 7; bit >= 0; bit--) {
    product = (product << 1) ^ ((product >>> 7) * 0x11d);
    product ^= ((b >>> bit) & 1) * a;
  }
  return product;
}

/** The coefficients (without the leading 1) of the product of (x - 2^i) for i below `degree`. */
function divisor(degree) {
  const result = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = multiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = multiply(root, 2);
  }
  return result;
}

/** The remainder of the polynomial of `data` times x^degree when it is divided by the polynomial of `divide`. */
function remainder(data, divide) {
  const result = new Array(divide.length).fill(0);
  for (const byte of data) {
    const factor = byte ^ result.shift();
    result.push(0);
    for (let i = 0; i < divide.length; i++) result[i] ^= multiply(divide[i], factor);
  }
  return result;
}

// ---- the codewords ----

/** The data codewords of `bytes` in byte mode for `version`: mode, count, bytes, terminator and padding. */
function dataCodewords(bytes, version) {
  const bits = [];
  const push = (value, count) => {
    for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4);
  push(bytes.length, countBits(version));
  for (const byte of bytes) push(byte, 8);
  const total = 8 * dataWords(BLOCKS[version - 1]);
  push(0, Math.min(4, total - bits.length));
  push(0, (8 - (bits.length % 8)) % 8);
  const words = [];
  for (let at = 0; at < bits.length; at += 8) words.push(parseInt(bits.slice(at, at + 8).join(''), 2));
  for (let pad = 0; words.length < total / 8; pad++) words.push(PAD[pad % 2]);
  return words;
}

/** The codewords that are placed: the data and the error correction of each block, interleaved. */
function interleave(words, version) {
  const [correction, shorter, size, longer] = BLOCKS[version - 1];
  const divide = divisor(correction);
  const blocks = [];
  let at = 0;
  for (let i = 0; i < shorter + longer; i++) {
    const length = i < shorter ? size : size + 1;
    const data = words.slice(at, at + length);
    at += length;
    blocks.push({ data, check: remainder(data, divide) });
  }
  const out = [];
  for (let i = 0; i <= size; i++) {
    for (const block of blocks) if (i < block.data.length) out.push(block.data[i]);
  }
  for (let i = 0; i < correction; i++) {
    for (const block of blocks) out.push(block.check[i]);
  }
  return out;
}

// ---- the symbol ----

/** A square of modules; `fixed` marks the modules of the function patterns, which the data and the masks leave alone. */
class Grid {
  constructor(version) {
    this.version = version;
    this.size = sizeOf(version);
    this.modules = new Uint8Array(this.size * this.size);
    this.fixed = new Uint8Array(this.size * this.size);
  }

  set(row, column, dark) {
    if (row < 0 || column < 0 || row >= this.size || column >= this.size) return;
    this.modules[row * this.size + column] = dark ? 1 : 0;
    this.fixed[row * this.size + column] = 1;
  }

  /** The finder patterns with their separators, the timing patterns and the alignment patterns. */
  drawPatterns() {
    const { size, version } = this;
    for (let i = 0; i < size; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    for (const [row, column] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      for (let dr = -1; dr <= 7; dr++) {
        for (let dc = -1; dc <= 7; dc++) {
          const distance = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
          this.set(row + dr, column + dc, distance !== 2 && distance !== 4);
        }
      }
    }
    const centres = CENTRES[version - 1];
    const last = centres.length - 1;
    for (let i = 0; i <= last; i++) {
      for (let j = 0; j <= last; j++) {
        // The three corners that the finder patterns hold have none.
        if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            this.set(centres[i] + dr, centres[j] + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
          }
        }
      }
    }
    if (version >= 7) this.drawVersion();
    this.drawFormat(0);
  }

  /** The 18 bits of the version information, twice. */
  drawVersion() {
    let rest = this.version;
    for (let i = 0; i < 12; i++) rest = (rest << 1) ^ ((rest >>> 11) * 0x1f25);
    const bits = (this.version << 12) | rest;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(b, a, dark);
      this.set(a, b, dark);
    }
  }

  /** The 15 bits of the format information (level and mask), twice, and the module that is always dark. */
  drawFormat(mask) {
    const { size } = this;
    const data = (LEVEL_M << 3) | mask;
    let rest = data;
    for (let i = 0; i < 10; i++) rest = (rest << 1) ^ ((rest >>> 9) * 0x537);
    const bits = ((data << 10) | rest) ^ 0x5412;
    const bit = (i) => ((bits >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) this.set(i, 8, bit(i));
    this.set(7, 8, bit(6));
    this.set(8, 8, bit(7));
    this.set(8, 7, bit(8));
    for (let i = 9; i < 15; i++) this.set(8, 14 - i, bit(i));
    for (let i = 0; i < 8; i++) this.set(8, size - 1 - i, bit(i));
    for (let i = 8; i < 15; i++) this.set(size - 15 + i, 8, bit(i));
    this.set(size - 8, 8, true);
  }

  /**
   * Puts the bits of `words` on the modules that no function pattern holds, in the zigzag of the specification. The
   * modules after the last bit (`remainder` of them) stay light.
   */
  place(words, remainder) {
    const { size } = this;
    const bits = [];
    for (const word of words) for (let i = 7; i >= 0; i--) bits.push((word >>> i) & 1);
    let next = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      const upward = ((right + 1) & 2) === 0;
      for (let step = 0; step < size; step++) {
        for (let j = 0; j < 2; j++) {
          const column = right - j;
          const row = upward ? size - 1 - step : step;
          if (this.fixed[row * size + column] === 1) continue;
          this.modules[row * size + column] = next < bits.length ? bits[next] : 0;
          next++;
        }
      }
    }
    if (next - bits.length !== remainder) throw new Error('the codewords do not fill the symbol');
  }

  /** A copy of the symbol with mask `mask` applied to the data modules and the format information drawn. */
  masked(mask) {
    const copy = new Grid(this.version);
    copy.modules.set(this.modules);
    copy.fixed.set(this.fixed);
    const { size } = copy;
    for (let row = 0; row < size; row++) {
      for (let column = 0; column < size; column++) {
        if (copy.fixed[row * size + column] === 0 && inMask(mask, row, column)) copy.modules[row * size + column] ^= 1;
      }
    }
    copy.drawFormat(mask);
    return copy;
  }
}

function inMask(mask, row, column) {
  switch (mask) {
    case 0:
      return (row + column) % 2 === 0;
    case 1:
      return row % 2 === 0;
    case 2:
      return column % 3 === 0;
    case 3:
      return (row + column) % 3 === 0;
    case 4:
      return (Math.floor(row / 2) + Math.floor(column / 3)) % 2 === 0;
    case 5:
      return ((row * column) % 2) + ((row * column) % 3) === 0;
    case 6:
      return (((row * column) % 2) + ((row * column) % 3)) % 2 === 0;
    default:
      return (((row + column) % 2) + ((row * column) % 3)) % 2 === 0;
  }
}

// The windows of eleven modules that look like a finder pattern with four light modules on one side.
const LOOKS_LIKE_FINDER = [0b10111010000, 0b00001011101];

/** The penalty of the specification for a symbol: runs of one colour, 2 by 2 blocks, finder-like windows, balance. */
function penalty({ modules, size }) {
  const at = (row, column) => modules[row * size + column];
  let total = 0;
  for (const across of [true, false]) {
    for (let line = 0; line < size; line++) {
      const get = (i) => (across ? at(line, i) : at(i, line));
      let run = 1;
      let window = get(0);
      for (let i = 1; i < size; i++) {
        if (get(i) === get(i - 1)) run++;
        else {
          if (run >= 5) total += run - 2;
          run = 1;
        }
        window = ((window << 1) | get(i)) & 0x7ff;
        if (i >= 10 && LOOKS_LIKE_FINDER.includes(window)) total += 40;
      }
      if (run >= 5) total += run - 2;
    }
  }
  let dark = 0;
  for (let row = 0; row < size; row++) {
    for (let column = 0; column < size; column++) {
      dark += at(row, column);
      if (row + 1 < size && column + 1 < size) {
        const same = at(row, column) === at(row, column + 1) && at(row, column) === at(row + 1, column) && at(row, column) === at(row + 1, column + 1);
        if (same) total += 3;
      }
    }
  }
  const cells = size * size;
  // Balance: the dark share is rounded up to a multiple of 5 percent, and each step of 5 percent that this is away
  // from 50 percent costs ten points. Any mask gives a symbol that every reader takes; this only picks among them.
  total += 10 * Math.abs(Math.floor((dark * 20 + cells - 1) / cells) - 10);
  return total;
}

/**
 * The QR code of `text`, as `{ version, size, mask, modules }`: `modules` holds `size * size` values, row by row, 1
 * for a dark module. The text is taken as UTF-8. Throws a RangeError for an empty text and for a text that is longer
 * than `MAX_BYTES` bytes.
 */
export function encode(text) {
  const bytes = new TextEncoder().encode(String(text));
  if (bytes.length === 0) throw new RangeError('nothing to encode');
  const version = versionFor(bytes.length);
  if (version === 0) throw new RangeError(`more than ${MAX_BYTES} bytes`);
  const grid = new Grid(version);
  grid.drawPatterns();
  // Versions 2 to 6 leave seven modules over after the codewords; the others none.
  grid.place(interleave(dataCodewords(bytes, version), version), version >= 2 && version <= 6 ? 7 : 0);
  let best = null;
  for (let mask = 0; mask < MASKS; mask++) {
    const candidate = grid.masked(mask);
    const score = penalty(candidate);
    // The first of equal scores stays.
    if (best === null || score < best.score) best = { mask, score, candidate };
  }
  return { version, size: best.candidate.size, mask: best.mask, modules: best.candidate.modules };
}

/**
 * The dark modules of `code` (from `encode`) as horizontal runs, `{ row, column, length }`, so that a drawing needs
 * one rectangle for each run and not for each module.
 */
export function darkRuns({ size, modules }) {
  const runs = [];
  for (let row = 0; row < size; row++) {
    let column = 0;
    while (column < size) {
      if (modules[row * size + column] === 0) {
        column++;
        continue;
      }
      const start = column;
      while (column < size && modules[row * size + column] === 1) column++;
      runs.push({ row, column: start, length: column - start });
    }
  }
  return runs;
}
