// A file of PEM that the user chooses for a field of the draft: the authorities of a group of upstreams, or the chain or
// the private key of a site. It is read in the browser, checked to be text in UTF-8, and named by the SHA-256 of what is sent, which is the text and not the bytes
// that were read: a byte order mark at the start of a file is not part of the text. What is in a file is not shown.
// What was read of a key is wiped as soon as it has served, on the way out of a failure as well; the text of a file
// cannot be wiped in the browser, and goes when nothing refers to it. A reading that a new choice or a change of the
// draft has passed by is dropped. Nothing runs when the module is loaded.

import { w } from '../../i18n.js';

/** The largest file of PEM that the API takes (1 MiB). */
export const PEM_MAX = 1048576;

const PROBLEMS = {
  secure: () => w('edit.pem.secure'),
  size: () => w('edit.pem.size'),
  utf8: () => w('edit.pem.utf8'),
  read: () => w('edit.pem.read'),
};

/** The words of a problem that `pickPem` gave. */
export function pemProblem(code) {
  return PROBLEMS[code]();
}

function readBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

/** The text of `bytes` and the SHA-256 of that text as 64 hexadecimal digits, or null for bytes that are not UTF-8. */
export async function pemFromBytes(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  const encoded = new TextEncoder().encode(text);
  try {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', encoded);
    return { text, sha256: [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('') };
  } finally {
    encoded.fill(0);
  }
}

async function readPem(file, read) {
  if (globalThis.crypto?.subtle === undefined) return { problem: 'secure' };
  if (file.size > PEM_MAX) return { problem: 'size' };
  let bytes = null;
  try {
    bytes = await read(file);
    const pem = await pemFromBytes(bytes);
    return pem === null ? { problem: 'utf8' } : { pem: { ...pem, name: file.name, size: file.size } };
  } catch {
    return { problem: 'read' };
  } finally {
    bytes?.fill(0);
  }
}

/**
 * Reads `file` for the field `key` of `draft`. Gives `{ pem: { text, sha256, name, size } }`, `{ problem }` (a code of
 * `pemProblem`), or null when another choice of the field, or the end of the draft, has passed this reading by.
 */
export async function pickPem(draft, key, file, read = readBytes) {
  const mark = draft.startReading(key);
  const outcome = await readPem(file, read);
  return draft.endReading(key, mark) ? outcome : null;
}
