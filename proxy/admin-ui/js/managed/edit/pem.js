// A file of PEM that the user chooses for a field of the draft: the authority of a group of upstreams. It is read in the
// browser, checked to be text in UTF-8, and named by the SHA-256 of what is sent, which is the text and not the bytes
// that were read: a byte order mark at the start of a file is not part of the text. What is in a file is not shown.
// A reading that a new choice or a change of the draft has passed by is dropped. Nothing runs when the module is
// loaded.

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
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return { text, sha256: [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('') };
}

async function readPem(file, read) {
  if (globalThis.crypto?.subtle === undefined) return { problem: 'secure' };
  if (file.size > PEM_MAX) return { problem: 'size' };
  try {
    const pem = await pemFromBytes(await read(file));
    return pem === null ? { problem: 'utf8' } : { pem: { ...pem, name: file.name, size: file.size } };
  } catch {
    return { problem: 'read' };
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
