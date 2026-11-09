// The lists of the rewrite of a route, in the panel of the route: what to remove, to set and to add in the query, in the
// fields of the request and in the fields of the response, one item to a line. How a line is read and written is in
// `route-items.js`. Nothing runs when the module is loaded.

import { el } from '../../../dom.js';
import { w } from '../../../i18n.js';
import { linesBox } from '../form.js';

const NAMES = () => w('edit.rewrite.names_hint');
const QUERY_PAIRS = () => w('edit.rewrite.query_hint');
const HEADER_PAIRS = () => w('edit.rewrite.header_hint');

// The lists of each kind of part: the key, its label and its help.
const QUERY_LISTS = [
  ['remove', () => w('edit.rewrite.remove'), NAMES],
  ['remove_prefixes', () => w('edit.rewrite.remove_prefixes'), NAMES],
  ['set', () => w('edit.rewrite.set'), QUERY_PAIRS],
  ['add', () => w('edit.rewrite.add'), QUERY_PAIRS],
];
const HEADER_LISTS = [
  ['remove', () => w('edit.rewrite.remove'), NAMES],
  ['set', () => w('edit.rewrite.set'), HEADER_PAIRS],
  ['add', () => w('edit.rewrite.add'), HEADER_PAIRS],
];
const PARTS = [
  ['query', () => w('edit.rewrite.query'), QUERY_LISTS],
  ['request_headers', () => w('edit.rewrite.request_headers'), HEADER_LISTS],
  ['response_headers', () => w('edit.rewrite.response_headers'), HEADER_LISTS],
];

/**
 * The lists of the rewrite of `route`, for the screen `screen`, in the `details` element `part` of the panel. A refusal of
 * a part as a whole is told at the top of that part.
 */
export function rewriteLists(screen, draft, route, part) {
  return PARTS.map(([name, title, lists]) => {
    const item = route.form[name];
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    screen.placeNote(item.cid, 'notice', note, part);
    const boxes = lists.map(([key, label, hint]) => {
      const box = linesBox(label(), item[key], { hint: hint(), rows: 3, onInput: (value) => draft.writeRoute(route, item, key, value) });
      screen.placeField(item.cid, key, box, part);
      return box.node;
    });
    return el('div', { class: 'tc-stack' }, el('h3', {}, title()), note, el('div', { class: 'tc-fields' }, boxes));
  });
}
