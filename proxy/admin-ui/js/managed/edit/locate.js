// Where the refusal of a check belongs. The API names the place of what it refuses as the path of a key of the request
// (`at`: `upstreams.app.servers[1].address`), and the table here gives the screen, the panel and the field of the draft
// for it. Names and numbers are read with what the request held when it was sent (`map`, see `Draft.build`), so a line
// that was taken away since does not shift the answer onto another. A place that the table does not hold is told in the
// band, in words only. Nothing runs when the module is loaded.

import { lazy, w } from '../../i18n.js';

const SERVER_FIELD = /^upstreams\.([A-Za-z0-9_-]{1,64})\.servers\[([0-9]{1,3})\]\.(address|weight|max_fails|fail_timeout_ms)$/;
const TLS_FIELD = /^upstreams\.([A-Za-z0-9_-]{1,64})\.tls\.(ca|server_name)$/;
const SERVERS = /^upstreams\.([A-Za-z0-9_-]{1,64})\.servers$/;
const GROUP = /^upstreams\.([A-Za-z0-9_-]{1,64})$/;
const RATE_FIELD = /^rate_limit\.(rate|burst|keys|exempt_cidrs)$/;
const FILE = /^files\[([0-9]{1,3})\]$/;
const NUMBERED = /^(sites|routes)\[([0-9]{1,4})\](?:[.[].*)?$/;

// The places that are a key alone. A `Map`, so that a name from outside cannot find what every object has.
const FIXED = new Map([
  ['upstreams', { screen: 'upstreams', group: null, cid: 'groups', field: 'notice' }],
  ['default_upstream', { screen: 'upstreams', group: null, cid: 'default', field: 'default' }],
  ['access', { screen: 'policy', group: null, cid: 'access', field: 'notice' }],
  ['rate_limit', { screen: 'policy', group: null, cid: 'rate', field: 'notice' }],
]);

const ORDINALS = {
  sites: (number) => w('edit.at.site', { n: number }),
  routes: (number) => w('edit.at.route', { n: number }),
};

/**
 * The place of `at` in the draft: `{ screen, group, cid, field }`, or `{ numbered: [kind, number] }` for a site or a
 * route (they have no form yet, and the number is from 1), or null for a place that the table does not hold.
 */
export function locate(at, map) {
  if (typeof at !== 'string') return null;
  if (FIXED.has(at)) return FIXED.get(at);
  let match = RATE_FIELD.exec(at);
  if (match !== null) return { screen: 'policy', group: null, cid: 'rate', field: match[1] };
  match = FILE.exec(at);
  if (match !== null) return map.files[Number(match[1])] ?? null;
  match = NUMBERED.exec(at);
  if (match !== null) return { numbered: [match[1], Number(match[2]) + 1] };
  match = SERVER_FIELD.exec(at);
  if (match !== null) {
    const group = map.groups.get(match[1]);
    const server = group?.servers[Number(match[2])];
    return server === undefined ? null : { screen: 'upstreams', group: group.cid, cid: server, field: match[3] };
  }
  match = TLS_FIELD.exec(at);
  if (match !== null) return placeOfGroup(map, match[1], match[2]);
  match = SERVERS.exec(at);
  if (match !== null) return placeOfGroup(map, match[1], 'servers');
  match = GROUP.exec(at);
  if (match !== null) return placeOfGroup(map, match[1], 'name');
  return null;
}

function placeOfGroup(map, name, field) {
  const group = map.groups.get(name);
  return group === undefined ? null : { screen: 'upstreams', group: group.cid, cid: group.cid, field };
}

/** The fault of what the band tells, not tied to a field. */
export function barFault(words) {
  return { screen: null, group: null, cid: null, field: 'bar', words };
}

/** The fault for a refusal in `words` about the place `at`. */
export function faultAt(at, map, words) {
  const place = locate(at, map);
  if (place === null) return barFault(words);
  if (place.numbered !== undefined) {
    const [kind, number] = place.numbered;
    return barFault(lazy(() => `${ORDINALS[kind](number)} ${words}`));
  }
  return { ...place, words };
}
