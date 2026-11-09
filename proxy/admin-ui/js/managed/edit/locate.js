// Where the refusal of a check belongs. The API names the place of what it refuses as the path of a key of the request
// (`at`: `upstreams.app.servers[1].address`), and the table here gives the screen, the panel and the field of the draft
// for it. Names and numbers are read with what the request held when it was sent (`map`, see `Draft.build`), so a line
// that was taken away since does not shift the answer onto another. A place that the table does not hold is told in the
// band, in words only. Nothing runs when the module is loaded.

import { lazy, t } from '../../i18n.js';

const SERVER_FIELD = /^upstreams\.([A-Za-z0-9_-]{1,64})\.servers\[([0-9]{1,3})\]\.(address|weight|max_fails|fail_timeout_ms)$/;
const TLS_FIELD = /^upstreams\.([A-Za-z0-9_-]{1,64})\.tls\.(ca|server_name)$/;
const SERVERS = /^upstreams\.([A-Za-z0-9_-]{1,64})\.servers$/;
const GROUP = /^upstreams\.([A-Za-z0-9_-]{1,64})$/;
const RATE_FIELD = /^rate_limit\.(rate|burst|keys|exempt_cidrs)$/;
const FILE = /^files\[([0-9]{1,3})\]$/;
const SITE = /^sites\[([0-9]{1,4})\](?:\.(name|hosts|certificate|certificate\.chain|certificate\.key|certificate\.acme))?$/;
const SITE_HOST = /^sites\[([0-9]{1,4})\]\.hosts\[([0-9]{1,4})\]$/;
const ROUTE = /^routes\[([0-9]{1,4})\](?:\.(host|path|upstream|max_body|records|access|stream|rewrite\.host|rewrite\.path|rewrite\.query|rewrite\.request_headers|rewrite\.response_headers))?$/;

// The places that are a key alone. A `Map`, so that a name from outside cannot find what every object has.
const FIXED = new Map([
  ['upstreams', { screen: 'upstreams', panel: null, cid: 'groups', field: 'notice' }],
  ['default_upstream', { screen: 'upstreams', panel: null, cid: 'default', field: 'default' }],
  ['access', { screen: 'policy', panel: null, cid: 'access', field: 'notice' }],
  ['rate_limit', { screen: 'policy', panel: null, cid: 'rate', field: 'notice' }],
  ['sites', { screen: 'sites', panel: null, cid: 'sites', field: 'notice' }],
  ['routes', { screen: 'routes', panel: null, cid: 'routes', field: 'notice' }],
]);

// What a key under a site stands for, as the field of its panel. A `Map`, for the same reason as above.
const SITE_FIELDS = new Map([
  ['name', 'name'],
  ['hosts', 'hosts'],
  ['certificate', 'certificate'],
  ['certificate.chain', 'chain'],
  ['certificate.key', 'key'],
  ['certificate.acme', 'renew_before_days'],
]);

// What a key under a route stands for: a part that is told as a whole has a number of its own, made from the number of the route.
const ROUTE_FIELDS = new Map([
  ['host', 'host'],
  ['path', 'path'],
  ['upstream', 'upstream'],
  ['max_body', 'max_body'],
  ['records', 'records'],
  ['rewrite.host', 'rewrite_host'],
  ['rewrite.path', 'rewrite_path'],
]);
const ROUTE_PARTS = new Map([
  ['access', 'access'],
  ['stream', 'stream'],
  ['rewrite.query', 'query'],
  ['rewrite.request_headers', 'request_headers'],
  ['rewrite.response_headers', 'response_headers'],
]);

function placeOfRoute(cid, key) {
  if (key === undefined) return { screen: 'routes', panel: cid, cid, field: 'notice' };
  if (ROUTE_PARTS.has(key)) return { screen: 'routes', panel: cid, cid: `${cid}.${ROUTE_PARTS.get(key)}`, field: 'notice' };
  return { screen: 'routes', panel: cid, cid, field: ROUTE_FIELDS.get(key) };
}

/**
 * The place of `at` in the draft: `{ screen, panel, cid, field }`, with `line` the line of its box (from 1) for one host
 * of a site, or null for a place that the table does not hold. A number past what the request held is such a place.
 */
export function locate(at, map) {
  if (typeof at !== 'string') return null;
  if (FIXED.has(at)) return FIXED.get(at);
  let match = RATE_FIELD.exec(at);
  if (match !== null) return { screen: 'policy', panel: null, cid: 'rate', field: match[1] };
  match = FILE.exec(at);
  if (match !== null) return map.files[Number(match[1])] ?? null;
  match = SITE_HOST.exec(at);
  if (match !== null) {
    const site = map.sites[Number(match[1])];
    const line = site?.hostLines[Number(match[2])];
    return line === undefined ? null : { screen: 'sites', panel: site.cid, cid: site.cid, field: 'hosts', line };
  }
  match = SITE.exec(at);
  if (match !== null) {
    const site = map.sites[Number(match[1])];
    if (site === undefined) return null;
    return { screen: 'sites', panel: site.cid, cid: site.cid, field: match[2] === undefined ? 'notice' : SITE_FIELDS.get(match[2]) };
  }
  match = ROUTE.exec(at);
  if (match !== null) {
    const cid = map.routes[Number(match[1])];
    return cid === undefined ? null : placeOfRoute(cid, match[2]);
  }
  match = SERVER_FIELD.exec(at);
  if (match !== null) {
    const group = map.groups.get(match[1]);
    const server = group?.servers[Number(match[2])];
    return server === undefined ? null : { screen: 'upstreams', panel: group.cid, cid: server, field: match[3] };
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
  return group === undefined ? null : { screen: 'upstreams', panel: group.cid, cid: group.cid, field };
}

/** The fault of what the band tells, not tied to a field. */
export function barFault(words) {
  return { screen: null, panel: null, cid: null, field: 'bar', words };
}

/** The fault for a refusal in `words` about the place `at`. */
export function faultAt(at, map, words) {
  const place = locate(at, map);
  if (place === null) return barFault(words);
  if (place.line !== undefined) {
    const { line, ...rest } = place;
    return { ...rest, words: lazy(() => `${t('edit.at.line', { n: line })} ${words}`) };
  }
  return { ...place, words };
}
