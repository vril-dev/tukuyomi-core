// The routes of a draft of the managed configuration and how each goes to and from a version. A route that has not been
// opened holds what the version says and is sent as it is; its form is made the first time its panel is opened. The
// parts of a form have numbers of their own, made from the number of the route, so a refusal that names a part alone
// goes when the part is written to. The lists of a rewrite are typed one item to a line, as `name=value` for a query
// and as `Name: value` for a field of a header. Nothing runs when the module is loaded.

import { w } from '../../i18n.js';
import { WIDE, accessOf, builtAccess, fault, linesOf, linesText, nextCid, numberOf, plain, texts, withList, withText } from './items.js';

const STREAM_NUMBERS = [
  ['idle_ms', WIDE, 15],
  ['total_ms', WIDE, 15],
];

const textOf = (value) => (typeof value === 'string' ? value : '');

/** A line of a list of `name=value`, cut at the first `=`: neither the name nor the value of a query can hold another. Null when it has no name. */
export function queryPair(line) {
  const at = line.indexOf('=');
  return at <= 0 ? null : { name: line.slice(0, at), value: line.slice(at + 1) };
}

/** A line of a list of `Name: value`, cut at the first `:`, which a name cannot hold; the blanks after the name and around the value belong to neither. Null when it has no name. */
export function headerPair(line) {
  const at = line.indexOf(':');
  return at <= 0 ? null : { name: line.slice(0, at).trimEnd(), value: line.slice(at + 1).trim() };
}

const queryLine = ({ name, value }) => `${name}=${value}`;
const headerLine = ({ name, value }) => (value === '' ? `${name}:` : `${name}: ${value}`);

// How the lists of each kind of part are read and written; `lines` holds a name to a line, and `pairs` two values.
const QUERY = { lines: ['remove', 'remove_prefixes'], pairs: ['set', 'add'], read: queryPair, write: queryLine, problem: (line) => w('edit.fault.query_pair', { line }) };
const HEADERS = { lines: ['remove'], pairs: ['set', 'add'], read: headerPair, write: headerLine, problem: (line) => w('edit.fault.header_pair', { line }) };
const PARTS = [
  ['query', QUERY],
  ['request_headers', HEADERS],
  ['response_headers', HEADERS],
];

function partOf(raw, cid, kind) {
  const part = { cid, raw: raw ?? {} };
  for (const key of kind.lines) part[key] = linesText(part.raw[key]);
  for (const key of kind.pairs) part[key] = Array.isArray(part.raw[key]) ? part.raw[key].map(kind.write).join('\n') : '';
  return part;
}

function streamOf(raw, cid) {
  return {
    cid,
    on: raw !== undefined,
    idle_ms: String(raw?.idle_ms ?? ''),
    total_ms: String(raw?.total_ms ?? ''),
    websocket: raw?.websocket === true,
    raw: raw ?? {},
  };
}

/** The item of a route of a version; `ref` is the group that it names. Its form is made by `makeForm`. */
export function routeOf(raw, ref) {
  return { cid: nextCid(), fresh: false, raw, ref, form: null, origin: null };
}

/** A new route, which names no group yet and has its form from the start. */
export function newRoute() {
  const route = { cid: nextCid(), fresh: true, raw: {}, ref: { text: '' }, form: null, origin: null };
  makeForm(route);
  return route;
}

/** What a route with a form holds as text, to tell whether it has changed since the form was made. */
function formText(route) {
  return JSON.stringify([route.ref, route.form], (key, value) => (key === 'raw' ? undefined : value));
}

/** Gives `route` its form, with what the version says. This is no change of the draft. */
export function makeForm(route) {
  const { cid, raw } = route;
  const rewrite = raw.rewrite ?? {};
  route.form = {
    cid,
    host: textOf(raw.host),
    path: textOf(raw.path),
    max_body: raw.max_body === undefined ? '' : String(raw.max_body),
    records: textOf(raw.records),
    access: accessOf(raw.access, `${cid}.access`),
    stream: streamOf(raw.stream, `${cid}.stream`),
    rewrite_host: textOf(rewrite.host),
    rewrite_path: textOf(rewrite.path),
    query: partOf(rewrite.query, `${cid}.query`, QUERY),
    request_headers: partOf(rewrite.request_headers, `${cid}.request_headers`, HEADERS),
    response_headers: partOf(rewrite.response_headers, `${cid}.response_headers`, HEADERS),
  };
  route.origin = formText(route);
}

/** Whether a route differs from what it was when its form was made; a route with no form has not changed, and a new one is told as new. */
export function routeChanged(route) {
  return !route.fresh && route.form !== null && formText(route) !== route.origin;
}

/** Whether `value` is a list of `{ name, value }` of strings, or is not written. */
const readablePairs = (value) => value === undefined || (Array.isArray(value) && value.every((pair) => plain(pair) && typeof pair.name === 'string' && typeof pair.value === 'string'));
const readableLines = (value) => value === undefined || texts(value);
const textOrAbsent = (value) => value === undefined || typeof value === 'string';

function readablePart(raw, kind) {
  if (raw === undefined) return true;
  return plain(raw) && kind.lines.every((key) => readableLines(raw[key])) && kind.pairs.every((key) => readablePairs(raw[key]));
}

function readableRewrite(raw) {
  if (raw === undefined) return true;
  if (!plain(raw) || !textOrAbsent(raw.host) || !textOrAbsent(raw.path)) return false;
  return PARTS.every(([name, kind]) => readablePart(raw[name], kind));
}

function readableStream(raw) {
  return raw === undefined || (plain(raw) && typeof raw.idle_ms === 'number' && typeof raw.total_ms === 'number' && typeof raw.websocket === 'boolean');
}

function readableAccess(raw) {
  return raw === undefined || (plain(raw) && ['deny_cidrs', 'allow_cidrs', 'deny_countries', 'allow_countries'].every((key) => readableLines(raw[key])));
}

/** Whether the route `raw` of a version has the form that its form is made from. */
export function readableRoute(raw) {
  if (!plain(raw) || typeof raw.upstream !== 'string' || !textOrAbsent(raw.host) || !textOrAbsent(raw.path) || !textOrAbsent(raw.records)) return false;
  if (raw.max_body !== undefined && typeof raw.max_body !== 'number') return false;
  return readableAccess(raw.access) && readableStream(raw.stream) && readableRewrite(raw.rewrite);
}

/** The values of a list of pairs, with a fault at its first line that has no name or separator. */
function builtPairs(route, part, key, kind, faults) {
  const lines = linesOf(part[key]).map((entry) => ({ line: entry.line, pair: kind.read(entry.text) }));
  const wrong = lines.find((entry) => entry.pair === null);
  if (wrong !== undefined) faults.push(fault('routes', route.cid, part.cid, key, kind.problem(wrong.line)));
  return lines.filter((entry) => entry.pair !== null).map((entry) => entry.pair);
}

function builtPart(route, part, kind, faults) {
  const built = { ...part.raw };
  for (const key of kind.lines) withList(built, part, key, linesOf(part[key]).map((entry) => entry.text));
  for (const key of kind.pairs) withList(built, part, key, builtPairs(route, part, key, kind, faults));
  return built;
}

/** The `rewrite` of a route: a part or the `rewrite` itself that the version did not write is written only when it holds something. */
function builtRewrite(route, faults) {
  const { form, raw } = route;
  const was = raw.rewrite ?? {};
  const built = { ...was };
  withText(built, 'host', form.rewrite_host);
  withText(built, 'path', form.rewrite_path);
  for (const [name, kind] of PARTS) {
    const part = builtPart(route, form[name], kind, faults);
    if (Object.keys(part).length > 0 || Object.hasOwn(was, name)) built[name] = part;
  }
  return Object.keys(built).length > 0 || raw.rewrite !== undefined ? built : undefined;
}

function builtStream(route, stream, faults) {
  if (!stream.on) return undefined;
  const built = { ...stream.raw, websocket: stream.websocket };
  for (const [key, pattern, digits] of STREAM_NUMBERS) {
    built[key] = numberOf(stream[key], pattern, digits, (words) => faults.push(fault('routes', route.cid, stream.cid, key, words)));
  }
  return built;
}

/** Whether a value of a route holds something: a list or an object with an entry, or any other value that is written. */
function filled(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (plain(value)) return Object.values(value).some(filled);
  return value !== undefined && value !== '';
}

/** Which of the parts of a route, in a version's shape, hold something: for its marks in the list. */
export function routeTags(shape) {
  return ['access', 'rewrite', 'stream', 'max_body', 'records'].filter((key) => filled(shape[key]));
}

/** What the list of the routes shows of `route` besides its group, as one text: it changes only when a line of the list would. */
export function routeLine(route) {
  const shape = builtRoute(route, '', []);
  return JSON.stringify([shape.host ?? null, shape.path ?? null, routeTags(shape), routeChanged(route)]);
}

/**
 * The route as the version holds it, with `upstream` the name of its group. A route with no form goes as it was read,
 * and one with a form is made from it: a part that is turned off is not written, and what a version did not write is
 * written only when it holds something.
 */
export function builtRoute(route, upstream, faults) {
  if (route.form === null) return { ...route.raw, upstream };
  const { form } = route;
  const report = (key) => (words) => faults.push(fault('routes', route.cid, route.cid, key, words));
  if (route.ref.cid === undefined && route.ref.text === '') report('upstream')(w('edit.fault.upstream'));
  const built = { ...route.raw, upstream };
  withText(built, 'host', form.host);
  withText(built, 'path', form.path);
  if (form.max_body.trim() === '') delete built.max_body;
  else built.max_body = numberOf(form.max_body, WIDE, 15, report('max_body'));
  if (form.records === '') delete built.records;
  else built.records = form.records;
  for (const [key, value] of [
    ['access', builtAccess(form.access, 'routes', route.cid, faults)],
    ['stream', builtStream(route, form.stream, faults)],
    ['rewrite', builtRewrite(route, faults)],
  ]) {
    if (value === undefined) delete built[key];
    else built[key] = value;
  }
  return built;
}
