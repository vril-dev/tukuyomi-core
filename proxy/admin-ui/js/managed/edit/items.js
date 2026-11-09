// The items of a draft of the managed configuration and how each goes to and from a version: the groups of upstreams with
// their servers, the access control, the rate limit and the sites. An item holds the text that was typed and a number of
// its own (`cid`) that never leaves the page; what is built from it starts from the object that it was read from, so a
// key that no form holds stays as it was. Nothing runs when the module is loaded.

import { w } from '../../i18n.js';
import { emptyField } from '../../parts.js';

/** A name of a group of upstreams, as the API takes it. */
export const NAME = /^[A-Za-z0-9_-]{1,64}$/;
// A number of the kind `u32` is written with at most 9 digits, and any other with at most 15: a number past what the
// API can read is refused about the whole item, so it is told here at its field.
const U32 = /^[0-9]{1,9}$/;
export const WIDE = /^[0-9]{1,15}$/;
// The forms of a line of a list; what is in a line that has the form is for the check of the API.
const NETWORK = /^[0-9A-Fa-f:.]+\/[0-9]{1,3}$/;
const COUNTRY = /^([A-Z]{2}|UNKNOWN)$/;

const SERVER_NUMBERS = [
  ['weight', U32, 9],
  ['max_fails', U32, 9],
  ['fail_timeout_ms', WIDE, 15],
];
const RATE_NUMBERS = [
  ['rate', U32, 9],
  ['burst', U32, 9],
  ['keys', WIDE, 15],
];
const networkLine = (line) => w('edit.fault.network', { line });
const countryLine = (line) => w('edit.fault.country', { line });
const ACCESS_LISTS = [
  ['deny_cidrs', NETWORK, networkLine],
  ['allow_cidrs', NETWORK, networkLine],
  ['deny_countries', COUNTRY, countryLine],
  ['allow_countries', COUNTRY, countryLine],
];

export const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/** Whether `value` is a list of strings. */
export const texts = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string');

let serial = 0;

export function nextCid() {
  serial += 1;
  return serial;
}

/** A fault of a field: the screen, the panel that holds it (null: none), the item and the field it is about, and its words. */
export const fault = (screen, panel, cid, field, words) => ({ screen, panel, cid, field, words });

export const linesText = (list) => (Array.isArray(list) ? list.join('\n') : '');

/** The lines of a list as it was typed, without what is blank, each with its number in the box (from 1). */
export function linesOf(text) {
  return text
    .split('\n')
    .map((line, at) => ({ text: line.trim(), line: at + 1 }))
    .filter((entry) => entry.text !== '');
}

/** The number that `text` holds, or 0 with the fault told to `report`. */
export function numberOf(text, pattern, digits, report) {
  const value = text.trim();
  if (value === '') {
    report(emptyField());
    return 0;
  }
  if (!pattern.test(value)) {
    report(w('edit.fault.number', { digits }));
    return 0;
  }
  return Number(value);
}

/** The object `built` with the list `values` under `key`: a key that was written stays when the list is empty, and one that was not is written for lines only. */
export function withList(built, item, key, values) {
  if (values.length > 0 || Object.hasOwn(item.raw, key)) built[key] = values;
}

/** The object `built` with `text` under `key`, which is not written when it is empty. */
export function withText(built, key, text) {
  const value = text.trim();
  if (value === '') delete built[key];
  else built[key] = value;
}

/** The values of the list under `key` of `item`, with a fault of the screen and the panel at the first line that is not in the form of its list. */
function builtList(screen, panel, item, key, pattern, problem, faults) {
  const lines = linesOf(item[key]);
  const wrong = lines.find((entry) => !pattern.test(entry.text));
  if (wrong !== undefined) faults.push(fault(screen, panel, item.cid, key, problem(wrong.line)));
  return lines.map((entry) => entry.text);
}

// ---- the groups of upstreams ----

function serverOf(raw) {
  return {
    cid: nextCid(),
    address: String(raw.address ?? ''),
    weight: String(raw.weight ?? ''),
    max_fails: String(raw.max_fails ?? ''),
    fail_timeout_ms: String(raw.fail_timeout_ms ?? ''),
    backup: raw.backup === true,
    raw,
  };
}

/** A new server: the values of a server of nginx that says nothing else. */
export function newServer() {
  return { cid: nextCid(), address: '', weight: '1', max_fails: '1', fail_timeout_ms: '10000', backup: false, raw: {} };
}

/** What a group holds as text, to tell whether it has changed since the draft was made. */
export function snapshot(group) {
  const servers = group.servers.map((server) => [server.address, server.weight, server.max_fails, server.fail_timeout_ms, server.backup]);
  return JSON.stringify([group.name, group.tls, group.ca, group.server_name, servers]);
}

export function groupOf(name, raw) {
  const tls = Object.hasOwn(raw, 'tls') ? raw.tls : {};
  const group = {
    cid: nextCid(),
    fresh: false,
    name,
    servers: raw.servers.map(serverOf),
    tls: Object.hasOwn(raw, 'tls'),
    ca: typeof tls.ca === 'string' ? tls.ca : '',
    server_name: typeof tls.server_name === 'string' ? tls.server_name : '',
    raw,
  };
  group.origin = snapshot(group);
  return group;
}

export function newGroup() {
  return { cid: nextCid(), fresh: true, name: '', servers: [newServer()], tls: false, ca: '', server_name: '', raw: {} };
}

export function builtServer(group, server, faults) {
  const report = (key) => (words) => faults.push(fault('upstreams', group.cid, server.cid, key, words));
  const built = { ...server.raw, address: server.address.trim(), backup: server.backup };
  if (built.address === '') report('address')(emptyField());
  for (const [key, pattern, digits] of SERVER_NUMBERS) built[key] = numberOf(server[key], pattern, digits, report(key));
  return built;
}

/** The `tls` of a group, or undefined when the group does not use TLS. */
export function builtTls(group, faults) {
  if (!group.tls) return undefined;
  if (group.ca === '') faults.push(fault('upstreams', group.cid, group.cid, 'ca', w('edit.fault.ca')));
  const built = { ...group.raw.tls, ca: group.ca };
  withText(built, 'server_name', group.server_name);
  return built;
}

// ---- the access control and the rate limit ----

/** The item of an access control that a version holds as `raw` (or does not hold). */
export function accessOf(raw, cid) {
  return {
    cid,
    on: raw !== undefined,
    deny_cidrs: linesText(raw?.deny_cidrs),
    allow_cidrs: linesText(raw?.allow_cidrs),
    deny_countries: linesText(raw?.deny_countries),
    allow_countries: linesText(raw?.allow_countries),
    raw: raw ?? {},
  };
}

export function rateOf(raw) {
  return {
    cid: 'rate',
    on: raw !== undefined,
    rate: String(raw?.rate ?? ''),
    burst: String(raw?.burst ?? ''),
    keys: String(raw?.keys ?? ''),
    exempt_cidrs: linesText(raw?.exempt_cidrs),
    raw: raw ?? {},
  };
}

/** The `access` of a screen and a panel, or undefined when it is turned off. */
export function builtAccess(access, screen, panel, faults) {
  if (!access.on) return undefined;
  const built = { ...access.raw };
  for (const [key, pattern, problem] of ACCESS_LISTS) withList(built, access, key, builtList(screen, panel, access, key, pattern, problem, faults));
  return built;
}

/** The `rate_limit`, or undefined when it is turned off. */
export function builtRate(rate, faults) {
  if (!rate.on) return undefined;
  const built = { ...rate.raw };
  for (const [key, pattern, digits] of RATE_NUMBERS) {
    built[key] = numberOf(rate[key], pattern, digits, (words) => faults.push(fault('policy', null, rate.cid, key, words)));
  }
  withList(built, rate, 'exempt_cidrs', builtList('policy', null, rate, 'exempt_cidrs', NETWORK, networkLine, faults));
  return built;
}

// ---- the sites ----

/** What a site holds as text, to tell whether it has changed since the draft was made: of its certificate, only what its kind uses. */
export function siteText(site) {
  const certificate = site.kind === 'acme' ? [site.renew_before_days] : [site.chain, site.key];
  return JSON.stringify([site.name, site.hosts, site.kind, certificate]);
}

/** The item of a site of a version. A certificate is held by its kind: the two files, or the days of the renewal. */
export function siteOf(raw) {
  const { certificate } = raw;
  const acme = Object.hasOwn(certificate, 'acme');
  const site = {
    cid: nextCid(),
    fresh: false,
    name: raw.name,
    hosts: linesText(raw.hosts),
    kind: acme ? 'acme' : 'file',
    chain: acme ? '' : certificate.chain,
    key: acme ? '' : certificate.key,
    renew_before_days: acme ? String(certificate.acme.renew_before_days ?? '') : '',
    raw,
  };
  site.origin = siteText(site);
  return site;
}

/** A new site, whose certificate is in files until it says otherwise. No value of the renewal is suggested. */
export function newSite() {
  return { cid: nextCid(), fresh: true, name: '', hosts: '', kind: 'file', chain: '', key: '', renew_before_days: '', raw: {} };
}

/** Whether the site `raw` of a version has the form that its item is made from. */
export function readableSite(raw) {
  if (!plain(raw) || typeof raw.name !== 'string' || !texts(raw.hosts) || !plain(raw.certificate)) return false;
  const { certificate } = raw;
  if (Object.hasOwn(certificate, 'acme')) return plain(certificate.acme) && !Object.hasOwn(certificate, 'chain') && !Object.hasOwn(certificate, 'key');
  return typeof certificate.chain === 'string' && typeof certificate.key === 'string';
}

/**
 * The site as the version holds it. Its `certificate` is made whole for its kind and not copied over the one that was
 * read: a version holds either the two files or `acme`, and never both.
 */
export function builtSite(site, faults) {
  const report = (key) => (words) => faults.push(fault('sites', site.cid, site.cid, key, words));
  const name = site.name.trim();
  if (name === '') report('name')(emptyField());
  const hosts = linesOf(site.hosts).map((entry) => entry.text);
  if (hosts.length === 0) report('hosts')(emptyField());
  let certificate;
  if (site.kind === 'acme') {
    certificate = { acme: { renew_before_days: numberOf(site.renew_before_days, U32, 9, report('renew_before_days')) } };
  } else {
    if (site.chain === '') report('chain')(w('edit.fault.chain'));
    if (site.key === '') report('key')(w('edit.fault.key'));
    certificate = { chain: site.chain, key: site.key };
  }
  return { ...site.raw, name, hosts, certificate };
}
