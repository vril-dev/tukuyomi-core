// What a saving changes, for the confirmation: the groups, the default group, the access list, the rate limit, the
// sites and the routes that are added, taken away or changed. A line names a group or a site, or the host and the path
// of a route, and none of its values, for a rewrite can hold a secret. Nothing runs when the module is loaded.

const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/** Whether two values of JSON are the same; the order of the keys of an object does not matter. */
function same(a, b) {
  if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((item, at) => same(item, b[at]));
  if (!plain(a) || !plain(b)) return a === b;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && same(a[key], b[key]));
}

/** What changes between the entries of two `Map`s of one area, in the order of the old ones and then of the new ones. */
function changed(area, before, after, label, out) {
  for (const [key, item] of before) {
    if (!after.has(key)) out.push({ area, action: 'remove', label: label(key, item) });
    else if (!same(item, after.get(key))) out.push({ area, action: 'change', label: label(key, item) });
  }
  for (const [key, item] of after) {
    if (!before.has(key)) out.push({ area, action: 'add', label: label(key, item) });
  }
}

/** A value that is there or not, changing as a whole. */
function single(area, a, b, out) {
  if (a === undefined && b === undefined) return;
  if (a === undefined) out.push({ area, action: 'add', label: '' });
  else if (b === undefined) out.push({ area, action: 'remove', label: '' });
  else if (!same(a, b)) out.push({ area, action: 'change', label: '' });
}

const routeKey = (route) => JSON.stringify([route.host ?? null, route.path ?? null]);
const routeLabel = (route) => `${route.host ?? '*'} ${route.path ?? '*'}`;

const isAcme = (site) => plain(site.certificate) && Object.hasOwn(site.certificate, 'acme');
const hostsKey = (site) => JSON.stringify([...site.hosts].sort());

/**
 * How many sites of `after` need a certificate that is not issued yet: those with ACME whose set of hosts no site with
 * ACME of `before` has. A certificate is kept under the set of the hosts of its site, so a site that is new, a change of
 * its hosts and a site that used files before all need one, and a new order of the hosts or a new name does not.
 */
export function sitesToIssue(before, after) {
  const issued = new Set(before.sites.filter(isAcme).map(hostsKey));
  return after.sites.filter((site) => isAcme(site) && !issued.has(hostsKey(site))).length;
}

/**
 * The lines of what changes from the version `before` to the version `after`: `{ area, action, label }` with `area`
 * one of `upstream`, `default`, `access`, `rate_limit`, `site` and `route`, and `action` one of `add`, `remove` and
 * `change`. Groups and sites are matched by their names and routes by their hosts and paths, so a renamed one is one
 * taken away and one added.
 */
export function changesBetween(before, after) {
  const out = [];
  changed('upstream', new Map(Object.entries(before.upstreams)), new Map(Object.entries(after.upstreams)), (key) => key, out);
  if (before.default_upstream !== after.default_upstream) out.push({ area: 'default', action: 'change', label: '' });
  single('access', before.access, after.access, out);
  single('rate_limit', before.rate_limit, after.rate_limit, out);
  const sites = (version) => new Map(version.sites.map((site) => [String(site.name), site]));
  changed('site', sites(before), sites(after), (key) => key, out);
  const routes = (version) => new Map(version.routes.map((route) => [routeKey(route), route]));
  changed('route', routes(before), routes(after), (key, route) => routeLabel(route), out);
  return out;
}
