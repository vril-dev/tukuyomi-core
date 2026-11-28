// What a saving changes, for the confirmation: the groups, the engines of the groups, the default group, the access
// list, the rate limit, the host policies, the sites and the routes that are added, taken away or changed. A line names
// a group, a host policy or a site, or the host and the path (or regular expression) of a route, and none of its values,
// for a rewrite can hold a secret. Nothing runs when the module is loaded.

const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/** Whether two values of JSON are the same; the order of the keys of an object does not matter. */
export function same(a, b) {
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

const routeKey = (route) => JSON.stringify([route.host ?? null, route.path ?? null, route.path_regex ?? null]);
// A regular expression is told with `~` before it (as nginx writes it), so that it is not read as the path of the same text.
const routePath = (route) => (route.path_regex === undefined ? (route.path ?? '*') : `~ ${route.path_regex}`);
const routeLabel = (route) => `${route.host ?? '*'} ${routePath(route)}`;

const isAcme = (site) => plain(site.certificate) && Object.hasOwn(site.certificate, 'acme');
export const hostsKey = (site) => JSON.stringify([...site.hosts].sort());

/**
 * How many sites of `after` need a certificate that is not issued yet: those with ACME whose set of hosts no site with
 * ACME of `before` has. A certificate is kept under the set of the hosts of its site, so a site that is new, a change of
 * its hosts and a site that used files before all need one, and a new order of the hosts or a new name does not.
 */
export function sitesToIssue(before, after) {
  const issued = new Set(before.sites.filter(isAcme).map(hostsKey));
  return after.sites.filter((site) => isAcme(site) && !issued.has(hostsKey(site))).length;
}

/** The host policies of a version, which may leave them out. */
const hostPoliciesOf = (version) => (Array.isArray(version.host_policies) ? version.host_policies : []);

/**
 * The names of the host policies of `after` that a change of the global `kind` (`access` or `rate_limit`) from
 * `before` to `after` does not reach, for each holds a `kind` of its own (`{}` too); none when the global one is the
 * same in both. `changes` says that the global one of `after` changes whatever it holds: it is not in its form.
 */
export function notReached(before, after, kind, changes = false) {
  if (!changes && same(before[kind], after[kind])) return [];
  return hostPoliciesOf(after)
    .filter((policy) => Object.hasOwn(policy, kind))
    .map((policy) => String(policy.name));
}

/** A group without its engine, which is told on its own (see `engineChanges`). */
function withoutEngine(group) {
  const rest = { ...group };
  delete rest.engine;
  return rest;
}

/**
 * The groups of both versions whose engine is written differently: `engine` when the engine that inspects the group
 * changes (the one it names, else `name`, the default engine), and `engine_key` when only the writing changes, for the
 * default engine, or the same name, written in one and not in the other: that changes what the group does when the
 * default engine is changed later. With no default engine known (`name` is null) every writing that changes is told as
 * a change of the engine.
 */
function engineChanges(before, after, name, out) {
  const engineOf = (group) => (typeof group.engine === 'string' ? group.engine : name);
  for (const [key, group] of Object.entries(before.upstreams)) {
    if (!Object.hasOwn(after.upstreams, key) || group.engine === after.upstreams[key].engine) continue;
    const [was, now] = [engineOf(group), engineOf(after.upstreams[key])];
    out.push({ area: was !== null && was === now ? 'engine_key' : 'engine', action: 'change', label: key });
  }
}

/**
 * The lines of what changes from the version `before` to the version `after`: `{ area, action, label }` with `area`
 * one of `upstream`, `engine`, `engine_key`, `default`, `access`, `rate_limit`, `host_policy`, `site` and `route`, and
 * `action` one of `add`, `remove` and `change`. Groups, host policies and sites are matched by their names and routes
 * by their hosts and paths or regular expressions (a path and a regular expression of the same text are two routes),
 * so a renamed one is one taken away and one added. The engine of a group is not part of the line of the group; `name`
 * is the default engine (null when it is not known).
 */
export function changesBetween(before, after, name = null) {
  const out = [];
  const groups = (version) => new Map(Object.entries(version.upstreams).map(([key, group]) => [key, withoutEngine(group)]));
  changed('upstream', groups(before), groups(after), (key) => key, out);
  engineChanges(before, after, name, out);
  if (before.default_upstream !== after.default_upstream) out.push({ area: 'default', action: 'change', label: '' });
  single('access', before.access, after.access, out);
  single('rate_limit', before.rate_limit, after.rate_limit, out);
  const policies = (version) => new Map(hostPoliciesOf(version).map((policy) => [String(policy.name), policy]));
  changed('host_policy', policies(before), policies(after), (key) => key, out);
  const sites = (version) => new Map(version.sites.map((site) => [String(site.name), site]));
  changed('site', sites(before), sites(after), (key) => key, out);
  const routes = (version) => new Map(version.routes.map((route) => [routeKey(route), route]));
  changed('route', routes(before), routes(after), (key, route) => routeLabel(route), out);
  return out;
}
