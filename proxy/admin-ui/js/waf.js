// The screens of the WAF. This file has the overview: the numbers of the proxy since it started, its state, the rule
// generation that the rules store chooses and the one that the proxy serves (with a warning when they differ), the
// generation that a rollback would choose, and the settings file that is in force. The other screens are in
// `generations.js` (the generations, the history and the rollback), `import.js` and `records.js` (the records and the
// audit log); `app.js` puts them in the order of the menu. A screen is `{ id, title, least, mount }`; `mount(ctx, root)`
// draws into `root` and gives back `{ stop }` (and `show(route)` when the address of the screen can change in it). Nothing runs when the
// module is loaded.

import { badge, button, el, mount, notice } from './dom.js';
import { screens as generationScreens } from './generations.js';
import { formatNumber, lazy, t, w } from './i18n.js';
import { screens as importScreens } from './import.js';
import { engineBadge, fingerprintView, generationState, hashOf, isFingerprint, kv, modeName, pageHead, panel, row, setBusy, stat, timeView } from './parts.js';
import { screens as recordScreens } from './records.js';

export { generationState };

// The tone and the words of each phase of the proxy. A value that is not here is shown as the API gave it.
const PHASES = {
  starting: ['warn', () => w('phase.starting')],
  ready: ['ok', () => w('phase.ready')],
  stopping: ['warn', () => w('phase.stopping')],
  stopped: ['bad', () => w('phase.stopped')],
  failed: ['bad', () => w('phase.failed')],
};

const SECOND = 1000;

/** The time since the proxy started in the two largest units that it has: `3 days 4 hours`, `4 hours 12 minutes`, `12 minutes 8 seconds`, `35 seconds`. */
export function uptimeText(ms) {
  const total = Math.floor(ms / SECOND);
  const [days, hours, minutes, seconds] = [Math.floor(total / 86400), Math.floor((total % 86400) / 3600), Math.floor((total % 3600) / 60), total % 60];
  if (days > 0) return t('uptime.dh', { d: formatNumber(days), h: hours });
  if (hours > 0) return t('uptime.hm', { h: hours, m: minutes });
  if (minutes > 0) return t('uptime.ms', { m: minutes, s: seconds });
  return t('uptime.s', { s: seconds });
}

/** The number a field of the proxy's state holds, or null when the proxy gave none (an old proxy, or none that answered). */
export function countOf(data, key) {
  const value = data?.proxy?.[key];
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

/** The readings of the configuration file again (`{ replaced, refused }`), or null when the proxy gave none. */
function reloadsOf(data) {
  const reloads = data?.proxy?.config_reloads;
  return reloads !== null && typeof reloads === 'object' && Number.isFinite(reloads.replaced) && Number.isFinite(reloads.refused) ? reloads : null;
}

/** Whether a proxy that answered left out a number of the overview, as an older proxy does. */
function figuresLeftOut(data) {
  const counts = ['uptime_ms', 'requests', 'blocked', 'policy_refused', 'upstream_failures'];
  return counts.some((key) => countOf(data, key) === null) || reloadsOf(data) === null || !isFingerprint(data.proxy?.config);
}

/**
 * The short word for a number that is missing: not read (the proxy cannot be reached, or had no room to answer), or not
 * given (the proxy answered without it). Why is said once, in the panel of the proxy.
 */
function missingWord(data) {
  return data.proxy !== null && typeof data.proxy === 'object' ? w('overview.not_given') : w('overview.missing');
}

/** The numbers of the proxy, in one row. A number that the proxy did not give is a dash and a short word (see `missingWord`). */
function overviewStats(data) {
  const count = (key) => countOf(data, key);
  const number = (key) => {
    const value = count(key);
    return value === null ? '—' : lazy(() => formatNumber(value));
  };
  const missing = (key, sub = null) => (count(key) === null ? missingWord(data) : sub);
  const uptime = count('uptime_ms');
  const failures = count('upstream_failures');
  const reloads = reloadsOf(data);
  return el(
    'div',
    { class: 'tc-stats' },
    stat(w('overview.requests'), number('requests'), missing('requests', uptime === null ? null : lazy(() => t('overview.since', { time: uptimeText(uptime) })))),
    stat(w('overview.blocked'), number('blocked'), missing('blocked', w('overview.blocked_note'))),
    stat(w('overview.policy'), number('policy_refused'), missing('policy_refused', w('overview.policy_note'))),
    stat(
      w('overview.failures'),
      number('upstream_failures'),
      missing('upstream_failures', [failures === 0 ? badge('ok', w('overview.failures_none')) : badge('warn', w('overview.failures_some')), w('overview.failures_note')]),
    ),
    stat(
      w('overview.reloads'),
      reloads === null ? '—' : lazy(() => formatNumber(reloads.replaced)),
      reloads === null ? missingWord(data) : lazy(() => t('overview.reloads_refused', { n: formatNumber(reloads.refused) })),
    ),
  );
}

function proxyPanel(data) {
  const proxy = data.proxy;
  if (proxy === null || typeof proxy !== 'object') {
    return panel(w('status.proxy'), [], data.reachable === false ? notice('bad', w('status.unreachable')) : notice('warn', w('status.busy')));
  }
  const [tone, words] = Object.hasOwn(PHASES, proxy.phase) ? PHASES[proxy.phase] : ['muted', () => String(proxy.phase)];
  return panel(
    w('status.proxy'),
    [badge(tone, words())],
    kv(
      row(w('status.mode'), badge('muted', lazy(() => modeName(proxy.mode)))),
      row(w('status.engine'), engineBadge(proxy.engine)),
      row(w('status.switching'), proxy.switching ? badge('warn', w('status.switching_on')) : w('status.switching_off')),
    ),
    figuresLeftOut(data) ? notice('info', w('overview.reason_old')) : null,
  );
}

function generationLine(value) {
  if (!isFingerprint(value)) return typeof value === 'string' ? value : w('status.unknown');
  return el('span', { class: 'tc-actions' }, fingerprintView(value), el('a', { class: 'tc-link', href: hashOf('generations', { id: value }) }, w('overview.open')));
}

function generationsPanel(data) {
  const state = generationState(data);
  let verdict = null;
  if (state === 'same') verdict = notice('ok', w('status.same'));
  if (state === 'differ') verdict = notice('warn', w('status.differ'));
  if (state === 'switching') verdict = notice('info', w('status.differ_switching'));
  const target = data.rollback_to;
  return panel(
    w('status.generations'),
    [],
    kv(
      row(w('status.chosen'), data.current === null || data.current === undefined ? w('status.none') : generationLine(data.current)),
      row(w('status.serving'), generationLine(data.proxy?.generation ?? null)),
      row(w('status.rollback'), typeof target === 'string' ? generationLine(target) : w('status.rollback_none')),
    ),
    typeof target === 'string' ? el('p', { class: 'tc-muted tc-small' }, w('status.rollback_note')) : null,
    verdict,
  );
}

function configPanel(data) {
  const config = data.proxy?.config;
  return panel(
    w('overview.config'),
    [],
    kv(row(w('overview.config_sha'), isFingerprint(config) ? fingerprintView(config) : el('span', { class: 'tc-muted' }, '—', ' ', missingWord(data)))),
    el('p', { class: 'tc-muted tc-small' }, w('overview.config_note')),
  );
}

function mountOverview(ctx, root) {
  const reload = button('', w('status.reload'), () => ctx.refreshStatus());
  const stamp = el('p', { class: 'tc-muted tc-small' });
  const body = el('div', { class: 'tc-stack tc-stack--wide' });
  mount(root, pageHead(w('overview.title'), reload), stamp, body);

  const draw = (status) => {
    setBusy(reload, status.busy);
    reload.setAttribute('aria-busy', String(status.busy));
    mount(stamp, status.at === null ? null : [w('status.read_at'), ' ', timeView(status.at.getTime())]);
    const failed = status.error === null ? null : notice('bad', w('status.failed'), ' ', ctx.describe(status.error));
    if (status.data === null) {
      mount(body, status.error === null ? notice('info', w('status.loading')) : failed);
      return;
    }
    mount(
      body,
      failed,
      overviewStats(status.data),
      el('div', { class: 'tc-overview' }, proxyPanel(status.data), generationsPanel(status.data), configPanel(status.data)),
    );
  };
  const stop = ctx.onStatus(draw);
  draw(ctx.status());
  return { stop };
}

export const screens = [
  { id: 'overview', title: w('nav.overview'), least: 'viewer', mount: mountOverview },
  ...generationScreens,
  ...importScreens,
  ...recordScreens,
];
