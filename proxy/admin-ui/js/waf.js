// The screens of the WAF. This file has the status: the state of the proxy, the rule generation that the rules store
// chooses and the one that the proxy serves (with a warning when they differ), and the generation that a rollback
// would choose. The other screens are in `generations.js` (the generations, the history and the rollback),
// `import.js` and `records.js` (the records and the audit log), and `screens` puts them in the order of the menu. A
// screen is `{ id, title, least, mount }`; `mount(ctx, root)` draws into `root` and gives back a function that undoes
// what it set up. Nothing runs when the module is loaded.

import { badge, el, mount, notice } from './dom.js';
import { screens as generationScreens } from './generations.js';
import { language, t } from './i18n.js';
import { screens as importScreens } from './import.js';
import { generationState } from './parts.js';
import { screens as recordScreens } from './records.js';

export { generationState };

// The tone and the words of each phase of the proxy, and the words of each mode. A value that is not here is shown as
// the API gave it.
const PHASES = {
  starting: ['warn', () => t('phase.starting')],
  ready: ['ok', () => t('phase.ready')],
  stopping: ['warn', () => t('phase.stopping')],
  stopped: ['bad', () => t('phase.stopped')],
  failed: ['bad', () => t('phase.failed')],
};
const MODES = {
  block: () => t('mode.block'),
  detect: () => t('mode.detect'),
};

function row(label, value) {
  return [el('dt', {}, label), el('dd', {}, value)];
}

function fingerprint(hex) {
  return typeof hex === 'string' ? el('code', { class: 'fp' }, hex) : el('span', { class: 'muted' }, t('status.none'));
}

function proxyCard(data) {
  const proxy = data.proxy;
  let content;
  if (proxy === null || typeof proxy !== 'object') {
    content =
      data.reachable === false ? notice('bad', t('status.unreachable')) : notice('warn', t('status.busy'));
  } else {
    const [tone, words] = Object.hasOwn(PHASES, proxy.phase) ? PHASES[proxy.phase] : ['muted', () => String(proxy.phase)];
    const mode = Object.hasOwn(MODES, proxy.mode) ? MODES[proxy.mode]() : String(proxy.mode);
    content = el(
      'dl',
      { class: 'kv' },
      row(t('status.state'), badge(tone, words())),
      row(t('status.mode'), badge('muted', mode)),
      row(t('status.switching'), proxy.switching ? badge('warn', t('status.switching_on')) : t('status.switching_off')),
    );
  }
  return el('section', { class: 'card' }, el('h2', {}, t('status.proxy')), content);
}

function generationsCard(data) {
  const state = generationState(data);
  const serving = data.proxy?.generation;
  let verdict = null;
  if (state === 'same') verdict = notice('ok', t('status.same'));
  if (state === 'differ') verdict = notice('warn', t('status.differ'));
  if (state === 'switching') verdict = notice('info', t('status.differ_switching'));
  return el(
    'section',
    { class: 'card' },
    el('h2', {}, t('status.generations')),
    el(
      'dl',
      { class: 'kv' },
      row(t('status.chosen'), fingerprint(data.current)),
      row(
        t('status.serving'),
        typeof serving === 'string' ? fingerprint(serving) : el('span', { class: 'muted' }, t('status.unknown')),
      ),
    ),
    verdict,
  );
}

function rollbackCard(data) {
  const target = data.rollback_to;
  const content =
    typeof target === 'string'
      ? [el('p', {}, fingerprint(target)), el('p', { class: 'muted small' }, t('status.rollback_note'))]
      : el('p', { class: 'muted' }, t('status.rollback_none'));
  return el('section', { class: 'card' }, el('h2', {}, t('status.rollback')), content);
}

function clock(at) {
  return new Intl.DateTimeFormat(language(), { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(at);
}

function mountStatus(ctx, root) {
  const reload = el('button', { type: 'button', class: 'btn', on: { click: () => ctx.refreshStatus() } }, t('status.reload'));
  const stamp = el('p', { class: 'muted small' });
  const body = el('div', { class: 'stack' });
  mount(root, el('div', { class: 'page-head' }, el('h1', {}, t('status.title')), reload), stamp, body);

  const draw = (status) => {
    reload.disabled = status.busy;
    reload.setAttribute('aria-busy', String(status.busy));
    mount(stamp, status.at === null ? '' : t('status.read_at', { time: clock(status.at) }));
    if (status.data === null) {
      mount(body, status.error === null ? notice('info', t('status.loading')) : notice('bad', t('status.failed'), ' ', ctx.describe(status.error)));
      return;
    }
    mount(
      body,
      status.error === null ? null : notice('bad', t('status.failed'), ' ', ctx.describe(status.error)),
      proxyCard(status.data),
      generationsCard(status.data),
      rollbackCard(status.data),
    );
  };
  const stop = ctx.onStatus(draw);
  draw(ctx.status());
  return stop;
}

const statusScreen = { id: 'status', title: () => t('nav.status'), least: 'viewer', mount: mountStatus };

// The order of the menu.
const ORDER = ['status', 'generations', 'import', 'history', 'records', 'audit'];
const ALL = [statusScreen, ...generationScreens, ...importScreens, ...recordScreens];

export const screens = ORDER.map((id) => ALL.find((screen) => screen.id === id));
