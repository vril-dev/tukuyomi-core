// The start of the page: the language, the theme and the way times are written, the session, the gates and the shell
// with its menu, its bar and its screens.
//
// A user is in one of these places, and only that place is drawn (see `gateOf`): the sign-in, the code of the second
// factor, the change of the password that must be changed, the setup of the second factor that must be set up, or the
// shell with its screens. The screens are not started, and the API is not asked for anything else, until the gate is
// open. The CSRF token lives in the `Api` object in memory; the only things kept in the browser are the language, the
// theme and the way times are written. A change of the language or of the way times are written works the words out
// again where they stand (see `retranslate`) and draws nothing again, so that what was typed or chosen stays. The
// address of a screen is the hash of the page: `#/<screen>`, `#/<screen>/<id>` and `#/<screen>?<key>=<value>`; a value
// in it is checked before it is used. Nothing runs when the module is loaded, except the start of the page when there
// is one.

import { screens as accountScreens, forgetHeld, mfaSetup, passwordForm } from './account/account.js';
import { Api, ApiError, gateOf } from './api.js';
import { badge, button, el, mount, notice, retranslate } from './dom.js';
import { LANGUAGES, language, lazy, pickLanguage, sentence, setLanguage, t, w } from './i18n.js';
import { forgetEnded } from './waf/import.js';
import { forgetDraft } from './managed/edit/draft.js';
import { screens as managedScreens } from './managed/managed.js';
import { Field, checkFields, clock, emptyField, hashOf, keepFocus, textInput } from './parts.js';
import { refilter } from './table.js';
import { screens as userScreens } from './account/users.js';
import { generationState, screens as wafScreens } from './waf/waf.js';

const KEYS = { language: 'tukuyomi_admin_language', theme: 'tukuyomi_admin_theme', time: 'tukuyomi_admin_time' };
const THEMES = ['auto', 'light', 'dark'];
const THEME_WORDS = { auto: () => t('theme.auto'), light: () => t('theme.light'), dark: () => t('theme.dark') };
const ROLES = ['viewer', 'operator', 'owner'];
/** How long the server keeps a session that waits for the code of the second factor. */
const CODE_WAIT_MS = 5 * 60 * 1000;

/**
 * The menu: groups of screens, in the order they are shown. The group of the overview has no name. A group that is
 * still to come is added here, with its screens, when the screens exist.
 */
const GROUPS = [
  { label: null, screens: ['overview'] },
  { label: w('nav.group.waf'), screens: ['generations', 'import', 'history'] },
  { label: w('nav.group.records'), screens: ['records', 'audit'] },
  { label: w('nav.group.forward'), screens: ['upstreams'] },
  { label: w('nav.group.policy'), screens: ['policy'] },
  { label: w('nav.group.managed'), screens: ['managed', 'managed-history', 'config'] },
  { label: w('nav.group.admin'), screens: ['account', 'users'] },
];
const ALL = [...wafScreens, ...managedScreens, ...accountScreens, ...userScreens];
/** The screens in the order of the menu. */
const screens = GROUPS.flatMap((group) => group.screens.map((id) => ALL.find((screen) => screen.id === id)));

function recall(key) {
  try {
    return globalThis.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function remember(key, value) {
  try {
    if (value === null) globalThis.localStorage.removeItem(key);
    else globalThis.localStorage.setItem(key, value);
  } catch {
    // The storage is blocked: the choice lasts until the page is closed.
  }
}

// ---- the address ----

/**
 * What a hash names. `known` says, for each screen, how to check the value after its name (`id`: a function) and the
 * keys after `?` (`query`: a function for each key that is allowed). Gives `{ screen, id, query, invalid }`: `screen`
 * is null when the hash names none of ours; `id` and `query` hold the values that passed; `invalid` lists what was
 * dropped (`id`, `path` for a part too many, `key` for a key that is not known, or the name of a known key), so that
 * the page can say that something was. A name that came from the address is never kept in it.
 */
export function parseRoute(hash, known) {
  const text = String(hash).replace(/^#\/?/, '');
  const mark = text.indexOf('?');
  const [name, id, ...rest] = (mark < 0 ? text : text.slice(0, mark)).split('/');
  if (!Object.hasOwn(known, name)) return { screen: null, id: null, query: {}, invalid: [] };
  const spec = known[name];
  const invalid = [];
  let value = null;
  if (id !== undefined && id !== '') {
    let decoded = null;
    try {
      decoded = decodeURIComponent(id);
    } catch {
      decoded = null;
    }
    if (decoded !== null && typeof spec.id === 'function' && spec.id(decoded)) value = decoded;
    else invalid.push('id');
  }
  if (rest.length > 0) invalid.push('path');
  const query = {};
  for (const [key, entry] of new URLSearchParams(mark < 0 ? '' : text.slice(mark + 1))) {
    const check = spec.query !== undefined && Object.hasOwn(spec.query, key) ? spec.query[key] : null;
    // The name of a key that the screen does not know is not kept: it came from the address, and it is not shown.
    if (check === null) invalid.push('key');
    else if (Object.hasOwn(query, key)) invalid.push(key);
    else if (entry !== '') {
      if (check(entry)) query[key] = entry;
      else invalid.push(key);
    }
  }
  return { screen: name, id: value, query, invalid };
}

/**
 * The words for a failed call. A change whose answer never came has an unknown result; a read just failed. An answer
 * with no sentence of its own (for example the empty 403 or 502 of the proxy in front) adds the number of its request,
 * which finds its record on the records screen.
 */
export function describe(error, { change = false } = {}) {
  if (error instanceof ApiError) {
    if (error.sentence !== '') return sentence(error.sentence);
    const words = error.kind === 'unknown' ? (change || error.status !== 0 ? t('error.unknown_result') : t('error.network')) : t('error.generic');
    return error.request === '' ? words : `${words} ${t('error.request', { id: error.request })}`;
  }
  return t('error.generic');
}

class App {
  constructor(root) {
    this.root = root;
    this.api = new Api();
    this.api.onSessionLost = () => this.showLogin(w('login.ended'));
    this.user = null;
    this.status = { data: null, error: null, at: null, busy: false };
    this.listeners = new Set();
    /** Functions that undo what the view on the screen set up. */
    this.teardown = [];
    /** Counts the views: an answer that comes after the view it was asked for has gone is dropped. */
    this.epoch = 0;
    this.codeBy = 0;
    this.title = lazy(() => t('app.name'));
    const saved = recall(KEYS.theme);
    this.theme = THEMES.includes(saved) ? saved : 'auto';
    clock.utc = recall(KEYS.time) === 'utc';
  }

  // ---- what every view shares ----

  leave() {
    this.epoch += 1;
    for (const undo of this.teardown.splice(0)) undo();
    this.listeners.clear();
  }

  live(epoch) {
    return epoch === this.epoch;
  }

  applyTheme() {
    const root = globalThis.document.documentElement;
    if (this.theme === 'auto') delete root.dataset.theme;
    else root.dataset.theme = this.theme;
  }

  setTitle(words) {
    this.title = words;
    globalThis.document.title = String(words);
  }

  /** The words are worked out again for the language, and nothing is drawn again. */
  chooseLanguage(code) {
    setLanguage(code);
    remember(KEYS.language, code);
    globalThis.document.documentElement.lang = code;
    retranslate();
    refilter();
    globalThis.document.title = String(this.title);
  }

  cycleTheme() {
    this.theme = THEMES[(THEMES.indexOf(this.theme) + 1) % THEMES.length];
    remember(KEYS.theme, this.theme === 'auto' ? null : this.theme);
    this.applyTheme();
    retranslate();
  }

  toggleTime() {
    clock.utc = !clock.utc;
    remember(KEYS.time, clock.utc ? 'utc' : null);
    retranslate();
    refilter();
  }

  /** The language choice, the theme button and the button for the way times are written. */
  tools() {
    const select = el(
      'select',
      { class: 'tc-select tc-select--auto', 'aria-label': w('bar.language'), on: { change: () => this.chooseLanguage(select.value) } },
      LANGUAGES.map((code) => el('option', { value: code, selected: code === language() }, code === 'ja' ? '日本語' : 'English')),
    );
    const nextTheme = () => THEMES[(THEMES.indexOf(this.theme) + 1) % THEMES.length];
    const theme = button('quiet small', lazy(() => `${t('theme.label')}: ${THEME_WORDS[this.theme]()}`), () => this.cycleTheme(), {
      'aria-label': lazy(() => t('theme.change', { now: THEME_WORDS[this.theme](), next: THEME_WORDS[nextTheme()]() })),
    });
    const timeWords = () => (clock.utc ? t('time.utc') : t('time.local'));
    const time = button('quiet small', lazy(() => `${t('time.label')}: ${timeWords()}`), () => this.toggleTime(), {
      'aria-label': lazy(() => t('time.change', { now: timeWords() })),
    });
    return el('div', { class: 'tc-bar__tools' }, select, theme, time);
  }

  /**
   * Runs `task` with the button held down and marked busy, so that a second click does nothing. `busy` are the words it
   * shows meanwhile. A button that is held down cannot take the focus, so a dialog that the task opened and closed
   * could not give it back: when the task ends with the focus nowhere, it goes back to the button.
   */
  async guarded(control, task, busy = null) {
    const saved = busy === null ? null : [...control.childNodes];
    control.disabled = true;
    control.setAttribute('aria-busy', 'true');
    if (busy !== null) mount(control, busy);
    try {
      await task();
    } finally {
      if (control.isConnected) {
        control.disabled = false;
        control.removeAttribute('aria-busy');
        if (saved !== null) control.replaceChildren(...saved);
        keepFocus(control);
      }
    }
  }

  /**
   * Ends the session and goes to the sign-in. The page leaves only when the server said that the session is ended, or
   * answered 401 (the session was gone already, and `onSessionLost` has taken the page to the sign-in). Any other end
   * is told in `messages`, and the page stays where it is, signed in.
   */
  async signOut(messages) {
    const epoch = this.epoch;
    try {
      await this.api.logout();
    } catch (error) {
      if (error instanceof ApiError && error.kind === 'session') return;
      if (this.live(epoch)) mount(messages, notice('bad', w('logout.failed')));
      return;
    }
    this.showLogin();
  }

  /** A button that signs out; a failure is told in `messages`. */
  signOutButton(label, kinds, messages) {
    const out = button(kinds, label, () => this.guarded(out, () => this.signOut(messages)));
    return out;
  }

  /** The page of a gate: a panel in the middle of the screen. */
  gatePage(title, ...children) {
    this.root.className = 'tc-gate';
    this.setTitle(lazy(() => `${title} - ${t('app.name')}`));
    mount(
      this.root,
      el('div', { class: 'tc-gate__top' }, this.tools()),
      el(
        'main',
        { class: 'tc-panel tc-gate__card', id: 'main' },
        el('span', { class: 'tc-gate__brand' }, w('app.name')),
        el('h1', { tabindex: '-1' }, title),
        ...children,
      ),
    );
  }

  // ---- the start, and the answer that says which gate comes next ----

  async boot() {
    this.leave();
    const epoch = this.epoch;
    this.root.className = 'tc-gate';
    mount(this.root, el('p', { class: 'tc-muted', role: 'status' }, w('app.loading')));
    let answer;
    try {
      answer = await this.api.call('GET', '/api/session', undefined, { auth: false });
    } catch (error) {
      if (!this.live(epoch)) return;
      if (error instanceof ApiError && error.status === 401) this.showLogin();
      else if (error instanceof ApiError && error.status === 403 && error.sentence === 'second factor required') {
        // A session that waits for its code cannot be taken up again: the CSRF token was only in the page.
        this.showLogin(w('login.step_lost'));
      } else this.showFailure(error);
      return;
    }
    this.enter(answer);
  }

  showFailure(error) {
    this.leave();
    this.gatePage(w('app.failed'), notice('bad', this.describing(error)), button('primary', w('app.retry'), () => this.boot()));
  }

  /** Goes to the place that the answer of a sign-in or of the session says. */
  enter(answer) {
    const gate = gateOf(answer);
    if (gate === 'login' || typeof answer.name !== 'string' || !ROLES.includes(answer.role)) {
      this.showLogin(gate === 'login' ? w('error.generic') : undefined);
      return;
    }
    this.user = { name: answer.name, role: answer.role };
    if (gate === 'mfa') {
      this.codeBy = Date.now() + CODE_WAIT_MS;
      this.showCode(false);
    } else if (gate === 'password') this.showPassword();
    else if (gate === 'setup') this.showSetup();
    else this.showShell(true);
  }

  describing(error, options) {
    return lazy(() => describe(error, options));
  }

  // ---- the gates ----

  showLogin(why) {
    this.leave();
    forgetHeld();
    forgetEnded();
    const draftDropped = forgetDraft();
    this.user = null;
    this.api.csrf = null;
    this.status = { data: null, error: null, at: null, busy: false };
    const epoch = this.epoch;
    const messages = el('div', { class: 'tc-stack', 'aria-live': 'polite' }, why ? notice('info', why) : null, draftDropped ? notice('warn', w('login.draft_dropped')) : null);
    const name = new Field(w('login.name'), textInput({ name: 'username', autocomplete: 'username', maxlength: '32', autocapitalize: 'none', spellcheck: 'false' }), { required: true });
    const password = new Field(w('login.password'), textInput({ type: 'password', name: 'password', autocomplete: 'current-password', maxlength: '128' }), { required: true });
    const submit = button('primary', w('login.submit'), null, { type: 'submit' });
    const form = el(
      'form',
      {
        class: 'tc-form',
        novalidate: true,
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            const typed = { name: name.control.value.trim(), password: password.control.value };
            if (!checkFields([[name, typed.name === '' ? emptyField() : null], [password, typed.password === '' ? emptyField() : null]])) return;
            password.control.value = '';
            await this.guarded(
              submit,
              async () => {
                try {
                  this.enter(await this.api.call('POST', '/api/login', typed, { auth: false }));
                } catch (error) {
                  if (!this.live(epoch)) return;
                  mount(messages, notice('bad', this.describing(error)));
                  password.control.focus();
                }
              },
              w('login.busy'),
            );
          },
        },
      },
      name.node,
      password.node,
      submit,
    );
    this.gatePage(w('login.title'), messages, form);
    name.control.focus();
  }

  showCode(recovery) {
    this.leave();
    const epoch = this.epoch;
    const left = this.codeBy - Date.now();
    if (left <= 0) {
      this.showLogin(w('login.step_expired'));
      return;
    }
    const timer = setTimeout(() => this.showLogin(w('login.step_expired')), left);
    this.teardown.push(() => clearTimeout(timer));
    const messages = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    const code = new Field(
      recovery ? w('mfa.recovery') : w('mfa.code'),
      textInput({ name: 'code', autocomplete: 'one-time-code', autocapitalize: 'none', spellcheck: 'false', maxlength: recovery ? '64' : '8', inputmode: recovery ? 'text' : 'numeric' }),
      { required: true },
    );
    const submit = button('primary', w('mfa.submit'), null, { type: 'submit' });
    const form = el(
      'form',
      {
        class: 'tc-form',
        novalidate: true,
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            // The server takes a recovery code only in capital letters (A to Z and 2 to 7, as it made them).
            const spaced = code.control.value.replace(/\s+/g, '');
            const typed = recovery ? spaced.replace(/[a-z]/g, (letter) => letter.toUpperCase()) : spaced;
            if (!checkFields([[code, typed === '' ? emptyField() : null]])) return;
            code.control.value = '';
            await this.guarded(
              submit,
              async () => {
                try {
                  this.enter(await this.api.call('POST', '/api/login/mfa', recovery ? { recovery: typed } : { code: typed }, { auth: false }));
                } catch (error) {
                  if (!this.live(epoch)) return;
                  if (error instanceof ApiError && error.status === 401 && error.sentence !== 'invalid credentials') {
                    // The session that waited for the code is gone.
                    this.showLogin(w('login.step_expired'));
                    return;
                  }
                  const wrong = error instanceof ApiError && error.status === 401;
                  mount(messages, notice('bad', wrong ? w('mfa.invalid') : this.describing(error)));
                  code.control.focus();
                }
              },
              w('mfa.busy'),
            );
          },
        },
      },
      code.node,
      submit,
    );
    const other = button('quiet', recovery ? w('mfa.use_code') : w('mfa.use_recovery'), () => this.showCode(!recovery));
    const back = this.signOutButton(w('mfa.back'), 'quiet', messages);
    this.gatePage(w('mfa.title'), el('p', {}, recovery ? w('mfa.intro_recovery') : w('mfa.intro')), messages, form, el('div', { class: 'tc-actions' }, other, back));
    code.control.focus();
  }

  showPassword() {
    this.leave();
    const messages = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' });
    const form = passwordForm(this.formContext(), {
      username: this.user.name,
      messages,
      onChanged: () => this.afterRenewal(w('login.changed')),
    });
    const out = this.signOutButton(w('bar.logout'), 'quiet', messages);
    this.gatePage(w('password.title'), el('p', {}, w('password.intro')), messages, form.node, el('div', { class: 'tc-actions' }, out));
    form.focus();
  }

  /**
   * After a change that gave the session a new CSRF token (the password, the second factor): reads the session to find
   * the next gate. A session that the API could not renew is gone, and a session that cannot be read is told as `lost`.
   */
  async afterRenewal(lost) {
    try {
      if (this.api.csrf === null) this.showLogin(w('login.ended'));
      else this.enter(await this.api.call('GET', '/api/session'));
    } catch (error) {
      // A 401 has taken the page to the sign-in already. Any other failure must not read as a failed change.
      if (!(error instanceof ApiError && error.kind === 'session')) this.showLogin(lost);
    }
  }

  showSetup() {
    this.leave();
    const messages = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' });
    const setup = mfaSetup(this.formContext(), { onDone: () => this.afterRenewal(w('login.mfa_changed')) });
    this.teardown.push(() => setup.stop());
    const out = this.signOutButton(w('bar.logout'), 'quiet', messages);
    this.gatePage(w('setup.title'), notice('info', w('setup.body')), messages, setup.node, el('div', { class: 'tc-actions' }, out));
  }

  // ---- the shell and its screens ----

  /** The screens that the role of the user may open. */
  allowed() {
    return screens.filter((screen) => ROLES.indexOf(this.user.role) >= ROLES.indexOf(screen.least));
  }

  async refreshStatus() {
    if (this.status.busy) return;
    // The status belongs to the session, not to the view: a read goes on when the user goes to another screen, and the
    // view that is shown when it ends gets the answer. Only a sign-in puts a new status in its place (`showLogin`), and
    // then the answer for the old session is dropped, with its busy state gone.
    const asked = { ...this.status, busy: true };
    this.status = asked;
    this.publish();
    let next;
    try {
      next = { data: await this.api.call('GET', '/api/status'), error: null, at: new Date(), busy: false };
    } catch (error) {
      next = { ...asked, error, busy: false };
    }
    if (this.status !== asked) return;
    this.status = next;
    this.publish();
  }

  publish() {
    for (const listener of this.listeners) listener(this.status);
  }

  /** What the forms that a gate and a screen share need of the page. */
  formContext() {
    return {
      api: this.api,
      describe: (error, options) => this.describing(error, options),
      guarded: (control, task, busy) => this.guarded(control, task, busy),
    };
  }

  context() {
    return {
      ...this.formContext(),
      user: this.user,
      status: () => this.status,
      refreshStatus: () => this.refreshStatus(),
      onStatus: (listener) => {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
      },
      toLogin: (why) => this.showLogin(why),
      /** Goes to a hash: a new place in the history, so that the back button comes back to where the user was. */
      navigate: (hash) => {
        globalThis.location.hash = hash;
      },
    };
  }

  /** The menu: the groups, with a link for each screen that the role allows. */
  menu(available, links) {
    return GROUPS.map((group) => {
      const mine = group.screens.map((id) => available.find((screen) => screen.id === id)).filter((screen) => screen !== undefined);
      if (mine.length === 0) return null;
      return el(
        'div',
        { class: 'tc-nav__group' },
        group.label === null ? null : el('span', { class: 'tc-nav__label' }, group.label),
        mine.map((screen) => {
          const link = el('a', { href: hashOf(screen.id), 'data-screen': screen.id }, screen.title);
          links.push(link);
          return link;
        }),
      );
    });
  }

  showShell(reload) {
    this.leave();
    const available = this.allowed();
    const known = Object.fromEntries(available.map((screen) => [screen.id, screen.route ?? {}]));
    const main = el('main', { class: 'tc-main', id: 'main', tabindex: '-1' });
    const links = [];
    const nav = el('nav', { class: 'tc-nav', id: 'menu', 'aria-label': w('nav.menu') }, el('span', { class: 'tc-nav__brand' }, w('app.name')), this.menu(available, links));
    const warning = el('a', { class: 'tc-badge tc-badge--warn', href: hashOf('overview') }, w('bar.warning'));
    warning.hidden = true;
    const alerts = el('div', { class: 'tc-alerts tc-stack', 'aria-live': 'polite' });
    const place = el('p', { class: 'tc-bar__place' });
    const toggle = el('button', { type: 'button', class: 'tc-btn tc-btn--small tc-bar__menu', 'aria-expanded': 'false', 'aria-controls': 'menu' }, w('nav.menu'));
    const setOpen = (open) => {
      nav.className = open ? 'tc-nav tc-nav--open' : 'tc-nav';
      toggle.setAttribute('aria-expanded', String(open));
    };
    toggle.addEventListener('click', () => setOpen(toggle.getAttribute('aria-expanded') !== 'true'));
    // Escape closes the open menu wherever the focus is, but not while a dialog is open: Escape closes the dialog.
    const onKey = (event) => {
      if (event.key !== 'Escape' || toggle.getAttribute('aria-expanded') !== 'true') return;
      if (event.target?.closest?.('dialog') || globalThis.document.querySelector('dialog[open]') !== null) return;
      setOpen(false);
      toggle.focus();
    };
    globalThis.document.addEventListener('keydown', onKey);
    this.teardown.push(() => globalThis.document.removeEventListener('keydown', onKey));
    const bar = el(
      'header',
      { class: 'tc-bar' },
      toggle,
      place,
      el('span', { class: 'tc-bar__spacer' }),
      warning,
      el('span', { class: 'tc-bar__user' }, el('span', { class: 'tc-bar__name', title: this.user.name }, this.user.name), badge('muted', this.user.role)),
      this.tools(),
      el('span', { class: 'tc-bar__out' }, this.signOutButton(w('bar.logout'), 'quiet', alerts)),
    );
    const skip = button('', w('app.skip'), () => main.focus(), { class: 'tc-btn tc-skip' });
    this.root.className = 'tc-shell';
    // The bar comes before the menu, so that the keyboard reaches the bar, then the menu, then the screen.
    mount(this.root, skip, el('div', { class: 'tc-top' }, bar, nav), el('div', { class: 'tc-content' }, alerts, main));

    const show = (status) => {
      warning.hidden = generationState(status.data) !== 'differ';
    };
    this.listeners.add(show);
    show(this.status);

    /** The address named something of a screen that this user may not see: the screen stays, without it, and the page says so. */
    const dropId = (id) => {
      globalThis.history.replaceState(null, '', hashOf(id));
      mount(alerts, notice('warn', w('route.dropped')));
    };

    let current = null;
    const go = (first) => {
      const parsed = parseRoute(globalThis.location.hash, known);
      const id = parsed.screen ?? available[0].id;
      const screen = available.find((candidate) => candidate.id === id);
      const canonical = hashOf(id, { id: parsed.id, query: parsed.query });
      if (globalThis.location.hash !== canonical) globalThis.history.replaceState(null, '', canonical);
      mount(alerts, parsed.invalid.length === 0 ? null : notice('warn', w('route.dropped')));
      const route = { id: parsed.id, query: parsed.query };
      if (current !== null && current.id === id && typeof current.controller.show === 'function') {
        current.controller.show(route);
      } else {
        if (current !== null) current.controller.stop();
        current = { id, controller: screen.mount({ ...this.context(), dropId: () => dropId(id) }, main, route) ?? { stop() {} } };
        const group = GROUPS.find((item) => item.screens.includes(id));
        mount(place, group?.label ? [el('span', { class: 'tc-muted' }, group.label), el('span', { class: 'tc-muted', 'aria-hidden': 'true' }, '/')] : null, el('strong', {}, screen.title));
        if (!first) main.querySelector('h1')?.focus();
      }
      for (const link of links) {
        if (link.getAttribute('data-screen') === id) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      }
      setOpen(false);
      this.setTitle(lazy(() => `${screen.title.text()} - ${t('app.name')}`));
    };
    const onHash = () => go(false);
    globalThis.addEventListener('hashchange', onHash);
    this.teardown.push(() => {
      globalThis.removeEventListener('hashchange', onHash);
      if (current !== null) current.controller.stop();
    });
    go(true);
    if (reload) this.refreshStatus();
  }
}

/** Starts the page in `root`. */
export function start(root) {
  const app = new App(root);
  setLanguage(pickLanguage(recall(KEYS.language), globalThis.navigator.languages ?? [globalThis.navigator.language]));
  globalThis.document.documentElement.lang = language();
  app.applyTheme();
  app.boot();
  return app;
}

if (globalThis.document !== undefined) start(globalThis.document.getElementById('app'));
