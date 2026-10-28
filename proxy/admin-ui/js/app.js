// The start of the page: the language and the theme, the session, the gates and the screens.
//
// A user is in one of these places, and only that place is drawn (see `gateOf`): the sign-in, the code of the second
// factor, the change of the password that must be changed, the setup of the second factor that must be set up, or the
// shell with its screens. The screens are not started, and the API is not asked for anything else, until the gate is
// open. The CSRF token lives in the `Api` object in memory; the only things kept in the browser are the language and
// the theme. Nothing runs when the module is loaded, except the start of the page when there is one.

import { Api, ApiError, gateOf } from './api.js';
import { badge, el, mount, notice, setText } from './dom.js';
import { LANGUAGES, language, pickLanguage, sentence, setLanguage, t } from './i18n.js';
import { generationState, screens } from './waf.js';

const KEYS = { language: 'tukuyomi_admin_language', theme: 'tukuyomi_admin_theme' };
const THEMES = ['auto', 'light', 'dark'];
const THEME_WORDS = { auto: () => t('theme.auto'), light: () => t('theme.light'), dark: () => t('theme.dark') };
const ROLES = ['viewer', 'operator', 'owner'];
/** How long the server keeps a session that waits for the code of the second factor. */
const CODE_WAIT_MS = 5 * 60 * 1000;
const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;

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

/** The screen that a hash (`#/status`) names, or the first of `ids` when it names none. */
export function routeOf(hash, ids) {
  const name = hash.replace(/^#\/?/, '').split(/[/?]/)[0];
  return ids.includes(name) ? name : ids[0];
}

/** The words for a failed call. A change whose answer never came has an unknown result; a read just failed. */
export function describe(error, { change = false } = {}) {
  if (error instanceof ApiError) {
    if (error.sentence !== '') return sentence(error.sentence);
    if (error.kind === 'unknown') return change || error.status !== 0 ? t('error.unknown_result') : t('error.network');
  }
  return t('error.generic');
}

/** The number of bytes of `text` in UTF-8, which is what the server counts in a password. */
function bytesOf(text) {
  return new TextEncoder().encode(text).length;
}

class App {
  constructor(root) {
    this.root = root;
    this.api = new Api();
    this.api.onSessionLost = () => this.showLogin(() => t('login.ended'));
    this.user = null;
    this.status = { data: null, error: null, at: null, busy: false };
    this.listeners = new Set();
    /** Functions that undo what the view on the screen set up. */
    this.teardown = [];
    /** Counts the views: an answer that comes after the view it was asked for has gone is dropped. */
    this.epoch = 0;
    this.redraw = () => this.boot();
    this.codeBy = 0;
    const saved = recall(KEYS.theme);
    this.theme = THEMES.includes(saved) ? saved : 'auto';
    this.fields = 0;
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

  chooseLanguage(code) {
    setLanguage(code);
    remember(KEYS.language, code);
    globalThis.document.documentElement.lang = code;
    this.redraw();
  }

  cycleTheme(button) {
    this.theme = THEMES[(THEMES.indexOf(this.theme) + 1) % THEMES.length];
    remember(KEYS.theme, this.theme === 'auto' ? null : this.theme);
    this.applyTheme();
    setText(button, this.themeWords());
  }

  themeWords() {
    return `${t('theme.label')}: ${THEME_WORDS[this.theme]()}`;
  }

  /** The language choice and the theme button. */
  tools() {
    const select = el(
      'select',
      { 'aria-label': t('bar.language'), on: { change: () => this.chooseLanguage(select.value) } },
      LANGUAGES.map((code) => el('option', { value: code, selected: code === language() }, code === 'ja' ? '日本語' : 'English')),
    );
    const theme = el('button', { type: 'button', class: 'btn', on: { click: () => this.cycleTheme(theme) } }, this.themeWords());
    return el('div', { class: 'tools' }, select, theme);
  }

  /** A labelled input: the row to place and the input itself. */
  field(label, attributes) {
    this.fields += 1;
    const id = `field-${this.fields}`;
    const input = el('input', { id, class: 'input', ...attributes });
    return { row: el('div', { class: 'field' }, el('label', { for: id }, label), input), input };
  }

  /** Runs `task` with the button held down and marked busy, so that a second click does nothing. */
  async guarded(button, task) {
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    try {
      await task();
    } finally {
      if (button.isConnected) {
        button.disabled = false;
        button.removeAttribute('aria-busy');
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
      if (this.live(epoch)) mount(messages, notice('bad', t('logout.failed')));
      return;
    }
    this.showLogin();
  }

  /** A button that signs out; a failure is told in `messages`. */
  signOutButton(label, className, messages) {
    const button = el('button', { type: 'button', class: className, on: { click: () => this.guarded(button, () => this.signOut(messages)) } }, label);
    return button;
  }

  /** The page of a gate: a card in the middle of the screen. */
  gatePage(title, ...children) {
    this.root.className = 'auth';
    globalThis.document.title = `${title} - ${t('app.name')}`;
    mount(
      this.root,
      el('div', { class: 'auth-top' }, this.tools()),
      el(
        'main',
        { class: 'auth-card card stack', id: 'main' },
        el('div', { class: 'brand' }, el('img', { src: '/ui/favicon.svg', alt: '', width: '28', height: '28' }), el('span', {}, t('app.name'))),
        el('h1', {}, title),
        ...children,
      ),
    );
  }

  // ---- the start, and the answer that says which gate comes next ----

  async boot() {
    this.leave();
    const epoch = this.epoch;
    this.redraw = () => this.boot();
    this.root.className = 'auth';
    mount(this.root, el('p', { class: 'plain', role: 'status' }, t('app.loading')));
    let answer;
    try {
      answer = await this.api.call('GET', '/api/session', undefined, { auth: false });
    } catch (error) {
      if (!this.live(epoch)) return;
      if (error instanceof ApiError && error.status === 401) this.showLogin();
      else if (error instanceof ApiError && error.status === 403 && error.sentence === 'second factor required') {
        // A session that waits for its code cannot be taken up again: the CSRF token was only in the page.
        this.showLogin(() => t('login.step_lost'));
      } else this.showFailure(error);
      return;
    }
    this.enter(answer);
  }

  showFailure(error) {
    this.leave();
    this.redraw = () => this.showFailure(error);
    this.gatePage(
      t('app.failed'),
      notice('bad', describe(error)),
      el('button', { type: 'button', class: 'btn btn-primary', on: { click: () => this.boot() } }, t('app.retry')),
    );
  }

  /** Goes to the place that the answer of a sign-in or of the session says. */
  enter(answer) {
    const gate = gateOf(answer);
    if (gate === 'login' || typeof answer.name !== 'string' || !ROLES.includes(answer.role)) {
      this.showLogin(gate === 'login' ? () => t('error.generic') : undefined);
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

  // ---- the gates ----

  showLogin(why) {
    this.leave();
    this.user = null;
    this.api.csrf = null;
    this.status = { data: null, error: null, at: null, busy: false };
    this.redraw = () => this.showLogin(why);
    const epoch = this.epoch;
    const messages = el('div', { class: 'stack', 'aria-live': 'polite' }, why ? notice('info', why()) : null);
    const name = this.field(t('login.name'), {
      type: 'text', name: 'username', autocomplete: 'username', maxlength: '32', required: true, autocapitalize: 'none', spellcheck: 'false',
    });
    const password = this.field(t('login.password'), {
      type: 'password', name: 'password', autocomplete: 'current-password', maxlength: '128', required: true,
    });
    const submit = el('button', { type: 'submit', class: 'btn btn-primary' }, t('login.submit'));
    const form = el(
      'form',
      {
        class: 'stack',
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            const typed = { name: name.input.value.trim(), password: password.input.value };
            password.input.value = '';
            await this.guarded(submit, async () => {
              try {
                this.enter(await this.api.call('POST', '/api/login', typed, { auth: false }));
              } catch (error) {
                if (!this.live(epoch)) return;
                mount(messages, notice('bad', describe(error)));
                password.input.focus();
              }
            });
          },
        },
      },
      name.row,
      password.row,
      submit,
    );
    this.gatePage(t('login.title'), messages, form);
    name.input.focus();
  }

  showCode(recovery) {
    this.leave();
    this.redraw = () => this.showCode(recovery);
    const epoch = this.epoch;
    const left = this.codeBy - Date.now();
    if (left <= 0) {
      this.showLogin(() => t('login.step_expired'));
      return;
    }
    const timer = setTimeout(() => this.showLogin(() => t('login.step_expired')), left);
    this.teardown.push(() => clearTimeout(timer));
    const messages = el('div', { class: 'stack', 'aria-live': 'polite' });
    const code = this.field(recovery ? t('mfa.recovery') : t('mfa.code'), {
      type: 'text',
      name: 'code',
      autocomplete: 'one-time-code',
      autocapitalize: 'none',
      spellcheck: 'false',
      required: true,
      maxlength: recovery ? '64' : '8',
      inputmode: recovery ? 'text' : 'numeric',
    });
    const submit = el('button', { type: 'submit', class: 'btn btn-primary' }, t('mfa.submit'));
    const form = el(
      'form',
      {
        class: 'stack',
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            // The server takes a recovery code only in capital letters (A to Z and 2 to 7, as it made them).
            const spaced = code.input.value.replace(/\s+/g, '');
            const typed = recovery ? spaced.replace(/[a-z]/g, (letter) => letter.toUpperCase()) : spaced;
            code.input.value = '';
            await this.guarded(submit, async () => {
              try {
                this.enter(await this.api.call('POST', '/api/login/mfa', recovery ? { recovery: typed } : { code: typed }, { auth: false }));
              } catch (error) {
                if (!this.live(epoch)) return;
                if (error instanceof ApiError && error.status === 401 && error.sentence !== 'invalid credentials') {
                  // The session that waited for the code is gone.
                  this.showLogin(() => t('login.step_expired'));
                  return;
                }
                const wrong = error instanceof ApiError && error.status === 401;
                mount(messages, notice('bad', wrong ? t('mfa.invalid') : describe(error)));
                code.input.focus();
              }
            });
          },
        },
      },
      code.row,
      submit,
    );
    const other = el(
      'button',
      { type: 'button', class: 'btn btn-link', on: { click: () => this.showCode(!recovery) } },
      recovery ? t('mfa.use_code') : t('mfa.use_recovery'),
    );
    const back = this.signOutButton(t('mfa.back'), 'btn btn-link', messages);
    this.gatePage(t('mfa.title'), el('p', {}, recovery ? t('mfa.intro_recovery') : t('mfa.intro')), messages, form, el('div', { class: 'actions' }, other, back));
    code.input.focus();
  }

  showPassword() {
    this.leave();
    this.redraw = () => this.showPassword();
    const epoch = this.epoch;
    const messages = el('div', { class: 'stack', 'aria-live': 'polite' });
    const attributes = { type: 'password', autocomplete: 'new-password', maxlength: '128', required: true };
    const current = this.field(t('password.current'), { ...attributes, autocomplete: 'current-password', name: 'current' });
    const next = this.field(t('password.new'), { ...attributes, name: 'new' });
    const again = this.field(t('password.confirm'), { ...attributes, name: 'again' });
    const submit = el('button', { type: 'submit', class: 'btn btn-primary' }, t('password.submit'));
    const form = el(
      'form',
      {
        class: 'stack',
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            const typed = { current: current.input.value, next: next.input.value, again: again.input.value };
            const size = bytesOf(typed.next);
            const problem =
              typed.next !== typed.again
                ? t('password.mismatch')
                : size < PASSWORD_MIN || size > PASSWORD_MAX
                  ? t('password.length')
                  : typed.next === typed.current
                    ? t('password.same')
                    : null;
            if (problem !== null) {
              mount(messages, notice('bad', problem));
              return;
            }
            await this.guarded(submit, async () => {
              try {
                await this.api.call('PUT', '/api/account/password', { current: typed.current, new: typed.next });
              } catch (error) {
                if (!this.live(epoch)) return;
                mount(messages, notice('bad', describe(error, { change: true })));
                for (const field of [current, next, again]) field.input.value = '';
                current.input.focus();
                return;
              }
              // The password is changed, and the change gives a new session; read it to find the next gate.
              try {
                if (this.api.csrf === null) this.showLogin(() => t('login.ended'));
                else this.enter(await this.api.call('GET', '/api/session'));
              } catch (error) {
                // A 401 has taken the page to the sign-in already. Any other failure must not read as a failed change.
                if (!(error instanceof ApiError && error.kind === 'session')) this.showLogin(() => t('login.changed'));
              }
            });
          },
        },
      },
      // Not shown: the name of the account, so that a password manager can tell whose password is changed.
      el('input', { type: 'text', name: 'username', autocomplete: 'username', value: this.user.name, readonly: true, hidden: true }),
      current.row,
      next.row,
      again.row,
      el('p', { class: 'muted small' }, t('password.hint')),
      submit,
    );
    const out = this.signOutButton(t('bar.logout'), 'btn btn-link', messages);
    this.gatePage(t('password.title'), el('p', {}, t('password.intro')), messages, form, el('div', { class: 'actions' }, out));
    current.input.focus();
  }

  showSetup() {
    this.leave();
    this.redraw = () => this.showSetup();
    const messages = el('div', { class: 'stack', 'aria-live': 'polite' });
    const out = this.signOutButton(t('bar.logout'), 'btn btn-primary', messages);
    this.gatePage(t('setup.title'), notice('info', t('setup.body')), messages, el('div', { class: 'actions' }, out));
  }

  // ---- the shell and its screens ----

  /** The screens that the role of the user may open. */
  allowed() {
    return screens.filter((screen) => ROLES.indexOf(this.user.role) >= ROLES.indexOf(screen.least));
  }

  async refreshStatus() {
    if (this.status.busy) return;
    // The status belongs to the session, not to the view: a read goes on when the language is switched, and the view
    // that is shown when it ends gets the answer. Only a sign-in puts a new status in its place (`showLogin`), and then
    // the answer for the old session is dropped, with its busy state gone.
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

  context() {
    return {
      api: this.api,
      user: this.user,
      status: () => this.status,
      refreshStatus: () => this.refreshStatus(),
      onStatus: (listener) => {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
      },
      describe,
    };
  }

  showShell(reload) {
    this.leave();
    this.redraw = () => this.showShell(false);
    const available = this.allowed();
    const main = el('main', { class: 'main', id: 'main', tabindex: '-1' });
    const links = available.map((screen) => el('a', { href: `#/${screen.id}`, 'data-screen': screen.id }, screen.title()));
    const warning = el('a', { class: 'chip chip-warn', href: '#/status', hidden: true }, t('bar.warning'));
    const alerts = el('div', { class: 'alerts', 'aria-live': 'polite' });
    const bar = el(
      'header',
      { class: 'bar' },
      el('div', { class: 'brand' }, el('img', { src: '/ui/favicon.svg', alt: '', width: '24', height: '24' }), el('span', {}, t('app.name'))),
      warning,
      el('span', { class: 'spacer' }),
      el('span', { class: 'who' }, el('span', {}, this.user.name), badge('muted', this.user.role)),
      this.tools(),
      this.signOutButton(t('bar.logout'), 'btn', alerts),
    );
    const skip = el('button', { type: 'button', class: 'skip', on: { click: () => main.focus() } }, t('app.skip'));
    this.root.className = 'shell';
    mount(this.root, skip, bar, alerts, el('div', { class: 'layout' }, el('nav', { class: 'nav', 'aria-label': t('nav.menu') }, links), main));

    const show = (status) => {
      warning.hidden = generationState(status.data) !== 'differ';
    };
    this.listeners.add(show);
    show(this.status);

    let stop = null;
    const route = (first) => {
      const id = routeOf(globalThis.location.hash, available.map((screen) => screen.id));
      if (globalThis.location.hash !== `#/${id}`) globalThis.history.replaceState(null, '', `#/${id}`);
      const screen = available.find((candidate) => candidate.id === id);
      if (stop !== null) stop();
      stop = screen.mount(this.context(), main) ?? null;
      for (const link of links) {
        if (link.dataset.screen === id) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      }
      globalThis.document.title = `${screen.title()} - ${t('app.name')}`;
      if (!first) main.focus({ preventScroll: true });
    };
    const onHash = () => route(false);
    globalThis.addEventListener('hashchange', onHash);
    this.teardown.push(() => {
      globalThis.removeEventListener('hashchange', onHash);
      if (stop !== null) stop();
    });
    route(true);
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
