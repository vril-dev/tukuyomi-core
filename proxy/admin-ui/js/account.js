// The account screen: the password, the second factor (its setup with a QR code and the recovery codes, and its
// removal) and the API tokens of the signed-in user. The password form and the setup of the second factor are also
// what the gates of the page show, so they are made here as parts that take the context of the page (`ctx`: `api`,
// `describe`, `guarded`, `redrawing`, `toLogin`).
//
// What the API shows only once (the secret of a setup, the recovery codes, the text of a new token) is kept in `held`,
// in memory, and nowhere else: never in the storage of the browser, in the address or in the history. A screen draws it,
// keeps it when the page is drawn again only because the language was switched, and gives it up, and its nodes, when it
// is left. The recovery codes that the API gives when a setup is confirmed are kept as soon as the answer comes, even
// when the screen that sent the code is gone by then, and wait for the next screen that is drawn (see `Held.confirm`);
// the end of the sign-in gives up all of it (see `forgetHeld`). A screen is `{ id, title, least, mount }`;
// `mount(ctx, root)` draws into `root` and gives back a function that undoes what it set up. Nothing runs when the
// module is loaded.

import { ApiError } from './api.js';
import { badge, el, mount, notice } from './dom.js';
import { t } from './i18n.js';
import { confirmChange, labelled, pageHead, row, table, utc } from './parts.js';
import { darkRuns, encode } from './qr.js';

export const ROLES = ['viewer', 'operator', 'owner'];
const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;
/** The name of a token: 1 to 64 printable ASCII characters, which is what the API takes. */
const TOKEN_NAME = /^[\x20-\x7e]{1,64}$/;
const DAYS = { min: 1, max: 365, start: 30 };
/** The light border around a QR code, in modules. */
const QUIET = 4;
/** The few recovery codes that make the screen warn. */
const FEW_CODES = 2;
const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';

// ---- what the forms check before they send ----

/** The roles that a user of `role` may give to a token: that role and the ones below it. */
export function rolesUpTo(role) {
  const at = ROLES.indexOf(role);
  return at < 0 ? [] : ROLES.slice(0, at + 1);
}

/** Whether `password` is 12 to 128 bytes in UTF-8, which is what the API counts. */
export function passwordFits(password) {
  const size = new TextEncoder().encode(password).length;
  return size >= PASSWORD_MIN && size <= PASSWORD_MAX;
}

/** What is wrong with a change of the password, as `mismatch`, `length` or `same`; null when nothing is. */
export function passwordProblem(current, next, again) {
  if (next !== again) return 'mismatch';
  if (!passwordFits(next)) return 'length';
  return next === current ? 'same' : null;
}

/**
 * What is wrong with the fields of a new token (`days` is the text of the field), as `name`, `role` or `days`; null
 * when nothing is. `own` is the role of the user, which no token may be above.
 */
export function tokenProblem({ name, role, days }, own) {
  if (!TOKEN_NAME.test(name)) return 'name';
  if (!rolesUpTo(own).includes(role)) return 'role';
  const count = /^\d{1,3}$/.test(days) ? Number(days) : 0;
  return count >= DAYS.min && count <= DAYS.max ? null : 'days';
}

/** The code of the second factor as it is sent: six digits stay; anything else is a recovery code, in capitals. */
export function codeToSend(typed) {
  const bare = typed.replace(/\s+/g, '');
  return /^\d{6}$/.test(bare) ? bare : bare.toUpperCase();
}

/** `text` in groups of four characters, which reads better than one long run. */
export function inGroups(text) {
  return String(text).replace(/(.{4})(?=.)/g, '$1 ');
}

/** `ms` (milliseconds since the epoch, as the API gives times of accounts) as UTC text. */
export function when(ms) {
  return typeof ms === 'number' && Number.isFinite(ms) ? utc(Math.floor(ms / 1000)) : String(ms);
}

// ---- what is shown once ----

/**
 * The steps of the setup of the second factor and what the API gave for them: `start` (nothing), `scan` (the secret
 * and the address that go into the app of the user) and `codes` (the recovery codes, instead of the secret). The
 * values are cleared when the setup ends or is given up.
 */
export class Enrollment {
  constructor() {
    this.clear();
  }

  clear() {
    this.step = 'start';
    this.secret = null;
    this.uri = null;
    this.codes = null;
  }

  /** Takes the answer of the start of a setup; false, and nothing kept, when it has no secret and address. */
  begin(answer) {
    if (typeof answer?.secret !== 'string' || typeof answer?.uri !== 'string' || answer.secret === '') return false;
    this.step = 'scan';
    this.secret = answer.secret;
    this.uri = answer.uri;
    return true;
  }

  /** Takes the answer of the confirmation: the recovery codes take the place of the secret. False when it has none. */
  finish(answer) {
    const codes = answer?.recovery;
    if (!Array.isArray(codes) || codes.length === 0 || !codes.every((code) => typeof code === 'string' && code !== '')) {
      return false;
    }
    this.step = 'codes';
    this.secret = null;
    this.uri = null;
    this.codes = [...codes];
    return true;
  }
}

/** Everything that the page holds for the user to see once. */
export class Held {
  constructor() {
    this.enrollment = new Enrollment();
    /** The token that was just made: `{ text, name, role, expires }`. */
    this.token = null;
    /** The confirmation of a setup that is on its way: the promise of its end (see `confirm`), or null. */
    this.confirming = null;
    /** Counts the times that all was given up for good; an answer that was asked for before is dropped. */
    this.turn = 0;
  }

  clear() {
    this.enrollment.clear();
    this.token = null;
  }

  /** Gives up what is held and what is on its way, for the end of a sign-in: none of it may reach the next one. */
  forget() {
    this.clear();
    this.confirming = null;
    this.turn += 1;
  }

  /**
   * Sends the code that proves the secret of a setup. The recovery codes of the answer are kept in `enrollment` as
   * soon as it comes, whichever screen is shown by then: the second factor is on with that answer, and the codes are
   * never made again. Gives the end as `{ error, kept }` (`kept`: the answer had the codes), or null when all was
   * given up while the call was on its way.
   */
  confirm(api, code) {
    const turn = this.turn;
    const ended = (async () => {
      let answer = null;
      let error = null;
      try {
        answer = await api.call('POST', '/api/account/mfa/confirm', { code });
      } catch (failure) {
        error = failure;
      }
      if (turn !== this.turn) return null;
      this.confirming = null;
      return { error, kept: error === null && this.enrollment.finish(answer) };
    })();
    this.confirming = ended;
    return ended;
  }
}

const held = new Held();

/** Gives up everything the page holds to be shown once, and what is on its way: the sign-in has ended. */
export function forgetHeld() {
  held.forget();
}

/** Gives up what is held, unless the page is only drawn again for the language (the same screen comes back at once). */
function release(ctx) {
  if (!ctx.redrawing()) held.clear();
}

// ---- small parts ----

function input(attributes) {
  return el('input', { class: 'input', ...attributes });
}

function submitButton(label) {
  return el('button', { type: 'submit', class: 'btn btn-primary' }, label);
}

function svg(tag, attributes) {
  const node = globalThis.document.createElementNS(SVG_NAMESPACE, tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, String(value));
  return node;
}

/**
 * The QR code of `text` as an SVG: a light square with a dark rectangle for each run of dark modules, and the quiet
 * zone around. Black on white whatever the theme is, as readers need. Null when the text does not fit.
 */
function qrView(text) {
  let code;
  try {
    code = encode(text);
  } catch {
    return null;
  }
  const side = code.size + 2 * QUIET;
  const image = svg('svg', {
    class: 'qr',
    viewBox: `0 0 ${side} ${side}`,
    role: 'img',
    'aria-label': t('twofa.qr_label'),
    'shape-rendering': 'crispEdges',
    focusable: 'false',
  });
  image.append(svg('rect', { class: 'qr-light', x: 0, y: 0, width: side, height: side }));
  for (const run of darkRuns(code)) {
    image.append(svg('rect', { class: 'qr-dark', x: run.column + QUIET, y: run.row + QUIET, width: run.length, height: 1 }));
  }
  return image;
}

/** A button that puts `text()` on the clipboard, and says whether that worked. */
function copyButton(text) {
  const status = el('span', { class: 'muted small', role: 'status' });
  const button = el(
    'button',
    {
      type: 'button',
      class: 'btn',
      on: {
        click: async () => {
          try {
            await globalThis.navigator.clipboard.writeText(text());
            mount(status, t('twofa.copied'));
          } catch {
            mount(status, t('twofa.copy_failed'));
          }
        },
      },
    },
    t('twofa.copy'),
  );
  return el('span', { class: 'row-actions' }, button, status);
}

const PASSWORD_PROBLEMS = {
  mismatch: () => t('password.mismatch'),
  length: () => t('password.length'),
  same: () => t('password.same'),
};

/**
 * The form that changes the password of the signed-in user. `messages` is where a failure is told. `onChanged` runs
 * when the API has changed the password and renewed the session; it is awaited with the button held down.
 */
export function passwordForm(ctx, { username, messages, onChanged }) {
  const secret = { type: 'password', maxlength: '128', required: true };
  const current = input({ ...secret, name: 'current', autocomplete: 'current-password' });
  const next = input({ ...secret, name: 'new', autocomplete: 'new-password' });
  const again = input({ ...secret, name: 'again', autocomplete: 'new-password' });
  const submit = submitButton(t('password.submit'));
  const fields = [current, next, again];
  const form = el(
    'form',
    {
      class: 'stack',
      on: {
        submit: async (event) => {
          event.preventDefault();
          if (submit.disabled) return;
          const typed = { current: current.value, next: next.value, again: again.value };
          const problem = passwordProblem(typed.current, typed.next, typed.again);
          if (problem !== null) {
            mount(messages, notice('bad', PASSWORD_PROBLEMS[problem]()));
            return;
          }
          await ctx.guarded(submit, async () => {
            try {
              await ctx.api.call('PUT', '/api/account/password', { current: typed.current, new: typed.next });
            } catch (error) {
              if (!form.isConnected) return;
              mount(messages, notice('bad', ctx.describe(error, { change: true })));
              for (const field of fields) field.value = '';
              current.focus();
              return;
            }
            for (const field of fields) field.value = '';
            await onChanged();
          });
        },
      },
    },
    // Not shown: the name of the account, so that a password manager can tell whose password is changed.
    el('input', { type: 'text', name: 'username', autocomplete: 'username', value: username, readonly: true, hidden: true }),
    labelled(t('password.current'), current),
    labelled(t('password.new'), next),
    labelled(t('password.confirm'), again),
    el('p', { class: 'muted small' }, t('password.hint')),
    el('div', { class: 'actions' }, submit),
  );
  return { node: form, focus: () => current.focus() };
}

// ---- the setup of the second factor ----

/**
 * The setup of the second factor: the password, then the secret as a QR code and as text with the code that proves
 * it, then the recovery codes, which are shown once. `node` is what goes on the page; `stop` is called when the page
 * is left. `onDone` runs when the user has saved the recovery codes and ends the setup.
 */
class SetupFlow {
  constructor(ctx, { onDone }) {
    this.ctx = ctx;
    this.onDone = onDone;
    this.alive = true;
    this.node = el('div', { class: 'stack' });
    /** Words for the next drawing (why the setup went back to its start). */
    this.flash = null;
    this.messages = null;
    this.draw();
    // A confirmation that was sent before this flow was drawn (the language was switched meanwhile) ends here.
    held.confirming?.then((ended) => this.settled(ended));
  }

  stop() {
    this.alive = false;
    mount(this.node);
    release(this.ctx);
  }

  draw() {
    const step = held.enrollment.step;
    const flash = this.flash;
    this.flash = null;
    this.messages = el('div', { class: 'notes', 'aria-live': 'polite' }, flash);
    const view = step === 'scan' ? this.scanView() : step === 'codes' ? this.codesView() : this.startView();
    mount(this.node, view);
  }

  tell(words) {
    if (this.alive) mount(this.messages, notice('bad', words));
  }

  startView() {
    const password = input({ type: 'password', name: 'password', autocomplete: 'current-password', maxlength: '128', required: true });
    const submit = submitButton(t('twofa.start'));
    const form = el(
      'form',
      {
        class: 'stack',
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            const typed = password.value;
            password.value = '';
            await this.ctx.guarded(submit, async () => {
              let answer;
              try {
                answer = await this.ctx.api.call('POST', '/api/account/mfa/setup', { password: typed });
              } catch (error) {
                this.tell(this.ctx.describe(error, { change: true }));
                return;
              }
              if (!this.alive) return;
              if (held.enrollment.begin(answer)) this.draw();
              else this.tell(t('error.generic'));
            });
          },
        },
      },
      el('p', {}, badge('muted', t('twofa.off'))),
      el('p', {}, t('twofa.intro_off')),
      this.messages,
      labelled(t('password.current'), password, t('twofa.start_hint')),
      el('div', { class: 'actions' }, submit),
    );
    return form;
  }

  scanView() {
    const { secret, uri } = held.enrollment;
    const code = input({
      type: 'text',
      name: 'code',
      autocomplete: 'one-time-code',
      inputmode: 'numeric',
      maxlength: '8',
      autocapitalize: 'none',
      spellcheck: 'false',
      required: true,
    });
    const confirm = submitButton(t('twofa.confirm'));
    if (held.confirming !== null) {
      confirm.disabled = true;
      confirm.setAttribute('aria-busy', 'true');
    }
    const cancel = el(
      'button',
      {
        type: 'button',
        class: 'btn',
        on: {
          click: () => {
            held.enrollment.clear();
            this.draw();
          },
        },
      },
      t('twofa.cancel'),
    );
    const form = el(
      'form',
      {
        class: 'stack',
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (confirm.disabled) return;
            const typed = code.value.replace(/\s+/g, '');
            code.value = '';
            if (!/^\d{6}$/.test(typed)) {
              this.tell(t('twofa.code_form'));
              return;
            }
            await this.ctx.guarded(confirm, () => this.confirm(typed));
          },
        },
      },
      this.messages,
      labelled(t('twofa.step2'), code),
      el('div', { class: 'actions' }, confirm, cancel),
    );
    const image = qrView(uri);
    return el(
      'div',
      { class: 'stack' },
      el('p', {}, t('twofa.step1')),
      image ?? notice('warn', t('twofa.qr_failed')),
      el('dl', { class: 'kv' }, row(t('twofa.secret'), el('code', { class: 'secret' }, inGroups(secret)))),
      copyButton(() => secret),
      el('p', { class: 'muted small' }, t('twofa.secret_hint')),
      form,
    );
  }

  /** Sends the code that proves the secret; on success the recovery codes are shown. */
  async confirm(typed) {
    this.settled(await held.confirm(this.ctx.api, typed));
  }

  /** The end of the confirmation (see `Held.confirm`): the recovery codes are shown, or why the setup goes on. */
  settled(ended) {
    if (!this.alive || ended === null) return;
    const { error, kept } = ended;
    if (error === null && !kept) {
      // The second factor is set, but the answer did not carry the codes.
      held.enrollment.clear();
      this.flash = notice('bad', t('twofa.codes_missing'));
    } else if (error !== null) {
      // A conflict says that the setup ran out (the API keeps the secret for ten minutes) or was never started.
      const conflict = error instanceof ApiError && error.kind === 'conflict';
      if (conflict) held.enrollment.clear();
      this.flash = notice(conflict ? 'warn' : 'bad', this.ctx.describe(error, { change: true }));
    }
    this.draw();
  }

  codesView() {
    const { codes } = held.enrollment;
    const done = el('button', { type: 'button', class: 'btn btn-primary', disabled: true, on: { click: () => this.finish() } }, t('twofa.codes_done'));
    const saved = el('input', { type: 'checkbox', on: { change: () => (done.disabled = !saved.checked) } });
    return el(
      'div',
      { class: 'stack' },
      notice('warn', el('p', {}, el('strong', {}, t('twofa.codes_title'))), el('p', {}, t('twofa.codes_warn'))),
      this.messages,
      el('ol', { class: 'codes', 'aria-label': t('twofa.codes_list') }, codes.map((code) => el('li', {}, el('code', {}, inGroups(code))))),
      copyButton(() => codes.join('\n')),
      el('label', { class: 'check' }, saved, el('span', {}, t('twofa.codes_saved'))),
      el('div', { class: 'actions' }, done),
    );
  }

  /** The user has saved the codes: the setup is over, and they are gone from the page. */
  async finish() {
    held.enrollment.clear();
    mount(this.node);
    await this.onDone();
  }
}

/** The setup of the second factor for a gate of the page. Gives `{ node, stop }`. */
export function mfaSetup(ctx, { onDone }) {
  const flow = new SetupFlow(ctx, { onDone });
  return { node: flow.node, stop: () => flow.stop() };
}

// ---- tokens ----

/**
 * A table of API tokens (`owner`: with the column of the owner). `remove(token)` runs when the button of a token is
 * pressed. The times of a token are in milliseconds.
 */
export function tokenTable(tokens, { owner, remove }) {
  const columns = [t('col.name'), ...(owner ? [t('col.owner')] : []), t('col.role'), t('col.expires'), t('col.last_used'), t('col.id'), t('col.actions')];
  const rows = tokens.map((token) => [
    String(token.name),
    ...(owner ? [String(token.owner)] : []),
    badge('muted', String(token.role)),
    el('span', { class: 'badges' }, when(token.expires), token.expired === true ? badge('bad', t('tokens.expired')) : null),
    token.last_used === null || token.last_used === undefined ? t('tokens.never') : when(token.last_used),
    el('code', { class: 'fp' }, String(token.id)),
    el(
      'button',
      { type: 'button', class: 'btn btn-danger btn-small', 'aria-label': t('tokens.delete_named', { name: String(token.name) }), on: { click: () => remove(token) } },
      t('tokens.delete'),
    ),
  ]);
  return table(columns, rows, t('tokens.caption'), { tight: owner ? [3, 4] : [2, 3] });
}

/** The lines of a confirmation that removes `token` (`owner`: with the owner of the token). */
export function tokenLines(token, { owner }) {
  return [
    el('p', {}, t('tokens.delete_what')),
    el(
      'dl',
      { class: 'kv' },
      row(t('col.name'), String(token.name)),
      owner ? row(t('col.owner'), String(token.owner)) : null,
      row(t('col.id'), el('code', { class: 'fp' }, String(token.id))),
    ),
  ];
}

// ---- the screen ----

class AccountScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.alive = true;
    this.reads = 0;
    this.session = null;
    this.sessionError = null;
    this.tokens = null;
    this.tokensError = null;
    this.layer = el('div');
    this.results = el('div', { class: 'notes', 'aria-live': 'polite' });
    this.reloadButton = el('button', { type: 'button', class: 'btn', on: { click: () => this.load() } }, t('screen.reload'));
    this.mfaBox = el('section', { class: 'card' });
    this.tokensBox = el('section', { class: 'card' });
    this.flow = new SetupFlow(ctx, { onDone: () => this.mfaDone() });
    // The codes of a confirmation that ends after this screen was drawn show where the session may have put the removal.
    held.confirming?.then(() => this.alive && this.drawMfa());
    const messages = el('div', { class: 'notes', 'aria-live': 'polite' });
    const password = passwordForm(ctx, { username: ctx.user.name, messages, onChanged: () => this.passwordChanged(messages) });
    mount(
      root,
      el(
        'div',
        { class: 'stack' },
        pageHead(t('account.title'), this.reloadButton),
        el('p', { class: 'muted' }, t('account.who', { name: ctx.user.name, role: ctx.user.role })),
        this.results,
        el('section', { class: 'card' }, el('h2', {}, t('account.password')), el('p', { class: 'muted' }, t('account.password_intro')), messages, password.node),
        this.mfaBox,
        this.tokensBox,
      ),
      this.layer,
    );
    this.drawMfa();
    this.drawTokens();
  }

  stop() {
    this.alive = false;
    this.flow.stop();
    mount(this.tokensBox);
  }

  async load() {
    const asked = (this.reads += 1);
    this.reloadButton.disabled = true;
    const [session, tokens] = await Promise.allSettled([this.ctx.api.call('GET', '/api/session'), this.ctx.api.call('GET', '/api/account/tokens')]);
    if (!this.alive || asked !== this.reads) return;
    this.reloadButton.disabled = false;
    if (session.status === 'fulfilled') {
      this.session = session.value;
      this.sessionError = null;
    } else this.sessionError = session.reason;
    if (tokens.status === 'fulfilled') {
      this.tokens = Array.isArray(tokens.value.tokens) ? tokens.value.tokens : [];
      this.tokensError = null;
    } else this.tokensError = tokens.reason;
    this.drawMfa();
    this.drawTokens();
  }

  async loadTokens() {
    try {
      const answer = await this.ctx.api.call('GET', '/api/account/tokens');
      this.tokens = Array.isArray(answer.tokens) ? answer.tokens : [];
      this.tokensError = null;
    } catch (error) {
      this.tokensError = error;
    }
    if (this.alive) this.drawTokens();
  }

  async loadSession() {
    try {
      this.session = await this.ctx.api.call('GET', '/api/session');
      this.sessionError = null;
    } catch (error) {
      this.sessionError = error;
    }
    if (this.alive) this.drawMfa();
  }

  /** The session ended with the change (the API could not make a new one): back to the sign-in. */
  ended(why) {
    if (this.ctx.api.csrf !== null) return false;
    this.ctx.toLogin(() => why);
    return true;
  }

  async passwordChanged(messages) {
    if (this.ended(t('login.ended'))) return;
    mount(messages, notice('ok', t('account.password_done')));
    // The tokens of the user were removed with the change.
    await this.loadTokens();
  }

  async mfaDone() {
    if (this.ended(t('login.mfa_changed'))) return;
    mount(this.results, notice('ok', t('twofa.set')));
    await this.loadSession();
  }

  // ---- the second factor ----

  drawMfa() {
    const session = this.session;
    let content;
    if (held.enrollment.step !== 'start') {
      // A setup is under way: nothing but it is shown, whatever the session says now.
      content = this.flow.node;
    } else if (session === null) {
      content = this.sessionError === null ? notice('info', t('account.loading')) : notice('bad', t('account.failed'), ' ', this.ctx.describe(this.sessionError));
    } else if (session.mfa === true) {
      content = this.removeView(session);
    } else {
      this.flow.draw();
      content = this.flow.node;
    }
    mount(
      this.mfaBox,
      el('h2', {}, t('twofa.title')),
      this.sessionError !== null && session !== null ? notice('bad', t('account.failed'), ' ', this.ctx.describe(this.sessionError)) : null,
      content,
    );
  }

  removeView(session) {
    const left = typeof session.recovery_left === 'number' ? session.recovery_left : null;
    const messages = el('div', { class: 'notes', 'aria-live': 'polite' });
    const password = input({ type: 'password', name: 'password', autocomplete: 'current-password', maxlength: '128', required: true });
    const code = input({ type: 'text', name: 'code', autocomplete: 'one-time-code', maxlength: '64', autocapitalize: 'none', spellcheck: 'false', required: true });
    const submit = el('button', { type: 'submit', class: 'btn btn-danger' }, t('twofa.remove'));
    const form = el(
      'form',
      {
        class: 'stack',
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            const typed = { password: password.value, code: codeToSend(code.value) };
            password.value = '';
            code.value = '';
            await this.ctx.guarded(submit, async () => {
              try {
                await this.ctx.api.call('DELETE', '/api/account/mfa', typed);
              } catch (error) {
                if (this.alive) mount(messages, notice('bad', this.ctx.describe(error, { change: true })));
                return;
              }
              if (this.ended(t('login.ended')) || !this.alive) return;
              mount(this.results, notice('ok', t('twofa.removed')));
              await this.loadSession();
            });
          },
        },
      },
      el('h3', {}, t('twofa.remove_title')),
      el('p', { class: 'muted' }, t('twofa.remove_hint')),
      messages,
      labelled(t('password.current'), password),
      labelled(t('twofa.remove_code'), code),
      el('div', { class: 'actions' }, submit),
    );
    return [
      el('p', {}, badge('ok', t('twofa.on'))),
      left === null ? null : el('p', {}, t('twofa.recovery_left', { n: left })),
      left !== null && left <= FEW_CODES ? notice('warn', t('twofa.recovery_low')) : el('p', { class: 'muted small' }, t('twofa.recovery_new')),
      form,
    ];
  }

  // ---- tokens ----

  drawTokens() {
    const tokens = this.tokens;
    let list;
    if (tokens === null) {
      list = this.tokensError === null ? notice('info', t('account.loading')) : notice('bad', t('tokens.failed'), ' ', this.ctx.describe(this.tokensError));
    } else if (tokens.length === 0) {
      list = el('p', { class: 'muted' }, t('tokens.empty'));
    } else {
      list = tokenTable(tokens, { owner: false, remove: (token) => this.removeToken(token) });
    }
    mount(
      this.tokensBox,
      el('h2', {}, t('tokens.title')),
      el('p', { class: 'muted' }, t('tokens.intro')),
      this.issuedView(),
      this.tokensError !== null && tokens !== null ? notice('bad', t('tokens.failed'), ' ', this.ctx.describe(this.tokensError)) : null,
      list,
      this.createForm(),
    );
  }

  /** The token that was just made, which is shown this once. */
  issuedView() {
    const token = held.token;
    if (token === null) return null;
    const close = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-primary',
        on: {
          click: () => {
            held.token = null;
            this.drawTokens();
          },
        },
      },
      t('tokens.issued_done'),
    );
    return notice(
      'warn',
      el('p', {}, el('strong', {}, t('tokens.issued_title', { name: token.name }))),
      el('p', {}, t('tokens.issued_warn')),
      el('p', {}, el('code', { class: 'secret' }, token.text)),
      el('p', { class: 'muted small' }, t('tokens.issued_info', { role: token.role, time: when(token.expires) })),
      el('div', { class: 'row-actions' }, copyButton(() => token.text), close),
    );
  }

  createForm() {
    const own = this.ctx.user.role;
    const name = input({ type: 'text', name: 'token-name', maxlength: '64', autocomplete: 'off', required: true, spellcheck: 'false' });
    const role = el(
      'select',
      { class: 'input', name: 'token-role' },
      rolesUpTo(own).map((choice) => el('option', { value: choice, selected: choice === own }, choice)),
    );
    const days = input({ type: 'number', name: 'token-days', min: String(DAYS.min), max: String(DAYS.max), step: '1', inputmode: 'numeric', value: String(DAYS.start), required: true });
    const password = input({ type: 'password', name: 'password', autocomplete: 'current-password', maxlength: '128', required: true });
    // The text of a token is shown once and a new token would take its place, so the next one waits until it is saved.
    const waiting = held.token !== null;
    const messages = el('div', { class: 'notes', 'aria-live': 'polite' }, waiting ? notice('info', t('tokens.issued_first')) : null);
    const submit = submitButton(t('tokens.create'));
    submit.disabled = waiting;
    const problems = { name: () => t('tokens.p_name'), role: () => t('tokens.p_role'), days: () => t('tokens.p_days') };
    return el(
      'form',
      {
        class: 'stack',
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled || held.token !== null) return;
            const typed = { name: name.value, role: role.value, days: days.value.trim() };
            const problem = tokenProblem(typed, own);
            if (problem !== null) {
              mount(messages, notice('bad', problems[problem]()));
              return;
            }
            const secret = password.value;
            password.value = '';
            await this.ctx.guarded(submit, async () => {
              let made;
              try {
                made = await this.ctx.api.call('POST', '/api/account/tokens', { name: typed.name, role: typed.role, days: Number(typed.days), password: secret });
              } catch (error) {
                if (this.alive) mount(messages, notice('bad', this.ctx.describe(error, { change: true })));
                return;
              }
              if (!this.alive) return;
              if (typeof made.token !== 'string') {
                mount(messages, notice('bad', t('error.generic')));
                await this.loadTokens();
                return;
              }
              held.token = { text: made.token, name: typed.name, role: typed.role, expires: made.expires };
              await this.loadTokens();
            });
          },
        },
      },
      el('h3', {}, t('tokens.create_title')),
      messages,
      el(
        'div',
        { class: 'fields' },
        labelled(t('tokens.name'), name, t('tokens.name_hint')),
        labelled(t('col.role'), role, t('tokens.role_hint', { role: own })),
        labelled(t('tokens.days'), days, t('tokens.days_hint')),
        labelled(t('password.current'), password, t('tokens.password_hint')),
      ),
      el('div', { class: 'actions' }, submit),
    );
  }

  async removeToken(token) {
    const yes = await confirmChange(this.layer, { title: t('tokens.delete_title'), lines: tokenLines(token, { owner: false }), confirm: t('tokens.delete'), tone: 'danger' });
    if (!yes || !this.alive) return;
    let error = null;
    try {
      await this.ctx.api.call('DELETE', `/api/account/tokens/${encodeURIComponent(token.id)}`);
    } catch (failure) {
      error = failure;
    }
    if (!this.alive) return;
    mount(this.results, error === null ? notice('ok', t('tokens.deleted', { name: String(token.name) })) : notice('bad', this.ctx.describe(error, { change: true })));
    await this.loadTokens();
  }
}

function mountAccount(ctx, root) {
  const screen = new AccountScreen(ctx, root);
  screen.load();
  return () => screen.stop();
}

export const screens = [{ id: 'account', title: () => t('nav.account'), least: 'viewer', mount: mountAccount }];
