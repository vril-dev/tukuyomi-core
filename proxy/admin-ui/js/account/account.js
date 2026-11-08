// The account screen: the password, the second factor (its setup with a QR code and the recovery codes, and its
// removal) and the API tokens of the signed-in user. The password form and the setup of the second factor are also
// what the gates of the page show, so they are made here as parts that take the context of the page (`ctx`: `api`,
// `describe`, `guarded`, `toLogin`).
//
// What the API shows only once (the secret of a setup, the recovery codes, the text of a new token) is kept in `held`,
// in memory, and nowhere else: never in the storage of the browser, in the address or in the history. A screen draws it
// and gives it up, and its nodes, when it is left. The recovery codes that the API gives when a setup is confirmed are
// kept as soon as the answer comes, even when the screen that sent the code is gone by then, and wait for the next
// screen that is drawn (see `Held.confirm`); the end of the sign-in gives up all of it (see `forgetHeld`). A screen is
// `{ id, title, least, mount }`; `mount(ctx, root)` draws into `root` and gives back `{ stop }`. Nothing runs when the
// module is loaded.

import { ApiError } from '../api.js';
import { badge, bindAttribute, button, el, mount, notice, result } from '../dom.js';
import { w } from '../i18n.js';
import { Field, checkFields, confirmChange, copyButton, emptyField, kv, pageHead, panel, restoreFocus, row, setBusy, textInput, timeCell, timeCellText, timeLabel, timeWords } from '../parts.js';
import { darkRuns, encode } from './qr.js';
import { Table } from '../table.js';

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

/**
 * What is wrong with a change of the password, in the order of the form: `length` or `same` for the new password, and
 * `mismatch` for the second one; none when nothing is.
 */
export function passwordProblems(current, next, again) {
  const onNext = !passwordFits(next) ? 'length' : next === current ? 'same' : null;
  return [onNext, next === again ? null : 'mismatch'].filter((problem) => problem !== null);
}

/**
 * The fields of a new token that are wrong (`days` is the text of the field), in the order of the form: `name`, `role`
 * and `days`; none when all are right. `own` is the role of the user, which no token may be above.
 */
export function tokenProblems({ name, role, days }, own) {
  const count = /^\d{1,3}$/.test(days) ? Number(days) : 0;
  return [
    TOKEN_NAME.test(name) ? null : 'name',
    rolesUpTo(own).includes(role) ? null : 'role',
    count >= DAYS.min && count <= DAYS.max ? null : 'days',
  ].filter((field) => field !== null);
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

// ---- small parts ----

function passwordInput(attributes = {}) {
  return textInput({ type: 'password', maxlength: '128', ...attributes });
}

function submitButton(label, kinds = 'primary') {
  return button(kinds, label, null, { type: 'submit' });
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
    class: 'tc-qr',
    viewBox: `0 0 ${side} ${side}`,
    role: 'img',
    'shape-rendering': 'crispEdges',
    focusable: 'false',
  });
  bindAttribute(image, 'aria-label', w('twofa.qr_label'));
  image.append(svg('rect', { class: 'tc-qr-light', x: 0, y: 0, width: side, height: side }));
  for (const run of darkRuns(code)) {
    image.append(svg('rect', { class: 'tc-qr-dark', x: run.column + QUIET, y: run.row + QUIET, width: run.length, height: 1 }));
  }
  return image;
}

/** The words for a field that is empty, or `problem` for a field that is filled in (null when nothing is wrong). */
const emptyOr = (value, problem) => (value === '' ? emptyField() : problem);

const PASSWORD_PROBLEMS = {
  mismatch: () => w('password.mismatch'),
  length: () => w('password.length'),
  same: () => w('password.same'),
};

/**
 * The form that changes the password of the signed-in user. `messages` is where a failure is told. `onChanged` runs
 * when the API has changed the password and renewed the session; it is awaited with the button held down.
 */
export function passwordForm(ctx, { username, messages, onChanged }) {
  const current = new Field(w('password.current'), passwordInput({ name: 'current', autocomplete: 'current-password' }), { required: true });
  const next = new Field(w('password.new'), passwordInput({ name: 'new', autocomplete: 'new-password' }), { required: true, hint: w('password.hint') });
  const again = new Field(w('password.confirm'), passwordInput({ name: 'again', autocomplete: 'new-password' }), { required: true });
  const submit = submitButton(w('password.submit'));
  const fields = [current, next, again];
  const form = el(
    'form',
    {
      class: 'tc-form',
      novalidate: true,
      on: {
        submit: async (event) => {
          event.preventDefault();
          if (submit.disabled) return;
          const typed = { current: current.control.value, next: next.control.value, again: again.control.value };
          const problems = passwordProblems(typed.current, typed.next, typed.again);
          const onNext = problems.find((problem) => problem === 'length' || problem === 'same') ?? null;
          const entries = [
            [current, emptyOr(typed.current, null)],
            [next, emptyOr(typed.next, onNext === null ? null : PASSWORD_PROBLEMS[onNext]())],
            [again, emptyOr(typed.again, problems.includes('mismatch') ? PASSWORD_PROBLEMS.mismatch() : null)],
          ];
          if (!checkFields(entries)) return;
          await ctx.guarded(
            submit,
            async () => {
              try {
                await ctx.api.call('PUT', '/api/account/password', { current: typed.current, new: typed.next });
              } catch (error) {
                if (!form.isConnected) return;
                mount(messages, notice('bad', ctx.describe(error, { change: true })));
                for (const field of fields) field.control.value = '';
                current.control.focus();
                return;
              }
              for (const field of fields) field.control.value = '';
              await onChanged();
            },
            w('password.busy'),
          );
        },
      },
    },
    // Not shown: the name of the account, so that a password manager can tell whose password is changed.
    el('input', { type: 'text', name: 'username', autocomplete: 'username', value: username, readonly: true, hidden: true }),
    current.node,
    next.node,
    again.node,
    el('div', { class: 'tc-actions' }, submit),
  );
  return { node: form, focus: () => current.control.focus() };
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
    this.node = el('div', { class: 'tc-stack' });
    /** Words for the next drawing (why the setup went back to its start). */
    this.flash = null;
    this.messages = null;
    this.draw();
    // A confirmation that was sent before this flow was drawn (the user left the screen and came back) ends here.
    held.confirming?.then((ended) => this.settled(ended));
  }

  stop() {
    this.alive = false;
    mount(this.node);
    held.clear();
  }

  draw() {
    const step = held.enrollment.step;
    const flash = this.flash;
    this.flash = null;
    this.messages = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' }, flash);
    const view = step === 'scan' ? this.scanView() : step === 'codes' ? this.codesView() : this.startView();
    mount(this.node, view);
  }

  tell(words) {
    if (this.alive) mount(this.messages, notice('bad', words));
  }

  startView() {
    const password = new Field(w('password.current'), passwordInput({ name: 'password', autocomplete: 'current-password' }), { required: true, hint: w('twofa.start_hint') });
    const submit = submitButton(w('twofa.start'));
    return el(
      'form',
      {
        class: 'tc-form',
        novalidate: true,
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            const typed = password.control.value;
            if (!checkFields([[password, typed === '' ? emptyField() : null]])) return;
            password.control.value = '';
            await this.ctx.guarded(
              submit,
              async () => {
                let answer;
                try {
                  answer = await this.ctx.api.call('POST', '/api/account/mfa/setup', { password: typed });
                } catch (error) {
                  this.tell(this.ctx.describe(error, { change: true }));
                  return;
                }
                if (!this.alive) return;
                if (held.enrollment.begin(answer)) this.draw();
                else this.tell(w('error.generic'));
              },
              w('twofa.start_busy'),
            );
          },
        },
      },
      el('p', {}, badge('muted', w('twofa.off'))),
      el('p', {}, w('twofa.intro_off')),
      this.messages,
      password.node,
      el('div', { class: 'tc-actions' }, submit),
    );
  }

  scanView() {
    const { secret, uri } = held.enrollment;
    const code = new Field(w('twofa.step2'), textInput({ name: 'code', autocomplete: 'one-time-code', inputmode: 'numeric', maxlength: '8', autocapitalize: 'none', spellcheck: 'false' }), { required: true });
    const confirm = submitButton(w('twofa.confirm'));
    if (held.confirming !== null) {
      confirm.disabled = true;
      confirm.setAttribute('aria-busy', 'true');
    }
    const cancel = button('', w('twofa.cancel'), () => {
      held.enrollment.clear();
      this.draw();
    });
    const form = el(
      'form',
      {
        class: 'tc-form',
        novalidate: true,
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (confirm.disabled) return;
            const typed = code.control.value.replace(/\s+/g, '');
            if (!checkFields([[code, emptyOr(typed, /^\d{6}$/.test(typed) ? null : w('twofa.code_form'))]])) return;
            code.control.value = '';
            await this.ctx.guarded(confirm, () => this.confirm(typed), w('twofa.confirm_busy'));
          },
        },
      },
      this.messages,
      code.node,
      el('div', { class: 'tc-actions' }, confirm, cancel),
    );
    const image = qrView(uri);
    const secretText = el('code', { class: 'tc-secret' }, inGroups(secret));
    return el(
      'div',
      { class: 'tc-stack' },
      el('p', {}, w('twofa.step1')),
      image ?? notice('warn', w('twofa.qr_failed')),
      kv(row(w('twofa.secret'), secretText)),
      copyButton(() => secret, secretText),
      el('p', { class: 'tc-muted tc-small' }, w('twofa.secret_hint')),
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
      this.flash = notice('bad', w('twofa.codes_missing'));
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
    const done = button('primary', w('twofa.codes_done'), () => this.finish(), { disabled: true });
    const saved = el('input', { type: 'checkbox', class: 'tc-check', on: { change: () => (done.disabled = !saved.checked) } });
    const list = el('ol', { class: 'tc-codes', 'aria-label': w('twofa.codes_list') }, codes.map((code) => el('li', {}, el('code', {}, inGroups(code)))));
    return el(
      'div',
      { class: 'tc-stack' },
      notice('warn', el('span', { class: 'tc-notice__title' }, w('twofa.codes_title')), el('span', {}, w('twofa.codes_warn'))),
      this.messages,
      list,
      copyButton(() => codes.join('\n'), list),
      el('label', { class: 'tc-choice' }, saved, el('span', {}, w('twofa.codes_saved'))),
      el('div', { class: 'tc-actions' }, done),
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
 * The table of API tokens (`owner`: with the column of the owner). `remove(token)` runs when the button of a token is
 * pressed. The times of a token are in milliseconds. Give it the tokens with `update({ rows })`.
 */
export function tokenTable({ owner, remove }) {
  return new Table({
    caption: w('tokens.caption'),
    rowKey: (token) => String(token.id),
    empty: { title: w('tokens.empty') },
    columns: [
      { key: 'name', label: w('col.name'), value: (token) => String(token.name) },
      ...(owner ? [{ key: 'owner', label: w('col.owner'), value: (token) => String(token.owner) }] : []),
      { key: 'role', label: w('col.role'), value: (token) => String(token.role), cell: (token) => badge('muted', String(token.role)) },
      {
        key: 'expires',
        label: timeLabel(w('col.expires')),
        value: (token) => token.expires,
        text: (token) => [timeCellText(token.expires), token.expired === true ? w('tokens.expired').text() : ''].join(' '),
        tight: true,
        cell: (token) => el('span', { class: 'tc-badges' }, timeCell(token.expires), token.expired === true ? badge('bad', w('tokens.expired')) : null),
      },
      {
        key: 'last_used',
        label: timeLabel(w('col.last_used')),
        value: (token) => token.last_used ?? null,
        text: (token) => (token.last_used === null || token.last_used === undefined ? w('tokens.never').text() : timeCellText(token.last_used)),
        tight: true,
        cell: (token) => (token.last_used === null || token.last_used === undefined ? w('tokens.never') : timeCell(token.last_used)),
      },
      { key: 'id', label: w('col.id'), value: (token) => String(token.id), mono: true },
      {
        key: 'actions',
        label: w('col.actions'),
        value: () => '',
        sortable: false,
        filter: false,
        cell: (token) => button('small danger', w('tokens.delete'), () => remove(token), { 'aria-label': w('tokens.delete_named', { name: String(token.name) }) }),
      },
    ],
  });
}

/** The lines of a confirmation that removes `token` (`owner`: with the owner of the token). */
export function tokenLines(token, { owner }) {
  return [
    el('p', {}, w('tokens.delete_what')),
    kv(
      row(w('col.name'), String(token.name)),
      owner ? row(w('col.owner'), String(token.owner)) : null,
      row(w('col.id'), el('code', {}, String(token.id))),
    ),
  ];
}

// ---- the screen ----

class AccountScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.root = root;
    this.alive = true;
    this.reads = 0;
    this.session = null;
    this.sessionError = null;
    this.tokens = null;
    this.tokensError = null;
    this.layer = el('div');
    this.results = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' });
    this.reloadButton = button('', w('screen.reload'), () => this.load());
    this.mfaBox = el('div');
    this.tokensBox = el('div');
    this.tokenTable = tokenTable({ owner: false, remove: (token) => this.removeToken(token) });
    this.flow = new SetupFlow(ctx, { onDone: () => this.mfaDone() });
    // The codes of a confirmation that ends after this screen was drawn show where the session may have put the removal.
    held.confirming?.then(() => this.alive && this.drawMfa());
    const messages = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' });
    const password = passwordForm(ctx, { username: ctx.user.name, messages, onChanged: () => this.passwordChanged(messages) });
    mount(
      root,
      pageHead(w('account.title'), this.reloadButton),
      el('p', { class: 'tc-intro' }, w('account.who', { name: ctx.user.name, role: ctx.user.role })),
      this.results,
      panel(w('account.password'), [], el('p', { class: 'tc-muted' }, w('account.password_intro')), messages, password.node),
      this.mfaBox,
      this.tokensBox,
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
    setBusy(this.reloadButton, true);
    const [session, tokens] = await Promise.allSettled([this.ctx.api.call('GET', '/api/session'), this.ctx.api.call('GET', '/api/account/tokens')]);
    if (!this.alive || asked !== this.reads) return;
    setBusy(this.reloadButton, false);
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
    if (this.alive) {
      this.drawTokens();
      restoreFocus(this.root, this.root.querySelector('h1'));
    }
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
    this.ctx.toLogin(why);
    return true;
  }

  async passwordChanged(messages) {
    if (this.ended(w('login.ended'))) return;
    mount(messages, result('ok', w('account.password_done_title'), w('account.password_done')));
    // The tokens of the user were removed with the change.
    await this.loadTokens();
  }

  async mfaDone() {
    if (this.ended(w('login.mfa_changed'))) return;
    mount(this.results, result('ok', w('twofa.set_title'), w('twofa.set')));
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
      content = this.sessionError === null ? notice('info', w('account.loading')) : notice('bad', w('account.failed'), ' ', this.ctx.describe(this.sessionError));
    } else if (session.mfa === true) {
      content = this.removeView(session);
    } else {
      this.flow.draw();
      content = this.flow.node;
    }
    mount(
      this.mfaBox,
      panel(
        w('twofa.title'),
        session?.mfa === true ? [badge('ok', w('twofa.on'))] : [],
        this.sessionError !== null && session !== null ? notice('bad', w('account.failed'), ' ', this.ctx.describe(this.sessionError)) : null,
        content,
      ),
    );
  }

  removeView(session) {
    const left = typeof session.recovery_left === 'number' ? session.recovery_left : null;
    const messages = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' });
    const password = new Field(w('password.current'), passwordInput({ name: 'password', autocomplete: 'current-password' }), { required: true });
    const code = new Field(w('twofa.remove_code'), textInput({ name: 'code', autocomplete: 'one-time-code', maxlength: '64', autocapitalize: 'none', spellcheck: 'false' }), { required: true });
    const submit = submitButton(w('twofa.remove'), 'danger');
    const form = el(
      'form',
      {
        class: 'tc-form',
        novalidate: true,
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled) return;
            const typed = { password: password.control.value, code: codeToSend(code.control.value) };
            if (!checkFields([[password, emptyOr(typed.password, null)], [code, emptyOr(typed.code, null)]])) return;
            password.control.value = '';
            code.control.value = '';
            await this.ctx.guarded(
              submit,
              async () => {
                try {
                  await this.ctx.api.call('DELETE', '/api/account/mfa', typed);
                } catch (error) {
                  if (this.alive) mount(messages, notice('bad', this.ctx.describe(error, { change: true })));
                  return;
                }
                if (this.ended(w('login.ended')) || !this.alive) return;
                mount(this.results, result('ok', w('twofa.removed_title'), w('twofa.removed')));
                await this.loadSession();
              },
              w('twofa.remove_busy'),
            );
          },
        },
      },
      el('h3', {}, w('twofa.remove_title')),
      el('p', { class: 'tc-muted' }, w('twofa.remove_hint')),
      messages,
      password.node,
      code.node,
      el('div', { class: 'tc-actions' }, submit),
    );
    return [
      left === null ? null : el('p', {}, w('twofa.recovery_left', { n: left })),
      left !== null && left <= FEW_CODES ? notice('warn', w('twofa.recovery_low')) : el('p', { class: 'tc-muted tc-small' }, w('twofa.recovery_new')),
      form,
    ];
  }

  // ---- tokens ----

  drawTokens() {
    const tokens = this.tokens;
    this.tokenTable.update({ rows: tokens ?? [], loading: tokens === null && this.tokensError === null });
    this.tokenTable.node.hidden = tokens === null && this.tokensError !== null;
    mount(
      this.tokensBox,
      panel(
        w('tokens.title'),
        [],
        el('p', { class: 'tc-muted' }, w('tokens.intro')),
        this.issuedView(),
        this.tokensError !== null ? notice('bad', w('tokens.failed'), ' ', this.ctx.describe(this.tokensError)) : null,
        this.tokenTable.node,
        this.createForm(),
      ),
    );
  }

  /** The token that was just made, which is shown this once. */
  issuedView() {
    const token = held.token;
    if (token === null) return null;
    const secret = el('code', { class: 'tc-secret' }, token.text);
    return notice(
      'warn',
      el('span', { class: 'tc-notice__title' }, w('tokens.issued_title', { name: token.name })),
      el('span', {}, w('tokens.issued_warn')),
      el('span', {}, secret),
      el('span', { class: 'tc-notice__next' }, w('tokens.issued_info', { role: token.role, time: timeWords(token.expires) })),
      el(
        'div',
        { class: 'tc-actions' },
        copyButton(() => token.text, secret),
        button('primary', w('tokens.issued_done'), () => {
          held.token = null;
          this.drawTokens();
        }),
      ),
    );
  }

  createForm() {
    const own = this.ctx.user.role;
    const name = new Field(w('tokens.name'), textInput({ name: 'token-name', maxlength: '64', autocomplete: 'off', spellcheck: 'false' }), { required: true, hint: w('tokens.name_hint') });
    const role = new Field(
      w('col.role'),
      el('select', { class: 'tc-select', name: 'token-role' }, rolesUpTo(own).map((choice) => el('option', { value: choice, selected: choice === own }, choice))),
      { hint: w('tokens.role_hint', { role: own }) },
    );
    const days = new Field(
      w('tokens.days'),
      textInput({ type: 'number', name: 'token-days', min: String(DAYS.min), max: String(DAYS.max), step: '1', inputmode: 'numeric', value: String(DAYS.start) }),
      { required: true, hint: w('tokens.days_hint') },
    );
    const password = new Field(w('password.current'), passwordInput({ name: 'password', autocomplete: 'current-password' }), { required: true, hint: w('tokens.password_hint') });
    // The text of a token is shown once and a new token would take its place, so the next one waits until it is saved.
    const waiting = held.token !== null;
    const messages = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' }, waiting ? notice('info', w('tokens.issued_first')) : null);
    const submit = submitButton(w('tokens.create'));
    submit.disabled = waiting;
    return el(
      'form',
      {
        class: 'tc-form tc-form--wide',
        novalidate: true,
        on: {
          submit: async (event) => {
            event.preventDefault();
            if (submit.disabled || held.token !== null) return;
            const typed = { name: name.control.value, role: role.control.value, days: days.control.value.trim() };
            const problems = tokenProblems(typed, own);
            const secret = password.control.value;
            const entries = [
              [name, emptyOr(typed.name, problems.includes('name') ? w('tokens.p_name') : null)],
              [role, problems.includes('role') ? w('tokens.p_role') : null],
              [days, emptyOr(typed.days, problems.includes('days') ? w('tokens.p_days') : null)],
              [password, emptyOr(secret, null)],
            ];
            if (!checkFields(entries)) return;
            password.control.value = '';
            await this.ctx.guarded(
              submit,
              async () => {
                let made;
                try {
                  made = await this.ctx.api.call('POST', '/api/account/tokens', { name: typed.name, role: typed.role, days: Number(typed.days), password: secret });
                } catch (error) {
                  if (this.alive) mount(messages, notice('bad', this.ctx.describe(error, { change: true })));
                  return;
                }
                if (!this.alive) return;
                if (typeof made.token !== 'string') {
                  mount(messages, notice('bad', w('error.generic')));
                  await this.loadTokens();
                  return;
                }
                held.token = { text: made.token, name: typed.name, role: typed.role, expires: made.expires };
                await this.loadTokens();
              },
              w('tokens.create_busy'),
            );
          },
        },
      },
      el('h3', {}, w('tokens.create_title')),
      messages,
      el('div', { class: 'tc-fields' }, name.node, role.node, days.node, password.node),
      el('div', { class: 'tc-actions' }, submit),
    );
  }

  async removeToken(token) {
    const yes = await confirmChange(this.layer, { title: w('tokens.delete_title'), lines: tokenLines(token, { owner: false }), confirm: w('tokens.delete'), tone: 'danger' });
    if (!yes || !this.alive) return;
    let error = null;
    try {
      await this.ctx.api.call('DELETE', `/api/account/tokens/${encodeURIComponent(token.id)}`);
    } catch (failure) {
      error = failure;
    }
    if (!this.alive) return;
    mount(this.results, error === null ? result('ok', w('tokens.deleted_title'), w('tokens.deleted', { name: String(token.name) })) : notice('bad', this.ctx.describe(error, { change: true })));
    await this.loadTokens();
  }
}

function mountAccount(ctx, root) {
  const screen = new AccountScreen(ctx, root);
  screen.load();
  return { stop: () => screen.stop() };
}

export const screens = [{ id: 'account', title: w('nav.account'), least: 'viewer', mount: mountAccount }];
