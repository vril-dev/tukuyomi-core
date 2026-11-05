// The screen of the users, for an owner: the list, a new user, and for each user the role, the state (disabled or
// enabled), the password and the second factor, which an owner sets back; and the API tokens of everyone, which an
// owner removes. Each change asks first and then tells how it ended. A user cannot be removed, only disabled, and the
// API refuses an owner's changes to its own account (the role, the state, the password and the second factor), so
// the screen does not offer them. A screen is `{ id, title, least, mount }`; `mount(ctx, root)` draws into `root` and
// gives back `{ stop }`. Nothing runs when the module is loaded.

import { badge, button, buttonClass, el, mount, notice, result } from './dom.js';
import { w } from './i18n.js';
import { ROLES, passwordFits, tokenLines, tokenTable } from './account.js';
import { Field, checkFields, confirmChange, emptyField, hashOf, instantOf, kv, openDialog, pageHead, panel, restoreFocus, row, setBusy, textInput, timeCell, timeCellText, timeLabel, timeView } from './parts.js';
import { Table } from './table.js';

/** The name of a user: 1 to 32 characters of a-z, 0-9, dot, underscore and hyphen. */
const NAME = /^[a-z0-9._-]{1,32}$/;

/**
 * What an owner may do with `user` on this screen, when the owner is `own`: the `role` to change, `toggle` (`disable`
 * or `enable`, or null), the `password` to set again and the second factor to take away (`resetMfa`, only when the user
 * has one). The owner's own account has none of them (`self`).
 */
export function userActions(user, own) {
  if (user.name === own) return { self: true, role: false, toggle: null, password: false, resetMfa: false };
  return { self: false, role: true, toggle: user.disabled === true ? 'enable' : 'disable', password: true, resetMfa: user.mfa === true };
}

/** The fields of a new user that are wrong, in the order of the form: `name`, `role` and `password`; none when all are right. */
export function userProblems({ name, role, password }) {
  return [NAME.test(name) ? null : 'name', ROLES.includes(role) ? null : 'role', passwordFits(password) ? null : 'password'].filter((field) => field !== null);
}

function roleSelect(current) {
  return el(
    'select',
    { class: 'tc-select', name: 'role' },
    ROLES.map((role) => el('option', { value: role, selected: role === current }, role)),
  );
}

/** The tone and the words of each state of a user that the list shows. */
const STATES = {
  you: ['info', () => w('badge.you')],
  disabled: ['bad', () => w('badge.disabled')],
  mfa: ['ok', () => w('badge.mfa')],
  must_change: ['warn', () => w('badge.must_change')],
};

const emptyOr = (value, problem) => (value === '' ? emptyField() : problem);

class UsersScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.root = root;
    this.alive = true;
    this.reads = 0;
    this.users = null;
    this.tokens = null;
    this.usersError = null;
    this.tokensError = null;
    this.layer = el('div');
    this.results = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' });
    this.reloadButton = button('', w('screen.reload'), () => this.load());
    this.usersBox = el('div', { class: 'tc-stack' });
    this.tokensBox = el('div', { class: 'tc-stack' });
    this.table = new Table({
      caption: w('users.caption'),
      rowKey: (user) => String(user.name),
      empty: { title: w('users.empty') },
      columns: [
        { key: 'name', label: w('col.name'), value: (user) => String(user.name) },
        { key: 'role', label: w('col.role'), value: (user) => String(user.role), cell: (user) => badge('muted', String(user.role)) },
        {
          key: 'state',
          label: w('col.state'),
          value: (user) => this.stateWords(user).join(' '),
          text: (user) => this.stateWords(user).map((word) => STATES[word][1]().text()).join(' '),
          cell: (user) => this.stateBadges(user),
        },
        { key: 'created', label: timeLabel(w('col.created')), value: (user) => instantOf(user.created), text: (user) => timeCellText(user.created), tight: true, cell: (user) => timeCell(user.created) },
        { key: 'changed', label: timeLabel(w('col.changed')), value: (user) => instantOf(user.changed), text: (user) => timeCellText(user.changed), tight: true, cell: (user) => timeCell(user.changed) },
        {
          key: 'actions',
          label: w('col.actions'),
          value: () => '',
          sortable: false,
          filter: false,
          cell: (user) => button('small', w('users.manage'), () => this.manage(user), { 'aria-label': w('users.manage_named', { name: String(user.name) }) }),
        },
      ],
    });
    this.tokenTable = tokenTable({ owner: true, remove: (token) => this.removeToken(token) });
    mount(
      root,
      pageHead(w('users.title'), this.reloadButton),
      el('p', { class: 'tc-intro' }, w('users.intro')),
      this.results,
      this.createPanel(),
      this.usersBox,
      this.tokensBox,
      this.layer,
    );
    this.draw();
  }

  stop() {
    this.alive = false;
  }

  async load() {
    const asked = (this.reads += 1);
    setBusy(this.reloadButton, true);
    const [users, tokens] = await Promise.allSettled([this.ctx.api.call('GET', '/api/users'), this.ctx.api.call('GET', '/api/tokens')]);
    if (!this.alive || asked !== this.reads) return;
    setBusy(this.reloadButton, false);
    if (users.status === 'fulfilled') {
      this.users = Array.isArray(users.value.users) ? users.value.users : [];
      this.usersError = null;
    } else this.usersError = users.reason;
    if (tokens.status === 'fulfilled') {
      this.tokens = Array.isArray(tokens.value.tokens) ? tokens.value.tokens : [];
      this.tokensError = null;
    } else this.tokensError = tokens.reason;
    this.draw();
    restoreFocus(this.root, this.root.querySelector('h1'));
  }

  draw() {
    this.drawUsers();
    this.drawTokens();
  }

  // ---- a new user ----

  createPanel() {
    const name = new Field(w('login.name'), textInput({ name: 'new-user', maxlength: '32', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' }), { required: true, hint: w('users.name_hint') });
    const role = new Field(w('col.role'), roleSelect('viewer'), { hint: w('users.role_hint') });
    const password = new Field(w('users.password'), textInput({ type: 'password', name: 'new-password', maxlength: '128', autocomplete: 'new-password' }), { required: true, hint: w('users.password_hint') });
    const messages = el('div', { class: 'tc-notes tc-stack', 'aria-live': 'polite' });
    const submit = button('primary', w('users.create'), null, { type: 'submit' });
    return panel(
      w('users.create_title'),
      [],
      el(
        'form',
        {
          class: 'tc-form tc-form--wide',
          novalidate: true,
          on: {
            submit: async (event) => {
              event.preventDefault();
              if (submit.disabled) return;
              const typed = { name: name.control.value, role: role.control.value, password: password.control.value };
              const problems = userProblems(typed);
              const entries = [
                [name, emptyOr(typed.name, problems.includes('name') ? w('users.p_name') : null)],
                [role, problems.includes('role') ? w('users.p_role') : null],
                [password, emptyOr(typed.password, problems.includes('password') ? w('users.p_password') : null)],
              ];
              if (!checkFields(entries)) return;
              const yes = await confirmChange(this.layer, {
                title: w('users.create_ask'),
                lines: [el('p', {}, w('users.create_what')), kv(row(w('col.name'), typed.name), row(w('col.role'), typed.role))],
                confirm: w('users.create'),
              });
              if (!yes || !this.alive) return;
              await this.ctx.guarded(
                submit,
                async () => {
                  let error = null;
                  try {
                    await this.ctx.api.call('POST', '/api/users', typed);
                  } catch (failure) {
                    error = failure;
                  }
                  password.control.value = '';
                  if (!this.alive) return;
                  if (error === null) {
                    name.control.value = '';
                    mount(messages);
                    mount(this.results, result('ok', w('users.created_title'), w('users.created', { name: typed.name })));
                  } else {
                    mount(messages, notice('bad', this.ctx.describe(error, { change: true })));
                  }
                  await this.load();
                },
                w('users.create_busy'),
              );
            },
          },
        },
        messages,
        el('div', { class: 'tc-fields' }, name.node, role.node, password.node),
        el('div', { class: 'tc-actions' }, submit),
      ),
    );
  }

  // ---- the users ----

  stateWords(user) {
    return [
      user.name === this.ctx.user.name ? 'you' : null,
      user.disabled === true ? 'disabled' : null,
      user.mfa === true ? 'mfa' : null,
      user.must_change === true ? 'must_change' : null,
    ].filter((word) => word !== null);
  }

  stateBadges(user) {
    const words = this.stateWords(user);
    return words.length === 0 ? null : el('span', { class: 'tc-badges' }, words.map((word) => badge(STATES[word][0], STATES[word][1]())));
  }

  drawUsers() {
    this.table.update({ rows: this.users ?? [], loading: this.users === null && this.usersError === null });
    this.table.node.hidden = this.users === null && this.usersError !== null;
    mount(
      this.usersBox,
      panel(w('users.list'), [], this.usersError === null ? null : notice('bad', w('users.failed'), ' ', this.ctx.describe(this.usersError)), this.table.node),
    );
  }

  /** Asks, sends the change, and tells how it ended; then reads the lists again. `dialog` is closed when it is sent. */
  async change({ title, lines, confirm, tone = 'primary', call, done }, dialog = null) {
    const yes = await confirmChange(this.layer, { title, lines, confirm, tone });
    if (!yes || !this.alive) return;
    let error = null;
    try {
      await call();
    } catch (failure) {
      error = failure;
    }
    if (!this.alive) return;
    if (dialog !== null) dialog.close();
    mount(this.results, error === null ? result('ok', w('users.done_title'), done) : notice(error.kind === 'conflict' || error.kind === 'unknown' ? 'warn' : 'bad', this.ctx.describe(error, { change: true })));
    await this.load();
  }

  manage(user) {
    const can = userActions(user, this.ctx.user.name);
    const dialog = openDialog(this.layer, w('users.sheet'));
    const name = encodeURIComponent(user.name);
    const person = kv(
      row(w('col.name'), String(user.name)),
      row(w('col.role'), badge('muted', String(user.role))),
      row(w('col.created'), timeView(user.created)),
      row(w('col.changed'), timeView(user.changed)),
    );
    if (can.self) {
      mount(dialog.body, person, notice('info', w('users.self')), el('a', { class: buttonClass(''), href: hashOf('account'), on: { click: () => dialog.close() } }, w('users.self_open')));
      return;
    }
    mount(dialog.body, person, this.roleSection(user, name, dialog), this.stateSection(user, name, can.toggle, dialog), this.passwordSection(user, name, dialog), this.mfaSection(user, name, can.resetMfa, dialog));
  }

  roleSection(user, name, dialog) {
    const field = new Field(w('col.role'), roleSelect(user.role), { hint: w('users.role_hint') });
    const start = () => {
      const chosen = field.control.value;
      if (chosen === user.role) {
        field.invalid(w('users.role_same'));
        field.control.focus();
        return;
      }
      field.valid();
      const lowered = ROLES.indexOf(chosen) < ROLES.indexOf(user.role);
      this.ctx.guarded(change, () =>
        this.change(
          {
            title: w('users.role_title'),
            lines: [el('p', {}, w('users.role_what', { name: user.name, from: user.role, to: chosen })), el('p', { class: 'tc-muted tc-small' }, lowered ? w('users.role_lowered') : w('users.role_raised'))],
            confirm: w('users.role_change'),
            call: () => this.ctx.api.call('PUT', `/api/users/${name}`, { role: chosen }),
            done: w('users.role_done', { name: user.name, to: chosen }),
          },
          dialog,
        ),
      );
    };
    const change = button('', w('users.role_change'), start);
    return el('section', { class: 'tc-stack' }, el('h3', {}, w('col.role')), field.node, el('div', { class: 'tc-actions' }, change));
  }

  stateSection(user, name, toggle, dialog) {
    const disabling = toggle === 'disable';
    const act = button(
      disabling ? 'danger' : '',
      disabling ? w('users.disable') : w('users.enable'),
      () =>
        this.ctx.guarded(act, () =>
          this.change(
            {
              title: disabling ? w('users.disable_title') : w('users.enable_title'),
              lines: [el('p', {}, disabling ? w('users.disable_what', { name: user.name }) : w('users.enable_what', { name: user.name }))],
              confirm: disabling ? w('users.disable') : w('users.enable'),
              tone: disabling ? 'danger' : 'primary',
              call: () => this.ctx.api.call('PUT', `/api/users/${name}`, { disabled: disabling }),
              done: disabling ? w('users.disable_done', { name: user.name }) : w('users.enable_done', { name: user.name }),
            },
            dialog,
          ),
        ),
    );
    return el('section', { class: 'tc-stack' }, el('h3', {}, w('col.state')), el('p', { class: 'tc-muted tc-small' }, disabling ? w('users.disable_hint') : w('users.enable_hint')), el('div', { class: 'tc-actions' }, act));
  }

  passwordSection(user, name, dialog) {
    const field = new Field(w('password.new'), textInput({ type: 'password', name: 'reset-password', maxlength: '128', autocomplete: 'new-password' }), { required: true, hint: w('users.password_reset_hint') });
    const start = () => {
      const typed = field.control.value;
      if (!checkFields([[field, emptyOr(typed, passwordFits(typed) ? null : w('users.p_password'))]])) return;
      field.control.value = '';
      this.ctx.guarded(set, () =>
        this.change(
          {
            title: w('users.password_ask'),
            lines: [el('p', {}, w('users.password_what', { name: user.name }))],
            confirm: w('users.password_set'),
            call: () => this.ctx.api.call('POST', `/api/users/${name}/password`, { password: typed }),
            done: w('users.password_done', { name: user.name }),
          },
          dialog,
        ),
      );
    };
    const set = button('', w('users.password_set'), start);
    return el('section', { class: 'tc-stack' }, el('h3', {}, w('users.password_title')), field.node, el('div', { class: 'tc-actions' }, set));
  }

  mfaSection(user, name, allowed, dialog) {
    let content = el('p', { class: 'tc-muted' }, w('users.mfa_none'));
    if (allowed) {
      const reset = button('danger', w('users.mfa_reset'), () =>
        this.ctx.guarded(reset, () =>
          this.change(
            {
              title: w('users.mfa_ask'),
              lines: [el('p', {}, w('users.mfa_what', { name: user.name }))],
              confirm: w('users.mfa_reset'),
              tone: 'danger',
              call: () => this.ctx.api.call('DELETE', `/api/users/${name}/mfa`),
              done: w('users.mfa_done', { name: user.name }),
            },
            dialog,
          ),
        ),
      );
      content = el('div', { class: 'tc-actions' }, reset);
    }
    return el('section', { class: 'tc-stack' }, el('h3', {}, w('users.mfa_title')), el('p', { class: 'tc-muted tc-small' }, w('users.mfa_hint')), content);
  }

  // ---- the tokens of everyone ----

  drawTokens() {
    const tokens = this.tokens;
    this.tokenTable.update({ rows: tokens ?? [], loading: tokens === null && this.tokensError === null });
    this.tokenTable.node.hidden = tokens === null && this.tokensError !== null;
    mount(
      this.tokensBox,
      panel(w('tokens.all_title'), [], el('p', { class: 'tc-muted' }, w('tokens.all_intro')), this.tokensError === null ? null : notice('bad', w('tokens.failed'), ' ', this.ctx.describe(this.tokensError)), this.tokenTable.node),
    );
  }

  removeToken(token) {
    return this.change({
      title: w('tokens.delete_title'),
      lines: tokenLines(token, { owner: true }),
      confirm: w('tokens.delete'),
      tone: 'danger',
      call: () => this.ctx.api.call('DELETE', `/api/tokens/${encodeURIComponent(token.id)}`),
      done: w('tokens.deleted', { name: String(token.name) }),
    });
  }
}

function mountUsers(ctx, root) {
  const screen = new UsersScreen(ctx, root);
  screen.load();
  return { stop: () => screen.stop() };
}

export const screens = [{ id: 'users', title: w('nav.users'), least: 'owner', mount: mountUsers }];
