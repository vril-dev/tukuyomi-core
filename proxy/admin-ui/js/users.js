// The screen of the users, for an owner: the list, a new user, and for each user the role, the state (disabled or
// enabled), the password and the second factor, which an owner sets back; and the API tokens of everyone, which an
// owner removes. Each change asks first and then tells how it ended. A user cannot be removed, only disabled, and the
// API refuses an owner's changes to its own account (the role, the state, the password and the second factor), so
// the screen does not offer them. A screen is `{ id, title, least, mount }`; `mount(ctx, root)` draws into `root` and
// gives back a function that undoes what it set up. Nothing runs when the module is loaded.

import { badge, el, mount, notice } from './dom.js';
import { t } from './i18n.js';
import { ROLES, passwordFits, tokenLines, tokenTable, when } from './account.js';
import { confirmChange, labelled, openSheet, pageHead, row, table } from './parts.js';

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

/** What is wrong with the fields of a new user, as `name`, `role` or `password`; null when nothing is. */
export function userProblem({ name, role, password }) {
  if (!NAME.test(name)) return 'name';
  if (!ROLES.includes(role)) return 'role';
  return passwordFits(password) ? null : 'password';
}

function roleSelect(current) {
  return el(
    'select',
    { class: 'input', name: 'role' },
    ROLES.map((role) => el('option', { value: role, selected: role === current }, role)),
  );
}

const PROBLEMS = {
  name: () => t('users.p_name'),
  role: () => t('users.p_role'),
  password: () => t('users.p_password'),
};

class UsersScreen {
  constructor(ctx, root) {
    this.ctx = ctx;
    this.alive = true;
    this.reads = 0;
    this.users = null;
    this.tokens = null;
    this.usersError = null;
    this.tokensError = null;
    this.layer = el('div');
    this.results = el('div', { class: 'notes', 'aria-live': 'polite' });
    this.reloadButton = el('button', { type: 'button', class: 'btn', on: { click: () => this.load() } }, t('screen.reload'));
    this.usersBox = el('section', { class: 'card' });
    this.tokensBox = el('section', { class: 'card' });
    mount(
      root,
      el(
        'div',
        { class: 'stack' },
        pageHead(t('users.title'), this.reloadButton),
        el('p', { class: 'muted' }, t('users.intro')),
        this.results,
        this.createCard(),
        this.usersBox,
        this.tokensBox,
      ),
      this.layer,
    );
    this.draw();
  }

  stop() {
    this.alive = false;
  }

  async load() {
    const asked = (this.reads += 1);
    this.reloadButton.disabled = true;
    const [users, tokens] = await Promise.allSettled([this.ctx.api.call('GET', '/api/users'), this.ctx.api.call('GET', '/api/tokens')]);
    if (!this.alive || asked !== this.reads) return;
    this.reloadButton.disabled = false;
    if (users.status === 'fulfilled') {
      this.users = Array.isArray(users.value.users) ? users.value.users : [];
      this.usersError = null;
    } else this.usersError = users.reason;
    if (tokens.status === 'fulfilled') {
      this.tokens = Array.isArray(tokens.value.tokens) ? tokens.value.tokens : [];
      this.tokensError = null;
    } else this.tokensError = tokens.reason;
    this.draw();
  }

  draw() {
    this.drawUsers();
    this.drawTokens();
  }

  // ---- a new user ----

  createCard() {
    const name = el('input', { class: 'input', type: 'text', name: 'new-user', maxlength: '32', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: true });
    const role = roleSelect('viewer');
    const password = el('input', { class: 'input', type: 'password', name: 'new-password', maxlength: '128', autocomplete: 'new-password', required: true });
    const messages = el('div', { class: 'notes', 'aria-live': 'polite' });
    const submit = el('button', { type: 'submit', class: 'btn btn-primary' }, t('users.create'));
    return el(
      'section',
      { class: 'card' },
      el('h2', {}, t('users.create_title')),
      el(
        'form',
        {
          class: 'stack',
          on: {
            submit: async (event) => {
              event.preventDefault();
              if (submit.disabled) return;
              const typed = { name: name.value, role: role.value, password: password.value };
              const problem = userProblem(typed);
              if (problem !== null) {
                mount(messages, notice('bad', PROBLEMS[problem]()));
                return;
              }
              const lines = [
                el('p', {}, t('users.create_what')),
                el('dl', { class: 'kv' }, row(t('col.name'), typed.name), row(t('col.role'), typed.role)),
              ];
              const yes = await confirmChange(this.layer, { title: t('users.create_title'), lines, confirm: t('users.create') });
              if (!yes || !this.alive) return;
              await this.ctx.guarded(submit, async () => {
                let error = null;
                try {
                  await this.ctx.api.call('POST', '/api/users', typed);
                } catch (failure) {
                  error = failure;
                }
                password.value = '';
                if (!this.alive) return;
                if (error === null) {
                  name.value = '';
                  mount(messages);
                  mount(this.results, notice('ok', t('users.created', { name: typed.name })));
                } else {
                  mount(messages, notice('bad', this.ctx.describe(error, { change: true })));
                }
                await this.load();
              });
            },
          },
        },
        messages,
        el(
          'div',
          { class: 'fields' },
          labelled(t('login.name'), name, t('users.name_hint')),
          labelled(t('col.role'), role, t('users.role_hint')),
          labelled(t('users.password'), password, t('users.password_hint')),
        ),
        el('div', { class: 'actions' }, submit),
      ),
    );
  }

  // ---- the users ----

  drawUsers() {
    const users = this.users;
    let content;
    if (users === null) {
      content = this.usersError === null ? notice('info', t('account.loading')) : notice('bad', t('users.failed'), ' ', this.ctx.describe(this.usersError));
    } else {
      content = [
        this.usersError === null ? null : notice('bad', t('users.failed'), ' ', this.ctx.describe(this.usersError)),
        table(
          [t('col.name'), t('col.role'), t('col.state'), t('col.created'), t('col.changed'), t('col.actions')],
          users.map((user) => [
            String(user.name),
            badge('muted', String(user.role)),
            el(
              'span',
              { class: 'badges' },
              user.name === this.ctx.user.name ? badge('muted', t('badge.you')) : null,
              user.disabled === true ? badge('bad', t('badge.disabled')) : null,
              user.mfa === true ? badge('ok', t('badge.mfa')) : null,
              user.must_change === true ? badge('warn', t('badge.must_change')) : null,
            ),
            when(user.created),
            when(user.changed),
            el(
              'button',
              { type: 'button', class: 'btn btn-small', 'aria-label': t('users.manage_named', { name: String(user.name) }), on: { click: () => this.manage(user) } },
              t('users.manage'),
            ),
          ]),
          t('users.caption'),
          { tight: [3, 4] },
        ),
      ];
    }
    mount(this.usersBox, el('h2', {}, t('users.list')), content);
  }

  /** Asks, sends the change, and tells how it ended; then reads the lists again. `sheet` is closed when it is sent. */
  async change({ title, lines, confirm, tone = 'primary', call, done }, sheet = null) {
    const yes = await confirmChange(this.layer, { title, lines, confirm, tone });
    if (!yes || !this.alive) return;
    let error = null;
    try {
      await call();
    } catch (failure) {
      error = failure;
    }
    if (!this.alive) return;
    if (sheet !== null) sheet.close();
    mount(this.results, error === null ? notice('ok', done) : notice(error.kind === 'conflict' || error.kind === 'unknown' ? 'warn' : 'bad', this.ctx.describe(error, { change: true })));
    await this.load();
  }

  manage(user) {
    const can = userActions(user, this.ctx.user.name);
    const sheet = openSheet(this.layer, t('users.sheet'));
    const name = encodeURIComponent(user.name);
    const person = el(
      'dl',
      { class: 'kv' },
      row(t('col.name'), String(user.name)),
      row(t('col.role'), badge('muted', String(user.role))),
      row(t('col.created'), when(user.created)),
      row(t('col.changed'), when(user.changed)),
    );
    if (can.self) {
      mount(sheet.body, person, notice('info', t('users.self')), el('a', { class: 'btn', href: '#/account', on: { click: () => sheet.close() } }, t('users.self_open')));
      return;
    }
    const parts = [person, this.roleSection(user, name, sheet)];
    parts.push(this.stateSection(user, name, can.toggle, sheet));
    parts.push(this.passwordSection(user, name, sheet));
    parts.push(this.mfaSection(user, name, can.resetMfa, sheet));
    mount(sheet.body, ...parts);
  }

  roleSection(user, name, sheet) {
    const role = roleSelect(user.role);
    const messages = el('div', { class: 'notes', 'aria-live': 'polite' });
    const start = () => {
      if (role.value === user.role) {
        mount(messages, notice('info', t('users.role_same')));
        return;
      }
      const lowered = ROLES.indexOf(role.value) < ROLES.indexOf(user.role);
      this.ctx.guarded(button, () =>
        this.change(
          {
            title: t('users.role_title'),
            lines: [
              el('p', {}, t('users.role_what', { name: user.name, from: user.role, to: role.value })),
              el('p', { class: 'small' }, lowered ? t('users.role_lowered') : t('users.role_raised')),
            ],
            confirm: t('users.role_change'),
            call: () => this.ctx.api.call('PUT', `/api/users/${name}`, { role: role.value }),
            done: t('users.role_done', { name: user.name, to: role.value }),
          },
          sheet,
        ),
      );
    };
    const button = el('button', { type: 'button', class: 'btn', on: { click: start } }, t('users.role_change'));
    return el('section', { class: 'card' }, el('h3', {}, t('col.role')), messages, labelled(t('col.role'), role, t('users.role_hint')), el('div', { class: 'actions' }, button));
  }

  stateSection(user, name, toggle, sheet) {
    const disabling = toggle === 'disable';
    const button = el(
      'button',
      {
        type: 'button',
        class: disabling ? 'btn btn-danger' : 'btn btn-primary',
        on: {
          click: () =>
            this.ctx.guarded(button, () =>
              this.change(
                {
                  title: disabling ? t('users.disable_title') : t('users.enable_title'),
                  lines: [el('p', {}, disabling ? t('users.disable_what', { name: user.name }) : t('users.enable_what', { name: user.name }))],
                  confirm: disabling ? t('users.disable') : t('users.enable'),
                  tone: disabling ? 'danger' : 'primary',
                  call: () => this.ctx.api.call('PUT', `/api/users/${name}`, { disabled: disabling }),
                  done: disabling ? t('users.disable_done', { name: user.name }) : t('users.enable_done', { name: user.name }),
                },
                sheet,
              ),
            ),
        },
      },
      disabling ? t('users.disable') : t('users.enable'),
    );
    return el('section', { class: 'card' }, el('h3', {}, t('col.state')), el('p', { class: 'muted small' }, disabling ? t('users.disable_hint') : t('users.enable_hint')), el('div', { class: 'actions' }, button));
  }

  passwordSection(user, name, sheet) {
    const password = el('input', { class: 'input', type: 'password', name: 'reset-password', maxlength: '128', autocomplete: 'new-password' });
    const messages = el('div', { class: 'notes', 'aria-live': 'polite' });
    const start = () => {
      const typed = password.value;
      if (!passwordFits(typed)) {
        mount(messages, notice('bad', t('users.p_password')));
        return;
      }
      password.value = '';
      this.ctx.guarded(button, () =>
        this.change(
          {
            title: t('users.password_title'),
            lines: [el('p', {}, t('users.password_what', { name: user.name }))],
            confirm: t('users.password_set'),
            call: () => this.ctx.api.call('POST', `/api/users/${name}/password`, { password: typed }),
            done: t('users.password_done', { name: user.name }),
          },
          sheet,
        ),
      );
    };
    const button = el('button', { type: 'button', class: 'btn', on: { click: start } }, t('users.password_set'));
    return el(
      'section',
      { class: 'card' },
      el('h3', {}, t('users.password_title')),
      el('p', { class: 'muted small' }, t('users.password_reset_hint')),
      messages,
      labelled(t('password.new'), password),
      el('div', { class: 'actions' }, button),
    );
  }

  mfaSection(user, name, allowed, sheet) {
    let content = el('p', { class: 'muted' }, t('users.mfa_none'));
    if (allowed) {
      const button = el(
        'button',
        {
          type: 'button',
          class: 'btn',
          on: {
            click: () =>
              this.ctx.guarded(button, () =>
                this.change(
                  {
                    title: t('users.mfa_title'),
                    lines: [el('p', {}, t('users.mfa_what', { name: user.name }))],
                    confirm: t('users.mfa_reset'),
                    call: () => this.ctx.api.call('DELETE', `/api/users/${name}/mfa`),
                    done: t('users.mfa_done', { name: user.name }),
                  },
                  sheet,
                ),
              ),
          },
        },
        t('users.mfa_reset'),
      );
      content = el('div', { class: 'actions' }, button);
    }
    return el('section', { class: 'card' }, el('h3', {}, t('users.mfa_title')), el('p', { class: 'muted small' }, t('users.mfa_hint')), content);
  }

  // ---- the tokens of everyone ----

  drawTokens() {
    const tokens = this.tokens;
    let content;
    if (tokens === null) {
      content = this.tokensError === null ? notice('info', t('account.loading')) : notice('bad', t('tokens.failed'), ' ', this.ctx.describe(this.tokensError));
    } else if (tokens.length === 0) {
      content = el('p', { class: 'muted' }, t('tokens.empty'));
    } else {
      content = [
        this.tokensError === null ? null : notice('bad', t('tokens.failed'), ' ', this.ctx.describe(this.tokensError)),
        tokenTable(tokens, { owner: true, remove: (token) => this.removeToken(token) }),
      ];
    }
    mount(this.tokensBox, el('h2', {}, t('tokens.all_title')), el('p', { class: 'muted' }, t('tokens.all_intro')), content);
  }

  removeToken(token) {
    return this.change({
      title: t('tokens.delete_title'),
      lines: tokenLines(token, { owner: true }),
      confirm: t('tokens.delete'),
      tone: 'danger',
      call: () => this.ctx.api.call('DELETE', `/api/tokens/${encodeURIComponent(token.id)}`),
      done: t('tokens.deleted', { name: String(token.name) }),
    });
  }
}

function mountUsers(ctx, root) {
  const screen = new UsersScreen(ctx, root);
  screen.load();
  return () => screen.stop();
}

export const screens = [{ id: 'users', title: () => t('nav.users'), least: 'owner', mount: mountUsers }];
