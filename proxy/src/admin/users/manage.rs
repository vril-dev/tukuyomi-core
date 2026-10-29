//! The routes with which an owner manages the users and the tokens of others. They are for a session only, as the
//! routes of the account are: a token, whatever its role, is refused (403, written to the audit log with the reason
//! `token`). An owner's token that could set the password of another user or take the second factor away would let
//! whoever holds it log in as that user.
//!
//! - `GET /api/users`: `{"users"}`, by name, each with `name`, `role`, `disabled`, `mfa` (whether it has a second
//!   factor), `must_change`, `created` and `changed`.
//! - `POST /api/users` with `{"name", "role", "password"}`: makes the user, who must change the password at the first
//!   login. 409 when the name is taken or the store has 1000 users.
//! - `PUT /api/users/<name>` with `{"role"}` or `{"disabled"}` (one of them): changes the role or the state. The
//!   sessions of the user are closed; the tokens too when the user is disabled or the role is lowered. A disable and
//!   a lowering also move `tokens_after` of the user, so no token made before counts, also if its file stays and the
//!   user is enabled or raised again. An owner cannot lower its own role or disable itself (403), and a change that
//!   leaves no enabled owner is refused (409).
//! - `POST /api/users/<name>/password` with `{"password"}`: sets the password of another user, who must change it at
//!   the next login. The sessions and the tokens of the user are removed, and `tokens_after` moves. An owner's own
//!   password is changed with the password of the account (403): else a stolen session could set a password it knows.
//! - `DELETE /api/users/<name>/mfa`: takes the second factor of another user away, so that it is set up again
//!   (409 when there is none; 403 for an owner's own, for the same reason). The sessions are closed.
//! - `GET /api/tokens`: `{"tokens"}`, the tokens of everybody (never a secret). `DELETE /api/tokens/<id>`: removes any
//!   token.
//!
//! The changes come one at a time in the process (`Auth::lock`) and read the owner who asks and the user again under
//! it: an owner that was lowered or disabled while its request waited is refused, and two owners cannot lower each
//! other at once. Each change is written to the audit log before it is made, and is stored only if the user is still
//! the one that was read. A name that no user can have is 404.

use http::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Role, User, now_ms};
use crate::admin::audit::Outcome;
use crate::admin::auth::tokens::Token;
use crate::admin::auth::{Auth, Cx, Refusal, Who};
use crate::admin::password::{Hash, Secret, valid_name, valid_password};
use crate::admin::server::{Answer, App, Gate, Handler, Req, Route, json_body, refusal};
use crate::admin::store::{EXISTS, FULL};

const USERS: &str = "/api/users/";
const TOKENS: &str = "/api/tokens/";

/// What a route of the management does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    List,
    Create,
    Update,
    Password,
    ResetMfa,
    Tokens,
    RevokeToken,
}

impl Op {
    /// The action that the audit log calls the operation.
    pub const fn action(self) -> &'static str {
        match self {
            Op::List => "users",
            Op::Create => "user_create",
            Op::Update => "user_update",
            Op::Password => "user_password",
            Op::ResetMfa => "user_mfa",
            Op::Tokens => "tokens",
            Op::RevokeToken => "token_revoke",
        }
    }
}

const fn route(method: Method, path: &'static str, op: Op) -> Route {
    Route {
        method,
        path,
        handler: Handler::Users(op),
        least: Some(Role::Owner),
        gate: Gate::Open,
        token: false,
        action: op.action(),
    }
}

/// The routes of the management. A `*` stands for one part of the path of a request.
pub(in crate::admin) static ROUTES: [Route; 7] = [
    route(Method::GET, "/api/users", Op::List),
    route(Method::POST, "/api/users", Op::Create),
    route(Method::PUT, "/api/users/*", Op::Update),
    route(Method::POST, "/api/users/*/password", Op::Password),
    route(Method::DELETE, "/api/users/*/mfa", Op::ResetMfa),
    route(Method::GET, "/api/tokens", Op::Tokens),
    route(Method::DELETE, "/api/tokens/*", Op::RevokeToken),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    name: String,
    role: String,
    password: Secret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateBody {
    role: Option<String>,
    disabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    password: Secret,
}

/// A change of the role or of the state of a user.
enum Change {
    Role(Role),
    Disabled(bool),
}

/// The part of the path that `prefix` leaves: the name in `/api/users/<name>`, up to the next `/`.
fn name_of<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    let name = rest.split('/').next()?;
    valid_name(name).then_some(name)
}

fn user_json(user: &User) -> Value {
    json!({
        "name": user.name,
        "role": user.role.name(),
        "disabled": user.disabled,
        "mfa": user.mfa.is_some(),
        "must_change": user.must_change,
        "created": user.created,
        "changed": user.changed,
    })
}

/// A token for a list: everything but the hash.
pub(in crate::admin) fn token_json(token: &Token, now: u64) -> Value {
    json!({
        "id": token.id,
        "owner": token.owner,
        "name": token.name,
        "role": token.role.name(),
        "created": token.created,
        "expires": token.expires,
        "expired": token.expires <= now,
        "last_used": (token.last_used != 0).then_some(token.last_used),
    })
}

impl Auth {
    /// The owner who asks, as the store has it now. Called under `lock`.
    fn owner(&self, who: &Who) -> Result<User, Refusal> {
        let user = self.current(who)?;
        if user.role < Role::Owner {
            return Err(Refusal::Denied("forbidden"));
        }
        Ok(user)
    }

    /// The user `name`. Called under `lock`.
    fn target(&self, name: &str) -> Result<User, Refusal> {
        match self.store.user(name) {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Refusal::NotFound),
            Err(_) => Err(Refusal::Unavailable),
        }
    }

    /// Every user, by name.
    fn users(&self, who: &Who) -> Result<Vec<User>, Refusal> {
        let _writing = self.lock();
        self.owner(who)?;
        let mut users = self.store.users().map_err(|_| Refusal::Unavailable)?;
        users.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(users)
    }

    /// Makes the user `name` for the owner `who`; the user must change the password at the first login.
    fn create_user(
        &self,
        who: &Who,
        name: &str,
        role: Role,
        password: &Secret,
        cx: &Cx<'_>,
    ) -> Result<User, Refusal> {
        if !valid_name(name) {
            return Err(Refusal::Invalid(
                "the name is not 1 to 32 bytes of a-z, 0-9, '.', '_' and '-'",
            ));
        }
        if !valid_password(password.as_str()) {
            return Err(Refusal::Invalid("the password is not 12 to 128 bytes"));
        }
        let hash = Hash::new(password.as_str(), self.iterations).ok_or(Refusal::Unavailable)?;
        let _writing = self.lock();
        self.owner(who)?;
        let event = |outcome| {
            who.event(cx, "user_create", outcome)
                .target(name)
                .after(role.name())
        };
        match self.store.user(name) {
            Ok(None) => {}
            Ok(Some(_)) => {
                let _ = self.audit.write(&event(Outcome::Denied).reason("exists"));
                return Err(Refusal::Conflict("the name is taken"));
            }
            Err(_) => return Err(Refusal::Unavailable),
        }
        let user = User {
            must_change: true,
            ..User::new(name, role, hash, now_ms())
        };
        self.audit
            .write(&event(Outcome::Ok))
            .map_err(|_| Refusal::Unavailable)?;
        match self.store.create(&user) {
            Ok(()) => Ok(user),
            Err(e) => {
                let (reason, refusal) = if e == EXISTS {
                    ("exists", Refusal::Conflict("the name is taken"))
                } else if e == FULL {
                    ("full", Refusal::Conflict("the store has too many users"))
                } else {
                    ("store", Refusal::Unavailable)
                };
                let _ = self.audit.write(&event(Outcome::Failed).reason(reason));
                Err(refusal)
            }
        }
    }

    /// Changes the role or the state of the user `name`.
    fn change_user(
        &self,
        who: &Who,
        name: &str,
        change: Change,
        cx: &Cx<'_>,
    ) -> Result<User, Refusal> {
        let _writing = self.lock();
        let actor = self.owner(who)?;
        let target = self.target(name)?;
        let mut next = target.clone();
        match change {
            Change::Role(role) => next.role = role,
            Change::Disabled(disabled) => next.disabled = disabled,
        }
        if next == target {
            return Ok(target);
        }
        if actor.name == target.name {
            if next.role < target.role {
                return Err(Refusal::Denied("an owner cannot lower its own role"));
            }
            if next.disabled && !target.disabled {
                return Err(Refusal::Denied("an owner cannot disable itself"));
            }
        }
        // Some enabled owner is left after the change.
        let others = self
            .store
            .users()
            .map_err(|_| Refusal::Unavailable)?
            .iter()
            .filter(|user| user.name != target.name && user.role == Role::Owner && !user.disabled)
            .count();
        if others == 0 && (next.role != Role::Owner || next.disabled) {
            return Err(Refusal::Conflict("the last enabled owner stays"));
        }
        next.changed = now_ms().max(target.changed.saturating_add(1));
        // A token whose file stays when the rights it was made under are cut must stay void when they come back.
        if (next.disabled && !target.disabled) || next.role < target.role {
            next.tokens_after = next.changed;
        }
        let (before, after) = (target.role.name(), next.role.name());
        let event = match change {
            Change::Role(_) => who
                .event(cx, "role", Outcome::Ok)
                .target(name)
                .change(before, after),
            Change::Disabled(true) => who
                .event(cx, "disable", Outcome::Ok)
                .target(name)
                .change("enabled", "disabled"),
            Change::Disabled(false) => who
                .event(cx, "enable", Outcome::Ok)
                .target(name)
                .change("disabled", "enabled"),
        };
        self.audit.write(&event).map_err(|_| Refusal::Unavailable)?;
        let action = match change {
            Change::Role(_) => "role",
            Change::Disabled(true) => "disable",
            Change::Disabled(false) => "enable",
        };
        self.replace(who, action, name, cx, target.changed, &next)?;
        self.sessions.close_user(name);
        // Every token of the user is void then, the ones that the new role would allow as well.
        if next.disabled || next.role < target.role {
            self.drop_tokens(name, None, who, cx);
        }
        Ok(next)
    }

    /// Sets the password of another user, who must change it at the next login.
    fn reset_password(
        &self,
        who: &Who,
        name: &str,
        password: &Secret,
        cx: &Cx<'_>,
    ) -> Result<User, Refusal> {
        if !valid_password(password.as_str()) {
            return Err(Refusal::Invalid("the password is not 12 to 128 bytes"));
        }
        let hash = Hash::new(password.as_str(), self.iterations).ok_or(Refusal::Unavailable)?;
        let _writing = self.lock();
        let actor = self.owner(who)?;
        if actor.name == name {
            return Err(Refusal::Denied("use the password of the account"));
        }
        let target = self.target(name)?;
        let changed = now_ms().max(target.changed.saturating_add(1));
        let next = User {
            password: hash,
            must_change: true,
            changed,
            tokens_after: changed,
            ..target.clone()
        };
        self.audit
            .write(&who.event(cx, "user_password", Outcome::Ok).target(name))
            .map_err(|_| Refusal::Unavailable)?;
        self.replace(who, "user_password", name, cx, target.changed, &next)?;
        self.sessions.close_user(name);
        self.drop_tokens(name, None, who, cx);
        Ok(next)
    }

    /// Takes the second factor of another user away.
    fn reset_mfa(&self, who: &Who, name: &str, cx: &Cx<'_>) -> Result<User, Refusal> {
        let _writing = self.lock();
        let actor = self.owner(who)?;
        if actor.name == name {
            return Err(Refusal::Denied("use the second factor of the account"));
        }
        let target = self.target(name)?;
        if target.mfa.is_none() {
            return Err(Refusal::Conflict("mfa is not set"));
        }
        let next = User {
            mfa: None,
            recovery: Vec::new(),
            changed: now_ms().max(target.changed.saturating_add(1)),
            ..target.clone()
        };
        self.audit
            .write(&who.event(cx, "user_mfa", Outcome::Ok).target(name))
            .map_err(|_| Refusal::Unavailable)?;
        self.replace(who, "user_mfa", name, cx, target.changed, &next)?;
        self.sessions.close_user(name);
        Ok(next)
    }
}

impl App {
    /// Answers a request of the route `op` for the owner `who`.
    pub(in crate::admin) fn users(&self, op: Op, req: &Req, who: &Who, cx: &Cx<'_>) -> Answer {
        let auth = &self.auth;
        let found = |result: Result<User, Refusal>| match result {
            Ok(user) => Answer::json(StatusCode::OK, user_json(&user)),
            Err(why) => refusal(why),
        };
        let unknown = || refusal(Refusal::NotFound);
        match op {
            Op::List => match auth.users(who) {
                Ok(users) => Answer::json(
                    StatusCode::OK,
                    json!({ "users": users.iter().map(user_json).collect::<Vec<_>>() }),
                ),
                Err(why) => refusal(why),
            },
            Op::Create => {
                let body: CreateBody = match json_body(req) {
                    Ok(body) => body,
                    Err(answer) => return answer,
                };
                let Some(role) = Role::parse(&body.role) else {
                    return refusal(Refusal::Invalid(
                        "the role is not viewer, operator or owner",
                    ));
                };
                found(auth.create_user(who, &body.name, role, &body.password, cx))
            }
            Op::Update => {
                let Some(name) = name_of(&req.path, USERS) else {
                    return unknown();
                };
                let body: UpdateBody = match json_body(req) {
                    Ok(body) => body,
                    Err(answer) => return answer,
                };
                let change = match (&body.role, body.disabled) {
                    (Some(role), None) => match Role::parse(role) {
                        Some(role) => Change::Role(role),
                        None => {
                            return refusal(Refusal::Invalid(
                                "the role is not viewer, operator or owner",
                            ));
                        }
                    },
                    (None, Some(disabled)) => Change::Disabled(disabled),
                    _ => {
                        return refusal(Refusal::Invalid("give either role or disabled"));
                    }
                };
                found(auth.change_user(who, name, change, cx))
            }
            Op::Password => {
                let Some(name) = name_of(&req.path, USERS) else {
                    return unknown();
                };
                let body: PasswordBody = match json_body(req) {
                    Ok(body) => body,
                    Err(answer) => return answer,
                };
                found(auth.reset_password(who, name, &body.password, cx))
            }
            Op::ResetMfa => match name_of(&req.path, USERS) {
                Some(name) => found(auth.reset_mfa(who, name, cx)),
                None => unknown(),
            },
            Op::Tokens => match auth.tokens(None) {
                Ok(tokens) => {
                    let now = now_ms();
                    Answer::json(
                        StatusCode::OK,
                        json!({ "tokens": tokens.iter().map(|token| token_json(token, now)).collect::<Vec<_>>() }),
                    )
                }
                Err(why) => refusal(why),
            },
            Op::RevokeToken => {
                let id = req.path.strip_prefix(TOKENS).unwrap_or_default();
                match auth.revoke_token(who, id, true, cx) {
                    Ok(()) => Answer::json(StatusCode::OK, json!({})),
                    Err(why) => refusal(why),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
