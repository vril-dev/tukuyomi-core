//! The routes of the account: the login with its second step, the session, the logout, the password, the second
//! factor and the tokens of the user who asks. A request with a token may use none of them (a token is for the
//! routes of the rules and the audit log), and a request with a session may use the ones that its state allows (see
//! `server`). The routes that ask for the password (its change, the setup and the removal of the second factor, the
//! making of a token) are 429 when the client has tried too often (the limit of the login, counted before any hash),
//! and a wrong password, and any try of a user who is locked, is the same 403 and counts against the lockout of the
//! user as at the login.
//!
//! - `POST /api/login` with `{"name", "password"}`: 200 with `{"name", "role", "csrf", "mfa", "must_change"}` and the
//!   cookie. `mfa` is `off` when the session counts, `verify` when the second factor must be given (the session is
//!   pending for 5 minutes), and `setup` when `admin.mfa` is `required` and the user must set one up first.
//!   `must_change` says the password must be changed. 401 `invalid credentials` for every refusal alike, 429 when the
//!   client has tried too often, 503 when the audit log or the store fails.
//! - `POST /api/login/mfa` with `{"code"}` (6 digits) or `{"recovery"}` (a recovery code), by the pending session:
//!   the same answer as a login that is complete, with a new cookie and CSRF token; a wrong code, and any code while
//!   the user is locked, is the answer of a wrong password.
//! - `POST /api/logout`: 200, and the session is closed also when the audit log cannot take its line.
//! - `GET /api/session`: `{"name", "role", "csrf", "mfa" (the user has a second factor), "recovery_left",
//!   "must_change", "state", "idle_expires_in_ms", "total_expires_in_ms"}`. `state` is `active`, `must_change` (the
//!   password must be changed first) or `mfa_setup` (the second factor must be set up first). A pending session is
//!   refused with 403 and the words `second factor required`, so that a page can show the right step after a reload.
//! - `PUT /api/account/password` with `{"current", "new"}`: 200 with the new `csrf` and a new cookie, the other
//!   sessions and the tokens of the user being closed and removed.
//! - `POST /api/account/mfa/setup` with `{"password"}`: 200 with `{"secret", "uri"}`, the seed in base32 and as an
//!   `otpauth://` address. 409 when the user has a second factor. The seed lives in the session for 10 minutes.
//! - `POST /api/account/mfa/confirm` with `{"code"}`: 200 with `{"csrf", "recovery"}` (10 codes, shown once) and a new
//!   cookie; the other sessions of the user are closed. 403 for a wrong code, 409 when no setup was started.
//! - `DELETE /api/account/mfa` with `{"password", "code"}`, the code being one of the application or a recovery code:
//!   200 with a new `csrf` and cookie. 403 when `admin.mfa` is `required`, 409 when there is no second factor.
//! - `GET /api/account/tokens`: `{"tokens"}`, the tokens of the user (never a secret). `POST /api/account/tokens` with
//!   `{"name", "role", "days", "password"}`: 200 with `{"id", "token", ...}`; the text of the token is shown once.
//!   `DELETE /api/account/tokens/<id>`: removes one of the user's own tokens (404 for another's).

use std::time::Instant;

use http::{Method, StatusCode};
use serde::Deserialize;
use serde_json::json;

use super::auth::totp::Proof;
use super::auth::{Changed, Cx, Entered, Login, Refusal, Who};
use super::password::Secret;
use super::server::{
    Answer, App, Gate, Handler, Req, Route, cleared_cookie, json_body, refusal, session_cookie,
};
use super::users::{Role, now_ms};
use crate::log::record::millis;

/// What a route of the account does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Login,
    LoginMfa,
    Logout,
    Session,
    Password,
    MfaSetup,
    MfaConfirm,
    MfaDisable,
    Tokens,
    TokenCreate,
    TokenRevoke,
}

impl Op {
    /// The action that the audit log calls the operation.
    pub const fn action(self) -> &'static str {
        match self {
            Op::Login => "login",
            Op::LoginMfa => "mfa",
            Op::Logout => "logout",
            Op::Session => "session",
            Op::Password => "password",
            Op::MfaSetup => "mfa_setup",
            Op::MfaConfirm => "mfa_confirm",
            Op::MfaDisable => "mfa_disable",
            Op::Tokens => "tokens",
            Op::TokenCreate => "token_create",
            Op::TokenRevoke => "token_revoke",
        }
    }
}

const fn route(
    method: Method,
    path: &'static str,
    op: Op,
    least: Option<Role>,
    gate: Gate,
) -> Route {
    Route {
        method,
        path,
        handler: Handler::Account(op),
        least,
        gate,
        token: false,
        action: op.action(),
    }
}

const VIEWER: Option<Role> = Some(Role::Viewer);

/// The routes of the account. A `*` stands for one part of the path of a request.
pub(in crate::admin) static ROUTES: [Route; 11] = [
    route(Method::POST, "/api/login", Op::Login, None, Gate::Open),
    route(
        Method::POST,
        "/api/login/mfa",
        Op::LoginMfa,
        VIEWER,
        Gate::Pending,
    ),
    route(
        Method::POST,
        "/api/logout",
        Op::Logout,
        VIEWER,
        Gate::Logout,
    ),
    route(
        Method::GET,
        "/api/session",
        Op::Session,
        VIEWER,
        Gate::Session,
    ),
    route(
        Method::PUT,
        "/api/account/password",
        Op::Password,
        VIEWER,
        Gate::Password,
    ),
    route(
        Method::POST,
        "/api/account/mfa/setup",
        Op::MfaSetup,
        VIEWER,
        Gate::Mfa,
    ),
    route(
        Method::POST,
        "/api/account/mfa/confirm",
        Op::MfaConfirm,
        VIEWER,
        Gate::Mfa,
    ),
    route(
        Method::DELETE,
        "/api/account/mfa",
        Op::MfaDisable,
        VIEWER,
        Gate::Mfa,
    ),
    route(
        Method::GET,
        "/api/account/tokens",
        Op::Tokens,
        VIEWER,
        Gate::Open,
    ),
    route(
        Method::POST,
        "/api/account/tokens",
        Op::TokenCreate,
        VIEWER,
        Gate::Open,
    ),
    route(
        Method::DELETE,
        "/api/account/tokens/*",
        Op::TokenRevoke,
        VIEWER,
        Gate::Open,
    ),
];

const TOKEN_PATH: &str = "/api/account/tokens/";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    name: String,
    password: Secret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    current: Secret,
    new: Secret,
}

/// A second factor given: a code or a recovery code.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofBody {
    code: Option<Secret>,
    recovery: Option<Secret>,
}

impl ProofBody {
    /// Exactly one of the two.
    fn proof(&self) -> Option<Proof<'_>> {
        match (&self.code, &self.recovery) {
            (Some(code), None) => Some(Proof::Code(code.as_str())),
            (None, Some(recovery)) => Some(Proof::Recovery(recovery.as_str())),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBody {
    password: Secret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmBody {
    code: Secret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisableBody {
    password: Secret,
    /// A code of the second factor, or a recovery code.
    code: Secret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    name: String,
    role: String,
    days: u32,
    password: Secret,
}

/// The answer to a login that is complete or pending, with the cookie.
fn entered(name: &str, entered: &Entered) -> Answer {
    Answer::json(
        StatusCode::OK,
        json!({
            "name": name,
            "role": entered.role.name(),
            "csrf": entered.opened.csrf,
            "mfa": entered.next.word(),
            "must_change": entered.must_change,
        }),
    )
    .cookie(session_cookie(&entered.opened.cookie))
}

fn session_answer(who: &Who) -> Answer {
    let state = if who.must_change {
        "must_change"
    } else if who.setup_needed {
        "mfa_setup"
    } else {
        "active"
    };
    Answer::json(
        StatusCode::OK,
        json!({
            "name": who.name,
            "role": who.role.name(),
            "csrf": who.csrf,
            "mfa": who.mfa,
            "recovery_left": who.recovery_left,
            "must_change": who.must_change,
            "state": state,
            "idle_expires_in_ms": millis(who.idle_left),
            "total_expires_in_ms": millis(who.total_left),
        }),
    )
}

/// The answer with the new `csrf` and the cookie of the session that replaced the others; a session that could not
/// be made leaves the person without one.
fn renewed(opened: Option<&crate::admin::session::Opened>, mut body: serde_json::Value) -> Answer {
    match opened {
        Some(opened) => {
            body["csrf"] = opened.csrf.clone().into();
            Answer::json(StatusCode::OK, body).cookie(session_cookie(&opened.cookie))
        }
        None => {
            body["csrf"] = serde_json::Value::Null;
            Answer::json(StatusCode::OK, body).cookie(cleared_cookie())
        }
    }
}

impl App {
    /// Answers a request of the route `op`. `who` is the user of a route that names a role.
    pub(in crate::admin) fn account(
        &self,
        op: Op,
        req: &Req,
        who: Option<&Who>,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Answer {
        match (op, who) {
            (Op::Login, _) => self.login(req, cx, now),
            (Op::LoginMfa, Some(who)) => self.login_mfa(req, who, cx, now),
            (Op::Logout, Some(who)) => {
                self.auth.logout(who, cx);
                Answer::json(StatusCode::OK, json!({})).cookie(cleared_cookie())
            }
            (Op::Session, Some(who)) => session_answer(who),
            (Op::Password, Some(who)) => self.password(req, who, cx, now),
            (Op::MfaSetup, Some(who)) => self.mfa_setup(req, who, cx, now),
            (Op::MfaConfirm, Some(who)) => self.mfa_confirm(req, who, cx, now),
            (Op::MfaDisable, Some(who)) => self.mfa_disable(req, who, cx, now),
            (Op::Tokens, Some(who)) => match self.auth.tokens(Some(&who.name)) {
                Ok(tokens) => {
                    let at = now_ms();
                    let list: Vec<_> = tokens
                        .iter()
                        .map(|token| crate::admin::users::manage::token_json(token, at))
                        .collect();
                    Answer::json(StatusCode::OK, json!({ "tokens": list }))
                }
                Err(why) => refusal(why),
            },
            (Op::TokenCreate, Some(who)) => self.token_create(req, who, cx, now),
            (Op::TokenRevoke, Some(who)) => {
                let id = req.path.strip_prefix(TOKEN_PATH).unwrap_or_default();
                match self.auth.revoke_token(who, id, false, cx) {
                    Ok(()) => Answer::json(StatusCode::OK, json!({})),
                    Err(why) => refusal(why),
                }
            }
            // A route that names a least role has a user by now.
            (_, None) => Answer::error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }

    fn login(&self, req: &Req, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: LoginBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        if !self.auth.allow_client(cx.client, now) {
            return Answer::error(StatusCode::TOO_MANY_REQUESTS, "too many tries");
        }
        match self.auth.login(&body.name, &body.password, cx, now) {
            Login::Opened(opened) => entered(&body.name, &opened),
            Login::Refused => Answer::error(StatusCode::UNAUTHORIZED, "invalid credentials"),
            Login::Unavailable => Answer::unavailable(),
        }
    }

    fn login_mfa(&self, req: &Req, who: &Who, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: ProofBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        let Some(proof) = body.proof() else {
            return Answer::error(StatusCode::BAD_REQUEST, "bad request");
        };
        if !self.auth.allow_client(cx.client, now) {
            return Answer::error(StatusCode::TOO_MANY_REQUESTS, "too many tries");
        }
        match self.auth.mfa_verify(who, proof, cx, now) {
            Ok(opened) => entered(&who.name, &opened),
            // The answer of a wrong password, so that nothing tells the two apart.
            Err(Refusal::Code) => Answer::error(StatusCode::UNAUTHORIZED, "invalid credentials"),
            Err(why) => refusal(why),
        }
    }

    fn password(&self, req: &Req, who: &Who, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: PasswordBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        if !self.auth.allow_client(cx.client, now) {
            return Answer::error(StatusCode::TOO_MANY_REQUESTS, "too many tries");
        }
        match self
            .auth
            .change_password(who, &body.current, &body.new, cx, now)
        {
            Changed::Done(opened) => renewed(opened.as_ref(), json!({})),
            Changed::Wrong => Answer::error(StatusCode::FORBIDDEN, "the current password is wrong"),
            Changed::Invalid => Answer::error(
                StatusCode::BAD_REQUEST,
                "the new password is not 12 to 128 bytes",
            ),
            Changed::Conflict => Answer::error(StatusCode::CONFLICT, "conflict"),
            Changed::Gone => Answer::error(StatusCode::UNAUTHORIZED, "unauthorized"),
            Changed::Unavailable => Answer::unavailable(),
        }
    }

    fn mfa_setup(&self, req: &Req, who: &Who, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: SetupBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        if !self.auth.allow_client(cx.client, now) {
            return Answer::error(StatusCode::TOO_MANY_REQUESTS, "too many tries");
        }
        match self.auth.mfa_setup(who, &body.password, cx, now) {
            Ok(started) => Answer::json(
                StatusCode::OK,
                json!({ "secret": started.secret, "uri": started.uri }),
            ),
            Err(why) => refusal(why),
        }
    }

    fn mfa_confirm(&self, req: &Req, who: &Who, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: ConfirmBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        match self.auth.mfa_confirm(who, body.code.as_str(), cx, now) {
            Ok(enrolled) => renewed(
                enrolled.opened.as_ref(),
                json!({ "recovery": enrolled.codes }),
            ),
            Err(why) => refusal(why),
        }
    }

    fn mfa_disable(&self, req: &Req, who: &Who, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: DisableBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        if !self.auth.allow_client(cx.client, now) {
            return Answer::error(StatusCode::TOO_MANY_REQUESTS, "too many tries");
        }
        // 6 digits are a code of the application; whatever else is taken for a recovery code, which the check refuses
        // if it is not one.
        let code = body.code.as_str();
        let proof = if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
            Proof::Code(code)
        } else {
            Proof::Recovery(code)
        };
        match self.auth.mfa_disable(who, &body.password, proof, cx, now) {
            Ok(opened) => renewed(opened.as_ref(), json!({})),
            Err(why) => refusal(why),
        }
    }

    fn token_create(&self, req: &Req, who: &Who, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: TokenBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        if !self.auth.allow_client(cx.client, now) {
            return Answer::error(StatusCode::TOO_MANY_REQUESTS, "too many tries");
        }
        let Some(role) = Role::parse(&body.role) else {
            return refusal(Refusal::Invalid(
                "the role is not viewer, operator or owner",
            ));
        };
        match self
            .auth
            .create_token(who, &body.name, role, body.days, &body.password, cx, now)
        {
            Ok(created) => {
                let mut answer = crate::admin::users::manage::token_json(&created.token, now_ms());
                answer["token"] = created.text.as_str().into();
                Answer::json(StatusCode::OK, answer)
            }
            Err(why) => refusal(why),
        }
    }
}

#[cfg(test)]
mod tests;
