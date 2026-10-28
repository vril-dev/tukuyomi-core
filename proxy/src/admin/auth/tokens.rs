//! The API tokens: a way in for a program, with a role that is not above its owner's.
//!
//! A token is `tkc_<id>_<secret>`: `id` is 16 lowercase hexadecimal digits (8 random bytes) and `secret` is 43
//! characters (32 random bytes as base64url without padding). It is shown once, when it is made. The store keeps
//! `tokens/<id>.json`: the id, the owner, the role, a name for the person (1 to 64 printable ASCII bytes), the SHA-256
//! of the secret's text, the time it was made, the time it ends and the time it was last used (0: never), the times
//! in milliseconds since the epoch. A file with another key, an id other than the one of its file, or a role, name
//! or hash that is not understood is not read.
//!
//! A person makes tokens for themself, with a role that is not above their own and an end of 1 to 365 days after
//! the time of making, at most 50 for one owner, and gives the password to make one (the same check as the change of
//! the password: see `Auth::confirm_password`). A token is sent as `Authorization: Bearer <token>`. A request with
//! a token is checked each time:
//! - the form is right and the store has the id, and the SHA-256 of the secret is the stored one (constant time);
//! - the owner is in the store and is not disabled, and its role is not below the token's: the role of the request
//!   is the token's;
//! - the token was made after the `tokens_after` of the owner (see `users`), so a token that a failed removal left
//!   behind still does not pass, also when the owner is enabled or raised again later;
//! - the token has not ended;
//! - under `admin.mfa` `required`, the owner has a second factor.
//!
//! A token that fails any of them is a miss: it is counted against the client (the limit of the login), and a client
//! that has no tries left is turned away before the token is looked at. A miss is not written to the audit log, so
//! anyone who can send a request cannot fill it. The time of use is written at most once in 10 minutes, and the
//! request goes on when it cannot be written.
//!
//! The tokens of a user are removed when the user is disabled, when its role is lowered, and when its password is
//! changed or set again (`Auth::drop_tokens`). The removal is a clean-up and is not relied on: each of these events
//! also moves `tokens_after` of the owner to the time of the event, so that no token made before it counts, whether
//! its file could be removed or not. A lowering voids every token of the user, also those whose role is not above the
//! new one: one time cannot tell the tokens apart.

use std::net::IpAddr;
use std::time::Instant;

use aws_lc_rs::constant_time;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{Auth, Authed, Cx, Refusal, Who};
use crate::acme::base64;
use crate::admin::audit::Outcome;
use crate::admin::password::{Secret, hex, random, unhex, valid_name as valid_user};
use crate::admin::store::{AdminError, EXISTS};
use crate::admin::users::{Role, now_ms};
use crate::rules::bundle::sha256;

/// The file of a token has a content that is not a token.
pub const BROKEN: AdminError = AdminError("a token file is broken");
const PREFIX: &str = "tkc_";
const ID_CHARS: usize = 16;
const SECRET_CHARS: usize = 43;
/// The most days a token lives.
pub const DAYS_MAX: u32 = 365;
/// The most tokens of one owner.
pub const PER_OWNER: usize = 50;
/// The most bytes of the name of a token.
pub const NAME_MAX: usize = 64;
/// The time between two writes of the time of use of a token, in milliseconds.
const TOUCH_EVERY_MS: u64 = 10 * 60 * 1000;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Whether `id` is the id of a token.
pub fn valid_id(id: &str) -> bool {
    id.len() == ID_CHARS && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `name` is a name for a token: 1 to 64 printable ASCII bytes.
pub fn valid_name(name: &str) -> bool {
    (1..=NAME_MAX).contains(&name.len()) && name.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// The id and the secret of the token `text`, if it has the form.
pub(crate) fn parse(text: &str) -> Option<(&str, &str)> {
    let (id, secret) = text.strip_prefix(PREFIX)?.split_once('_')?;
    let shaped = valid_id(id)
        && secret.len() == SECRET_CHARS
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    shaped.then_some((id, secret))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    id: String,
    owner: String,
    role: String,
    name: String,
    hash: String,
    created: u64,
    expires: u64,
    last_used: u64,
}

/// A token as the store keeps it: never the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub id: String,
    pub owner: String,
    pub role: Role,
    pub name: String,
    hash: [u8; 32],
    pub created: u64,
    pub expires: u64,
    /// When the token was last used, or 0.
    pub last_used: u64,
}

impl Token {
    /// The bytes of the file of the token.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        serde_json::to_vec(&Stored {
            id: self.id.clone(),
            owner: self.owner.clone(),
            role: self.role.name().to_owned(),
            name: self.name.clone(),
            hash: hex(&self.hash),
            created: self.created,
            expires: self.expires,
            last_used: self.last_used,
        })
        .map_err(|_| AdminError("a token cannot be written"))
    }

    /// The token in `bytes`, which must be the file of the token `id`.
    pub fn decode(bytes: &[u8], id: &str) -> Result<Token, AdminError> {
        let stored: Stored = serde_json::from_slice(bytes).map_err(|_| BROKEN)?;
        if stored.id != id
            || !valid_id(id)
            || !valid_user(&stored.owner)
            || !valid_name(&stored.name)
        {
            return Err(BROKEN);
        }
        Ok(Token {
            id: stored.id,
            owner: stored.owner,
            role: Role::parse(&stored.role).ok_or(BROKEN)?,
            name: stored.name,
            hash: unhex(&stored.hash).ok_or(BROKEN)?,
            created: stored.created,
            expires: stored.expires,
            last_used: stored.last_used,
        })
    }

    /// Whether `secret` is the secret of this token.
    fn verifies(&self, secret: &str) -> bool {
        constant_time::verify_slices_are_equal(&sha256(secret.as_bytes()), &self.hash).is_ok()
    }
}

/// A new token for `owner` made at `created` that lives `days`: its text, shown once, and the record. None: no
/// random number.
pub(crate) fn mint(
    owner: &str,
    role: Role,
    name: &str,
    created: u64,
    days: u32,
) -> Option<(Secret, Token)> {
    let mut id = [0u8; ID_CHARS / 2];
    let mut secret = [0u8; 32];
    let drawn = random(&mut id) && random(&mut secret);
    let id = hex(&id);
    let secret_text = Secret::new(base64::url(&secret));
    secret.zeroize();
    if !drawn {
        return None;
    }
    let token = Token {
        hash: sha256(secret_text.as_str().as_bytes()),
        id,
        owner: owner.to_owned(),
        role,
        name: name.to_owned(),
        created,
        expires: created.saturating_add(u64::from(days) * DAY_MS),
        last_used: 0,
    };
    let text = Secret::new(format!("{PREFIX}{}_{}", token.id, secret_text.as_str()));
    Some((text, token))
}

/// A token that was made.
pub struct Created {
    /// The text of the token, shown once.
    pub text: Secret,
    pub token: Token,
}

impl Auth {
    /// The user of a request with the token `text`, or why not. See the module for the checks.
    pub(super) fn token(&self, text: &str, client: IpAddr, now: Instant) -> Authed {
        if self.guard.exhausted(client, now) {
            return Authed::Limited;
        }
        let miss = || {
            let _ = self.guard.allow_client(client, now);
            Authed::Unauthorized
        };
        let Some((id, secret)) = parse(text) else {
            return miss();
        };
        let token = match self.store.token(id) {
            Ok(Some(token)) => token,
            Ok(None) => return miss(),
            Err(_) => return Authed::Unavailable,
        };
        if !token.verifies(secret) {
            return miss();
        }
        let user = match self.store.user(&token.owner) {
            Ok(Some(user)) => user,
            Ok(None) => return miss(),
            Err(_) => return Authed::Unavailable,
        };
        let at = now_ms();
        let live = !user.disabled
            && user.role >= token.role
            && token.created > user.tokens_after
            && token.expires > at
            && !(self.mfa_required && user.mfa.is_none());
        if !live {
            return miss();
        }
        if at.saturating_sub(token.last_used) >= TOUCH_EVERY_MS {
            let _ = self.store.touch_token(&token.id, at);
        }
        let mut who = self.who(&user, token.role);
        who.auth = Some(format!("token:{}", token.id));
        Authed::Who(who)
    }

    /// Makes a token with `role` for `who`, who is logged in with a session and gives the `password`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_token(
        &self,
        who: &Who,
        name: &str,
        role: Role,
        days: u32,
        password: &Secret,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Result<Created, Refusal> {
        if !valid_name(name) {
            return Err(Refusal::Invalid(
                "the name of a token is not 1 to 64 printable ASCII bytes",
            ));
        }
        if !(1..=DAYS_MAX).contains(&days) {
            return Err(Refusal::Invalid("days is not 1 to 365"));
        }
        // The password is checked before the lock is taken: the hash takes long and nobody else may wait for it.
        let seen = self.current(who)?;
        self.confirm_password(who, &seen, password, "token_create", cx, now)?;
        let _writing = self.lock();
        // The user is read again: if it was changed meanwhile, the password that was checked is not its.
        let user = self.current(who)?;
        if role > user.role {
            return Err(Refusal::Denied("the role is above the role of the user"));
        }
        let held = self
            .store
            .tokens()
            .map_err(|_| Refusal::Unavailable)?
            .iter()
            .filter(|token| token.owner == user.name)
            .count();
        if held >= PER_OWNER {
            return Err(Refusal::Conflict("the user has too many tokens"));
        }
        // After `tokens_after`, also within the same millisecond: the check of a token needs it.
        let created = now_ms().max(user.tokens_after.saturating_add(1));
        let (text, token) =
            mint(&user.name, role, name, created, days).ok_or(Refusal::Unavailable)?;
        let event = |outcome| {
            who.event(cx, "token_create", outcome)
                .target(&token.id)
                .after(role.name())
        };
        self.audit
            .write(&event(Outcome::Ok))
            .map_err(|_| Refusal::Unavailable)?;
        if let Err(e) = self.store.create_token(&token) {
            let reason = if e == EXISTS { "exists" } else { "store" };
            let _ = self.audit.write(&event(Outcome::Failed).reason(reason));
            return Err(Refusal::Unavailable);
        }
        Ok(Created { text, token })
    }

    /// The tokens of `owner`, or all of them, the newest first.
    pub fn tokens(&self, owner: Option<&str>) -> Result<Vec<Token>, Refusal> {
        let mut tokens = self.store.tokens().map_err(|_| Refusal::Unavailable)?;
        if let Some(owner) = owner {
            tokens.retain(|token| token.owner == owner);
        }
        tokens.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
        Ok(tokens)
    }

    /// Removes the token `id`: one of `who`'s own, or any when `any_owner`.
    pub fn revoke_token(
        &self,
        who: &Who,
        id: &str,
        any_owner: bool,
        cx: &Cx<'_>,
    ) -> Result<(), Refusal> {
        if !valid_id(id) {
            return Err(Refusal::NotFound);
        }
        let _writing = self.lock();
        let token = match self.store.token(id) {
            Ok(Some(token)) if any_owner || token.owner == who.name => token,
            Ok(_) => return Err(Refusal::NotFound),
            Err(_) => return Err(Refusal::Unavailable),
        };
        let event = |outcome| who.event(cx, "token_revoke", outcome).target(&token.id);
        self.audit
            .write(&event(Outcome::Ok))
            .map_err(|_| Refusal::Unavailable)?;
        if self.store.remove_token(id).is_err() {
            let _ = self.audit.write(&event(Outcome::Failed).reason("store"));
            return Err(Refusal::Unavailable);
        }
        Ok(())
    }

    /// Removes the tokens of `owner` whose role is above `above`, all of them for none, because the rights they were
    /// made under are gone. A token that stays is refused when it is used (see the module); the failure is written.
    pub(crate) fn drop_tokens(&self, owner: &str, above: Option<Role>, who: &Who, cx: &Cx<'_>) {
        if self.store.remove_tokens(owner, above).is_err() {
            let _ = self.audit.write(
                &who.event(cx, "token_revoke", Outcome::Failed)
                    .target(owner)
                    .reason("store"),
            );
        }
    }
}

#[cfg(test)]
mod tests;
