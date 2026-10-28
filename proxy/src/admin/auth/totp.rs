//! The second factor: the time-based one-time password (RFC 6238) and the recovery codes, and the parts of the
//! account that use them.
//!
//! A code is the HMAC-SHA1 of the number of the 30-second step since the epoch, cut to 6 digits (RFC 4226, section
//! 5.3). The seed is 20 random bytes, given to the person as base32 (RFC 4648, no padding) and in an `otpauth://`
//! address with the issuer `tukuyomi-core` and the name of the user as the account. The code of the step before and
//! of the step after the present one is taken as well. A step is taken once: the user keeps the last step that was
//! used, and a code of a step that is not after it is refused, so a code that was seen cannot be used again. Every
//! candidate is compared with the code that was given, in constant time, and all three are compared whatever the
//! first one says.
//!
//! A user has 10 recovery codes, each 16 characters of `A-Z` and `2-7` (10 random bytes in base32), made when the
//! second factor is set up and shown once. They are kept as SHA-256, every one is compared in constant time, and a
//! code that was used is removed. A person gives either a code or a recovery code, never both.
//!
//! The parts of the account here, as methods of `Auth`:
//! - `mfa_verify`: the second step of a login. The session is the pending one that the password opened. A wrong
//!   code, and any code while the user is locked, counts as a failed login for the user and for the client; on
//!   success the failures are cleared, the pending session is closed and a session of the full kind is opened (so
//!   the id and the CSRF token are new). The last step, or the recovery code, is written without a new `changed`:
//!   it is no change of the rights, and the other sessions of the user must stay.
//! - `mfa_setup`: with the password. A seed is made and kept in the session only, for 10 minutes.
//! - `mfa_confirm`: with a code of that seed. The seed, the recovery codes and the last step are stored, the other
//!   sessions of the user are closed, and a new session is opened for the request.
//! - `mfa_disable`: with the password and a code or a recovery code; refused when `admin.mfa` is `required`.
//!
//! Each of them reads the user again under the lock of this process, and every change is written to the audit log
//! before it is made.

use std::fmt;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::{constant_time, hmac};
use zeroize::Zeroize;

use super::{Auth, Cx, Entered, Next, Refusal, Who};
use crate::admin::audit::Outcome;
use crate::admin::password::{Secret, random};
use crate::admin::session::Opened;
use crate::admin::users::{User, now_ms};
use crate::rules::bundle::sha256;

/// The seconds of a step.
pub const STEP_SECS: u64 = 30;
/// The bytes of a seed.
pub const SEED_LEN: usize = 20;
/// The recovery codes of a user.
pub const RECOVERY_CODES: usize = 10;
/// The issuer in the address of a seed.
pub const ISSUER: &str = "tukuyomi-core";
const DIGITS: usize = 6;
const MODULUS: u32 = 1_000_000;
const RECOVERY_BYTES: usize = 10;
const RECOVERY_CHARS: usize = 16;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The seed of a second factor. It is not shown by `Debug` and its bytes are zeroed when it is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Seed([u8; SEED_LEN]);

impl Seed {
    /// A new seed from the random numbers of the provider. None: it has none.
    pub fn random() -> Option<Seed> {
        let mut bytes = [0u8; SEED_LEN];
        let drawn = random(&mut bytes);
        let seed = drawn.then_some(Seed(bytes));
        bytes.zeroize();
        seed
    }

    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> Seed {
        Seed(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// The second factor of a user: the seed and the last step that was used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totp {
    pub seed: Seed,
    pub last_step: u64,
}

/// The seconds since the epoch now.
pub fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The code of `seed` for `step`: HOTP (RFC 4226) with HMAC-SHA1 and 6 digits.
pub fn code(seed: &Seed, step: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed.as_bytes());
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let digest = tag.as_ref();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let truncated = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    truncated % MODULUS
}

/// The step that `given` is the code of, if it is one that may be used at `now_secs`: the present step or the one
/// before or after, and after `last_step`. `given` must be exactly 6 digits. When two of the steps give the same
/// code, the later one is returned.
pub fn check(seed: &Seed, last_step: u64, given: &str, now_secs: u64) -> Option<u64> {
    if given.len() != DIGITS || !given.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let step = now_secs / STEP_SECS;
    let mut found: Option<u64> = None;
    for candidate in [step.saturating_sub(1), step, step.saturating_add(1)] {
        let expected = format!("{:0width$}", code(seed, candidate), width = DIGITS);
        let same = constant_time::verify_slices_are_equal(expected.as_bytes(), given.as_bytes());
        if same.is_ok() && candidate > last_step {
            found = Some(found.map_or(candidate, |best| best.max(candidate)));
        }
    }
    found
}

/// `bytes` in base32 (RFC 4648) without padding.
pub fn base32(bytes: &[u8]) -> String {
    let letter = |bits: u32| char::from(BASE32[usize::from(u8::try_from(bits & 31).unwrap_or(0))]);
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut held = 0u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        held += 8;
        while held >= 5 {
            held -= 5;
            out.push(letter(buffer >> held));
        }
        buffer &= (1 << held) - 1;
    }
    if held > 0 {
        out.push(letter(buffer << (5 - held)));
    }
    out
}

/// `text` with every byte but a letter, a digit and `-._~` as `%XX`.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The address that an authenticator application reads, for the user `account`.
pub fn uri(account: &str, seed: &Seed) -> String {
    let issuer = escape(ISSUER);
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        account = escape(account),
        secret = base32(seed.as_bytes()),
    )
}

/// New recovery codes. None: no random number.
pub fn recovery_codes() -> Option<Vec<String>> {
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        let mut bytes = [0u8; RECOVERY_BYTES];
        let drawn = random(&mut bytes);
        let code = base32(&bytes);
        bytes.zeroize();
        if !drawn {
            return None;
        }
        codes.push(code);
    }
    Some(codes)
}

/// What a recovery code is kept as.
pub fn recovery_hash(code: &str) -> [u8; 32] {
    sha256(code.as_bytes())
}

/// The place of `given` among the kept `hashes`. Every hash is compared.
pub fn recovery_match(hashes: &[[u8; 32]], given: &str) -> Option<usize> {
    let shaped = given.len() == RECOVERY_CHARS && given.bytes().all(|b| BASE32.contains(&b));
    if !shaped {
        return None;
    }
    let digest = recovery_hash(given);
    let mut found = None;
    for (at, hash) in hashes.iter().enumerate() {
        if constant_time::verify_slices_are_equal(hash, &digest).is_ok() {
            found = Some(at);
        }
    }
    found
}

/// What a person gives as the second factor.
#[derive(Clone, Copy)]
pub enum Proof<'a> {
    Code(&'a str),
    Recovery(&'a str),
}

/// What a proof matched.
enum Used {
    Step(u64),
    Recovery(usize),
}

/// What `proof` matches among the second factor of `user`, at `secs`.
fn matched(user: &User, proof: Proof<'_>, secs: u64) -> Option<Used> {
    let mfa = user.mfa.as_ref()?;
    match proof {
        Proof::Code(given) => check(&mfa.seed, mfa.last_step, given, secs).map(Used::Step),
        Proof::Recovery(given) => recovery_match(&user.recovery, given).map(Used::Recovery),
    }
}

/// `user` after `used` was used: the last step is the one used, or the recovery code is gone.
fn spent(user: &User, used: &Used) -> User {
    let mut next = user.clone();
    match *used {
        Used::Step(step) => {
            if let Some(mfa) = next.mfa.as_mut() {
                mfa.last_step = step;
            }
        }
        Used::Recovery(at) => {
            next.recovery.remove(at);
        }
    }
    next
}

/// The seed of a setup that was started, for the person to put into the application.
pub struct Started {
    /// The seed in base32.
    pub secret: String,
    pub uri: String,
}

/// The second factor that was set up.
pub struct Enrolled {
    /// The session that replaces the others; none if it could not be made.
    pub opened: Option<Opened>,
    /// The recovery codes, shown once.
    pub codes: Vec<String>,
}

impl Auth {
    /// A proof that was not right: counted against the user and written, and a lock that it makes is written too.
    fn wrong_code(
        &self,
        who: &Who,
        action: &'static str,
        locked: bool,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Refusal {
        let locking = self.guard.failed(&who.name, who.changed, now);
        let reason = if locked { "locked" } else { "wrong code" };
        let written = self.audit.write(
            &who.event(cx, action, Outcome::Denied)
                .target(&who.name)
                .reason(reason),
        );
        if locking {
            self.locked_line(cx, &who.name);
        }
        if written.is_ok() {
            Refusal::Code
        } else {
            Refusal::Unavailable
        }
    }

    /// The second step of a login, for the pending session of `who`.
    pub fn mfa_verify(
        &self,
        who: &Who,
        proof: Proof<'_>,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Result<Entered, Refusal> {
        let _writing = self.lock();
        let user = self.current(who)?;
        let locked = self.guard.locked(&user.name, user.changed, now);
        let Some(used) = matched(&user, proof, unix_secs()).filter(|_| !locked) else {
            return Err(self.wrong_code(who, "mfa", locked, cx, now));
        };
        let next = spent(&user, &used);
        let mut event = who.event(cx, "mfa", Outcome::Ok).target(&who.name);
        if matches!(used, Used::Recovery(_)) {
            event = event.reason("recovery code");
        }
        self.audit.write(&event).map_err(|_| Refusal::Unavailable)?;
        self.replace(who, "mfa", &who.name, cx, user.changed, &next)?;
        self.guard.succeeded(&user.name);
        self.sessions.close(&who.cookie);
        let opened = self
            .start(&next, false, cx, now)
            .ok_or(Refusal::Unavailable)?;
        Ok(Entered {
            opened,
            role: next.role,
            next: Next::Off,
            must_change: next.must_change,
        })
    }

    /// Starts the setup of the second factor of `who` with the password: a seed is made and kept in the session.
    pub fn mfa_setup(
        &self,
        who: &Who,
        password: &Secret,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Result<Started, Refusal> {
        let user = self.current(who)?;
        if user.mfa.is_some() {
            return Err(Refusal::Conflict("mfa is set already"));
        }
        self.confirm_password(who, &user, password, "mfa_setup", cx, now)?;
        let seed = Seed::random().ok_or(Refusal::Unavailable)?;
        self.audit
            .write(&who.event(cx, "mfa_setup", Outcome::Ok).target(&who.name))
            .map_err(|_| Refusal::Unavailable)?;
        if !self.sessions.set_setup(&who.cookie, seed.clone(), now) {
            return Err(Refusal::Gone);
        }
        Ok(Started {
            secret: base32(seed.as_bytes()),
            uri: uri(&who.name, &seed),
        })
    }

    /// Ends the setup with a code of the seed that the session holds.
    pub fn mfa_confirm(
        &self,
        who: &Who,
        given: &str,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Result<Enrolled, Refusal> {
        let _writing = self.lock();
        let user = self.current(who)?;
        if user.mfa.is_some() {
            return Err(Refusal::Conflict("mfa is set already"));
        }
        let seed = self
            .sessions
            .setup(&who.cookie, now)
            .ok_or(Refusal::Conflict(
                "mfa setup was not started or has run out",
            ))?;
        let step = check(&seed, 0, given, unix_secs()).ok_or(Refusal::Code)?;
        let codes = recovery_codes().ok_or(Refusal::Unavailable)?;
        let next = User {
            mfa: Some(Totp {
                seed,
                last_step: step,
            }),
            recovery: codes.iter().map(|code| recovery_hash(code)).collect(),
            changed: now_ms().max(user.changed.saturating_add(1)),
            ..user.clone()
        };
        self.audit
            .write(&who.event(cx, "mfa_confirm", Outcome::Ok).target(&who.name))
            .map_err(|_| Refusal::Unavailable)?;
        self.replace(who, "mfa_confirm", &who.name, cx, user.changed, &next)?;
        self.sessions.close_user(&who.name);
        Ok(Enrolled {
            opened: self.start(&next, false, cx, now),
            codes,
        })
    }

    /// Takes the second factor of `who` away, with the password and a proof. The session that replaces the others
    /// is returned, if it could be made.
    pub fn mfa_disable(
        &self,
        who: &Who,
        password: &Secret,
        proof: Proof<'_>,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Result<Option<Opened>, Refusal> {
        if self.mfa_required {
            return Err(Refusal::Denied("mfa is required"));
        }
        let seen = self.current(who)?;
        if seen.mfa.is_none() {
            return Err(Refusal::Conflict("mfa is not set"));
        }
        // The password is checked before the lock is taken: the hash takes long and nobody else may wait for it.
        self.confirm_password(who, &seen, password, "mfa_disable", cx, now)?;
        let _writing = self.lock();
        // The user is read again: if it was changed meanwhile, the password that was checked is not its.
        let user = self.current(who)?;
        let locked = self.guard.locked(&user.name, user.changed, now);
        if matched(&user, proof, unix_secs())
            .filter(|_| !locked)
            .is_none()
        {
            return Err(self.wrong_code(who, "mfa_disable", locked, cx, now));
        }
        let next = User {
            mfa: None,
            recovery: Vec::new(),
            changed: now_ms().max(user.changed.saturating_add(1)),
            ..user.clone()
        };
        self.audit
            .write(&who.event(cx, "mfa_disable", Outcome::Ok).target(&who.name))
            .map_err(|_| Refusal::Unavailable)?;
        self.replace(who, "mfa_disable", &who.name, cx, user.changed, &next)?;
        self.guard.succeeded(&user.name);
        self.sessions.close_user(&who.name);
        Ok(self.start(&next, false, cx, now))
    }
}

#[cfg(test)]
mod tests;
