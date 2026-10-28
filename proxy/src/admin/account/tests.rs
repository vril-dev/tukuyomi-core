use serde_json::{Value, json};

use super::*;
use crate::admin::auth::tokens::{self, Token};
use crate::admin::auth::totp::{self, Seed, Totp};
use crate::admin::file_store::FileAdminStore;
use crate::admin::server::COOKIE_NAME;
use crate::admin::server::tests::{
    JSON_TYPE, PASSWORD, Rig, Session, alter_user, rig, rig_with, session_of,
};
use crate::admin::store::AdminStore;
use crate::config::Mfa;

const SECRET_SEED: [u8; totp::SEED_LEN] = [7; totp::SEED_LEN];

/// Gives the user `name` the second factor with the seed `SECRET_SEED`, and returns the recovery codes.
fn enrol(rig: &Rig, name: &str) -> Vec<String> {
    let codes = totp::recovery_codes().unwrap();
    let hashes: Vec<[u8; 32]> = codes.iter().map(|code| totp::recovery_hash(code)).collect();
    alter_user(rig, name, |user| {
        user.mfa = Some(Totp {
            seed: Seed::from_bytes(SECRET_SEED),
            last_step: 0,
        });
        user.recovery = hashes;
    });
    codes
}

/// The code of the seed of `enrol` for the present step and `ahead` steps later.
fn code_now(ahead: u64) -> String {
    let step = totp::unix_secs() / totp::STEP_SECS + ahead;
    format!("{:06}", totp::code(&Seed::from_bytes(SECRET_SEED), step))
}

/// A code that none of the steps around now has.
fn wrong_code() -> String {
    let seed = Seed::from_bytes(SECRET_SEED);
    let step = totp::unix_secs() / totp::STEP_SECS;
    let taken: Vec<u32> = (0..=2).map(|n| totp::code(&seed, step + n - 1)).collect();
    (123_456u32..)
        .find(|n| !taken.contains(n))
        .map(|n| format!("{n:06}"))
        .unwrap()
}

/// The answer to the second step of a login, for the pending `session`.
fn verify(rig: &Rig, session: &Session, body: Value) -> Answer {
    rig.with(session, "POST", "/api/login/mfa", &[], &body.to_string())
}

fn status(rig: &Rig, session: &Session, method: &str, path: &str) -> (StatusCode, String) {
    let answer = rig.with(session, method, path, &[], "{}");
    let words = answer.body["error"].as_str().unwrap_or_default().to_owned();
    (answer.status, words)
}

/// A request with the token, and no cookie.
fn bearer(rig: &Rig, token: &str, method: &str, path: &str, body: &str) -> Answer {
    let auth = format!("Bearer {token}");
    rig.send(
        method,
        path,
        &[JSON_TYPE, ("authorization", auth.as_str())],
        body,
    )
}

/// Makes a token through the API for the user of `session`; its id and text.
fn make_token(rig: &Rig, session: &Session, role: &str, days: u32) -> (String, String) {
    let body =
        json!({ "name": "test", "role": role, "days": days, "password": PASSWORD }).to_string();
    let answer = rig.with(session, "POST", "/api/account/tokens", &[], &body);
    assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
    (
        answer.body["id"].as_str().unwrap().to_owned(),
        answer.body["token"].as_str().unwrap().to_owned(),
    )
}

/// Puts a token for `owner` into the store, with these times; its text.
fn insert(rig: &Rig, owner: &str, role: Role, ends: u64, used: u64) -> String {
    let store = FileAdminStore::open(rig.dir.path()).unwrap();
    // After the time from which the tokens of the owner count, as the token of a person is.
    let after = store
        .user(owner)
        .unwrap()
        .map_or(0, |user| user.tokens_after + 1);
    let (text, mut token) = tokens::mint(owner, role, "inserted", now_ms().max(after), 1).unwrap();
    token.expires = ends;
    token.last_used = used;
    store.create_token(&token).unwrap();
    text.as_str().to_owned()
}

fn token_in_store(rig: &Rig, id: &str) -> Option<Token> {
    FileAdminStore::open(rig.dir.path())
        .unwrap()
        .token(id)
        .unwrap()
}

/// The base32 text decoded.
fn unbase32(text: &str) -> Vec<u8> {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut buffer, mut held) = (Vec::new(), 0u32, 0u32);
    for c in text.chars() {
        buffer = (buffer << 5) | u32::try_from(ALPHABET.find(c).unwrap()).unwrap();
        held += 5;
        if held >= 8 {
            held -= 8;
            out.push(u8::try_from((buffer >> held) & 0xff).unwrap());
        }
    }
    out
}

#[test]
fn the_second_factor_is_set_up_with_the_password_and_a_code_and_then_asked_for_at_the_login() {
    let rig = rig();
    let first = rig.login("vera");
    let second = rig.login("vera");
    // A wrong password does not start the setup; the right one gives the seed.
    let wrong = json!({ "password": "wrong password 1" }).to_string();
    let refused = rig.with(&first, "POST", "/api/account/mfa/setup", &[], &wrong);
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let right = json!({ "password": PASSWORD }).to_string();
    let started = rig.with(&first, "POST", "/api/account/mfa/setup", &[], &right);
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let secret = started.body["secret"].as_str().unwrap();
    assert!(started.body["uri"].as_str().unwrap().starts_with(&format!(
        "otpauth://totp/tukuyomi-core:vera?secret={secret}"
    )));
    let seed = Seed::from_bytes(unbase32(secret).try_into().unwrap());
    // Nothing is stored before the code is confirmed, and a code that is wrong or a setup that was not started is
    // refused.
    assert!(rig.user("vera").mfa.is_none());
    let code = format!(
        "{:06}",
        totp::code(&seed, totp::unix_secs() / totp::STEP_SECS)
    );
    let bad = json!({ "code": wrong_code() }).to_string();
    let confirm = |session: &Session, body: &str| {
        rig.with(session, "POST", "/api/account/mfa/confirm", &[], body)
    };
    assert_eq!(confirm(&first, &bad).status, StatusCode::FORBIDDEN);
    let good = json!({ "code": code }).to_string();
    assert_eq!(confirm(&second, &good).status, StatusCode::CONFLICT);
    // The confirmation stores the seed and ten recovery codes, closes the other sessions and renews this one.
    let done = confirm(&first, &good);
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    assert_eq!(done.body["recovery"].as_array().unwrap().len(), 10);
    let renewed = session_of(&done);
    assert_ne!(renewed.id, first.id);
    assert_eq!(
        status(&rig, &second, "GET", "/api/session").0,
        StatusCode::UNAUTHORIZED
    );
    let seen = rig.with(&renewed, "GET", "/api/session", &[], "");
    assert_eq!(seen.body["mfa"], true);
    assert_eq!(seen.body["recovery_left"], 10);
    let stored = rig.user("vera");
    assert_eq!(stored.mfa.as_ref().unwrap().seed, seed);
    assert_eq!(stored.recovery.len(), 10);
    // The code that confirmed is a step that was used.
    assert_eq!(confirm(&renewed, &good).status, StatusCode::CONFLICT);
    rig.with(&renewed, "POST", "/api/logout", &[], "");
    let login = rig.try_login("vera", PASSWORD);
    assert_eq!(login.body["mfa"], "verify");
    let pending = session_of(&login);
    let again = verify(&rig, &pending, json!({ "code": code }));
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    let next = format!(
        "{:06}",
        totp::code(&seed, totp::unix_secs() / totp::STEP_SECS + 1)
    );
    let entered = verify(&rig, &pending, json!({ "code": next }));
    assert_eq!(entered.status, StatusCode::OK, "{:?}", entered.body);
    assert_eq!(entered.body["mfa"], "off");
}

#[test]
fn a_code_of_the_same_step_is_refused_the_second_time_and_a_later_step_is_taken() {
    let rig = rig();
    enrol(&rig, "vera");
    // The codes are made once: a step may pass between the logins, and the same text must be sent twice.
    let (used, later) = (code_now(0), code_now(1));
    let first = session_of(&rig.try_login("vera", PASSWORD));
    let entered = verify(&rig, &first, json!({ "code": used }));
    assert_eq!(entered.status, StatusCode::OK, "{:?}", entered.body);
    // Another login with the code that was used is refused, with the answer of a wrong password.
    let second = session_of(&rig.try_login("vera", PASSWORD));
    let replay = verify(&rig, &second, json!({ "code": used }));
    let wrong = rig.try_login("vera", "wrong password 1");
    assert_eq!((replay.status, &replay.body), (wrong.status, &wrong.body));
    assert_eq!(
        verify(&rig, &second, json!({ "code": later })).status,
        StatusCode::OK
    );
    // The use of the second factor did not close the session of the first login.
    let renewed = session_of(&entered);
    assert_eq!(
        rig.with(&renewed, "GET", "/api/session", &[], "").status,
        StatusCode::OK
    );
}

#[test]
fn a_recovery_code_works_once() {
    let rig = rig();
    let codes = enrol(&rig, "vera");
    let first = session_of(&rig.try_login("vera", PASSWORD));
    let entered = verify(&rig, &first, json!({ "recovery": codes[3] }));
    assert_eq!(entered.status, StatusCode::OK, "{:?}", entered.body);
    let seen = rig.with(&session_of(&entered), "GET", "/api/session", &[], "");
    assert_eq!(seen.body["recovery_left"], 9);
    let second = session_of(&rig.try_login("vera", PASSWORD));
    assert_eq!(
        verify(&rig, &second, json!({ "recovery": codes[3] })).status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        verify(&rig, &second, json!({ "recovery": codes[4] })).status,
        StatusCode::OK
    );
    // Either a code or a recovery code, not both and not none.
    let third = session_of(&rig.try_login("vera", PASSWORD));
    for body in [
        json!({}),
        json!({ "code": code_now(1), "recovery": codes[5] }),
    ] {
        assert_eq!(verify(&rig, &third, body).status, StatusCode::BAD_REQUEST);
    }
}

#[test]
fn failed_codes_lock_the_user_like_failed_passwords_and_the_answer_is_the_same() {
    let rig = rig();
    enrol(&rig, "vera");
    let wrong_password = rig.try_login("vera", "wrong password 1");
    assert_eq!(wrong_password.status, StatusCode::UNAUTHORIZED);
    let pending = session_of(&rig.try_login("vera", PASSWORD));
    // The password step did not clear the failure of the wrong password: four failures, and the next locks.
    for n in 1..=3 {
        let answer = verify(&rig, &pending, json!({ "code": wrong_code() }));
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "failure {n}");
        assert_eq!(answer.body, wrong_password.body);
    }
    let fifth = verify(&rig, &pending, json!({ "code": wrong_code() }));
    assert_eq!(fifth.status, StatusCode::UNAUTHORIZED);
    assert!(
        rig.audit()
            .iter()
            .any(|line| line["action"] == "lock" && line["target"] == "vera")
    );
    // The right code is refused now, as is the right password, with the same answer.
    let sixth = verify(&rig, &pending, json!({ "code": code_now(0) }));
    assert_eq!(
        (sixth.status, &sixth.body),
        (wrong_password.status, &wrong_password.body)
    );
    let locked = rig.try_login("vera", PASSWORD);
    assert_eq!(
        (locked.status, &locked.body),
        (wrong_password.status, &wrong_password.body)
    );
    // The failures were written as the failures of the second step.
    let failures = rig
        .audit()
        .iter()
        .filter(|line| line["action"] == "mfa" && line["result"] == "denied")
        .count();
    assert_eq!(failures, 5);
}

#[test]
fn a_pending_session_can_use_no_route_but_the_check_of_the_second_factor_and_the_logout() {
    let rig = rig();
    enrol(&rig, "alice");
    let login = rig.try_login("alice", PASSWORD);
    assert_eq!(
        (
            login.body["mfa"].as_str(),
            login.body["must_change"].as_bool()
        ),
        (Some("verify"), Some(false))
    );
    let pending = session_of(&login);
    for (method, path) in [
        ("GET", "/api/session"),
        ("GET", "/api/audit"),
        ("GET", "/api/status"),
        ("GET", "/api/users"),
        ("PUT", "/api/account/password"),
        ("POST", "/api/account/mfa/setup"),
        ("POST", "/api/account/mfa/confirm"),
        ("DELETE", "/api/account/mfa"),
        ("GET", "/api/account/tokens"),
        ("POST", "/api/account/tokens"),
    ] {
        assert_eq!(
            status(&rig, &pending, method, path),
            (StatusCode::FORBIDDEN, "second factor required".to_owned()),
            "{method} {path}"
        );
    }
    // The check needs the CSRF token of the pending session, as any change does.
    let cookie = format!("{COOKIE_NAME}={}", pending.id);
    let body = json!({ "code": code_now(0) }).to_string();
    let no_token = rig.send(
        "POST",
        "/api/login/mfa",
        &[JSON_TYPE, ("cookie", cookie.as_str())],
        &body,
    );
    assert_eq!(no_token.status, StatusCode::FORBIDDEN);
    // A session that counts is not for the check.
    let full = {
        let entered = verify(&rig, &pending, json!({ "code": code_now(0) }));
        assert_eq!(entered.status, StatusCode::OK);
        session_of(&entered)
    };
    assert_eq!(
        status(&rig, &full, "POST", "/api/login/mfa").0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(&rig, &full, "GET", "/api/users").0, StatusCode::OK);
    // The pending session was closed by the check.
    assert_eq!(
        status(&rig, &pending, "GET", "/api/session").0,
        StatusCode::UNAUTHORIZED
    );
    // A pending session ends with the logout.
    let again = session_of(&rig.try_login("alice", PASSWORD));
    assert_eq!(
        status(&rig, &again, "POST", "/api/logout").0,
        StatusCode::OK
    );
    assert_eq!(
        status(&rig, &again, "GET", "/api/session").0,
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn under_required_a_user_without_a_second_factor_can_only_set_it_up() {
    let rig = rig_with(&[], Mfa::Required);
    let login = rig.try_login("ola", PASSWORD);
    assert_eq!(login.body["mfa"], "setup");
    let ola = session_of(&login);
    let seen = rig.with(&ola, "GET", "/api/session", &[], "");
    assert_eq!(
        (seen.status, seen.body["state"].as_str()),
        (StatusCode::OK, Some("mfa_setup"))
    );
    let setup = (
        StatusCode::FORBIDDEN,
        "second factor setup required".to_owned(),
    );
    for (method, path) in [
        ("GET", "/api/audit"),
        ("GET", "/api/account/tokens"),
        ("PUT", "/api/account/password"),
    ] {
        assert_eq!(status(&rig, &ola, method, path), setup, "{method} {path}");
    }
    let body = json!({ "password": PASSWORD }).to_string();
    let started = rig.with(&ola, "POST", "/api/account/mfa/setup", &[], &body);
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    // The second factor cannot be taken away when it is required.
    let disable = json!({ "password": PASSWORD, "code": "123456" }).to_string();
    let refused = rig.with(&ola, "DELETE", "/api/account/mfa", &[], &disable);
    assert_eq!(
        (refused.status, refused.body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mfa is required"))
    );
    // A user who has one is not limited, and the owner's setup comes with a password change that is due.
    enrol(&rig, "vera");
    let vera = session_of(&rig.try_login("vera", PASSWORD));
    assert_eq!(
        verify(&rig, &vera, json!({ "code": code_now(0) })).body["mfa"],
        "off"
    );
    alter_user(&rig, "dave", |user| user.disabled = false);
    alter_user(&rig, "dave", |user| user.must_change = true);
    let dave = session_of(&rig.try_login("dave", PASSWORD));
    assert_eq!(
        rig.with(&dave, "POST", "/api/account/mfa/setup", &[], &body)
            .status,
        StatusCode::OK
    );
    assert_eq!(
        status(&rig, &dave, "GET", "/api/account/tokens").0,
        StatusCode::FORBIDDEN
    );
}

#[test]
fn a_user_who_must_change_the_password_can_use_nothing_but_the_change_the_session_and_the_logout() {
    let rig = rig();
    alter_user(&rig, "vera", |user| user.must_change = true);
    let login = rig.try_login("vera", PASSWORD);
    assert_eq!(
        (
            login.body["mfa"].as_str(),
            login.body["must_change"].as_bool()
        ),
        (Some("off"), Some(true))
    );
    let vera = session_of(&login);
    let seen = rig.with(&vera, "GET", "/api/session", &[], "");
    assert_eq!(
        (
            seen.body["state"].as_str(),
            seen.body["must_change"].as_bool()
        ),
        (Some("must_change"), Some(true))
    );
    for (method, path) in [
        ("GET", "/api/status"),
        ("GET", "/api/account/tokens"),
        ("POST", "/api/account/tokens"),
        ("POST", "/api/account/mfa/setup"),
    ] {
        assert_eq!(
            status(&rig, &vera, method, path),
            (StatusCode::FORBIDDEN, "password change required".to_owned()),
            "{method} {path}"
        );
    }
    let body = json!({ "current": PASSWORD, "new": "a new password!" }).to_string();
    let done = rig.with(&vera, "PUT", "/api/account/password", &[], &body);
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    assert!(!rig.user("vera").must_change);
    let renewed = session_of(&done);
    // Nothing limits the session now: the route exists in the table, and the rig has no rules to answer it.
    assert_eq!(
        status(&rig, &renewed, "GET", "/api/status").0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&rig, &renewed, "GET", "/api/account/tokens").0,
        StatusCode::OK
    );
}

#[test]
fn a_token_has_a_role_not_above_its_owners_and_lives_at_most_a_year() {
    let rig = rig();
    let ola = rig.login("ola");
    // Every body has the password, unless it is given.
    let make = |mut body: Value| {
        body.as_object_mut()
            .unwrap()
            .entry("password")
            .or_insert(json!(PASSWORD));
        rig.with(&ola, "POST", "/api/account/tokens", &[], &body.to_string())
    };
    let ok = make(json!({ "name": "ci", "role": "operator", "days": 365 }));
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
    let text = ok.body["token"].as_str().unwrap().to_owned();
    assert!(text.starts_with("tkc_") && text.len() == 64);
    assert_eq!(
        ok.body["expires"].as_u64().unwrap() - ok.body["created"].as_u64().unwrap(),
        365 * 86_400_000
    );
    assert_eq!(
        make(json!({ "name": "ci", "role": "viewer", "days": 1 })).status,
        StatusCode::OK
    );
    for (body, want) in [
        (
            json!({ "name": "ci", "role": "owner", "days": 1 }),
            StatusCode::FORBIDDEN,
        ),
        (
            json!({ "name": "ci", "role": "operator", "days": 366 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "ci", "role": "operator", "days": 0 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "", "role": "operator", "days": 1 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "ci", "role": "admin", "days": 1 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "ci", "role": "operator" }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "ci", "role": "viewer", "days": 1, "password": "wrong password 1" }),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(make(body.clone()).status, want, "{body}");
    }
    // A body without the password is no body of the route.
    let no_password = json!({ "name": "ci", "role": "viewer", "days": 1 }).to_string();
    assert_eq!(
        rig.with(&ola, "POST", "/api/account/tokens", &[], &no_password)
            .status,
        StatusCode::BAD_REQUEST
    );
    // The list has what a person needs to tell them apart, and no secret; the line of the audit log no text.
    let list = rig.with(&ola, "GET", "/api/account/tokens", &[], "");
    let tokens = list.body["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 2);
    for token in tokens {
        let mut keys: Vec<&String> = token.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "created",
                "expired",
                "expires",
                "id",
                "last_used",
                "name",
                "owner",
                "role"
            ]
        );
    }
    let audit = format!("{:?}", rig.audit());
    assert!(!audit.contains(&text) && !audit.contains(&text[21..]));
    let created = rig
        .audit()
        .into_iter()
        .find(|line| line["action"] == "token_create")
        .unwrap();
    assert_eq!(
        (
            created["actor"].as_str(),
            created["after"].as_str(),
            created["result"].as_str()
        ),
        (Some("ola"), Some("operator"), Some("ok"))
    );
    // A person removes their own tokens and not another's.
    let alice = rig.login("alice");
    let (theirs, _) = make_token(&rig, &alice, "owner", 1);
    let path = |id: &str| format!("/api/account/tokens/{id}");
    assert_eq!(
        rig.with(&ola, "DELETE", &path(&theirs), &[], "").status,
        StatusCode::NOT_FOUND
    );
    let mine = tokens[0]["id"].as_str().unwrap();
    assert_eq!(
        rig.with(&ola, "DELETE", &path(mine), &[], "").status,
        StatusCode::OK
    );
    assert!(token_in_store(&rig, mine).is_none());
    assert!(token_in_store(&rig, &theirs).is_some());
}

#[test]
fn a_token_is_used_with_its_role_without_a_cookie_or_a_csrf_token_and_only_on_the_routes_of_a_role()
{
    let rig = rig();
    let ola = rig.login("ola");
    let (_, operator) = make_token(&rig, &ola, "operator", 30);
    let (viewer_id, viewer) = make_token(&rig, &ola, "viewer", 30);
    assert_eq!(
        bearer(&rig, &operator, "GET", "/api/audit", "").status,
        StatusCode::OK
    );
    let refused = bearer(&rig, &viewer, "GET", "/api/audit", "");
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let line = rig.audit().pop().unwrap();
    assert_eq!(
        (
            line["actor"].as_str(),
            line["auth"].as_str(),
            line["reason"].as_str(),
            line["result"].as_str()
        ),
        (
            Some("ola"),
            Some(format!("token:{viewer_id}").as_str()),
            Some("role"),
            Some("denied")
        )
    );
    assert!(line.get("session").is_none());
    // A change needs no CSRF token with a token and does with a session; the rig has no rules to answer the route.
    assert_eq!(
        bearer(&rig, &operator, "POST", "/api/activate", "{}").status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        rig.with(&ola, "POST", "/api/activate", &[], "{}").status,
        StatusCode::NOT_FOUND
    );
    let cookie = format!("{COOKIE_NAME}={}", ola.id);
    assert_eq!(
        rig.send(
            "POST",
            "/api/activate",
            &[JSON_TYPE, ("cookie", cookie.as_str())],
            "{}"
        )
        .status,
        StatusCode::FORBIDDEN
    );
    // The origin is still looked at.
    let auth = format!("Bearer {operator}");
    let foreign = rig.send(
        "POST",
        "/api/activate",
        &[
            JSON_TYPE,
            ("authorization", auth.as_str()),
            ("origin", "https://evil.example.test"),
        ],
        "{}",
    );
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    // Never the login, the session or the account.
    for (method, path) in [
        ("GET", "/api/session"),
        ("POST", "/api/logout"),
        ("POST", "/api/login/mfa"),
        ("PUT", "/api/account/password"),
        ("POST", "/api/account/mfa/setup"),
        ("GET", "/api/account/tokens"),
        ("POST", "/api/account/tokens"),
        ("DELETE", "/api/account/mfa"),
    ] {
        let answer = bearer(&rig, &operator, method, path, "{}");
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{method} {path}");
    }
    // A cookie and a token together are a bad request, and so are two cookies of the session with a token.
    let both = rig.send(
        "GET",
        "/api/audit",
        &[
            ("cookie", cookie.as_str()),
            ("authorization", auth.as_str()),
        ],
        "",
    );
    assert_eq!(both.status, StatusCode::BAD_REQUEST);
    // Not the token scheme, or not a token: unauthorized.
    for field in [
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer tkc_nothing",
        &format!("Bearer {operator}x"),
    ] {
        let answer = rig.send("GET", "/api/audit", &[("authorization", field)], "");
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{field}");
    }
}

#[test]
fn a_token_is_refused_when_it_has_ended_or_the_rights_it_was_made_under_are_gone() {
    let rig = rig();
    let at = now_ms();
    let audit = |text: &str| bearer(&rig, text, "GET", "/api/audit", "").status;
    // Ended.
    assert_eq!(
        audit(&insert(&rig, "ola", Role::Operator, at + 60_000, 0)),
        StatusCode::OK
    );
    assert_eq!(
        audit(&insert(&rig, "ola", Role::Operator, at - 1, 0)),
        StatusCode::UNAUTHORIZED
    );
    // The owner's password was set again: the tokens are removed, and one that stayed is still refused.
    let ola = rig.login("ola");
    let (id, text) = make_token(&rig, &ola, "operator", 30);
    let old = token_in_store(&rig, &id).unwrap();
    assert_eq!(audit(&text), StatusCode::OK);
    let body = json!({ "current": PASSWORD, "new": "a new password!" }).to_string();
    assert_eq!(
        rig.with(&ola, "PUT", "/api/account/password", &[], &body)
            .status,
        StatusCode::OK
    );
    assert!(token_in_store(&rig, &id).is_none());
    assert_eq!(audit(&text), StatusCode::UNAUTHORIZED);
    FileAdminStore::open(rig.dir.path())
        .unwrap()
        .create_token(&old)
        .unwrap();
    assert_eq!(audit(&text), StatusCode::UNAUTHORIZED);
    // A token of a user that is gone.
    let gone = insert(&rig, "nobody", Role::Viewer, at + 60_000, 0);
    assert_eq!(audit(&gone), StatusCode::UNAUTHORIZED);
}

#[test]
fn a_wrong_password_counts_against_the_lockout_and_a_locked_user_is_refused_with_the_same_answer() {
    let rig = rig();
    let vera = rig.login("vera");
    let change = |current: &str| {
        let body = json!({ "current": current, "new": "a new password!" }).to_string();
        rig.with(&vera, "PUT", "/api/account/password", &[], &body)
    };
    let locks = || {
        rig.audit()
            .iter()
            .filter(|line| line["action"] == "lock" && line["target"] == "vera")
            .count()
    };
    let wrong = change("wrong password 1");
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    for n in 2..=4 {
        let answer = change("wrong password 1");
        assert_eq!(
            (answer.status, &answer.body),
            (wrong.status, &wrong.body),
            "{n}"
        );
    }
    assert_eq!(locks(), 0);
    // The fifth wrong password locks the user.
    assert_eq!(change("wrong password 1").status, StatusCode::FORBIDDEN);
    assert_eq!(locks(), 1);
    // Now the right password is refused with the same answer, and so is the making of a token, and the login.
    let right = change(PASSWORD);
    assert_eq!((right.status, &right.body), (wrong.status, &wrong.body));
    let token = json!({ "name": "ci", "role": "viewer", "days": 1, "password": PASSWORD });
    let refused = rig.with(
        &vera,
        "POST",
        "/api/account/tokens",
        &[],
        &token.to_string(),
    );
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body, json!({ "error": "the password is wrong" }));
    assert_eq!(
        rig.try_login("vera", PASSWORD).status,
        StatusCode::UNAUTHORIZED
    );
    assert!(rig.user("vera").password.verify(PASSWORD));
    assert!(
        FileAdminStore::open(rig.dir.path())
            .unwrap()
            .tokens()
            .unwrap()
            .is_empty()
    );
    // Each try was written with its reason.
    let reasons: Vec<String> = rig
        .audit()
        .iter()
        .filter(|line| line["target"] == "vera" && line["result"] == "denied")
        .filter_map(|line| line["reason"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(&reasons[..5], ["wrong password"; 5]);
    assert!(reasons[5..].iter().all(|reason| reason == "locked"));
}

#[test]
fn the_routes_that_ask_for_the_password_take_a_try_of_the_client_before_they_look_at_it() {
    let rig = rig();
    // The login took one of the 30 tries a minute; the right password is taken 29 times, as the making of a token.
    let vera = rig.login("vera");
    let right = json!({ "name": "ci", "role": "viewer", "days": 1, "password": PASSWORD });
    for n in 1..=29 {
        let answer = rig.with(
            &vera,
            "POST",
            "/api/account/tokens",
            &[],
            &right.to_string(),
        );
        assert_eq!(answer.status, StatusCode::OK, "{n}: {:?}", answer.body);
    }
    // The next one is turned away, with the wrong password as well, and nothing counts against the user.
    let wrong =
        json!({ "name": "ci", "role": "viewer", "days": 1, "password": "wrong password 1" });
    let turned_away = rig.with(
        &vera,
        "POST",
        "/api/account/tokens",
        &[],
        &wrong.to_string(),
    );
    assert_eq!(turned_away.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(rig.audit().iter().all(|line| line["result"] != "denied"));
}

#[test]
fn a_token_whose_file_stayed_is_still_void_after_the_owner_is_enabled_or_raised_again() {
    let rig = rig();
    let audit = |text: &str| bearer(&rig, text, "GET", "/api/audit", "").status;
    let alice = rig.login("alice");
    let change = |body: Value| {
        rig.with(&alice, "PUT", "/api/users/ola", &[], &body.to_string())
            .status
    };
    // The file of the token is put back each time a change took it away, as if the removal had failed.
    let put_back = |token: &Token| {
        FileAdminStore::open(rig.dir.path())
            .unwrap()
            .create_token(token)
            .unwrap();
    };
    // Disabled, then enabled again.
    let (id, live) = make_token(&rig, &rig.login("ola"), "operator", 30);
    let kept = token_in_store(&rig, &id).unwrap();
    assert_eq!(audit(&live), StatusCode::OK);
    assert_eq!(change(json!({ "disabled": true })), StatusCode::OK);
    assert!(token_in_store(&rig, &id).is_none());
    put_back(&kept);
    assert_eq!(audit(&live), StatusCode::UNAUTHORIZED);
    assert_eq!(change(json!({ "disabled": false })), StatusCode::OK);
    assert_eq!(audit(&live), StatusCode::UNAUTHORIZED);
    // Lowered to viewer, then raised to operator again; a token made after the change counts.
    let (id, live) = make_token(&rig, &rig.login("ola"), "operator", 30);
    let kept = token_in_store(&rig, &id).unwrap();
    assert_eq!(audit(&live), StatusCode::OK);
    assert_eq!(change(json!({ "role": "viewer" })), StatusCode::OK);
    assert!(token_in_store(&rig, &id).is_none());
    put_back(&kept);
    assert_eq!(audit(&live), StatusCode::UNAUTHORIZED);
    assert_eq!(change(json!({ "role": "operator" })), StatusCode::OK);
    assert_eq!(audit(&live), StatusCode::UNAUTHORIZED);
    let (_, fresh) = make_token(&rig, &rig.login("ola"), "operator", 30);
    assert_eq!(audit(&fresh), StatusCode::OK);
}

#[test]
fn under_required_the_token_of_an_owner_without_a_second_factor_is_refused() {
    let rig = rig_with(&[], Mfa::Required);
    let at = now_ms();
    let text = insert(&rig, "ola", Role::Operator, at + 60_000, 0);
    let audit = |text: &str| bearer(&rig, text, "GET", "/api/audit", "").status;
    assert_eq!(audit(&text), StatusCode::UNAUTHORIZED);
    enrol(&rig, "ola");
    assert_eq!(audit(&text), StatusCode::OK);
}

#[test]
fn a_token_that_is_not_right_counts_against_the_client_and_a_client_with_no_tries_left_is_turned_away()
 {
    let rig = rig();
    let valid = insert(&rig, "ola", Role::Operator, now_ms() + 60_000, 0);
    assert_eq!(
        bearer(&rig, &valid, "GET", "/api/audit", "").status,
        StatusCode::OK
    );
    // A token that is right is not a try: it can be used again and again.
    for _ in 0..40 {
        assert_eq!(
            bearer(&rig, &valid, "GET", "/api/audit", "").status,
            StatusCode::OK
        );
    }
    let bad = format!("tkc_0123456789abcdef_{}", "a".repeat(43));
    let mut refused = 0;
    loop {
        let answer = bearer(&rig, &bad, "GET", "/api/audit", "");
        if answer.status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        refused += 1;
        assert!(refused <= 30, "the limit was not reached");
    }
    assert_eq!(refused, 30);
    // The right token is not looked at once the tries are gone.
    assert_eq!(
        bearer(&rig, &valid, "GET", "/api/audit", "").status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[test]
fn the_time_of_use_of_a_token_is_written_at_most_once_in_ten_minutes() {
    let rig = rig();
    let at = now_ms();
    let minute = 60_000;
    let fresh = insert(&rig, "ola", Role::Operator, at + 60 * minute, at - minute);
    let stale = insert(
        &rig,
        "ola",
        Role::Operator,
        at + 60 * minute,
        at - 11 * minute,
    );
    let never = insert(&rig, "ola", Role::Operator, at + 60 * minute, 0);
    for text in [&fresh, &stale, &never] {
        assert_eq!(
            bearer(&rig, text, "GET", "/api/audit", "").status,
            StatusCode::OK
        );
    }
    let used = |text: &str| {
        let id = tokens::parse(text).unwrap().0.to_owned();
        token_in_store(&rig, &id).unwrap().last_used
    };
    assert_eq!(used(&fresh), at - minute);
    assert!(used(&stale) >= at);
    assert!(used(&never) >= at);
}

#[test]
fn the_second_factor_is_taken_away_with_the_password_and_a_code_or_a_recovery_code() {
    let rig = rig();
    let codes = enrol(&rig, "vera");
    let log_in = |ahead: u64| {
        let pending = session_of(&rig.try_login("vera", PASSWORD));
        session_of(&verify(&rig, &pending, json!({ "code": code_now(ahead) })))
    };
    let disable = |session: &Session, password: &str, code: &str| {
        let body = json!({ "password": password, "code": code }).to_string();
        rig.with(session, "DELETE", "/api/account/mfa", &[], &body)
    };
    let vera = log_in(0);
    // A wrong password, a code that is wrong and a recovery code that is none take nothing away.
    assert_eq!(
        disable(&vera, "wrong password 1", &code_now(1)).status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        disable(&vera, PASSWORD, &wrong_code()).status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        disable(&vera, PASSWORD, "AAAAAAAAAAAAAAAA").status,
        StatusCode::FORBIDDEN
    );
    assert!(rig.user("vera").mfa.is_some());
    // A recovery code does it, and the session is renewed.
    let done = disable(&vera, PASSWORD, &codes[0]);
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    assert!(rig.user("vera").mfa.is_none() && rig.user("vera").recovery.is_empty());
    assert_eq!(
        status(&rig, &vera, "GET", "/api/session").0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(rig.try_login("vera", PASSWORD).body["mfa"], "off");
    // So does a code of the application, from a step after the one that was used to log in. No second factor is
    // none to take away.
    enrol(&rig, "vera");
    let again = log_in(0);
    let done = disable(&again, PASSWORD, &code_now(1));
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    let renewed = session_of(&done);
    assert_eq!(
        disable(&renewed, PASSWORD, &code_now(1)).status,
        StatusCode::CONFLICT
    );
}
