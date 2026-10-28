use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

use serde_json::{Value, json};

use super::*;
use crate::admin::auth::totp::{self, Seed, Totp};
use crate::admin::auth::{Authed, tokens};
use crate::admin::file_store::FileAdminStore;
use crate::admin::server::tests::{JSON_TYPE, PASSWORD, Rig, Session, alter_user, rig, session_of};
use crate::admin::store::AdminStore;

/// A change by the owner `session`, with the JSON `body`.
fn change(rig: &Rig, session: &Session, method: &str, path: &str, body: Value) -> Answer {
    rig.with(session, method, path, &[], &body.to_string())
}

fn words(answer: &Answer) -> &str {
    answer.body["error"].as_str().unwrap_or_default()
}

fn tokens_of(rig: &Rig, owner: &str) -> Vec<String> {
    FileAdminStore::open(rig.dir.path())
        .unwrap()
        .tokens()
        .unwrap()
        .into_iter()
        .filter(|token| token.owner == owner)
        .map(|token| token.id)
        .collect()
}

/// A token of `session`'s user, made through the API; its text.
fn token(rig: &Rig, session: &Session, role: &str) -> String {
    let body = json!({ "name": "test", "role": role, "days": 30, "password": PASSWORD });
    let answer = change(rig, session, "POST", "/api/account/tokens", body);
    assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
    answer.body["token"].as_str().unwrap().to_owned()
}

fn with_token(rig: &Rig, text: &str, method: &str, path: &str, body: &str) -> Answer {
    let auth = format!("Bearer {text}");
    rig.send(
        method,
        path,
        &[JSON_TYPE, ("authorization", auth.as_str())],
        body,
    )
}

#[test]
fn an_owner_makes_a_user_who_must_change_the_password_and_nobody_else_may() {
    let rig = rig();
    let alice = rig.login("alice");
    let new = json!({ "name": "newbie", "role": "viewer", "password": "first password 1" });
    let made = change(&rig, &alice, "POST", "/api/users", new.clone());
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    assert_eq!(
        (
            made.body["name"].as_str(),
            made.body["role"].as_str(),
            made.body["must_change"].as_bool()
        ),
        (Some("newbie"), Some("viewer"), Some(true))
    );
    let stored = rig.user("newbie");
    assert!(stored.must_change && stored.password.verify("first password 1"));
    // The name is taken; the input is not right; the others are not owners.
    assert_eq!(
        change(&rig, &alice, "POST", "/api/users", new).status,
        StatusCode::CONFLICT
    );
    for (body, want) in [
        (
            json!({ "name": "Bad Name", "role": "viewer", "password": "first password 1" }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "other", "role": "root", "password": "first password 1" }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "other", "role": "viewer", "password": "short" }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "name": "other", "role": "viewer", "password": "first password 1", "must_change": false }),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            change(&rig, &alice, "POST", "/api/users", body.clone()).status,
            want,
            "{body}"
        );
    }
    let (ola, vera) = (rig.login("ola"), rig.login("vera"));
    let body = json!({ "name": "other", "role": "viewer", "password": "first password 1" });
    for session in [&ola, &vera] {
        assert_eq!(
            change(&rig, session, "POST", "/api/users", body.clone()).status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            rig.with(session, "GET", "/api/users", &[], "").status,
            StatusCode::FORBIDDEN
        );
    }
    // The list has the users by name and nothing of their secrets; the line of the audit log has no password.
    let list = rig.with(&alice, "GET", "/api/users", &[], "");
    let names: Vec<&str> = list.body["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alice", "dave", "newbie", "ola", "vera"]);
    let text = list.body.to_string();
    assert!(
        ["password", "hash", "salt", "secret", "recovery"]
            .iter()
            .all(|key| !text.contains(key))
    );
    let created = rig
        .audit()
        .into_iter()
        .find(|line| line["action"] == "user_create" && line["result"] == "ok")
        .unwrap();
    assert_eq!(
        (
            created["actor"].as_str(),
            created["target"].as_str(),
            created["after"].as_str()
        ),
        (Some("alice"), Some("newbie"), Some("viewer"))
    );
    assert!(!format!("{:?}", rig.audit()).contains("first password 1"));
    // The new user logs in, and has to change the password.
    let login = rig.try_login("newbie", "first password 1");
    assert_eq!(login.body["must_change"], true);
}

#[test]
fn lowering_or_disabling_a_user_ends_its_sessions_and_the_tokens_it_no_longer_has_the_rights_for() {
    let rig = rig();
    let alice = rig.login("alice");
    let ola = rig.login("ola");
    let operator = token(&rig, &ola, "operator");
    let viewer = token(&rig, &ola, "viewer");
    let audit = |text: &str| with_token(&rig, text, "GET", "/api/audit", "").status;
    assert_eq!(audit(&operator), StatusCode::OK);
    // The role is lowered to viewer: the session is closed and every token is void, also the one that the viewer
    // role would allow, and the files of both are removed.
    let lowered = change(
        &rig,
        &alice,
        "PUT",
        "/api/users/ola",
        json!({ "role": "viewer" }),
    );
    assert_eq!(lowered.status, StatusCode::OK, "{:?}", lowered.body);
    assert_eq!(
        rig.with(&ola, "GET", "/api/session", &[], "").status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(audit(&operator), StatusCode::UNAUTHORIZED);
    assert!(tokens_of(&rig, "ola").is_empty());
    assert_eq!(
        with_token(&rig, &viewer, "GET", "/api/status", "").status,
        StatusCode::UNAUTHORIZED
    );
    let line = rig
        .audit()
        .into_iter()
        .find(|line| line["action"] == "role")
        .unwrap();
    assert_eq!(
        (
            line["actor"].as_str(),
            line["target"].as_str(),
            line["before"].as_str(),
            line["after"].as_str()
        ),
        (Some("alice"), Some("ola"), Some("operator"), Some("viewer"))
    );
    // Disabled: no login, no token. Enabled again: the login works and the token does not come back.
    let off = change(
        &rig,
        &alice,
        "PUT",
        "/api/users/ola",
        json!({ "disabled": true }),
    );
    assert_eq!(off.status, StatusCode::OK);
    assert_eq!(
        rig.try_login("ola", PASSWORD).status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        with_token(&rig, &viewer, "GET", "/api/status", "").status,
        StatusCode::UNAUTHORIZED
    );
    assert!(tokens_of(&rig, "ola").is_empty());
    change(
        &rig,
        &alice,
        "PUT",
        "/api/users/ola",
        json!({ "disabled": false }),
    );
    assert_eq!(rig.try_login("ola", PASSWORD).status, StatusCode::OK);
    assert_eq!(
        with_token(&rig, &viewer, "GET", "/api/status", "").status,
        StatusCode::UNAUTHORIZED
    );
    // A user that is not there, and a request that asks for both or none.
    assert_eq!(
        change(
            &rig,
            &alice,
            "PUT",
            "/api/users/nobody",
            json!({ "role": "viewer" })
        )
        .status,
        StatusCode::NOT_FOUND
    );
    for body in [
        json!({}),
        json!({ "role": "viewer", "disabled": true }),
        json!({ "role": "root" }),
    ] {
        assert_eq!(
            change(&rig, &alice, "PUT", "/api/users/ola", body).status,
            StatusCode::BAD_REQUEST
        );
    }
}

#[test]
fn an_owner_cannot_lower_or_disable_itself_and_the_last_owner_stays() {
    let rig = rig();
    let alice = rig.login("alice");
    let own = |body: Value| change(&rig, &alice, "PUT", "/api/users/alice", body);
    let lowered = own(json!({ "role": "operator" }));
    assert_eq!(
        (lowered.status, words(&lowered)),
        (StatusCode::FORBIDDEN, "an owner cannot lower its own role")
    );
    let disabled = own(json!({ "disabled": true }));
    assert_eq!(
        (disabled.status, words(&disabled)),
        (StatusCode::FORBIDDEN, "an owner cannot disable itself")
    );
    // Nothing changed, and a change that is none is none.
    assert_eq!(own(json!({ "role": "owner" })).status, StatusCode::OK);
    assert_eq!(rig.user("alice").role, Role::Owner);
    assert_eq!(
        rig.with(&alice, "GET", "/api/session", &[], "").status,
        StatusCode::OK
    );
    // With a second owner, either may lower the other; the one that is left cannot lower itself.
    assert_eq!(
        change(
            &rig,
            &alice,
            "PUT",
            "/api/users/ola",
            json!({ "role": "owner" })
        )
        .status,
        StatusCode::OK
    );
    let ola = rig.login("ola");
    let lowered = change(
        &rig,
        &ola,
        "PUT",
        "/api/users/alice",
        json!({ "role": "viewer" }),
    );
    assert_eq!(lowered.status, StatusCode::OK, "{:?}", lowered.body);
    assert_eq!(
        rig.with(&alice, "GET", "/api/session", &[], "").status,
        StatusCode::UNAUTHORIZED
    );
    let last = change(
        &rig,
        &ola,
        "PUT",
        "/api/users/ola",
        json!({ "role": "operator" }),
    );
    assert_eq!(last.status, StatusCode::FORBIDDEN);
    assert_eq!(rig.user("ola").role, Role::Owner);
    // An owner who was lowered after its request was checked and before the change was made changes nothing.
    let stale = rig.login("ola");
    let Authed::Who(who) = rig.app.auth.session(&stale.id, Instant::now()) else {
        panic!("a session that counts");
    };
    alter_user(&rig, "ola", |user| user.role = Role::Operator);
    let cx = Cx {
        id: "0123456789abcdef-1",
        client: IpAddr::from([127, 0, 0, 1]),
    };
    let refused = rig
        .app
        .auth
        .change_user(&who, "alice", Change::Role(Role::Owner), &cx);
    assert_eq!(refused.err(), Some(Refusal::Denied("forbidden")));
    assert_eq!(rig.user("alice").role, Role::Viewer);
}

#[test]
fn an_owner_sets_a_password_and_takes_a_second_factor_away_but_not_its_own() {
    let rig = rig();
    alter_user(&rig, "vera", |user| {
        user.mfa = Some(Totp {
            seed: Seed::from_bytes([3; totp::SEED_LEN]),
            last_step: 0,
        });
        user.recovery = vec![totp::recovery_hash("AAAAAAAAAAAAAAAA")];
    });
    let alice = rig.login("alice");
    let vera = session_of(&rig.try_login("vera", PASSWORD));
    let (_, record) = tokens::mint("vera", Role::Viewer, "kept", now_ms(), 1).unwrap();
    FileAdminStore::open(rig.dir.path())
        .unwrap()
        .create_token(&record)
        .unwrap();
    let reset = change(
        &rig,
        &alice,
        "POST",
        "/api/users/vera/password",
        json!({ "password": "a fresh password" }),
    );
    assert_eq!(reset.status, StatusCode::OK, "{:?}", reset.body);
    let stored = rig.user("vera");
    assert!(stored.must_change && stored.password.verify("a fresh password"));
    // The sessions and the tokens of the user are gone.
    assert_eq!(
        rig.with(&vera, "GET", "/api/session", &[], "").status,
        StatusCode::UNAUTHORIZED
    );
    assert!(tokens_of(&rig, "vera").is_empty());
    assert_eq!(
        rig.try_login("vera", PASSWORD).status,
        StatusCode::UNAUTHORIZED
    );
    let login = rig.try_login("vera", "a fresh password");
    assert_eq!(
        (
            login.body["mfa"].as_str(),
            login.body["must_change"].as_bool()
        ),
        (Some("verify"), Some(true))
    );
    // The second factor is taken away; there is none to take away the second time.
    let removed = change(&rig, &alice, "DELETE", "/api/users/vera/mfa", json!({}));
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);
    assert!(rig.user("vera").mfa.is_none() && rig.user("vera").recovery.is_empty());
    assert_eq!(rig.try_login("vera", "a fresh password").body["mfa"], "off");
    assert_eq!(
        change(&rig, &alice, "DELETE", "/api/users/vera/mfa", json!({})).status,
        StatusCode::CONFLICT
    );
    let lines: Vec<(String, String)> = rig
        .audit()
        .iter()
        .filter(|l| l["action"].as_str().is_some_and(|a| a.starts_with("user_")))
        .map(|l| {
            (
                l["action"].as_str().unwrap().to_owned(),
                l["target"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        lines,
        [
            ("user_password".to_owned(), "vera".to_owned()),
            ("user_mfa".to_owned(), "vera".to_owned())
        ]
    );
    // Not for itself: that is done with the password of the account, which asks for the old one.
    let own = change(
        &rig,
        &alice,
        "POST",
        "/api/users/alice/password",
        json!({ "password": "a fresh password" }),
    );
    assert_eq!(
        (own.status, words(&own)),
        (StatusCode::FORBIDDEN, "use the password of the account")
    );
    assert_eq!(
        change(&rig, &alice, "DELETE", "/api/users/alice/mfa", json!({})).status,
        StatusCode::FORBIDDEN
    );
    assert!(rig.user("alice").password.verify(PASSWORD));
    // A name that is no name, and a path that is none.
    assert_eq!(
        change(
            &rig,
            &alice,
            "DELETE",
            "/api/users/Bad%20Name/mfa",
            json!({})
        )
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        change(&rig, &alice, "PUT", "/api/users/vera/other", json!({})).status,
        StatusCode::NOT_FOUND
    );
}

#[test]
fn the_routes_of_the_management_are_for_a_session_and_a_token_of_an_owner_is_refused_on_each() {
    let rig = rig();
    let alice = rig.login("alice");
    let owner = token(&rig, &alice, "owner");
    let ola = rig.login("ola");
    token(&rig, &ola, "viewer");
    let id = tokens_of(&rig, "ola").remove(0);
    let new = json!({ "name": "viaapi", "role": "viewer", "password": "first password 1" });
    let tokens_path = format!("/api/tokens/{id}");
    let routes = [
        ("GET", "/api/users", String::new()),
        ("POST", "/api/users", new.to_string()),
        (
            "PUT",
            "/api/users/ola",
            json!({ "role": "viewer" }).to_string(),
        ),
        (
            "POST",
            "/api/users/ola/password",
            json!({ "password": "a fresh password" }).to_string(),
        ),
        ("DELETE", "/api/users/ola/mfa", String::new()),
        ("GET", "/api/tokens", String::new()),
        ("DELETE", tokens_path.as_str(), String::new()),
    ];
    assert_eq!(routes.len(), ROUTES.len());
    for (method, path, body) in &routes {
        let answer = with_token(&rig, &owner, method, path, body);
        assert_eq!(
            (answer.status, words(&answer)),
            (StatusCode::FORBIDDEN, "forbidden"),
            "{method} {path}"
        );
    }
    // Nothing changed: no new user, the role and the password of ola, the token of ola.
    let store = FileAdminStore::open(rig.dir.path()).unwrap();
    assert!(store.user("viaapi").unwrap().is_none());
    let stored = rig.user("ola");
    assert_eq!((stored.role, stored.must_change), (Role::Operator, false));
    assert!(stored.password.verify(PASSWORD));
    assert_eq!(tokens_of(&rig, "ola"), [id]);
    // Each refusal was written, for the owner whose token it was, with the reason.
    let refusals: Vec<_> = rig
        .audit()
        .into_iter()
        .filter(|line| line["reason"] == "token")
        .collect();
    assert_eq!(refusals.len(), routes.len());
    assert!(refusals.iter().all(|line| {
        line["actor"] == "alice"
            && line["auth"]
                .as_str()
                .is_some_and(|auth| auth.starts_with("token:"))
    }));
    // The session of the owner does all of them: the list of the tokens of everybody, and the removal of any.
    let all = rig.with(&alice, "GET", "/api/tokens", &[], "");
    assert_eq!(all.body["tokens"].as_array().unwrap().len(), 2);
    assert_eq!(
        rig.with(&alice, "DELETE", &tokens_path, &[], "").status,
        StatusCode::OK
    );
}

#[test]
fn nothing_is_changed_while_the_audit_log_cannot_take_the_line() {
    let rig = rig();
    let (alice, ola) = (rig.login("alice"), rig.login("ola"));
    rig.fail.store(true, Ordering::SeqCst);
    let new = json!({ "name": "newbie", "role": "viewer", "password": "first password 1" });
    let refused = [
        change(&rig, &alice, "POST", "/api/users", new),
        change(
            &rig,
            &alice,
            "PUT",
            "/api/users/ola",
            json!({ "role": "viewer" }),
        ),
        change(
            &rig,
            &alice,
            "PUT",
            "/api/users/ola",
            json!({ "disabled": true }),
        ),
        change(
            &rig,
            &alice,
            "POST",
            "/api/users/ola/password",
            json!({ "password": "a fresh password" }),
        ),
        change(
            &rig,
            &ola,
            "POST",
            "/api/account/tokens",
            json!({ "name": "ci", "role": "viewer", "days": 1, "password": PASSWORD }),
        ),
        change(
            &rig,
            &ola,
            "POST",
            "/api/account/mfa/setup",
            json!({ "password": PASSWORD }),
        ),
    ];
    for answer in &refused {
        assert_eq!(
            answer.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{:?}",
            answer.body
        );
    }
    // Nothing was made or changed, and the sessions are as they were.
    rig.fail.store(false, Ordering::SeqCst);
    let store = FileAdminStore::open(rig.dir.path()).unwrap();
    assert!(store.user("newbie").unwrap().is_none());
    let stored = rig.user("ola");
    assert_eq!(
        (stored.role, stored.disabled, stored.must_change),
        (Role::Operator, false, false)
    );
    assert!(stored.password.verify(PASSWORD));
    assert!(tokens_of(&rig, "ola").is_empty());
    assert_eq!(
        rig.with(&ola, "GET", "/api/session", &[], "").status,
        StatusCode::OK
    );
    let confirm = json!({ "code": "123456" });
    assert_eq!(
        change(&rig, &ola, "POST", "/api/account/mfa/confirm", confirm).status,
        StatusCode::CONFLICT
    );
}
