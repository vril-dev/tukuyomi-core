use serde_json::Value;
use tokio::runtime::Builder;
use tokio::time::Instant;

use super::*;
use crate::acme::tests::{Canned, Scratch, authority, response, unurl};

const BAD_NONCE_BODY: &[u8] = br#"{"type":"urn:ietf:params:acme:error:badNonce"}"#;

fn run<F: std::future::Future>(body: F) -> F::Output {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(body)
}

fn client(dir: &Scratch) -> Client {
    Client::new(
        &dir.join("one-ca.pem"),
        Instant::now() + std::time::Duration::from_secs(30),
    )
    .unwrap()
}

/// The header and the payload of the message that a request carries.
fn message(request: &str) -> (Value, Vec<u8>) {
    let body = request.split_once("\r\n\r\n").unwrap().1;
    let message: Value = serde_json::from_str(body).unwrap();
    let header = serde_json::from_slice(&unurl(message["protected"].as_str().unwrap())).unwrap();
    (header, unurl(message["payload"].as_str().unwrap()))
}

fn bad_nonce(nonce: &str) -> Vec<u8> {
    response(
        "400 Bad Request",
        &[
            ("Replay-Nonce", nonce),
            ("Content-Type", "application/problem+json"),
        ],
        BAD_NONCE_BODY,
    )
}

/// The first answers of a CA: the directory, and a nonce for the first message.
fn start(server: &Canned) {
    let directory = format!(
        r#"{{"newNonce":"{}","newAccount":"{}","newOrder":"{}"}}"#,
        server.url("/nonce"),
        server.url("/acct"),
        server.url("/order")
    );
    server.push(response("200 OK", &[], directory.as_bytes()));
    server.push(response("200 OK", &[("Replay-Nonce", "n1")], b""));
}

#[test]
fn a_bad_nonce_is_answered_once_by_signing_again_with_the_nonce_that_came_with_it() {
    let dir = Scratch::new();
    authority(dir.path(), "one");
    run(async {
        let server = Canned::start(dir.path(), "one").await;
        start(&server);
        server.push(bad_nonce("n2"));
        let account = server.url("/acct/1");
        server.push(response(
            "201 Created",
            &[("Replay-Nonce", "n3"), ("Location", &account)],
            b"{}",
        ));
        let key = Key::generate().unwrap().0;
        let session = Session::open(client(&dir), key, &server.url("/dir"), "ops@example.test")
            .await
            .unwrap();
        assert_eq!(session.account.as_deref(), Some(account.as_str()));
        assert_eq!(session.nonce.as_deref(), Some("n3"));
        let asked = server.asked();
        assert_eq!(asked.len(), 4, "{asked:?}");
        assert!(asked[0].starts_with("GET /dir "));
        assert!(asked[1].starts_with("HEAD /nonce "));
        let (first, payload) = message(&asked[2]);
        let (second, again) = message(&asked[3]);
        assert_eq!(
            (first["nonce"].as_str(), second["nonce"].as_str()),
            (Some("n1"), Some("n2"))
        );
        assert!(first.get("jwk").is_some() && first.get("kid").is_none());
        assert_eq!(payload, again);
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            payload,
            serde_json::json!({"termsOfServiceAgreed": true, "contact": ["mailto:ops@example.test"]})
        );
    });
}

#[test]
fn a_second_bad_nonce_in_a_row_is_a_failure_and_a_third_message_is_not_sent() {
    let dir = Scratch::new();
    authority(dir.path(), "one");
    run(async {
        let server = Canned::start(dir.path(), "one").await;
        start(&server);
        server.push(bad_nonce("n2"));
        server.push(bad_nonce("n3"));
        server.push(response(
            "201 Created",
            &[("Location", &server.url("/acct/1"))],
            b"{}",
        ));
        let key = Key::generate().unwrap().0;
        let failed =
            Session::open(client(&dir), key, &server.url("/dir"), "ops@example.test").await;
        assert_eq!(
            failed.err(),
            Some(Failure::Problem(
                "urn:ietf:params:acme:error:badNonce".to_owned()
            ))
        );
        assert_eq!(server.asked().len(), 4);
    });
}

/// A session that has an account and a nonce already, for the CA of `server`.
fn session(dir: &Scratch, server: &Canned) -> Session {
    Session {
        client: client(dir),
        key: Key::generate().unwrap().0,
        new_nonce: Url::parse(&server.url("/nonce")).unwrap(),
        new_order: Url::parse(&server.url("/order")).unwrap(),
        account: Some(server.url("/acct/1")),
        nonce: Some("n0".to_owned()),
    }
}

#[test]
fn an_authorization_for_another_name_or_a_wildcard_or_an_unsafe_token_is_refused_before_a_file_is_made()
 {
    let dir = Scratch::new();
    authority(dir.path(), "one");
    let files = Scratch::new();
    run(async {
        let hosts = ["a.test".to_owned()];
        let cases = [
            (
                "evil.test",
                false,
                "tok-1",
                "an authorization for a name that was not asked for",
            ),
            ("a.test", true, "tok-1", "an authorization for a wildcard"),
            ("a.test", false, "../x", "a token that is a path"),
            ("a.test", false, "", "no token"),
        ];
        for (name, wildcard, token, what) in cases {
            let server = Canned::start(dir.path(), "one").await;
            let authorization = serde_json::json!({
                "identifier": {"type": "dns", "value": name},
                "status": "pending",
                "wildcard": wildcard,
                "challenges": [{"type": "http-01", "url": server.url("/chall/1"), "token": token}],
            });
            server.push(response(
                "200 OK",
                &[("Replay-Nonce", "n9")],
                authorization.to_string().as_bytes(),
            ));
            let mut challenges = Challenges::new(files.path());
            let url = Url::parse(&server.url("/authz/1")).unwrap();
            let refused = session(&dir, &server)
                .authorize(&url, &hosts, &mut challenges)
                .await;
            assert!(refused.is_err(), "{what}");
            // The authorization was read, and the challenge was not answered.
            assert_eq!(server.asked().len(), 1, "{what}");
            assert_eq!(
                std::fs::read_dir(files.path()).unwrap().count(),
                0,
                "{what}"
            );
        }
    });
}
