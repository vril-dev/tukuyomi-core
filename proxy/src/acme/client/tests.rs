use tokio::runtime::Builder;

use super::*;
use crate::acme::tests::{Canned, Scratch, authority, response};

fn reply(headers: &[(&str, &str)]) -> Reply {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(value).unwrap(),
        );
    }
    Reply {
        status: 200,
        headers: map,
        body: Vec::new(),
    }
}

#[test]
fn a_url_is_https_only_at_most_2048_bytes_and_has_no_user_no_fragment_and_no_blank() {
    let base = "https://a.example/";
    let longest = format!("{base}{}", "x".repeat(2048 - base.len()));
    let too_long = format!("{longest}x");
    assert!(Url::parse(&longest).is_ok());
    for good in [
        "https://acme.example/dir",
        "https://127.0.0.1:14000/dir?x=1",
        "https://[::1]:8443/d",
        "https://a.example",
    ] {
        assert!(Url::parse(good).is_ok(), "{good}");
    }
    assert_eq!(Url::parse("https://[::1]:8443/d").unwrap().port, 8443);
    assert_eq!(Url::parse("https://a.example/d").unwrap().port, 443);
    for bad in [
        "http://a.example/",
        "ftp://a.example/",
        "HTTPS://a.example/",
        "https://",
        "https:///x",
        "https://user@a.example/",
        "https://a.example/#f",
        "https://a.example/a b",
        "https://a.example/a\tb",
        "https://a.example/\u{e9}",
        "https://a.example:0/",
        "https://a.example:99999/",
        &too_long,
    ] {
        assert!(Url::parse(bad).is_err(), "{bad:.40}");
    }
}

#[test]
fn the_pause_is_the_retry_after_in_seconds_from_1_to_10_and_1_if_there_is_none() {
    for (value, want) in [
        (Some("0"), 1),
        (Some("1"), 1),
        (Some("5"), 5),
        (Some("10"), 10),
        (Some("11"), 10),
        (Some("99999999999999999999"), 10),
        (Some("Wed, 21 Oct 2026 07:28:00 GMT"), 1),
        (Some("-3"), 1),
        (Some(""), 1),
        (None, 1),
    ] {
        let headers: Vec<(&str, &str)> = value.map(|v| ("retry-after", v)).into_iter().collect();
        assert_eq!(
            reply(&headers).retry_after(),
            Duration::from_secs(want),
            "{value:?}"
        );
    }
}

#[test]
fn a_nonce_is_1_to_256_characters_of_the_url_safe_alphabet() {
    assert_eq!(
        reply(&[("replay-nonce", "aB3-_9")]).nonce().as_deref(),
        Some("aB3-_9")
    );
    assert_eq!(reply(&[]).nonce(), None);
    let longest = "a".repeat(256);
    assert!(reply(&[("replay-nonce", &longest)]).nonce().is_some());
    let too_long = "a".repeat(257);
    for bad in ["", "ab=", "a b", "a.b", "a/b", too_long.as_str()] {
        assert_eq!(reply(&[("replay-nonce", bad)]).nonce(), None, "{bad:.20}");
    }
}

#[test]
fn a_problem_type_is_written_with_the_odd_bytes_escaped_and_at_most_200_bytes_of_it() {
    let mut r = reply(&[]);
    r.status = 400;
    r.body = "{\"type\":\"urn:ietf:params:acme:error:a\\u0007b\u{e9}\",\"detail\":\"x\"}"
        .as_bytes()
        .to_vec();
    assert_eq!(
        r.refused(),
        Failure::Problem("urn:ietf:params:acme:error:a\\x07b\\xc3\\xa9".to_owned())
    );
    let long = format!(r#"{{"type":"{}"}}"#, "a".repeat(300));
    r.body = long.into_bytes();
    assert_eq!(r.refused(), Failure::Problem("a".repeat(200)));
    // No document, or one without a type: only a fixed sentence.
    for body in [&b"not json"[..], b"{}", b"[]", br#"{"type":3}"#] {
        r.body = body.to_vec();
        assert!(matches!(r.refused(), Failure::Text(_)));
    }
}

#[test]
fn the_client_trusts_the_authorities_of_ca_file_only_follows_no_redirect_and_reads_at_most_64_kib()
{
    let dir = Scratch::new();
    authority(dir.path(), "one");
    authority(dir.path(), "two");
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let server = Canned::start(dir.path(), "one").await;
            let url = Url::parse(&server.url("/dir")).unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);

            // A server whose certificate comes from another authority is not talked to: the handshake fails.
            let other = Client::new(&dir.join("two-ca.pem"), deadline).unwrap();
            assert_eq!(
                other.get(&url).await.unwrap_err(),
                Failure::Text("the TLS handshake with the CA failed")
            );

            let client = Client::new(&dir.join("one-ca.pem"), deadline).unwrap();
            server.push(response(
                "200 OK",
                &[
                    ("Replay-Nonce", "n-1"),
                    ("Content-Type", "application/json"),
                ],
                br#"{"a":1}"#,
            ));
            let got = client.get(&url).await.unwrap();
            assert_eq!(
                (got.status, got.nonce().as_deref(), &got.body[..]),
                (200, Some("n-1"), &br#"{"a":1}"#[..])
            );
            // A redirect is an answer like any other; it is not followed.
            server.push(response(
                "302 Found",
                &[("Location", "https://127.0.0.1:1/elsewhere")],
                b"",
            ));
            let got = client.get(&url).await.unwrap();
            assert_eq!(
                (got.status, got.header("location")),
                (302, Some("https://127.0.0.1:1/elsewhere"))
            );
            // The body is read up to 64 KiB, and a byte more fails.
            server.push(response("200 OK", &[], &vec![b'x'; 64 * 1024]));
            assert_eq!(client.get(&url).await.unwrap().body.len(), 64 * 1024);
            server.push(response("200 OK", &[], &vec![b'x'; 64 * 1024 + 1]));
            assert_eq!(
                client.get(&url).await.unwrap_err(),
                Failure::Text("an answer of the CA is over 64 KiB")
            );
            // The request is what the CA expects of a POST: the content type of a JWS, and the length.
            server.push(response("200 OK", &[], b""));
            client.post(&url, "{\"k\":1}".to_owned()).await.unwrap();
            let asked = server.asked();
            let last = asked.last().unwrap().to_ascii_lowercase();
            assert!(last.starts_with("post /dir http/1.1\r\n"), "{last}");
            assert!(
                last.contains("\r\ncontent-type: application/jose+json\r\n"),
                "{last}"
            );
            assert!(last.contains("\r\ncontent-length: 7\r\n"), "{last}");
            assert!(last.ends_with("\r\n\r\n{\"k\":1}"), "{last}");
        });
}

#[test]
fn a_request_that_the_deadline_cuts_off_fails_and_the_authority_file_must_be_usable() {
    let dir = Scratch::new();
    authority(dir.path(), "one");
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let server = Canned::start(dir.path(), "one").await;
            let url = Url::parse(&server.url("/dir")).unwrap();
            // Nothing is pushed: the server closes the connection after the request, and the deadline has passed.
            let past = Client::new(&dir.join("one-ca.pem"), Instant::now()).unwrap();
            assert!(past.get(&url).await.is_err());
        });
    assert!(Client::new(&dir.join("missing.pem"), Instant::now()).is_err());
    assert!(Client::new(&dir.join("one.key"), Instant::now()).is_err());
}
