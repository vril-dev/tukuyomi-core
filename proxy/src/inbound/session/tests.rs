use std::time::{Duration, Instant as StdInstant};

use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};

use super::*;
use crate::inbound::conn::tests::{
    BLOCK, Mode, Parsed, Rig, config, finish_sending, form_post, parse_response, put, read_all,
    routed_to_h_test, run,
};

const SEC: Duration = Duration::from_secs(1);

/// A configuration that keeps a connection for a while after a response.
fn kept() -> ProxyConfig {
    ProxyConfig {
        keepalive_timeout: 10 * SEC,
        lingering_timeout: Duration::from_millis(300),
        ..config()
    }
}

fn get(target: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n").into_bytes()
}

/// Reads until `n` responses have come (the answers of the proxy have no body), or the server closes the
/// connection; and whether it did.
async fn responses(sock: &TcpStream, n: usize) -> (Vec<Parsed>, bool) {
    let mut raw = Vec::new();
    let mut found = Vec::new();
    let mut buf = [0u8; 4096];
    let closed = timeout(30 * SEC, async {
        while found.len() < n {
            while let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head: Vec<u8> = raw.drain(..end + 4).collect();
                found.push(parse_response(&head));
            }
            if found.len() >= n {
                break;
            }
            sock.readable().await.unwrap();
            match sock.try_read(&mut buf) {
                Ok(0) => return true,
                Ok(k) => raw.extend_from_slice(&buf[..k]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return true,
            }
        }
        false
    })
    .await
    .expect("the responses came");
    (found, closed)
}

/// Everything the server sends until it closes the connection; a reset is a failure.
async fn read_clean(sock: &TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    timeout(30 * SEC, async {
        loop {
            sock.readable().await.unwrap();
            match sock.try_read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("the connection was reset: {e}"),
            }
        }
    })
    .await
    .expect("the server closed the connection");
    out
}

#[test]
fn requests_on_one_connection_are_inspected_and_answered_in_order() {
    run(async {
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        // Two requests in one write, the second with a body; then a third on the same connection.
        let mut both = get("/a");
        both.extend_from_slice(&form_post("Content-Length: 3\r\n\r\na=b"));
        put(&client, &both).await;
        let (answers, closed) = responses(&client, 2).await;
        assert!(!closed);
        for answer in &answers {
            assert_eq!(answer.status, 403);
            assert!(answer.all("connection").is_empty());
        }
        put(&client, &get("/c")).await;
        let (answers, closed) = responses(&client, 1).await;
        assert!(!closed && answers[0].status == 403);
        finish_sending(&mut client).await;
        assert!(read_all(&client).await.is_empty());
        let seen = rig.finish(task).await;
        let order: Vec<(&str, &str)> = seen
            .iter()
            .map(|s| (s.method.as_str(), s.uri.as_str()))
            .collect();
        assert_eq!(order, [("GET", "/a"), ("POST", "/p?q=1"), ("GET", "/c")]);
        assert!(seen.iter().all(|s| s.proto == "HTTP/1.1"));
    });
}

#[test]
fn a_404_keeps_the_connection_if_the_request_had_no_body_and_ends_it_otherwise() {
    run(async {
        // The host `h` has no route here.
        let rig = Rig::with(kept(), Mode::Answer(BLOCK), &routed_to_h_test()).await;
        let (client, task) = rig.connect().await;
        for target in ["/a", "/b"] {
            put(&client, &get(target)).await;
            let (answers, closed) = responses(&client, 1).await;
            assert!(!closed && answers[0].status == 404);
            assert!(answers[0].all("connection").is_empty());
        }
        put(&client, &form_post("Content-Length: 3\r\n\r\na=b")).await;
        let last = parse_response(&read_all(&client).await);
        assert_eq!(last.status, 404);
        assert_eq!(last.all("connection"), ["close"]);
        assert!(rig.finish(task).await.is_empty());
    });
}

#[test]
fn a_bad_second_head_closes_the_connection_without_breaking_the_first_answer() {
    run(async {
        let bad = b"GET /b HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
        // Pipelined behind the first request.
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        let mut both = get("/a");
        both.extend_from_slice(bad);
        put(&client, &both).await;
        let raw = read_all(&client).await;
        let first = parse_response(&raw);
        assert_eq!(first.status, 403);
        // The answer is whole and nothing follows it: no answer to the bad head.
        assert_eq!(
            raw.len(),
            raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4
        );
        let seen = rig.finish(task).await;
        assert_eq!(seen.len(), 1);
        // Sent after the first answer.
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/a")).await;
        let (answers, closed) = responses(&client, 1).await;
        assert!(!closed && answers[0].status == 403);
        put(&client, bad).await;
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 1);
    });
}

#[test]
fn a_response_that_ends_the_connection_says_so_and_nothing_after_it_is_served() {
    run(async {
        let chunked = form_post("Transfer-Encoding: chunked\r\n\r\n3\r\na=b\r\n0\r\n\r\n");
        let old = b"GET /old HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\n".to_vec();
        let closing = b"GET /close HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".to_vec();
        for (name, first) in [("chunked", chunked), ("http/1.0", old), ("close", closing)] {
            let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
            let (client, task) = rig.connect().await;
            let mut input = first.clone();
            input.extend_from_slice(&get("/after"));
            put(&client, &input).await;
            let raw = read_all(&client).await;
            let answer = parse_response(&raw);
            assert_eq!(answer.status, 403, "{name}");
            assert_eq!(answer.all("connection"), ["close"], "{name}");
            let seen = rig.finish(task).await;
            assert_eq!(seen.len(), 1, "{name}");
            if name == "http/1.0" {
                assert_eq!(seen[0].proto, "HTTP/1.0");
                assert!(
                    raw.starts_with(b"HTTP/1.0 403"),
                    "{:?}",
                    raw.escape_ascii().to_string()
                );
            }
        }
    });
}

#[test]
fn the_number_of_requests_and_the_age_of_the_connection_end_it() {
    run(async {
        // The second request is the last one.
        let few = ProxyConfig {
            keepalive_requests: 2,
            ..kept()
        };
        let rig = Rig::new(few, Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        let (first, closed) = responses(&client, 1).await;
        assert!(!closed && first[0].all("connection").is_empty());
        put(&client, &get("/2")).await;
        let (second, _) = responses(&client, 1).await;
        assert_eq!(second[0].all("connection"), ["close"]);
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 2);

        // The age of the connection: the request that is answered after it has the last answer.
        let old = ProxyConfig {
            keepalive_time: Duration::from_millis(400),
            ..kept()
        };
        let rig = Rig::new(old, Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        let (first, _) = responses(&client, 1).await;
        assert!(first[0].all("connection").is_empty());
        sleep(Duration::from_millis(500)).await;
        put(&client, &get("/2")).await;
        let (second, _) = responses(&client, 1).await;
        assert_eq!(second[0].all("connection"), ["close"]);
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 2);
    });
}

#[test]
fn the_time_of_a_request_and_of_a_head_start_again_with_each_request() {
    run(async {
        // Neither the request time nor the head time is as long as the connection lives.
        let cfg = ProxyConfig {
            request_total: Duration::from_millis(1500),
            head_read: Duration::from_millis(1500),
            keepalive_timeout: 10 * SEC,
            ..config()
        };
        let rig = Rig::new(cfg, Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        sleep(Duration::from_millis(1800)).await;
        put(&client, &get("/2")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        // A head that takes longer than the connection has lived, in two pieces within its own time.
        let third = get("/3");
        put(&client, &third[..10]).await;
        sleep(Duration::from_millis(1000)).await;
        put(&client, &third[10..]).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        finish_sending(&mut client).await;
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 3);
    });
}

#[test]
fn an_idle_connection_closes_after_the_wait_and_at_once_when_the_stop_begins() {
    run(async {
        let wait = ProxyConfig {
            keepalive_timeout: Duration::from_millis(400),
            ..config()
        };
        let rig = Rig::new(wait, Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        let answered = StdInstant::now();
        assert!(read_all(&client).await.is_empty());
        assert!(answered.elapsed() >= Duration::from_millis(300));
        assert!(answered.elapsed() < 10 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);

        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        sleep(Duration::from_millis(100)).await;
        let began = StdInstant::now();
        rig.ctx.ingress.close();
        assert!(read_all(&client).await.is_empty());
        assert!(began.elapsed() < 5 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);

        // A request that starts after the stop has no way to the driver, and its answer ends the connection.
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        rig.ctx.ingress.close();
        put(&client, &get("/late")).await;
        let answer = parse_response(&read_all(&client).await);
        assert_eq!(answer.status, 503);
        assert_eq!(answer.all("connection"), ["close"]);
        assert!(rig.finish(task).await.is_empty());
    });
}

#[test]
fn an_answer_before_the_body_was_read_closes_the_connection_but_the_client_still_reads_it() {
    run(async {
        // A chunked body that is over the limit answers 413 half way. The client goes on sending, and its bytes
        // are read and thrown away, so that the close does not reset the connection under it.
        let patient = ProxyConfig {
            lingering_timeout: 5 * SEC,
            ..kept()
        };
        let rig = Rig::new(patient, Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        let mut head = form_post("Transfer-Encoding: chunked\r\n\r\n800\r\n");
        head.extend_from_slice(&[b'a'; 2048]);
        put(&client, &head).await;
        let (answers, _) = responses(&client, 1).await;
        assert_eq!(answers[0].status, 413);
        assert_eq!(answers[0].all("connection"), ["close"]);
        put(&client, &[b'b'; 100_000]).await;
        finish_sending(&mut client).await;
        assert!(read_clean(&client).await.is_empty());
        assert!(rig.finish(task).await.is_empty());

        // The reading is bounded: by the time a read waits, and by the bytes.
        let cfg = ProxyConfig {
            lingering_timeout: Duration::from_millis(300),
            lingering_time: 5 * SEC,
            lingering_bytes: 10_000,
            ..kept()
        };
        let rig = Rig::new(cfg.clone(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &head).await;
        let _ = responses(&client, 1).await;
        let began = StdInstant::now();
        assert!(rig.finish(task).await.is_empty());
        assert!(began.elapsed() >= Duration::from_millis(250) && began.elapsed() < 4 * SEC);
        let rig = Rig::new(
            ProxyConfig {
                lingering_timeout: 5 * SEC,
                ..cfg
            },
            Mode::Answer(BLOCK),
        )
        .await;
        let (client, task) = rig.connect().await;
        put(&client, &head).await;
        let _ = responses(&client, 1).await;
        put(&client, &[b'b'; 20_000]).await;
        let began = StdInstant::now();
        assert!(rig.finish(task).await.is_empty());
        assert!(began.elapsed() < 4 * SEC);
        drop(client);
    });
}

#[test]
fn a_response_that_closes_the_connection_is_read_whole_although_the_client_went_on_sending() {
    run(async {
        let old = b"GET /old HTTP/1.0\r\nHost: h\r\n\r\n".to_vec();
        let closing = b"GET /close HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".to_vec();
        for (name, first) in [("http/1.0", old), ("close", closing)] {
            let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
            let (mut client, task) = rig.connect().await;
            // The requests behind the first one are more than the gate reads, and no head of them is refused,
            // so only the lingering keeps the close from resetting the connection under the client.
            let mut input = first.clone();
            for _ in 0..2000 {
                input.extend_from_slice(&get("/next"));
            }
            put(&client, &input).await;
            let (answers, _) = responses(&client, 1).await;
            assert_eq!(answers[0].status, 403, "{name}");
            assert_eq!(answers[0].all("connection"), ["close"], "{name}");
            // The client has not seen the end of the response yet, and goes on.
            put(&client, &[b'b'; 100_000]).await;
            finish_sending(&mut client).await;
            assert!(read_clean(&client).await.is_empty(), "{name}");
            assert_eq!(rig.finish(task).await.len(), 1, "{name}");
        }
    });
}

#[test]
fn a_drain_closes_the_connection_that_waits_for_a_request_and_leaves_one_that_is_in_a_request() {
    run(async {
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        sleep(Duration::from_millis(100)).await;
        let began = StdInstant::now();
        rig.ctx.ingress.drain();
        assert!(read_all(&client).await.is_empty());
        assert!(began.elapsed() < 5 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);

        // A connection that has begun its next request is not told: half of the head is there.
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        let second = get("/2");
        put(&client, &second[..10]).await;
        sleep(Duration::from_millis(100)).await;
        rig.ctx.ingress.drain();
        sleep(Duration::from_millis(100)).await;
        put(&client, &second[10..]).await;
        let (answers, closed) = responses(&client, 1).await;
        assert!(!closed && answers[0].status == 403 && answers[0].all("connection").is_empty());
        finish_sending(&mut client).await;
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 2);
    });
}

#[test]
fn a_request_without_a_copy_of_its_head_is_not_served_and_closes_the_connection() {
    run(async {
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let local = server.local_addr().unwrap();
        let (session, mut gate) = Session::start(server, peer, local, &rig.ctx, Instant::now());
        put(&client, &get("/a")).await;
        gate.first_head(Instant::now() + 10 * SEC).await.unwrap();
        // The copy the gate made is lost, as it would be if hyper and the gate disagreed about the bytes.
        let other = http::Request::get("/other")
            .header("host", "h")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(session.link.take_for(&other).is_none());
        assert_eq!(session.drive(&mut gate).await, End::Done);
        drop(gate);
        let answer = parse_response(&read_all(&client).await);
        assert_eq!(answer.status, 400);
        assert_eq!(answer.all("connection"), ["close"]);
        assert_eq!(answer.all("content-length"), ["0"]);
        let served = tokio::spawn(async {});
        assert!(rig.finish(served).await.is_empty());
    });
}
