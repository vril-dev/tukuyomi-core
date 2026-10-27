use std::future::Future;
use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::run::signals::tests::runtime;

const METRICS: &str = "tukuyomi_test_total 1\n";

/// A stand-in for the proxy: it is ready, or not for the word it is given.
struct Fake {
    ready: Mutex<Result<(), &'static str>>,
}

impl Fake {
    fn new() -> Arc<Fake> {
        Arc::new(Fake {
            ready: Mutex::new(Err("starting")),
        })
    }

    fn set(&self, ready: Result<(), &'static str>) {
        *self.ready.lock().unwrap() = ready;
    }
}

impl Source for Fake {
    fn ready(&self) -> Result<(), &'static str> {
        *self.ready.lock().unwrap()
    }

    fn metrics(&self) -> String {
        METRICS.to_string()
    }
}

/// Runs a test body; a body that hangs fails the test instead of the run.
fn run<F: Future>(body: F) -> F::Output {
    runtime().block_on(async {
        timeout(Duration::from_secs(60), body)
            .await
            .expect("the test hung")
    })
}

/// The listener on a free loopback port, and the handle that keeps it open.
async fn start(source: &Arc<Fake>) -> (SocketAddr, Status) {
    let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let address = listener.local_addr().unwrap();
    (address, serve(listener, source.clone()))
}

/// Sends `request` and reads until the listener closes. A reset ends the read as a close does.
async fn exchange(address: SocketAddr, request: &[u8]) -> String {
    let mut sock = TcpStream::connect(address).await.unwrap();
    sock.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = sock.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

fn get(address: SocketAddr, target: &str) -> impl Future<Output = String> {
    let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    async move { exchange(address, request.as_bytes()).await }
}

fn body(answer: &str) -> &str {
    answer.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

#[test]
fn readyz_follows_the_word_that_the_proxy_gives_and_healthz_and_metrics_answer_throughout() {
    run(async {
        let source = Fake::new();
        let (address, _status) = start(&source).await;
        for (ready, status, text) in [
            (Err("starting"), "503 Service Unavailable", "starting"),
            (Ok(()), "200 OK", "ready"),
            (
                Err("inspector down"),
                "503 Service Unavailable",
                "inspector down",
            ),
            (Err("stopping"), "503 Service Unavailable", "stopping"),
        ] {
            source.set(ready);
            let answer = get(address, "/readyz").await;
            assert!(
                answer.starts_with(&format!("HTTP/1.1 {status}\r\n")),
                "{answer}"
            );
            assert_eq!(body(&answer), text);
            assert!(answer.contains("Connection: close\r\n"), "{answer}");
            assert!(answer.contains(&format!("Content-Length: {}\r\n", text.len())));

            let health = get(address, "/healthz").await;
            assert!(health.starts_with("HTTP/1.1 200 OK\r\n"), "{health}");
            assert_eq!(body(&health), "ok");
            assert!(
                get(address, "/metrics")
                    .await
                    .starts_with("HTTP/1.1 200 OK\r\n")
            );
        }

        let metrics = get(address, "/metrics").await;
        assert!(
            metrics.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"),
            "{metrics}"
        );
        assert_eq!(body(&metrics), METRICS);

        // A HEAD has the status and the length of the GET, and no body.
        let head = exchange(
            address,
            b"HEAD /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains(&format!("Content-Length: {}\r\n", METRICS.len())));
        assert_eq!(body(&head), "");
    });
}

#[test]
fn another_method_is_405_another_target_is_404_and_a_head_that_is_not_http_1_1_is_400() {
    run(async {
        let source = Fake::new();
        let (address, _status) = start(&source).await;
        let post = exchange(address, b"POST /healthz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            post.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{post}"
        );
        assert!(post.contains("Allow: GET, HEAD\r\n"), "{post}");
        // The method decides first, for any target.
        let post = exchange(address, b"DELETE /other HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(post.starts_with("HTTP/1.1 405 "), "{post}");

        for target in [
            "/healthz?x=1",
            "/metrics?",
            "/healthz/",
            "/",
            "/Healthz",
            "http://x/healthz",
        ] {
            let answer = get(address, target).await;
            assert!(
                answer.starts_with("HTTP/1.1 404 Not Found\r\n"),
                "{target}: {answer}"
            );
            assert!(answer.contains("Content-Length: 0\r\n"), "{answer}");
        }

        for request in [
            &b"GET /healthz HTTP/1.0\r\n\r\n"[..],
            b"GET /healthz HTTP/1.1 \r\n\r\n",
            b"nonsense\r\n\r\n",
            b"GET /healthz HTTP/1.1\r\nBad Name: x\r\n\r\n",
        ] {
            let answer = exchange(address, request).await;
            assert!(
                answer.starts_with("HTTP/1.1 400 Bad Request\r\n"),
                "{:?}: {answer}",
                String::from_utf8_lossy(request)
            );
        }
        // None of that ended the listener.
        assert!(
            get(address, "/healthz")
                .await
                .starts_with("HTTP/1.1 200 OK")
        );
    });
}

#[test]
fn a_head_of_4096_bytes_is_read_and_one_byte_more_is_refused() {
    run(async {
        let source = Fake::new();
        let (address, _status) = start(&source).await;
        let head = |total: usize| {
            let start = "GET /healthz HTTP/1.1\r\nX-Pad: ";
            let pad = total - start.len() - "\r\n\r\n".len();
            format!("{start}{}\r\n\r\n", "a".repeat(pad))
        };
        let exact = head(HEAD_MAX);
        assert_eq!(exact.len(), HEAD_MAX);
        let answer = exchange(address, exact.as_bytes()).await;
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer:.60}");

        // One byte past the limit: the end of the head is not in the bytes that are read. The answer may be lost to
        // the reset that the unread byte brings, so either it is 400 or nothing came; it is never 200.
        let over = head(HEAD_MAX + 1);
        let answer = exchange(address, over.as_bytes()).await;
        assert!(
            answer.is_empty() || answer.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{answer:.60}"
        );
        assert!(
            get(address, "/healthz")
                .await
                .starts_with("HTTP/1.1 200 OK")
        );
    });
}

#[test]
fn a_ninth_connection_is_accepted_and_closed_and_one_is_served_again_when_a_place_is_free() {
    run(async {
        let source = Fake::new();
        let (address, _status) = start(&source).await;
        // Eight connections that send nothing take all the places.
        let mut held = Vec::new();
        for _ in 0..SEATS {
            held.push(TcpStream::connect(address).await.unwrap());
        }
        sleep(Duration::from_millis(200)).await;

        // The ninth is accepted and closed at once: it reads the end without an answer, long before the head time.
        let began = tokio::time::Instant::now();
        let mut ninth = TcpStream::connect(address).await.unwrap();
        let mut out = Vec::new();
        let _ = ninth.read_to_end(&mut out).await;
        assert!(out.is_empty());
        assert!(began.elapsed() < HEAD_WAIT);

        // A place comes free when one of the eight goes, and then the next connection is answered.
        held.pop();
        let mut answer = String::new();
        for _ in 0..50 {
            answer = get(address, "/healthz").await;
            if !answer.is_empty() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer:?}");
    });
}

#[test]
fn a_connection_that_sends_no_head_in_time_is_closed_without_an_answer() {
    run(async {
        let source = Fake::new();
        let (address, _status) = start(&source).await;
        let began = tokio::time::Instant::now();
        let mut sock = TcpStream::connect(address).await.unwrap();
        // Part of a head, and then nothing.
        sock.write_all(b"GET /healthz HTT").await.unwrap();
        let mut out = Vec::new();
        let _ = sock.read_to_end(&mut out).await;
        assert!(out.is_empty());
        assert!(began.elapsed() >= HEAD_WAIT);
    });
}

#[test]
fn dropping_the_status_closes_the_listener() {
    run(async {
        let source = Fake::new();
        let (address, status) = start(&source).await;
        assert!(
            get(address, "/healthz")
                .await
                .starts_with("HTTP/1.1 200 OK")
        );
        drop(status);
        // The aborted task is dropped when the runtime next runs it, and the listener goes with it.
        let mut refused = false;
        for _ in 0..50 {
            if TcpStream::connect(address).await.is_err() {
                refused = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(refused, "the listener is still open");
    });
}

#[test]
fn the_proxy_is_ready_only_when_it_is_bound_not_stopping_and_the_kernel_is_ready() {
    let readiness = Readiness::new();
    assert_eq!(readiness.check(Phase::Starting), Err("starting"));
    assert_eq!(readiness.check(Phase::Ready), Err("starting"));
    readiness.bound();
    assert_eq!(readiness.check(Phase::Ready), Ok(()));
    // The restart of the inspector, and a kernel that failed.
    assert_eq!(readiness.check(Phase::Starting), Err("inspector down"));
    assert_eq!(readiness.check(Phase::Stopping), Err("inspector down"));
    readiness.stopping();
    assert_eq!(readiness.check(Phase::Ready), Err("stopping"));
}
