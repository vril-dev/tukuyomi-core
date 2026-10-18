use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, timeout};

use crate::config::ProxyConfig;
use crate::forward::origin::tests::{
    Outcome, Seen, bare, collect, config, ctx, far, next_request, pull, put, refused, request, run,
};
use crate::forward::origin::{OriginError, forward};
use crate::inbound::conn::Ctx;

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// An upstream that takes any number of connections and serves each as `serve` does. It counts the connections
/// it took and those that ended, and keeps the requests it read.
struct Upstream {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    ended: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    /// `serve` is given the number of the connection (from 0), the stream, and the place where requests are kept.
    async fn start<F, Fut>(serve: F) -> Upstream
    where
        F: Fn(usize, TcpStream, Arc<Mutex<Vec<Seen>>>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = Upstream {
            addr: listener.local_addr().unwrap(),
            accepted: Arc::new(AtomicUsize::new(0)),
            ended: Arc::new(AtomicUsize::new(0)),
            seen: Arc::default(),
        };
        let (accepted, ended, seen) = (
            upstream.accepted.clone(),
            upstream.ended.clone(),
            upstream.seen.clone(),
        );
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let n = accepted.fetch_add(1, Ordering::SeqCst);
                let (done, ended) = (serve(n, sock, seen.clone()), ended.clone());
                tokio::spawn(async move {
                    done.await;
                    ended.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        upstream
    }

    /// An upstream that answers every request with `ok`, as long as the connection lasts.
    async fn keeping() -> Upstream {
        Upstream::start(|_, sock, seen| serve_ok(sock, seen, Duration::ZERO)).await
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Waits until `n` connections have ended: closed by the proxy, or by the upstream itself.
    async fn ended(&self, n: usize) {
        timeout(Duration::from_secs(10), async {
            while self.ended.load(Ordering::SeqCst) < n {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the connections ended");
    }
}

/// Answers each request with `ok` after `pause`, until the other side closes. The answer to a HEAD request has
/// no body.
async fn serve_ok(sock: TcpStream, seen: Arc<Mutex<Vec<Seen>>>, pause: Duration) {
    while let Some(next) = next_request(&sock).await {
        let head = next.line.starts_with("HEAD ");
        seen.lock().unwrap().push(next);
        sleep(pause).await;
        let reply = if head { &OK[..OK.len() - 2] } else { OK };
        if put(&sock, reply).await.is_err() {
            return;
        }
    }
}

/// A configuration that keeps connections.
fn keeping(addr: SocketAddr) -> ProxyConfig {
    ProxyConfig {
        upstream_keepalive: 32,
        ..config(addr)
    }
}

/// Forwards a request with no body and reads the answer to its end: the status and the body.
async fn fetch(ctx: &Ctx, method: &str) -> Result<(u16, Vec<u8>), OriginError> {
    let out: Outcome = forward(bare(ctx, method), ctx, far()).await;
    let response = out?;
    let status = response.status().as_u16();
    Ok((status, collect(response.into_body()).await.0))
}

#[test]
fn requests_to_one_upstream_share_a_connection_and_do_not_ask_it_to_close() {
    run(async {
        let up = Upstream::keeping().await;
        let ctx = ctx(keeping(up.addr));
        for _ in 0..5 {
            assert_eq!(fetch(&ctx, "GET").await.unwrap(), (200, b"ok".to_vec()));
        }
        assert_eq!(up.accepted(), 1);
        assert_eq!(ctx.pool.waiting(), 1);
        let seen = up.seen.lock().unwrap();
        assert_eq!(seen.len(), 5);
        assert!(
            seen.iter()
                .all(|request| request.all("connection").is_empty())
        );
    });
}

#[test]
fn without_a_pool_every_request_has_its_own_connection_and_asks_it_to_close() {
    run(async {
        let up = Upstream::keeping().await;
        let ctx = ctx(config(up.addr));
        for _ in 0..3 {
            assert_eq!(fetch(&ctx, "GET").await.unwrap(), (200, b"ok".to_vec()));
        }
        assert_eq!(up.accepted(), 3);
        assert_eq!(ctx.pool.waiting(), 0);
        up.ended(3).await;
        let seen = up.seen.lock().unwrap();
        assert!(
            seen.iter()
                .all(|request| request.all("connection") == ["close"])
        );
    });
}

#[test]
fn a_connection_carries_the_configured_number_of_requests_and_no_more() {
    run(async {
        let up = Upstream::keeping().await;
        let ctx = ctx(ProxyConfig {
            upstream_keepalive_requests: 2,
            ..keeping(up.addr)
        });
        for _ in 0..5 {
            fetch(&ctx, "GET").await.unwrap();
        }
        // 2 + 2 + 1.
        assert_eq!(up.accepted(), 3);

        // One request per connection: nothing is kept.
        let up = Upstream::keeping().await;
        let ctx = self::ctx(ProxyConfig {
            upstream_keepalive_requests: 1,
            ..keeping(up.addr)
        });
        for _ in 0..3 {
            fetch(&ctx, "GET").await.unwrap();
        }
        assert_eq!((up.accepted(), ctx.pool.waiting()), (3, 0));
    });
}

#[test]
fn a_connection_waits_for_the_configured_time_and_not_longer() {
    run(async {
        let up = Upstream::keeping().await;
        let ctx = ctx(ProxyConfig {
            upstream_keepalive_timeout: Duration::from_millis(600),
            ..keeping(up.addr)
        });
        fetch(&ctx, "GET").await.unwrap();
        sleep(Duration::from_millis(100)).await;
        fetch(&ctx, "GET").await.unwrap();
        assert_eq!(up.accepted(), 1);
        sleep(Duration::from_millis(900)).await;
        fetch(&ctx, "GET").await.unwrap();
        // The one that waited too long was closed, not used.
        assert_eq!(up.accepted(), 2);
        up.ended(1).await;
    });
}

#[test]
fn a_connection_that_waits_closes_itself_at_the_end_of_the_wait() {
    run(async {
        let up = Upstream::keeping().await;
        // The reads of a busy connection may idle for a minute; a waiting one may wait for a third of a second.
        let ctx = ctx(ProxyConfig {
            response_idle: Duration::from_secs(60),
            upstream_keepalive_timeout: Duration::from_millis(300),
            ..keeping(up.addr)
        });
        fetch(&ctx, "GET").await.unwrap();
        let start = Instant::now();
        // Nothing takes or puts a connection from here on, and the upstream still sees this one closed.
        up.ended(1).await;
        assert!(start.elapsed() >= Duration::from_millis(250));
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(up.accepted(), 1);
    });
}

#[test]
fn a_connection_that_is_taken_gets_the_limit_of_the_request_back() {
    run(async {
        // The upstream takes 0.6 s to answer, which is more than the connection may wait. The limit of the wait
        // must not be the limit of the answer.
        let up =
            Upstream::start(|_, sock, seen| serve_ok(sock, seen, Duration::from_millis(600))).await;
        let ctx = ctx(ProxyConfig {
            response_idle: Duration::from_secs(60),
            upstream_keepalive_timeout: Duration::from_millis(400),
            ..keeping(up.addr)
        });
        for _ in 0..3 {
            assert_eq!(fetch(&ctx, "GET").await.unwrap().0, 200);
        }
        assert_eq!(up.accepted(), 1);
    });
}

#[test]
fn a_connection_whose_request_is_still_being_written_is_not_kept() {
    run(async {
        // The upstream answers as soon as it has the head and then reads nothing more, so the body of the request
        // (far more than the sockets hold) is still being written when the answer has been read to its end.
        let up = Upstream::start(|_, sock, _| async move {
            let mut head = Vec::new();
            let mut buf = [0u8; 4096];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = pull(&sock, &mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                head.extend_from_slice(&buf[..n]);
            }
            put(&sock, OK).await.unwrap();
            sleep(Duration::from_secs(30)).await;
        })
        .await;
        let ctx = ctx(ProxyConfig {
            max_buffered_bytes: 64 << 20,
            ..keeping(up.addr)
        });
        let sent = request(&ctx, "POST", &[("Host", "h.test")], &vec![b'a'; 32 << 20]);
        let response = forward(sent, &ctx, far()).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(collect(response.into_body()).await.0, b"ok");
        assert_eq!(ctx.pool.waiting(), 0);
    });
}

#[test]
fn the_pool_keeps_the_configured_number_and_closes_the_one_that_waited_longest() {
    run(async {
        let up =
            Upstream::start(|_, sock, seen| serve_ok(sock, seen, Duration::from_millis(100))).await;
        let ctx = Arc::new(ctx(ProxyConfig {
            upstream_keepalive: 2,
            ..keeping(up.addr)
        }));
        let fetching: Vec<_> = (0..3)
            .map(|_| {
                let ctx = ctx.clone();
                tokio::spawn(async move { fetch(&ctx, "GET").await })
            })
            .collect();
        for fetching in fetching {
            assert_eq!(fetching.await.unwrap().unwrap().0, 200);
        }
        assert_eq!(up.accepted(), 3);
        assert_eq!(ctx.pool.waiting(), 2);
        up.ended(1).await;
        // The newest connection is taken first: a request in turn finds one, and makes no new connection.
        fetch(&ctx, "GET").await.unwrap();
        assert_eq!((up.accepted(), ctx.pool.waiting()), (3, 2));
    });
}

#[test]
fn a_connection_that_the_upstream_closed_while_it_waited_is_not_used() {
    run(async {
        let up = Upstream::start(|_, sock, seen| async move {
            if let Some(next) = next_request(&sock).await {
                seen.lock().unwrap().push(next);
                put(&sock, OK).await.unwrap();
            }
            // The upstream closes a connection that has done its work, with no word to the proxy.
        })
        .await;
        let ctx = ctx(keeping(up.addr));
        fetch(&ctx, "POST").await.unwrap();
        up.ended(1).await;
        sleep(Duration::from_millis(100)).await;
        // Not even a request that must not be sent twice meets the closed connection.
        fetch(&ctx, "POST").await.unwrap();
        assert_eq!(up.accepted(), 2);
    });
}

/// The upstream answers the first request on its first connection, reads the second request and closes without a
/// word, and then serves every connection as usual. A request is sent on a pooled connection that way.
async fn closing_upstream() -> Upstream {
    Upstream::start(|n, sock, seen| async move {
        if n > 0 {
            serve_ok(sock, seen, Duration::ZERO).await;
            return;
        }
        for _ in 0..2 {
            let Some(next) = next_request(&sock).await else {
                return;
            };
            let first = seen.lock().unwrap().is_empty();
            seen.lock().unwrap().push(next);
            if first {
                put(&sock, OK).await.unwrap();
            }
        }
    })
    .await
}

#[test]
fn a_request_that_fails_on_a_pooled_connection_is_sent_again_if_it_may_be() {
    run(async {
        for method in ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"] {
            let up = closing_upstream().await;
            let ctx = ctx(keeping(up.addr));
            fetch(&ctx, "GET").await.unwrap();
            let sent = request(&ctx, method, &[("Host", "h.test")], b"abc");
            let response = forward(sent, &ctx, far()).await.unwrap();
            assert_eq!(response.status(), 200, "{method}");
            collect(response.into_body()).await;
            // The same request, body and all, went to the new connection.
            assert_eq!(up.accepted(), 2, "{method}");
            let seen = up.seen.lock().unwrap();
            let last = seen.last().unwrap();
            assert!(last.line.starts_with(method), "{method}");
            assert_eq!(last.body, b"abc", "{method}");
        }
    });
}

#[test]
fn a_request_that_must_not_be_sent_twice_is_not_sent_again() {
    run(async {
        for method in ["POST", "LOCK", "PATCH"] {
            let up = closing_upstream().await;
            let ctx = ctx(keeping(up.addr));
            fetch(&ctx, "GET").await.unwrap();
            // A key from the client does not make the request safe to send twice.
            let sent = request(
                &ctx,
                method,
                &[("Host", "h.test"), ("Idempotency-Key", "k1")],
                b"abc",
            );
            assert_eq!(refused(forward(sent, &ctx, far()).await), OriginError::Send);
            sleep(Duration::from_millis(200)).await;
            assert_eq!(up.accepted(), 1, "{method}");
            // The next request is not troubled by it.
            assert_eq!(fetch(&ctx, "GET").await.unwrap().0, 200);
            assert_eq!(up.accepted(), 2, "{method}");
        }
    });
}

#[test]
fn a_new_connection_that_fails_is_not_tried_again() {
    run(async {
        // The upstream reads the request and closes with no answer.
        let up = Upstream::start(|_, sock, seen| async move {
            if let Some(next) = next_request(&sock).await {
                seen.lock().unwrap().push(next);
            }
        })
        .await;
        let ctx = ctx(keeping(up.addr));
        assert_eq!(fetch(&ctx, "GET").await.unwrap_err(), OriginError::Send);
        sleep(Duration::from_millis(200)).await;
        assert_eq!(up.accepted(), 1);
    });
}

#[test]
fn a_body_that_is_dropped_before_its_end_does_not_return_the_connection() {
    run(async {
        let up = Upstream::start(|n, sock, seen| async move {
            if n > 0 {
                serve_ok(sock, seen, Duration::ZERO).await;
                return;
            }
            // A body of 100 bytes, 3 of them sent; then the connection is watched until it ends.
            next_request(&sock).await.unwrap();
            put(&sock, b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc")
                .await
                .unwrap();
            while next_request(&sock).await.is_some() {}
        })
        .await;
        let ctx = ctx(keeping(up.addr));
        let response = forward(bare(&ctx, "GET"), &ctx, far()).await.unwrap();
        drop(response);
        assert_eq!(ctx.pool.waiting(), 0);
        up.ended(1).await;
        assert_eq!(fetch(&ctx, "GET").await.unwrap().0, 200);
        assert_eq!(up.accepted(), 2);
    });
}

#[test]
fn an_answer_that_ends_the_connection_does_not_return_it() {
    run(async {
        // Each answer is read to its end. Only the last two, which say nothing about the connection, are kept.
        // The upstream closes after an answer whose body lasts until the connection ends, and not after the others.
        let cases: [(&[u8], usize, bool); 7] = [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                0,
                false,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: x, Close\r\n\r\nok",
                0,
                false,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: upgrade\r\n\r\nok",
                0,
                false,
            ),
            (b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", 0, false),
            (b"HTTP/1.1 200 OK\r\n\r\nok", 0, true),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
                1,
                false,
            ),
            (OK, 1, false),
        ];
        for (reply, waiting, closes) in cases {
            let up = Upstream::start(move |_, sock, _| async move {
                next_request(&sock).await.unwrap();
                put(&sock, reply).await.unwrap();
                while !closes && next_request(&sock).await.is_some() {}
            })
            .await;
            let ctx = ctx(keeping(up.addr));
            let (status, body) = fetch(&ctx, "GET").await.unwrap();
            let text = String::from_utf8_lossy(reply);
            assert_eq!((status, body), (200, b"ok".to_vec()), "{text:?}");
            assert_eq!(ctx.pool.waiting(), waiting, "{text:?}");
        }
    });
}

#[test]
fn an_answer_without_a_body_returns_its_connection_with_its_head() {
    run(async {
        let up = Upstream::keeping().await;
        let ctx = ctx(keeping(up.addr));
        // The answer to a HEAD request: the response is not read at all.
        let response = forward(bare(&ctx, "HEAD"), &ctx, far()).await.unwrap();
        assert_eq!(ctx.pool.waiting(), 1);
        drop(response);
        assert_eq!(ctx.pool.waiting(), 1);
        assert_eq!(fetch(&ctx, "GET").await.unwrap().0, 200);
        assert_eq!(up.accepted(), 1);
    });
}

#[test]
fn the_cap_on_the_head_holds_again_on_a_connection_that_is_used_again() {
    run(async {
        let up = Upstream::start(|_, sock, _| async move {
            next_request(&sock).await.unwrap();
            put(&sock, OK).await.unwrap();
            next_request(&sock).await.unwrap();
            let mut long = b"HTTP/1.1 200 OK\r\nX-Long: ".to_vec();
            long.extend_from_slice(&[b'a'; 300]);
            long.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
            put(&sock, &long).await.unwrap();
            while next_request(&sock).await.is_some() {}
        })
        .await;
        let ctx = ctx(ProxyConfig {
            // The first answer fits, a head of 300 bytes does not.
            upstream_head_wire: 200,
            ..keeping(up.addr)
        });
        assert_eq!(fetch(&ctx, "GET").await.unwrap().0, 200);
        assert_eq!(fetch(&ctx, "GET").await.unwrap_err(), OriginError::Head);
        assert_eq!((up.accepted(), ctx.pool.waiting()), (1, 0));
    });
}

#[test]
fn a_connection_that_waited_is_not_cut_off_by_the_time_it_waited() {
    run(async {
        // The time a connection may be idle in a read is 1 s; it waits for 0.6 s and is used for an answer that
        // takes 0.6 s. The wait before it must not count against the wait for the answer.
        let up = Upstream::start(|_, sock, seen| async move {
            let mut n = 0;
            while let Some(next) = next_request(&sock).await {
                seen.lock().unwrap().push(next);
                if n > 0 {
                    sleep(Duration::from_millis(600)).await;
                }
                n += 1;
                put(&sock, OK).await.unwrap();
            }
        })
        .await;
        let ctx = ctx(ProxyConfig {
            response_idle: Duration::from_millis(1000),
            upstream_keepalive_timeout: Duration::from_millis(1000),
            ..keeping(up.addr)
        });
        fetch(&ctx, "GET").await.unwrap();
        sleep(Duration::from_millis(600)).await;
        assert_eq!(fetch(&ctx, "GET").await.unwrap().0, 200);
        assert_eq!(up.accepted(), 1);
    });
}
