use std::convert::Infallible;
use std::pin::pin;
use std::sync::Mutex as StdMutex;

use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::AsyncWrite;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::limits;

use super::*;
use crate::inbound::represent::tests::head_of;

const SEC: Duration = Duration::from_secs(1);

fn settings() -> Settings {
    Settings {
        limits: Limits {
            max_head_bytes: 1024,
            max_body: 1 << 10,
        },
        head_read: 5 * SEC,
        keepalive_timeout: 5 * SEC,
        max_body_wire: 4096,
        read_idle: 60 * SEC,
        write_idle: 60 * SEC,
    }
}

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

/// Runs a test body; a body that hangs fails the test instead of the run.
fn run<F: Future>(body: F) -> F::Output {
    runtime().block_on(async {
        timeout(Duration::from_secs(60), body)
            .await
            .expect("the test hung")
    })
}

/// A connected pair: the client side, and a gate over the server side.
async fn rig(settings: Settings) -> (TcpStream, Gate<TcpStream>, Arc<Link>, Gauge) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let link = Link::new(Instant::now());
    let (gate, gauge) = Gate::new(server, settings, link.clone(), Instant::now());
    (client, gate, link, gauge)
}

/// Writes all of `bytes`; a client that is cut off is not a failure of the test.
async fn put(sock: &TcpStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        if sock.writable().await.is_err() {
            return;
        }
        match sock.try_write(bytes) {
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
    }
}

async fn read_some<T: AsyncRead + Unpin>(io: &mut T, room: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; room];
    let n = poll_fn(|cx| {
        let mut buf = ReadBuf::new(&mut out);
        ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
        Poll::Ready(Ok::<_, io::Error>(buf.filled().len()))
    })
    .await?;
    out.truncate(n);
    Ok(out)
}

/// What the gate hands on until it has nothing more for now: the bytes, and whether it ended in the end of the
/// stream (otherwise it waits, or failed).
async fn drain(gate: &mut Gate<TcpStream>) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    loop {
        match timeout(Duration::from_millis(150), read_some(gate, 4096)).await {
            Err(_) => return (bytes, false),
            Ok(Ok(chunk)) if chunk.is_empty() => return (bytes, true),
            Ok(Ok(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(Err(_)) => return (bytes, false),
        }
    }
}

/// Everything the gate hands on until the stream ends.
async fn until_end(gate: &mut Gate<TcpStream>) -> Vec<u8> {
    timeout(10 * SEC, async {
        let mut bytes = Vec::new();
        loop {
            let chunk = read_some(gate, 4096).await.unwrap();
            if chunk.is_empty() {
                return bytes;
            }
            bytes.extend_from_slice(&chunk);
        }
    })
    .await
    .expect("the stream ended")
}

fn get(target: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n").into_bytes()
}

fn post(target: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {target} HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

const CHUNKED: &str = "POST /c HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n";

/// The request hyper would make of `get(target)`.
fn parts_of(target: &str) -> http::request::Parts {
    Request::builder()
        .method("GET")
        .uri(target)
        .header("host", "h")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

fn queued_targets(link: &Link) -> Vec<String> {
    link.lock()
        .queue
        .iter()
        .map(|q| String::from_utf8_lossy(q.head.target()).into_owned())
        .collect()
}

#[test]
fn heads_and_bodies_pass_in_order_and_a_body_that_looks_like_a_request_is_only_a_body() {
    run(async {
        let (client, mut gate, link, _) = rig(settings()).await;
        let inner = "GET /inner HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut input = post("/first", inner);
        input.extend_from_slice(&get("/second"));
        put(&client, &input).await;
        let (bytes, ended) = drain(&mut gate).await;
        assert_eq!(bytes, input);
        assert!(!ended);
        // Two requests: the body of the first is not a third.
        assert_eq!(queued_targets(&link), ["/first", "/second"]);
        assert_eq!(link.lock().released, 2);
        assert_eq!(gate.failure(), None);
    });
}

#[test]
fn a_head_is_held_back_until_it_is_complete_and_has_passed() {
    run(async {
        let (client, mut gate, link, _) = rig(settings()).await;
        let request = get("/slow");
        put(&client, &request[..request.len() - 3]).await;
        let (bytes, _) = drain(&mut gate).await;
        assert!(bytes.is_empty(), "{bytes:?}");
        assert!(queued_targets(&link).is_empty());
        put(&client, &request[request.len() - 3..]).await;
        let (bytes, _) = drain(&mut gate).await;
        assert_eq!(bytes, request);
        assert_eq!(queued_targets(&link), ["/slow"]);
    });
}

#[test]
fn a_refused_head_passes_nothing_and_a_later_one_waits_for_the_answers_before_it() {
    run(async {
        let (client, mut gate, link, _) = rig(settings()).await;
        let first = get("/ok");
        let mut input = first.clone();
        // Two lengths: smuggling material.
        input.extend_from_slice(
            b"POST /bad HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
        );
        put(&client, &input).await;
        let (bytes, ended) = drain(&mut gate).await;
        assert_eq!(bytes, first);
        // The first request is not answered yet: the gate does not show hyper the end, not to break the answer.
        assert!(!ended);
        assert_eq!(gate.failure(), Some(Reject::BadRequest));
        assert_eq!(queued_targets(&link), ["/ok"]);
        drop(link.finish());
        let (bytes, ended) = drain(&mut gate).await;
        assert!(bytes.is_empty() && ended);
    });
}

#[test]
fn the_queue_holds_sixteen_heads_and_the_next_waits_for_a_request_to_be_taken() {
    run(async {
        let (client, mut gate, link, _) = rig(settings()).await;
        let mut input = Vec::new();
        for n in 0..20 {
            input.extend_from_slice(&get(&format!("/{n}")));
        }
        put(&client, &input).await;
        let (bytes, _) = drain(&mut gate).await;
        assert_eq!(link.lock().released, 16);
        let sixteen: Vec<u8> = (0..16).flat_map(|n| get(&format!("/{n}"))).collect();
        assert_eq!(bytes, sixteen);
        // Hyper takes one request: the gate goes on by one.
        assert!(link.take_for(&parts_of("/0")).is_some());
        let (bytes, _) = drain(&mut gate).await;
        assert_eq!(bytes, get("/16"));
        assert_eq!(link.lock().released, 17);
    });
}

#[test]
fn a_chunked_head_is_the_last_one_and_the_bytes_after_it_are_capped() {
    run(async {
        let (client, mut gate, link, gauge) = rig(settings()).await;
        let mut input = CHUNKED.as_bytes().to_vec();
        input.extend_from_slice(b"3\r\na=b\r\n0\r\n\r\n");
        input.extend_from_slice(&get("/after"));
        put(&client, &input).await;
        let (bytes, _) = drain(&mut gate).await;
        // Everything goes on to hyper, and nothing after the head is taken for a request.
        assert_eq!(bytes, input);
        assert_eq!(queued_targets(&link), ["/c"]);
        assert!(!gauge.over());

        // 4096 bytes after the head are the limit; one more is over it.
        for (extra, over) in [(4096, false), (4097, true)] {
            let (client, mut gate, _, gauge) = rig(settings()).await;
            let mut input = CHUNKED.as_bytes().to_vec();
            input.resize(CHUNKED.len() + extra, b'x');
            put(&client, &input).await;
            let (bytes, _) = drain(&mut gate).await;
            assert_eq!(
                bytes.len(),
                if over { input.len() - 1 } else { input.len() }
            );
            assert_eq!(gauge.over(), over, "{extra}");
        }
    });
}

const UPGRADE_GET: &str =
    "GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

#[test]
fn a_head_with_an_upgrade_line_is_the_last_one_and_what_follows_it_is_kept_back() {
    run(async {
        let (client, mut gate, link, _) = rig(settings()).await;
        assert!(!link.last());
        let mut input = UPGRADE_GET.as_bytes().to_vec();
        input.extend_from_slice(&get("/after"));
        put(&client, &input).await;
        let (bytes, ended) = drain(&mut gate).await;
        // Only the head goes on; the gate waits, and the second request is neither queued nor handed on.
        assert_eq!(bytes, UPGRADE_GET.as_bytes());
        assert!(!ended);
        assert_eq!(queued_targets(&link), ["/ws"]);
        assert!(link.last());
        // More bytes are not read at all, so they are neither handed on nor kept.
        put(&client, &get("/later")).await;
        let (bytes, ended) = drain(&mut gate).await;
        assert!(bytes.is_empty() && !ended);
        assert_eq!(queued_targets(&link), ["/ws"]);
        // What the gate had read behind the head is given back, once, for the tunnel.
        assert_eq!(&gate.take_rest()[..], &get("/after")[..]);
        assert!(gate.take_rest().is_empty());
        let mut left = vec![0u8; 64];
        let n = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut left);
            ready!(Pin::new(gate.stream()).poll_read(cx, &mut buf))?;
            Poll::Ready(Ok::<_, io::Error>(buf.filled().len()))
        })
        .await
        .unwrap();
        assert_eq!(&left[..n], &get("/later")[..]);

        // The body that a Content-Length says goes on with the head.
        let (client, mut gate, _, _) = rig(settings()).await;
        let with_body = format!(
            "POST /h2c HTTP/1.1\r\nHost: h\r\nUpgrade: h2c\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=b{}",
            String::from_utf8_lossy(&get("/after"))
        );
        put(&client, with_body.as_bytes()).await;
        let (bytes, _) = drain(&mut gate).await;
        assert_eq!(
            bytes,
            with_body.as_bytes()[..with_body.len() - get("/after").len()]
        );
        assert_eq!(&gate.take_rest()[..], &get("/after")[..]);
    });
}

#[test]
fn an_idle_connection_ends_after_the_wait_and_a_partial_head_after_its_own_time() {
    run(async {
        let wait = Settings {
            keepalive_timeout: Duration::from_millis(300),
            head_read: Duration::from_millis(300),
            ..settings()
        };
        let (client, mut gate, link, _) = rig(wait).await;
        put(&client, &get("/a")).await;
        let (bytes, _) = drain(&mut gate).await;
        assert_eq!(bytes, get("/a"));
        // While the request is in service the gate waits without a time.
        sleep(Duration::from_millis(500)).await;
        let (bytes, ended) = drain(&mut gate).await;
        assert!(bytes.is_empty() && !ended);
        // The answer is complete: the wait for the next request starts there.
        let answered = Instant::now();
        drop(link.finish());
        assert!(until_end(&mut gate).await.is_empty());
        assert!(answered.elapsed() >= Duration::from_millis(250));
        assert_eq!(gate.failure(), None);

        // A head that stops half way is refused when its time is up, once the answers are done.
        let (client, mut gate, link, _) = rig(wait).await;
        put(&client, &get("/a")).await;
        let _ = drain(&mut gate).await;
        drop(link.finish());
        put(&client, b"GET /half HTT").await;
        let started = Instant::now();
        assert!(until_end(&mut gate).await.is_empty());
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert_eq!(gate.failure(), Some(Reject::Timeout));
    });
}

#[test]
fn the_first_head_is_read_before_hyper_starts_and_its_bytes_then_go_on() {
    run(async {
        let (client, mut gate, link, _) = rig(settings()).await;
        let request = post("/p", "a=b&");
        let expected = request.clone();
        let split = request.len() - 6;
        // The head arrives in pieces; the body starts in the same write as the end of the head.
        let writer = tokio::spawn(async move {
            put(&client, &request[..10]).await;
            sleep(Duration::from_millis(50)).await;
            put(&client, &request[10..split]).await;
            sleep(Duration::from_millis(50)).await;
            put(&client, &request[split..]).await;
            client
        });
        gate.first_head(Instant::now() + 10 * SEC).await.unwrap();
        assert_eq!(queued_targets(&link), ["/p"]);
        let (bytes, _) = drain(&mut gate).await;
        assert_eq!(bytes, expected);
        drop(writer.await.unwrap());
    });
}

/// A head of exactly `size` bytes.
fn head_of_size(size: usize) -> Vec<u8> {
    let fixed = "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: \r\n\r\n".len();
    let raw = format!(
        "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: {}\r\n\r\n",
        "p".repeat(size - fixed)
    );
    assert_eq!(raw.len(), size);
    raw.into_bytes()
}

#[test]
fn the_first_head_must_fit_the_buffer_and_come_in_time() {
    run(async {
        let soon = |ms| Instant::now() + Duration::from_millis(ms);
        // A head of exactly the buffer size is read; one byte more is not.
        let (client, mut gate, _, _) = rig(settings()).await;
        put(&client, &head_of_size(1024)).await;
        assert_eq!(gate.first_head(soon(10_000)).await, Ok(()));
        let (client, mut gate, _, _) = rig(settings()).await;
        put(&client, &head_of_size(1025)).await;
        assert_eq!(
            gate.first_head(soon(10_000)).await,
            Err(Reject::FieldsTooLarge)
        );
        // No line end in a full buffer: the request line is the part that is too long.
        let (client, mut gate, _, _) = rig(settings()).await;
        put(&client, format!("GET /{}", "a".repeat(2000)).as_bytes()).await;
        assert_eq!(gate.first_head(soon(10_000)).await, Err(Reject::UriTooLong));
        // Nothing comes: the time is up. The peer goes away with half a head, or with nothing: closed.
        let (_client, mut gate, _, _) = rig(settings()).await;
        assert_eq!(gate.first_head(soon(150)).await, Err(Reject::Timeout));
        let (client, mut gate, _, _) = rig(settings()).await;
        put(&client, b"GET / HTTP/1.1\r\nHo").await;
        drop(client);
        assert_eq!(gate.first_head(soon(10_000)).await, Err(Reject::Closed));
        let (client, mut gate, _, _) = rig(settings()).await;
        drop(client);
        assert_eq!(gate.first_head(soon(10_000)).await, Err(Reject::Closed));
    });
}

#[test]
fn bytes_that_come_with_a_chunked_first_head_count_against_the_cap() {
    run(async {
        // The buffer holds the head and all the bytes after it: 4096 are at the limit, 4097 are over it.
        let big = Settings {
            limits: Limits {
                max_head_bytes: 8192,
                max_body: 1 << 10,
            },
            ..settings()
        };
        for (extra, want) in [(4096, Ok(())), (4097, Err(Reject::ContentTooLarge))] {
            let (client, mut gate, _, _) = rig(big).await;
            let mut input = CHUNKED.as_bytes().to_vec();
            input.resize(CHUNKED.len() + extra, b'x');
            put(&client, &input).await;
            sleep(Duration::from_millis(100)).await;
            assert_eq!(gate.first_head(Instant::now() + 10 * SEC).await, want);
        }
    });
}

#[test]
fn hyper_and_the_head_check_must_see_the_same_request() {
    let head = head_of("POST /a?b=%41 HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nx-a: 2 \r\nX-B:\tv\r\n\r\n");
    let base = || {
        Request::builder()
            .method("POST")
            .uri("/a?b=%41")
            .version(Version::HTTP_11)
            .header("host", "h")
            .header("x-a", "1")
            .header("x-a", "2")
            .header("x-b", "v")
    };
    let parts = |request: Request<()>| request.into_parts().0;
    assert!(same_head(&head, &parts(base().body(()).unwrap())));
    let swapped = Request::builder()
        .method("POST")
        .uri("/a?b=%41")
        .header("host", "h")
        .header("x-a", "2")
        .header("x-a", "1")
        .header("x-b", "v")
        .body(())
        .unwrap();
    let different = [
        base().method("PUT").body(()).unwrap(),
        base().uri("/a?b=%42").body(()).unwrap(),
        base().uri("http://h/a?b=%41").body(()).unwrap(),
        base().version(Version::HTTP_10).body(()).unwrap(),
        base().header("x-c", "3").body(()).unwrap(),
        swapped,
    ];
    for (n, request) in different.into_iter().enumerate() {
        assert!(!same_head(&head, &parts(request)), "case {n}");
    }
    let old = head_of("GET / HTTP/1.0\r\nHost: h\r\n\r\n");
    let seen = |version| {
        let request = Request::builder()
            .uri("/")
            .version(version)
            .header("host", "h");
        request.body(()).unwrap().into_parts().0
    };
    assert!(same_head(&old, &seen(Version::HTTP_10)));
    assert!(!same_head(&old, &seen(Version::HTTP_11)));
}

#[test]
fn a_request_without_a_head_or_with_another_one_is_not_taken() {
    let link = Link::new(Instant::now());
    // Hyper made a request that the gate never passed.
    assert!(link.take_for(&parts_of("/x")).is_none());
    let queue = |link: &Link, target: &str| {
        link.push(Queued {
            head: head_of(&format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n")),
            began: Instant::now(),
        });
    };
    queue(&link, "/a");
    queue(&link, "/b");
    // The oldest head is for another request: it is used up and nothing is served.
    assert!(link.take_for(&parts_of("/b")).is_none());
    assert!(link.take_for(&parts_of("/b")).is_some());
    assert!(link.take_for(&parts_of("/b")).is_none());
}

/// Writes `bytes` to the stream through the gate, as hyper does.
async fn write_through(gate: &mut Gate<TcpStream>, bytes: &[u8]) {
    let n = poll_fn(|cx| Pin::new(&mut *gate).poll_write(cx, bytes))
        .await
        .unwrap();
    assert_eq!(n, bytes.len());
}

async fn flush_through(gate: &mut Gate<TcpStream>) {
    poll_fn(|cx| Pin::new(&mut *gate).poll_flush(cx))
        .await
        .unwrap();
}

#[test]
fn the_end_is_shown_only_when_every_answer_is_given_and_what_was_written_is_flushed() {
    run(async {
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let wait = Settings {
            keepalive_timeout: Duration::from_millis(300),
            ..settings()
        };
        // A refused head after the answered request: the answer is complete as far as the service knows (the body
        // is dropped when its last frame is encoded), but hyper has not flushed it yet.
        let (client, mut gate, link, _) = rig(wait).await;
        let mut input = get("/ok");
        input.extend_from_slice(
            b"POST /bad HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        );
        put(&client, &input).await;
        let _ = drain(&mut gate).await;
        assert_eq!(gate.failure(), Some(Reject::BadRequest));
        write_through(&mut gate, answer).await;
        drop(link.finish());
        let (bytes, ended) = drain(&mut gate).await;
        assert!(bytes.is_empty() && !ended);
        flush_through(&mut gate).await;
        assert!(until_end(&mut gate).await.is_empty());

        // The wait for the next request counts from the flush: the deadline of the answer has passed by then.
        let (client, mut gate, link, _) = rig(wait).await;
        put(&client, &get("/ok")).await;
        let _ = drain(&mut gate).await;
        write_through(&mut gate, answer).await;
        drop(link.finish());
        sleep(Duration::from_millis(500)).await;
        let (_, ended) = drain(&mut gate).await;
        assert!(!ended && !link.waiting());
        flush_through(&mut gate).await;
        let flushed = Instant::now();
        let (_, ended) = drain(&mut gate).await;
        assert!(!ended && link.waiting());
        assert!(until_end(&mut gate).await.is_empty());
        assert!(flushed.elapsed() >= Duration::from_millis(250));
    });
}

/// A stream that takes no byte from a write until the test gives it room.
struct Paced {
    inner: TcpStream,
    room: Arc<StdMutex<(usize, Option<Waker>)>>,
}

impl Paced {
    fn give_room(room: &StdMutex<(usize, Option<Waker>)>) {
        let mut room = room.lock().unwrap();
        room.0 = usize::MAX;
        if let Some(waker) = room.1.take() {
            waker.wake();
        }
    }
}

impl AsyncRead for Paced {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Paced {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let room = self.room.clone();
        let mut room = room.lock().unwrap();
        if room.0 == 0 {
            room.1 = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let want = buf.len().min(room.0);
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &buf[..want]))?;
        room.0 -= n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A response body that tells the link that the request is answered when hyper drops it, as the session's does.
struct Answer {
    data: Option<Bytes>,
    _finish: Finish,
}

impl Body for Answer {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[test]
fn a_response_that_is_still_in_the_write_buffer_when_a_bad_head_follows_reaches_the_client_whole() {
    run(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        // Hyper can write nothing to the stream until the test says so: the whole response, which is small enough
        // to be encoded in one go, waits in its buffer after the body is dropped.
        let room = Arc::new(StdMutex::new((0usize, None)));
        let paced = Paced {
            inner: server,
            room: room.clone(),
        };
        let link = Link::new(Instant::now());
        let (mut gate, _) = Gate::new(paced, settings(), link.clone(), Instant::now());
        let mut input = get("/a");
        input.extend_from_slice(
            b"GET /bad HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        );
        put(&client, &input).await;
        gate.first_head(Instant::now() + 5 * SEC).await.unwrap();
        let service = {
            let link = link.clone();
            service_fn(move |req: Request<Incoming>| {
                let link = link.clone();
                async move {
                    let (parts, _) = req.into_parts();
                    assert!(link.take_for(&parts).is_some());
                    Ok::<_, Infallible>(Response::new(Answer {
                        data: Some(Bytes::from_static(&[b'#'; 100])),
                        _finish: link.finish(),
                    }))
                }
            })
        };
        let mut hyper = http1::Builder::new();
        hyper
            .keep_alive(true)
            .half_close(false)
            .timer(TokioTimer::new())
            .header_read_timeout(None)
            .max_header_size(1024)
            .max_buf_size(8192);
        let serving = tokio::spawn(async move {
            let _ = hyper.serve_connection(TokioIo::new(gate), service).await;
        });
        // The request is answered and nothing is out. The refusal of the head after it must wait.
        sleep(Duration::from_millis(300)).await;
        assert!(!serving.is_finished());
        Paced::give_room(&room);
        let mut raw = Vec::new();
        timeout(10 * SEC, async {
            let mut buf = [0u8; 1024];
            loop {
                client.readable().await.unwrap();
                match client.try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => raw.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("the connection failed: {e}"),
                }
            }
        })
        .await
        .expect("the connection ended");
        serving.await.unwrap();
        // The head, and the body in one chunk with the end of the chunks.
        assert!(raw.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(raw.ends_with(b"\r\n0\r\n\r\n"));
        assert_eq!(raw.iter().filter(|&&b| b == b'#').count(), 100);
    });
}

#[test]
fn up_to_two_empty_lines_before_a_later_head_are_dropped_and_a_third_is_refused() {
    run(async {
        let first = post("/a", "x=1");
        let both = [first.clone(), get("/b")].concat();
        // The line ends alone, as CRLF or as LF. Two cases come in two pieces: split inside a CRLF, and after the
        // first empty line.
        for (blanks, split, fine) in [
            ("\r\n", None, true),
            ("\r\n\n", None, true),
            ("\r\n\r\n", Some(1), true),
            ("\r\n\r\n", Some(2), true),
            ("\r\n\r\n\r\n", None, false),
            ("\n\n\n", None, false),
        ] {
            let (client, mut gate, link, _) = rig(settings()).await;
            let rest = [blanks.as_bytes(), &get("/b")].concat();
            put(&client, &first).await;
            let mut bytes = Vec::new();
            let mut second = Instant::now();
            match split {
                Some(at) => {
                    put(&client, &rest[..at]).await;
                    bytes.extend_from_slice(&drain(&mut gate).await.0);
                    second = Instant::now();
                    put(&client, &rest[at..]).await;
                }
                None => put(&client, &rest).await,
            }
            bytes.extend_from_slice(&drain(&mut gate).await.0);
            // Hyper never sees an empty line.
            if fine {
                assert_eq!(bytes, both, "{blanks:?}");
                assert_eq!(queued_targets(&link), ["/a", "/b"]);
                assert_eq!(gate.failure(), None);
                // The time of the head counts from its request line, not from the empty line before it.
                if split == Some(2) {
                    assert!(link.lock().queue[1].began >= second);
                }
            } else {
                assert_eq!(bytes, first, "{blanks:?}");
                assert_eq!(queued_targets(&link), ["/a"]);
                assert_eq!(gate.failure(), Some(Reject::BadRequest));
            }
        }
        // The first head of a connection starts at its first byte.
        let (client, mut gate, _, _) = rig(settings()).await;
        put(&client, &[b"\r\n".as_slice(), &get("/a")].concat()).await;
        assert_eq!(
            gate.first_head(Instant::now() + 10 * SEC).await,
            Err(Reject::BadRequest)
        );
    });
}

// ---- the fuzz test ----

/// A small generator that needs nothing but integers (xorshift64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

/// Lines to put into a head: the smuggling material, and the plain.
const INJECT: [&str; 17] = [
    "Content-Length: 5",
    "Content-Length: 0",
    "Content-Length: 1\r\nContent-Length: 2",
    "Content-Length: +5",
    "Content-Length: 5, 5",
    "Content-Length : 5",
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: chunked, identity",
    "Transfer-Encoding : chunked",
    "\tTransfer-Encoding: chunked",
    " folded: value",
    "X-A: a\nTransfer-Encoding: chunked",
    "Connection: close",
    "Expect: 100-continue",
    "Host: other",
    "X-Long: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "TE: trailers",
];

const CORPUS: [&[u8]; 5] = [
    b"GET /a?x=1 HTTP/1.1\r\nHost: h\r\nAccept: */*\r\n\r\n",
    b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\na=b&c=d",
    b"POST /c HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na=b\r\n0\r\n\r\n",
    b"GET /old HTTP/1.0\r\nHost: h\r\n\r\n",
    b"POST /q HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
];

fn positions(input: &[u8], needle: &[u8]) -> Vec<usize> {
    input
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(at, _)| at)
        .collect()
}

/// A valid run of requests, damaged in one to three ways: most often after the head of the first request, so
/// that it is a later request that is wrong.
fn mutated(rng: &mut Rng) -> Vec<u8> {
    let mut whole = Vec::new();
    for _ in 0..1 + rng.below(4) {
        whole.extend_from_slice(CORPUS[rng.below(CORPUS.len())]);
    }
    let keep = match positions(&whole, b"\r\n\r\n").first() {
        Some(&end) if rng.below(10) < 7 => end + 4,
        _ => 0,
    };
    let mut input = whole.split_off(keep);
    damage(&mut input, rng);
    whole.extend_from_slice(&input);
    whole
}

/// One to three kinds of damage to `input`.
fn damage(input: &mut Vec<u8>, rng: &mut Rng) {
    for _ in 0..1 + rng.below(3) {
        match rng.below(9) {
            // Cut.
            0 => {
                let at = rng.below(input.len() + 1);
                input.truncate(at);
            }
            // Duplicate a span.
            1 if !input.is_empty() => {
                let from = rng.below(input.len());
                let to = from + rng.below(input.len() - from) + 1;
                let at = rng.below(input.len() + 1);
                let span = input[from..to].to_vec();
                input.splice(at..at, span);
            }
            // Inject a line into a head.
            2 => {
                let ends = positions(input, b"\r\n");
                if !ends.is_empty() {
                    let at = ends[rng.below(ends.len())] + 2;
                    let line = format!("{}\r\n", INJECT[rng.below(INJECT.len())]);
                    input.splice(at..at, line.into_bytes());
                }
            }
            // Shift a Content-Length.
            3 => {
                let lengths = positions(input, b"Content-Length: ");
                if !lengths.is_empty() {
                    let at = lengths[rng.below(lengths.len())] + 16;
                    let end = input[at..]
                        .iter()
                        .position(|b| !b.is_ascii_digit())
                        .map_or(input.len(), |n| at + n);
                    let value = match rng.below(4) {
                        0 => "99999999999999999999".to_string(),
                        1 => "0".to_string(),
                        n => (rng.below(40) + n).to_string(),
                    };
                    input.splice(at..end, value.into_bytes());
                }
            }
            // A line end that is only a line feed, in one place or everywhere.
            4 => {
                let ends = positions(input, b"\r\n");
                if !ends.is_empty() {
                    if rng.below(2) == 0 {
                        let at = ends[rng.below(ends.len())];
                        input.remove(at);
                    } else {
                        input.retain(|&b| b != b'\r');
                    }
                }
            }
            // A byte of any value.
            5 if !input.is_empty() => {
                let at = rng.below(input.len());
                input[at] = u8::try_from(rng.below(256)).unwrap();
            }
            // A few bytes of any value.
            6 => {
                let at = rng.below(input.len() + 1);
                let junk: Vec<u8> = (0..1 + rng.below(6))
                    .map(|_| u8::try_from(rng.below(256)).unwrap())
                    .collect();
                input.splice(at..at, junk);
            }
            // Empty lines after the end of a head.
            7 => {
                let ends = positions(input, b"\r\n\r\n");
                if !ends.is_empty() {
                    let at = ends[rng.below(ends.len())] + 4;
                    let lines = if rng.below(2) == 0 { "\r\n" } else { "\n" };
                    input.splice(at..at, lines.repeat(1 + rng.below(3)).into_bytes());
                }
            }
            // A blank line out of a head.
            _ => {
                let blanks = positions(input, b"\r\n\r\n");
                if !blanks.is_empty() {
                    let at = blanks[rng.below(blanks.len())];
                    input.drain(at..at + 2);
                }
            }
        }
    }
}

/// What hyper made of one input behind the gate: the heads the gate passed, the requests that hyper handed to the
/// service and that were compared with a copy, and how many of them were not the request the gate had passed.
struct Run {
    released: u64,
    compared: u64,
    mismatched: u64,
    /// The last request that was compared ends the connection (chunked, HTTP/1.0, `Connection: close`, or no
    /// matching copy), so the requests behind it are not made.
    ended_by_request: bool,
}

/// Polls `work` until it is done, or until every byte of the input has been read and a second look finds the same
/// state: then only a time, or bytes that never come, could move it (`None`). The case does not wait for a time.
async fn until_quiet<F: Future>(
    work: F,
    gauge: &Gauge,
    len: u64,
    state: impl Fn() -> [u64; 4],
) -> Option<F::Output> {
    let mut work = pin!(work);
    let mut quiet = None;
    timeout(
        Duration::from_secs(10),
        poll_fn(|cx| {
            if let Poll::Ready(done) = work.as_mut().poll(cx) {
                return Poll::Ready(Some(done));
            }
            if gauge.read() < len && !gauge.over() {
                return Poll::Pending;
            }
            let now = state();
            if quiet == Some(now) {
                return Poll::Ready(None);
            }
            quiet = Some(now);
            cx.waker().wake_by_ref();
            Poll::Pending
        }),
    )
    .await
    .expect("the case ended or went quiet")
}

/// Serves `input` as a connection: the gate reads the first head, hyper serves the rest, as in `Session`. The
/// client does not close its side, so the last request of the input is made and compared like the others. The
/// case is driven until hyper ends the connection, or until it is quiet (see `until_quiet`). `lose_copy` is the
/// request (counted from 0) whose copy is taken away before the service looks for it, to see that the harness
/// notices.
async fn behind_the_gate(listener: &TcpListener, input: &[u8], lose_copy: Option<u64>) -> Run {
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let input = input.to_vec();
    let len = u64::try_from(input.len()).unwrap();
    let writer = tokio::spawn(async move {
        put(&client, &input).await;
        // Read what the server answers, so that it can write, until it closes.
        let mut sink = [0u8; 4096];
        loop {
            if client.readable().await.is_err() {
                return;
            }
            match client.try_read(&mut sink) {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
    });
    let link = Link::new(Instant::now());
    let (mut gate, gauge) = Gate::new(server, settings(), link.clone(), Instant::now());
    // The requests compared, the ones without their copy, and whether the last one ends the connection.
    let seen = Arc::new(StdMutex::new((0u64, 0u64, false)));
    let state = || {
        let shared = link.lock();
        [
            gauge.read(),
            shared.released,
            shared.completed,
            seen.lock().unwrap().0,
        ]
    };
    let first = until_quiet(
        gate.first_head(Instant::now() + 5 * SEC),
        &gauge,
        len,
        state,
    )
    .await;
    if matches!(first, Some(Ok(()))) {
        let service = {
            let (link, seen) = (link.clone(), seen.clone());
            service_fn(move |req: Request<Incoming>| {
                let (link, seen) = (link.clone(), seen.clone());
                async move {
                    let finish = link.finish();
                    let (parts, body) = req.into_parts();
                    let n = seen.lock().unwrap().0;
                    if lose_copy == Some(n) {
                        link.lock().queue.pop_front();
                    }
                    let taken = link.take_for(&parts);
                    // As the session ends the connection after a chunked or an HTTP/1.0 request, one that asks for
                    // it, and a request that was not the one the gate passed.
                    let ends = taken
                        .as_ref()
                        .is_none_or(|t| t.head.chunked() || t.head.http10() || t.head.close());
                    {
                        let mut seen = seen.lock().unwrap();
                        seen.0 += 1;
                        seen.1 += u64::from(taken.is_none());
                        seen.2 = ends;
                    }
                    let _ = body.collect().await;
                    drop(finish);
                    let mut response = Response::new(Empty::<Bytes>::new());
                    if ends {
                        response.headers_mut().insert(
                            http::header::CONNECTION,
                            http::HeaderValue::from_static("close"),
                        );
                    }
                    Ok::<_, Infallible>(response)
                }
            })
        };
        let mut server = http1::Builder::new();
        server
            .keep_alive(true)
            .half_close(false)
            .timer(TokioTimer::new())
            .header_read_timeout(None)
            .max_headers(limits::HEADERS)
            .max_header_size(1024)
            .max_buf_size(8192)
            .title_case_headers(true);
        let conn = server.serve_connection(TokioIo::new(&mut gate), service);
        let _ = until_quiet(conn, &gauge, len, state).await;
    }
    let released = link.lock().released;
    drop(gate);
    let _ = writer.await;
    let (compared, mismatched, ended_by_request) = *seen.lock().unwrap();
    Run {
        released,
        compared,
        mismatched,
        ended_by_request,
    }
}

#[test]
fn damaged_requests_behind_the_gate_are_what_the_gate_passed_or_the_connection_closes() {
    run(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut rng = Rng(0x5eed_1234_abcd_ef01);
        let (mut compared, mut several, mut ended) = (0u64, 0u64, 0u64);
        for case in 0..3000 {
            let input = mutated(&mut rng);
            let run = behind_the_gate(&listener, &input, None).await;
            assert_eq!(
                run.mismatched,
                0,
                "case {case}: hyper made a request that the gate did not pass: {}",
                input.escape_ascii()
            );
            // Every head the gate passed was made a request by hyper and compared with its copy, the last one
            // too, unless a request ended the connection before the ones behind it.
            if run.ended_by_request {
                assert!(run.compared <= run.released, "case {case}");
            } else {
                assert_eq!(
                    run.compared,
                    run.released,
                    "case {case}: {}",
                    input.escape_ascii()
                );
            }
            compared += run.compared;
            several += u64::from(run.compared > 1);
            ended += u64::from(run.ended_by_request);
        }
        // Inputs with several requests got through whole, and some were ended by a request, so the requests behind
        // the first were looked at.
        assert!(
            compared > 0 && several > 0 && ended > 0,
            "{compared} {several} {ended}"
        );
    });
}

#[test]
fn the_harness_notices_a_request_without_its_copy_also_when_it_is_the_last() {
    run(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let input = [get("/first"), get("/last")].concat();
        let run = behind_the_gate(&listener, &input, None).await;
        assert_eq!((run.released, run.compared, run.mismatched), (2, 2, 0));
        // The copy of the last request is lost, as if hyper and the gate had not seen the same bytes.
        let run = behind_the_gate(&listener, &input, Some(1)).await;
        assert_eq!((run.released, run.compared, run.mismatched), (2, 2, 1));
    });
}
