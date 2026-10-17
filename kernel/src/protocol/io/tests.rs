use super::*;
use crate::protocol::codec::{KIND_BODY, KIND_CLOSED, KIND_HELLO, encode_frame};
use std::thread;

const RUN: u64 = 0x0102_0304_0506_0708;
const INC: u32 = 7;
const SEC: Duration = Duration::from_secs(1);
/// Far enough that a deadline meant not to fire never does.
const FAR: Duration = Duration::from_secs(60);

/// A received-kind frame, built by hand (`encode_frame` builds only what Rust sends).
fn raw(kind: u8, len: u32, run: u64, tx: u64, msg: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"TKV0");
    v.push(kind);
    v.extend_from_slice(&[0, 0, 0]);
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(&run.to_be_bytes());
    v.extend_from_slice(&INC.to_be_bytes());
    v.extend_from_slice(&tx.to_be_bytes());
    v.extend_from_slice(&msg.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn closed() -> Vec<u8> {
    raw(KIND_CLOSED, 1, RUN, 1, 2, &[1])
}

fn pair() -> (UnixStream, UnixStream) {
    UnixStream::pair().unwrap()
}

/// `recv` with `idle` and `frame_io` given and `hard` far away.
fn rx(a: &UnixStream, idle: Duration, frame_io: Duration) -> Result<(Header, Vec<u8>), ConnError> {
    let now = Instant::now();
    recv(a, RUN, INC, now + idle, frame_io, now + FAR)
}

/// `recv` that should find a frame: generous limits.
fn rx_ok(a: &UnixStream) -> Result<(Header, Vec<u8>), ConnError> {
    rx(a, 5 * SEC, 5 * SEC)
}

#[test]
fn a_frame_arrives_whole_and_checked() {
    let (a, b) = pair();
    (&b).write_all(&closed()).unwrap();
    let (h, p) = rx_ok(&a).unwrap();
    assert_eq!(
        (h.kind, h.len, h.run, h.inc, h.tx, h.msg),
        (KIND_CLOSED, 1, RUN, INC, 1, 2)
    );
    assert_eq!(p, [1]);
}

#[test]
fn two_frames_in_a_row_are_read_one_at_a_time() {
    let (a, b) = pair();
    let mut two = closed();
    two.extend_from_slice(&raw(KIND_CLOSED, 1, RUN, 3, 4, &[2]));
    (&b).write_all(&two).unwrap();
    assert_eq!(rx_ok(&a).unwrap().1, [1]);
    assert_eq!(rx_ok(&a).unwrap().1, [2]);
}

#[test]
fn send_writes_the_encoded_frame_bytes() {
    let (a, b) = pair();
    let f = encode_frame(KIND_BODY, RUN, INC, 3, 4, b"abc").unwrap();
    send(&a, &f, Instant::now() + SEC).unwrap();
    let mut got = vec![0u8; f.len()];
    (&b).read_exact(&mut got).unwrap();
    assert_eq!(got, f);
}

#[test]
fn send_refuses_a_frame_whose_length_field_does_not_match() {
    let (a, _b) = pair();
    let mut f = encode_frame(KIND_BODY, RUN, INC, 3, 4, b"abc").unwrap();
    let bad = Err(ConnError::Io(ErrorKind::InvalidInput));
    assert_eq!(send(&a, &f[..HEADER_LEN - 1], Instant::now() + SEC), bad);
    assert_eq!(send(&a, &f[..f.len() - 1], Instant::now() + SEC), bad);
    f.push(0);
    assert_eq!(send(&a, &f, Instant::now() + SEC), bad);
    let big = raw(
        KIND_BODY,
        MAX_BODY as u32 + 1,
        RUN,
        1,
        1,
        &vec![0; MAX_BODY + 1],
    );
    assert_eq!(send(&a, &big, Instant::now() + SEC), bad);
}

#[test]
fn an_idle_expiry_before_the_first_byte_is_would_block_and_consumes_nothing() {
    let (a, b) = pair();
    let t = Instant::now();
    for _ in 0..3 {
        assert_eq!(
            rx(&a, Duration::from_millis(30), 5 * SEC),
            Err(ConnError::Io(ErrorKind::WouldBlock))
        );
    }
    assert!(t.elapsed() < 5 * SEC);
    // the stream is sound: a frame that comes now is read whole by the next call
    (&b).write_all(&closed()).unwrap();
    assert_eq!(rx_ok(&a).unwrap().1, [1]);
}

#[test]
fn a_polling_reader_gets_a_frame_that_comes_late() {
    let (a, b) = pair();
    let w = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        (&b).write_all(&closed()).unwrap();
        b
    });
    let t = Instant::now();
    let got = loop {
        match rx(&a, Duration::from_millis(20), 5 * SEC) {
            Err(ConnError::Io(ErrorKind::WouldBlock)) => assert!(t.elapsed() < 10 * SEC),
            other => break other,
        }
    };
    assert_eq!(got.unwrap().1, [1]);
    let _b = w.join().unwrap();
}

#[test]
fn a_deadline_already_over_fails_without_reading() {
    let (a, b) = pair();
    (&b).write_all(&closed()).unwrap();
    // idle reached, and hard reached: WouldBlock, nothing read
    let now = Instant::now();
    assert_eq!(
        recv(&a, RUN, INC, now, 5 * SEC, now + FAR),
        Err(ConnError::Io(ErrorKind::WouldBlock))
    );
    assert_eq!(
        recv(&a, RUN, INC, now + FAR, 5 * SEC, now),
        Err(ConnError::Io(ErrorKind::WouldBlock))
    );
    // nothing was read: the frame is still there
    assert!(rx_ok(&a).is_ok());
    let f = encode_frame(KIND_BODY, RUN, INC, 3, 4, b"abc").unwrap();
    assert_eq!(
        send(&a, &f, Instant::now()),
        Err(ConnError::Io(ErrorKind::TimedOut))
    );
}

#[test]
fn an_expiry_inside_a_frame_is_timed_out() {
    // idle is far: only frame_io can fire, and it must not be waited out as idle
    let t = Instant::now();
    let (a, b) = pair();
    (&b).write_all(&closed()[..10]).unwrap();
    assert_eq!(
        rx(&a, FAR, Duration::from_millis(50)),
        Err(ConnError::Io(ErrorKind::TimedOut))
    );
    // header complete, payload missing
    let (a, b) = pair();
    (&b).write_all(&closed()[..HEADER_LEN]).unwrap();
    assert_eq!(
        rx(&a, FAR, Duration::from_millis(50)),
        Err(ConnError::Io(ErrorKind::TimedOut))
    );
    // frame_io 0: the first byte is read, nothing more is allowed
    let (a, b) = pair();
    (&b).write_all(&closed()).unwrap();
    assert_eq!(
        rx(&a, FAR, Duration::ZERO),
        Err(ConnError::Io(ErrorKind::TimedOut))
    );
    assert!(t.elapsed() < 10 * SEC);
}

#[test]
fn idle_does_not_cut_a_frame_that_has_started() {
    let (a, b) = pair();
    (&b).write_all(&closed()[..1]).unwrap();
    let w = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        (&b).write_all(&closed()[1..]).unwrap();
        b
    });
    // the first byte comes before idle; the rest comes after idle but within frame_io
    let r = rx(&a, Duration::from_millis(100), 5 * SEC);
    assert_eq!(r.unwrap().1, [1]);
    let _b = w.join().unwrap();
}

#[test]
fn the_wait_for_the_first_byte_is_not_charged_to_frame_io() {
    let (a, b) = pair();
    let w = thread::spawn(move || {
        thread::sleep(SEC);
        (&b).write_all(&closed()).unwrap();
        b
    });
    // frame_io is shorter than the wait, but it starts at the first byte
    let r = rx(&a, 10 * SEC, Duration::from_millis(500));
    assert_eq!(r.unwrap().1, [1]);
    let _b = w.join().unwrap();
}

#[test]
fn a_slow_peer_cannot_stretch_frame_io() {
    let (a, b) = pair();
    let w = thread::spawn(move || {
        for byte in closed() {
            if (&b).write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let t = Instant::now();
    let r = rx(&a, 10 * SEC, Duration::from_millis(200));
    assert_eq!(r, Err(ConnError::Io(ErrorKind::TimedOut)));
    assert!(t.elapsed() < SEC, "the frame needs about 1.9 s to arrive");
    drop(a);
    w.join().unwrap();
}

#[test]
fn hard_cuts_before_idle_and_before_frame_io() {
    let t = Instant::now();
    // no byte: hard is before idle
    let (a, _b) = pair();
    assert_eq!(
        recv(&a, RUN, INC, t + FAR, FAR, t + Duration::from_millis(50)),
        Err(ConnError::Io(ErrorKind::WouldBlock))
    );
    // inside a frame: hard is before t + frame_io
    let (a, b) = pair();
    (&b).write_all(&closed()[..10]).unwrap();
    assert_eq!(
        recv(
            &a,
            RUN,
            INC,
            t + FAR,
            FAR,
            Instant::now() + Duration::from_millis(50)
        ),
        Err(ConnError::Io(ErrorKind::TimedOut))
    );
    // t + frame_io overflows: hard is used
    let (a, b) = pair();
    (&b).write_all(&closed()[..10]).unwrap();
    assert_eq!(
        recv(
            &a,
            RUN,
            INC,
            t + FAR,
            Duration::MAX,
            Instant::now() + Duration::from_millis(50)
        ),
        Err(ConnError::Io(ErrorKind::TimedOut))
    );
    assert!(t.elapsed() < 10 * SEC);
}

#[test]
fn a_full_socket_times_out_on_send() {
    let (a, _b) = pair();
    let f = encode_frame(KIND_BODY, RUN, INC, 3, 4, &vec![0u8; MAX_BODY]).unwrap();
    let t = Instant::now();
    let mut r = Ok(());
    // nobody reads: the socket buffer fills within a few frames
    for _ in 0..1000 {
        r = send(&a, &f, Instant::now() + Duration::from_millis(100));
        if r.is_err() {
            break;
        }
    }
    assert_eq!(r, Err(ConnError::Io(ErrorKind::TimedOut)));
    assert!(t.elapsed() < 10 * SEC);
}

#[test]
fn a_closed_peer_is_reported() {
    let (a, b) = pair();
    drop(b);
    assert_eq!(rx_ok(&a), Err(ConnError::PeerClosed));
    let f = encode_frame(KIND_BODY, RUN, INC, 3, 4, b"abc").unwrap();
    assert_eq!(
        send(&a, &f, Instant::now() + SEC),
        Err(ConnError::Io(ErrorKind::BrokenPipe))
    );
    let (a, b) = pair();
    (&b).write_all(&closed()[..5]).unwrap();
    drop(b);
    assert_eq!(
        rx_ok(&a),
        Err(ConnError::Truncated {
            got: 5,
            want: HEADER_LEN
        })
    );
}

#[test]
fn a_bad_header_is_refused_before_the_payload_is_read() {
    // HELLO longer than its limit: refused on the header alone, no payload follows
    let (a, b) = pair();
    (&b).write_all(&raw(KIND_HELLO, 1 << 30, RUN, 0, 0, &[]))
        .unwrap();
    assert_eq!(
        rx_ok(&a),
        Err(ConnError::TooLong {
            kind: KIND_HELLO,
            len: 1 << 30
        })
    );
    // a frame of another run
    let (a, b) = pair();
    (&b).write_all(&raw(KIND_CLOSED, 1, RUN + 1, 1, 2, &[1]))
        .unwrap();
    assert_eq!(rx_ok(&a), Err(ConnError::RunMismatch(RUN + 1)));
}
