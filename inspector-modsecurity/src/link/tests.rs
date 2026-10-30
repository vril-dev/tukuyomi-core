use super::*;
use crate::codec::{ConnError, encode_hello};
use crate::codec::{Hello, KIND_BODY, KIND_BODY_END, KIND_TX_BEGIN, KIND_TX_END, MAX_BODY};
use crate::testkit::{Fake, INC, Log, RUN, Script, begin_payload, inbound, read_out};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

const TIMEOUT: Duration = Duration::from_millis(150);

fn pair() -> (UnixStream, UnixStream) {
    UnixStream::pair().unwrap()
}

/// Writes bytes from a thread; a write that fails ends it, as the reader going away does.
fn write_later(peer: UnixStream, pieces: Vec<(Duration, Vec<u8>)>) -> JoinHandle<()> {
    thread::spawn(move || {
        for (wait, bytes) in pieces {
            thread::sleep(wait);
            if (&peer).write_all(&bytes).is_err() {
                return;
            }
        }
    })
}

#[test]
fn a_frame_may_be_waited_for_but_must_arrive_in_time_once_it_has_begun() {
    let frame = inbound(KIND_BODY, 0, 1, 2, b"abcdefgh");
    let nothing = Duration::ZERO;

    // Nothing for three times the timeout, then a whole frame: no deadline before the first byte.
    let (a, b) = pair();
    let writer = write_later(b, vec![(3 * TIMEOUT, frame.clone())]);
    assert_eq!(recv(&a, RUN, INC, TIMEOUT).unwrap().1, b"abcdefgh");
    writer.join().unwrap();

    // The first byte, then nothing for longer than the timeout: the frame is late.
    let (a, b) = pair();
    let writer = write_later(
        b,
        vec![
            (nothing, frame[..1].to_vec()),
            (3 * TIMEOUT, frame[1..].to_vec()),
        ],
    );
    assert_eq!(
        recv(&a, RUN, INC, TIMEOUT).unwrap_err(),
        ConnError::Io(ErrorKind::TimedOut)
    );
    drop(a);
    writer.join().unwrap();

    // Every byte is within the timeout of the one before, but the frame as a whole is not: one deadline for
    // the frame, which a slow sender cannot stretch.
    let (a, b) = pair();
    let pieces = frame.iter().map(|&x| (TIMEOUT / 5, vec![x])).collect();
    let writer = write_later(b, pieces);
    assert_eq!(
        recv(&a, RUN, INC, TIMEOUT).unwrap_err(),
        ConnError::Io(ErrorKind::TimedOut)
    );
    drop(a);
    writer.join().unwrap();
}

#[test]
fn a_frame_is_written_whole_and_a_stalled_peer_hits_the_deadline() {
    let (a, b) = pair();
    let frame = inbound(KIND_BODY, 0, 1, 2, &vec![7u8; MAX_BODY]);
    let reader = thread::spawn(move || recv(&b, RUN, INC, Duration::from_secs(5)));
    send(&a, &frame, FRAME_TIMEOUT).unwrap();
    let (h, p) = reader.join().unwrap().unwrap();
    assert_eq!((h.kind, p.len()), (KIND_BODY, MAX_BODY));

    // The peer reads nothing: the buffer fills, and a write then stops at its deadline.
    let (a, _b) = pair();
    let stalled = (0..200)
        .map(|_| send(&a, &frame, TIMEOUT))
        .find(Result::is_err);
    assert_eq!(stalled, Some(Err(ConnError::Io(ErrorKind::TimedOut))));
}

fn hello_frame() -> Vec<u8> {
    let hello = Hello {
        pid: 1,
        nonce: [0; 16],
        toolchain: b"t",
        engine_version: b"v",
        engine_source: b"s",
        rules_sha256: [0; 32],
        mem_limit: 0,
        gomaxprocs: 1,
    };
    encode_hello(RUN, INC, &hello).unwrap()
}

/// Serves one end of a socket pair on a thread and returns the other end, after the HELLO was read from it.
fn start(
    script: Script,
    close_deadline: Duration,
) -> (UnixStream, JoinHandle<Ended>, Arc<Mutex<Log>>) {
    let (a, b) = pair();
    let (fake, log) = Fake::new(script);
    let hello = hello_frame();
    let session = thread::spawn(move || {
        serve(
            a,
            RUN,
            INC,
            &hello,
            Table::new(fake, RUN, INC),
            close_deadline,
        )
    });
    assert_eq!(read_out(&b).unwrap().kind, 0x01, "HELLO first");
    (b, session, log)
}

fn write(peer: &UnixStream, kind: u8, tx: u64, msg: u32, payload: &[u8]) {
    (&*peer)
        .write_all(&inbound(kind, 0, tx, msg, payload))
        .unwrap();
}

#[test]
fn drain_closes_the_open_transactions_and_then_bye_counts_them() {
    let (peer, session, log) = start(Script::default(), Duration::from_secs(1));
    write(&peer, KIND_TX_BEGIN, 1, 1, &begin_payload(0));
    let o = read_out(&peer).unwrap();
    assert_eq!((o.kind, o.tx, o.msg, o.payload[0]), (0x20, 1, 1, 1));
    write(&peer, KIND_DRAIN, 0, 0, b"");
    // The second DRAIN is counted, a new transaction is refused, the open one goes on.
    write(&peer, KIND_DRAIN, 0, 0, b"");
    write(&peer, KIND_TX_BEGIN, 2, 1, &begin_payload(0));
    let o = read_out(&peer).unwrap();
    assert_eq!((o.kind, o.tx, o.payload[0], o.payload[3]), (0x21, 2, 1, 2));
    write(&peer, KIND_BODY_END, 1, 2, b"");
    let o = read_out(&peer).unwrap();
    assert_eq!((o.kind, o.tx, o.msg, o.payload[0]), (0x20, 1, 2, 2));
    write(&peer, KIND_TX_END, 1, 3, &[1]);
    assert_eq!(read_out(&peer).unwrap().kind, 0x22);
    let bye = read_out(&peer).unwrap();
    assert_eq!(bye.kind, 0x03);
    let counts: Vec<u64> = bye
        .payload
        .chunks(8)
        .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
        .collect();
    assert_eq!(counts, [1, 1, 0]);
    let ended = session.join().unwrap();
    assert_eq!((ended.code, ended.dup_drains), (EXIT_OK, 1));
    assert_eq!(log.lock().unwrap().closes, 1);
    // BYE is the last frame: the connection is closed.
    assert!(read_out(&peer).is_none());
}

#[test]
fn drain_with_no_open_transaction_is_answered_with_bye_at_once() {
    let (peer, session, log) = start(Script::default(), Duration::from_secs(1));
    write(&peer, KIND_DRAIN, 0, 0, b"");
    let bye = read_out(&peer).unwrap();
    assert_eq!(bye.kind, 0x03);
    // Started, closed and closed with an error: all zero.
    assert_eq!(bye.payload, [0; 24]);
    let ended = session.join().unwrap();
    assert_eq!((ended.code, ended.dup_drains), (EXIT_OK, 0));
    assert_eq!(log.lock().unwrap().closes, 0);
    assert!(read_out(&peer).is_none());
}

#[test]
fn a_lost_connection_ends_the_session_after_closing_every_transaction() {
    let (peer, session, log) = start(Script::default(), Duration::from_secs(1));
    write(&peer, KIND_TX_BEGIN, 1, 1, &begin_payload(0));
    assert_eq!(read_out(&peer).unwrap().kind, 0x20);
    drop(peer);
    let ended = session.join().unwrap();
    assert_eq!(ended.code, EXIT_LOST_CLEAN);
    assert_eq!((ended.counts.started, ended.counts.closed), (1, 1));
    assert_eq!(log.lock().unwrap().closes, 1);

    // The same, when closing takes longer than the deadline.
    let slow = Script {
        close_takes: Duration::from_millis(200),
        ..Script::default()
    };
    let (peer, session, _) = start(slow, Duration::from_millis(20));
    write(&peer, KIND_TX_BEGIN, 1, 1, &begin_payload(0));
    assert_eq!(read_out(&peer).unwrap().kind, 0x20);
    drop(peer);
    assert_eq!(session.join().unwrap().code, EXIT_LOST_TIMEOUT);
}

#[test]
fn a_frame_that_breaks_the_protocol_ends_the_session() {
    let (peer, session, _) = start(Script::default(), Duration::from_secs(1));
    // A VERDICT is a kind that the kernel does not send.
    (&peer)
        .write_all(&inbound(0x20, 0, 1, 1, &[0; 24]))
        .unwrap();
    let ended = session.join().unwrap();
    assert_eq!(ended.code, EXIT_LOST_CLEAN);
    assert!(
        ended.why.starts_with("read: WrongDirection"),
        "{}",
        ended.why
    );
}
