use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;
use tokio::time::{Instant as TokioInstant, sleep, timeout};

use super::*;

const PREFACE_BYTES: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The time of the preface and of a header block in these tests.
const LIMIT: Duration = Duration::from_millis(400);

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

/// One frame.
fn frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut out = vec![len[1], len[2], len[3], kind, flags, 0, 0, 0, 1];
    out.extend_from_slice(payload);
    out
}

/// What the reader of a watch came to: the bytes it read, how it ended, and whether the watch says it timed out.
struct Read {
    bytes: Vec<u8>,
    end: io::Result<()>,
    timed_out: bool,
    took: Duration,
}

/// A watch whose preface has `LIMIT` from now and whose header blocks have `LIMIT`, read to its end in the
/// background; and the client's end of the stream.
fn watched() -> (JoinHandle<Read>, DuplexStream) {
    let (client, server) = duplex(1 << 20);
    let began = TokioInstant::now();
    let (mut watch, _gauge) = Watch::new(
        server,
        began + LIMIT,
        LIMIT,
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    let reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        let end = loop {
            match watch.read(&mut buf).await {
                Ok(0) => break Ok(()),
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(e) => break Err(e),
            }
        };
        Read {
            bytes,
            end,
            timed_out: watch.timed_out(),
            took: began.elapsed(),
        }
    });
    (reader, client)
}

/// Sends `bytes` one at a time, `pause` apart.
async fn drip(client: &mut DuplexStream, bytes: &[u8], pause: Duration) {
    for byte in bytes {
        // The reader may have ended before the last byte, with the error that the test looks for.
        if client.write_all(&[*byte]).await.is_err() {
            return;
        }
        sleep(pause).await;
    }
}

async fn finished(reader: JoinHandle<Read>) -> Read {
    timeout(Duration::from_secs(10), reader)
        .await
        .expect("the reader ended")
        .unwrap()
}

#[test]
fn a_preface_that_is_not_complete_in_time_fails_the_read_and_one_that_is_complete_does_not() {
    runtime().block_on(async {
        // In pieces, within the time: nothing is cut, and every byte comes through as it was.
        let (reader, mut client) = watched();
        drip(&mut client, &PREFACE_BYTES[..12], Duration::from_millis(5)).await;
        client.write_all(&PREFACE_BYTES[12..]).await.unwrap();
        drop(client);
        let read = finished(reader).await;
        assert!(read.end.is_ok() && !read.timed_out);
        assert_eq!(read.bytes, PREFACE_BYTES);

        // Half of it, and then nothing: the read fails when the time has passed, and not before.
        let (reader, mut client) = watched();
        client.write_all(&PREFACE_BYTES[..12]).await.unwrap();
        let read = finished(reader).await;
        assert_eq!(read.end.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(read.timed_out);
        assert!(
            read.took >= LIMIT && read.took < LIMIT * 5,
            "{:?}",
            read.took
        );
        drop(client);

        // One byte at a time, too slowly.
        let (reader, mut client) = watched();
        drip(&mut client, PREFACE_BYTES, LIMIT / 10).await;
        let read = finished(reader).await;
        assert!(read.timed_out && read.end.is_err());
        assert!(read.bytes.len() < PREFACE_BYTES.len());
    });
}

#[test]
fn a_header_block_has_its_time_from_its_first_byte_to_the_end_of_the_frame_that_ends_it() {
    runtime().block_on(async {
        let settings = frame(0x4, 0, &[]);
        let headers = frame(0x1, 0x4, &[0x82; 20]);

        // The block in time, one byte at a time: through.
        let (reader, mut client) = watched();
        client.write_all(PREFACE_BYTES).await.unwrap();
        client.write_all(&settings).await.unwrap();
        drip(&mut client, &headers, Duration::from_millis(5)).await;
        drop(client);
        let read = finished(reader).await;
        assert!(read.end.is_ok() && !read.timed_out);

        // The same bytes too slowly: cut when the time has passed, with the block not complete.
        let (reader, mut client) = watched();
        client.write_all(PREFACE_BYTES).await.unwrap();
        client.write_all(&settings).await.unwrap();
        let began = TokioInstant::now();
        drip(&mut client, &headers, LIMIT / 10).await;
        let read = finished(reader).await;
        assert!(read.timed_out && read.end.is_err());
        assert!(began.elapsed() < LIMIT * 5);
        assert!(read.bytes.len() < PREFACE_BYTES.len() + settings.len() + headers.len());

        // A block that goes on in frames of continuation is one block: its time does not start again with each.
        let first = frame(0x1, 0, &[0x82; 4]);
        let more = frame(0x9, 0, &[0x82; 4]);
        let (reader, mut client) = watched();
        client.write_all(PREFACE_BYTES).await.unwrap();
        client.write_all(&first).await.unwrap();
        for _ in 0..30 {
            if client.write_all(&more).await.is_err() {
                break;
            }
            sleep(LIMIT / 10).await;
        }
        let read = finished(reader).await;
        assert!(read.timed_out && read.end.is_err());
        drop(client);

        // A block with a pause before its last frame, which ends it within the time: through.
        let (reader, mut client) = watched();
        client.write_all(PREFACE_BYTES).await.unwrap();
        client.write_all(&first).await.unwrap();
        sleep(LIMIT / 4).await;
        client
            .write_all(&frame(0x9, 0x4, &[0x82; 4]))
            .await
            .unwrap();
        drop(client);
        let read = finished(reader).await;
        assert!(read.end.is_ok() && !read.timed_out);
    });
}

#[test]
fn a_client_that_sends_large_fields_and_a_long_body_slowly_is_not_cut() {
    runtime().block_on(async {
        let (reader, mut client) = watched();
        client.write_all(PREFACE_BYTES).await.unwrap();
        client.write_all(&frame(0x4, 0, &[])).await.unwrap();
        // Fields of 16 KiB in a frame that ends the block, then a body in frames of data over more than the time
        // of a block, and then a second request.
        let mut sent = Vec::new();
        sent.extend_from_slice(&frame(0x1, 0x4, &vec![0x82; 16 * 1024]));
        for _ in 0..8 {
            sent.extend_from_slice(&frame(0x0, 0, &vec![b'x'; 16 * 1024]));
        }
        sent.extend_from_slice(&frame(0x1, 0x5, &[0x82; 20]));
        let began = TokioInstant::now();
        for piece in sent.chunks(24 * 1024) {
            client.write_all(piece).await.unwrap();
            sleep(LIMIT / 4).await;
        }
        assert!(began.elapsed() > LIMIT);
        drop(client);
        let read = finished(reader).await;
        assert!(read.end.is_ok() && !read.timed_out);
        assert_eq!(read.bytes.len(), PREFACE_BYTES.len() + 9 + sent.len());
    });
}
