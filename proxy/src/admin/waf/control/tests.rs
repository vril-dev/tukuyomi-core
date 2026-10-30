use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixListener;
use std::thread::{self, JoinHandle};

use super::*;
use crate::admin::file_store::tests::scratch;

fn fp(n: u8) -> Fingerprint {
    Fingerprint::of(&[n])
}

/// A socket in `dir` that takes one connection, reads its line and, if `reply` is there, answers with it and closes.
/// Without a reply it keeps the connection open for `hold`. The thread gives back the line it read.
fn serve(dir: &Path, reply: Option<String>, hold: Duration) -> (PathBuf, JoinHandle<String>) {
    let path = dir.join("c.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let thread = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(sock.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        match reply {
            Some(text) => sock.write_all(text.as_bytes()).unwrap(),
            None => thread::sleep(hold),
        }
        line
    });
    (path, thread)
}

fn status_line(mode: &str) -> String {
    format!(
        "{{\"generation\":\"{}\",\"mode\":\"{mode}\",\"engine\":\"coraza\",\"phase\":\"ready\",\"switching\":false,\"ready\":true}}\n",
        fp(1).hex()
    )
}

fn control(path: &Path) -> Control {
    Control::new(path, Duration::from_secs(1))
}

#[test]
fn a_status_and_the_answers_to_a_switch_are_read_from_the_lines_of_the_proxy() {
    let dir = scratch();
    let (path, thread) = serve(dir.path(), Some(status_line("detect")), Duration::ZERO);
    let status = control(&path).status().state().unwrap();
    assert_eq!(thread.join().unwrap(), "{\"op\":\"status\"}\n");
    assert_eq!(
        status,
        Status {
            generation: fp(1),
            mode: "detect",
            engine: "coraza",
            phase: "ready",
            switching: false,
            ready: true
        }
    );
    fs::remove_file(&path).unwrap();
    for (word, reply) in [
        ("switched", Reply::Switched),
        ("unchanged", Reply::Unchanged),
        ("refused", Reply::Refused),
        ("failed", Reply::Failed),
        ("busy", Reply::Busy),
    ] {
        let line = format!(
            "{{\"result\":\"{word}\",\"reason\":\"x\",\"generation\":\"{}\"}}\n",
            fp(2).hex()
        );
        let (path, thread) = serve(dir.path(), Some(line), Duration::ZERO);
        assert_eq!(control(&path).switch(fp(2)), Some(reply), "{word}");
        assert_eq!(
            thread.join().unwrap(),
            format!("{{\"op\":\"switch\",\"expect\":\"{}\"}}\n", fp(2).hex())
        );
        fs::remove_file(&path).unwrap();
    }
}

#[test]
fn no_socket_no_answer_and_an_answer_that_is_not_the_proxys_are_all_unreachable() {
    let dir = scratch();
    assert_eq!(
        control(&dir.path().join("none.sock")).status(),
        Seen::Unreachable
    );
    let good = format!(
        "{{\"result\":\"switched\",\"generation\":\"{}\"}}\n",
        fp(1).hex()
    );
    let cases = [
        // Not JSON, two lines, no line feed, an unknown word, a short generation, and an error answer.
        "not json\n".to_owned(),
        format!("{}{}", status_line("block"), status_line("block")),
        status_line("block").trim_end().to_owned(),
        status_line("loud"),
        status_line("block").replace(&fp(1).hex(), "abc"),
        "{\"result\":\"error\",\"reason\":\"no answer\"}\n".to_owned(),
    ];
    for reply in cases {
        let (path, thread) = serve(dir.path(), Some(reply.clone()), Duration::ZERO);
        assert_eq!(control(&path).status(), Seen::Unreachable, "{reply:?}");
        thread.join().unwrap();
        fs::remove_file(&path).unwrap();
    }
    let (path, thread) = serve(
        dir.path(),
        Some(good.replace("switched", "done")),
        Duration::ZERO,
    );
    assert_eq!(control(&path).switch(fp(1)), None);
    thread.join().unwrap();
    fs::remove_file(&path).unwrap();
    // A proxy that takes the question and says nothing is given up after the time of the question.
    let (path, thread) = serve(dir.path(), None, Duration::from_millis(600));
    let impatient = Control {
        path: path.clone(),
        ask_wait: Duration::from_millis(100),
        switch_wait: Duration::from_millis(100),
    };
    let began = Instant::now();
    assert_eq!(impatient.status(), Seen::Unreachable);
    assert!(began.elapsed() < Duration::from_millis(500));
    thread.join().unwrap();
}

/// A socket in `dir` that takes `closed` connections and closes each at once, and then, if `then` is there, serves one
/// connection with that line.
fn closing(dir: &Path, closed: usize, then: Option<String>) -> (PathBuf, JoinHandle<()>) {
    let path = dir.join("c.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let thread = thread::spawn(move || {
        for _ in 0..closed {
            drop(listener.accept().unwrap());
        }
        if let Some(text) = then {
            let (mut sock, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(sock.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            sock.write_all(text.as_bytes()).unwrap();
        }
    });
    (path, thread)
}

#[test]
fn a_proxy_that_takes_the_connection_and_closes_it_has_no_place_and_is_not_unreachable() {
    let dir = scratch();
    // Closed once, then it answers: the question is asked again after a pause, and the state is read.
    let (path, thread) = closing(dir.path(), 1, Some(status_line("block")));
    let began = Instant::now();
    assert!(matches!(control(&path).status(), Seen::State(_)));
    assert!(began.elapsed() >= ASK_AGAIN);
    thread.join().unwrap();
    fs::remove_file(&path).unwrap();
    // Closed both times: busy, which is reachable and has no state.
    let (path, thread) = closing(dir.path(), 2, None);
    let seen = control(&path).status();
    assert_eq!(
        (seen, seen.reachable(), seen.state()),
        (Seen::Busy, true, None)
    );
    thread.join().unwrap();
    fs::remove_file(&path).unwrap();
    // An order that is closed on was not taken, which is what the proxy says of an order it cannot take now.
    let (path, thread) = closing(dir.path(), 1, None);
    assert_eq!(control(&path).switch(fp(2)), Some(Reply::Busy));
    thread.join().unwrap();
}

#[test]
fn a_socket_whose_queue_is_full_is_given_up_within_the_time_of_a_question() {
    let dir = scratch();
    let path = dir.path().join("c.sock");
    // A listener that never accepts, and connections waiting at it until its queue is full. A connection that is
    // dropped at once still waits in the queue, so no descriptors are held.
    let _listener = UnixListener::bind(&path).unwrap();
    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let full = runtime.block_on(async {
        for waiting in 0..10_000 {
            match timeout(ASK_WAIT, tokio::net::UnixStream::connect(&path)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Some((waiting, e.kind())),
                Err(_) => return None,
            }
        }
        None
    });
    assert!(
        matches!(full, Some((waiting, io::ErrorKind::WouldBlock)) if waiting > 0),
        "{full:?}"
    );
    let began = Instant::now();
    assert_eq!(control(&path).status(), Seen::Unreachable);
    assert_eq!(control(&path).switch(fp(1)), None);
    assert!(began.elapsed() < 2 * ASK_WAIT);
}
