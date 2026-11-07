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

/// The line of a proxy that sends the figures as well.
fn figures_line() -> String {
    status_line("block").replace(
        "\"ready\":true",
        &format!(
            "\"ready\":true,\"reloading\":true,\"uptime_ms\":1234,\"requests\":50,\"blocked\":3,\"policy_refused\":2,\"upstream_failures\":4,\"config\":\"{}\",\"managed\":\"{}\",\"resolve_timeout_ms\":30000,\"config_reloads\":{{\"replaced\":5,\"refused\":1}}",
            fp(3).hex(),
            fp(4).hex()
        ),
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
            ready: true,
            // A proxy that does not send the figures.
            reloading: None,
            uptime_ms: None,
            requests: None,
            blocked: None,
            policy_refused: None,
            upstream_failures: None,
            config: None,
            managed: None,
            resolve_timeout_ms: None,
            config_reloads: None,
        }
    );
    for key in [
        "config",
        "reloading",
        "resolve_timeout_ms",
        "config_reloads",
    ] {
        assert_eq!(status.json()[key], Value::Null, "{key}");
    }
    fs::remove_file(&path).unwrap();
    // A proxy that sends them: they are read, and shown as they are.
    let (path, thread) = serve(dir.path(), Some(figures_line()), Duration::ZERO);
    let status = control(&path).status().state().unwrap();
    thread.join().unwrap();
    assert_eq!(
        status.json(),
        json!({
            "generation": fp(1).hex(),
            "mode": "block",
            "engine": "coraza",
            "phase": "ready",
            "switching": false,
            "reloading": true,
            "ready": true,
            "uptime_ms": 1234,
            "requests": 50,
            "blocked": 3,
            "policy_refused": 2,
            "upstream_failures": 4,
            "config": fp(3).hex(),
            "managed": fp(4).hex(),
            "resolve_timeout_ms": 30000,
            "config_reloads": {"replaced": 5, "refused": 1},
        })
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
        // A figure that is there and is not what it should be: a negative count, a short or an upper case digest, and
        // a reading count that is not a number.
        figures_line().replace("\"requests\":50", "\"requests\":-1"),
        figures_line().replace(&fp(3).hex(), "abc"),
        figures_line().replace(&fp(3).hex(), &fp(3).hex().to_uppercase()),
        figures_line().replace("\"replaced\":5", "\"replaced\":\"5\""),
        figures_line().replace("\"reloading\":true", "\"reloading\":1"),
        figures_line().replace("\"resolve_timeout_ms\":30000", "\"resolve_timeout_ms\":-1"),
        // A time of the lookup outside the range of the configuration: none, and one more than 3600 s.
        figures_line().replace("\"resolve_timeout_ms\":30000", "\"resolve_timeout_ms\":0"),
        figures_line().replace(
            "\"resolve_timeout_ms\":30000",
            "\"resolve_timeout_ms\":3600001",
        ),
    ];
    for reply in cases {
        let (path, thread) = serve(dir.path(), Some(reply.clone()), Duration::ZERO);
        assert_eq!(control(&path).status(), Seen::Unreachable, "{reply:?}");
        thread.join().unwrap();
        fs::remove_file(&path).unwrap();
    }
    // 3600 s, the longest, is taken.
    let longest = figures_line().replace(
        "\"resolve_timeout_ms\":30000",
        "\"resolve_timeout_ms\":3600000",
    );
    let (path, thread) = serve(dir.path(), Some(longest), Duration::ZERO);
    let status = control(&path)
        .status()
        .state()
        .map(|status| status.resolve_timeout_ms);
    assert_eq!(status, Some(Some(3_600_000)));
    thread.join().unwrap();
    fs::remove_file(&path).unwrap();
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
        (seen.clone(), seen.reachable(), seen.state()),
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

/// The answer of a proxy to a reload order, as `serve` sends it: one line.
fn reload_answer(dir: &Path, line: &str) -> Option<Reloaded> {
    let (path, thread) = serve(dir, Some(line.to_owned()), Duration::ZERO);
    let answered = control(&path).reload(fp(5).bytes(), Duration::from_secs(1));
    assert_eq!(
        thread.join().unwrap(),
        format!("{{\"op\":\"reload\",\"managed\":\"{}\"}}\n", fp(5).hex())
    );
    fs::remove_file(&path).unwrap();
    answered
}

#[test]
fn an_answer_to_a_reload_is_taken_only_with_the_words_and_the_fields_of_its_result() {
    let dir = scratch();
    let (config, managed) = (fp(3).hex(), fp(4).hex());
    let detail = |text: &str| {
        format!(
            "{{\"result\":\"refused\",\"reason\":\"tls\",\"detail\":\"{text}\",\"managed\":\"{managed}\"}}\n"
        )
    };
    let taken = [
        (
            format!("{{\"result\":\"replaced\",\"config\":\"{config}\",\"managed\":\"{managed}\"}}\n"),
            Reloaded::Replaced {
                config: fp(3).bytes(),
                managed: Some(fp(4).bytes()),
            },
        ),
        (
            detail("a certificate and a private key are not a pair (site a)"),
            Reloaded::Refused {
                reason: "tls",
                detail: "a certificate and a private key are not a pair (site a)".to_owned(),
                managed: Some(fp(4).bytes()),
            },
        ),
        // A sentence of 512 bytes is the longest.
        (
            detail(&"x".repeat(DETAIL_MAX)),
            Reloaded::Refused {
                reason: "tls",
                detail: "x".repeat(DETAIL_MAX),
                managed: Some(fp(4).bytes()),
            },
        ),
        (
            "{\"result\":\"refused\",\"reason\":\"unmanaged\",\"detail\":\"the configuration in force has no managed object\",\"managed\":null}\n".to_owned(),
            Reloaded::Refused {
                reason: "unmanaged",
                detail: "the configuration in force has no managed object".to_owned(),
                managed: None,
            },
        ),
        (
            format!("{{\"result\":\"busy\",\"reason\":\"reload under way\",\"managed\":\"{managed}\"}}\n"),
            Reloaded::Busy {
                reason: "reload under way",
                managed: Some(fp(4).bytes()),
            },
        ),
        // A proxy that does not know the order.
        (
            "{\"result\":\"error\",\"reason\":\"unknown op\"}\n".to_owned(),
            Reloaded::Error("unknown op"),
        ),
    ];
    for (line, reloaded) in taken {
        assert_eq!(reload_answer(dir.path(), &line), Some(reloaded), "{line:?}");
    }
    let refused = [
        // An unknown result, and a reason of another result or of none.
        format!("{{\"result\":\"done\",\"managed\":\"{managed}\"}}\n"),
        format!("{{\"result\":\"busy\",\"reason\":\"tls\",\"managed\":\"{managed}\"}}\n"),
        format!(
            "{{\"result\":\"replaced\",\"reason\":\"tls\",\"config\":\"{config}\",\"managed\":\"{managed}\"}}\n"
        ),
        "{\"result\":\"error\",\"reason\":\"no such thing\"}\n".to_owned(),
        // Digits that are short or upper case, a `replaced` without `config`, `config` beside another result.
        format!("{{\"result\":\"replaced\",\"config\":\"abc\",\"managed\":\"{managed}\"}}\n"),
        format!(
            "{{\"result\":\"replaced\",\"config\":\"{config}\",\"managed\":\"{}\"}}\n",
            managed.to_uppercase()
        ),
        format!("{{\"result\":\"replaced\",\"managed\":\"{managed}\"}}\n"),
        format!(
            "{{\"result\":\"busy\",\"reason\":\"starting\",\"config\":\"{config}\",\"managed\":\"{managed}\"}}\n"
        ),
        // A sentence that is missing, empty, one byte too long, or has a byte outside 0x20 to 0x7e.
        format!("{{\"result\":\"refused\",\"reason\":\"tls\",\"managed\":\"{managed}\"}}\n"),
        detail(""),
        detail(&"x".repeat(DETAIL_MAX + 1)),
        detail("a\\u001fb"),
        detail("caf\u{e9}"),
        // A sentence beside another result, and a version beside an error.
        format!(
            "{{\"result\":\"busy\",\"reason\":\"starting\",\"detail\":\"x\",\"managed\":\"{managed}\"}}\n"
        ),
        format!("{{\"result\":\"error\",\"reason\":\"unknown op\",\"managed\":\"{managed}\"}}\n"),
    ];
    for line in refused {
        assert_eq!(reload_answer(dir.path(), &line), None, "{line:?}");
    }
    // A proxy that closes the connection without a line gives no answer either.
    let (path, thread) = closing(dir.path(), 1, None);
    assert_eq!(
        control(&path).reload(fp(5).bytes(), Duration::from_secs(1)),
        None
    );
    thread.join().unwrap();
}
