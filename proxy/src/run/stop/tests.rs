use super::*;
use crate::log;
use crate::run::signals::tests::{fixture, runtime};
use std::sync::mpsc::sync_channel;
use std::thread;
use tokio::sync::oneshot;
use tukuyomi_kernel::Shutdown;

fn shutdown(phase: Phase, confirmed: bool, removed: bool) -> End {
    End::Done {
        kernel: Shutdown {
            results: Vec::new(),
            phase,
            bye: true,
            exit_confirmed: confirmed,
            dir_removed: removed,
            held_left: 0,
            waiting_left: 0,
        },
        retired_clean: true,
    }
}

#[test]
fn only_a_stopped_confirmed_removed_kernel_is_a_clean_end() {
    assert!(clean_shutdown(&shutdown(Phase::Stopped, true, true)));
    assert!(!clean_shutdown(&shutdown(Phase::Stopped, false, true)));
    assert!(!clean_shutdown(&shutdown(Phase::Stopped, true, false)));
    assert!(!clean_shutdown(&shutdown(Phase::Ready, true, true)));
    assert!(!clean_shutdown(&shutdown(
        Phase::Failed(Failure::ReapUnknown),
        true,
        true
    )));
    assert!(!clean_shutdown(&End::Fatal(
        "result for an unknown request"
    )));
    // A kernel that was stopped before, and did not stop cleanly, makes the end unclean too.
    let End::Done { kernel, .. } = shutdown(Phase::Stopped, true, true) else {
        unreachable!()
    };
    assert!(!clean_shutdown(&End::Done {
        kernel,
        retired_clean: false
    }));
}

fn proxy_config(stop_inspect_ms: u64, stop_wait_ms: u64) -> ProxyConfig {
    let loaded = config_for_tests();
    ProxyConfig {
        stop_inspect: Duration::from_millis(stop_inspect_ms),
        stop_wait: Duration::from_millis(stop_wait_ms),
        ..loaded
    }
}

fn config_for_tests() -> ProxyConfig {
    let ms = Duration::from_millis;
    ProxyConfig {
        listeners: Vec::new(),
        max_conns: 1,
        max_head_bytes: 1024,
        max_body: 0,
        inspect_body: 0,
        max_body_wire: 0,
        max_buffered_bytes: 0,
        upstream_max_headers: 1,
        upstream_max_head_bytes: 8192,
        upstream_head_wire: 16384,
        drive_slice: ms(1),
        ready_wait: ms(1),
        head_read: ms(1),
        body_read: ms(1),
        inspect_wait: ms(1),
        upstream_connect: ms(1),
        upstream_header: ms(1),
        request_total: ms(1),
        response_idle: ms(1),
        conn_total: ms(1),
        stop_inspect: ms(1),
        stop_wait: ms(1),
        keepalive_timeout: ms(1),
        keepalive_requests: 1,
        keepalive_time: ms(1),
        lingering_time: ms(1),
        lingering_timeout: ms(1),
        lingering_bytes: 1,
        trusted_proxies: Vec::new(),
        upstream_keepalive: 0,
        upstream_keepalive_timeout: ms(1),
        upstream_keepalive_requests: 1,
    }
}

/// The way from the connections to a stand-in driver.
fn connections(tx: &SyncSender<Msg>) -> Ingress {
    Ingress::new(tx.clone())
}

/// A stand-in driver thread: takes the stop message, then ends as `end` says.
fn driver_thread(
    end: Option<End>,
    end_tx: oneshot::Sender<End>,
) -> (
    SyncSender<Msg>,
    thread::JoinHandle<Option<std::time::Instant>>,
) {
    let (tx, rx) = sync_channel::<Msg>(2);
    let handle = thread::spawn(move || {
        let inspect_by = match rx.recv() {
            Ok(Msg::Stop { inspect_by }) => Some(inspect_by),
            _ => None,
        };
        if let Some(end) = end {
            let _ = end_tx.send(end);
        }
        inspect_by
    });
    (tx, handle)
}

#[test]
fn the_stop_gives_the_driver_its_deadline_and_exits_zero_after_a_clean_end() {
    let log = log::start_logger(log::Format::Json).unwrap();
    runtime().block_on(async {
        let f = fixture();
        let (tx, driver) = driver_thread(Some(shutdown(Phase::Stopped, true, true)), f.end);
        let connections = connections(&tx);
        let before = std::time::Instant::now();
        assert!(connections.sender().is_some());
        let code = stop(
            f.waits,
            Cause::Signal("SIGTERM"),
            tx,
            &connections,
            &proxy_config(700, 2000),
            Duration::from_millis(500),
            &log,
        )
        .await;
        assert_eq!(code, EXIT_OK);
        // The stop closes the way from the connections to the driver.
        assert!(connections.sender().is_none());
        let inspect_by = driver.join().unwrap().expect("the stop message");
        assert!(inspect_by >= before + Duration::from_millis(700));
        assert!(inspect_by <= std::time::Instant::now() + Duration::from_millis(700));
    });
}

#[test]
fn the_stop_exits_one_unless_the_end_is_clean_and_the_cause_is_not_a_failure() {
    let log = log::start_logger(log::Format::Json).unwrap();
    let cfg = proxy_config(10, 100);
    let grace = Duration::from_millis(50);
    runtime().block_on(async {
        // A kernel that did not stop cleanly.
        for end in [
            shutdown(Phase::Stopped, false, true),
            End::Fatal("result for an unknown request"),
        ] {
            let f = fixture();
            let (tx, driver) = driver_thread(Some(end), f.end);
            let connections = connections(&tx);
            assert_eq!(
                stop(
                    f.waits,
                    Cause::Signal("SIGINT"),
                    tx,
                    &connections,
                    &cfg,
                    grace,
                    &log
                )
                .await,
                EXIT_FAILED
            );
            driver.join().unwrap();
        }
        // A failure as the cause, although the driver ends cleanly.
        for cause in [Cause::Failed(Failure::BudgetExhausted), Cause::Late] {
            let f = fixture();
            let (tx, driver) = driver_thread(Some(shutdown(Phase::Stopped, true, true)), f.end);
            let connections = connections(&tx);
            assert_eq!(
                stop(f.waits, cause, tx, &connections, &cfg, grace, &log).await,
                EXIT_FAILED
            );
            driver.join().unwrap();
        }
        // The driver gone without an end.
        let f = fixture();
        let (tx, driver) = driver_thread(None, f.end);
        let connections = connections(&tx);
        assert_eq!(
            stop(
                f.waits,
                Cause::Signal("SIGHUP"),
                tx,
                &connections,
                &cfg,
                grace,
                &log
            )
            .await,
            EXIT_FAILED
        );
        driver.join().unwrap();
    });
}

#[test]
fn the_stop_aborts_connections_that_outlive_it() {
    let log = log::start_logger(log::Format::Json).unwrap();
    runtime().block_on(async {
        let mut f = fixture();
        f.waits.conns.spawn(std::future::pending());
        let (tx, driver) = driver_thread(Some(shutdown(Phase::Stopped, true, true)), f.end);
        let connections = connections(&tx);
        let start = Instant::now();
        let code = stop(
            f.waits,
            Cause::Signal("SIGTERM"),
            tx,
            &connections,
            &proxy_config(10, 150),
            Duration::from_millis(100),
            &log,
        )
        .await;
        let spent = start.elapsed();
        assert_eq!(code, EXIT_OK);
        assert!(spent >= Duration::from_millis(150) && spent < Duration::from_secs(5));
        driver.join().unwrap();
    });
}
