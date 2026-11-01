use std::time::Duration;

use tokio::time::{Instant, sleep};
use tukuyomi_kernel::Verdict;

use super::*;
use crate::config::{ForwardConfig, Keep, Records, RouteConfig};
use crate::inbound::conn::tests::{BLOCK, Mode, Rig, config, parse_response, put, read_all, run};
use crate::inspect::driver::Outcome;
use crate::log::LOG_QUEUE;
use crate::route::{Rule, Table};

/// A forwarding configuration whose one route, which holds for every request, has these `records`.
fn keeping(records: RouteKeep) -> ForwardConfig {
    let route = RouteConfig {
        records: Some(records),
        ..RouteConfig::plain(0)
    };
    let mut forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
    forward.routes = Table::new(vec![(Rule::forward(None, None).unwrap(), route)]).unwrap();
    forward
}

const GET: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n";

/// The same without `Connection: close`, so that the connection notices when the client closes it.
const GET_OPEN: &[u8] = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";

/// The request records among `records`.
fn requests(records: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    of_type(records, "request")
}

/// The records of the type `kind` among `records`.
fn of_type(records: Vec<serde_json::Value>, kind: &str) -> Vec<serde_json::Value> {
    records
        .into_iter()
        .filter(|record| record["type"] == kind)
        .collect()
}

#[test]
fn a_required_route_turns_a_request_away_while_the_queue_has_no_place_for_its_record_and_the_others_do_not()
 {
    run(async {
        // The queue is full and nobody reads it. The driver of the test blocks every request it gets, with 403.
        for (records, status) in [
            (RouteKeep::Required, 503),
            (RouteKeep::BestEffort, 403),
            (RouteKeep::Security, 403),
        ] {
            let rig = Rig::with(config(), Mode::Answer(BLOCK), &keeping(records)).await;
            let log = rig.ctx.log.clone();
            for _ in 0..LOG_QUEUE {
                log.line("fill");
            }
            assert_eq!(log.dropped(), 0);
            let (client, task) = rig.connect().await;
            put(&client, GET).await;
            let response = parse_response(&read_all(&client).await);
            assert_eq!(response.status, status, "{records:?}");
            let refused = u64::from(records == RouteKeep::Required);
            assert_eq!(rig.ctx.counters.records_refused.get(), refused);
            // The record of the answer found no place, as any record does.
            assert_eq!(log.dropped(), 1, "{records:?}");
            let seen = rig.finish(task).await;
            assert_eq!(seen.len(), usize::from(status == 403), "{records:?}");
        }
    });
}

#[test]
fn a_request_of_a_required_route_gets_a_place_when_the_queue_is_read_and_its_record_is_queued_with_it()
 {
    run(async {
        let rig = Rig::with(config(), Mode::Answer(BLOCK), &keeping(RouteKeep::Required)).await;
        let (log, lines) = (rig.ctx.log.clone(), rig.lines.clone());
        for _ in 0..LOG_QUEUE {
            log.line("fill");
        }
        let (client, first) = rig.connect().await;
        put(&client, GET).await;
        assert_eq!(parse_response(&read_all(&client).await).status, 503);
        first.await.unwrap();

        // The queue is read: the next request is let in, inspected and blocked, and its record is in the queue.
        lines.take();
        let (client, second) = rig.connect().await;
        put(&client, GET).await;
        assert_eq!(parse_response(&read_all(&client).await).status, 403);
        let seen = rig.finish(second).await;
        assert_eq!(seen.len(), 1);
        assert_eq!(log.dropped(), 1);
        let records = lines.take();
        assert_eq!(records.len(), 1, "{records:?}");
        assert!(crate::log::is_answer(
            &records[0],
            "blocked",
            403,
            "blocked by a rule"
        ));
        // Nothing stays taken: every place of the queue is free again.
        for _ in 0..LOG_QUEUE {
            log.line("fill");
        }
        assert_eq!(log.dropped(), 1);
    });
}

#[test]
fn a_request_that_the_lag_of_the_shipper_turns_away_is_counted_and_has_no_record() {
    run(async {
        let rig = Rig::with(config(), Mode::Answer(BLOCK), &keeping(RouteKeep::Required)).await;
        // A shipper that has written no position: how far behind it is is not known.
        let dir = std::env::temp_dir().join(format!("tukuyomi-keep-ship-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let records = Records {
            dir: dir.clone(),
            file_bytes: 1 << 20,
            files: 3,
            keep: Keep::Required,
            sync_ms: None,
            ship: None,
        };
        rig.ctx.log.watch_ship(&records).unwrap();
        let lines = rig.lines.clone();
        let (client, task) = rig.connect().await;
        put(&client, GET).await;
        assert_eq!(parse_response(&read_all(&client).await).status, 503);
        assert_eq!(rig.ctx.counters.records_refused.get(), 1);
        rig.finish(task).await;
        let records = lines.take();
        assert!(requests(records.clone()).is_empty(), "{records:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    });
}

#[test]
fn a_request_that_was_let_in_and_is_dropped_before_its_answer_has_a_record_whatever_its_route_says()
{
    run(async {
        for records in [
            RouteKeep::Required,
            RouteKeep::BestEffort,
            RouteKeep::Security,
        ] {
            let rig = Rig::with(config(), Mode::Hold, &keeping(records)).await;
            let (log, lines) = (rig.ctx.log.clone(), rig.lines.clone());
            let free = rig.ctx.inspect.available_permits();
            let (client, task) = rig.connect().await;
            put(&client, GET_OPEN).await;
            // The request is with the inspection, which does not answer; then the client goes away.
            let by = Instant::now() + Duration::from_secs(20);
            while rig.ctx.inspect.available_permits() == free {
                assert!(
                    Instant::now() < by,
                    "{records:?}: the request did not arrive"
                );
                sleep(Duration::from_millis(5)).await;
            }
            drop(client);
            rig.finish(task).await;
            let written = lines.take();
            // The record of the request is there, so the connection does not write one of its own.
            assert!(
                of_type(written.clone(), "connection").is_empty(),
                "{records:?}: {written:?}"
            );
            let records_seen = requests(written);
            assert_eq!(records_seen.len(), 1, "{records:?}: {records_seen:?}");
            let record = &records_seen[0];
            assert_eq!(record["class"], "closed", "{records:?}");
            assert_eq!(record["status"], 0, "{records:?}");
            assert_eq!(
                record["reason"], "peer closed during the body",
                "{records:?}"
            );
            assert_eq!(record["path"], "/a", "{records:?}");
            // The seat of a required route is back, and the place of the record with it.
            let seats: Vec<_> = (0..LOG_QUEUE / 2).map(|_| log.seat()).collect();
            assert!(seats.iter().all(Option::is_some), "{records:?}");
        }
    });
}

#[test]
fn a_security_route_keeps_a_request_a_rule_matched_or_the_inspection_could_not_take_whatever_the_answer_was()
 {
    run(async {
        let rule = |verdict| Mode::Answer(Outcome::Verdict(verdict));
        let detected = Verdict::Detected {
            rule_id: 9201,
            status: 403,
        };
        let wild = Verdict::Block {
            phase: 1,
            rule_id: 9201,
            status: 99,
        };
        // The upstream is not there, so a request that is let through ends in 502.
        for (mode, status, kept) in [
            (rule(detected), 502, true),
            (rule(wild), 500, true),
            (Mode::Gone, 503, true),
            (rule(Verdict::Allow), 502, false),
        ] {
            let rig = Rig::with(config(), mode, &keeping(RouteKeep::Security)).await;
            let lines = rig.lines.clone();
            let (client, task) = rig.connect().await;
            put(&client, GET).await;
            assert_eq!(parse_response(&read_all(&client).await).status, status);
            rig.finish(task).await;
            let written = lines.take();
            let seen = requests(written.clone());
            assert_eq!(seen.len(), usize::from(kept), "{status}: {seen:?}");
            // A response whose record is not written still counts for its connection, which writes none of its own.
            let ended = of_type(written, "connection");
            assert!(ended.is_empty(), "{status}: {ended:?}");
        }
    });
}
