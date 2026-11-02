use std::time::SystemTime;

use tukuyomi_proxy::log::ship::Position as State;
use tukuyomi_records_ship::files;
use tukuyomi_records_ship::row::Row;
use tukuyomi_records_ship::store::{MOVED, Store};

use super::support::{Database, Records, at, connect, lines, raws, rows, shipper, until_idle};

#[test]
#[ignore = "needs a MySQL server"]
fn a_batch_and_its_position_are_stored_together_or_not_at_all() {
    let db = Database::new();
    db.run(async {
        let mut store = connect(&db).await;
        assert_eq!(store.position().await.unwrap(), None);
        // A position is expected and the row of it is not there (an operator deleted it): nothing is stored, and the
        // row is not made.
        let e = store
            .commit(Some(at(10)), at(30), &rows(0, 3))
            .await
            .unwrap_err();
        assert_eq!(e.what, MOVED);
        assert_eq!(db.count().await, 0);
        assert_eq!(store.position().await.unwrap(), None);
        assert_eq!(store.commit(None, at(30), &rows(0, 3)).await.unwrap(), 3);
        assert_eq!(store.position().await.unwrap(), Some(at(30)));
        // A batch whose position does not follow the one the database has is stored not at all: its rows go with
        // the position, as when the shipper dies between the insert and the commit.
        let e = store
            .commit(Some(at(1)), at(50), &rows(3, 5))
            .await
            .unwrap_err();
        assert_eq!(e.what, MOVED);
        let e = store.commit(None, at(50), &rows(3, 5)).await.unwrap_err();
        assert_eq!(e.what, MOVED);
        assert_eq!(db.count().await, 3);
        assert_eq!(store.position().await.unwrap(), Some(at(30)));
        // With the position that the database has, the same batch is stored once.
        assert_eq!(
            store
                .commit(Some(at(30)), at(50), &rows(3, 5))
                .await
                .unwrap(),
            2
        );
        assert_eq!(db.count().await, 5);
        // The same rows sent again are not stored again, and the position still moves.
        assert_eq!(
            store
                .commit(Some(at(50)), at(70), &rows(0, 5))
                .await
                .unwrap(),
            0
        );
        assert_eq!(db.count().await, 5);
        assert_eq!(store.position().await.unwrap(), Some(at(70)));
        // A position without rows, and the same position again: it is not taken for another.
        assert_eq!(store.commit(Some(at(70)), at(70), &[]).await.unwrap(), 0);
        assert_eq!(store.commit(Some(at(70)), at(70), &[]).await.unwrap(), 0);
    });
}

#[test]
#[ignore = "needs a MySQL server"]
fn a_batch_of_many_rows_is_stored_in_order_and_once() {
    let db = Database::new();
    db.run(async {
        let mut store = connect(&db).await;
        // More rows than one statement takes: the rows go in several, in one transaction.
        assert_eq!(store.commit(None, at(1), &rows(0, 250)).await.unwrap(), 250);
        let expected: Vec<String> = (0..250).map(|n| format!("row {n}")).collect();
        assert_eq!(db.raws().await, expected);
        // Sent again, none is stored, in each of the statements.
        assert_eq!(
            store
                .commit(Some(at(1)), at(2), &rows(0, 250))
                .await
                .unwrap(),
            0
        );
        assert_eq!(db.count().await, 250);
    });
}

#[test]
#[ignore = "needs a MySQL server"]
fn lines_that_a_database_could_refuse_are_stored_and_do_not_stop_the_batch() {
    let db = Database::new();
    db.run(async {
        let mut store = connect(&db).await;
        let long_invalid = b"\xff".repeat(4096);
        let bad: Vec<Row> = [
            &b"\xff\xfe not utf-8"[..],
            &long_invalid[..],
            br#"{"type":"request","ts":"0000-01-01T00:00:00.000Z","client":"999.1.1.1","status":99999999999,"path":"/a\u0000b","rules":["x"]}"#,
            br#"{"type":"request","ts":"2026-13-45T25:61:61.000Z","id":"\u0000","host":"h"}"#,
            br#"{"ts":"2026-10-25T08:00:00.123Z","type":"request","client":"::ffff:192.0.2.1","status":403,"rules":[942100],"rule":942100}"#,
            br#"{"ts":"9999-12-31T23:59:59.999Z","type":"line","line":"last"}"#,
            br#"{"ts":"1000-01-01T00:00:00.000Z","type":"line","line":"first"}"#,
            br#"{"ts":"0999-12-31T23:59:59.999Z","type":"line","line":"before"}"#,
            b"",
            b"{}",
        ]
        .iter()
        .map(|line| Row::of(line))
        .collect();
        assert_eq!(store.commit(None, at(10), &bad).await.unwrap(), 10);
        assert_eq!(db.count().await, 10);
        assert_eq!(
            db.text("SELECT CONCAT(client, ' ', rules, ' ', status) FROM tukuyomi_records WHERE rule = 942100")
                .await,
            "192.0.2.1 [942100] 403"
        );
        assert_eq!(
            db.text("SELECT CONCAT(SUM(`type` = 'unknown'), ' ', SUM(`type` = 'request'), ' ', SUM(`type` = 'line')) FROM tukuyomi_records")
                .await,
            "4 3 3"
        );
        // The times at the ends of what the type holds are kept; one before it is the time the server stored it at.
        assert_eq!(
            db.text("SELECT DATE_FORMAT(MAX(ts), '%Y-%m-%d %H:%i:%s.%f') FROM tukuyomi_records")
                .await,
            "9999-12-31 23:59:59.999000"
        );
        assert_eq!(
            db.text("SELECT CAST(SUM(ts = '1000-01-01 00:00:00.000') AS CHAR) FROM tukuyomi_records")
                .await,
            "1"
        );
        assert_eq!(
            db.text("SELECT CAST(SUM(ts < '1000-01-02') AS CHAR) FROM tukuyomi_records")
                .await,
            "1"
        );
        // The longest line is kept whole.
        assert_eq!(db.raws().await[1].chars().count(), 4096);
    });
}

#[test]
#[ignore = "needs a MySQL server"]
fn a_request_number_of_any_length_is_cut_and_the_batch_is_stored() {
    let db = Database::new();
    db.run(async {
        let mut store = connect(&db).await;
        let mut state = 7u64;
        let id: String = (0..3000)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                char::from(b'a' + u8::try_from((state >> 33) % 26).unwrap())
            })
            .collect();
        let long = format!("{{\"ts\":\"2026-10-25T08:00:00.123Z\",\"type\":\"request\",\"id\":\"{id}\",\"method\":\"GET\"}}");
        let rows = [Row::of(b"{\"type\":\"line\"}"), Row::of(long.as_bytes()), Row::of(b"after")];
        assert_eq!(store.commit(None, at(5000), &rows).await.unwrap(), 3);
        assert_eq!(
            db.text("SELECT CAST(CHAR_LENGTH(request_id) AS CHAR) FROM tukuyomi_records WHERE request_id IS NOT NULL")
                .await,
            "128"
        );
        // The line itself is kept whole.
        assert_eq!(db.raws().await[1], long);
    });
}

#[test]
#[ignore = "needs a MySQL server"]
fn a_replay_stores_nothing_twice() {
    let db = Database::new();
    let records = Records::new();
    records.write("records.log", &lines(0, 7));
    db.run(async {
        let mut first = shipper(&records, 3, 0, db.settings());
        until_idle(&mut first).await;
        assert_eq!(db.raws().await, raws(0, 7));
        // The position of the database and the position file are the same.
        let position = first.follower().position().unwrap();
        assert_eq!(
            position.offset,
            std::fs::metadata(records.path("records.log"))
                .unwrap()
                .len()
        );
        let state = State::parse(&std::fs::read(records.path("ship.state")).unwrap()).unwrap();
        assert_eq!(
            (state.identity(), state.offset),
            (position.identity, position.offset)
        );
        // The database forgets the position (a restore from a copy, a table emptied): the files are shipped from the
        // start again, and the table keeps each line once.
        db.exec("DELETE FROM tukuyomi_records_state").await;
        let mut second = shipper(&records, 3, 0, db.settings());
        until_idle(&mut second).await;
        assert_eq!(db.raws().await, raws(0, 7));
        assert_eq!(second.follower().position(), Some(position));
        // A shipper that starts again goes on from the position and stores nothing.
        let mut third = shipper(&records, 3, 0, db.settings());
        until_idle(&mut third).await;
        assert_eq!(db.count().await, 7);
    });
}

#[test]
#[ignore = "needs a MySQL server"]
fn old_rows_are_removed_and_recent_ones_stay() {
    let db = Database::new();
    let records = Records::new();
    let now = files::rfc3339(SystemTime::now());
    records.write(
        "records.log",
        &format!(
            "{{\"ts\":\"2020-01-01T00:00:00.000Z\",\"type\":\"line\",\"line\":\"old\"}}\n\
             {{\"ts\":\"2021-06-01T00:00:00.000Z\",\"type\":\"line\",\"line\":\"older\"}}\n\
             {{\"ts\":\"{now}\",\"type\":\"line\",\"line\":\"new\"}}\n\
             not a record\n"
        ),
    );
    db.run(async {
        let mut shipper = shipper(&records, 10, 30, db.settings());
        until_idle(&mut shipper).await;
        let kept = db.raws().await;
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept[0].contains("\"new\"") && kept[1] == "not a record");
        // What was removed is not shipped again by the same shipper.
        until_idle(&mut shipper).await;
        assert_eq!(db.count().await, 2);
    });
}
