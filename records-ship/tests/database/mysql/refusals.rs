use mysql_async::OptsBuilder;
use mysql_async::prelude::Queryable;
use tukuyomi_proxy::log::ship::Identity;
use tukuyomi_records_ship::follow::Position;
use tukuyomi_records_ship::row::Row;
use tukuyomi_records_ship::store::mysql::{MyStore, Settings};
use tukuyomi_records_ship::store::{CERTIFICATE, LOGIN, NEWER, Store};

use super::support::{Database, Records, connect, lines, shipper};

/// When the tables are there, the shipper takes no right to create and no lock of the server for setting up: a lock
/// that someone else holds does not hold it up, though it would hold up a connection that has to make a table. (A
/// user without the right to create cannot be made here: the user of the tests may neither create a user nor take
/// back a right of its own, so this is the way to see that nothing is made when everything is there.)
#[test]
#[ignore = "needs a MySQL server"]
fn tables_that_are_there_are_taken_without_the_lock_of_setting_up() {
    let db = Database::new();
    db.run(async {
        // The first connection makes the tables.
        drop(connect(&db).await);
        // Another connection holds the lock of setting up.
        let mut other = mysql_async::Conn::new(db.settings().opts).await.unwrap();
        let got: Option<Option<i64>> = other
            .exec_first("SELECT GET_LOCK(?, 0)", ("tukuyomi_records_setup",))
            .await
            .unwrap();
        assert_eq!(got.flatten(), Some(1));
        let mut store = MyStore::connect(&db.settings())
            .await
            .unwrap_or_else(|e| panic!("a connection that makes nothing waited for the lock: {e}"));
        let rows = [Row::of(b"one"), Row::of(b"two")];
        let to = Position {
            identity: Identity { inode: 1, born: 2 },
            offset: 8,
            lost_lines: 0,
        };
        assert_eq!(store.commit(None, to, &rows).await.unwrap(), 2);
        assert_eq!(store.position().await.unwrap(), Some(to));
        // A table that is not there has to be made, which needs the lock: it is waited for, and the wait is bounded.
        db.exec("DROP TABLE tukuyomi_records_state").await;
        let waited = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            MyStore::connect(&db.settings()),
        )
        .await;
        assert!(waited.is_err(), "a table was made without the lock");
        other.disconnect().await.unwrap();
    });
}

/// A table that an operator dropped is made again when the shipper connects, though the version of the layout is
/// recorded; the tables that are there keep what they hold.
#[test]
#[ignore = "needs a MySQL server"]
fn a_table_that_is_missing_is_made_again_and_the_shipping_goes_on() {
    let db = Database::new();
    db.run(async {
        let mut store = connect(&db).await;
        let first = Position {
            identity: Identity { inode: 1, born: 2 },
            offset: 8,
            lost_lines: 0,
        };
        assert_eq!(
            store.commit(None, first, &[Row::of(b"one")]).await.unwrap(),
            1
        );
        drop(store);
        // The table of the positions is gone: the shipping starts again, and the rows stay.
        db.exec("DROP TABLE tukuyomi_records_state").await;
        let mut store = connect(&db).await;
        assert_eq!(store.position().await.unwrap(), None);
        let second = Position {
            offset: 16,
            ..first
        };
        assert_eq!(
            store
                .commit(None, second, &[Row::of(b"two")])
                .await
                .unwrap(),
            1
        );
        assert_eq!(db.count().await, 2);
        drop(store);
        // The table of the rows is gone: the position stays, and the shipping goes on from it.
        db.exec("DROP TABLE tukuyomi_records").await;
        let mut store = connect(&db).await;
        assert_eq!(store.position().await.unwrap(), Some(second));
        let third = Position {
            offset: 24,
            ..first
        };
        let rows = [Row::of(b"three")];
        assert_eq!(store.commit(Some(second), third, &rows).await.unwrap(), 1);
        assert_eq!(db.count().await, 1);
    });
}

/// A wrong password is a refusal of the login, which waiting does not mend: the shipper says so to its caller.
#[test]
#[ignore = "needs a MySQL server that asks for the password"]
fn a_wrong_password_is_a_refused_login() {
    let db = Database::new();
    let records = Records::new();
    records.write("records.log", &lines(0, 2));
    let settings = Settings {
        opts: OptsBuilder::from_opts(db.settings().opts)
            .pass(Some("not the password"))
            .into(),
        source: "test".to_owned(),
    };
    db.run(async {
        let e = match MyStore::connect(&settings).await {
            Ok(_) => panic!("a connection with a wrong password was made"),
            Err(e) => e,
        };
        assert_eq!((e.what, e.code.as_deref()), (LOGIN, Some("28000")), "{e}");
        let mut shipper = shipper(&records, 10, 0, settings);
        assert!(!shipper.login_refused());
        shipper.turn().await;
        assert!(shipper.login_refused());
    });
}

#[test]
#[ignore = "needs a MySQL server"]
fn a_newer_layout_of_the_tables_is_refused_and_the_same_one_is_taken() {
    let db = Database::new();
    db.run(async {
        // The first connection makes the tables; a second one finds them.
        drop(connect(&db).await);
        drop(connect(&db).await);
        assert_eq!(
            db.text("SELECT CAST(MAX(version) AS CHAR) FROM tukuyomi_records_schema")
                .await,
            "1"
        );
        db.exec("UPDATE tukuyomi_records_schema SET version = 2")
            .await;
        let e = match MyStore::connect(&db.settings()).await {
            Ok(_) => panic!("a newer layout was accepted"),
            Err(e) => e,
        };
        assert_eq!(e.what, NEWER);
        // Refused while the tables are made as well: the lock of setting up is let go.
        db.exec("DROP TABLE tukuyomi_records_state").await;
        let e = match MyStore::connect(&db.settings()).await {
            Ok(_) => panic!("a newer layout was accepted"),
            Err(e) => e,
        };
        assert_eq!(e.what, NEWER);
        let mut other = mysql_async::Conn::new(db.settings().opts).await.unwrap();
        let got: Option<Option<i64>> = other
            .exec_first("SELECT GET_LOCK(?, 0)", ("tukuyomi_records_setup",))
            .await
            .unwrap();
        assert_eq!(got.flatten(), Some(1));
        other.disconnect().await.unwrap();
    });
}

/// The server of the test offers TLS with a certificate that no authority of the system vouches for (and that is not
/// for the name of the connection): with the string as it is written, which means TLS, it is not connected to.
#[test]
#[ignore = "needs a MySQL server that offers TLS with a certificate of its own"]
fn a_certificate_that_is_not_accepted_is_refused() {
    let db = Database::new();
    db.run(async {
        let e = match MyStore::connect(&db.tls_settings()).await {
            Ok(_) => panic!("a connection with a certificate that nobody vouches for was made"),
            Err(e) => e,
        };
        assert_eq!(e.what, CERTIFICATE, "{e}");
    });
}
