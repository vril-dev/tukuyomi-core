use tokio_postgres::config::SslMode;
use tukuyomi_proxy::log::ship::Identity;
use tukuyomi_records_ship::follow::Position;
use tukuyomi_records_ship::row::Row;
use tukuyomi_records_ship::store::pgsql::PgStore;
use tukuyomi_records_ship::store::{CERTIFICATE, LOGIN, NEWER, Store};

use super::support::{Database, Records, connect, lines, shipper};

/// A user who may use the tables but not create anything gets as far as the first batch when the tables are there.
/// It could not connect at all while the shipper asked for the right to create on every connection. (The user of the
/// tests may not create roles, so the right is taken from the user of the tests on its own schema.)
#[test]
#[ignore = "needs a PostgreSQL server"]
fn a_user_that_may_not_create_runs_when_the_tables_are_there() {
    let db = Database::new();
    db.run(async {
        // The first connection makes the tables, with the right to create.
        drop(connect(&db).await);
        db.exec("REVOKE CREATE ON SCHEMA {s} FROM CURRENT_USER")
            .await;
        assert_eq!(
            db.text("SELECT has_schema_privilege(current_user, '{s}', 'CREATE')::text")
                .await,
            "false"
        );
        let mut store = PgStore::connect(&db.settings())
            .await
            .unwrap_or_else(|e| panic!("the user without the right to create cannot connect: {e}"));
        let rows = [Row::of(b"one"), Row::of(b"two")];
        let to = Position {
            identity: Identity { inode: 1, born: 2 },
            offset: 8,
            lost_lines: 0,
        };
        assert_eq!(store.commit(None, to, &rows).await.unwrap(), 2);
        assert_eq!(store.position().await.unwrap(), Some(to));
        // It does not make a table that is not there: it has no right to.
        db.exec("DROP TABLE {s}.tukuyomi_records_state").await;
        let e = match PgStore::connect(&db.settings()).await {
            Ok(_) => panic!("the user without the right to create made a table"),
            Err(e) => e,
        };
        assert_eq!(e.code.as_deref(), Some("42501"), "{e}");
    });
}

/// A table that an operator dropped is made again when the shipper connects, though the version of the layout is
/// recorded; the tables that are there keep what they hold.
#[test]
#[ignore = "needs a PostgreSQL server"]
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
        db.exec("DROP TABLE {s}.tukuyomi_records_state").await;
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
        db.exec("DROP TABLE {s}.tukuyomi_records").await;
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
#[ignore = "needs a PostgreSQL server that asks for the password"]
fn a_wrong_password_is_a_refused_login() {
    let db = Database::new();
    let records = Records::new();
    records.write("records.log", &lines(0, 2));
    let mut settings = db.settings();
    settings.config.password("not the password");
    db.run(async {
        let e = match PgStore::connect(&settings).await {
            Ok(_) => panic!("a connection with a wrong password was made"),
            Err(e) => e,
        };
        assert_eq!((e.what, e.code.as_deref()), (LOGIN, Some("28P01")), "{e}");
        let mut shipper = shipper(&records, 10, 0, settings);
        assert!(!shipper.login_refused());
        shipper.turn().await;
        assert!(shipper.login_refused());
    });
}

#[test]
#[ignore = "needs a PostgreSQL server"]
fn a_newer_layout_of_the_tables_is_refused_and_the_same_one_is_taken() {
    let db = Database::new();
    db.run(async {
        // The first connection makes the tables; a second one finds them.
        drop(connect(&db).await);
        drop(connect(&db).await);
        assert_eq!(
            db.text("SELECT max(version)::text FROM {s}.tukuyomi_records_schema")
                .await,
            "1"
        );
        db.exec("UPDATE {s}.tukuyomi_records_schema SET version = 2")
            .await;
        let e = match PgStore::connect(&db.settings()).await {
            Ok(_) => panic!("a newer layout was accepted"),
            Err(e) => e,
        };
        assert_eq!(e.what, NEWER);
    });
}

/// The server of the test offers TLS with a certificate that no authority of the system vouches for (and that is not
/// for the name of the connection): with `require` it is not connected to.
#[test]
#[ignore = "needs a PostgreSQL server that offers TLS with a certificate of its own"]
fn a_certificate_that_is_not_accepted_is_refused() {
    let db = Database::new();
    db.run(async {
        let mut settings = db.settings();
        settings.config.ssl_mode(SslMode::Require);
        let e = match PgStore::connect(&settings).await {
            Ok(_) => panic!("a connection with a certificate that nobody vouches for was made"),
            Err(e) => e,
        };
        assert_eq!(e.what, CERTIFICATE, "{e}");
        // `prefer` is made as `require`: it verifies as well, and does not fall back to plain.
        settings.config.ssl_mode(SslMode::Prefer);
        let e = match PgStore::connect(&settings).await {
            Ok(_) => panic!("a connection with a certificate that nobody vouches for was made"),
            Err(e) => e,
        };
        assert_eq!(e.what, CERTIFICATE, "{e}");
    });
}
