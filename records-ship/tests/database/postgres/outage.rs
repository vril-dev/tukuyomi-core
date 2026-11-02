use super::support::{Database, INTERVAL, Records, Relay, lines, raws, shipper, until_idle};

#[test]
#[ignore = "needs a PostgreSQL server"]
fn a_database_that_stops_is_waited_for_and_the_shipping_goes_on_without_loss() {
    let db = Database::new();
    let records = Records::new();
    records.write("records.log", &lines(0, 4));
    // The shipper reaches the server through a relay that the test stops and starts.
    let relay = Relay::start(db.server(), 0);
    let port = relay.port;
    let settings = db.settings_through(port);
    db.run(async {
        let mut shipper = shipper(&records, 3, 0, settings);
        until_idle(&mut shipper).await;
        assert_eq!(db.raws().await, raws(0, 4));
        let shipped = shipper.follower().position();

        // The database goes away; lines go on being written.
        relay.stop();
        records.append("records.log", &lines(4, 9));
        let waits = [
            shipper.turn().await,
            shipper.turn().await,
            shipper.turn().await,
            shipper.turn().await,
        ];
        // The waits double from the interval; nothing was shipped and the position stays.
        assert_eq!(
            waits,
            [INTERVAL, 2 * INTERVAL, 4 * INTERVAL, 8 * INTERVAL],
            "{waits:?}"
        );
        assert_eq!(db.raws().await, raws(0, 4));
        assert_eq!(shipper.follower().position(), shipped);

        // It comes back at the same address: the rest is shipped, once.
        let relay = Relay::start(db.server(), port);
        until_idle(&mut shipper).await;
        assert_eq!(db.raws().await, raws(0, 9));
        assert_eq!(shipper.turn().await, INTERVAL);
        // The next failure waits the interval again.
        relay.stop();
        records.append("records.log", &lines(9, 10));
        assert_eq!(shipper.turn().await, INTERVAL);
        assert_eq!(shipper.turn().await, 2 * INTERVAL);
    });
}
