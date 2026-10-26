use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::inbound::conn::tests::{BLOCK, Mode, Rig, parse_response, put, read_all, run};
use crate::inbound::session::tests::{get, kept};

const SEC: Duration = Duration::from_secs(1);

#[test]
fn a_request_without_a_copy_of_its_head_is_not_served_and_closes_the_connection() {
    run(async {
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let local = server.local_addr().unwrap();
        let (serving, mut gate) = Serving::start(
            server,
            peer,
            local,
            &rig.ctx,
            0,
            Instant::now(),
            Scheme::Http,
        );
        put(&client, &get("/a")).await;
        gate.first_head(Instant::now() + 10 * SEC).await.unwrap();
        // The copy the gate made is lost, as it would be if hyper and the gate disagreed about the bytes.
        let other = http::Request::get("/other")
            .header("host", "h")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(serving.link.take_for(&other).is_none());
        assert_eq!(serving.drive(&mut gate).await, End::Done);
        drop(gate);
        let answer = parse_response(&read_all(&client).await);
        assert_eq!(answer.status, 400);
        assert_eq!(answer.all("connection"), ["close"]);
        assert_eq!(answer.all("content-length"), ["0"]);
        let served = tokio::spawn(async {});
        assert!(rig.finish(served).await.is_empty());
    });
}
