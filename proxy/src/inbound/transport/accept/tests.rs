use std::future::poll_fn;
use std::sync::mpsc::sync_channel;

use tokio::runtime::{Builder, Runtime};
use tokio::time::timeout;

use super::*;
use crate::inspect::driver::Msg;

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

/// The next thing the acceptor gives within `ms` milliseconds, if there is one.
async fn next(acceptor: &mut Acceptor, ms: u64) -> Option<Accepted> {
    timeout(Duration::from_millis(ms), poll_fn(|cx| acceptor.poll(cx)))
        .await
        .ok()
}

/// The connection the acceptor gives within five seconds.
async fn conn(acceptor: &mut Acceptor) -> Arrival {
    match next(acceptor, 5000).await {
        Some(Accepted::Conn(arrival)) => arrival,
        _ => panic!("no connection was accepted"),
    }
}

async fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

fn ingress() -> Arc<Ingress> {
    let (tx, _rx) = sync_channel::<Msg>(1);
    Arc::new(Ingress::new(tx))
}

#[test]
fn only_running_out_of_a_resource_pauses_the_accept_loop() {
    for errno in [12, 23, 24, 105] {
        assert!(is_resource_error(errno), "{errno}");
    }
    // EAGAIN, EINTR, ECONNABORTED
    for errno in [11, 4, 103] {
        assert!(!is_resource_error(errno), "{errno}");
    }
}

#[test]
fn a_connection_permit_is_taken_before_accept_and_a_shortage_drains_the_idle() {
    runtime().block_on(async {
        let (listener, addr) = listener().await;
        let permits = Arc::new(Semaphore::new(1));
        let shared = ingress();
        let mut told = shared.drained();
        let mut acceptor = Acceptor::new(vec![listener], permits.clone(), shared);
        let _first = TcpStream::connect(addr).await.unwrap();
        let _second = TcpStream::connect(addr).await.unwrap();
        let _third = TcpStream::connect(addr).await.unwrap();

        let first = conn(&mut acceptor).await;
        assert_eq!(permits.available_permits(), 0);
        // A connection that is accepted with a permit tells nobody.
        assert!(!told.has_changed().unwrap());
        // The second connection arrives with every permit in use: it is taken in to wait, once, and the idle
        // connections are told. It is not served before a permit is back.
        assert!(next(&mut acceptor, 150).await.is_none());
        assert!(told.has_changed().unwrap());
        let _ = told.borrow_and_update();
        assert!(next(&mut acceptor, 150).await.is_none());
        assert!(!told.has_changed().unwrap());
        drop(first.permit);
        let second = conn(&mut acceptor).await;
        // The third one arrives with every permit in use again, and tells again.
        assert!(next(&mut acceptor, 150).await.is_none());
        assert!(told.has_changed().unwrap());
        drop(second.permit);
        conn(&mut acceptor).await;
    });
}

#[test]
fn the_listeners_share_the_permits_and_take_turns() {
    runtime().block_on(async {
        let ((a, a_addr), (b, b_addr)) = (listener().await, listener().await);
        let permits = Arc::new(Semaphore::new(1));
        let shared = ingress();
        let mut told = shared.drained();
        let mut acceptor = Acceptor::new(vec![a, b], permits.clone(), shared);
        let _x = TcpStream::connect(b_addr).await.unwrap();
        let first = conn(&mut acceptor).await;
        assert_eq!(first.listener, 1);
        // One permit is all there is: a connection at each listener waits for it, whatever the listener, and the
        // one after that stays in its backlog (the idle connections are told for each of the two, not for it).
        let _y = TcpStream::connect(a_addr).await.unwrap();
        let _z = TcpStream::connect(b_addr).await.unwrap();
        let _w = TcpStream::connect(b_addr).await.unwrap();
        assert!(next(&mut acceptor, 150).await.is_none());
        assert!(told.has_changed().unwrap());
        let _ = told.borrow_and_update();
        drop(first.permit);
        // The permits go to the ones that wait in turn, the listener after the last served first.
        let second = conn(&mut acceptor).await;
        assert_eq!(second.listener, 0);
        drop(second.permit);
        let third = conn(&mut acceptor).await;
        assert_eq!(third.listener, 1);
        // The connection behind the waiting one of the second listener comes last.
        drop(third.permit);
        let fourth = conn(&mut acceptor).await;
        assert_eq!(fourth.listener, 1);

        // With permits to spare, a listener with a long backlog does not keep the other one waiting.
        let ((a, a_addr), (b, b_addr)) = (listener().await, listener().await);
        let mut acceptor = Acceptor::new(vec![a, b], Arc::new(Semaphore::new(8)), ingress());
        let mut keep = Vec::new();
        for _ in 0..3 {
            keep.push(TcpStream::connect(a_addr).await.unwrap());
        }
        keep.push(TcpStream::connect(b_addr).await.unwrap());
        let mut order = Vec::new();
        for _ in 0..4 {
            order.push(conn(&mut acceptor).await.listener);
        }
        assert_eq!(order[..2], [0, 1], "{order:?}");
        assert_eq!(order[2..], [0, 0], "{order:?}");
    });
}

#[test]
fn the_first_address_that_cannot_be_bound_ends_the_bind() {
    runtime().block_on(async {
        let (taken, addr) = listener().await;
        let free = "127.0.0.1:0".parse().unwrap();
        let permits = Arc::new(Semaphore::new(1));
        assert!(
            Acceptor::bind(&[free, addr], permits.clone(), ingress())
                .await
                .is_err()
        );
        let mut both = Acceptor::bind(&[free, free], permits, ingress())
            .await
            .unwrap();
        assert_eq!(both.listeners.len(), 2);
        drop(taken);
        assert!(next(&mut both, 100).await.is_none());
    });
}
