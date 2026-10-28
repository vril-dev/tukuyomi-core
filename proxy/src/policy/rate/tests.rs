use super::*;

const SEC: u64 = NANOS;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A limit of `rate` a second and `burst`, which counts at most `keys` clients and leaves out the `exempt` networks.
fn limit(rate: u32, burst: u32, keys: usize, exempt: &[&str]) -> RateLimit {
    RateLimit::new(&RateLimitConfig {
        rate,
        burst,
        keys,
        exempt: exempt.iter().map(|net| Cidr::parse(net).unwrap()).collect(),
    })
}

#[test]
fn burst_plus_one_requests_pass_at_once_and_the_next_is_refused_until_one_gap_has_passed() {
    // Two a second: a gap of half a second, and a tolerance of three gaps.
    let limit = limit(2, 3, 1024, &[]);
    let client = ip("192.0.2.1");
    let gap = SEC / 2;
    for _ in 0..4 {
        assert_eq!(limit.admit_at(client, 0), Ok(()));
    }
    // The fifth is refused, and refusing it again changes nothing.
    assert_eq!(limit.admit_at(client, 0), Err(1));
    assert_eq!(limit.admit_at(client, 0), Err(1));
    // One nanosecond short of a gap is refused, and a gap passes.
    assert_eq!(limit.admit_at(client, gap - 1), Err(1));
    assert_eq!(limit.admit_at(client, gap), Ok(()));
    assert_eq!(limit.admit_at(client, gap), Err(1));
}

#[test]
fn a_refused_client_is_told_the_seconds_to_wait_rounded_up_and_at_least_one() {
    assert_eq!(seconds(1), 1);
    assert_eq!(seconds(NANOS), 1);
    assert_eq!(seconds(NANOS + 1), 2);
    assert_eq!(seconds(u64::MAX), u32::MAX);
    // A quarter of a second, then a whole one: both are told 1.
    for rate in [4, 1] {
        let limit = limit(rate, 0, 1024, &[]);
        let client = ip("192.0.2.1");
        assert_eq!(limit.admit_at(client, 0), Ok(()));
        assert_eq!(limit.admit_at(client, 0), Err(1));
    }
}

#[test]
fn clients_in_one_ipv6_network_of_64_bits_share_a_count_and_other_clients_do_not() {
    let limit = limit(1, 0, 1024, &[]);
    assert_eq!(limit.admit_at(ip("2001:db8:0:1::1"), 0), Ok(()));
    assert_eq!(limit.admit_at(ip("2001:db8:0:1:ffff::2"), 0), Err(1));
    assert_eq!(limit.admit_at(ip("2001:db8:0:2::1"), 0), Ok(()));
    // An IPv4 address is one client; the same address written as IPv4-mapped is the same client, and the all-zero
    // IPv6 network is not the IPv4 address 0.0.0.0.
    assert_eq!(limit.admit_at(ip("192.0.2.1"), 0), Ok(()));
    assert_eq!(limit.admit_at(ip("192.0.2.2"), 0), Ok(()));
    assert_eq!(limit.admit_at(ip("::ffff:192.0.2.1"), 0), Err(1));
    assert_eq!(limit.admit_at(ip("0.0.0.0"), 0), Ok(()));
    assert_eq!(limit.admit_at(ip("::"), 0), Ok(()));
    assert_eq!(limit.keys(), 6);
}

#[test]
fn a_full_table_drops_the_client_of_the_oldest_request_and_counts_it_and_a_new_client_is_not_refused()
 {
    let limit = limit(1, 0, 3, &[]);
    let (a, b, c, d) = (
        ip("192.0.2.1"),
        ip("192.0.2.2"),
        ip("192.0.2.3"),
        ip("192.0.2.4"),
    );
    for client in [a, b, c] {
        assert_eq!(limit.admit_at(client, 0), Ok(()));
    }
    // `a` makes the latest request, though a refused one, so `b` is the oldest.
    assert_eq!(limit.admit_at(a, 0), Err(1));
    assert_eq!((limit.keys(), limit.evicted()), (3, 0));
    assert_eq!(limit.admit_at(d, 0), Ok(()));
    assert_eq!((limit.keys(), limit.evicted()), (3, 1));
    // `a` kept its count, and `b` lost it and passes as a new client, which drops `c`.
    assert_eq!(limit.admit_at(a, 0), Err(1));
    assert_eq!(limit.admit_at(b, 0), Ok(()));
    assert_eq!((limit.keys(), limit.evicted()), (3, 2));
}

#[test]
fn clients_whose_number_has_passed_are_dropped_a_few_at_a_time_and_are_not_counted_as_evicted() {
    let limit = limit(1, 0, 8, &[]);
    for last in 1..=6 {
        assert_eq!(limit.admit_at(ip(&format!("192.0.2.{last}")), 0), Ok(()));
    }
    assert_eq!(limit.keys(), 6);
    // A second later all six have passed. One request drops the oldest `SWEEP` of them, and adds its own.
    assert_eq!(limit.admit_at(ip("192.0.2.9"), SEC), Ok(()));
    assert_eq!(limit.keys(), 6 - SWEEP + 1);
    assert_eq!(limit.evicted(), 0);
    // A client that was dropped passes as a new one.
    assert_eq!(limit.admit_at(ip("192.0.2.1"), SEC), Ok(()));
}

#[test]
fn an_exempt_network_is_not_counted() {
    let limit = limit(1, 0, 1024, &["198.51.100.0/24", "2001:db8::/32"]);
    for client in ["198.51.100.7", "2001:db8:5::1", "::ffff:198.51.100.8"] {
        for _ in 0..5 {
            assert_eq!(limit.admit_at(ip(client), 0), Ok(()));
        }
    }
    assert_eq!(limit.keys(), 0);
    assert_eq!(limit.admit_at(ip("198.51.101.7"), 0), Ok(()));
    assert_eq!(limit.admit_at(ip("198.51.101.7"), 0), Err(1));
}

#[test]
fn the_extremes_of_rate_and_burst_and_of_the_clock_do_not_overflow() {
    for (rate, burst) in [(1, 100_000), (100_000, 100_000), (1, 0), (100_000, 0)] {
        let limit = limit(rate, burst, 1024, &[]);
        let client = ip("192.0.2.1");
        for _ in 0..=burst {
            assert_eq!(limit.admit_at(client, 0), Ok(()), "{rate} {burst}");
        }
        assert_eq!(limit.admit_at(client, 0), Err(1), "{rate} {burst}");
        // At the end of the clock the numbers stop at the largest one and nothing wraps.
        let other = ip("192.0.2.2");
        assert_eq!(
            limit.admit_at(other, u64::MAX - 1),
            Ok(()),
            "{rate} {burst}"
        );
        for _ in 0..3 {
            let _ = limit.admit_at(other, u64::MAX);
        }
    }
}
