use std::time::Duration;

use http::{HeaderName, HeaderValue};

use super::*;

fn servers(weights: &[u32]) -> Vec<ServerConfig> {
    weights
        .iter()
        .enumerate()
        .map(|(i, &weight)| ServerConfig {
            address: format!("127.0.0.1:{}", 9000 + i).parse().unwrap(),
            weight,
            max_fails: 1,
            fail_timeout: Duration::from_secs(10),
            backup: false,
        })
        .collect()
}

fn fields(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
    }
    map
}

fn key_of(policy: HashKey, client: &str, pairs: &[(&str, &str)]) -> Option<[u8; 32]> {
    Hash::new(&policy, &servers(&[1]))
        .key(client.parse().unwrap(), &fields(pairs))
        .map(|key| key.0)
}

fn header(name: &'static str) -> HashKey {
    HashKey::Header(HeaderName::from_static(name))
}

/// The server each of 1000 keys goes to, among the servers that `may` accepts.
fn homes(config: &[ServerConfig], may: impl Fn(usize) -> bool) -> Vec<usize> {
    let turn = Turn::new(config);
    let hash = Hash::new(&HashKey::ClientIp, config);
    (0..1000)
        .map(|n| {
            let key = Key::of(format!("key {n}").as_bytes());
            hash.pick(&turn, &may, |i| i64::from(config[i].weight), &key)
                .unwrap()
        })
        .collect()
}

#[test]
fn a_key_always_goes_to_the_same_server_and_only_the_keys_of_a_server_that_goes_move() {
    let config = servers(&[1, 1, 1, 1]);
    let all = homes(&config, |_| true);
    assert_eq!(all, homes(&config, |_| true));
    let count = |homes: &[usize], server: usize| homes.iter().filter(|&&h| h == server).count();
    // Each server has a share, and the share is not nothing.
    for server in 0..4 {
        assert!(count(&all, server) > 150, "server {server}");
    }
    // One server cannot be chosen: its keys go to the others, and no other key moves.
    let without = homes(&config, |i| i != 2);
    for (n, (before, after)) in all.iter().zip(&without).enumerate() {
        assert_ne!(*after, 2, "key {n}");
        if *before != 2 {
            assert_eq!(before, after, "key {n} moved between servers that stayed");
        }
    }
    // The server that comes back gets the keys it had.
    assert_eq!(all, homes(&config, |_| true));
}

#[test]
fn a_server_has_a_share_of_the_keys_in_proportion_to_its_weight() {
    let config = servers(&[3, 1]);
    let heavy = homes(&config, |_| true).iter().filter(|&&h| h == 0).count();
    // 750 of 1000 for a weight of 3 against 1, give or take the spread of a hash.
    assert!((700..=800).contains(&heavy), "{heavy}");
}

#[test]
fn the_number_drawn_is_neither_0_nor_1_and_the_score_is_finite_at_both_ends() {
    for bits in [0, u64::MAX, 1 << 12, (u64::MAX >> 12) << 12] {
        let u = unit(bits);
        assert!(u > 0.0 && u < 1.0, "{bits}: {u}");
        let score = 100.0 / -u.ln();
        assert!(score.is_finite() && score > 0.0, "{bits}: {score}");
    }
}

#[test]
fn the_servers_are_told_apart_by_their_address_and_place_and_not_by_where_they_are_written() {
    let a = place("127.0.0.1:9000".parse().unwrap(), 0);
    let b = place("127.0.0.1:9000".parse().unwrap(), 1);
    let c = place("[::1]:9000".parse().unwrap(), 0);
    let d = place("127.0.0.1:9001".parse().unwrap(), 0);
    assert!(a != b && a != c && a != d && b != c);
    // The same servers in another order have the same places.
    let hash = Hash::new(&HashKey::ClientIp, &servers(&[1, 1]));
    let mut reversed = servers(&[1, 1]);
    reversed.reverse();
    let other = Hash::new(&HashKey::ClientIp, &reversed);
    assert_eq!(hash.places[0], other.places[1]);
    // An IPv4 address written as IPv6 is the IPv4 address, and the same address twice is told from itself.
    let mut twice = servers(&[1, 1, 1]);
    twice[1].address = "[::ffff:127.0.0.1]:9000".parse().unwrap();
    twice[2].address = "127.0.0.1:9000".parse().unwrap();
    let hash = Hash::new(&HashKey::ClientIp, &twice);
    assert_eq!(hash.places[0], a);
    assert_eq!(hash.places[1], b);
    assert_eq!(hash.places[2], place("127.0.0.1:9000".parse().unwrap(), 2));
}

#[test]
fn the_client_is_the_address_and_an_ipv6_client_is_its_64_bit_network() {
    let key = |client: &str| key_of(HashKey::ClientIp, client, &[]).unwrap();
    assert_eq!(key("203.0.113.9"), key("::ffff:203.0.113.9"));
    assert_ne!(key("203.0.113.9"), key("203.0.113.10"));
    assert_eq!(
        key("2001:db8:1:2::1"),
        key("2001:db8:1:2:ffff:ffff:ffff:ffff")
    );
    assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
}

#[test]
fn a_header_key_is_the_first_field_with_the_name_and_has_1_to_1024_bytes() {
    let key = |pairs: &[(&str, &str)]| key_of(header("x-user"), "203.0.113.9", pairs);
    let first = key(&[("X-User", "ann"), ("x-user", "bob")]);
    assert_eq!(first, key(&[("x-user", "ann")]));
    assert_ne!(first, key(&[("x-user", "bob")]));
    assert_eq!(key(&[("X-Other", "ann")]), None);
    assert_eq!(key(&[("x-user", "")]), None);
    let longest = "a".repeat(1024);
    assert!(key(&[("x-user", &longest)]).is_some());
    assert_eq!(key(&[("x-user", &format!("{longest}a"))]), None);
}

#[test]
fn a_cookie_key_is_the_first_cookie_with_the_name_from_all_the_lines_without_the_blanks_around_it()
{
    let key =
        |pairs: &[(&str, &str)]| key_of(HashKey::Cookie("sid".to_string()), "203.0.113.9", pairs);
    let one = key(&[("Cookie", "a=1; sid=abc ; b=2")]);
    assert_eq!(one, key(&[("Cookie", "sid=abc")]));
    // Several lines, as an HTTP/1.1 request may have: the name is looked for in each, the first one wins.
    let lines = key(&[
        ("Cookie", "a=1"),
        ("Cookie", "b=2; sid=abc"),
        ("Cookie", "sid=def"),
    ]);
    assert_eq!(lines, one);
    assert_ne!(lines, key(&[("Cookie", "sid=def")]));
    // The name is exact and the cookie is not a part of another one.
    assert_eq!(key(&[("Cookie", "SID=abc; xsid=abc; sid2=abc")]), None);
    assert_eq!(key(&[("Cookie", "sid=")]), None);
    assert_eq!(key(&[("Cookie", "sid")]), None);
    assert_eq!(key(&[("X-Other", "sid=abc")]), None);
}
