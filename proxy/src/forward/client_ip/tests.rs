use super::*;

fn net(text: &str) -> Cidr {
    Cidr::parse(text).unwrap_or_else(|| panic!("{text} is a network"))
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn sock(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

/// The client of a request from `peer` that has the given `X-Forwarded-For` lines, with `trusted` networks.
fn client(peer: &str, trusted: &[&str], lines: &[&str]) -> SocketAddr {
    let trusted: Vec<Cidr> = trusted.iter().map(|t| net(t)).collect();
    let lines: Vec<&[u8]> = lines.iter().map(|l| l.as_bytes()).collect();
    effective(sock(peer), &trusted, &lines)
}

#[test]
fn a_network_is_an_address_with_a_prefix_and_nothing_below_the_prefix() {
    for text in [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "192.0.2.7/32",
        "::/0",
        "2001:db8::/32",
        "2001:db8::1/128",
    ] {
        assert!(Cidr::parse(text).is_some(), "{text}");
    }
    for text in [
        "",
        "10.0.0.0",
        "10.0.0.0/",
        "/8",
        // The prefix is at the limit, then past it.
        "10.0.0.0/33",
        "2001:db8::/129",
        // A bit below the prefix: the address does not name a network.
        "10.0.0.1/8",
        "2001:db8::1/32",
        // Only decimal digits, and no leading zero.
        "10.0.0.0/+8",
        "10.0.0.0/-1",
        "10.0.0.0/08",
        "10.0.0.0/0x8",
        "10.0.0.0/8 ",
        " 10.0.0.0/8",
        "10.0.0.0/8/8",
        "10.0.0.0/999",
        // Not an address: a leading zero, a host name, a port, a zone, a bracket.
        "010.0.0.0/8",
        "localhost/8",
        "10.0.0.0:80/8",
        "fe80::/10%eth0",
        "[::]/0",
        // A mapped address is written as IPv4.
        "::ffff:10.0.0.0/104",
    ] {
        assert_eq!(Cidr::parse(text), None, "{text:?}");
    }
}

#[test]
fn a_network_holds_the_addresses_of_its_prefix_only() {
    let v4 = net("10.0.0.0/8");
    assert!(v4.contains(ip("10.255.255.255")));
    assert!(!v4.contains(ip("11.0.0.0")));
    assert!(!v4.contains(ip("9.255.255.255")));
    let one = net("192.0.2.7/32");
    assert!(one.contains(ip("192.0.2.7")) && !one.contains(ip("192.0.2.8")));
    assert!(net("0.0.0.0/0").contains(ip("203.0.113.1")));

    let v6 = net("2001:db8::/32");
    assert!(v6.contains(ip("2001:db8:ffff::1")));
    assert!(!v6.contains(ip("2001:db9::")));
    assert!(net("::/0").contains(ip("2001:db8::1")));

    // The families do not meet, except through the mapped form of an IPv4 address.
    assert!(!net("0.0.0.0/0").contains(ip("2001:db8::1")));
    assert!(!net("::/0").contains(ip("10.0.0.1")));
    assert!(v4.contains(ip("::ffff:10.1.2.3")));
    assert!(!v4.contains(ip("::ffff:11.1.2.3")));
}

#[test]
fn a_peer_that_is_not_trusted_is_the_client_whatever_it_says() {
    // No networks at all, and a network that is not the peer's.
    let peer = "203.0.113.9:5555";
    assert_eq!(client(peer, &[], &["198.51.100.7"]), sock(peer));
    assert_eq!(client(peer, &["10.0.0.0/8"], &["198.51.100.7"]), sock(peer));
    assert_eq!(client(peer, &[], &[]), sock(peer));
}

#[test]
fn a_trusted_peer_without_a_list_is_the_client() {
    let peer = "10.0.0.2:5555";
    assert_eq!(client(peer, &["10.0.0.0/8"], &[]), sock(peer));
}

#[test]
fn the_list_is_read_from_the_right_and_the_trusted_addresses_are_skipped() {
    let trusted = ["10.0.0.0/8"];
    let peer = "10.0.0.2:5555";
    // The first address that is not trusted from the right is the client, with the port 0.
    assert_eq!(
        client(peer, &trusted, &["198.51.100.7, 10.0.0.9"]),
        sock("198.51.100.7:0")
    );
    // An address further to the left is not looked at once the client is found.
    assert_eq!(
        client(peer, &trusted, &["203.0.113.1, 198.51.100.7, 10.0.0.9"]),
        sock("198.51.100.7:0")
    );
    // A trusted address between two others does not stop the reading.
    assert_eq!(
        client(peer, &trusted, &["203.0.113.1, 10.0.0.8, 10.0.0.9"]),
        sock("203.0.113.1:0")
    );
    // Several lines are one list in the order received, and blanks around an entry do not count.
    assert_eq!(
        client(
            peer,
            &trusted,
            &["203.0.113.1", "  198.51.100.7\t,10.0.0.8", "10.0.0.9"]
        ),
        sock("198.51.100.7:0")
    );
}

#[test]
fn a_list_of_trusted_addresses_only_gives_the_leftmost() {
    let trusted = ["10.0.0.0/8"];
    let peer = "10.0.0.2:5555";
    assert_eq!(
        client(peer, &trusted, &["10.0.0.7, 10.0.0.8", "10.0.0.9"]),
        sock("10.0.0.7:0")
    );
    assert_eq!(client(peer, &trusted, &["10.0.0.7"]), sock("10.0.0.7:0"));
}

#[test]
fn an_entry_that_is_not_an_address_leaves_the_peer_as_the_client() {
    let trusted = ["10.0.0.0/8"];
    let peer = "10.0.0.2:5555";
    for line in [
        // The bad entry is the last one, or comes before a trusted one, with a good address further left.
        "198.51.100.7, unknown",
        "198.51.100.7, unknown, 10.0.0.9",
        // Empty entries, a port, a bracket, a zone, a name, a quoted value.
        "198.51.100.7,",
        "198.51.100.7,,10.0.0.9",
        "",
        "198.51.100.7:80",
        "[2001:db8::1]",
        "fe80::1%eth0",
        "\"198.51.100.7\"",
        "for=198.51.100.7",
        "198.51.100.7 10.0.0.9",
    ] {
        assert_eq!(client(peer, &trusted, &[line]), sock(peer), "{line:?}");
    }
    // What lies to the left of the client is not looked at, however bad it is.
    assert_eq!(
        client(peer, &trusted, &["unknown,, 198.51.100.7"]),
        sock("198.51.100.7:0")
    );
    // A line that is not UTF-8 is not an address either.
    let trusted = [net("10.0.0.0/8")];
    let lines: [&[u8]; 1] = [b"198.51.100.7, \xff"];
    assert_eq!(effective(sock(peer), &trusted, &lines), sock(peer));
}

#[test]
fn ipv6_is_read_the_same_way_and_a_mapped_address_is_the_ipv4_address() {
    let trusted = ["2001:db8:1::/48", "10.0.0.0/8"];
    // An IPv6 peer and client.
    assert_eq!(
        client(
            "[2001:db8:1::2]:5555",
            &trusted,
            &["2001:db8:2::7, 2001:db8:1::9"]
        ),
        sock("[2001:db8:2::7]:0")
    );
    // A mapped peer is the IPv4 address, in the trust and in the result.
    assert_eq!(
        client("[::ffff:10.0.0.2]:5555", &trusted, &["::ffff:198.51.100.7"]),
        sock("198.51.100.7:0")
    );
    // A mapped peer that is not trusted stays the peer, as it was given.
    assert_eq!(
        client("[::ffff:203.0.113.9]:5555", &trusted, &["198.51.100.7"]),
        sock("[::ffff:203.0.113.9]:5555")
    );
}
