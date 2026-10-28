use std::net::IpAddr;

use super::*;
use crate::policy::mmdb::tests::{
    Record, database, database_of, database_with_data, map, pointer, text,
};

fn ip(address: &str) -> IpAddr {
    address.parse().unwrap()
}

fn country(code: &str) -> Country {
    Country::parse(code).unwrap()
}

/// A record whose country has this ISO code, and whose registered country has `registered`.
fn record(code: &str, registered: &str) -> Record {
    Record::Data(map(&[
        ("country", map(&[("iso_code", text(code))])),
        ("registered_country", map(&[("iso_code", text(registered))])),
    ]))
}

#[test]
fn the_country_is_that_of_the_record_else_the_registered_one_else_unknown() {
    let networks = [
        ("203.0.113.0/24", Record::Country("JP")),
        ("192.0.2.0/24", Record::Registered("FR")),
        ("100.64.0.0/16", Record::Neither),
        ("2001:db8::/32", Record::Country("DE")),
    ];
    for bits in [24, 28, 32] {
        let geo = Geo::open(database(true, bits, &networks)).unwrap();
        assert_eq!(geo.country(ip("203.0.113.9")), country("JP"));
        assert_eq!(geo.country(ip("::ffff:203.0.113.9")), country("JP"));
        assert_eq!(geo.country(ip("2001:db8::9")), country("DE"));
        // No code in the country: the registered country's.
        assert_eq!(geo.country(ip("192.0.2.9")), country("FR"));
        // A record without a country, and an address that the database does not know.
        assert_eq!(geo.country(ip("100.64.0.9")), Country::Unknown);
        assert_eq!(geo.country(ip("8.8.8.8")), Country::Unknown);
        assert_eq!(geo.country(ip("2001:db9::1")), Country::Unknown);
    }
}

#[test]
fn a_code_that_is_not_two_upper_case_letters_is_unknown_and_the_registered_country_is_not_asked() {
    let geo = Geo::open(database(
        false,
        24,
        &[
            ("192.0.2.0/24", record("jp", "US")),
            ("198.51.100.0/24", record("JPN", "US")),
            ("203.0.113.0/24", record("UNKNOWN", "US")),
            ("100.64.0.0/16", record("J1", "US")),
            ("100.65.0.0/16", record("US", "JP")),
        ],
    ))
    .unwrap();
    for address in ["192.0.2.1", "198.51.100.1", "203.0.113.1", "100.64.0.1"] {
        assert_eq!(geo.country(ip(address)), Country::Unknown, "{address}");
    }
    assert_eq!(geo.country(ip("100.65.0.1")), country("US"));
}

#[test]
fn loopback_private_link_local_and_unspecified_addresses_are_unknown_whatever_the_database_says() {
    let geo = Geo::open(database(
        true,
        24,
        &[
            ("0.0.0.0/32", Record::Country("JP")),
            ("10.0.0.0/8", Record::Country("JP")),
            ("127.0.0.0/8", Record::Country("JP")),
            ("169.0.0.0/8", Record::Country("JP")),
            ("172.0.0.0/8", Record::Country("JP")),
            ("192.0.0.0/8", Record::Country("JP")),
            ("::1/128", Record::Country("JP")),
            ("fc00::/7", Record::Country("JP")),
            ("fe80::/10", Record::Country("JP")),
            ("2001:db8::/32", Record::Country("JP")),
        ],
    ))
    .unwrap();
    for address in [
        "0.0.0.0",
        "10.1.2.3",
        "127.0.0.1",
        "169.254.9.9",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.1.1",
        "::",
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:10.1.2.3",
    ] {
        assert_eq!(geo.country(ip(address)), Country::Unknown, "{address}");
    }
    // The first address on each side of 172.16.0.0/12 is looked up, and so are the others the database has.
    for address in ["172.15.255.255", "172.32.0.0", "192.0.2.1", "2001:db8::1"] {
        assert_eq!(geo.country(ip(address)), country("JP"), "{address}");
    }
}

#[test]
fn a_database_is_refused_when_its_records_cannot_be_read_as_countries() {
    let ok = |kind: &str, networks: &[(&str, Record)]| {
        Geo::open(database_of(kind, true, 24, networks)).err()
    };
    let jp = [("203.0.113.0/24", Record::Country("JP"))];
    let none = [("203.0.113.0/24", Record::Neither)];
    // The type has `Country` in it, or a record has a code.
    assert_eq!(ok("GeoLite2-Country", &none), None);
    assert_eq!(ok("DBIP-Country-Lite", &jp), None);
    assert_eq!(ok("Anything", &jp), None);
    assert_eq!(ok("GeoIP2-ISP", &none), Some(NO_COUNTRIES));
    // A record that is not a map, a country that is not a map.
    for data in [text("JP"), map(&[("country", text("JP"))])] {
        let file = database_with_data("Test-Country", &data);
        assert!(Geo::open(file).is_err(), "{data:?}");
    }
    // A record that is a pointer loop, or a pointer to a pointer.
    let looped = [map(&[("country", pointer(0))])].concat();
    assert_eq!(
        Geo::open(database_with_data("Test-Country", &looped))
            .err()
            .map(|f| f.0),
        Some("the country database has values nested too deep")
    );
    // A file that is cut.
    let file = database(true, 24, &jp);
    assert!(Geo::open(file[..file.len() / 2].to_vec()).is_err());
    assert!(Geo::open(Vec::new()).is_err());
}

#[test]
fn two_handles_are_equal_only_if_they_are_the_same_database() {
    let file = database(true, 24, &[("203.0.113.0/24", Record::Country("JP"))]);
    let one = Geo::open(file.clone()).unwrap();
    assert_eq!(one, one.clone());
    assert_ne!(one, Geo::open(file).unwrap());
}
