use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustls::pki_types::ServerName;

use super::*;
use crate::forward::tls::tests::Pki;
use crate::route::Table;

const LISTEN: &str = "127.0.0.1:8080";

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn terms(address: Address) -> ServerConfig<Address> {
    ServerConfig {
        address,
        weight: 3,
        max_fails: 2,
        fail_timeout: Duration::from_secs(7),
        backup: true,
    }
}

fn name(name: &str, port: u16) -> Address {
    Address::Name {
        name: name.to_string(),
        port,
    }
}

fn settings(groups: &[(&str, Vec<Address>)], wait_ms: u64) -> ForwardSettings {
    ForwardSettings {
        resolve_timeout: Duration::from_millis(wait_ms),
        groups: groups
            .iter()
            .map(|(group, servers)| GroupConfig {
                name: group.to_string(),
                servers: servers.iter().cloned().map(terms).collect(),
                tls: None,
            })
            .collect(),
        routes: Table::default(),
        default: Some(0),
    }
}

/// A lookup that gives these addresses (IP texts) for a name, at the port asked for, and fails for any other.
fn table(
    entries: &[(&str, &[&str])],
    calls: Arc<AtomicUsize>,
) -> impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static {
    let entries: Vec<(String, Vec<String>)> = entries
        .iter()
        .map(|(n, ips)| (n.to_string(), ips.iter().map(|ip| ip.to_string()).collect()))
        .collect();
    move |asked, port| {
        calls.fetch_add(1, Ordering::SeqCst);
        entries
            .iter()
            .find(|(n, _)| n == asked)
            .map(|(_, ips)| {
                ips.iter()
                    .map(|ip| SocketAddr::new(ip.parse().unwrap(), port))
                    .collect()
            })
            .ok_or_else(|| io::Error::other("unknown name"))
    }
}

fn refused(
    settings: ForwardSettings,
    lookup: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
) -> Refusal {
    complete(settings, &[addr(LISTEN)], lookup).expect_err("the start is refused")
}

fn calls() -> Arc<AtomicUsize> {
    Arc::new(AtomicUsize::new(0))
}

#[test]
fn every_address_of_a_name_is_a_server_in_its_place_with_the_terms_of_the_server_written() {
    let count = calls();
    let lookup = table(
        &[(
            "app.test",
            &["192.0.2.10", "192.0.2.11", "192.0.2.10", "2001:db8::1"],
        )],
        count.clone(),
    );
    let literal = |text: &str| Address::Literal(addr(text));
    let done = complete(
        settings(
            &[
                (
                    "main",
                    vec![
                        literal("192.0.2.1:80"),
                        name("app.test", 80),
                        literal("192.0.2.10:80"),
                    ],
                ),
                ("api", vec![name("app.test", 80), name("app.test", 81)]),
            ],
            5_000,
        ),
        &[addr(LISTEN)],
        lookup,
    )
    .unwrap();
    let servers = |group: usize| -> Vec<SocketAddr> {
        done.forward.groups[group]
            .servers
            .iter()
            .map(|s| s.address)
            .collect()
    };
    // The addresses of the name are in the place of the name, each once, and a server that is written with one
    // of them is a server of its own.
    assert_eq!(
        servers(0),
        [
            addr("192.0.2.1:80"),
            addr("192.0.2.10:80"),
            addr("192.0.2.11:80"),
            addr("[2001:db8::1]:80"),
            addr("192.0.2.10:80"),
        ]
    );
    assert_eq!(servers(1).len(), 3 + 3);
    for group in &done.forward.groups {
        assert!(
            group
                .servers
                .iter()
                .all(|s| (s.weight, s.max_fails, s.fail_timeout, s.backup)
                    == (3, 2, Duration::from_secs(7), true))
        );
    }
    // A name with a port is looked up once, wherever it is written.
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(
        done.lines,
        [
            "start: upstream main app.test:80 resolved to 192.0.2.10:80, 192.0.2.11:80, [2001:db8::1]:80",
            "start: upstream api app.test:80 resolved to 192.0.2.10:80, 192.0.2.11:80, [2001:db8::1]:80",
            "start: upstream api app.test:81 resolved to 192.0.2.10:81, 192.0.2.11:81, [2001:db8::1]:81",
        ]
    );
    assert_eq!(done.forward.default, Some(0));
}

#[test]
fn an_ip_literal_is_not_looked_up() {
    let count = calls();
    let done = complete(
        settings(
            &[("main", vec![Address::Literal(addr("192.0.2.1:80"))])],
            5_000,
        ),
        &[addr(LISTEN)],
        table(&[], count.clone()),
    )
    .unwrap();
    assert_eq!(done.forward.groups[0].servers.len(), 1);
    assert!(done.lines.is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn a_name_that_cannot_be_used_refuses_the_start_and_says_which_server_it_is() {
    // The second server of the group `g` is the name; the first is an IP literal.
    let group = || {
        let servers = vec![
            Address::Literal(addr("192.0.2.1:80")),
            name("app.test", 8080),
        ];
        settings(&[("g", servers)], 5_000)
    };
    let start =
        |ips: &'static [&'static str]| refused(group(), table(&[("app.test", ips)], calls()));
    let place = |why: &'static str| Refusal {
        why,
        group: "g".to_string(),
        position: Some(2),
    };
    assert_eq!(
        refused(group(), table(&[], calls())),
        place("a server name cannot be looked up")
    );
    assert_eq!(start(&[]), place("a server name has no address"));
    let unusable = "a server name has an address that is unspecified or a multicast address";
    for ips in [
        &["192.0.2.5", "0.0.0.0"][..],
        &["::"],
        &["::ffff:0.0.0.0"],
        &["224.0.0.1"],
        &["ff02::1"],
        &["192.0.2.5", "::ffff:224.0.0.1"],
    ] {
        assert_eq!(start(ips), place(unusable), "{ips:?}");
    }
    // The address of listen, as an IPv4 address or mapped; the same address at another port is another one.
    let own = place("a server name has the address of a listener");
    assert_eq!(start(&["192.0.2.5", "127.0.0.1"]), own);
    assert_eq!(start(&["::ffff:127.0.0.1"]), own);
    let other_port = settings(&[("g", vec![name("app.test", 8081)])], 5_000);
    let lookup = table(&[("app.test", &["127.0.0.1"])], calls());
    assert!(complete(other_port, &[addr(LISTEN)], lookup).is_ok());
}

#[test]
fn a_group_may_have_64_servers_once_the_names_are_looked_up_and_not_65() {
    let ips = |n: usize| -> Vec<String> { (1..=n).map(|i| format!("192.0.2.{i}")).collect() };
    let lookup = |n: usize| {
        let all = ips(n);
        move |_: &str, port: u16| -> io::Result<Vec<SocketAddr>> {
            Ok(all
                .iter()
                .map(|ip| SocketAddr::new(ip.parse().unwrap(), port))
                .collect())
        }
    };
    let group = |servers: Vec<Address>| settings(&[("g", servers)], 5_000);
    let done = complete(
        group(vec![name("app.test", 80)]),
        &[addr(LISTEN)],
        lookup(64),
    )
    .unwrap();
    assert_eq!(done.forward.groups[0].servers.len(), 64);
    let too_many = "an upstream has more than 64 servers once the names are looked up";
    let r = refused(group(vec![name("app.test", 80)]), lookup(65));
    assert_eq!((r.why, r.position), (too_many, Some(1)));
    // One server is written before the name, so the name may bring 63.
    let literal = Address::Literal(addr("198.51.100.1:80"));
    let done = complete(
        group(vec![literal.clone(), name("app.test", 80)]),
        &[addr(LISTEN)],
        lookup(63),
    )
    .unwrap();
    assert_eq!(done.forward.groups[0].servers.len(), 64);
    let r = refused(group(vec![literal, name("app.test", 80)]), lookup(64));
    assert_eq!((r.why, r.position), (too_many, Some(2)));
}

#[test]
fn names_not_looked_up_by_the_deadline_refuse_the_start_at_the_first_name_that_is_missing() {
    let slow = |asked: &str, port: u16| -> io::Result<Vec<SocketAddr>> {
        if asked == "slow.test" {
            thread::sleep(Duration::from_secs(3));
        }
        Ok(vec![SocketAddr::new(addr("192.0.2.9:1").ip(), port)])
    };
    let begun = Instant::now();
    let r = refused(
        settings(
            &[(
                "g",
                vec![
                    name("fast.test", 80),
                    name("slow.test", 80),
                    name("later.test", 80),
                ],
            )],
            100,
        ),
        slow,
    );
    assert_eq!(
        (r.why, r.group.as_str(), r.position),
        (
            "the names were not looked up within resolve_timeout_ms",
            "g",
            Some(2)
        )
    );
    // The caller did not wait for the lookup that is still going on.
    assert!(begun.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_lookup_that_panics_refuses_the_start() {
    let r = refused(
        settings(&[("g", vec![name("app.test", 80)])], 5_000),
        |_: &str, _: u16| -> io::Result<Vec<SocketAddr>> { panic!("the lookup fails") },
    );
    assert_eq!(r.why, "the lookup of the names stopped");
}

#[test]
fn a_loopback_address_at_the_port_of_an_unspecified_listen_is_the_proxy_itself() {
    let group = |port: u16| settings(&[("g", vec![name("app.test", port)])], 5_000);
    let start = |listen: &str, port: u16, ips: &'static [&'static str]| {
        complete(
            group(port),
            &[addr(listen)],
            table(&[("app.test", ips)], calls()),
        )
        .err()
        .map(|r| r.why)
    };
    let own = Some("a server name has the address of a listener");
    for listen in ["0.0.0.0:8080", "[::]:8080"] {
        for ips in [
            &["127.0.0.1"][..],
            &["192.0.2.5", "127.0.0.2"],
            &["::1"],
            &["::ffff:127.0.0.1"],
        ] {
            assert_eq!(start(listen, 8080, ips), own, "{listen} {ips:?}");
        }
        // Another address at the port, and a loopback address at another port, are other servers.
        assert_eq!(start(listen, 8080, &["192.0.2.5"]), None, "{listen}");
        assert_eq!(start(listen, 8081, &["127.0.0.1"]), None, "{listen}");
    }
    // A listen address that is not unspecified is itself only.
    assert_eq!(start("192.0.2.1:8080", 8080, &["127.0.0.1"]), None);
    // Every listener counts, not the first one only.
    let two = [addr("127.0.0.1:8081"), addr("192.0.2.1:8080")];
    let lookup = table(&[("app.test", &["192.0.2.1"])], calls());
    assert_eq!(
        complete(group(8080), &two, lookup).err().map(|r| r.why),
        own
    );
}

/// The groups of `settings` named in `with` have these `tls`.
fn with_tls(mut settings: ForwardSettings, with: &[(usize, Settings)]) -> ForwardSettings {
    for (group, tls) in with {
        settings.groups[*group].tls = Some(tls.clone());
    }
    settings
}

#[test]
fn a_group_with_tls_gets_one_name_for_each_server_and_each_address_of_a_name() {
    let pki = Pki::new();
    let by = |server_name: Option<&str>| Settings {
        ca_file: pki.ca(),
        server_name: server_name.map(str::to_string),
    };
    let groups = |server_name: Option<&str>| {
        with_tls(
            settings(
                &[
                    (
                        "main",
                        vec![
                            Address::Literal(addr("192.0.2.1:443")),
                            name("app.test", 443),
                            Address::Literal(addr("[2001:db8::1]:443")),
                        ],
                    ),
                    ("plain", vec![name("app.test", 80)]),
                ],
                5_000,
            ),
            &[(0, by(server_name))],
        )
    };
    let lookup = || table(&[("app.test", &["192.0.2.10", "192.0.2.11"])], calls());
    let done = complete(groups(None), &[addr(LISTEN)], lookup()).unwrap();
    // A group without `tls` has none; the group with it has a name for each server, the name of the server for
    // each address that it comes to.
    assert!(done.forward.groups[1].tls.is_none());
    let ip = |text: &str| ServerName::IpAddress(text.parse::<std::net::IpAddr>().unwrap().into());
    let app = tls::dns_name("app.test").unwrap();
    let main = &done.forward.groups[0];
    assert_eq!(main.servers.len(), 4);
    assert_eq!(
        main.tls.as_ref().unwrap().names(),
        [ip("192.0.2.1"), app.clone(), app, ip("2001:db8::1")]
    );
    // With a `server_name` it is the name of every server.
    let done = complete(groups(Some("api.test")), &[addr(LISTEN)], lookup()).unwrap();
    let api = tls::dns_name("api.test").unwrap();
    assert_eq!(
        done.forward.groups[0].tls.as_ref().unwrap().names(),
        [api.clone(), api.clone(), api.clone(), api]
    );
}

#[test]
fn a_file_of_authorities_or_a_name_that_cannot_be_used_refuses_the_start() {
    let pki = Pki::new();
    let by = |ca_file: PathBuf, server_name: Option<&str>| Settings {
        ca_file,
        server_name: server_name.map(str::to_string),
    };
    // The second group is the one with `tls`; the first is plain and has a server before it.
    let start = |tls: Settings, servers: Vec<Address>| {
        let groups = settings(
            &[
                ("first", vec![Address::Literal(addr("192.0.2.1:80"))]),
                ("second", servers),
            ],
            5_000,
        );
        let lookup = table(&[("a-.test", &["192.0.2.9"])], calls());
        refused(with_tls(groups, &[(1, tls)]), lookup)
    };
    let literal = || vec![Address::Literal(addr("192.0.2.2:443"))];
    let group_only = |fault: Fault| Refusal {
        why: fault.text(),
        group: "second".to_string(),
        position: None,
    };
    // The file is missing, holds no certificate, or is no more than a certificate that cannot be used.
    let missing = by(PathBuf::from("/nonexistent/ca.pem"), None);
    assert_eq!(start(missing, literal()), group_only(Fault::Unreadable));
    let empty = by(pki.file("empty.pem", b""), None);
    assert_eq!(start(empty, literal()), group_only(Fault::NotCertificates));
    let junk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let junk = by(pki.file("junk.pem", junk.as_bytes()), None);
    assert_eq!(start(junk, literal()), group_only(Fault::NotAnchor));
    // The sentence tells the group and no server.
    assert_eq!(
        group_only(Fault::Unreadable).to_string(),
        "an upstream ca_file cannot be read (upstream second)"
    );
    // A name that TLS cannot use, as a `server_name` or as the name of a server, says which server it is.
    let place = |position| Refusal {
        why: Fault::Name.text(),
        group: "second".to_string(),
        position: Some(position),
    };
    let servers = vec![
        Address::Literal(addr("192.0.2.2:443")),
        name("a-.test", 443),
    ];
    assert_eq!(start(by(pki.ca(), None), servers.clone()), place(2));
    assert_eq!(start(by(pki.ca(), Some("a-.test")), servers), place(1));
}
