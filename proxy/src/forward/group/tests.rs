use std::time::Duration;

use tukuyomi_kernel::Engine;

use super::*;
use crate::forward::origin::tests::config;

const FAIL_TIMEOUT: Duration = Duration::from_secs(10);

fn server(i: usize, max_fails: u32, backup: bool) -> ServerConfig {
    ServerConfig {
        address: format!("127.0.0.1:{}", 9000 + i).parse().unwrap(),
        weight: 1,
        max_fails,
        fail_timeout: FAIL_TIMEOUT,
        backup,
    }
}

/// A group of these servers, and the instant `ms` milliseconds after its start.
fn build(servers: Vec<ServerConfig>) -> (Upstreams, impl Fn(u64) -> Instant) {
    let mut forward = ForwardConfig::of(&[]);
    forward.groups[0].servers = servers;
    let upstreams = Upstreams::new(&forward, &config());
    let start = Instant::now();
    (upstreams, move |ms| start + Duration::from_millis(ms))
}

/// The servers that `pick` gives over `n` choices, none tried.
fn chosen(group: &Group, now: Instant, n: usize) -> Vec<usize> {
    (0..n)
        .filter_map(|_| group.pick(Tried::default(), now))
        .collect()
}

#[test]
fn a_server_with_max_fails_failures_in_the_window_is_left_out_for_the_fail_timeout_and_then_comes_back()
 {
    let (upstreams, at) = build(vec![server(0, 2, false), server(1, 2, false)]);
    let group = upstreams.group(0);
    group.fail(0, at(0));
    assert!(chosen(group, at(1), 4).contains(&0), "one failure of two");
    group.fail(0, at(1000));
    // Left out until 1000 ms plus the fail timeout.
    assert_eq!(chosen(group, at(1001), 4), [1, 1, 1, 1]);
    assert_eq!(chosen(group, at(10_999), 4), [1, 1, 1, 1]);
    assert!(chosen(group, at(11_000), 4).contains(&0));
    // After it came back it needs max_fails new failures.
    group.fail(0, at(11_000));
    assert!(chosen(group, at(11_001), 4).contains(&0));
    group.fail(0, at(11_002));
    assert_eq!(chosen(group, at(11_003), 4), [1, 1, 1, 1]);
}

#[test]
fn failures_that_are_further_apart_than_the_fail_timeout_do_not_add_up() {
    let (upstreams, at) = build(vec![server(0, 2, false), server(1, 2, false)]);
    let group = upstreams.group(0);
    group.fail(0, at(0));
    group.fail(0, at(10_000));
    group.fail(0, at(20_000));
    assert!(chosen(group, at(20_001), 4).contains(&0));
}

#[test]
fn a_server_is_not_left_out_if_it_is_the_only_one_or_does_not_count_failures() {
    let (upstreams, at) = build(vec![server(0, 1, false)]);
    let group = upstreams.group(0);
    for ms in 0..5 {
        group.fail(0, at(ms));
    }
    assert_eq!(chosen(group, at(10), 3), [0, 0, 0]);

    let (upstreams, at) = build(vec![server(0, 0, false), server(1, 1, false)]);
    let group = upstreams.group(0);
    for ms in 0..5 {
        group.fail(0, at(ms));
    }
    assert!(chosen(group, at(10), 4).contains(&0));
    // The failures are counted for the group also when the server does not count them to leave itself out.
    assert_eq!(group.failures(), 5);
    assert_eq!(
        upstreams.failures().map(|(_, n)| n).collect::<Vec<_>>(),
        [5]
    );
}

#[test]
fn a_server_that_was_tried_is_not_given_again_and_a_backup_serves_when_the_others_are_out() {
    let (upstreams, at) = build(vec![
        server(0, 1, false),
        server(1, 1, false),
        server(2, 1, true),
    ]);
    let group = upstreams.group(0);
    let mut tried = Tried::default();
    let mut order = Vec::new();
    while let Some(i) = group.pick(tried, at(1)) {
        tried.add(i);
        order.push(i);
    }
    // Every server once, the backup last; then none.
    assert_eq!(order.len(), 3);
    assert_eq!(order[2], 2);
    // Both primaries out: the backup serves; all out: none.
    group.fail(0, at(2));
    group.fail(1, at(2));
    assert_eq!(chosen(group, at(3), 3), [2, 2, 2]);
    group.fail(2, at(3));
    assert_eq!(group.pick(Tried::default(), at(4)), None);
    assert!(group.pick(Tried::default(), at(10_004)).is_some());
}

use http::{HeaderMap, Uri};

use crate::config::RouteConfig;
use crate::forward::rewrite::{Headers, Query, Rewrite};
use crate::route::{Rule, Table};

#[test]
fn a_target_read_in_more_than_one_way_takes_no_route_with_a_path_and_so_no_edit() {
    let mut forward = ForwardConfig::of(&["127.0.0.1:9000".parse().unwrap()]);
    let rewrite = Rewrite::new(
        Some("/api/"),
        None,
        Some("/v2/"),
        Query::default(),
        Headers::default(),
        Headers::default(),
    )
    .unwrap();
    let route = RouteConfig {
        rewrite,
        ..RouteConfig::plain(0)
    };
    let rule = Rule::forward(None, Some("/api/")).unwrap();
    forward.routes = Table::new(vec![(rule, route)]).unwrap();
    let upstreams = Upstreams::new(&forward, &config());
    // The default route holds for what the route with the path does not, and it edits nothing.
    let sent = |target: &str| {
        let route = upstreams.find(None, target.as_bytes()).unwrap();
        let (_, uri) = route
            .rewrite
            .request(HeaderMap::new(), target.parse::<Uri>().unwrap())
            .unwrap();
        uri.to_string()
    };
    assert_eq!(sent("/api/x?a=1"), "/v2/x?a=1");
    for target in ["/api/../x", "/api//x", "/api/%2e/x", "/api/a;b", "/api/%2F"] {
        assert_eq!(sent(target), target);
    }
}

#[test]
fn the_upstreams_are_guarded_only_when_some_route_has_an_access_list() {
    use crate::forward::client_ip::{Access, Cidr};
    let guarded = |lists: &[(&[&str], &[&str])]| {
        let mut forward = ForwardConfig::of(&["127.0.0.1:9000".parse().unwrap()]);
        let nets = |list: &[&str]| list.iter().map(|net| Cidr::parse(net).unwrap()).collect();
        let entries = lists
            .iter()
            .enumerate()
            .map(|(i, &(deny, allow))| {
                let route = RouteConfig {
                    access: Access::new(nets(deny), nets(allow)),
                    ..RouteConfig::plain(0)
                };
                (
                    Rule::forward(None, Some(&format!("/r{i}/"))).unwrap(),
                    route,
                )
            })
            .collect();
        forward.routes = Table::new(entries).unwrap();
        Upstreams::new(&forward, &config()).guarded()
    };
    assert!(!guarded(&[]));
    assert!(!guarded(&[(&[], &[]), (&[], &[])]));
    assert!(guarded(&[(&[], &[]), (&["10.0.0.0/8"], &[])]));
    assert!(guarded(&[(&[], &["10.0.0.0/8"])]));
}

#[test]
fn the_way_to_the_admin_process_is_taken_by_the_name_of_its_host_alone() {
    let mut forward = ForwardConfig::of(&["127.0.0.1:9000".parse().unwrap()]);
    forward.admin = Some(AdminWay {
        host: "admin.example".to_owned(),
        access: Access::default(),
        server: "127.0.0.1:9180".parse().unwrap(),
        engine: Engine::Coraza,
    });
    let upstreams = Upstreams::new(&forward, &config());
    let way = |host: &[u8]| {
        upstreams
            .admin(Some(host))
            .map(|(route, _)| route.group.servers[0].address())
    };
    let admin = Some("127.0.0.1:9180".parse().unwrap());
    for host in [
        &b"admin.example"[..],
        b"ADMIN.Example",
        b"admin.example:8443",
        b"admin.example.",
    ] {
        assert_eq!(way(host), admin, "{host:?}");
    }
    for host in [
        &b"xadmin.example"[..],
        b"admin.example.evil",
        b"a.admin.example",
        b"admin.example:0",
        b"[::1",
    ] {
        assert_eq!(way(host), None, "{host:?}");
    }
    assert!(upstreams.admin(None).is_none());
    // A configuration without the way has none.
    let plain = Upstreams::new(&ForwardConfig::of(&[]), &config());
    assert!(plain.admin(Some(b"admin.example")).is_none());
}

/// The group `main` of these servers, made from the groups `earlier` when the configuration is read again.
fn reread(earlier: &Upstreams, servers: Vec<ServerConfig>) -> Upstreams {
    let mut forward = ForwardConfig::of(&[]);
    forward.groups[0].servers = servers;
    Upstreams::following(&forward, &config(), earlier)
}

#[test]
fn a_server_that_is_left_out_stays_left_out_when_the_configuration_is_read_again() {
    let servers = || vec![server(0, 1, false), server(1, 1, false)];
    let (earlier, at) = build(servers());
    earlier.group(0).fail(0, at(1000));
    let later = reread(&earlier, servers());
    let group = later.group(0);
    // Left out until 1000 ms plus the fail timeout, as it was.
    assert_eq!(chosen(group, at(1001), 4), [1, 1, 1, 1]);
    assert_eq!(chosen(group, at(10_999), 4), [1, 1, 1, 1]);
    assert!(chosen(group, at(11_000), 4).contains(&0));
    assert_eq!(later.anew(&earlier).count(), 0);

    // The failures of the only server of a group are counted too: with a second server added, it is left out.
    let (earlier, at) = build(vec![server(0, 1, false)]);
    earlier.group(0).fail(0, at(1000));
    let later = reread(&earlier, servers());
    assert_eq!(chosen(later.group(0), at(1001), 4), [1, 1, 1, 1]);
}

#[test]
fn a_failure_counted_for_the_group_it_replaces_counts_for_the_new_group_and_the_other_way_round() {
    let servers = || vec![server(0, 2, false), server(1, 2, false)];
    let (earlier, at) = build(servers());
    let later = reread(&earlier, servers());
    // One failure for each group makes the 2 that leave the server out, for both.
    earlier.group(0).fail(0, at(0));
    assert!(chosen(later.group(0), at(1), 4).contains(&0));
    later.group(0).fail(0, at(1));
    assert_eq!(chosen(earlier.group(0), at(2), 4), [1, 1, 1, 1]);
    assert_eq!(chosen(later.group(0), at(2), 4), [1, 1, 1, 1]);
    // The failures of a group are its own, and start from 0 with the new group.
    assert_eq!(earlier.group(0).failures(), 1);
    assert_eq!(later.group(0).failures(), 1);
}

#[test]
fn a_server_counts_from_nothing_when_its_limits_change_or_it_is_in_a_group_with_another_name() {
    let (earlier, at) = build(vec![server(0, 1, false), server(1, 1, false)]);
    earlier.group(0).fail(0, at(0));
    let more_fails = |server: &mut ServerConfig| server.max_fails = 2;
    let longer_timeout = |server: &mut ServerConfig| server.fail_timeout = Duration::from_secs(11);
    let edits: [&dyn Fn(&mut ServerConfig); 2] = [&more_fails, &longer_timeout];
    for edit in edits {
        // A third server is added; it has nothing before it, so it is not counted among those that start anew.
        let mut servers = vec![
            server(0, 1, false),
            server(1, 1, false),
            server(2, 1, false),
        ];
        edit(&mut servers[0]);
        let later = reread(&earlier, servers);
        assert!(chosen(later.group(0), at(1), 6).contains(&0));
        assert_eq!(later.anew(&earlier).collect::<Vec<_>>(), [("main", 1)]);
    }

    let mut renamed = ForwardConfig::of(&[]);
    renamed.groups[0].name = "other".to_owned();
    renamed.groups[0].servers = vec![server(0, 1, false), server(1, 1, false)];
    let later = Upstreams::following(&renamed, &config(), &earlier);
    assert!(chosen(later.group(0), at(1), 4).contains(&0));
    assert_eq!(later.anew(&earlier).count(), 0);
}

#[test]
fn a_server_counts_from_nothing_when_it_is_spoken_to_in_another_way() {
    use std::fs;
    use std::path::PathBuf;

    use crate::config::Address;
    use crate::forward::tls::tests::Pki;
    use crate::forward::tls::{self, Authorities, Client, Settings};

    let pki = Pki::new();
    let bytes = fs::read(pki.ca()).unwrap();
    let copy = pki.file("copy.pem", &bytes);
    // The same authorities in other bytes: a line feed more.
    let longer = pki.file("longer.pem", &[bytes.as_slice(), b"\n"].concat());
    let by = |path: PathBuf, name: &str| Settings {
        authorities: Authorities::File(path),
        server_name: Some(name.to_owned()),
    };
    // The group of two servers, spoken to as `settings` say (plainly for `None`), made from `earlier` if there is one.
    let group = |settings: Option<Settings>, earlier: Option<&Upstreams>| {
        let mut forward = ForwardConfig::of(&[]);
        forward.groups[0].servers = vec![server(0, 1, false), server(1, 1, false)];
        if let Some(settings) = &settings {
            let names = forward.groups[0]
                .servers
                .iter()
                .map(|server| tls::name_of(settings, &Address::Literal(server.address)).unwrap())
                .collect();
            forward.groups[0].tls = Some(Client::new(tls::config(settings).unwrap(), names));
        }
        match earlier {
            Some(earlier) => Upstreams::following(&forward, &config(), earlier),
            None => Upstreams::new(&forward, &config()),
        }
    };

    let earlier = group(Some(by(pki.ca(), "app.test")), None);
    earlier.group(0).fail(0, Instant::now());
    assert!(earlier.group(0).left_out(0));
    for (what, settings, same) in [
        ("the same file", Some(by(pki.ca(), "app.test")), true),
        ("a copy of the file", Some(by(copy, "app.test")), true),
        ("another name", Some(by(pki.ca(), "other.test")), false),
        ("other bytes", Some(by(longer, "app.test")), false),
        ("no TLS", None, false),
    ] {
        let later = group(settings, Some(&earlier));
        assert_eq!(later.group(0).left_out(0), same, "{what}");
        assert_eq!(later.anew(&earlier).count(), usize::from(!same), "{what}");
    }

    // A server that was plain is spoken to over TLS: it counts from nothing too.
    let plain = group(None, None);
    plain.group(0).fail(0, Instant::now());
    assert!(plain.group(0).left_out(0));
    let later = group(Some(by(pki.ca(), "app.test")), Some(&plain));
    assert!(!later.group(0).left_out(0));
}

#[test]
fn a_server_is_the_same_by_its_address_and_its_place_among_those_at_that_address_not_by_its_index()
{
    // The first address is written twice, and it is the second of the two that fails.
    let (earlier, at) = build(vec![
        server(0, 1, false),
        server(1, 1, false),
        server(0, 1, false),
    ]);
    earlier.group(0).fail(2, at(0));
    // Read again with another order, and the first of the two as an IPv4 address written as IPv6.
    let mut servers = vec![
        server(0, 1, false),
        server(0, 1, false),
        server(1, 1, false),
    ];
    servers[0].address = "[::ffff:127.0.0.1]:9000".parse().unwrap();
    let later = reread(&earlier, servers);
    let picked = chosen(later.group(0), at(1), 6);
    assert!(picked.contains(&0) && picked.contains(&2), "{picked:?}");
    assert!(!picked.contains(&1), "{picked:?}");
    assert_eq!(later.anew(&earlier).count(), 0);
}
