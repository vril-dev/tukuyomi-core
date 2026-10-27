use std::time::Duration;

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
