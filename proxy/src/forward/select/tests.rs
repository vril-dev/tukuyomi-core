use std::time::Duration;

use super::*;

fn servers(weights: &[(u32, bool)]) -> Vec<ServerConfig> {
    weights
        .iter()
        .enumerate()
        .map(|(i, &(weight, backup))| ServerConfig {
            address: format!("127.0.0.1:{}", 9000 + i).parse().unwrap(),
            weight,
            max_fails: 1,
            fail_timeout: Duration::from_secs(10),
            backup,
        })
        .collect()
}

fn picks(
    turn: &Turn,
    config: &[ServerConfig],
    n: usize,
    may: impl Fn(usize) -> bool,
) -> Vec<usize> {
    (0..n)
        .map(|_| turn.pick(&may, weight(config)).unwrap())
        .collect()
}

/// The weight of each of these servers, as the configuration gives it.
fn weight(config: &[ServerConfig]) -> impl Fn(usize) -> i64 + '_ {
    |i| i64::from(config[i].weight)
}

#[test]
fn the_servers_are_chosen_in_proportion_to_their_weights_and_the_heavy_one_does_not_go_first_every_time()
 {
    let config = servers(&[(5, false), (1, false), (1, false)]);
    let turn = Turn::new(&config);
    // Seven choices give the weights exactly, in the order that spreads the heavy server out.
    assert_eq!(picks(&turn, &config, 7, |_| true), [0, 0, 1, 0, 2, 0, 0]);
    // The state is back where it started after a whole round, so any number of rounds keeps the ratio.
    let all = picks(&turn, &config, 70, |_| true);
    let count = |server: usize| all.iter().filter(|&&s| s == server).count();
    assert_eq!([count(0), count(1), count(2)], [50, 10, 10]);
}

#[test]
fn a_server_that_may_not_be_chosen_is_left_out_and_a_backup_serves_only_when_no_other_can() {
    let config = servers(&[(1, false), (1, false), (3, true)]);
    let turn = Turn::new(&config);
    // Both primaries: the backup is never chosen, however heavy.
    let all = picks(&turn, &config, 10, |_| true);
    assert!(all.iter().all(|&s| s < 2));
    assert_eq!(all.iter().filter(|&&s| s == 0).count(), 5);
    // One primary left out: the other one gets every request.
    assert!(picks(&turn, &config, 5, |i| i != 0).iter().all(|&s| s == 1));
    // No primary: the backup.
    assert!(picks(&turn, &config, 3, |i| i == 2).iter().all(|&s| s == 2));
    // Nothing may be chosen.
    assert_eq!(turn.pick(|_| false, weight(&config)), None);
}

/// The server that `least::pick` gives when the servers have `in_use` requests, among those that `may` accepts.
fn fewest(
    turn: &Turn,
    config: &[ServerConfig],
    in_use: &[u64],
    may: impl Fn(usize) -> bool,
) -> Option<usize> {
    least::pick(turn, may, weight(config), |i| in_use[i])
}

#[test]
fn the_server_with_the_fewest_requests_for_its_weight_is_chosen() {
    let config = servers(&[(1, false), (1, false), (2, false)]);
    let turn = Turn::new(&config);
    assert_eq!(fewest(&turn, &config, &[3, 1, 5], |_| true), Some(1));
    // 4 requests for a weight of 2 are fewer than 3 for a weight of 1, and than 9.
    assert_eq!(fewest(&turn, &config, &[3, 9, 4], |_| true), Some(2));
    // A server that may not be chosen is not looked at, however few requests it has.
    assert_eq!(fewest(&turn, &config, &[3, 0, 4], |i| i != 1), Some(2));
    assert_eq!(fewest(&turn, &config, &[0, 0, 0], |_| false), None);
    // The numbers are products, which do not overflow.
    let most = u64::MAX;
    assert_eq!(
        fewest(&turn, &config, &[most, most, most - 1], |_| true),
        Some(2)
    );
}

#[test]
fn servers_with_as_few_requests_take_turns_by_weight_and_do_not_leave_one_server_all_of_them() {
    let config = servers(&[(1, false), (1, false), (2, false)]);
    let turn = Turn::new(&config);
    // Nobody has a request: the weighted round robin.
    let idle: Vec<usize> = (0..8)
        .map(|_| fewest(&turn, &config, &[0, 0, 0], |_| true).unwrap())
        .collect();
    let count = |all: &[usize], server: usize| all.iter().filter(|&&s| s == server).count();
    assert_eq!(
        [count(&idle, 0), count(&idle, 1), count(&idle, 2)],
        [2, 2, 4]
    );
    // Two of the three are as few (1 request for a weight of 1): they take turns. The third has 3 for a weight of 2.
    let two: Vec<usize> = (0..6)
        .map(|_| fewest(&turn, &config, &[1, 1, 3], |_| true).unwrap())
        .collect();
    assert_eq!([count(&two, 0), count(&two, 1), count(&two, 2)], [3, 3, 0]);
}

#[test]
fn a_backup_server_is_chosen_by_the_fewest_requests_only_when_no_other_server_can_be() {
    let config = servers(&[(1, false), (1, true)]);
    let turn = Turn::new(&config);
    assert_eq!(fewest(&turn, &config, &[100, 0], |_| true), Some(0));
    assert_eq!(fewest(&turn, &config, &[100, 0], |i| i == 1), Some(1));
}
