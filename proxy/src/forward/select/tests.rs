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

fn picks(turn: &Turn, n: usize, may: impl Fn(usize) -> bool) -> Vec<usize> {
    (0..n).map(|_| turn.pick(&may).unwrap()).collect()
}

#[test]
fn the_servers_are_chosen_in_proportion_to_their_weights_and_the_heavy_one_does_not_go_first_every_time()
 {
    let turn = Turn::new(&servers(&[(5, false), (1, false), (1, false)]));
    // Seven choices give the weights exactly, in the order that spreads the heavy server out.
    assert_eq!(picks(&turn, 7, |_| true), [0, 0, 1, 0, 2, 0, 0]);
    // The state is back where it started after a whole round, so any number of rounds keeps the ratio.
    let all = picks(&turn, 70, |_| true);
    let count = |server: usize| all.iter().filter(|&&s| s == server).count();
    assert_eq!([count(0), count(1), count(2)], [50, 10, 10]);
}

#[test]
fn a_server_that_may_not_be_chosen_is_left_out_and_a_backup_serves_only_when_no_other_can() {
    let turn = Turn::new(&servers(&[(1, false), (1, false), (3, true)]));
    // Both primaries: the backup is never chosen, however heavy.
    let all = picks(&turn, 10, |_| true);
    assert!(all.iter().all(|&s| s < 2));
    assert_eq!(all.iter().filter(|&&s| s == 0).count(), 5);
    // One primary left out: the other one gets every request.
    assert!(picks(&turn, 5, |i| i != 0).iter().all(|&s| s == 1));
    // No primary: the backup.
    assert!(picks(&turn, 3, |i| i == 2).iter().all(|&s| s == 2));
    // Nothing may be chosen.
    assert_eq!(turn.pick(|_| false), None);
}
