use std::collections::VecDeque;
use std::sync::mpsc::sync_channel;

use tokio::sync::oneshot;
use tukuyomi_kernel::Engine;

use super::*;
use crate::log::recording;
use crate::rules::switch::tests::{made_in, scratch, switcher};
use crate::run::signals::tests::{fixture, runtime};

#[test]
fn sigusr1_while_a_switch_is_under_way_is_a_line_and_changes_nothing() {
    runtime().block_on(async {
        let root = scratch();
        let (_, made) = made_in(&root.0, &["a"]);
        let mut switcher = switcher(&root.0, made[0]);
        let mut f = fixture();
        let (_reply, told) = oneshot::channel();
        f.waits.switch = Some((Engine::Coraza, told));
        // The engines that an earlier SIGUSR1 has still to switch.
        f.waits.queue = VecDeque::from([Engine::ModSecurity]);
        let (ingress, taken) = sync_channel(1);
        let (log, lines) = recording();
        let counters = Counters::start();

        reload(&mut f.waits, &mut switcher, &ingress, &counters, &log);

        assert_eq!(
            lines.texts(),
            [
                "reload: SIGUSR1",
                "reload: a switch is in progress, ignored"
            ]
        );
        assert_eq!(f.waits.queue, VecDeque::from([Engine::ModSecurity]));
        assert!(f.waits.switch.is_some());
        assert!(taken.try_recv().is_err());
        assert_eq!(counters.switches.total(), 0);
    });
}
