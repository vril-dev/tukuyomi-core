use super::*;
use std::collections::VecDeque;
use std::thread;

/// A request as the kernel got it.
struct Sent {
    method: Vec<u8>,
    uri: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

impl Sent {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(got, _)| got.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, value)| value.as_slice())
    }
}

/// A kernel that answers as it is told and records what it is asked.
struct Fake {
    /// The phase now; each `poll` moves on to the next one of `script`, and the last one stays.
    phase: Phase,
    script: VecDeque<Phase>,
    /// The verdicts of the requests in the order they come; a request past the end is never answered.
    verdicts: VecDeque<Verdict>,
    refuse: Option<Refused>,
    answers: Vec<(ReqId, Verdict)>,
    sent: Vec<Sent>,
    cancelled: Vec<ReqId>,
    shutdowns: u32,
    detail: Option<Vec<u8>>,
    dir_removed: bool,
    /// The phase the kernel is in after `shutdown`.
    stop_phase: Phase,
}

impl Fake {
    fn new(script: &[Phase], verdicts: &[Verdict]) -> Fake {
        Fake {
            phase: Phase::Starting,
            script: script.iter().copied().collect(),
            verdicts: verdicts.iter().copied().collect(),
            refuse: None,
            answers: Vec::new(),
            sent: Vec::new(),
            cancelled: Vec::new(),
            shutdowns: 0,
            detail: None,
            dir_removed: true,
            stop_phase: Phase::Stopped,
        }
    }

    /// Ready at the first step, then the verdicts.
    fn ready(verdicts: &[Verdict]) -> Fake {
        Fake::new(&[Phase::Ready], verdicts)
    }
}

impl TrialKernel for Fake {
    fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused> {
        assert_eq!(
            self.phase,
            Phase::Ready,
            "a request before the kernel was ready"
        );
        if let Some(refused) = self.refuse {
            return Err(refused);
        }
        let id = ReqId::try_from(self.sent.len()).unwrap();
        self.sent.push(Sent {
            method: req.method.to_vec(),
            uri: req.uri.to_vec(),
            headers: req
                .headers
                .iter()
                .map(|(n, v)| (n.to_vec(), v.to_vec()))
                .collect(),
            body: req.body.to_vec(),
        });
        if let Some(verdict) = self.verdicts.pop_front() {
            self.answers.push((id, verdict));
        }
        Ok(id)
    }

    fn cancel(&mut self, id: ReqId) {
        self.cancelled.push(id);
    }

    fn poll(&mut self, _until: Instant) -> Vec<(ReqId, Verdict)> {
        if let Some(next) = self.script.pop_front() {
            self.phase = next;
        }
        if self.answers.is_empty() {
            thread::sleep(Duration::from_millis(1));
        }
        std::mem::take(&mut self.answers)
    }

    fn status(&self) -> Status {
        Status {
            phase: self.phase,
            inc: 1,
            restarts: 0,
            waiting: 0,
            held: 0,
            records: 0,
        }
    }

    fn shutdown(&mut self, _deadline: Instant) -> Shutdown {
        self.shutdowns += 1;
        Shutdown {
            results: Vec::new(),
            phase: self.stop_phase,
            bye: true,
            exit_confirmed: true,
            dir_removed: self.dir_removed,
            held_left: 0,
            waiting_left: 0,
        }
    }

    fn start_detail(&self) -> Option<Vec<u8>> {
        self.detail.clone()
    }
}

fn limits(accept_block: bool) -> Limits {
    Limits {
        ready_wait: Duration::from_millis(60),
        inspect_wait: Duration::from_millis(60),
        stop_inspect: Duration::from_secs(1),
        slice: Duration::from_millis(5),
        accept_block,
        mode: Mode::Block,
    }
}

const BLOCK: Verdict = Verdict::Block {
    phase: 1,
    rule_id: 949110,
    status: 403,
};

const DETECTED: Verdict = Verdict::Detected {
    rule_id: 949110,
    status: 403,
};

fn go(kernel: &mut Fake, accept_block: bool) -> Finish {
    run(kernel, &limits(accept_block), &AtomicBool::new(false))
}

#[test]
fn three_requests_of_the_fixed_shape_that_are_allowed_pass() {
    let mut kernel = Fake::ready(&[Verdict::Allow; 3]);
    let finish = go(&mut kernel, false);
    assert!(finish.passed());
    assert_eq!(finish.result, Ok(Vec::new()));
    assert_eq!(kernel.shutdowns, 1);

    let shapes: [(&[u8], &[u8]); 3] =
        [(b"GET", b""), (b"POST", b"a=b"), (b"POST", br#"{"a":"b"}"#)];
    assert_eq!(kernel.sent.len(), 3);
    for (sent, (method, body)) in kernel.sent.iter().zip(shapes) {
        assert_eq!(
            (
                sent.method.as_slice(),
                sent.uri.as_slice(),
                sent.body.as_slice()
            ),
            (method, &b"/"[..], body)
        );
        // A name for the host, never an address, and the headers that the default rules ask for.
        assert_eq!(sent.header("Host"), Some(&b"example.test"[..]));
        assert!(sent.header("User-Agent").is_some() && sent.header("Accept").is_some());
        if body.is_empty() {
            assert!(
                sent.header("Content-Type").is_none() && sent.header("Content-Length").is_none()
            );
        } else {
            let length = body.len().to_string();
            assert_eq!(sent.header("Content-Length"), Some(length.as_bytes()));
            assert!(sent.header("Content-Type").is_some());
        }
    }
    assert_eq!(
        kernel.sent[1].header("Content-Type"),
        Some(&b"application/x-www-form-urlencoded"[..])
    );
    assert_eq!(
        kernel.sent[2].header("Content-Type"),
        Some(&b"application/json"[..])
    );
}

#[test]
fn a_block_fails_the_trial_unless_it_is_accepted_and_an_uninspectable_request_always_fails() {
    // The trial stops at the first request that fails.
    let mut kernel = Fake::ready(&[Verdict::Allow, BLOCK, Verdict::Allow]);
    let finish = go(&mut kernel, false);
    let blocked = Failed::Blocked {
        probe: PROBES[1].name,
        phase: 1,
        rule_id: 949110,
        status: 403,
    };
    assert_eq!(finish.result, Err(blocked));
    assert!(!finish.passed());
    assert_eq!((kernel.sent.len(), kernel.shutdowns), (2, 1));

    // Accepted, the blocks are reported and the trial goes on.
    let mut kernel = Fake::ready(&[BLOCK, Verdict::Allow, BLOCK]);
    let finish = go(&mut kernel, true);
    let accepted = |probe: &Probe| Accepted::Block {
        probe: probe.name,
        phase: 1,
        rule_id: 949110,
        status: 403,
    };
    assert_eq!(
        finish.result,
        Ok(vec![accepted(&PROBES[0]), accepted(&PROBES[2])])
    );
    assert!(finish.passed());

    // Not even then is a request that was not inspected a pass.
    let lost = Verdict::Uninspectable(Reason::Unavailable);
    let mut kernel = Fake::ready(&[Verdict::Allow, lost]);
    let finish = go(&mut kernel, true);
    let failed = Failed::Uninspectable {
        probe: PROBES[1].name,
        reason: Reason::Unavailable,
    };
    assert_eq!(finish.result, Err(failed));
}

#[test]
fn a_detection_of_a_bundle_that_detects_is_not_a_failure_and_is_reported() {
    let mut kernel = Fake::ready(&[Verdict::Allow, DETECTED, Verdict::Allow]);
    let detect = Limits {
        mode: Mode::Detect,
        ..limits(false)
    };
    let finish = run(&mut kernel, &detect, &AtomicBool::new(false));
    let reported = Accepted::Detected {
        probe: PROBES[1].name,
        rule_id: 949110,
        status: 403,
    };
    assert_eq!(finish.result, Ok(vec![reported]));
    assert!(finish.passed());
    assert_eq!((kernel.sent.len(), kernel.shutdowns), (3, 1));
}

#[test]
fn a_detection_of_a_bundle_that_blocks_fails_the_trial_even_when_blocks_are_accepted() {
    let mut kernel = Fake::ready(&[Verdict::Allow, DETECTED, Verdict::Allow]);
    let finish = go(&mut kernel, true);
    let failed = Failed::Uninspectable {
        probe: PROBES[1].name,
        reason: Reason::Protocol,
    };
    assert_eq!(finish.result, Err(failed));
    assert!(!finish.passed());
    assert_eq!((kernel.sent.len(), kernel.shutdowns), (2, 1));
}

#[test]
fn a_start_that_fails_ends_the_trial_with_its_detail_and_without_a_request() {
    let failure = Phase::Failed(Failure::Exit(11));
    let mut kernel = Fake::new(&[Phase::Starting, failure], &[]);
    kernel.detail = Some(b"tkv0-inspector: start: rules rejected\n".to_vec());
    let finish = go(&mut kernel, true);
    assert_eq!(finish.result, Err(Failed::Start(Failure::Exit(11))));
    assert_eq!(finish.detail, kernel.detail);
    assert!(!finish.passed());
    assert_eq!((kernel.sent.len(), kernel.shutdowns), (0, 1));
}

#[test]
fn an_inspector_that_is_not_ready_in_time_or_a_request_without_a_verdict_fails() {
    let mut kernel = Fake::new(&[Phase::Starting], &[]);
    assert_eq!(go(&mut kernel, false).result, Err(Failed::NotReady));
    assert_eq!(kernel.shutdowns, 1);

    let mut kernel = Fake::ready(&[]);
    let finish = go(&mut kernel, false);
    assert_eq!(
        finish.result,
        Err(Failed::NoVerdict {
            probe: PROBES[0].name
        })
    );
    assert_eq!((kernel.cancelled.clone(), kernel.shutdowns), (vec![0], 1));

    let mut kernel = Fake::ready(&[]);
    kernel.refuse = Some(Refused::Full);
    let failed = Failed::Refused {
        probe: PROBES[0].name,
        refused: Refused::Full,
    };
    assert_eq!(go(&mut kernel, false).result, Err(failed));
}

#[test]
fn a_signal_ends_the_trial_and_the_kernel_is_still_shut_down() {
    let mut kernel = Fake::ready(&[Verdict::Allow; 3]);
    let finish = run(&mut kernel, &limits(false), &AtomicBool::new(true));
    assert_eq!(finish.result, Err(Failed::Interrupted));
    assert_eq!((kernel.sent.len(), kernel.shutdowns), (0, 1));
}

#[test]
fn a_trial_passes_only_if_the_inspector_is_gone_and_the_kernel_stopped() {
    let mut kernel = Fake::ready(&[Verdict::Allow; 3]);
    kernel.dir_removed = false;
    let finish = go(&mut kernel, false);
    assert!(finish.result.is_ok());
    assert!(!finish.clean && !finish.passed());

    // The kernel failed while it was stopped: every request was fine, and the trial is not a pass.
    let mut kernel = Fake::ready(&[Verdict::Allow; 3]);
    kernel.stop_phase = Phase::Failed(Failure::Exit(11));
    let finish = go(&mut kernel, false);
    assert_eq!(finish.result, Err(Failed::NotStopped));
    assert!(finish.clean && !finish.passed());

    // A start that failed is not a trial that left something behind.
    let failure = Phase::Failed(Failure::Exit(11));
    let mut kernel = Fake::new(&[failure], &[]);
    kernel.stop_phase = failure;
    let finish = go(&mut kernel, false);
    assert_eq!(finish.result, Err(Failed::Start(Failure::Exit(11))));
    assert!(finish.clean);
}
