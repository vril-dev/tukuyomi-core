//! The kernel values of the configuration as the proxy keeps them: the `kernel` object checked into one kernel
//! configuration, and the inspectors of the engines other than Coraza.
//!
//! `kernel.inspector` is the inspector of the engine Coraza and is always there. The object `kernel.engines` may be
//! left out. When it is there it has the one key `modsecurity`, whose value has the one key `inspector`: an absolute
//! clean path, by the rule that `kernel.inspector` follows. The file is not looked at here; the start of the
//! inspector does that. A generation of an engine can be used only if the configuration has an inspector for the
//! engine (`KernelSettings::check_engine`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use tukuyomi_kernel::Engine;

use super::{ConfigError, Object, ProxyConfig, clean_abs, ensure};
use crate::rules::bundle::Fingerprint;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawKernel {
    inspector: String,
    #[serde(default, deserialize_with = "super::present")]
    engines: Option<Object<RawEngines>>,
    tmp_root: String,
    gomaxprocs: u16,
    gomemlimit: u64,
    slots: usize,
    wait_queue: usize,
    records: usize,
    discard_limit: u32,
    tick_ms: u64,
    hello_wait_ms: u64,
    frame_io_ms: u64,
    verdict_wait_ms: u64,
    wait_deadline_ms: u64,
    closed_wait_ms: u64,
    stop_after_ms: u64,
    drain_wait_ms: u64,
    exit_wait_ms: u64,
    kill_grace_ms: u64,
    restarts: u32,
    restart_window_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawEngines {
    modsecurity: Object<RawEngine>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEngine {
    inspector: String,
}

/// The inspectors of the engines other than Coraza, whose inspector is `kernel.inspector`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Engines {
    modsecurity: Option<PathBuf>,
}

/// Checks the `engines` object.
pub(super) fn check(raw: Option<Object<RawEngines>>) -> Result<Engines, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(Engines::default());
    };
    let Object(modsecurity) = raw.modsecurity;
    let inspector = PathBuf::from(modsecurity.inspector);
    ensure(
        clean_abs(&inspector),
        "kernel.engines.modsecurity.inspector is not an absolute clean path",
    )?;
    Ok(Engines {
        modsecurity: Some(inspector),
    })
}

/// The `kernel` object converted into one kernel configuration and checked by that type's own check. `rules` is the
/// directory of the rules store.
pub(super) fn settings(k: RawKernel, rules: &Path) -> Result<KernelSettings, ConfigError> {
    let engines = check(k.engines)?;
    let config = tukuyomi_kernel::Config {
        engine: Engine::Coraza,
        inspector: PathBuf::from(k.inspector),
        // The check looks at the form of the path only, so the directory of a generation, which is below this
        // one, gets the same answer. The fingerprint is any value of its type.
        rules: rules.join("generations"),
        rules_sha256: [0; 32],
        tmp_root: PathBuf::from(k.tmp_root),
        gomaxprocs: k.gomaxprocs,
        gomemlimit: k.gomemlimit,
        slots: k.slots,
        wait_queue: k.wait_queue,
        records: k.records,
        discard_limit: k.discard_limit,
        tick: Duration::from_millis(k.tick_ms),
        hello_wait: Duration::from_millis(k.hello_wait_ms),
        frame_io: Duration::from_millis(k.frame_io_ms),
        verdict_wait: Duration::from_millis(k.verdict_wait_ms),
        wait_deadline: Duration::from_millis(k.wait_deadline_ms),
        closed_wait: Duration::from_millis(k.closed_wait_ms),
        stop_after: Duration::from_millis(k.stop_after_ms),
        drain_wait: Duration::from_millis(k.drain_wait_ms),
        exit_wait: Duration::from_millis(k.exit_wait_ms),
        kill_grace: Duration::from_millis(k.kill_grace_ms),
        restarts: k.restarts,
        restart_window: Duration::from_millis(k.restart_window_ms),
    };
    config.check().map_err(|e| ConfigError(e.0))?;
    Ok(KernelSettings(config, engines))
}

/// The least time the HTTP side must allow for an inspection: the kernel's wait for the first frame, two
/// verdicts, and 18 driver steps of one slice and one frame write each. `None` if the sum overflows.
pub(super) fn inspect_floor(kernel: &tukuyomi_kernel::Config, slice: Duration) -> Option<Duration> {
    let steps = slice.checked_add(kernel.frame_io)?.checked_mul(18)?;
    kernel
        .wait_deadline
        .checked_add(kernel.verdict_wait.checked_mul(2)?)?
        .checked_add(steps)
}

/// The relations between the `proxy` object and the kernel values, checked in this order.
pub(super) fn relations(proxy: &ProxyConfig, settings: &KernelSettings) -> Result<(), ConfigError> {
    let kernel = &settings.0;
    ensure(
        proxy.drive_slice <= kernel.tick,
        "drive_slice_ms is above the kernel tick",
    )?;
    ensure(
        proxy.ready_wait >= kernel.hello_wait,
        "ready_wait_ms is below the kernel hello_wait",
    )?;
    ensure(
        proxy.head_read <= proxy.request_total,
        "head_read_ms is above request_total_ms",
    )?;
    ensure(
        proxy.body_read <= proxy.request_total,
        "body_read_ms is above request_total_ms",
    )?;
    ensure(
        inspect_floor(kernel, proxy.drive_slice).is_some_and(|low| proxy.inspect_wait >= low),
        "inspect_wait_ms is below the kernel inspection time",
    )?;
    ensure(
        proxy.inspect_wait <= proxy.request_total,
        "inspect_wait_ms is above request_total_ms",
    )?;
    // The two stages of the exchange with the upstream follow each other, and both must end before the request time
    // does. A server that holds a stage up is counted against only if the limit of the stage comes first; if the end
    // of the request time comes first, the request ends there and no server is at fault. A slow client or a long
    // inspection can still use up the time that is left, and the request then ends the same way.
    ensure(
        proxy
            .upstream_connect
            .checked_add(proxy.upstream_header)
            .is_some_and(|n| n < proxy.request_total),
        "upstream_connect_ms plus upstream_header_ms is not below request_total_ms",
    )?;
    ensure(
        proxy.request_total <= proxy.conn_total,
        "request_total_ms is above conn_total_ms",
    )?;
    ensure(
        proxy.response_idle <= proxy.conn_total,
        "response_idle_ms is above conn_total_ms",
    )?;
    ensure(
        proxy.keepalive_timeout <= proxy.conn_total,
        "keepalive_timeout_ms is above conn_total_ms",
    )?;
    // A connection that waits in the pool is read from the whole time, and a read that waits for longer than
    // `response_idle` fails.
    ensure(
        proxy.upstream_keepalive_timeout <= proxy.response_idle,
        "upstream_keepalive_timeout_ms is above response_idle_ms",
    )?;
    // A request that starts before `keepalive_time` gets its answer, or the upstream's response head, before
    // the connection time is over (`request_total` bounds that part of a request, not a streamed body).
    ensure(
        proxy
            .keepalive_time
            .checked_add(proxy.request_total)
            .is_some_and(|n| n <= proxy.conn_total),
        "keepalive_time_ms plus request_total_ms is above conn_total_ms",
    )?;
    ensure(
        proxy.lingering_timeout <= proxy.lingering_time,
        "lingering_timeout_ms is above lingering_time_ms",
    )?;
    ensure(
        proxy.stop_inspect < proxy.stop_wait,
        "stop_inspect_ms is not below stop_wait_ms",
    )?;
    ensure(
        proxy
            .stop_inspect
            .checked_add(kernel.kill_grace)
            .is_some_and(|n| proxy.stop_wait > n),
        "stop_wait_ms is not above stop_inspect_ms plus kill_grace",
    )?;
    // A connection holds at most one inspection, so a longer queue would never fill. The bound also keeps the
    // queue and its permits small.
    ensure(
        kernel.wait_queue <= proxy.max_conns,
        "wait_queue is above max_conns",
    )?;
    Ok(())
}

/// The kernel values of the file, checked. The rules directory and fingerprint come from the rules store at
/// start-up, and the engine and its inspector from the generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelSettings(pub(super) tukuyomi_kernel::Config, Engines);

impl KernelSettings {
    /// The kernel configuration for one generation, whose rules are inspected by `engine`, checked again.
    pub fn for_generation(
        &self,
        dir: PathBuf,
        generation: Fingerprint,
        engine: Engine,
    ) -> Result<tukuyomi_kernel::Config, ConfigError> {
        let kernel = tukuyomi_kernel::Config {
            rules: dir,
            rules_sha256: generation.bytes(),
            ..self.for_engine(engine)?
        };
        kernel.check().map_err(|e| ConfigError(e.0))?;
        Ok(kernel)
    }

    /// Whether a generation of `engine` can be used here: the configuration has an inspector for the engine, and the
    /// kernel accepts the settings with it. A fixed sentence says why not.
    pub fn check_engine(&self, engine: Engine) -> Result<(), ConfigError> {
        self.for_engine(engine)?
            .check()
            .map_err(|e| ConfigError(e.0))
    }

    /// The kernel values with the engine and its inspector in place of the ones of Coraza.
    fn for_engine(&self, engine: Engine) -> Result<tukuyomi_kernel::Config, ConfigError> {
        let inspector = match engine {
            Engine::Coraza => self.0.inspector.clone(),
            Engine::ModSecurity => self.1.modsecurity.clone().ok_or(ConfigError(
                "kernel.engines has no inspector for the engine of the generation",
            ))?,
        };
        Ok(tukuyomi_kernel::Config {
            engine,
            inspector,
            ..self.0.clone()
        })
    }
}
