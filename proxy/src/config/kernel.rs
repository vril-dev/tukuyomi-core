//! The kernel values of the configuration as the proxy keeps them: the `kernel` object checked into one kernel
//! configuration, and the inspectors of the engines other than Coraza.
//!
//! `kernel.inspector` is the inspector of the engine Coraza and is always there. The object `kernel.engines` may be
//! left out. When it is there it has the one key `modsecurity`, whose value has the one key `inspector`: an absolute
//! clean path, by the rule that `kernel.inspector` follows. The file is not looked at here; the start of the
//! inspector does that. A generation of an engine can be used only if the configuration has an inspector for the
//! engine and the kernel has a pinned build of that inspector (`KernelSettings::check_engine`).

use std::path::PathBuf;

use serde::Deserialize;
use tukuyomi_kernel::Engine;

use super::{ConfigError, Object, clean_abs, ensure};
use crate::rules::bundle::Fingerprint;

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

/// The kernel values of the file, checked. The rules directory and fingerprint come from the rules store at
/// start-up, and the engine and its inspector from the generation.
#[derive(Clone, Debug)]
pub struct KernelSettings(pub(super) tukuyomi_kernel::Config, Engines);

impl KernelSettings {
    pub(super) fn new(base: tukuyomi_kernel::Config, engines: Engines) -> KernelSettings {
        KernelSettings(base, engines)
    }

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

    /// Whether a generation of `engine` can be used here: the configuration has an inspector for the engine and the
    /// kernel has a pinned build of that inspector. A fixed sentence says which of the two is missing.
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
