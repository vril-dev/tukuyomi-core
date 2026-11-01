//! The engines that can inspect the requests of a generation, and the inspector build that the kernel accepts for
//! each.
//!
//! A generation names its engine, and the host starts the inspector of that engine. The kernel knows the engines by
//! name (`parse`, `name`) and, in this code and in no configuration, the build of the inspector it accepts for each
//! (`pinned`): the HELLO of an inspector has to report exactly that build, so an inspector of another engine or of
//! another build is refused at its start. Every engine has a build, and a new engine is given its build with it.
#![forbid(unsafe_code)]

/// The engine that inspects the requests of a generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Engine {
    #[default]
    Coraza,
    ModSecurity,
}

/// The build of an inspector as its HELLO reports it, for any engine: the toolchain that built the inspector, the
/// version of the engine, and the hash of the source of the engine.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Build {
    pub toolchain: &'static [u8],
    pub version: &'static [u8],
    pub source: &'static [u8],
}

/// Go's toolchain, the Coraza module and the `go.sum` hash of it. Change these together with the inspector's
/// `go.mod` and `go.sum`.
const CORAZA: Build = Build {
    toolchain: b"go1.27.2",
    version: b"v3.8.1",
    source: b"h1:dMV55FbMR2vOks/acrT43RShR+VkzU6jwp+XPdxay8o=",
};

/// Rust's toolchain, the libmodsecurity release and the SHA-256 of its source archive. Change these together with the
/// toolchain that builds the inspector and with `VERSION` and `SHA256` in `scripts/build-modsecurity.sh`.
const MODSECURITY: Build = Build {
    toolchain: b"rustc 1.94.1",
    version: b"v3.0.17",
    source: b"f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50",
};

impl Engine {
    /// The engine that `name` names: the lowercase name, exactly.
    pub fn parse(name: &str) -> Option<Engine> {
        match name {
            "coraza" => Some(Engine::Coraza),
            "modsecurity" => Some(Engine::ModSecurity),
            _ => None,
        }
    }

    /// The name of the engine, as `parse` reads it.
    pub fn name(self) -> &'static str {
        match self {
            Engine::Coraza => "coraza",
            Engine::ModSecurity => "modsecurity",
        }
    }

    /// The inspector build that the kernel accepts for the engine.
    pub(crate) fn pinned(self) -> &'static Build {
        match self {
            Engine::Coraza => &CORAZA,
            Engine::ModSecurity => &MODSECURITY,
        }
    }
}

#[cfg(test)]
mod tests;
