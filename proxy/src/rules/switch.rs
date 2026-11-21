//! The choice of the generations that a running proxy switches to.
//!
//! The proxy reads the rules store when it starts, and again when it is told to switch (SIGUSR1). A switch is for one
//! engine: it reads the generation chosen for the engine (`current`), takes the hold on it, asks for its directory and
//! builds the kernel configuration for it, in this order: the hold comes before the directory, the engine, the mode
//! and the routes, so that a removal that has finished is found by the directory and one that is going on keeps the
//! hold from being taken. `Switcher` keeps what that takes: the store, the kernel values of the configuration, the
//! generation that runs for each engine that was started with its hold, and, while a switch is under way, the
//! engine and the generation it is for with its hold. There is one switch under way at a time, whatever the engine.
//! When the driver has answered, `finish` keeps the hold of the generation that serves and gives the other back, so a
//! generation that serves is never without a hold, and `rules remove` cannot take it from under a running inspector.
//! A refusal is a fixed sentence of the store or of the configuration, and the proxy goes on with the generations that
//! run. A generation chosen for an engine that does not run is a switch like any other: it starts the engine.

use tukuyomi_kernel::Engine;

use crate::config::KernelSettings;
use crate::rules::bundle::{Fingerprint, Mode};
use crate::rules::routes::Routes;
use crate::rules::store::{ENGINES, Hold, RuleStore, index};

/// A generation with the hold that keeps it from being removed.
struct Held {
    generation: Fingerprint,
    _hold: Hold,
}

/// What reading the store for a switch came to.
#[derive(Debug)]
pub enum Next {
    /// A switch is under way already.
    Busy,
    /// The store chooses the generation that runs for the engine.
    Running(Fingerprint),
    /// The store chooses no generation for the engine.
    Unchosen,
    /// The store or the configuration refused.
    Refused(&'static str),
    /// The generation to switch to, held, with its mode, its routes and the kernel configuration for it (whose
    /// engine is the engine of the switch).
    Ready {
        generation: Fingerprint,
        mode: Mode,
        routes: Routes,
        kernel: Box<tukuyomi_kernel::Config>,
    },
}

pub struct Switcher {
    store: Box<dyn RuleStore>,
    settings: KernelSettings,
    running: [Option<Held>; ENGINES.len()],
    next: Option<(Engine, Held)>,
}

impl Switcher {
    /// `started` are the generations that the proxy started with, one for each engine that runs, each with its hold.
    pub fn new(
        store: Box<dyn RuleStore>,
        settings: KernelSettings,
        started: Vec<(Engine, Fingerprint, Hold)>,
    ) -> Switcher {
        let mut running = [const { None }; ENGINES.len()];
        for (engine, generation, hold) in started {
            running[index(engine)] = Some(Held {
                generation,
                _hold: hold,
            });
        }
        Switcher {
            store,
            settings,
            running,
            next: None,
        }
    }

    /// The engine of what names none: the engine that SIGUSR1 switches first.
    pub fn default_engine(&self) -> Engine {
        self.settings.default_engine()
    }

    /// Reads the store for the generation chosen for `engine`. On `Ready` the hold on the new generation is kept
    /// until `finish`; every other answer leaves no hold behind.
    pub fn prepare(&mut self, engine: Engine) -> Next {
        if self.next.is_some() {
            return Next::Busy;
        }
        let generation = match self.store.current(engine) {
            Ok(Some(generation)) => generation,
            Ok(None) => return Next::Unchosen,
            Err(e) => return Next::Refused(e.0),
        };
        if self.running(engine) == Some(generation) {
            return Next::Running(generation);
        }
        let hold = match self.store.hold(generation) {
            Ok(hold) => hold,
            Err(e) => return Next::Refused(e.0),
        };
        let dir = match self.store.generation_dir(generation) {
            Ok(dir) => dir,
            Err(e) => return Next::Refused(e.0),
        };
        let mode = match self.store.mode(generation) {
            Ok(mode) => mode,
            Err(e) => return Next::Refused(e.0),
        };
        let routes = match self.store.routes(generation) {
            Ok(routes) => routes,
            Err(e) => return Next::Refused(e.0),
        };
        let kernel = match self.settings.for_generation(dir, generation, engine) {
            Ok(kernel) => kernel,
            Err(e) => return Next::Refused(e.0),
        };
        self.next = Some((
            engine,
            Held {
                generation,
                _hold: hold,
            },
        ));
        Next::Ready {
            generation,
            mode,
            routes,
            kernel: Box::new(kernel),
        }
    }

    /// The generation that serves `engine`, if the engine runs.
    pub fn running(&self, engine: Engine) -> Option<Fingerprint> {
        self.running[index(engine)]
            .as_ref()
            .map(|held| held.generation)
    }

    /// The engine whose switch is under way.
    pub fn switching(&self) -> Option<Engine> {
        self.next.as_ref().map(|(engine, _)| *engine)
    }

    /// The driver has answered: the new generation serves (`switched`) or the one that ran goes on.
    pub fn finish(&mut self, switched: bool) {
        if let Some((engine, next)) = self.next.take()
            && switched
        {
            self.running[index(engine)] = Some(next);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
