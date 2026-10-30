//! The choice of the generation that a running proxy switches to.
//!
//! The proxy reads the rules store when it starts, and again when it is told to switch (SIGUSR1). A switch reads the
//! chosen generation (`current`), takes the hold on it, asks for its directory and builds the kernel configuration
//! for it, in this order: the hold comes before the directory, the engine, the mode and the routes, so that a removal
//! that has finished is found by the directory and one that is going on keeps the hold from being taken. `Switcher`
//! keeps what that takes: the store, the kernel values of the configuration, the generation that runs with its hold,
//! and, while a switch is under way, the generation it is for with its hold. When the driver has answered, `finish`
//! keeps the hold of the generation that serves and gives the other back, so a generation that serves is never
//! without a hold, and `rules remove` cannot take it from under a running inspector. A refusal is a fixed sentence of
//! the store or of the configuration, and the proxy goes on with the generation that runs.

use crate::config::KernelSettings;
use crate::rules::bundle::{Fingerprint, Mode};
use crate::rules::routes::Routes;
use crate::rules::store::{Hold, RuleStore};

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
    /// The store chooses the generation that runs.
    Running(Fingerprint),
    /// The store or the configuration refused.
    Refused(&'static str),
    /// The generation to switch to, held, with its mode, its routes and the kernel configuration for it.
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
    running: Held,
    next: Option<Held>,
}

impl Switcher {
    /// `hold` is the hold on `generation`, which the proxy started with.
    pub fn new(
        store: Box<dyn RuleStore>,
        settings: KernelSettings,
        generation: Fingerprint,
        hold: Hold,
    ) -> Switcher {
        Switcher {
            store,
            settings,
            running: Held {
                generation,
                _hold: hold,
            },
            next: None,
        }
    }

    /// Reads the store. On `Ready` the hold on the new generation is kept until `finish`; every other answer
    /// leaves no hold behind.
    pub fn prepare(&mut self) -> Next {
        if self.next.is_some() {
            return Next::Busy;
        }
        let generation = match self.store.current() {
            Ok(Some(generation)) => generation,
            Ok(None) => return Next::Refused("no generation is chosen"),
            Err(e) => return Next::Refused(e.0),
        };
        if generation == self.running.generation {
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
        let engine = match self.store.engine(generation) {
            Ok(engine) => engine,
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
        self.next = Some(Held {
            generation,
            _hold: hold,
        });
        Next::Ready {
            generation,
            mode,
            routes,
            kernel: Box::new(kernel),
        }
    }

    /// The generation that serves.
    pub fn running(&self) -> Fingerprint {
        self.running.generation
    }

    /// The driver has answered: the new generation serves (`switched`) or the one that ran goes on.
    pub fn finish(&mut self, switched: bool) {
        if let Some(next) = self.next.take()
            && switched
        {
            self.running = next;
        }
    }
}

#[cfg(test)]
mod tests;
