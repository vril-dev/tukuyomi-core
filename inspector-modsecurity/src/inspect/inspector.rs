//! The engine and the rules, which every request of a generation is inspected with.

use std::rc::Rc;

use crate::codec::FaultCode;
use crate::ffi::{Engine, EngineTransaction, Error, Rules};
use crate::owner::{Fault, Inspection};

use super::transaction::InspectedRequest;

/// The inspection of the requests of one generation. `detect` is the mode of the generation: a rule of the
/// operator that would stop a request is then only noted, and the request goes on.
///
/// The engine and the rules are shared with each request that is being inspected, which keeps them alive until
/// the request is done with them. Everything runs on one thread.
pub struct Inspector {
    engine: Rc<Engine>,
    rules: Rc<Rules>,
    detect: bool,
    /// The count of the requests that this process has inspected, plus one, which the library uses as the name of the
    /// next. It is not the number that the kernel gave the request: the inspection is not told that number.
    next: u64,
}

impl Inspector {
    /// Makes the engine, with a log callback that writes nothing. The process has restricted itself and built
    /// the rules before this: the engine opens a socket while it is made, which a restriction does not stop.
    pub fn new(rules: Rules, detect: bool) -> Result<Inspector, Error> {
        Ok(Inspector {
            engine: Rc::new(Engine::new()?),
            rules: Rc::new(rules),
            detect,
            next: 1,
        })
    }
}

impl Inspection for Inspector {
    type Tx = InspectedRequest;

    fn start(&mut self) -> Result<InspectedRequest, Fault> {
        let id = format!("{:016x}", self.next);
        self.next = self.next.wrapping_add(1);
        let engine = EngineTransaction::new(&self.engine, &self.rules, &id).map_err(|_| Fault {
            code: FaultCode::Incomplete,
            text: "request inspection incomplete",
        })?;
        Ok(InspectedRequest::new(engine, self.detect))
    }
}
