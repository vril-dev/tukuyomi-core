//! The records of the chosen generations of the rules store: one file for each engine.
//!
//! `current.<engine>` (`current.coraza`, `current.modsecurity`) names the generation chosen for the engine, in the form
//! that `current` had before the engines were chosen apart: its 64 digits and a newline. A file `current` that an older
//! version wrote is read still, for the engine of the generation it names: when the engine has no `current.<engine>`,
//! that generation is the chosen one. When the engine has both and they name different generations, none is chosen: the
//! store refuses to read the choice (an older version chose after this one did, or a choice stopped halfway), and
//! `activate` makes it whole. The older file is read first and the file of the engine second, so that a choice that
//! writes the file of the engine and then removes the older file is never read as no choice. A `current.<engine>` that
//! names a generation of another engine is broken.
//!
//! `choose` writes `current.<engine>.new`, syncs it and renames it over `current.<engine>`, syncs the directory, and
//! then removes the older file when it names a generation of the same engine, or cannot be told (a record that cannot
//! be read, or one whose generation has no manifest): a choice that fails to read what it replaces still replaces it.
//! A `current.<engine>.new` that a choice left when it stopped halfway is removed by the next `choose` for the same
//! engine, and by nothing else; nothing reads it.
//!
//! This version never writes `current`. An older version reads `current` only, so to go back to it the operator
//! removes the `current.*` files and chooses with it.

use std::fs;
use std::io;

use tukuyomi_kernel::Engine;

use super::{CURRENT, CURRENT_LEN, FileStore, read_regular, sync_dir, write_new};
use crate::rules::bundle::Fingerprint;
use crate::rules::store::{RuleStore, StoreError};

/// A record whose name has no generation of the engine that its file is for, or is not the form of a record.
const BROKEN: StoreError = StoreError("the current generation record is broken");
/// The older record and the one of the engine name different generations.
const DISAGREE: StoreError = StoreError("the current generation records of the engine disagree");

/// The name of the record of `engine`.
fn record_name(engine: Engine) -> String {
    format!("{CURRENT}.{}", engine.name())
}

impl FileStore {
    /// Reads the record at `<dir>/<name>`: absent is no choice yet; a link, a special file, a file over 65 bytes or any
    /// failure to read it is a refusal, and so is a content other than 64 lowercase digits and one newline.
    fn read_record(&self, name: &str) -> Result<Option<Fingerprint>, StoreError> {
        const UNREADABLE: StoreError = StoreError("the current generation record cannot be read");
        let record = match read_regular(&self.dir.join(name), CURRENT_LEN, None) {
            Ok(record) => record,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(UNREADABLE),
        };
        match record.split_last() {
            Some((b'\n', hex)) => Fingerprint::from_hex(hex).map(Some).ok_or(BROKEN),
            _ => Err(BROKEN),
        }
    }

    /// The generation that the file `current` of an older version names, if it is one of `engine`. A generation whose
    /// manifest cannot be read is no generation of any engine that can be told, and is refused.
    fn older(&self, engine: Engine) -> Result<Option<Fingerprint>, StoreError> {
        match self.read_record(CURRENT)? {
            Some(generation) if self.engine(generation)? == engine => Ok(Some(generation)),
            _ => Ok(None),
        }
    }

    /// The generation chosen for `engine` (see the module documentation).
    pub(super) fn chosen(&self, engine: Engine) -> Result<Option<Fingerprint>, StoreError> {
        let older = self.older(engine)?;
        let own = self.read_record(&record_name(engine))?;
        if let Some(generation) = own
            && self.engine(generation)? != engine
        {
            return Err(BROKEN);
        }
        match (older, own) {
            (Some(older), Some(own)) if older != own => Err(DISAGREE),
            (older, own) => Ok(own.or(older)),
        }
    }

    /// Chooses `generation` for its engine, after `verify`. The lock is held by the caller.
    pub(super) fn choose(&self, generation: Fingerprint) -> Result<(), StoreError> {
        const CANNOT: StoreError = StoreError("the current generation record cannot be written");
        self.verify(generation)?;
        let engine = self.engine(generation)?;
        let name = record_name(engine);
        let new = self.dir.join(format!("{name}.new"));
        match fs::remove_file(&new) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(CANNOT),
        }
        let record = format!("{}\n", generation.hex());
        write_new(&new, record.as_bytes())
            .and_then(|()| fs::rename(&new, self.dir.join(&name)))
            .and_then(|()| sync_dir(&self.dir))
            .map_err(|_| {
                let _ = fs::remove_file(&new);
                CANNOT
            })?;
        // The record of the engine is written; the older one, if it is the engine's, is what it replaces.
        let replaced = match self.older(engine) {
            Ok(older) => older.is_some(),
            Err(_) => true,
        };
        if replaced {
            self.forget(&[CURRENT])?;
        }
        Ok(())
    }

    /// Leaves `engine` with no chosen generation, and gives the one that was chosen. The lock is held by the caller.
    /// The older record goes first: if the removal stops after it, the engine keeps the choice it had, and not an
    /// older one that the engine's own record replaced.
    pub(super) fn leave(&self, engine: Engine) -> Result<Option<Fingerprint>, StoreError> {
        let Some(was) = self.chosen(engine)? else {
            return Ok(None);
        };
        let own = record_name(engine);
        if self.older(engine)?.is_some() {
            self.forget(&[CURRENT, &own])?;
        } else {
            self.forget(&[&own])?;
        }
        Ok(Some(was))
    }

    /// Removes the records `names`, in order, which may be absent, and makes the removal durable.
    fn forget(&self, names: &[&str]) -> Result<(), StoreError> {
        const CANNOT: StoreError = StoreError("the current generation record cannot be removed");
        for name in names {
            match fs::remove_file(self.dir.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(CANNOT),
            }
        }
        sync_dir(&self.dir).map_err(|_| CANNOT)
    }
}
