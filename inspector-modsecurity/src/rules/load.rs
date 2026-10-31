//! Builds the rules of a generation from the copy of its files.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::ffi::{self, EngineState, Rules};
use crate::sandbox::Restricted;

use super::files;
use super::guard;
use super::markers::Markers;
use super::model::Model;
use super::reader::Reason;
use super::refusal::Refusal;

/// The directives that follow the operator's. The engine is on whatever mode the generation has (the mode is
/// kept by the inspector), the request body is read, and a JSON body nests at most `JSON_DEPTH_LIMIT`
/// levels: the library parses a JSON body again at every level, so a deep body costs much more than a flat
/// one. The body limit is not set here: the inspector counts the body itself.
pub(super) const FIXED_DIRECTIVES: &str =
    "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyJsonDepthLimit 64\n";
const JSON_DEPTH_LIMIT: u64 = 64;

/// The working directory belongs to the whole process, and tests run on several threads: it is changed
/// and put back under this lock.
pub(super) static WORKING_DIRECTORY: Mutex<()> = Mutex::new(());

const NOT_ABSOLUTE: Reason = "the root of the copy is not an absolute path";
const NO_RULE_FILE: Reason = "no rule file is loaded";
const NOT_A_RULE_FILE: Reason = "a rule file is not a file of the generation";
const CANNOT_ENTER: Reason = "the working directory cannot be changed to the root of the copy";
const CANNOT_LEAVE: Reason = "the working directory cannot be put back";
const CANNOT_MAKE: Reason = "the engine library cannot make a set of rules";
const FIXED_FAILED: Reason = "the engine library did not take the fixed directives";
const FILE_FAILED: Reason = "the engine library did not read the rule file";
const SETTINGS_DIFFER: Reason =
    "the engine settings that were read back are not the ones that are set";
const RULES_DIFFER: Reason =
    "the rules that the engine library built differ from what the checks of the rule files read";

/// Builds the rules of a generation. `root` is the root of the copy, which holds the files of the generation
/// at their paths, `files` the checked bytes of each of them, and `load` the rule files in the order they
/// are loaded. `restricted` is what `sandbox::restrict` gave the process that has restricted itself: the rules
/// are built only by such a process.
///
/// The rules are checked first (`guard`), on the bytes in `files`, which is what was checked against the
/// manifest, never on what is on the disk now. Then the library reads the files in the copy, each by its own
/// call, so that a failure names its file. The library finds a file that a rule names by looking from the
/// working directory first, which is the root of the copy while the library reads, and is `/` again when
/// this returns, whatever happened.
///
/// The process restricts itself (`sandbox::restrict`, to the directory that holds the copy) before it builds
/// the rules, so a text that gets past the checks and names a file elsewhere, to read or to write, is refused
/// by the library: it cannot open anything outside the copy. The proof that it has is an argument, so that
/// the order cannot be got wrong. What the library then built is compared with what the checks read
/// (`verify`), and a difference is a refusal.
///
/// The fixed directives are added before the files. When rules are added one after the other, the library
/// keeps the first value of a setting: a later `SecRuleEngine Off` in a file would not replace a
/// `SecRuleEngine On` that was added before it (inside one file, the later directive wins, so adding them
/// after would not do). The settings are read back, and a set of rules that does not hold the fixed ones is
/// refused. Then the rules that were built are looked at once more, with no help from the text (`verify`).
///
/// A process builds its rules once, and a failure ends it. The scanner of the library keeps state in
/// static variables that a read which failed can leave behind, so the next read in the same process may be
/// refused for no reason of its own; the inspector exits when it refuses a set of rules, so that never meets it.
pub fn build(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    load: &[String],
    _restricted: Restricted,
) -> Result<Rules, Refusal> {
    if !root.is_absolute() {
        return Err(Refusal::environment(NOT_ABSOLUTE));
    }
    if load.is_empty() {
        return Err(Refusal::rules(NO_RULE_FILE, None));
    }
    let mut markers = Markers::default();
    let mut model = Model::default();
    for path in load {
        let text = (files::is_path(path.as_bytes()))
            .then(|| files.get(path))
            .flatten()
            .ok_or(Refusal::rules(NOT_A_RULE_FILE, None))?;
        guard::check_file(path, text, files, &mut markers, &mut model)
            .map_err(|reason| Refusal::rules(reason, Some(path)))?;
    }
    markers
        .finish()
        .map_err(|(path, reason)| Refusal::rules(reason, Some(path)))?;
    assemble(root, load, &model)
}

/// What follows the checks of the text: the library reads the files, and the rules that it built are looked at.
/// The checks have been made; what they read is `model`.
pub(super) fn assemble(root: &Path, load: &[String], model: &Model) -> Result<Rules, Refusal> {
    let _directory = WORKING_DIRECTORY
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let read = env::set_current_dir(root)
        .map_err(|_| Refusal::environment(CANNOT_ENTER))
        .and_then(|()| read_rules(root, load));
    // The working directory is put back whether the rules were read or not.
    let left = env::set_current_dir("/");
    let rules = read?;
    left.map_err(|_| Refusal::environment(CANNOT_LEAVE))?;
    settle(rules, root, load, model)
}

/// What follows the reading of the library: the settings that it holds are read back, and the rules that it
/// built are looked at.
pub(super) fn settle(
    rules: Rules,
    root: &Path,
    load: &[String],
    model: &Model,
) -> Result<Rules, Refusal> {
    match rules.settings() {
        Ok(settings)
            if settings.engine == EngineState::On
                && settings.body_access == Some(true)
                && settings.json_depth_limit == Some(JSON_DEPTH_LIMIT) => {}
        _ => return Err(Refusal::rules(SETTINGS_DIFFER, None)),
    }
    verify(&rules, root, load, model)?;
    Ok(rules)
}

/// The second look at the rules that were built. The checks of the files read the text with a reader of
/// their own, and a text that the reader and the library read in two ways would pass them. So the library
/// is asked what it built. Every rule must come from one of the rule files, and none may be one that the
/// checks refuse. And what the library built must be what the reader read (`model`): the same rules, markers,
/// default actions and settings. A difference is a refusal that says so and quotes nothing from the rules.
pub(super) fn verify(
    rules: &Rules,
    root: &Path,
    load: &[String],
    model: &Model,
) -> Result<(), Refusal> {
    check_kinds(rules, root, load)?;
    compare(rules, model)
}

/// The rules must come from the rule files, and none may be of a kind that the checks refuse (a reserved id,
/// an action that is not allowed, a stop that leaves no message, a setting that must not be set).
pub(super) fn check_kinds(rules: &Rules, root: &Path, load: &[String]) -> Result<(), Refusal> {
    let files: Vec<PathBuf> = load.iter().map(|path| root.join(path)).collect();
    match rules.check(&files) {
        Ok(None) => Ok(()),
        _ => Err(Refusal::rules(RULES_DIFFER, None)),
    }
}

/// What the library built must be what the reader read.
pub(super) fn compare(rules: &Rules, model: &Model) -> Result<(), Refusal> {
    match rules.describe() {
        Ok(built) if built == model.encode() => Ok(()),
        _ => Err(Refusal::rules(RULES_DIFFER, None)),
    }
}

/// The library reads the fixed directives and then the files, with the working directory at the root of the
/// copy.
fn read_rules(root: &Path, load: &[String]) -> Result<Rules, Refusal> {
    let mut rules = Rules::new().map_err(|_| Refusal::environment(CANNOT_MAKE))?;
    rules
        .add_text(FIXED_DIRECTIVES)
        .map_err(|_| Refusal::environment(FIXED_FAILED))?;
    for path in load {
        // The path is a path of the generation (it was checked), so the file stays under the root. The
        // library is given an absolute path: it takes the directory of the rule file from it.
        rules.add_file(&root.join(path)).map_err(|e| match e {
            ffi::Error::Rules | ffi::Error::Internal => Refusal::rules(FILE_FAILED, Some(path)),
            _ => Refusal::environment(CANNOT_MAKE),
        })?;
    }
    Ok(rules)
}
