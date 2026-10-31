//! The start-up checks of the operator's rules, and the building of the rules from the copy.
//!
//! `build` checks each rule file of the generation (`guard`, which reads the file with the reader (`reader`),
//! and the files that the rules read, `files`, and the `skipAfter` names, `markers`) and then has
//! libmodsecurity read the files in the copy, and looks at the rules that it built (`load`). What the reader
//! read is kept in a model (`model`, with the settings in `settings`), and the rules that the library built have to
//! be what the model holds, written as the same text (`describe`): the two readers of the one text cannot
//! differ without the build refusing it.
//!
//! What the library does when a setting is absent, taken from its source (version 3.0.17), is why the
//! inspector counts the body and the arguments itself and why a directive that sets one is refused
//! (`directive`). The request body limit (`SecRequestBodyLimit`) is 0, which the library reads as no limit.
//! The limit of a body without files (`SecRequestBodyNoFilesLimit`) and the limit of the arguments
//! (`SecArgumentsLimit`) are not set, which is no limit. The action at the body limit
//! (`SecRequestBodyLimitAction`) is not set, and matters only when a limit is set. With none of the four
//! present, the library never reads less of a request than the inspector passes to it, and the limits of
//! the inspector are the only ones.

mod describe;
mod files;
mod guard;
mod load;
mod markers;
mod model;
mod reader;
mod refusal;
mod settings;

pub use load::build;
pub use refusal::{EXIT_ENVIRONMENT, EXIT_RULES, Refusal};

#[cfg(test)]
mod tests;
