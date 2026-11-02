#![forbid(unsafe_code)]
//! The records shipper: copies the record files of the proxy into a database, in order, and keeps its place so that
//! it can stop and start again, or lose the database for a while, and go on from where it was. The place goes into
//! the database in the same transaction as the lines, and each line is stored under a hash that is unique in the
//! table, so a restart does not store a line a second time.
//!
//! What it does not promise:
//!
//! - Lines the proxy rotates away before the shipper has read them are lost. When the shipper held the file, it
//!   counts the lines in `lost_lines` of the position; when it never saw the file, it can only say in its log that
//!   lines may be lost, and the count does not include them.
//! - Lines with the same bytes are one row, because of the unique hash.
//! - A record file that is cut short in place (what `copytruncate` of a tool that rotates logs does) is not
//!   followed: the proxy rotates by renaming, and a file that grows past the saved position again before the
//!   shipper looks is taken for the same file, so its first lines are not shipped.
//! - Old rows are removed (`retention_days`) by the time written in the record, which is the clock of the proxy.
//!
//! The parts, one file each: `run` (the process: arguments, configuration, signals, notices to the service
//! manager), `dsn` (the file with the connection string), `files` (the record files and the position file as the
//! proxy names and writes them), `follow` (the reader of the record files, by inode, birth time and offset, through rotations),
//! `row` (a line as the columns of the table), `store` (the database behind a trait, and its drivers `store::pgsql` and
//! `store::mysql`), and `ship` (the loop that ties them together).
//!
//! The shipper runs as a process of its own, apart from the proxy: the database client and its dependencies are in
//! this executable and not in the one that takes requests from outside, and the password of the database is known
//! to this process only.

pub mod dsn;
pub mod files;
pub mod follow;
pub mod row;
pub mod run;
pub mod ship;
pub mod store;
