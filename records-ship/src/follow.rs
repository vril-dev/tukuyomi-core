//! The follower reads the lines of the record files in order, from a position, and goes on to the next file when a
//! file ends and a newer one exists.
//!
//! A position is a file by identity and the offset of the first byte not yet shipped. The identity is the inode and
//! the time at which the file was born: the proxy rotates the files by renaming them, so a file is found again by
//! its identity among the names a record file can have (`files::record_paths`), as the reader of the admin process
//! does, and the birth time tells it from a later file to which the file system gave the same inode number (a file
//! system reuses the number of a deleted file at once). A file that gives no birth time is an error.
//!
//! A rotation renames every file, one after the other, and a look that is under way meanwhile can miss a file: the
//! look goes from the oldest name to the newest, and a file moves to an older name. So the directory is taken as
//! seen only when two looks in a row agree on every name and every identity; if they do not, the look is repeated a
//! few times, and then the turn gives up (`Note::Unsettled`) and the next one tries again.
//!
//! The follower holds the file it reads open, and the newer files that it has found and not read yet. A file that
//! is removed from the directory while the follower holds it is still read to its end: the disk is held for no
//! more than that one file. A newer file that is removed before the follower has read it is lost, and the follower
//! counts its lines (it can, for it holds the file) in `lost_lines` and says so in a note. What it cannot count
//! is a loss it did not see: when the last file the follower knows of is not in the directory any more (the file of
//! the saved position after a restart, or the newest file it holds, for the proxy may have rotated more files than
//! it keeps while the database was out of reach), the files after it may have come and gone unseen. Their lines
//! are not known, and a note says that lines may be lost. The note comes also when nothing was lost, for the
//! follower cannot tell the two apart.
//!
//! `read` takes at most `max` whole lines from the position on and returns them with the position they lead to; it
//! changes nothing that the caller must undo. `accept` makes that position the one that the database has
//! committed. `resume` is for after the database was reached again: it keeps the files that are held, so that a file
//! the proxy rotated away meanwhile is still read to its end. A last line without its line feed is left for later
//! while its file is the newest, for the proxy may be writing it, and is taken as a line when a newer file exists,
//! for its file is closed. A line is cut at `RECORD_MAX` bytes, which no record the proxy writes reaches, and the
//! rest of it is left out and counted in a note. An empty line is skipped.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use tukuyomi_proxy::log::record::RECORD_MAX;
use tukuyomi_proxy::log::ship::Identity;

use crate::files;

/// The bytes read from a file at a time.
const CHUNK: usize = 64 * 1024;
/// How many times the directory is looked at again when two looks in a row do not agree, and the pause before each.
const RESCANS: usize = 3;
const RESCAN_WAIT: Duration = Duration::from_millis(30);

/// A place in the record files: a file by identity, the offset in it of the first byte not yet shipped, and the
/// lines found lost so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub identity: Identity,
    pub offset: u64,
    pub lost_lines: u64,
}

/// Lines to ship and the positions before and after them.
#[derive(Debug)]
pub struct Batch {
    pub lines: Vec<Vec<u8>>,
    /// The position that the database has now: `None` before the first batch.
    pub from: Option<Position>,
    pub to: Position,
}

/// Something that happened to the files, which the caller says in its log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// A file was removed before the follower read it: this many lines were lost.
    Lost(u64),
    /// This many lines were cut at `RECORD_MAX` bytes.
    Cut(u64),
    /// The saved position does not fit the file (it is shorter, or no line ends at the offset): the follower reads
    /// the file from its start.
    Rewound,
    /// The file of the saved position is not there: the follower reads from the oldest file there is, and lines may
    /// be lost.
    Gone,
    /// The newest file the follower holds is not in the directory any more: files after it may have been removed
    /// before the follower saw them. Lines may be lost, and `lost_lines` does not count them.
    Unseen,
    /// The directory changed during every one of the looks, so nothing was read this time.
    Unsettled,
}

/// An open record file and its identity.
struct Open {
    file: File,
    identity: Identity,
}

/// A record file that a look found, and which of the names of `files::record_paths` it had.
struct Found {
    name: usize,
    open: Open,
}

/// The reader of the record files in a directory.
pub struct Follower {
    dir: PathBuf,
    files: usize,
    chunk: usize,
    /// The position that the database has; `None` before the first batch.
    committed: Option<Position>,
    /// The file that is read now, and the offset in it of the next byte to read.
    current: Option<Open>,
    offset: u64,
    /// The files newer than the current one, the oldest first, as they were found at the last read.
    ahead: Vec<Open>,
    /// The lines found lost, those of the committed position included.
    lost: u64,
    notes: Vec<Note>,
}

impl Follower {
    /// A follower of the files in `dir` (at most `files` of them) that goes on from `committed`, or from the start
    /// of the oldest file if it is `None`.
    pub fn new(dir: &Path, files: usize, committed: Option<Position>) -> Follower {
        Follower {
            dir: dir.to_path_buf(),
            files,
            chunk: CHUNK,
            committed,
            current: None,
            offset: committed.map_or(0, |position| position.offset),
            ahead: Vec::new(),
            lost: committed.map_or(0, |position| position.lost_lines),
            notes: Vec::new(),
        }
    }

    /// Goes on from `committed`, the position that the database has now, after the database was reached again. The
    /// files that are held stay open when the position is the one the follower has or is in one of them (a batch
    /// whose answer was lost was committed all the same); only a position in no held file starts the follower anew.
    pub fn resume(&mut self, committed: Option<Position>) {
        if self.committed == committed || committed.is_some_and(|position| self.adopt(position)) {
            return;
        }
        *self = Follower {
            chunk: self.chunk,
            notes: std::mem::take(&mut self.notes),
            ..Follower::new(&self.dir, self.files, committed)
        };
    }

    /// The position that the database has.
    pub fn position(&self) -> Option<Position> {
        self.committed
    }

    /// What happened to the files since the last call.
    pub fn take_notes(&mut self) -> Vec<Note> {
        std::mem::take(&mut self.notes)
    }

    /// The record files that are in the directory now, the oldest first.
    fn scan(&self) -> io::Result<Vec<Found>> {
        let mut found: Vec<Found> = Vec::new();
        for (name, path) in files::record_paths(&self.dir, self.files)
            .iter()
            .enumerate()
        {
            let file = match files::open_record(path) {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let identity = Identity::of(&file.metadata()?).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a record file has no birth time",
                )
            })?;
            if found.iter().all(|seen| seen.open.identity != identity) {
                found.push(Found {
                    name,
                    open: Open { file, identity },
                });
            }
        }
        Ok(found)
    }

    /// The record files that are in the directory now, the oldest first, once two looks in a row show the same names
    /// and the same files. `None`: they did not agree in any of the looks.
    fn listing(&self) -> io::Result<Option<Vec<Open>>> {
        let mut before = self.scan()?;
        for attempt in 0..=RESCANS {
            let after = self.scan()?;
            let agree = before.len() == after.len()
                && before
                    .iter()
                    .zip(&after)
                    .all(|(a, b)| a.name == b.name && a.open.identity == b.open.identity);
            if agree {
                return Ok(Some(after.into_iter().map(|found| found.open).collect()));
            }
            before = after;
            if attempt < RESCANS {
                sleep(RESCAN_WAIT);
            }
        }
        Ok(None)
    }

    /// Looks at the directory and brings `current` and `ahead` up to date: finds the file of the position, takes
    /// the newer files that are there, and counts the lines of those that were removed unread. Nothing changes if
    /// a file cannot be read. False: the directory did not hold still, and nothing was done.
    fn settle(&mut self) -> io::Result<bool> {
        let Some(mut listing) = self.listing()? else {
            self.notes.push(Note::Unsettled);
            return Ok(false);
        };
        // The file to read from now on if there is none held: it and the offset in it; and what that says.
        let mut start: Option<(Open, u64)> = None;
        let (mut rewound, mut gone) = (false, false);
        // The newest file held is not in the directory: the files that came after it may have been removed unseen.
        // The files of the directory are held from now on, so this is said once for a loss.
        let unseen = self
            .ahead
            .last()
            .or(self.current.as_ref())
            .is_some_and(|last| {
                !listing.is_empty() && listing.iter().all(|open| open.identity != last.identity)
            });
        let tail = if let Some(current) = &self.current {
            // The files after the current one; all of them if the current one is not in the directory any more.
            let at = listing
                .iter()
                .position(|open| open.identity == current.identity);
            match at {
                Some(at) => listing.split_off(at + 1),
                None => listing,
            }
        } else {
            let found = self.committed.and_then(|committed| {
                listing
                    .iter()
                    .position(|open| open.identity == committed.identity)
            });
            if let Some(at) = found {
                let mut tail = listing.split_off(at);
                let first = tail.remove(0);
                rewound = !self.fits(&first.file, self.offset)?;
                start = Some((first, if rewound { 0 } else { self.offset }));
                tail
            } else if listing.is_empty() {
                listing
            } else {
                // Nothing was shipped yet, or the file of the position is gone: the oldest file, from its start.
                gone = self.committed.is_some();
                let tail = listing.split_off(1);
                start = listing.pop().map(|first| (first, 0));
                tail
            }
        };
        // A file that was newer and is not in the directory now was removed before it was read.
        let mut lost = 0;
        for held in &self.ahead {
            if tail.iter().all(|open| open.identity != held.identity) {
                lost += count_lines(&held.file, self.chunk)?;
            }
        }
        if let Some((open, offset)) = start {
            self.current = Some(open);
            self.offset = offset;
        }
        if rewound {
            self.notes.push(Note::Rewound);
        }
        if gone {
            self.notes.push(Note::Gone);
        }
        if unseen {
            self.notes.push(Note::Unseen);
        }
        if lost > 0 {
            self.lost = self.lost.saturating_add(lost);
            self.notes.push(Note::Lost(lost));
        }
        self.ahead = tail;
        Ok(true)
    }

    /// Whether `offset` is the end of a line of `file`, or the start of it: the saved position fits the file.
    fn fits(&self, file: &File, offset: u64) -> io::Result<bool> {
        if offset == 0 {
            return Ok(true);
        }
        if offset > file.metadata()?.len() {
            return Ok(false);
        }
        let mut last = [0u8; 1];
        Ok(file.read_exact_at(&mut last, offset - 1).is_ok() && last[0] == b'\n')
    }

    /// Takes at most `max` whole lines from the position on, in the current file and then in the newer ones. `None`:
    /// there is nothing to ship and the position stays.
    pub fn read(&mut self, max: usize) -> io::Result<Option<Batch>> {
        if !self.settle()? {
            return Ok(None);
        }
        let Some(current) = &self.current else {
            return Ok(None);
        };
        let mut out = Taken::default();
        let mut at: Option<usize> = None;
        let mut identity = current.identity;
        let mut offset = self.offset;
        loop {
            let (file, newer) = match at {
                None => (&current.file, self.ahead.len()),
                Some(i) => (&self.ahead[i].file, self.ahead.len() - i - 1),
            };
            let len = file.metadata()?.len();
            if at.is_none() && offset > len {
                // The current file is shorter than the position: it was cut, or it is another file.
                offset = 0;
                self.offset = 0;
                self.notes.push(Note::Rewound);
            }
            let room = max - out.lines.len();
            offset = read_lines(file, offset, len, room, newer > 0, self.chunk, &mut out)?;
            if out.lines.len() >= max || newer == 0 {
                break;
            }
            // This file is done and a newer one exists.
            let next = at.map_or(0, |i| i + 1);
            identity = self.ahead[next].identity;
            at = Some(next);
            offset = 0;
        }
        if out.cut > 0 {
            self.notes.push(Note::Cut(out.cut));
        }
        let to = Position {
            identity,
            offset,
            lost_lines: self.lost,
        };
        if out.lines.is_empty() && self.committed == Some(to) {
            return Ok(None);
        }
        Ok(Some(Batch {
            lines: out.lines,
            from: self.committed,
            to,
        }))
    }

    /// The database has committed `batch`: its position is the one to go on from.
    pub fn accept(&mut self, batch: &Batch) {
        // The batch was read from the held files, so its position is in one of them.
        self.adopt(batch.to);
    }

    /// Goes on from `position` if its file is the current one or one of the newer ones that are held. The files
    /// before it are done with. False: it is in no held file, and nothing changed.
    fn adopt(&mut self, position: Position) -> bool {
        let here = self
            .current
            .as_ref()
            .is_some_and(|current| current.identity == position.identity);
        if !here {
            let Some(at) = self
                .ahead
                .iter()
                .position(|open| open.identity == position.identity)
            else {
                return false;
            };
            self.current = self.ahead.drain(..=at).next_back();
        }
        self.offset = position.offset;
        self.lost = self.lost.max(position.lost_lines);
        self.committed = Some(position);
        true
    }
}

/// The lines taken from the files, and how many of them were cut.
#[derive(Default)]
struct Taken {
    lines: Vec<Vec<u8>>,
    cut: u64,
}

/// Appends to `out` the whole lines of `file` from `offset`, at most `room`, and returns the offset after the last
/// line taken. `len` is the length of the file that was seen. When `closed` is true the file gets no more bytes, so
/// a last line without a line feed is taken too and the offset is `len`. A line over `RECORD_MAX` bytes is cut
/// there and counted in `out.cut`; an empty line is skipped.
fn read_lines(
    file: &File,
    offset: u64,
    len: u64,
    room: usize,
    closed: bool,
    chunk: usize,
    out: &mut Taken,
) -> io::Result<u64> {
    let mut buffer = vec![0u8; chunk.max(1)];
    let mut line: Vec<u8> = Vec::new();
    let mut overlong = false;
    let mut position = offset;
    let mut taken = offset;
    let mut left = room;
    // Adds the bytes of one chunk to the line being put together, up to `RECORD_MAX`.
    let append = |line: &mut Vec<u8>, overlong: &mut bool, part: &[u8]| {
        if !*overlong {
            let space = RECORD_MAX - line.len();
            if part.len() > space {
                line.extend_from_slice(&part[..space]);
                *overlong = true;
            } else {
                line.extend_from_slice(part);
            }
        }
    };
    while left > 0 && position < len {
        let want = usize::try_from(len - position).map_or(buffer.len(), |n| n.min(buffer.len()));
        let got = file.read_at(&mut buffer[..want], position)?;
        if got == 0 {
            // The file is shorter than it was seen to be.
            break;
        }
        let mut start = 0;
        while start < got {
            let Some(n) = buffer[start..got].iter().position(|&b| b == b'\n') else {
                append(&mut line, &mut overlong, &buffer[start..got]);
                break;
            };
            append(&mut line, &mut overlong, &buffer[start..start + n]);
            start += n + 1;
            taken = position + start as u64;
            if overlong {
                out.cut += 1;
            }
            if !line.is_empty() {
                out.lines.push(std::mem::take(&mut line));
                left -= 1;
            }
            overlong = false;
            if left == 0 {
                return Ok(taken);
            }
        }
        position += got as u64;
    }
    if closed && position >= len && (!line.is_empty() || overlong) {
        if overlong {
            out.cut += 1;
        }
        out.lines.push(line);
        taken = len;
    }
    Ok(taken)
}

/// The lines of `file`: its line feeds, and one more for a last line that has none.
fn count_lines(file: &File, chunk: usize) -> io::Result<u64> {
    let len = file.metadata()?.len();
    let mut buffer = vec![0u8; chunk.max(1)];
    let mut position = 0u64;
    let mut count = 0u64;
    let mut last = b'\n';
    while position < len {
        let want = usize::try_from(len - position).map_or(buffer.len(), |n| n.min(buffer.len()));
        let got = file.read_at(&mut buffer[..want], position)?;
        if got == 0 {
            break;
        }
        count += buffer[..got].iter().filter(|&&b| b == b'\n').count() as u64;
        last = buffer[got - 1];
        position += got as u64;
    }
    Ok(count + u64::from(last != b'\n'))
}

#[cfg(test)]
mod tests;
