use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

use tukuyomi_proxy::log::sink::RecordFile;

use super::*;

/// A fresh 0700 directory under the temp directory, removed with everything in it when dropped.
struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-ship-follow-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    TestDir(dir)
}

fn put(dir: &TestDir, name: &str, text: &str) {
    fs::write(dir.0.join(name), text).unwrap();
}

fn append(dir: &TestDir, name: &str, text: &str) {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(dir.0.join(name))
        .unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

fn identity(dir: &TestDir, name: &str) -> Identity {
    Identity::of(&fs::metadata(dir.0.join(name)).unwrap()).unwrap()
}

fn follower(dir: &TestDir) -> Follower {
    follower_of(dir, 4)
}

fn follower_of(dir: &TestDir, files: usize) -> Follower {
    Follower::new(&dir.0, files, None)
}

/// The lines of a batch as text.
fn texts(batch: &Batch) -> Vec<String> {
    batch
        .lines
        .iter()
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect()
}

/// Reads, and accepts what was read.
fn take(follower: &mut Follower, max: usize) -> Vec<String> {
    match follower.read(max).unwrap() {
        Some(batch) => {
            follower.accept(&batch);
            texts(&batch)
        }
        None => Vec::new(),
    }
}

#[test]
fn lines_that_cross_the_reads_are_whole() {
    let dir = scratch();
    put(&dir, "records.log", "alpha\nbravo-long-line\ncharlie\n");
    let mut follower = follower(&dir);
    follower.chunk = 7;
    let batch = follower.read(10).unwrap().unwrap();
    assert_eq!(texts(&batch), ["alpha", "bravo-long-line", "charlie"]);
    assert_eq!(batch.from, None);
    assert_eq!(batch.to.offset, 30);
    assert_eq!(batch.to.identity, identity(&dir, "records.log"));
}

#[test]
fn a_batch_ends_at_its_limit_and_the_next_goes_on() {
    let dir = scratch();
    put(&dir, "records.log", "a\nb\nc\n");
    let mut follower = follower(&dir);
    let batch = follower.read(2).unwrap().unwrap();
    assert_eq!(texts(&batch), ["a", "b"]);
    assert_eq!(batch.to.offset, 4);
    // Not accepted: the same lines come again.
    assert_eq!(texts(&follower.read(2).unwrap().unwrap()), ["a", "b"]);
    follower.accept(&batch);
    let next = follower.read(2).unwrap().unwrap();
    assert_eq!(texts(&next), ["c"]);
    assert_eq!(next.from, Some(batch.to));
    follower.accept(&next);
    assert!(follower.read(2).unwrap().is_none());
}

#[test]
fn a_last_line_without_its_line_feed_waits() {
    let dir = scratch();
    put(&dir, "records.log", "one\ntwo");
    let mut follower = follower(&dir);
    assert_eq!(take(&mut follower, 10), ["one"]);
    assert_eq!(follower.position().unwrap().offset, 4);
    assert!(follower.read(10).unwrap().is_none());
    append(&dir, "records.log", "-done\n");
    assert_eq!(take(&mut follower, 10), ["two-done"]);
    assert_eq!(follower.position().unwrap().offset, 13);
}

#[test]
fn a_file_with_a_newer_one_gives_its_last_line() {
    let dir = scratch();
    put(&dir, "records.1.log", "one\ntwo");
    put(&dir, "records.log", "three\n");
    let mut follower = follower(&dir);
    assert_eq!(take(&mut follower, 10), ["one", "two", "three"]);
    assert_eq!(
        follower.position().unwrap().identity,
        identity(&dir, "records.log")
    );
}

#[test]
fn a_rotation_by_rename_is_followed_by_inode() {
    let dir = scratch();
    put(&dir, "records.log", "a\nb\n");
    let mut follower = follower(&dir);
    assert_eq!(take(&mut follower, 1), ["a"]);
    // The proxy renames the file in use and opens a new one.
    fs::rename(dir.0.join("records.log"), dir.0.join("records.1.log")).unwrap();
    put(&dir, "records.log", "c\n");
    assert_eq!(take(&mut follower, 10), ["b", "c"]);
    let position = follower.position().unwrap();
    assert_eq!(position.identity, identity(&dir, "records.log"));
    assert_eq!(position.offset, 2);
    assert_eq!(position.lost_lines, 0);
    // A second rotation moves the file again; nothing is read twice.
    fs::rename(dir.0.join("records.1.log"), dir.0.join("records.2.log")).unwrap();
    fs::rename(dir.0.join("records.log"), dir.0.join("records.1.log")).unwrap();
    put(&dir, "records.log", "d\n");
    assert_eq!(take(&mut follower, 10), ["d"]);
}

#[test]
fn a_restart_finds_its_file_under_another_name() {
    let dir = scratch();
    put(&dir, "records.log", "a\nb\n");
    let mut first = follower(&dir);
    assert_eq!(take(&mut first, 1), ["a"]);
    let saved = first.position();
    drop(first);
    fs::rename(dir.0.join("records.log"), dir.0.join("records.2.log")).unwrap();
    put(&dir, "records.log", "c\n");
    let mut second = Follower::new(&dir.0, 4, saved);
    assert_eq!(take(&mut second, 10), ["b", "c"]);
    assert!(second.take_notes().is_empty());
}

#[test]
fn a_file_that_is_removed_before_it_is_read_is_counted() {
    let dir = scratch();
    put(&dir, "records.1.log", "x\ny\n");
    put(&dir, "records.log", "p\nq\nr");
    let mut follower = follower(&dir);
    // The first read lists the newer file.
    assert_eq!(take(&mut follower, 1), ["x"]);
    fs::remove_file(dir.0.join("records.log")).unwrap();
    let batch = follower.read(10).unwrap().unwrap();
    assert_eq!(texts(&batch), ["y"]);
    // The three lines of the file, the last one without a line feed.
    assert_eq!(batch.to.lost_lines, 3);
    // The newest file held is gone, so the follower also says that files may have gone unseen.
    assert_eq!(follower.take_notes(), [Note::Unseen, Note::Lost(3)]);
    follower.accept(&batch);
    assert_eq!(follower.position().unwrap().lost_lines, 3);
    // Once counted it is not counted again.
    assert!(follower.read(10).unwrap().is_none());
    assert!(follower.take_notes().is_empty());
}

#[test]
fn the_file_being_read_is_read_to_its_end_after_it_is_removed() {
    let dir = scratch();
    put(&dir, "records.log", "a\nb\n");
    let mut follower = follower(&dir);
    assert_eq!(take(&mut follower, 1), ["a"]);
    fs::remove_file(dir.0.join("records.log")).unwrap();
    put(&dir, "records.log", "c\n");
    // The held file gives its last line, and the new one follows. Nothing is counted lost, but the follower cannot
    // know that no file went unseen between the two, and says so.
    assert_eq!(take(&mut follower, 10), ["b", "c"]);
    assert_eq!(follower.position().unwrap().lost_lines, 0);
    assert_eq!(follower.take_notes(), [Note::Unseen]);
}

#[test]
fn a_saved_position_in_a_file_that_is_gone_starts_at_the_oldest_file() {
    let dir = scratch();
    put(&dir, "records.1.log", "old\n");
    put(&dir, "records.log", "new\n");
    let saved = Position {
        identity: Identity {
            inode: u64::MAX,
            born: 1,
        },
        offset: 5,
        lost_lines: 2,
    };
    let mut follower = Follower::new(&dir.0, 4, Some(saved));
    let batch = follower.read(10).unwrap().unwrap();
    assert_eq!(texts(&batch), ["old", "new"]);
    assert_eq!(batch.from, Some(saved));
    // The lost lines of before stay counted; the lines of the gone file are not known.
    assert_eq!(batch.to.lost_lines, 2);
    assert_eq!(follower.take_notes(), [Note::Gone]);
}

#[test]
fn a_position_that_does_not_fit_its_file_starts_the_file_again() {
    let dir = scratch();
    put(&dir, "records.log", "ab\ncd\n");
    let id = identity(&dir, "records.log");
    let at = |offset| Position {
        identity: id,
        offset,
        lost_lines: 0,
    };
    // Past the end, and inside a line: another file with the same inode number, or one that was cut.
    for offset in [100, 2] {
        let mut follower = Follower::new(&dir.0, 4, Some(at(offset)));
        assert_eq!(
            texts(&follower.read(10).unwrap().unwrap()),
            ["ab", "cd"],
            "{offset}"
        );
        assert_eq!(follower.take_notes(), [Note::Rewound], "{offset}");
    }
    // At the end of a line it goes on.
    let mut follower = Follower::new(&dir.0, 4, Some(at(3)));
    assert_eq!(texts(&follower.read(10).unwrap().unwrap()), ["cd"]);
    assert!(follower.take_notes().is_empty());
}

#[test]
fn a_file_that_becomes_shorter_is_read_from_its_start() {
    let dir = scratch();
    put(&dir, "records.log", "aaaa\nbbbb\n");
    let mut follower = follower(&dir);
    assert_eq!(take(&mut follower, 10), ["aaaa", "bbbb"]);
    put(&dir, "records.log", "c\n");
    assert_eq!(take(&mut follower, 10), ["c"]);
    assert_eq!(follower.take_notes(), [Note::Rewound]);
}

#[test]
fn a_line_over_the_limit_is_cut_and_the_next_is_whole() {
    let dir = scratch();
    let long = "x".repeat(RECORD_MAX + 100);
    put(&dir, "records.log", &format!("{long}\nshort\n"));
    let mut follower = follower(&dir);
    follower.chunk = 1000;
    let batch = follower.read(10).unwrap().unwrap();
    assert_eq!(batch.lines.len(), 2);
    assert_eq!(batch.lines[0].len(), RECORD_MAX);
    assert_eq!(batch.lines[1], b"short");
    assert_eq!(follower.take_notes(), [Note::Cut(1)]);
    // The longest line that is not cut.
    let exact = "y".repeat(RECORD_MAX);
    put(&dir, "records.log", &format!("{exact}\n"));
    let mut follower = Follower::new(&dir.0, 4, None);
    let batch = follower.read(10).unwrap().unwrap();
    assert_eq!(batch.lines[0].len(), RECORD_MAX);
    assert!(follower.take_notes().is_empty());
}

#[test]
fn empty_lines_are_skipped_and_passed() {
    let dir = scratch();
    put(&dir, "records.log", "a\n\n\nb\n");
    let mut follower = follower(&dir);
    let batch = follower.read(10).unwrap().unwrap();
    assert_eq!(texts(&batch), ["a", "b"]);
    assert_eq!(batch.to.offset, 6);
}

#[test]
fn no_files_is_nothing_to_do() {
    let dir = scratch();
    let mut follower = follower(&dir);
    assert!(follower.read(10).unwrap().is_none());
    // An empty file gives a position and no lines.
    put(&dir, "records.log", "");
    let batch = follower.read(10).unwrap().unwrap();
    assert!(batch.lines.is_empty());
    assert_eq!(batch.to.offset, 0);
}

#[test]
fn a_file_with_the_inode_of_the_saved_one_but_another_birth_is_another_file() {
    let dir = scratch();
    put(&dir, "records.log", "one\ntwo\nthree\n");
    let here = identity(&dir, "records.log");
    // The saved position is in a file that was deleted, and the file system gave its inode to this one.
    let saved = Position {
        identity: Identity {
            born: here.born + 1,
            ..here
        },
        offset: 8,
        lost_lines: 0,
    };
    let mut follower = Follower::new(&dir.0, 4, Some(saved));
    // The file is not taken for the one of the position: it is read from its start, and the follower says so.
    assert_eq!(
        texts(&follower.read(10).unwrap().unwrap()),
        ["one", "two", "three"]
    );
    assert_eq!(follower.take_notes(), [Note::Gone]);
    // The same file with its own birth time is the one: the follower goes on after the offset.
    let mut follower = Follower::new(
        &dir.0,
        4,
        Some(Position {
            identity: here,
            ..saved
        }),
    );
    assert_eq!(texts(&follower.read(10).unwrap().unwrap()), ["three"]);
    assert!(follower.take_notes().is_empty());
}

#[test]
fn the_held_files_stay_when_the_database_is_reached_again() {
    let dir = scratch();
    put(&dir, "records.log", "a\nb\n");
    let mut follower = follower(&dir);
    assert_eq!(take(&mut follower, 1), ["a"]);
    // The proxy rotates the held file away while the database is out of reach: it is gone from the directory.
    fs::remove_file(dir.0.join("records.log")).unwrap();
    put(&dir, "records.log", "c\n");
    follower.resume(follower.position());
    // The held file is read to its end first, and nothing is counted lost.
    assert_eq!(take(&mut follower, 10), ["b", "c"]);
    assert_eq!(follower.position().unwrap().lost_lines, 0);
    assert_eq!(follower.take_notes(), [Note::Unseen]);
}

#[test]
fn a_batch_that_the_database_committed_without_the_answer_is_not_read_again() {
    let dir = scratch();
    put(&dir, "records.1.log", "x\n");
    put(&dir, "records.log", "y\nz\n");
    let mut follower = follower(&dir);
    // The batch reaches into the newer file; the database commits it but the answer is lost.
    let batch = follower.read(10).unwrap().unwrap();
    assert_eq!(texts(&batch), ["x", "y", "z"]);
    follower.resume(Some(batch.to));
    assert!(follower.read(10).unwrap().is_none());
    append(&dir, "records.log", "w\n");
    let next = follower.read(10).unwrap().unwrap();
    assert_eq!(texts(&next), ["w"]);
    assert_eq!(next.from, Some(batch.to));
    // A position in no held file starts the follower anew, from the file of the position.
    let mut other = Follower::new(&dir.0, 4, None);
    let first = other.read(1).unwrap().unwrap();
    other.accept(&first);
    follower.resume(other.position());
    assert_eq!(take(&mut follower, 10), ["y", "z", "w"]);
}

/// The proxy writes eight short lines (`s0` to `s7`, a file holds about ten) and then `rotations` long ones (`b0` and
/// on, a file holds one) while nothing is read, after the follower has read `s0` to `s2` of the first file and holds
/// it. Gives the lines that the next read takes, the notes of that read, and the lost lines the position counts;
/// and sees to it that a second read says nothing more.
fn read_after_rotations(rotations: usize) -> (String, Vec<Note>, u64) {
    let dir = scratch();
    let mut writer = RecordFile::open_in("records", &dir.0, 1000, 4).unwrap();
    for n in 0..8 {
        assert!(writer.append(format!("s{n} {}\n", "x".repeat(96)).as_bytes()));
    }
    let mut follower = follower_of(&dir, 4);
    assert_eq!(take(&mut follower, 3).len(), 3);
    for n in 0..rotations {
        assert!(writer.append(format!("b{n} {}\n", "y".repeat(596)).as_bytes()));
    }
    let lines = take(&mut follower, 100);
    let notes = follower.take_notes();
    assert!(follower.read(100).unwrap().is_none());
    assert!(follower.take_notes().is_empty());
    let names: Vec<&str> = lines
        .iter()
        .map(|line| line.split(' ').next().unwrap())
        .collect();
    (
        names.join(" "),
        notes,
        follower.position().unwrap().lost_lines,
    )
}

#[test]
fn files_that_may_have_gone_unseen_are_reported() {
    // The held file is renamed to the last name the proxy keeps: it is still there, and nothing is said.
    assert_eq!(
        read_after_rotations(3),
        ("s3 s4 s5 s6 s7 b0 b1 b2".to_owned(), vec![], 0)
    );
    // One rotation more removes it. All the files that are left are newer than it, but the follower cannot know
    // that none came and went before them, so it says that lines may be lost, though none was.
    assert_eq!(
        read_after_rotations(4),
        (
            "s3 s4 s5 s6 s7 b0 b1 b2 b3".to_owned(),
            vec![Note::Unseen],
            0
        )
    );
    // After seven, `b0` to `b2` are gone and were never seen: the rest of the held file and the files that are
    // left are read, the lines of the three are not known, and the position does not count them.
    assert_eq!(
        read_after_rotations(7),
        (
            "s3 s4 s5 s6 s7 b3 b4 b5 b6".to_owned(),
            vec![Note::Unseen],
            0
        )
    );
}

/// The record files are rotated as fast as the proxy rotates them (a file for each line, and the most files), while
/// the follower reads them with pauses in which several rotations happen: every line must come out once, in order,
/// and none may be said to be lost. The writer is the proxy's own, so the order of the renames is its own.
#[test]
fn rotations_during_the_looks_lose_and_repeat_nothing() {
    const LINES: usize = 1500;
    // The follower is never allowed more than this many lines behind: the files hold more than that.
    const AHEAD: usize = 40;
    let dir = scratch();
    let written = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(AtomicUsize::new(0));
    let writer = {
        let (path, written, seen) = (dir.0.clone(), written.clone(), seen.clone());
        thread::spawn(move || {
            // A line is about 100 bytes and a file takes 150: a rotation for each line.
            let mut file = RecordFile::open_in("records", &path, 150, 64).unwrap();
            for n in 0..LINES {
                while n >= seen.load(Ordering::Acquire) + AHEAD {
                    thread::sleep(Duration::from_micros(200));
                }
                assert!(file.append(
                    format!("{{\"n\":{n:06},\"pad\":\"{}\"}}\n", "x".repeat(80)).as_bytes()
                ));
                written.store(n + 1, Ordering::Release);
                thread::sleep(Duration::from_micros(500));
            }
        })
    };
    let mut follower = follower_of(&dir, 64);
    let mut got: Vec<String> = Vec::new();
    let mut notes = Vec::new();
    let started = Instant::now();
    // Until the writer is done and the follower has nothing more.
    let mut idle = 0;
    while idle < 3 {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "got {} lines",
            got.len()
        );
        match follower.read(100).unwrap() {
            Some(batch) => {
                follower.accept(&batch);
                got.extend(texts(&batch));
                idle = 0;
            }
            None if written.load(Ordering::Acquire) == LINES => idle += 1,
            None => {}
        }
        notes.extend(follower.take_notes());
        seen.store(got.len(), Ordering::Release);
        thread::sleep(Duration::from_millis(3));
    }
    writer.join().unwrap();
    for (n, line) in got.iter().enumerate() {
        assert!(
            line.starts_with(&format!("{{\"n\":{n:06},")),
            "line {n} is {line}"
        );
    }
    assert_eq!(got.len(), LINES);
    notes.retain(|note| *note != Note::Unsettled);
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(follower.position().unwrap().lost_lines, 0);
}
