use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::log::{Format, open, run};

/// A fresh 0700 directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-sink-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    // A umask can only remove bits; make the mode exactly 0700.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
}

/// The name of the file in use while the older files are renamed up by one.
const MOVING: &str = "records.rotating";

fn config(dir: &Path, file_bytes: u64, files: usize) -> RecordsConfig {
    RecordsConfig {
        dir: dir.to_path_buf(),
        file_bytes,
        files,
    }
}

fn opened(dir: &Path, file_bytes: u64, files: usize) -> RecordFile {
    match RecordFile::open(&config(dir, file_bytes, files)) {
        Ok(file) => file,
        Err(why) => panic!("the file was refused: {why}"),
    }
}

/// A line of 30 bytes with its line feed.
fn line(n: usize) -> String {
    format!("line {n:02} {}\n", "x".repeat(21))
}

fn lines(numbers: &[usize]) -> String {
    numbers.iter().map(|&n| line(n)).collect()
}

fn read(dir: &Path, name: &str) -> String {
    fs::read_to_string(dir.join(name)).unwrap()
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn names(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    found.sort();
    found
}

/// A record file whose file in use takes no write: `/dev/full` answers every write with "no space left".
fn full(dir: &Path, file_bytes: u64, files: usize) -> RecordFile {
    let mut file = opened(dir, file_bytes, files);
    file.current = Some(Current {
        file: OpenOptions::new().write(true).open("/dev/full").unwrap(),
        size: 0,
        id: (0, 0),
    });
    file
}

#[test]
fn the_file_is_made_with_mode_0600_and_the_rotation_keeps_the_count_with_whole_lines_and_drops_the_oldest()
 {
    let dir = scratch();
    let mut file = opened(dir.path(), 100, 3);
    assert_eq!(
        fs::metadata(dir.path().join("records.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    for n in 0..20 {
        assert!(file.append(line(n).as_bytes()));
    }
    assert_eq!(
        names(dir.path()),
        ["records.1.log", "records.2.log", "records.log"]
    );
    assert_eq!(read(dir.path(), "records.log"), lines(&[18, 19]));
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[15, 16, 17]));
    assert_eq!(read(dir.path(), "records.2.log"), lines(&[12, 13, 14]));
}

#[test]
fn a_file_may_reach_the_size_and_the_line_past_it_starts_the_next_one() {
    let dir = scratch();
    // Three lines are 90 bytes: they fill the file, and the fourth is the first past it. Two files are kept.
    let mut file = opened(dir.path(), 90, 2);
    for n in 0..4 {
        assert!(file.append(line(n).as_bytes()));
    }
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[0, 1, 2]));
    assert_eq!(read(dir.path(), "records.log"), lines(&[3]));
    for n in 4..7 {
        assert!(file.append(line(n).as_bytes()));
    }
    assert_eq!(names(dir.path()), ["records.1.log", "records.log"]);
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[3, 4, 5]));
    assert_eq!(read(dir.path(), "records.log"), lines(&[6]));
    // A line longer than the size is the only one in its file.
    let tiny = scratch();
    let mut small = opened(tiny.path(), 20, 2);
    assert!(small.append(line(0).as_bytes()));
    assert!(small.append(line(1).as_bytes()));
    assert_eq!(read(tiny.path(), "records.1.log"), lines(&[0]));
    assert_eq!(read(tiny.path(), "records.log"), lines(&[1]));
}

#[test]
fn an_existing_file_is_continued_and_rotated_when_the_next_line_does_not_fit() {
    let dir = scratch();
    fs::write(dir.path().join("records.log"), lines(&[0, 1, 2])).unwrap();
    let mut file = opened(dir.path(), 100, 2);
    assert!(file.append(line(3).as_bytes()));
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[0, 1, 2]));
    assert_eq!(read(dir.path(), "records.log"), lines(&[3]));
}

#[test]
fn the_directory_and_the_file_are_looked_at_before_anything_is_written() {
    let dir = scratch();
    let refused = |dir: &Path| RecordFile::open(&config(dir, 100, 2)).err();

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        refused(dir.path()),
        Some("the directory has group or other permission bits")
    );
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        refused(&dir.path().join("absent")),
        Some("the directory cannot be read")
    );
    let other = scratch();
    symlink(dir.path(), other.path().join("link")).unwrap();
    assert_eq!(
        refused(&other.path().join("link")),
        Some("the directory is not a real directory")
    );

    // A link, a FIFO or a directory in place of the file; the FIFO must not make the open wait.
    let file = dir.path().join("records.log");
    let cannot = Some("the record file cannot be opened");
    symlink("/dev/null", &file).unwrap();
    assert_eq!(refused(dir.path()), cannot);
    fs::remove_file(&file).unwrap();
    let made = Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(&file)
        .status();
    assert!(made.unwrap().success());
    assert_eq!(refused(dir.path()), cannot);
    fs::remove_file(&file).unwrap();
    fs::create_dir(&file).unwrap();
    assert_eq!(refused(dir.path()), cannot);
    fs::remove_dir(&file).unwrap();

    // A regular file of another user (a user id the owner does not have; the real one cannot be made).
    assert!(opened(dir.path(), 100, 2).current.is_some());
    let uid = host::fs_uid().unwrap();
    assert_eq!(
        open_current(dir.path(), RECORDS, uid.wrapping_add(1)).err(),
        Some("the record file is not a regular file of this user")
    );
}

#[test]
fn a_write_that_fails_is_counted_apart_and_the_standard_error_still_has_the_line() {
    let dir = scratch();
    let (log, items) = open(8);
    assert!(log.attach(full(dir.path(), 100, 2)));
    log.line("one");
    log.line("two");
    let counts = log.counts.clone();
    drop(log);
    let mut out = Vec::new();
    run(&items, &counts, Format::Json, &mut out);
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.lines().next().unwrap().ends_with("\"line\":\"one\"}"));
    assert_eq!(counts.write_errors.load(Ordering::Relaxed), 0);
    assert_eq!(counts.dropped.load(Ordering::Relaxed), 0);
    assert!(counts.file_errors.load(Ordering::Relaxed) >= 1);
}

#[test]
fn the_json_form_writes_the_file_after_the_standard_error_and_the_text_form_never_does() {
    let dir = scratch();
    for (format, written) in [(Format::Text, false), (Format::Json, true)] {
        let (log, items) = open(8);
        log.line("before");
        assert!(log.attach(opened(dir.path(), 4096, 2)));
        log.line("after");
        let counts = log.counts.clone();
        drop(log);
        let mut out = Vec::new();
        run(&items, &counts, format, &mut out);
        let kept = read(dir.path(), "records.log");
        if written {
            // The same line as the standard error got, and only what came after the file was handed over.
            let last = String::from_utf8(out)
                .unwrap()
                .lines()
                .last()
                .unwrap()
                .to_string();
            assert_eq!(kept, format!("{last}\n"));
            assert!(kept.contains("\"line\":\"after\""), "{kept}");
        } else {
            assert_eq!(kept, "");
        }
        assert_eq!(counts.file_errors.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn the_file_is_opened_again_only_a_second_after_a_failure() {
    let dir = scratch();
    let mut file = full(dir.path(), 100, 2);
    let t0 = Instant::now();
    // The write fails and the file is closed; what comes within the second is lost for the file without a try.
    assert!(!file.append_at(line(0).as_bytes(), t0));
    assert!(file.current.is_none());
    assert!(!file.append_at(line(1).as_bytes(), t0 + Duration::from_millis(999)));
    assert!(file.current.is_none());
    assert!(file.append_at(line(2).as_bytes(), t0 + Duration::from_secs(1)));
    assert_eq!(read(dir.path(), "records.log"), lines(&[2]));
}

#[test]
fn a_rename_that_fails_loses_the_line_and_the_rotation_is_tried_again_a_second_later() {
    let dir = scratch();
    let mut file = opened(dir.path(), 100, 2);
    for n in 0..3 {
        assert!(file.append(line(n).as_bytes()));
    }
    // The fourth line does not fit, and the directory takes no new name.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let t0 = Instant::now();
    assert!(!file.append_at(line(3).as_bytes(), t0));
    assert!(!file.append_at(line(4).as_bytes(), t0 + Duration::from_millis(500)));
    // A second later the full file is opened again and the rename fails again.
    assert!(!file.append_at(line(5).as_bytes(), t0 + Duration::from_secs(1)));
    assert_eq!(read(dir.path(), "records.log"), lines(&[0, 1, 2]));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(file.append_at(line(6).as_bytes(), t0 + Duration::from_secs(2)));
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[0, 1, 2]));
    assert_eq!(read(dir.path(), "records.log"), lines(&[6]));
}

#[test]
fn a_file_that_is_removed_or_replaced_is_noticed_within_a_second_and_a_new_one_is_made() {
    let dir = scratch();
    let path = dir.path().join("records.log");
    let mut file = opened(dir.path(), 1000, 2);
    let t0 = Instant::now();
    assert!(file.append_at(line(0).as_bytes(), t0));
    // The path is looked at once a second: until then the lines go to the removed file without a word.
    fs::remove_file(&path).unwrap();
    assert!(file.append_at(line(1).as_bytes(), t0 + Duration::from_millis(500)));
    // The look finds no file. That line is lost for the file, which is counted, and the next line makes a new one.
    assert!(!file.append_at(line(2).as_bytes(), t0 + Duration::from_secs(1)));
    assert!(file.current.is_none());
    assert!(file.append_at(line(3).as_bytes(), t0 + Duration::from_secs(1)));
    assert_eq!(read(dir.path(), "records.log"), lines(&[3]));
    assert_eq!(mode_of(&path), 0o600);

    // Another file in its place is found the same way, and is continued.
    let other = dir.path().join("other");
    fs::write(&other, lines(&[9])).unwrap();
    fs::rename(&other, &path).unwrap();
    assert!(!file.append_at(line(4).as_bytes(), t0 + Duration::from_secs(2)));
    assert!(file.append_at(line(5).as_bytes(), t0 + Duration::from_secs(2)));
    assert_eq!(read(dir.path(), "records.log"), lines(&[9, 5]));
}

#[test]
fn the_path_is_looked_at_before_a_rotation_so_a_file_that_is_not_ours_is_not_renamed() {
    let dir = scratch();
    let path = dir.path().join("records.log");
    let mut file = opened(dir.path(), 100, 2);
    for n in 0..3 {
        assert!(file.append(line(n).as_bytes()));
    }
    // Within the second, and the fourth line does not fit.
    fs::remove_file(&path).unwrap();
    fs::write(&path, lines(&[9])).unwrap();
    assert!(!file.append(line(3).as_bytes()));
    assert_eq!(names(dir.path()), ["records.log"]);
    assert_eq!(read(dir.path(), "records.log"), lines(&[9]));
}

#[test]
fn a_rotation_that_cannot_move_the_file_in_use_keeps_every_older_file() {
    let dir = scratch();
    let mut file = opened(dir.path(), 100, 3);
    fs::write(dir.path().join("records.1.log"), lines(&[10])).unwrap();
    fs::write(dir.path().join("records.2.log"), lines(&[20])).unwrap();
    for n in 0..3 {
        assert!(file.append(line(n).as_bytes()));
    }
    // The file in use cannot go to its temporary name: a directory is there.
    let moving = dir.path().join(MOVING);
    fs::create_dir(&moving).unwrap();
    let t0 = Instant::now();
    assert!(!file.append_at(line(3).as_bytes(), t0));
    assert_eq!(
        names(dir.path()),
        ["records.1.log", "records.2.log", "records.log", MOVING]
    );
    assert_eq!(read(dir.path(), "records.log"), lines(&[0, 1, 2]));
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[10]));
    assert_eq!(read(dir.path(), "records.2.log"), lines(&[20]));
    // A second later the rotation is tried again and shifts all three.
    fs::remove_dir(&moving).unwrap();
    assert!(file.append_at(line(4).as_bytes(), t0 + Duration::from_secs(1)));
    assert_eq!(
        names(dir.path()),
        ["records.1.log", "records.2.log", "records.log"]
    );
    assert_eq!(read(dir.path(), "records.log"), lines(&[4]));
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[0, 1, 2]));
    assert_eq!(read(dir.path(), "records.2.log"), lines(&[10]));

    // A rename of the older files that fails puts the file in use back where it was.
    fs::remove_file(dir.path().join("records.2.log")).unwrap();
    fs::create_dir(dir.path().join("records.2.log")).unwrap();
    let t1 = t0 + Duration::from_secs(2);
    assert!(file.append_at(line(5).as_bytes(), t1));
    assert!(file.append_at(line(6).as_bytes(), t1));
    assert!(!file.append_at(line(7).as_bytes(), t1));
    assert_eq!(read(dir.path(), "records.log"), lines(&[4, 5, 6]));
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[0, 1, 2]));
    assert!(!dir.path().join(MOVING).exists());
}

#[test]
fn the_files_beyond_the_count_are_removed_when_the_file_is_opened_and_after_a_rotation() {
    let dir = scratch();
    for n in [1, 2, 3, 4, 7, 63, 64] {
        fs::write(dir.path().join(format!("records.{n}.log")), "x").unwrap();
    }
    // What is not a regular file stays.
    symlink("/dev/null", dir.path().join("records.5.log")).unwrap();
    fs::create_dir(dir.path().join("records.6.log")).unwrap();
    let mut file = opened(dir.path(), 100, 3);
    // Kept: the files the count keeps, the link, the directory, and a number that no count can have made.
    assert_eq!(
        names(dir.path()),
        [
            "records.1.log",
            "records.2.log",
            "records.5.log",
            "records.6.log",
            "records.64.log",
            "records.log"
        ]
    );
    fs::write(dir.path().join("records.9.log"), "x").unwrap();
    for n in 0..4 {
        assert!(file.append(line(n).as_bytes()));
    }
    assert!(!dir.path().join("records.9.log").exists());
    assert!(dir.path().join("records.5.log").exists());
    assert_eq!(read(dir.path(), "records.1.log"), lines(&[0, 1, 2]));
}

#[test]
fn a_file_with_group_or_other_bits_is_set_to_0600_and_the_directory_is_looked_at_when_the_file_is_opened_again()
 {
    let dir = scratch();
    let path = dir.path().join("records.log");
    fs::write(&path, lines(&[0])).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    drop(opened(dir.path(), 100, 2));
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(read(dir.path(), "records.log"), lines(&[0]));

    // After a failure the directory is looked at again before the file is opened: a directory that others can reach
    // is refused, and the file is opened when it is closed to them again.
    let mut file = full(dir.path(), 100, 2);
    let t0 = Instant::now();
    assert!(!file.append_at(line(1).as_bytes(), t0));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(!file.append_at(line(2).as_bytes(), t0 + Duration::from_secs(1)));
    assert!(file.current.is_none());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(file.append_at(line(3).as_bytes(), t0 + Duration::from_secs(2)));
    assert_eq!(read(dir.path(), "records.log"), lines(&[0, 3]));
}

#[test]
fn the_files_of_another_stem_are_named_and_rotated_by_it() {
    let dir = scratch();
    let mut file = RecordFile::open_in("audit", dir.path(), 90, 2).unwrap();
    for n in 0..4 {
        assert!(file.append(line(n).as_bytes()));
    }
    assert!(file.sync());
    assert_eq!(names(dir.path()), ["audit.1.log", "audit.log"]);
    assert_eq!(read(dir.path(), "audit.1.log"), lines(&[0, 1, 2]));
    assert_eq!(read(dir.path(), "audit.log"), lines(&[3]));
}
