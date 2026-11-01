use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::sync::atomic::AtomicU32;
use std::time::Instant;

use super::*;
use crate::config::Keep;
use crate::log::{Unkept, open};

/// A fresh 0700 directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-ship-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
}

/// The identity of the file at `path`.
fn identity(path: &Path) -> Identity {
    Identity::of(&fs::metadata(path).unwrap()).expect("the file system tells when a file was made")
}

/// Record file number `n` with `size` bytes in it; its identity.
fn make(dir: &Path, n: usize, size: usize) -> Identity {
    fs::write(record_file(dir, n), vec![b'x'; size]).unwrap();
    identity(&record_file(dir, n))
}

/// A position written just now in the file with this identity.
fn position(file: Identity, offset: u64) -> Position {
    Position {
        inode: file.inode,
        born: file.born,
        offset,
        lost_lines: 0,
        ts: timestamp(SystemTime::now()),
    }
}

fn config(dir: &Path, files: usize) -> Records {
    Records {
        dir: dir.to_path_buf(),
        file_bytes: 1 << 20,
        files,
        keep: Keep::Required,
        sync_ms: None,
        ship: None,
    }
}

/// Waits until `cond` holds; the watch looks once a second.
fn until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_position_is_one_line_with_the_inode_and_birth_as_text_and_nothing_else_is_a_position() {
    let max = Position {
        inode: u64::MAX,
        born: u128::MAX,
        offset: 7,
        lost_lines: 0,
        ts: timestamp(SystemTime::UNIX_EPOCH),
    };
    let good = max.line();
    assert_eq!(
        good,
        "{\"version\":1,\"inode\":\"18446744073709551615\",\"born\":\"340282366920938463463374607431768211455\",\"offset\":7,\"lost_lines\":0,\"ts\":\"1970-01-01T00:00:00.000Z\"}\n"
    );
    assert_eq!(Position::parse(good.as_bytes()), Some(max.clone()));
    assert_eq!(
        max.identity(),
        Identity {
            inode: u64::MAX,
            born: u128::MAX
        }
    );
    for bad in [
        good.trim_end().to_string(),
        good.replace("\"version\":1", "\"version\":2"),
        good.replace("18446744073709551615", "18446744073709551616"),
        good.replace("18446744073709551615", "184467440737095516150"),
        good.replace("18446744073709551615", "-1"),
        good.replace("\"inode\":\"18446744073709551615\"", "\"inode\":5"),
        good.replace(
            "340282366920938463463374607431768211455",
            "340282366920938463463374607431768211456",
        ),
        good.replace(
            "340282366920938463463374607431768211455",
            "3402823669209384634633746074317682114550",
        ),
        good.replace("340282366920938463463374607431768211455", ""),
        good.replace("340282366920938463463374607431768211455", "-1"),
        good.replace(
            "\"born\":\"340282366920938463463374607431768211455\"",
            "\"born\":5",
        ),
        good.replace("\"born\":\"340282366920938463463374607431768211455\",", ""),
        good.replace("\"lost_lines\":0,", "\"lost_lines\":0,\"more\":1,"),
        good.replace("\"offset\":7,", ""),
        good.replace('\n', "\n\n"),
        format!("{good}{good}"),
        good.replace("1970", "19\u{7f}0"),
    ] {
        assert!(Position::parse(bad.as_bytes()).is_none(), "{bad}");
    }
}

#[test]
fn the_distance_is_the_rest_of_the_file_it_names_and_every_newer_file() {
    let dir = scratch();
    let sizes = [300, 1000, 2000];
    let files: Vec<Identity> = (0..3).map(|n| make(dir.path(), n, sizes[n])).collect();
    let bytes =
        |count, file: Identity, offset| unshipped_bytes(dir.path(), count, &position(file, offset));
    assert_eq!(bytes(3, files[1], 400), Some(600 + 300));
    assert_eq!(bytes(3, files[0], 100), Some(200));
    assert_eq!(bytes(3, files[0], 300), Some(0));
    assert_eq!(bytes(3, files[2], 0), Some(2000 + 1000 + 300));
    // A position past the end of the file leaves nothing of it.
    assert_eq!(bytes(3, files[1], 5000), Some(300));
    // A file that is not there: it was rotated away. A file past `files` is not looked at.
    let gone = Identity {
        inode: files.iter().map(|f| f.inode).max().unwrap() + 1,
        born: 1,
    };
    assert_eq!(bytes(3, gone, 0), None);
    assert_eq!(bytes(2, files[2], 0), None);
    // `records.log` is not there for a moment in a rotation.
    fs::remove_file(record_file(dir.path(), 0)).unwrap();
    assert_eq!(bytes(3, files[1], 400), Some(600));
    // What is not a regular file cannot be counted.
    fs::remove_file(record_file(dir.path(), 1)).unwrap();
    fs::create_dir(record_file(dir.path(), 1)).unwrap();
    assert_eq!(bytes(3, files[2], 0), None);
}

#[test]
fn a_file_that_took_the_inode_of_a_deleted_one_is_not_the_file_a_position_names() {
    let dir = scratch();
    // The position names a file that was deleted. The file system gave its inode to the file that is there now,
    // which is newer: the inode is the same and the birth time is not.
    let made = make(dir.path(), 0, 5000);
    let deleted = Identity {
        inode: made.inode,
        born: made.born - 1_000_000_000,
    };
    assert_eq!(unshipped_bytes(dir.path(), 3, &position(deleted, 0)), None);
    assert_eq!(
        unshipped_bytes(dir.path(), 3, &position(made, 0)),
        Some(5000)
    );
}

#[test]
fn the_file_that_a_rotation_is_moving_is_counted_and_a_file_that_is_not_found_is_looked_for_again()
{
    let dir = scratch();
    // In the middle of a rotation `records.log` is not there, and the file in use is `records.rotating`.
    fs::write(rotating_file(dir.path()), vec![b'x'; 500]).unwrap();
    let moving = identity(&rotating_file(dir.path()));
    make(dir.path(), 2, 700);
    assert_eq!(
        unshipped_bytes(dir.path(), 3, &position(moving, 100)),
        Some(400)
    );
    fs::remove_file(rotating_file(dir.path())).unwrap();
    make(dir.path(), 0, 10);

    // The file is not found, and a moment later it is: the rotation has put it in place.
    let hidden = dir.path().join("hidden");
    fs::write(&hidden, vec![b'x'; 500]).unwrap();
    let file = identity(&hidden);
    fs::write(position_file(dir.path()), position(file, 100).line()).unwrap();
    let target = record_file(dir.path(), 1);
    let mover = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        fs::rename(&hidden, &target).unwrap();
    });
    let again = Duration::from_millis(600);
    assert_eq!(look(dir.path(), 3, again), 10 + 400);
    mover.join().unwrap();
    // A file that is not there the second time either makes the distance unknown.
    fs::remove_file(record_file(dir.path(), 1)).unwrap();
    assert_eq!(look(dir.path(), 3, Duration::from_millis(10)), UNKNOWN);
}

#[test]
fn a_position_counts_for_ninety_seconds_either_way() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let ms = Duration::from_millis;
    let at = |before: bool, by: Duration| timestamp(if before { now - by } else { now + by });
    assert!(recent(&timestamp(now), now));
    // The limit, and the first millisecond past it, on both sides.
    assert!(recent(&at(true, FRESH), now));
    assert!(!recent(&at(true, FRESH + ms(1)), now));
    assert!(recent(&at(false, FRESH), now));
    assert!(!recent(&at(false, FRESH + ms(1)), now));
    // A text that is not in the shape of the time of a position is not one.
    let good = timestamp(now);
    let spaced = good.replace('T', " ");
    let short = good.replace(".000", ".0");
    let bad: [&str; 5] = ["", "now", good.trim_end_matches('Z'), &spaced, &short];
    for bad in bad {
        assert!(!recent(bad, now), "{bad}");
    }
}

#[test]
fn a_position_that_is_old_or_from_the_future_makes_the_distance_unknown() {
    let dir = scratch();
    let file = make(dir.path(), 0, 100);
    let again = Duration::from_millis(10);
    let written = |at: SystemTime| Position {
        ts: timestamp(at),
        ..position(file, 0)
    };
    let now = SystemTime::now();
    for (at, distance) in [
        (now, 100),
        (now - Duration::from_secs(60), 100),
        (now - Duration::from_secs(120), UNKNOWN),
        (now + Duration::from_secs(120), UNKNOWN),
    ] {
        fs::write(position_file(dir.path()), written(at).line()).unwrap();
        assert_eq!(look(dir.path(), 3, again), distance);
    }
}

#[test]
fn the_position_is_read_only_from_a_regular_file_of_a_position_that_is_short_enough() {
    let dir = scratch();
    assert_eq!(read_position(dir.path()), None);
    let good = position(Identity { inode: 5, born: 6 }, 9);
    fs::write(position_file(dir.path()), good.line()).unwrap();
    assert_eq!(read_position(dir.path()), Some(good.clone()));
    // A link is not followed.
    let elsewhere = dir.path().join("elsewhere");
    fs::rename(position_file(dir.path()), &elsewhere).unwrap();
    symlink(&elsewhere, position_file(dir.path())).unwrap();
    assert_eq!(read_position(dir.path()), None);
    // A line that is a position and has the longest length that is read, and one byte more.
    fs::remove_file(position_file(dir.path())).unwrap();
    let mut long = good;
    long.ts = "t".repeat(TS_MAX + 1);
    fs::write(position_file(dir.path()), long.line()).unwrap();
    assert_eq!(read_position(dir.path()), None);
    fs::write(position_file(dir.path()), vec![b'x'; 1025]).unwrap();
    assert_eq!(read_position(dir.path()), None);
}

/// Makes `lag` show the distance `unshipped`, as a look that began when the logger had written `written` bytes.
fn looked(lag: &Lag, unshipped: u64, written: u64) {
    *lag.seen.lock().unwrap() = Seen { unshipped, written };
}

#[test]
fn a_request_is_turned_away_from_the_limit_on_and_while_the_distance_is_not_known() {
    let lag = Lag::new(Some(900));
    assert!(lag.behind());
    assert_eq!(lag.unshipped(), Unshipped::Unknown);
    looked(&lag, 899, 0);
    assert!(!lag.behind());
    assert_eq!(lag.unshipped(), Unshipped::Bytes(899));
    looked(&lag, 900, 0);
    assert!(lag.behind());
}

#[test]
fn what_the_logger_wrote_since_the_look_counts_towards_the_distance() {
    let lag = Lag::new(Some(900));
    lag.wrote(40);
    looked(&lag, 800, 40);
    assert_eq!(lag.unshipped(), Unshipped::Bytes(800));
    lag.wrote(99);
    assert!(!lag.behind());
    assert_eq!(lag.unshipped(), Unshipped::Bytes(899));
    lag.wrote(1);
    assert!(lag.behind());
    // While the distance is not known, what is written changes nothing.
    looked(&lag, UNKNOWN, 140);
    lag.wrote(5);
    assert_eq!(lag.unshipped(), Unshipped::Unknown);
}

#[test]
fn the_watch_admits_when_the_shipper_is_near_and_turns_away_again_when_it_falls_behind() {
    let dir = scratch();
    let (log, _items) = open(8);
    // Without a shipper only the health of the file counts.
    assert!(log.admitting());
    assert_eq!(log.unshipped(), None);

    // 3 files of 1 MiB: from 1 MiB on the shipper is behind. There is no position yet.
    let file = make(dir.path(), 0, 100);
    let config = config(dir.path(), 3);
    log.watch_ship(&config).unwrap();
    assert!(log.watch_ship(&config).is_err());
    assert!(!log.admitting());
    assert!(matches!(log.admit(), Err(Unkept::Behind)));
    assert_eq!(log.unshipped(), Some(Unshipped::Unknown));

    fs::write(position_file(dir.path()), position(file, 0).line()).unwrap();
    until("the shipper to be near", || log.admitting());
    assert_eq!(log.unshipped(), Some(Unshipped::Bytes(100)));
    assert!(log.admit().is_ok());

    // The file grows to the limit: the shipper is behind by exactly it.
    make(dir.path(), 0, 1 << 20);
    until("the shipper to be behind", || !log.admitting());
    assert_eq!(log.unshipped(), Some(Unshipped::Bytes(1 << 20)));
    // It ships a part of it, and the distance is below the limit by one byte.
    fs::write(position_file(dir.path()), position(file, 1).line()).unwrap();
    until("the shipper to be near again", || log.admitting());
    assert_eq!(log.unshipped(), Some(Unshipped::Bytes((1 << 20) - 1)));
    // A position in a file that is not there any more is a distance that is not known.
    let gone = Identity {
        inode: u64::MAX,
        born: 1,
    };
    fs::write(position_file(dir.path()), position(gone, 0).line()).unwrap();
    until("the position to name a file that is gone", || {
        !log.admitting()
    });
    assert_eq!(log.unshipped(), Some(Unshipped::Unknown));
}

#[test]
fn with_two_files_the_shipper_is_not_judged_and_its_distance_is_still_shown() {
    let dir = scratch();
    let (log, _items) = open(8);
    let file = make(dir.path(), 0, 100);
    log.watch_ship(&config(dir.path(), 2)).unwrap();
    // There is no position yet, which turns a request away when there are 3 files.
    assert!(log.admitting());
    assert!(log.admit().is_ok());
    assert_eq!(log.unshipped(), Some(Unshipped::Unknown));

    // The shipper has caught up: its distance is known, and a request is let in as before.
    fs::write(position_file(dir.path()), position(file, 0).line()).unwrap();
    until("the distance to be known", || {
        log.unshipped() == Some(Unshipped::Bytes(100))
    });
    assert!(log.admitting());
    assert!(log.admit().is_ok());
}
