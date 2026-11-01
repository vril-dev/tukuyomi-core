use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tukuyomi_proxy::log::ship::Identity;

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
        "tukuyomi-ship-files-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    TestDir(dir)
}

#[test]
fn the_time_has_the_form_of_a_record() {
    assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
    let at = UNIX_EPOCH + Duration::from_millis(1_793_000_000_123);
    assert_eq!(rfc3339(at), "2026-10-26T07:33:20.123Z");
    // 2024-02-29, the leap day.
    let leap = UNIX_EPOCH + Duration::from_secs(1_709_164_800);
    assert_eq!(rfc3339(leap), "2024-02-29T00:00:00.000Z");
    // After the year 9999 the text keeps its shape.
    let far = UNIX_EPOCH + Duration::from_secs(400_000_000_000);
    assert_eq!(rfc3339(far), "9999-12-31T23:59:59.999Z");
}

#[test]
fn the_names_go_from_the_oldest_to_the_newest() {
    let names: Vec<String> = record_paths(Path::new("/d"), 4)
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        [
            "/d/records.3.log",
            "/d/records.2.log",
            "/d/records.1.log",
            "/d/records.rotating",
            "/d/records.log"
        ]
    );
}

#[test]
fn the_position_file_has_the_agreed_form() {
    let dir = scratch();
    let position = Position {
        identity: Identity {
            inode: 18_446_744_073_709_551_615,
            born: 1_793_000_000_123_456_789,
        },
        offset: 4096,
        lost_lines: 3,
    };
    write_state(
        &dir.0,
        &position,
        UNIX_EPOCH + Duration::from_millis(1_793_000_000_123),
    )
    .unwrap();
    let path = dir.0.join("ship.state");
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(
        text,
        "{\"version\":1,\"inode\":\"18446744073709551615\",\"born\":\"1793000000123456789\",\"offset\":4096,\"lost_lines\":3,\"ts\":\"2026-10-26T07:33:20.123Z\"}\n"
    );
    // The reader of the proxy takes it back.
    let state = ship::Position::parse(text.as_bytes()).unwrap();
    assert_eq!(
        (state.identity(), state.offset, state.lost_lines),
        (position.identity, 4096, 3)
    );
    // Only the owner can read it, and no temporary file is left.
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let names: Vec<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    // A later write replaces it.
    let next = Position {
        offset: 5000,
        ..position
    };
    write_state(&dir.0, &next, UNIX_EPOCH).unwrap();
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("\"offset\":5000")
    );
}

#[test]
fn a_link_in_place_of_a_record_file_is_refused() {
    let dir = scratch();
    fs::write(dir.0.join("real"), "x\n").unwrap();
    std::os::unix::fs::symlink(dir.0.join("real"), dir.0.join("records.log")).unwrap();
    assert!(open_record(&dir.0.join("records.log")).is_err());
    assert!(open_record(&dir.0.join("real")).is_ok());
    fs::create_dir(dir.0.join("records.1.log")).unwrap();
    assert!(open_record(&dir.0.join("records.1.log")).is_err());
}
