use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::acme::tests::Scratch;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn the_account_key_is_made_once_with_mode_0600_and_a_file_is_never_replaced() {
    let dir = Scratch::new();
    let path = dir.join("account.key");
    let first = account_key(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(names(dir.path()), ["account.key"]);
    let bytes = fs::read(&path).unwrap();
    let second = account_key(&path).unwrap();
    assert_eq!((second.x(), second.y()), (first.x(), first.y()));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // A file that is not a key is an error, and stays; so is a directory that is not there.
    fs::write(&path, b"not a key").unwrap();
    assert!(account_key(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"not a key");
    assert!(account_key(&dir.join("no/such/dir/account.key")).is_err());
    // A link to nothing is not followed to make a file behind it.
    std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("linked")).unwrap();
    assert!(account_key(&dir.join("linked")).is_err());
    assert!(!dir.join("elsewhere").exists());
}

#[test]
fn a_temporary_file_that_a_stop_left_is_not_the_account_key_and_a_key_that_is_there_is_used_and_kept()
 {
    let dir = Scratch::new();
    let path = dir.join("account.key");
    let stale = dir.join(".acme-0123456789abcdef.tmp");
    fs::write(&stale, b"-----BEGIN PRIVATE KEY-----\nMIG").unwrap();
    // Only the temporary file is there: no key file is, a key is made, and the temporary file is left alone.
    assert_eq!(read_file(&path, MAX_KEY_FILE).err(), Some(Fault::Missing));
    let made = account_key(&path).unwrap();
    assert_eq!(
        names(dir.path()),
        [".acme-0123456789abcdef.tmp", "account.key"]
    );
    assert_eq!(
        fs::read(&stale).unwrap(),
        b"-----BEGIN PRIVATE KEY-----\nMIG"
    );
    // The key that is there is used; neither it nor the temporary file changes.
    let bytes = fs::read(&path).unwrap();
    let again = account_key(&path).unwrap();
    assert_eq!((again.x(), again.y()), (made.x(), made.y()));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // Creating over a file that is there fails, leaves it as it is, and leaves no temporary file of its own.
    let err = create_new(&path, b"other").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        names(dir.path()),
        [".acme-0123456789abcdef.tmp", "account.key"]
    );
}

#[test]
fn a_challenge_file_is_put_whole_over_an_old_one_and_removed_with_the_challenges() {
    let dir = Scratch::new();
    {
        let mut challenges = Challenges::new(dir.path());
        fs::write(dir.join("Tok_-1"), b"old").unwrap();
        challenges.put("Tok_-1", "abc.def").unwrap();
        challenges.put("T2", "x").unwrap();
        assert_eq!(fs::read(dir.join("Tok_-1")).unwrap(), b"abc.def");
        // A token that is not one makes no file, and no file is made outside the directory.
        for bad in ["", "..", "a/b", "../x", "a.b", "a b", &"a".repeat(129)] {
            assert!(challenges.put(bad, "x").is_err(), "{bad:.20}");
        }
        assert_eq!(names(dir.path()), ["T2", "Tok_-1"]);
        challenges.put(&"a".repeat(128), "x").unwrap();
    }
    assert!(names(dir.path()).is_empty());
}

#[test]
fn a_key_and_a_chain_replace_the_old_files_and_a_fault_in_writing_leaves_both_as_they_were() {
    let dir = Scratch::new();
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    fs::write(&cert, b"old chain").unwrap();
    fs::write(&key, b"old key").unwrap();
    // The chain cannot be written (its directory is not there): the key is not replaced, and nothing is left over.
    assert!(install(&dir.join("no/c.pem"), &key, "new key", "new chain").is_err());
    assert_eq!(fs::read(&key).unwrap(), b"old key");
    assert_eq!(names(dir.path()), ["c.pem", "k.pem"]);
    install(&cert, &key, "new key", "new chain").unwrap();
    assert_eq!(fs::read(&key).unwrap(), b"new key");
    assert_eq!(fs::read(&cert).unwrap(), b"new chain");
    assert_eq!(mode(&key), 0o600);
    assert_eq!(mode(&cert) & !0o644, 0);
    assert_eq!(names(dir.path()), ["c.pem", "k.pem"]);
}
