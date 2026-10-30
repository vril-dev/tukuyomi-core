use super::*;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

/// A directory under the temporary directory that is removed when it goes out of scope.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        let dir = std::env::temp_dir().join(format!("tkv-ffi-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        Dir(dir)
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_version_is_the_one_of_the_headers() {
    assert_eq!(engine_version(), Ok("3.0.17"));
}

#[test]
fn a_small_rules_file_loads_and_a_broken_one_gives_the_fixed_error() {
    let dir = Dir::new();
    let good = dir.file(
        "good.conf",
        "SecRuleEngine On\nSecRule ARGS \"@contains attack\" \"id:1001,phase:2,deny,status:403,log\"\n",
    );
    // A rule without an id is wrong.
    let broken = dir.file(
        "broken.conf",
        "SecRule ARGS \"@contains attack\" \"phase:2,deny\"\n",
    );
    let _engine = Engine::new().unwrap();
    let mut rules = Rules::new().unwrap();
    assert_eq!(rules.add_file(&good), Ok(()));

    let mut rules = Rules::new().unwrap();
    let err = rules.add_file(&broken).unwrap_err();
    assert_eq!(err, Error::Rules);
    assert!(!err.text().contains(dir.0.to_str().unwrap()));
    // A file that is not there is refused the same way.
    assert_eq!(
        rules.add_file(&dir.0.join("missing.conf")),
        Err(Error::Rules)
    );
}

#[test]
fn a_path_with_a_nul_byte_is_refused_before_the_library_sees_it() {
    let mut rules = Rules::new().unwrap();
    assert_eq!(
        rules.add_file(Path::new(OsStr::from_bytes(b"a\0b.conf"))),
        Err(Error::Path)
    );
}
