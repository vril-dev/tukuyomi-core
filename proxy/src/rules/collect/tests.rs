use super::*;
use crate::rules::bundle::Manifest;
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// A fresh directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }

    /// Writes a file below the directory, with the directories above it.
    fn put(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, data).unwrap();
        path
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
        "tukuyomi-proxy-collect-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    TestDir(dir)
}

/// A CRS directory as the fetch script leaves it, with its `.example` files.
fn crs(root: &TestDir) -> PathBuf {
    root.put("crs/crs-setup.conf", b"SecAction \"id:900990\"\n");
    root.put("crs/crs-setup.conf.example", b"example\n");
    root.put("crs/rules/B-second.conf", b"second\n");
    root.put("crs/rules/A-first.conf", b"first\n");
    root.put("crs/rules/words.data", b"one\n");
    root.put("crs/rules/A-first.conf.example", b"example\n");
    root.path().join("crs")
}

/// A case of a CRS directory that is refused: what it is called, the change made to the directory, the reason.
type Case = (&'static str, fn(&TestDir), &'static str);

fn refused(inputs: &Inputs) -> &'static str {
    match collect(inputs) {
        Err(e) => e.reason,
        Ok(_) => panic!("accepted"),
    }
}

fn rules_only(file: PathBuf) -> Inputs {
    Inputs {
        rules: vec![file],
        ..Inputs::default()
    }
}

#[test]
fn the_bundle_has_the_crs_and_the_operator_files_in_the_load_order() {
    let root = scratch();
    let inputs = Inputs {
        crs: Some(crs(&root)),
        crs_off: vec![OsString::from("B-second.conf")],
        rules: vec![
            root.put("mine/z.conf", b"z\n"),
            root.put("mine/a.conf", b"a\n"),
        ],
        data: vec![root.put("mine/list.data", b"x\n")],
    };
    let bundle = collect(&inputs).unwrap();
    let manifest = Manifest::parse(bundle.manifest()).unwrap();
    let files: Vec<&str> = manifest.files().iter().map(|f| f.path.as_str()).collect();
    // The `.example` files are not in it, and neither is the file that is turned off.
    assert_eq!(
        files,
        [
            "crs/crs-setup.conf",
            "crs/rules/A-first.conf",
            "crs/rules/words.data",
            "rules/a.conf",
            "rules/list.data",
            "rules/z.conf",
        ]
    );
    let load: Vec<&str> = manifest.load().iter().map(|p| p.as_str()).collect();
    assert_eq!(
        load,
        [
            "crs/crs-setup.conf",
            "crs/rules/A-first.conf",
            "rules/z.conf",
            "rules/a.conf",
        ]
    );
    // Without the file that is turned off the CRS loads both, by the bytes of their names.
    let inputs = Inputs {
        crs: Some(root.path().join("crs")),
        ..Inputs::default()
    };
    let manifest = Manifest::parse(collect(&inputs).unwrap().manifest()).unwrap();
    let load: Vec<&str> = manifest.load().iter().map(|p| p.as_str()).collect();
    assert_eq!(
        load,
        [
            "crs/crs-setup.conf",
            "crs/rules/A-first.conf",
            "crs/rules/B-second.conf",
        ]
    );
}

#[test]
fn a_crs_directory_of_another_layout_is_refused() {
    let layout = "the CRS directory holds an entry that is not part of it";
    let kinds = "the CRS rules directory holds a file of another kind";
    // Each change is made to a fresh CRS directory.
    let cases: [Case; 9] = [
        ("hidden", |r| drop(r.put("crs/.hidden", b"x")), layout),
        (
            "plugins",
            |r| drop(r.put("crs/plugins/p.conf", b"x")),
            layout,
        ),
        (
            "setup is a link",
            |r| {
                fs::remove_file(r.path().join("crs/crs-setup.conf")).unwrap();
                symlink(
                    r.path().join("crs/crs-setup.conf.example"),
                    r.path().join("crs/crs-setup.conf"),
                )
                .unwrap();
            },
            layout,
        ),
        (
            "no setup",
            |r| fs::remove_file(r.path().join("crs/crs-setup.conf")).unwrap(),
            "the CRS directory has no crs-setup.conf",
        ),
        (
            "no rules",
            |r| fs::remove_dir_all(r.path().join("crs/rules")).unwrap(),
            "the CRS directory has no rules directory",
        ),
        (
            "another extension",
            |r| drop(r.put("crs/rules/x.txt", b"x")),
            kinds,
        ),
        (
            "a link in rules",
            |r| {
                symlink(
                    r.path().join("crs/crs-setup.conf"),
                    r.path().join("crs/rules/l.conf"),
                )
                .unwrap()
            },
            "the CRS rules directory holds an entry that is not a file",
        ),
        (
            "a directory in rules",
            |r| fs::create_dir(r.path().join("crs/rules/sub")).unwrap(),
            "the CRS rules directory holds an entry that is not a file",
        ),
        (
            "a hidden rule file",
            |r| drop(r.put("crs/rules/.x.conf", b"x")),
            "the name of a CRS file is not a name in a bundle",
        ),
    ];
    for (name, change, reason) in cases {
        let root = scratch();
        let dir = crs(&root);
        change(&root);
        let inputs = Inputs {
            crs: Some(dir),
            ..Inputs::default()
        };
        assert_eq!(refused(&inputs), reason, "{name}");
    }
    // The directory itself is not a link.
    let root = scratch();
    crs(&root);
    symlink(root.path().join("crs"), root.path().join("link")).unwrap();
    let inputs = Inputs {
        crs: Some(root.path().join("link")),
        ..Inputs::default()
    };
    assert_eq!(
        refused(&inputs),
        "the CRS directory is not a real directory"
    );
}

#[test]
fn a_file_that_is_turned_off_must_be_a_conf_file_of_the_crs() {
    let root = scratch();
    let off = |name: &str, crs: Option<PathBuf>| Inputs {
        crs,
        crs_off: vec![OsString::from(name)],
        rules: vec![root.put("mine.conf", b"x")],
        ..Inputs::default()
    };
    let unknown = "a file that is turned off is not a .conf file of the CRS";
    let dir = crs(&root);
    assert_eq!(refused(&off("A-frist.conf", Some(dir.clone()))), unknown);
    assert_eq!(refused(&off("words.data", Some(dir.clone()))), unknown);
    assert_eq!(refused(&off("A-first.conf.example", Some(dir))), unknown);
    assert_eq!(
        refused(&off("A-first.conf", None)),
        "a file of the CRS is turned off but no CRS is given"
    );
}

#[test]
fn an_input_file_must_be_a_regular_file_and_a_name_in_a_bundle() {
    let root = scratch();
    let good = root.put("good.conf", b"x\n");
    // Not a regular file: a link (to a good file), a directory, a FIFO that is not opened, an absent file.
    let link = root.path().join("link.conf");
    symlink(&good, &link).unwrap();
    assert_eq!(refused(&rules_only(link)), "an input file is a link");
    let dir = root.path().join("dir.conf");
    fs::create_dir(&dir).unwrap();
    assert_eq!(
        refused(&rules_only(dir)),
        "an input file is not a regular file"
    );
    let fifo = root.path().join("fifo.conf");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        refused(&rules_only(fifo)),
        "an input file is not a regular file"
    );
    assert_eq!(
        refused(&rules_only(root.path().join("absent.conf"))),
        "an input file does not exist"
    );
    // The limit of a file and the first byte past it.
    let limit = root.put("limit.conf", &vec![b'x'; 2 << 20]);
    assert!(collect(&rules_only(limit)).is_ok());
    let past = root.put("past.conf", &vec![b'x'; (2 << 20) + 1]);
    assert_eq!(
        refused(&rules_only(past)),
        "an input file is over 2 MiB, is not a regular file or changed while it was read"
    );
    // A name that cannot be a path of the bundle.
    let name = "the name of an input file is not a name in a bundle";
    assert_eq!(refused(&rules_only(root.put("bad name.conf", b"x"))), name);
    assert_eq!(refused(&rules_only(root.put(".hidden.conf", b"x"))), name);
}

#[test]
fn the_bundle_needs_a_rule_file_and_keeps_its_names_and_limits() {
    let root = scratch();
    let data = root.put("a/list.data", b"x\n");
    let none = "no rule file is given: name a CRS or a rule file";
    assert_eq!(refused(&Inputs::default()), none);
    let inputs = Inputs {
        data: vec![data.clone()],
        ..Inputs::default()
    };
    assert_eq!(refused(&inputs), none);
    // A rule file and a data file of one name, and two rule files of one name.
    let same = "two input files have the same name in the bundle";
    let inputs = Inputs {
        rules: vec![root.put("b/list.data", b"y\n")],
        data: vec![data],
        ..Inputs::default()
    };
    assert_eq!(refused(&inputs), same);
    let inputs = Inputs {
        rules: vec![root.put("c/r.conf", b"1"), root.put("d/r.conf", b"2")],
        ..Inputs::default()
    };
    assert_eq!(refused(&inputs), same);
    // 128 files and the 129th.
    let many: Vec<PathBuf> = (0..129)
        .map(|i| root.put(&format!("many/r{i:03}.conf"), b"x"))
        .collect();
    let inputs = Inputs {
        rules: many[..128].to_vec(),
        ..Inputs::default()
    };
    assert!(collect(&inputs).is_ok());
    let inputs = Inputs {
        rules: many,
        ..Inputs::default()
    };
    assert_eq!(
        refused(&inputs),
        "the bundle would have more than 128 files"
    );
    // 8 MiB in all, and one byte more.
    let big: Vec<PathBuf> = (0..4)
        .map(|i| root.put(&format!("big/d{i}.data"), &vec![b'x'; 2 << 20]))
        .collect();
    let inputs = Inputs {
        rules: vec![root.put("big/r.conf", b"")],
        data: big,
        ..Inputs::default()
    };
    assert!(collect(&inputs).is_ok());
    let inputs = Inputs {
        rules: vec![root.put("big/s.conf", b"x")],
        ..inputs
    };
    assert_eq!(refused(&inputs), "the input files add up to over 8 MiB");
}
