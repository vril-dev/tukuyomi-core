use super::*;
use std::fs;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn read(text: &str) -> Option<Fingerprint> {
    Fingerprint::from_hex(text.as_bytes())
}

#[test]
fn exactly_64_lowercase_hex_digits_are_a_fingerprint() {
    let fingerprint = read(HEX).unwrap();
    assert_eq!(fingerprint.bytes()[..2], [0x01, 0x23]);
    assert_eq!(fingerprint.bytes()[30..], [0xcd, 0xef]);
}

#[test]
fn any_other_text_is_not_a_fingerprint() {
    assert_eq!(read(&HEX[..63]), None);
    assert_eq!(read(&HEX.to_uppercase()), None);
    assert_eq!(read(&format!("{}g", &HEX[..63])), None);
}

#[test]
fn hex_gives_back_the_digits_that_were_read() {
    assert_eq!(read(HEX).unwrap().hex(), HEX);
}

fn path(text: &str) -> BundlePath {
    BundlePath::parse(text).unwrap_or_else(|| panic!("{text} is not a path"))
}

fn entry(name: &str, size: u64) -> Entry {
    Entry {
        path: path(name),
        size,
        sha256: [7; 32],
    }
}

#[test]
fn a_path_has_one_to_four_components_of_the_allowed_characters() {
    let (x, y) = ("x".repeat(128), "y".repeat(127));
    let accepted = [
        "a",
        "a/b/c/d",
        "A_b-c.d",
        "a..b",
        "rules/manifest.json",
        &x,
        &format!("{y}/{y}"),
    ];
    for text in accepted {
        assert!(BundlePath::parse(text).is_some(), "{text}");
    }
    let rejected = [
        "",
        "/a",
        "a/",
        "a//b",
        ".a",
        "a/.b",
        "a/b/c/d/e",
        "manifest.json",
        "a b",
        "a\\b",
        "é",
        &"x".repeat(129),
        &format!("{x}/{y}"),
    ];
    for text in rejected {
        assert!(BundlePath::parse(text).is_none(), "{text}");
    }
    assert_eq!(
        path("a/b/c").parents().collect::<Vec<_>>(),
        ["a", "a/b"].to_vec()
    );
}

#[test]
fn the_writer_gives_the_golden_manifest_and_its_fingerprint() {
    let golden = format!(
        "{}/../inspector/testdata/manifest-v1-golden.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = fs::read(&golden).unwrap();
    // The entries and the load order of the golden file, written again by the writer.
    let manifest = Manifest::parse(&bytes).unwrap();
    assert_eq!(manifest.mode(), Mode::Block);
    let rebuilt = Manifest::new(
        manifest.mode(),
        manifest.files().to_vec(),
        manifest.load().to_vec(),
    )
    .unwrap();
    assert_eq!(rebuilt.encode(), bytes);
    // The fingerprint is what `sha256sum` gives for the file.
    let sum = fs::read_to_string(format!("{golden}.sha256")).unwrap();
    assert_eq!(format!("{}\n", Fingerprint::of(&bytes).hex()), sum);
}

#[test]
fn the_writer_gives_the_golden_manifest_of_version_2_and_its_fingerprint() {
    let golden = format!(
        "{}/../inspector/testdata/manifest-v2-golden.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = fs::read(&golden).unwrap();
    // The entries and the load order of the golden file, written again by the writer.
    let manifest = Manifest::parse(&bytes).unwrap();
    assert_eq!(manifest.mode(), Mode::Detect);
    let rebuilt = Manifest::new(
        Mode::Detect,
        manifest.files().to_vec(),
        manifest.load().to_vec(),
    )
    .unwrap();
    assert_eq!(rebuilt.encode(), bytes);
    // The fingerprint is what `sha256sum` gives for the file.
    let sum = fs::read_to_string(format!("{golden}.sha256")).unwrap();
    assert_eq!(format!("{}\n", Fingerprint::of(&bytes).hex()), sum);
}

#[test]
fn the_mode_is_in_the_manifest_and_so_in_the_fingerprint_and_only_one_spelling_of_it_is_read() {
    let one = path("a.conf");
    let make =
        |mode| Bundle::new(mode, vec![(one.clone(), b"x".to_vec())], vec![one.clone()]).unwrap();
    let (block, detect) = (make(Mode::Block), make(Mode::Detect));
    assert_ne!(block.fingerprint(), detect.fingerprint());
    assert_eq!(
        Manifest::parse(block.manifest()).unwrap().mode(),
        Mode::Block
    );
    assert_eq!(
        Manifest::parse(detect.manifest()).unwrap().mode(),
        Mode::Detect
    );
    let detect = String::from_utf8(detect.manifest().to_vec()).unwrap();
    let block = String::from_utf8(block.manifest().to_vec()).unwrap();
    assert!(detect.starts_with(r#"{"version":2,"mode":"detect","files":["#));
    let cases = [
        detect.replace("\"mode\":\"detect\"", "\"mode\":\"block\""),
        detect.replace("\"mode\":\"detect\"", "\"mode\":\"Detect\""),
        detect.replace("\"mode\":\"detect\",", ""),
        detect.replace(
            "\"version\":2,\"mode\":\"detect\"",
            "\"mode\":\"detect\",\"version\":2",
        ),
        detect.replace("\"version\":2", "\"version\":3"),
        block.replace("\"version\":1,", "\"version\":1,\"mode\":\"detect\","),
        block.replace("\"version\":1,", "\"version\":1,\"mode\":null,"),
    ];
    for text in cases {
        assert!(Manifest::parse(text.as_bytes()).is_err(), "{text}");
    }
}

#[test]
fn the_test_bundle_of_the_kernel_has_the_manifest_that_the_writer_gives() {
    let root = format!("{}/../kernel/tests/rules", env!("CARGO_MANIFEST_DIR"));
    let conf = path("rules/basic.conf");
    let data = fs::read(format!("{root}/rules/basic.conf")).unwrap();
    let bundle = Bundle::new(Mode::Block, vec![(conf.clone(), data)], vec![conf]).unwrap();
    let manifest = fs::read(format!("{root}/manifest.json")).unwrap();
    assert_eq!(bundle.manifest(), manifest);
    assert_eq!(bundle.fingerprint(), Fingerprint::of(&manifest));
}

#[test]
fn a_bundle_lists_its_files_in_the_order_of_their_paths_and_loads_in_the_given_order() {
    let files = ["rules/b.conf", "crs/z.data", "rules/a.conf", "crs/a.conf"]
        .map(|name| (path(name), name.as_bytes().to_vec()))
        .to_vec();
    let load = vec![path("rules/b.conf"), path("crs/a.conf")];
    let bundle = Bundle::new(Mode::Block, files, load.clone()).unwrap();
    let manifest = Manifest::parse(bundle.manifest()).unwrap();
    let listed: Vec<&str> = manifest.files().iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        listed,
        ["crs/a.conf", "crs/z.data", "rules/a.conf", "rules/b.conf"]
    );
    assert_eq!(manifest.load(), load);
    assert_eq!(manifest.files()[1].sha256, sha256(b"crs/z.data"));
}

#[test]
fn a_manifest_is_read_only_in_the_one_form() {
    let one = path("a.conf");
    let bundle = Bundle::new(Mode::Block, vec![(one.clone(), b"x".to_vec())], vec![one]).unwrap();
    let good = String::from_utf8(bundle.manifest().to_vec()).unwrap();
    assert!(Manifest::parse(good.as_bytes()).is_ok());
    let digest = hex(&sha256(b"x"));
    let cases = [
        good.replace("\"version\":1,", "\"version\": 1,"),
        good.trim_end().to_owned(),
        format!("{good} "),
        good.replace(&digest, &digest.to_uppercase()),
        good.replace("\"version\":1", "\"version\":2"),
        good.replace(
            "\"path\":\"a.conf\",\"size\":1",
            "\"size\":1,\"path\":\"a.conf\"",
        ),
        good.replace("\"version\":1,", "\"version\":1,\"version\":1,"),
        good.replace("\"version\":1,", "\"version\":1,\"extra\":0,"),
        good.replace("\"load\":[\"a.conf\"]", "\"load\":[\"b.conf\"]"),
    ];
    for text in cases {
        assert!(Manifest::parse(text.as_bytes()).is_err(), "{text}");
    }
}

#[test]
fn a_manifest_keeps_the_limits_of_a_bundle() {
    let load = |names: &[&str]| names.iter().map(|n| path(n)).collect::<Vec<_>>();
    let files = |sizes: &[u64]| -> Vec<Entry> {
        sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| entry(&format!("f{i:03}"), size))
            .collect()
    };
    let mib = 1u64 << 20;
    // The file and the total at the limit and one byte past it.
    assert!(Manifest::new(Mode::Block, files(&[2 * mib; 4]), load(&["f000"])).is_ok());
    assert!(Manifest::new(Mode::Block, files(&[2 * mib + 1]), load(&["f000"])).is_err());
    assert!(
        Manifest::new(
            Mode::Block,
            files(&[2 * mib, 2 * mib, 2 * mib, 2 * mib, 1]),
            load(&["f000"])
        )
        .is_err()
    );
    // 128 files and the 129th.
    assert!(Manifest::new(Mode::Block, files(&[1; 128]), load(&["f000"])).is_ok());
    assert!(Manifest::new(Mode::Block, files(&[1; 129]), load(&["f000"])).is_err());
    // The load list: not empty, in files, once each.
    assert!(Manifest::new(Mode::Block, files(&[1]), Vec::new()).is_err());
    assert!(Manifest::new(Mode::Block, files(&[1]), load(&["f001"])).is_err());
    assert!(Manifest::new(Mode::Block, files(&[1, 1]), load(&["f000", "f000"])).is_err());
    // The paths are in strictly increasing order.
    let twice = vec![entry("f000", 1), entry("f000", 1)];
    assert!(Manifest::new(Mode::Block, twice, load(&["f000"])).is_err());
    let unsorted = vec![entry("f001", 1), entry("f000", 1)];
    assert!(Manifest::new(Mode::Block, unsorted, load(&["f000"])).is_err());
}

#[test]
fn a_bundle_refuses_a_path_twice_and_a_manifest_over_64_kib() {
    let one = path("a.conf");
    let twice = vec![(one.clone(), Vec::new()), (one.clone(), Vec::new())];
    assert_eq!(
        Bundle::new(Mode::Block, twice, vec![one]).unwrap_err(),
        BundleError("a path is used twice in the bundle")
    );
    // 128 files with paths of 247 bytes, all loaded: the manifest is about 75 KiB.
    let names: Vec<BundlePath> = (0..128)
        .map(|i| {
            let part = "x".repeat(80);
            path(&format!("{part}/{part}/{part}/{i:03}"))
        })
        .collect();
    let files = names.iter().map(|n| (n.clone(), Vec::new())).collect();
    assert_eq!(
        Bundle::new(Mode::Block, files, names).unwrap_err(),
        BundleError("the manifest of the bundle is over 64 KiB")
    );
}
