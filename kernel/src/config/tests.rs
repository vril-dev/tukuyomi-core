use super::*;

#[test]
fn clean_abs_accepts_only_absolute_clean_paths() {
    for good in ["/w", "/w/tmp", "/w/a.b/c-d", "/..w"] {
        assert!(clean_abs(Path::new(good)), "{good:?}");
    }
    for bad in [
        "", "/", "w/x", "/w/", "/w//x", "/w/./x", "/w/../x", "/w/x\0y", "//w",
    ] {
        assert!(!clean_abs(Path::new(bad)), "{bad:?}");
    }
    let long = format!("/{}", "a".repeat(4094));
    assert!(clean_abs(Path::new(&long)));
    let long = format!("/{}", "a".repeat(4095));
    assert!(!clean_abs(Path::new(&long)));
}
