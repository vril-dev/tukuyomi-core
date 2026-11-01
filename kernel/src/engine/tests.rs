use super::*;

#[test]
fn an_engine_is_read_by_its_lowercase_name_only_and_gives_that_name_back() {
    for engine in [Engine::Coraza, Engine::ModSecurity] {
        assert_eq!(Engine::parse(engine.name()), Some(engine));
    }
    for bad in [
        "",
        "Coraza",
        "MODSECURITY",
        "mod_security",
        "modsecurity ",
        " coraza",
        "coraza\0",
        "libmodsecurity",
    ] {
        assert_eq!(Engine::parse(bad), None, "{bad:?}");
    }
    assert_eq!(Engine::default(), Engine::Coraza);
}

#[test]
fn each_engine_has_the_pinned_build_of_its_inspector() {
    assert_eq!(
        Engine::Coraza.pinned(),
        &Build {
            toolchain: b"go1.27.2",
            version: b"v3.8.1",
            source: b"h1:dMV55FbMR2vOks/acrT43RShR+VkzU6jwp+XPdxay8o=",
        }
    );
    assert_eq!(
        Engine::ModSecurity.pinned(),
        &Build {
            toolchain: b"rustc 1.94.1",
            version: b"v3.0.17",
            source: b"f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50",
        }
    );
}
