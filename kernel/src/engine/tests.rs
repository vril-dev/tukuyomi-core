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
fn only_coraza_has_a_pinned_build_so_far() {
    let coraza = Engine::Coraza.pinned().unwrap();
    assert_eq!(
        (coraza.toolchain, coraza.version),
        (&b"go1.27.2"[..], &b"v3.8.1"[..])
    );
    assert_eq!(Engine::ModSecurity.pinned(), None);
}
