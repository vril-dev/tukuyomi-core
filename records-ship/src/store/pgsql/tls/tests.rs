use super::*;

#[test]
fn the_connector_is_made_from_the_authorities_of_the_system() {
    assert!(connector().is_ok());
}
