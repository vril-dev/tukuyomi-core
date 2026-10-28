use super::*;

fn made(days: u32) -> (Secret, Token) {
    mint("alice", Role::Operator, "ci", 1000, days).unwrap()
}

#[test]
fn a_token_has_its_form_and_only_that_form_is_taken() {
    let (text, token) = made(30);
    let text = text.as_str();
    assert_eq!(text.len(), 4 + 16 + 1 + 43);
    let (id, secret) = parse(text).unwrap();
    assert_eq!(id, token.id);
    assert!(token.verifies(secret));
    // The text is never what is kept: the store has the SHA-256 of the secret.
    assert!(
        !String::from_utf8(token.encode().unwrap())
            .unwrap()
            .contains(secret)
    );
    assert!(!token.verifies(&"A".repeat(43)));
    assert!(!token.verifies(&secret[1..]));
    for bad in [
        "",
        "tkc_",
        &text[1..],
        &text.replace("tkc_", "tkd_"),
        &text[..text.len() - 1],
        &format!("{text}A"),
        &text.replacen('_', "-", 1),
        &format!("tkc_0123456789ABCDEF_{}", "a".repeat(43)),
    ] {
        assert!(parse(bad).is_none(), "{bad:?}");
    }
    // The secret may have `-` and `_` in it, as the id may not have `_`.
    assert!(parse(&format!("tkc_0123456789abcdef_{}", "_-".repeat(21) + "a")).is_some());
}

#[test]
fn a_token_ends_after_its_days_and_is_kept_and_read_back_whole() {
    let (_, token) = made(365);
    assert_eq!((token.created, token.expires), (1000, 1000 + 365 * DAY_MS));
    let bytes = token.encode().unwrap();
    assert_eq!(Token::decode(&bytes, &token.id).unwrap(), token);
    // Another id, a key that is not known, a role or a name that is not understood: not read.
    assert!(Token::decode(&bytes, "0123456789abcdef").is_err());
    let object = || serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
    let mut extra = object();
    extra["later"] = serde_json::json!(1);
    assert!(Token::decode(extra.to_string().as_bytes(), &token.id).is_err());
    for (key, value) in [
        ("role", "root"),
        ("name", "line\nbreak"),
        ("owner", "Not A Name"),
        ("hash", "00"),
    ] {
        let mut broken = object();
        broken[key] = serde_json::json!(value);
        assert!(
            Token::decode(broken.to_string().as_bytes(), &token.id).is_err(),
            "{key}"
        );
    }
}

#[test]
fn the_name_of_a_token_is_printable_ascii_of_at_most_64_bytes() {
    assert!(valid_name("deploy from CI #1"));
    assert!(valid_name(&"n".repeat(64)));
    for bad in ["", &"n".repeat(65), "tab\there", "caf\u{e9}", "line\nbreak"] {
        assert!(!valid_name(bad), "{bad:?}");
    }
    assert!(valid_id("0123456789abcdef"));
    for bad in ["", "0123456789abcde", "0123456789abcdeF", "../0123456789ab"] {
        assert!(!valid_id(bad), "{bad:?}");
    }
}
