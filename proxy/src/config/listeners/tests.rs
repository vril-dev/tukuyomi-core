use super::*;

/// The `listeners` array with one TLS listener, with `http2` as its `http2` key if that is given.
fn json(http2: Option<&str>) -> String {
    let http2 = http2.map_or_else(String::new, |value| format!(r#","http2":{value}"#));
    format!(
        r#"[{{"address":"127.0.0.1:443","tls":{{"min_version":"1.2","certificates":[{{"cert_file":"/c.pem","key_file":"/k.pem","hosts":["a.example"]}}]{http2}}}}}]"#
    )
}

fn checked(text: &str) -> Result<Vec<ListenerConfig>, ConfigError> {
    check(serde_json::from_str(text).map_err(|_| ConfigError("not accepted by serde"))?)
}

/// The `http2` object with these values.
fn object(streams: u64, stream: u64, connection: u64, list: u64, buffer: u64) -> String {
    format!(
        r#"{{"max_streams":{streams},"stream_window":{stream},"connection_window":{connection},"max_header_list":{list},"send_buffer":{buffer}}}"#
    )
}

fn http2_of(listeners: &[ListenerConfig]) -> Option<Http2Config> {
    match &listeners[0].kind {
        ListenerKind::Tls(tls) => tls.http2,
        _ => panic!("not a TLS listener"),
    }
}

#[test]
fn http2_is_off_without_the_key_and_its_values_are_taken_as_they_are() {
    assert_eq!(http2_of(&checked(&json(None)).unwrap()), None);
    let on = checked(&json(Some(&object(128, 65535, 262_144, 32768, 16384)))).unwrap();
    assert_eq!(
        http2_of(&on),
        Some(Http2Config {
            max_streams: 128,
            stream_window: 65535,
            connection_window: 262_144,
            max_header_list: 32768,
            send_buffer: 16384,
        })
    );
}

#[test]
fn every_value_of_http2_has_its_bounds_and_the_first_value_past_each_is_refused() {
    // The values of a good object, with one changed to the value under test; (index of the value, value, accepted).
    let good = [128, 65535, 262_144, 32768, 16384];
    let cases = [
        (0, 1, true),
        (0, 0, false),
        (0, 256, true),
        (0, 257, false),
        (1, 65535, true),
        (1, 65534, false),
        (1, 1 << 20, true),
        (1, (1 << 20) + 1, false),
        (2, 65535, true),
        (2, 65534, false),
        (2, 4 << 20, true),
        (2, (4 << 20) + 1, false),
        (3, 1024, true),
        (3, 1023, false),
        (4, 1024, true),
        (4, 1023, false),
    ];
    for (at, value, accepted) in cases {
        let mut values = good;
        values[at] = value;
        let text = json(Some(&object(
            values[0], values[1], values[2], values[3], values[4],
        )));
        assert_eq!(checked(&text).is_ok(), accepted, "value {at} = {value}");
    }
    // The send buffer has 1 MiB for itself, which a single stream can hold; one byte more is past it.
    for (buffer, accepted) in [(1 << 20, true), ((1 << 20) + 1, false)] {
        let text = json(Some(&object(1, 65535, 65535, 32768, buffer)));
        assert_eq!(checked(&text).is_ok(), accepted, "send_buffer {buffer}");
    }
}

#[test]
fn what_a_connection_can_hold_is_at_most_16_mib() {
    // `connection_window + max_streams * (send_buffer + 32 KiB)`: 256 streams, the least window, and the buffer
    // that comes to the limit, and the first buffer past it.
    for (buffer, accepted) in [(32512, true), (32513, false)] {
        let text = json(Some(&object(256, 65535, 65535, 32768, buffer)));
        assert_eq!(checked(&text).is_ok(), accepted, "send_buffer {buffer}");
    }
    // The recommended values come to about 6 MiB, and a window of 4 MiB with them is still under the limit.
    assert!(checked(&json(Some(&object(128, 65535, 4 << 20, 32768, 16384)))).is_ok());
}

#[test]
fn what_a_connection_can_hold_with_the_fields_and_a_chunk_of_each_stream_is_at_most_16_mib() {
    // `connection_window + max_streams * (send_buffer + 32 KiB + max_header_list + chunk)`: the recommended values with
    // a 16 KiB chunk come to about 12 MiB; 256 small streams with the chunk that comes to the limit, and one byte more.
    let recommended = checked(&json(Some(&object(128, 65535, 262_144, 32768, 16384)))).unwrap();
    assert!(holds_fit(&recommended, 16384));
    let small = checked(&json(Some(&object(256, 65535, 65535, 1024, 1024)))).unwrap();
    assert!(holds_fit(&small, 30464));
    assert!(!holds_fit(&small, 30465));
    // A listener without http2 holds none of it.
    assert!(holds_fit(&checked(&json(None)).unwrap(), 1 << 20));
}

#[test]
fn a_header_list_is_at_most_four_times_the_head_size_of_the_proxy() {
    let at = checked(&json(Some(&object(128, 65535, 262_144, 32768, 16384)))).unwrap();
    assert!(header_lists_fit(&at, 8192));
    assert!(!header_lists_fit(&at, 8191));
    // A listener without http2, and one that is not TLS, have none.
    assert!(header_lists_fit(&checked(&json(None)).unwrap(), 1024));
    assert!(header_lists_fit(&[], 1024));
}

#[test]
fn http2_is_an_object_with_all_its_keys_and_nothing_else() {
    for text in [
        // null is not "left out".
        json(Some("null")),
        // A key is missing, one is not known, the value is not an object, or a number is not whole.
        json(Some(
            r#"{"max_streams":128,"stream_window":65535,"connection_window":262144,"max_header_list":32768}"#,
        )),
        json(Some(
            r#"{"max_streams":128,"stream_window":65535,"connection_window":262144,"max_header_list":32768,"send_buffer":16384,"adaptive":true}"#,
        )),
        json(Some("[128,65535,262144,32768,16384]")),
        json(Some(
            r#"{"max_streams":128.5,"stream_window":65535,"connection_window":262144,"max_header_list":32768,"send_buffer":16384}"#,
        )),
    ] {
        assert!(checked(&text).is_err(), "{text}");
    }
}
