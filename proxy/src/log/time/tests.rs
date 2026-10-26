use super::*;
use std::time::Duration;

fn at(secs: u64, millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(secs * 1000 + millis)
}

#[test]
fn the_epoch_a_leap_day_and_a_date_of_2026() {
    assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
    // 2000 is a leap year because 400 divides it.
    assert_eq!(rfc3339(at(951_782_400, 500)), "2000-02-29T00:00:00.500Z");
    assert_eq!(rfc3339(at(951_868_800, 0)), "2000-03-01T00:00:00.000Z");
    assert_eq!(rfc3339(at(1_792_915_200, 123)), "2026-10-25T08:00:00.123Z");
    // The last millisecond of a day, and the start of the next.
    assert_eq!(rfc3339(at(86_399, 999)), "1970-01-01T23:59:59.999Z");
    assert_eq!(rfc3339(at(86_400, 0)), "1970-01-02T00:00:00.000Z");
}

#[test]
fn a_time_outside_the_text_is_held_to_its_ends() {
    assert_eq!(
        rfc3339(UNIX_EPOCH - Duration::from_secs(1)),
        "1970-01-01T00:00:00.000Z"
    );
    assert_eq!(rfc3339(at(LAST_SECOND, 0)), "9999-12-31T23:59:59.000Z");
    assert_eq!(rfc3339(at(LAST_SECOND + 1, 0)), "9999-12-31T23:59:59.999Z");
}
