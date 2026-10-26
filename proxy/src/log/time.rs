//! The time of a record, as RFC 3339 in UTC with milliseconds (`2026-10-25T08:00:00.123Z`).
//!
//! The date comes from the number of days since 1970-01-01 by the inverse of the calendar calculation that
//! `acme::der` uses to read a date. A time before 1970 is written as 1970-01-01T00:00:00.000Z, and one after the
//! year 9999 as the last second of that year, so the text always has the same shape.

use std::time::{SystemTime, UNIX_EPOCH};

/// The last second that the text can show: 9999-12-31T23:59:59.
const LAST_SECOND: u64 = 253_402_300_799;

/// The text of `at`.
pub fn rfc3339(at: SystemTime) -> String {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let (secs, millis) = if since.as_secs() > LAST_SECOND {
        (LAST_SECOND, 999)
    } else {
        (since.as_secs(), u64::from(since.subsec_millis()))
    };
    // At most 253 402 300 799, so the day number fits in an `i64`.
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let (year, month, day) = civil_from_days(days);
    let rest = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The date of the day that is `days` days from 1970-01-01 (proleptic Gregorian calendar): year, month, day.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests;
