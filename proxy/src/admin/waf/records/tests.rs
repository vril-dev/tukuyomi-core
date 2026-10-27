use std::fs;

use super::*;
use crate::admin::file_store::tests::{TestDir, scratch};

fn ts(n: u32) -> String {
    format!("2026-10-25T08:{:02}:{:02}.000Z", n / 60, n % 60)
}

fn request(n: u32, id: &str, status: u16, extra: Value) -> String {
    let mut record = json!({
        "ts": ts(n), "type": "request", "id": id, "conn": 1, "client": "192.0.2.1", "class": "forwarded",
        "status": status, "generation": "0123456789abcdef",
    });
    for (key, value) in extra.as_object().unwrap() {
        record[key] = value.clone();
    }
    record.to_string()
}

/// Writes file number `n` of the records with `lines`, each ended by a line feed.
fn put(dir: &TestDir, n: usize, lines: &[String]) {
    let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
    fs::write(name(dir.path(), STEM, n), text).unwrap();
}

fn plain(n: u32, id: &str) -> String {
    request(n, id, 200, json!({}))
}

/// Ten records in two files: `a10` to `a14` in the file in use, `b0` to `b4` in the file before.
fn ten() -> TestDir {
    let dir = scratch();
    let a = [
        plain(10, "a10"),
        plain(11, "a11"),
        request(
            12,
            "a12",
            403,
            json!({"class": "blocked", "rule": 949_110, "rules": [942_100, 949_110]}),
        ),
        plain(13, "a13"),
        plain(14, "a14"),
    ];
    let b: Vec<String> = (0..5).map(|n| plain(n, &format!("b{n}"))).collect();
    put(&dir, 0, &a);
    put(&dir, 1, &b);
    dir
}

const NEWEST_FIRST: [&str; 10] = [
    "a14", "a13", "a12", "a11", "a10", "b4", "b3", "b2", "b1", "b0",
];

fn ids(page: &Page) -> Vec<&str> {
    page.records
        .iter()
        .map(|record| record["id"].as_str().unwrap())
        .collect()
}

fn find(dir: &TestDir, query: &str) -> Vec<String> {
    let page = read(
        dir.path(),
        3,
        &Query::parse(query).unwrap(),
        Limits::STANDARD,
    )
    .unwrap();
    assert!(page.next.is_none(), "{query}");
    ids(&page).into_iter().map(str::to_owned).collect()
}

#[test]
fn a_filter_finds_the_line_in_any_file_and_the_lines_come_newest_first_as_they_were_written() {
    let dir = ten();
    assert_eq!(find(&dir, ""), NEWEST_FIRST);
    assert_eq!(find(&dir, "id=b2"), ["b2"]);
    assert_eq!(find(&dir, "status=403"), ["a12"]);
    // The id of a rule among the matched ones, and as the rule of the verdict.
    assert_eq!(find(&dir, "rule=942100"), ["a12"]);
    assert_eq!(find(&dir, "rule=949110"), ["a12"]);
    assert_eq!(find(&dir, "class=blocked&type=request"), ["a12"]);
    assert!(find(&dir, "type=connection").is_empty());
    assert_eq!(find(&dir, "client=192.0.2.1&status=200").len(), 9);
    assert_eq!(find(&dir, "generation=0123456789abcdef").len(), 10);
    let long = format!("generation=0123456789abcdef{}", "0".repeat(48));
    assert_eq!(find(&dir, &long).len(), 10);
    assert!(find(&dir, "generation=ffffffffffffffff").is_empty());
    // Both ends of the time are in; the colons may be coded; the fraction may be left out or longer.
    let from = "2026-10-25T08%3A00%3A11Z";
    assert_eq!(
        find(&dir, &format!("from={from}&to=2026-10-25T08:00:13.0009Z")),
        ["a13", "a12", "a11"]
    );
    assert_eq!(
        find(&dir, "from=2026-10-25T08:00:14.001Z"),
        Vec::<String>::new()
    );
    // The line is the one in the file: the text of a request stays as the proxy wrote it.
    let hidden = request(20, "c20", 200, json!({"path": "/a%2Fb%00%22"}));
    put(&dir, 0, std::slice::from_ref(&hidden));
    let page = read(
        dir.path(),
        3,
        &Query::parse("id=c20").unwrap(),
        Limits::STANDARD,
    )
    .unwrap();
    assert_eq!(page.records[0]["path"], "/a%2Fb%00%22");
    assert_eq!(
        page.records[0],
        serde_json::from_str::<Value>(&hidden).unwrap()
    );
}

#[test]
fn a_query_with_a_field_twice_an_unknown_field_or_a_value_of_the_wrong_form_is_refused() {
    for query in [
        "id=a1&id=a2",
        "color=red",
        "id",
        "id=",
        "status=1000",
        "status=x",
        "rule=1.5",
        "client=192.0.2",
        "type=other",
        "generation=0123",
        "from=2026-02-30T00:00:00Z",
        "from=2026-10-25T08:00:00",
        "from=2026-10-25T08:00:00+09:00",
        "to=2026-10-25T24:00:00Z",
        "id=%zz",
        "id=%4",
        "id=a%00",
        "file=1",
        "file=1&offset=2",
        "offset=2&inode=3",
    ] {
        assert!(Query::parse(query).is_err(), "{query}");
    }
    let whole = Query::parse("file=1&offset=2&inode=3").unwrap();
    assert_eq!(
        whole.start,
        Some(Start {
            file: 1,
            offset: 2,
            inode: 3
        })
    );
}

/// The ids that the pages give one after the other until the last, and the number of pages.
fn paged(dir: &TestDir, files: usize, limits: Limits) -> (Vec<String>, usize) {
    let mut query = Query::default();
    let (mut got, mut pages) = (Vec::new(), 0);
    loop {
        let page = read(dir.path(), files, &query, limits).unwrap();
        pages += 1;
        assert!(pages < 100, "the pages do not end");
        got.extend(ids(&page).into_iter().map(str::to_owned));
        match page.next {
            Some(start) => query.start = Some(start),
            None => return (got, pages),
        }
    }
}

#[test]
fn the_limit_of_lines_gives_a_continuation_that_goes_on_at_the_right_line() {
    let dir = ten();
    for lines in [1, 3, 5, 9, 10] {
        // A chunk of 64 bytes cuts the lines of about 190 bytes in many places.
        let limits = Limits {
            lines,
            read: 1 << 30,
            chunk: 64,
        };
        let (got, pages) = paged(&dir, 3, limits);
        assert_eq!(got, NEWEST_FIRST, "{lines} lines a page");
        assert_eq!(pages, 10usize.div_ceil(lines), "{lines} lines a page");
    }
    // 500 lines are the most of an answer.
    assert_eq!(Limits::STANDARD.lines, 500);
}

#[test]
fn the_limit_of_bytes_read_gives_a_continuation_too_and_the_first_chunk_is_always_read() {
    let dir = ten();
    let limits = Limits {
        lines: 100,
        read: 600,
        chunk: 64,
    };
    let (got, pages) = paged(&dir, 3, limits);
    assert_eq!(got, NEWEST_FIRST);
    assert!(pages >= 3, "{pages}");
    // A budget below one chunk still reads that chunk, and goes on from the line it found.
    let tiny = Limits {
        lines: 100,
        read: 1,
        chunk: 4096,
    };
    let (got, _) = paged(&dir, 3, tiny);
    assert_eq!(got, NEWEST_FIRST);
    assert_eq!(Limits::STANDARD.read, 256 << 20);
}

#[test]
fn a_continuation_finds_its_file_again_after_a_rotation_and_a_continuation_that_is_gone_is_refused()
{
    let dir = ten();
    let two = Limits {
        lines: 2,
        ..Limits::STANDARD
    };
    let first = read(dir.path(), 3, &Query::default(), two).unwrap();
    assert_eq!(ids(&first), ["a14", "a13"]);
    let start = first.next.unwrap();
    assert_eq!(start.file, 0);
    // The proxy rotates: the file in use becomes number 1, the one before it number 2, and a new one is in use.
    fs::rename(name(dir.path(), STEM, 1), name(dir.path(), STEM, 2)).unwrap();
    fs::rename(name(dir.path(), STEM, 0), name(dir.path(), STEM, 1)).unwrap();
    put(&dir, 0, &[plain(30, "new")]);
    let query = Query {
        start: Some(start),
        ..Query::default()
    };
    let rest = read(dir.path(), 3, &query, Limits::STANDARD).unwrap();
    assert_eq!(
        ids(&rest),
        ["a12", "a11", "a10", "b4", "b3", "b2", "b1", "b0"]
    );
    assert!(rest.next.is_none());
    // Not an end of a line, and no such file any more.
    let mid = Query {
        start: Some(Start {
            offset: start.offset + 3,
            file: 1,
            ..start
        }),
        ..Query::default()
    };
    assert_eq!(
        read(dir.path(), 3, &mid, Limits::STANDARD).err(),
        Some(Error::Gone)
    );
    fs::remove_file(name(dir.path(), STEM, 1)).unwrap();
    assert_eq!(
        read(dir.path(), 3, &query, Limits::STANDARD).err(),
        Some(Error::Gone)
    );
}

#[test]
fn a_line_that_is_cut_off_too_long_or_not_a_record_is_left_out_whatever_the_chunk() {
    let dir = scratch();
    let long = format!("{}{}", plain(3, "long"), "x".repeat(5000));
    let text = format!(
        "{}\n\nnot json\n[1]\n{{\"id\":\"no-ts\"}}\n{long}\n{}\n{}\n{{\"ts\":\"2026-10-25T08:00:59.000Z\",\"type\":\"requ",
        plain(1, "first"),
        plain(2, "second"),
        "y".repeat(9000),
    );
    fs::write(name(dir.path(), STEM, 0), text).unwrap();
    for chunk in [1, 7, 64, 4096, 1 << 16] {
        let limits = Limits {
            chunk,
            ..Limits::STANDARD
        };
        let page = read(dir.path(), 2, &Query::default(), limits).unwrap();
        assert_eq!(ids(&page), ["second", "first"], "chunk {chunk}");
    }
    // A missing file in use (a rotation is under way) and a directory without records are no lines.
    fs::remove_file(name(dir.path(), STEM, 0)).unwrap();
    let page = read(dir.path(), 2, &Query::default(), Limits::STANDARD).unwrap();
    assert!(page.records.is_empty() && page.next.is_none());
}

#[test]
fn the_read_stops_at_the_first_line_older_than_from() {
    let dir = ten();
    let page = read(
        dir.path(),
        3,
        &Query::parse("from=2026-10-25T08:00:13Z").unwrap(),
        Limits {
            lines: 1,
            ..Limits::STANDARD
        },
    )
    .unwrap();
    assert_eq!(ids(&page), ["a14"]);
    let both = find(&dir, "from=2026-10-25T08:00:13Z");
    assert_eq!(both, ["a14", "a13"]);
}
