use std::net::IpAddr;

use super::*;

// ---- a writer of small databases, for the tests of this reader and of everything that needs a database ----

/// The control bytes of a value of the type with this number (1 to 15) and `size`.
fn control(kind: u8, size: usize) -> Vec<u8> {
    let (low, more): (u8, Vec<u8>) = match size {
        0..=28 => (u8::try_from(size).unwrap(), Vec::new()),
        29..=284 => (29, vec![u8::try_from(size - 29).unwrap()]),
        285..=65_820 => (
            30,
            u16::try_from(size - 285).unwrap().to_be_bytes().to_vec(),
        ),
        _ => (
            31,
            u32::try_from(size - 65_821).unwrap().to_be_bytes()[1..].to_vec(),
        ),
    };
    let mut out = if kind <= 7 {
        vec![(kind << 5) | low]
    } else {
        vec![low, kind - 7]
    };
    out.extend(more);
    out
}

pub(crate) fn text(value: &str) -> Vec<u8> {
    [control(2, value.len()), value.as_bytes().to_vec()].concat()
}

/// A number of the type uint16 (5), uint32 (6) or uint64 (9), in as few bytes as it takes.
pub(crate) fn uint(kind: u8, value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    [control(kind, 8 - skip), bytes[skip..].to_vec()].concat()
}

pub(crate) fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = control(7, entries.len());
    for (key, value) in entries {
        out.extend(text(key));
        out.extend(value);
    }
    out
}

fn array(items: &[Vec<u8>]) -> Vec<u8> {
    [control(11, items.len()), items.concat()].concat()
}

/// A pointer to `target`, in the shortest of its four forms.
pub(crate) fn pointer(target: usize) -> Vec<u8> {
    let be = |value: usize, len: usize| value.to_be_bytes()[8 - len..].to_vec();
    let high = |value: usize, shift: u32| u8::try_from(value >> shift).unwrap();
    match target {
        0..2048 => [vec![0x20 | high(target, 8)], be(target, 1)].concat(),
        2048..526_336 => [vec![0x28 | high(target - 2048, 16)], be(target - 2048, 2)].concat(),
        526_336..134_744_064 => [
            vec![0x30 | high(target - 526_336, 24)],
            be(target - 526_336, 3),
        ]
        .concat(),
        _ => [vec![0x38], be(target, 4)].concat(),
    }
}

/// One value of every type, so that reading a record has to go over them to reach the keys after them.
fn every_type() -> Vec<u8> {
    array(&[
        uint(5, 7),
        uint(6, 70_000),
        uint(9, 1 << 40),
        control(10, 0),
        [control(8, 4), vec![0xFF, 0xFF, 0xFF, 0xFE]].concat(),
        [control(3, 8), 1.5f64.to_be_bytes().to_vec()].concat(),
        [control(15, 4), 1.5f32.to_be_bytes().to_vec()].concat(),
        [control(4, 3), vec![1, 2, 3]].concat(),
        control(14, 1),
        control(14, 0),
        map(&[("k", text("v"))]),
    ])
}

/// What a network of a test database holds.
#[derive(Clone)]
pub(crate) enum Record {
    /// A country, with a registered country of the same code.
    Country(&'static str),
    /// A country without a code, and this registered country.
    Registered(&'static str),
    /// A record without a country of any kind.
    Neither,
    /// These bytes of the data section, as they are.
    Data(Vec<u8>),
}

fn encode(record: &Record) -> Vec<u8> {
    match record {
        Record::Country(code) => map(&[
            ("everything", every_type()),
            ("continent", map(&[("code", text("AS"))])),
            (
                "country",
                map(&[
                    ("geoname_id", uint(6, 1_861_060)),
                    ("iso_code", text(code)),
                    (
                        "names",
                        map(&[("en", text("Land")), ("ja", text("\u{56fd}"))]),
                    ),
                ]),
            ),
            ("registered_country", map(&[("iso_code", text(code))])),
        ]),
        Record::Registered(code) => map(&[
            ("country", map(&[("geoname_id", uint(6, 5))])),
            ("registered_country", map(&[("iso_code", text(code))])),
        ]),
        Record::Neither => map(&[("continent", map(&[("code", text("EU"))]))]),
        Record::Data(bytes) => bytes.clone(),
    }
}

/// The values of the metadata that tests change to make a database that is refused.
pub(crate) struct Meta {
    pub nodes: u64,
    pub record_bits: u64,
    pub ip_version: u64,
    pub version: u64,
    pub kind: String,
}

/// The file made of `tree`, `data` and the metadata `meta`.
pub(crate) fn assemble(tree: &[u8], data: &[u8], meta: &Meta) -> Vec<u8> {
    let metadata = map(&[
        ("binary_format_major_version", uint(5, meta.version)),
        ("build_epoch", uint(9, 1_700_000_000)),
        ("database_type", text(&meta.kind)),
        ("description", map(&[("en", text("a test database"))])),
        ("ip_version", uint(5, meta.ip_version)),
        ("languages", array(&[text("en")])),
        ("node_count", uint(6, meta.nodes)),
        ("record_size", uint(5, meta.record_bits)),
    ]);
    [tree, &[0; 16], data, MARKER, &metadata].concat()
}

#[derive(Clone, Copy)]
enum Child {
    Empty,
    Node(usize),
    Data(usize),
}

/// A database of the `networks` (`address/length`, no two of which overlap), each with its record, of the type `kind`,
/// with records of `record_bits` bits. When `ipv6` the tree is one of IPv6 addresses, and an IPv4 network is put under
/// `::/96` as the databases of the MaxMind company do.
pub(crate) fn database_of(
    kind: &str,
    ipv6: bool,
    record_bits: u32,
    networks: &[(&str, Record)],
) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    let mut nodes = vec![[Child::Empty; 2]];
    for (index, (network, record)) in networks.iter().enumerate() {
        offsets.push(data.len());
        data.extend(encode(record));
        let (address, length) = network.split_once('/').unwrap();
        let length: usize = length.parse().unwrap();
        let mut bits = Vec::new();
        let bit_of = |octets: &[u8], i: usize| (octets[i / 8] >> (7 - i % 8)) & 1 == 1;
        match address.parse::<IpAddr>().unwrap() {
            IpAddr::V4(v4) => {
                assert!(length <= 32);
                if ipv6 {
                    bits.extend([false; 96]);
                }
                bits.extend((0..length).map(|i| bit_of(&v4.octets(), i)));
            }
            IpAddr::V6(v6) => {
                assert!(ipv6 && length <= 128);
                bits.extend((0..length).map(|i| bit_of(&v6.octets(), i)));
            }
        }
        let mut at = 0;
        for (depth, &bit) in bits.iter().enumerate() {
            let side = usize::from(bit);
            if depth + 1 == bits.len() {
                nodes[at][side] = Child::Data(index);
                continue;
            }
            at = match nodes[at][side] {
                Child::Node(next) => next,
                Child::Empty => {
                    nodes.push([Child::Empty; 2]);
                    nodes[at][side] = Child::Node(nodes.len() - 1);
                    nodes.len() - 1
                }
                Child::Data(_) => panic!("{network} is inside another network"),
            };
        }
    }
    // As in the databases of the MaxMind company, the IPv4 addresses are in the tree a second time, under ::ffff:0:0/96,
    // by the same nodes.
    if ipv6 && networks.iter().any(|(network, _)| !network.contains(':')) {
        let mut at = 0;
        for _ in 0..96 {
            let Child::Node(next) = nodes[at][0] else {
                unreachable!("the networks put nodes under ::/96")
            };
            at = next;
        }
        let ipv4 = at;
        let mut at = 0;
        for depth in 0..96 {
            let side = usize::from(depth >= 80);
            if depth == 95 {
                nodes[at][side] = Child::Node(ipv4);
                continue;
            }
            at = match nodes[at][side] {
                Child::Node(next) => next,
                _ => {
                    nodes.push([Child::Empty; 2]);
                    nodes[at][side] = Child::Node(nodes.len() - 1);
                    nodes.len() - 1
                }
            };
        }
    }
    let count = nodes.len();
    let value = |child: Child| {
        u32::try_from(match child {
            Child::Empty => count,
            Child::Node(next) => next,
            Child::Data(i) => count + 16 + offsets[i],
        })
        .unwrap()
    };
    let mut tree = Vec::new();
    for [left, right] in &nodes {
        let (left, right) = (value(*left), value(*right));
        match record_bits {
            24 => {
                assert!(left < 1 << 24 && right < 1 << 24);
                tree.extend(&left.to_be_bytes()[1..]);
                tree.extend(&right.to_be_bytes()[1..]);
            }
            28 => {
                assert!(left < 1 << 28 && right < 1 << 28);
                tree.extend(&left.to_be_bytes()[1..]);
                tree.push(u8::try_from(((left >> 24) << 4) | (right >> 24)).unwrap());
                tree.extend(&right.to_be_bytes()[1..]);
            }
            _ => {
                tree.extend(left.to_be_bytes());
                tree.extend(right.to_be_bytes());
            }
        }
    }
    let meta = Meta {
        nodes: count as u64,
        record_bits: u64::from(record_bits),
        ip_version: if ipv6 { 6 } else { 4 },
        version: 2,
        kind: kind.to_owned(),
    };
    assemble(&tree, &data, &meta)
}

/// A database of the type `Test-Country`.
pub(crate) fn database(ipv6: bool, record_bits: u32, networks: &[(&str, Record)]) -> Vec<u8> {
    database_of("Test-Country", ipv6, record_bits, networks)
}

/// A database of IPv4 addresses with one node: the left half of the addresses lead to the record `data`, the right
/// half to nothing.
pub(crate) fn database_with_data(kind: &str, data: &[u8]) -> Vec<u8> {
    let meta = Meta {
        nodes: 1,
        record_bits: 24,
        ip_version: 4,
        version: 2,
        kind: kind.to_owned(),
    };
    assemble(&[0, 0, 17, 0, 0, 1], data, &meta)
}

// ---- the tests ----

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

const NETWORKS: [(&str, Record); 5] = [
    ("203.0.113.0/24", Record::Country("JP")),
    ("198.51.100.0/25", Record::Country("US")),
    ("2001:db8::/32", Record::Country("DE")),
    ("192.0.2.0/24", Record::Registered("FR")),
    ("100.64.0.0/16", Record::Neither),
];

/// The code under `country`, if `ip` has a record that has one.
fn code(db: &Mmdb, address: &str) -> Option<String> {
    let record = db.find(ip(address)).unwrap()?;
    let country = record.get("country").unwrap()?;
    let code = country.get("iso_code").unwrap()?;
    Some(code.text().unwrap().to_owned())
}

fn assert_lookups(db: &Mmdb, ipv6: bool) {
    let known = |address: &str, want: &str| {
        assert_eq!(code(db, address).as_deref(), Some(want), "{address}")
    };
    let none = |address: &str| assert_eq!(code(db, address), None, "{address}");
    // The edges of a /24 and of a /25, and one address past each.
    known("203.0.113.0", "JP");
    known("203.0.113.255", "JP");
    none("203.0.114.0");
    none("203.0.112.255");
    known("198.51.100.127", "US");
    none("198.51.100.128");
    none("8.8.8.8");
    // A record without a code of its country, and one without any country.
    none("192.0.2.1");
    assert!(db.find(ip("192.0.2.1")).unwrap().is_some());
    none("100.64.0.1");
    assert!(db.find(ip("100.64.0.1")).unwrap().is_some());
    assert!(db.find(ip("100.65.0.1")).unwrap().is_none());
    // An IPv4-mapped address is the IPv4 address it holds.
    known("::ffff:203.0.113.1", "JP");
    if ipv6 {
        known("2001:db8::1", "DE");
        known("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "DE");
        none("2001:db9::1");
        none("2001:db7:ffff::1");
    } else {
        // An address of the other family is not found in a tree of IPv4 addresses.
        assert!(db.find(ip("2001:db8::1")).unwrap().is_none());
    }
}

#[test]
fn an_ipv4_and_an_ipv6_address_are_found_in_a_tree_of_ipv6_addresses_of_every_record_size() {
    for bits in [24, 28, 32] {
        let db = Mmdb::parse(database(true, bits, &NETWORKS)).unwrap();
        assert_eq!(db.database_type(), "Test-Country");
        assert_lookups(&db, true);
    }
}

#[test]
fn an_ipv4_tree_finds_ipv4_addresses_and_does_not_find_ipv6_ones() {
    let ipv4: Vec<_> = NETWORKS
        .iter()
        .filter(|(network, _)| !network.contains(':'))
        .cloned()
        .collect();
    for bits in [24, 28] {
        let db = Mmdb::parse(database(false, bits, &ipv4)).unwrap();
        assert_lookups(&db, false);
    }
}

#[test]
fn a_tree_of_ipv6_addresses_without_ipv4_networks_finds_no_ipv4_address() {
    let only: Vec<_> = NETWORKS[2..3].to_vec();
    let db = Mmdb::parse(database(true, 24, &only)).unwrap();
    assert!(db.find(ip("203.0.113.1")).unwrap().is_none());
    assert_eq!(code(&db, "2001:db8::1").as_deref(), Some("DE"));
}

#[test]
fn every_distinct_record_of_the_tree_is_visited_once_in_the_order_of_the_nodes() {
    let db = Mmdb::parse(database(true, 24, &NETWORKS)).unwrap();
    let mut codes = Vec::new();
    db.for_each_record(|record| {
        codes.push(
            record
                .get("country")?
                .and_then(|country| country.get("iso_code").ok().flatten())
                .map(|code| code.text().unwrap().to_owned()),
        );
        Ok(())
    })
    .unwrap();
    // Five networks, five records; the order is that of the tree, which starts with the IPv4 half.
    assert_eq!(codes.len(), 5);
    assert_eq!(codes.iter().flatten().count(), 3);
    // A fault of the visitor stops it.
    let mut seen = 0;
    let stopped = db.for_each_record(|_| {
        seen += 1;
        Err(Fault("stop"))
    });
    assert_eq!((stopped, seen), (Err(Fault("stop")), 1));
}

fn refused(bytes: Vec<u8>) -> &'static str {
    Mmdb::parse(bytes).err().expect("the file is refused").0
}

#[test]
fn a_file_that_is_cut_or_has_metadata_that_cannot_be_used_is_refused() {
    let full = database(true, 24, &NETWORKS);
    let marker = full
        .windows(MARKER.len())
        .rposition(|part| part == MARKER)
        .unwrap();
    // Nothing, half the file, and the file up to the marker: no metadata. Cut inside the metadata, it does not read.
    assert_eq!(refused(Vec::new()), NO_METADATA.0);
    assert_eq!(refused(full[..full.len() / 2].to_vec()), NO_METADATA.0);
    assert_eq!(refused(full[..marker].to_vec()), NO_METADATA.0);
    assert_eq!(refused(full[..full.len() - 5].to_vec()), BAD_METADATA.0);
    // A marker alone ends the file with an empty metadata.
    assert_eq!(refused(MARKER.to_vec()), BAD_METADATA.0);
    // The marker is looked for in the last 128 KiB only.
    let mut far = full.clone();
    far.extend(vec![0u8; MAX_METADATA + MARKER.len()]);
    assert_eq!(refused(far), NO_METADATA.0);
    // The last marker is the one that counts: the bytes of the marker inside the data do not end the data.
    let inside = Record::Data(map(&[(
        "m",
        [control(4, MARKER.len()), MARKER.to_vec()].concat(),
    )]));
    assert!(Mmdb::parse(database(false, 24, &[("203.0.113.0/24", inside)])).is_ok());
}

#[test]
fn metadata_with_a_value_that_cannot_be_used_is_refused() {
    let base = |change: &dyn Fn(&mut Meta)| {
        let tree = [0, 0, 17, 0, 0, 1];
        let mut meta = Meta {
            nodes: 1,
            record_bits: 24,
            ip_version: 4,
            version: 2,
            kind: "Test-Country".to_owned(),
        };
        change(&mut meta);
        assemble(&tree, &map(&[("a", text("b"))]), &meta)
    };
    assert!(Mmdb::parse(base(&|_| ())).is_ok());
    assert_eq!(refused(base(&|m| m.version = 3)), BAD_VERSION.0);
    assert_eq!(refused(base(&|m| m.version = 1)), BAD_VERSION.0);
    for bits in [0, 16, 20, 23, 25, 27, 29, 31, 33, 48] {
        assert_eq!(
            refused(base(&|m| m.record_bits = bits)),
            BAD_RECORD_SIZE.0,
            "{bits}"
        );
    }
    for version in [0, 3, 5, 7] {
        assert_eq!(refused(base(&|m| m.ip_version = version)), BAD_IP_VERSION.0);
    }
    assert_eq!(refused(base(&|m| m.nodes = 0)), NO_NODES.0);
    // A tree of two nodes does not fit before the data: the file holds the bytes of one and the 16 of the gap, and
    // a tree that is longer than the file by one byte is refused too.
    assert_eq!(refused(base(&|m| m.nodes = 2)), BAD_TREE.0);
    assert_eq!(
        refused(base(&|m| m.nodes = u64::from(u32::MAX))),
        BAD_TREE.0
    );
    assert_eq!(
        refused(base(&|m| m.nodes = u64::from(u32::MAX) + 1)),
        BAD_METADATA.0
    );
}

#[test]
fn the_high_bits_of_a_record_are_read_from_the_bytes_that_hold_them_for_every_record_size() {
    let node = |record_bits: u32, bytes: &[u8]| Mmdb {
        bytes: bytes.to_vec(),
        nodes: 1,
        node_len: bytes.len(),
        record_bits,
        ipv6: false,
        ipv4_start: 0,
        data: bytes.len()..bytes.len(),
        kind: String::new(),
    };
    // Records of 28 bits share the middle byte: its high four bits are the top four bits of the left record, and its
    // low four bits those of the right record. Each record has bits set in all of its bytes.
    let db = node(28, &[0x12, 0x34, 0x56, 0xAB, 0x78, 0x9A, 0xBC]);
    assert_eq!(db.record(0, false), Ok(0x0A12_3456));
    assert_eq!(db.record(0, true), Ok(0x0B78_9ABC));
    let db = node(24, &[0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6]);
    assert_eq!(db.record(0, false), Ok(0x00A1_B2C3));
    assert_eq!(db.record(0, true), Ok(0x00D4_E5F6));
    let db = node(32, &[0x81, 0x02, 0x03, 0x04, 0xF5, 0x06, 0x07, 0x08]);
    assert_eq!(db.record(0, false), Ok(0x8102_0304));
    assert_eq!(db.record(0, true), Ok(0xF506_0708));
}

/// `database` with the first record of the first node (24 bits) set to `record`.
fn with_first_record(record: u32) -> Vec<u8> {
    let mut file = database(false, 24, &NETWORKS[..1]);
    file[..3].copy_from_slice(&record.to_be_bytes()[1..]);
    file
}

#[test]
fn a_record_of_the_tree_that_leads_outside_the_data_is_refused_at_the_first_byte_past_it() {
    // The tree of the one network has 24 nodes, and the data is its one record.
    let count = 24;
    let record_len = u32::try_from(encode(&NETWORKS[0].1).len()).unwrap();
    let last = count + 16 + record_len - 1;
    assert!(Mmdb::parse(with_first_record(last)).is_ok());
    assert_eq!(refused(with_first_record(last + 1)), OUTSIDE.0);
    // Inside the gap of 16 bytes before the data, and at the largest number a record takes.
    assert_eq!(refused(with_first_record(count + 1)), OUTSIDE.0);
    assert_eq!(refused(with_first_record(count + 15)), OUTSIDE.0);
    assert_eq!(refused(with_first_record(0xFF_FFFF)), OUTSIDE.0);
    // The first byte of the data, the last node and the end of the nodes (nothing) are fine.
    assert!(Mmdb::parse(with_first_record(count + 16)).is_ok());
    assert!(Mmdb::parse(with_first_record(count - 1)).is_ok());
    assert!(Mmdb::parse(with_first_record(count)).is_ok());
}

#[test]
fn a_tree_that_is_deeper_than_an_address_or_goes_round_is_refused_and_a_lookup_does_not_loop() {
    // `nodes` nodes in a row: the left record of each leads to the next one and the last one to `closing`, the right
    // records lead to nothing.
    let chain = |nodes: usize, closing: u32| {
        let mut tree = Vec::new();
        for i in 0..nodes {
            let next = if i + 1 < nodes {
                u32::try_from(i + 1).unwrap()
            } else {
                closing
            };
            tree.extend(&next.to_be_bytes()[1..]);
            tree.extend(&u32::try_from(nodes).unwrap().to_be_bytes()[1..]);
        }
        let meta = Meta {
            nodes: nodes as u64,
            record_bits: 24,
            ip_version: 4,
            version: 2,
            kind: "Test-Country".to_owned(),
        };
        assemble(&tree, &[], &meta)
    };
    // The 32 bits of an IPv4 address take 32 nodes; one more is deeper than the address.
    let db = Mmdb::parse(chain(32, 32)).unwrap();
    assert!(db.find(ip("0.0.0.0")).unwrap().is_none());
    assert!(db.find(ip("128.0.0.0")).unwrap().is_none());
    assert_eq!(refused(chain(33, 33)), SHALLOW.0);
    assert_eq!(refused(chain(40, 40)), SHALLOW.0);
    // The last node leads back to the first, or to itself.
    assert_eq!(refused(chain(3, 0)), SHALLOW.0);
    assert_eq!(refused(chain(1, 0)), SHALLOW.0);
}

#[test]
fn a_node_that_is_reached_a_second_time_too_deep_for_its_height_is_refused() {
    // A tree of IPv6 addresses. A spine of 96 nodes (the left records) leads to a chain of 32 nodes, which is walked
    // first: its head is 96 nodes below the root and it is 32 high. The right record of the root leads to a row of `row`
    // nodes whose last one leads to the same head, `row + 1` nodes below the root. A walk may pass 128 nodes in all, so
    // a head at 96 nodes below the root still fits and one at 97 does not.
    let aliased = |row: usize| {
        let (spine, chain) = (96, 32);
        let count = spine + chain + row;
        let at = |i: usize| u32::try_from(i).unwrap();
        // Every record leads to nothing unless it is set here.
        let mut nodes = vec![[at(count); 2]; count];
        for (i, node) in nodes.iter_mut().enumerate().take(spine + chain - 1) {
            node[0] = at(i + 1);
        }
        nodes[0][1] = at(spine + chain);
        for (i, node) in nodes.iter_mut().enumerate().skip(spine + chain) {
            node[0] = if i + 1 < count { at(i + 1) } else { at(spine) };
        }
        let tree: Vec<u8> = nodes
            .iter()
            .flatten()
            .flat_map(|record| record.to_be_bytes()[1..].to_vec())
            .collect();
        let meta = Meta {
            nodes: count as u64,
            record_bits: 24,
            ip_version: 6,
            version: 2,
            kind: "Test-Country".to_owned(),
        };
        assemble(&tree, &[], &meta)
    };
    assert!(Mmdb::parse(aliased(95)).is_ok());
    assert_eq!(refused(aliased(96)), SHALLOW.0);
}

#[test]
fn a_value_of_every_type_is_read_over_and_pointers_of_every_form_are_followed() {
    // Each form of pointer is met in a section that is long enough for its target: the text is at the target.
    /// Makes the pointer to a target.
    type Make = Box<dyn Fn(usize) -> Vec<u8>>;
    let forms: [(usize, Make); 4] = [
        (3, Box::new(pointer)),
        (2048 + 5000, Box::new(pointer)),
        (526_336 + 1000, Box::new(pointer)),
        // The fourth form holds the whole offset, and a database may use it for any offset.
        (
            700_000,
            Box::new(|target| {
                [
                    vec![0x38],
                    u32::try_from(target).unwrap().to_be_bytes().to_vec(),
                ]
                .concat()
            }),
        ),
    ];
    for (form, (target, make)) in forms.iter().enumerate() {
        let mut section = vec![0u8; *target];
        section.extend(text("JP"));
        let at = section.len();
        let bytes = make(*target);
        assert_eq!(usize::from((bytes[0] >> 3) & 3), form, "{target}");
        section.extend(&bytes);
        assert_eq!(Value::at(&section, at).text(), Ok("JP"), "{target}");
        assert_eq!(Value::at(&section, at).check(), Ok(()), "{target}");
        // A pointer to the first offset past the section is refused.
        let second = section.len();
        section.extend(make(second + bytes.len()));
        assert_eq!(
            Value::at(&section, second).text().err(),
            Some(OUTSIDE),
            "{target}"
        );
    }
    // A key that is a pointer to a text, and a value that is a pointer, which `get` goes over.
    let mut section = text("iso_code");
    let map_at = section.len();
    section.extend(control(7, 3));
    section.extend(pointer(0));
    section.extend(text("JP"));
    section.extend(text("p"));
    section.extend(pointer(0));
    section.extend(text("n"));
    section.extend(uint(9, u64::MAX));
    let root = Value::at(&section, map_at);
    assert_eq!(root.get("iso_code").unwrap().unwrap().text(), Ok("JP"));
    assert_eq!(root.get("p").unwrap().unwrap().text(), Ok("iso_code"));
    assert_eq!(root.get("n").unwrap().unwrap().unsigned(), Ok(u64::MAX));
    assert!(root.get("absent").unwrap().is_none());
    assert_eq!(root.check(), Ok(()));
    // A map after a value of every type is reached by going over them.
    let skipping = map(&[("everything", every_type()), ("n", uint(6, 70_000))]);
    let root = Value::at(&skipping, 0);
    assert_eq!(root.get("n").unwrap().unwrap().unsigned(), Ok(70_000));
    assert_eq!(root.check(), Ok(()));
    // Numbers: none, a short one, and a value that is not a number or not a text or not a map.
    assert_eq!(uint(5, 0).len(), 1);
    assert_eq!(Value::at(&uint(5, 0), 0).unsigned(), Ok(0));
    assert_eq!(Value::at(&uint(6, 255), 0).unsigned(), Ok(255));
    assert_eq!(Value::at(&text("x"), 0).unsigned(), Err(NOT_NUMBER));
    assert_eq!(Value::at(&uint(5, 1), 0).text(), Err(NOT_TEXT));
    assert_eq!(Value::at(&uint(5, 1), 0).get("a").err(), Some(NOT_MAP));
    // A text of 29, 285 and 65821 bytes uses the longer forms of the size.
    for len in [28, 29, 284, 285, 65_820, 65_821] {
        let value = text(&"a".repeat(len));
        assert_eq!(Value::at(&value, 0).text().unwrap().len(), len);
        assert_eq!(Value::at(&value, 0).skip(0), Ok(value.len()));
    }
}

fn faulty(section: &[u8]) -> Fault {
    Value::first(section)
        .check()
        .expect_err("the value is refused")
}

#[test]
fn a_value_that_is_cut_or_does_not_fit_its_type_or_goes_in_a_loop_is_refused() {
    // Cut short: a text that claims ten bytes, a map without its value, an empty section.
    assert_eq!(faulty(&[control(2, 10), b"abc".to_vec()].concat()), CUT);
    assert_eq!(faulty(&[control(7, 1), text("a")].concat()), CUT);
    assert_eq!(faulty(&[]), CUT);
    // Sizes: a double of 4 bytes, a float of 8, a uint16 of 3, a uint32 of 5, a uint64 of 9, a uint128 of 17, an int32
    // of 5, a boolean of 2.
    for (kind, size) in [
        (3, 4),
        (15, 8),
        (5, 3),
        (6, 5),
        (9, 9),
        (10, 17),
        (8, 5),
        (14, 2),
    ] {
        let value = [control(kind, size), vec![0; size]].concat();
        assert_eq!(faulty(&value), BAD_SIZE, "{kind} {size}");
    }
    // The types that the data section does not use, and the extended type 0.
    assert_eq!(faulty(&[0, 5]), BAD_TYPE);
    assert_eq!(faulty(&[0, 6]), BAD_TYPE);
    assert_eq!(faulty(&[0, 0]), BAD_TYPE);
    assert_eq!(faulty(&[0, 9]), BAD_TYPE);
    // A key that is not a text, a text that is not UTF-8.
    assert_eq!(
        faulty(&[control(7, 1), uint(5, 1), text("v")].concat()),
        NOT_TEXT
    );
    assert_eq!(
        faulty(&[control(2, 2), vec![0xFF, 0xFE]].concat()),
        NOT_UTF8
    );
    // A pointer to a pointer, and a map that holds a pointer to itself.
    assert_eq!(faulty(&[pointer(2), pointer(0)].concat()), CHAIN);
    let looped = [control(7, 1), text("country"), pointer(0)].concat();
    assert_eq!(faulty(&looped), DEEP);
    // A pointer past the end of the section.
    assert_eq!(faulty(&pointer(5)), OUTSIDE);
}

#[test]
fn nesting_up_to_the_depth_limit_passes_and_one_level_more_is_refused() {
    let nested = |levels: usize| {
        let mut value = text("end");
        for _ in 0..levels {
            value = map(&[("k", value)]);
        }
        value
    };
    // The text at the end is at the depth of the number of levels.
    assert_eq!(Value::first(&nested(16)).check(), Ok(()));
    assert_eq!(faulty(&nested(17)), DEEP);
    let mut arrays = text("end");
    for _ in 0..17 {
        arrays = array(&[arrays]);
    }
    assert_eq!(faulty(&arrays), DEEP);
    // The same through skipping, which `get` does over the entries that come before the key.
    let before = map(&[("deep", nested(17)), ("k", text("v"))]);
    assert_eq!(Value::first(&before).get("k").err(), Some(DEEP));
}

#[test]
fn a_value_with_more_values_in_it_than_the_limit_is_refused() {
    let list = |items: usize| array(&vec![uint(5, 0); items]);
    // The array and its items are the values: 4096 in all pass.
    assert_eq!(Value::first(&list(4095)).check(), Ok(()));
    assert_eq!(faulty(&list(4096)), MANY);
    // What a pointer leads to is counted each time it is met: 100 pointers to an array of 100 items.
    let mut section = list(100);
    let pointers = array(&vec![pointer(0); 100]);
    let at = section.len();
    section.extend(&pointers);
    assert_eq!(Value::at(&section, at).check().err(), Some(MANY));
}

#[test]
fn the_bytes_of_a_text_or_a_key_cost_units_and_a_pointer_to_a_text_pays_for_it_each_time() {
    // The array and the text are two units, and the text is one unit more for every 64 bytes of it: the longest
    // text that passes, and one byte more.
    let longest = (usize::try_from(MAX_VALUES).unwrap() - 2) * TEXT_UNIT + (TEXT_UNIT - 1);
    let in_array = |len: usize| array(&[text(&"a".repeat(len))]);
    assert_eq!(Value::first(&in_array(longest)).check(), Ok(()));
    assert_eq!(faulty(&in_array(longest + 1)), MANY);
    // A key costs the same: the map and its value are two units.
    let long_key = |len: usize| map(&[("k".repeat(len).as_str(), text("v"))]);
    assert_eq!(Value::first(&long_key(longest)).check(), Ok(()));
    assert_eq!(faulty(&long_key(longest + 1)), MANY);
    // A text of 4 KiB is 64 units, and a pointer to it costs the pointer, the text and those units each time it is met:
    // 62 pointers and the array come to 4093 units, 63 to 4159.
    let mut section = text(&"a".repeat(4096));
    assert_eq!(Value::first(&section).check(), Ok(()));
    let at = section.len();
    section.extend(array(&vec![pointer(0); 62]));
    assert_eq!(Value::at(&section, at).check(), Ok(()));
    let more = section.len();
    section.extend(array(&vec![pointer(0); 63]));
    assert_eq!(Value::at(&section, more).check().err(), Some(MANY));
}

#[test]
fn a_database_whose_record_is_a_pointer_loop_or_too_deep_is_refused_where_the_records_are_checked()
{
    let loop_data = [control(7, 1), text("country"), pointer(0)].concat();
    let db = Mmdb::parse(database_with_data("Test-Country", &loop_data)).unwrap();
    assert_eq!(db.for_each_record(|record| record.check()), Err(DEEP));
    // A lookup on it does not loop either: reading goes over a pointer and does not follow it.
    let record = db.find(ip("1.2.3.4")).unwrap().unwrap();
    let country = record.get("country").unwrap().unwrap();
    assert!(country.get("x").unwrap().is_none());
    assert!(country.get("country").unwrap().is_some());
}
