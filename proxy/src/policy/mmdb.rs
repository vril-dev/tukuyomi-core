//! A reader of the MaxMind DB format, version 2, written from the public format specification. It holds the bytes of a
//! file and the few numbers of its metadata, and reads nothing else from outside: no dependency, no `unsafe`, no
//! mapping of the file.
//!
//! A file is a search tree, 16 bytes of zeros, the data section, and the metadata section, which starts after the last
//! `\xAB\xCD\xEFMaxMind.com` of the file (looked for in the last 128 KiB only). The metadata is a map in the form of
//! the data section; `binary_format_major_version` (2), `node_count`, `record_size` (24, 28 or 32 bits), `ip_version`
//! (4 or 6) and `database_type` are read from it. The tree has `node_count` nodes of two records each. A record below
//! `node_count` names the next node, one equal to it says that nothing is known for the addresses below it, and a
//! larger one points into the data section, `record - node_count - 16` bytes from its start. An address is walked one
//! bit at a time from the root, and an IPv4 address in a tree of IPv6 addresses starts at the node that 96 zero bits
//! lead to (`::/96`).
//!
//! The bytes are not trusted. `Mmdb::parse` checks the metadata, the length of the tree against the length of the file,
//! the place that every record of the tree refers to, and that no walk of the tree goes round or passes more nodes than
//! an address has bits (so a lookup always ends in a record). `Value::check` goes through a value of the data section and
//! everything its pointers lead to, and refuses a value that is cut short, a pointer outside the section or to another
//! pointer (the specification forbids it, and it is how a loop would be made), a size that does not fit the type, a
//! text that is not UTF-8, a key that is not a text, nesting deeper than `MAX_DEPTH`, and a value that costs more than
//! `MAX_VALUES` units (each value is one unit, each key or text is one unit more for every `TEXT_UNIT` bytes of it, and
//! what a pointer leads to is counted each time it is met). Every read is a bounds-checked `get`, so bad data gives a
//! `Fault` and never a panic.
//! Checking every record that the tree leads to (`for_each_record` and `Value::check`) takes at most `MAX_VALUES` units
//! for each distinct record, so it validates at most `MAX_VALUES * TEXT_UNIT` bytes of text for each. A lookup that
//! comes after the check does not validate a key again: `get` compares the keys as bytes.

use std::net::IpAddr;
use std::ops::Range;

/// Why a database was refused: a fixed sentence that carries no value of the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault(pub &'static str);

/// The text that starts the metadata section.
const MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";
/// The longest the metadata section may be, the marker not counted.
const MAX_METADATA: usize = 128 * 1024;
/// The bytes between the search tree and the data section.
const SEPARATOR: usize = 16;
/// The deepest nesting of maps, arrays and pointers that `Value::check` takes.
const MAX_DEPTH: u32 = 16;
/// The most units that `Value::check` goes through for one value: a value is one unit, and a text or a key is one
/// more for every `TEXT_UNIT` bytes of it.
const MAX_VALUES: u32 = 4096;
/// The bytes of a text that cost one unit of `MAX_VALUES`.
const TEXT_UNIT: usize = 64;
/// In the heights of the nodes (see `Mmdb::height`), the mark of a node that the walk is passing now.
const ON_PATH: u8 = u8::MAX;

const NO_METADATA: Fault = Fault("the country database has no metadata section");
const BAD_METADATA: Fault = Fault("the country database has metadata that cannot be used");
const BAD_VERSION: Fault = Fault("the country database is not of format version 2");
const BAD_RECORD_SIZE: Fault =
    Fault("the country database has a record size that is not 24, 28 or 32 bits");
const BAD_IP_VERSION: Fault = Fault("the country database is not of IPv4 or IPv6 addresses");
const NO_NODES: Fault = Fault("the country database has no nodes");
const BAD_TREE: Fault =
    Fault("the country database has a search tree that does not fit before its data section");
const OUTSIDE: Fault =
    Fault("the country database has a reference that is outside its data section");
const SHALLOW: Fault =
    Fault("the country database has a search tree that goes round or is deeper than an address");
const CUT: Fault = Fault("the country database has a value that is cut short");
const BAD_TYPE: Fault = Fault("the country database has a value of a type that it may not have");
const BAD_SIZE: Fault = Fault("the country database has a value whose size does not fit its type");
const CHAIN: Fault = Fault("the country database has a pointer to a pointer");
const DEEP: Fault = Fault("the country database has values nested too deep");
const MANY: Fault =
    Fault("the country database has a record with too many values or too much text");
const NOT_MAP: Fault =
    Fault("the country database has a value that is not a map where one is needed");
const NOT_TEXT: Fault =
    Fault("the country database has a value that is not a text where one is needed");
const NOT_NUMBER: Fault =
    Fault("the country database has a value that is not a number where one is needed");
const NOT_UTF8: Fault = Fault("the country database has a text that is not UTF-8");

/// The types of the data section that a value can have. The cache container and the end marker are not among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Pointer,
    Text,
    Double,
    Bytes,
    Uint16,
    Uint32,
    Map,
    Int32,
    Uint64,
    Uint128,
    Array,
    Boolean,
    Float,
}

/// The control bytes of a value, read.
struct Head {
    kind: Kind,
    /// A pointer: the offset it holds. A map or an array: how many entries (pairs for a map). A boolean: its value.
    /// Any other: the bytes of its payload.
    size: usize,
    /// Where the payload, or the first entry, starts.
    body: usize,
    /// Where the payload ends, or for a value without one (a pointer, a map, an array, a boolean) where it starts.
    end: usize,
}

/// A value of a section (of the data, or of the metadata): the bytes of the section and where the value starts. A
/// pointer is an offset from the start of the section.
#[derive(Clone, Copy, Debug)]
pub struct Value<'a> {
    section: &'a [u8],
    at: usize,
}

/// `size` if it is `want`, the size of the payload of a double or a float.
fn exact(size: usize, want: usize) -> Result<usize, Fault> {
    if size == want {
        Ok(size)
    } else {
        Err(BAD_SIZE)
    }
}

/// `size` if it is at most `most`: a number may be written with fewer bytes than its type has.
fn at_most(size: usize, most: usize) -> Result<usize, Fault> {
    if size <= most {
        Ok(size)
    } else {
        Err(BAD_SIZE)
    }
}

impl<'a> Value<'a> {
    fn at(section: &'a [u8], at: usize) -> Value<'a> {
        Value { section, at }
    }

    /// The first value of a section: the map of the metadata, which is a section of its own.
    fn first(section: &'a [u8]) -> Value<'a> {
        Value::at(section, 0)
    }

    fn head(&self) -> Result<Head, Fault> {
        let section = self.section;
        let byte = |at: usize| section.get(at).copied().map(usize::from).ok_or(CUT);
        let number = |at: usize, len: usize| {
            let end = at.checked_add(len).ok_or(CUT)?;
            let bytes = section.get(at..end).ok_or(CUT)?;
            Ok::<usize, Fault>(bytes.iter().fold(0, |sum, &b| (sum << 8) | usize::from(b)))
        };
        let control = byte(self.at)?;
        let mut at = self.at + 1;
        let mut number_of_kind = control >> 5;
        if number_of_kind == 0 {
            // An extended type: the type is 7 more than the next byte, which is never 0.
            let extended = byte(at)?;
            at += 1;
            if extended == 0 {
                return Err(BAD_TYPE);
            }
            number_of_kind = 7 + extended;
        }
        if number_of_kind == 1 {
            // A pointer. The size bits tell how many bytes follow (1 to 4); the low bits of the control byte are the
            // high bits of the offset, which the second and the third form offset from 2048 and from 526336.
            let high = control & 7;
            let (high, len, base) = match (control >> 3) & 3 {
                0 => (high << 8, 1, 0),
                1 => (high << 16, 2, 2048),
                2 => (high << 24, 3, 526_336),
                _ => (0, 4, 0),
            };
            let target = (high | number(at, len)?).checked_add(base).ok_or(OUTSIDE)?;
            at += len;
            if target >= section.len() {
                return Err(OUTSIDE);
            }
            return Ok(Head {
                kind: Kind::Pointer,
                size: target,
                body: at,
                end: at,
            });
        }
        let mut size = control & 31;
        if size >= 29 {
            let (len, base) = match size {
                29 => (1, 29),
                30 => (2, 285),
                _ => (3, 65_821),
            };
            size = number(at, len)? + base;
            at += len;
        }
        let (kind, payload) = match number_of_kind {
            2 => (Kind::Text, size),
            3 => (Kind::Double, exact(size, 8)?),
            4 => (Kind::Bytes, size),
            5 => (Kind::Uint16, at_most(size, 2)?),
            6 => (Kind::Uint32, at_most(size, 4)?),
            7 => (Kind::Map, 0),
            8 => (Kind::Int32, at_most(size, 4)?),
            9 => (Kind::Uint64, at_most(size, 8)?),
            10 => (Kind::Uint128, at_most(size, 16)?),
            11 => (Kind::Array, 0),
            14 => (Kind::Boolean, at_most(size, 1).map(|_| 0)?),
            15 => (Kind::Float, exact(size, 4)?),
            _ => return Err(BAD_TYPE),
        };
        let end = at
            .checked_add(payload)
            .filter(|&end| end <= section.len())
            .ok_or(CUT)?;
        Ok(Head {
            kind,
            size,
            body: at,
            end,
        })
    }

    /// The value this one stands for: itself, or the value its pointer points to, which is not a pointer itself.
    fn resolved(&self) -> Result<Value<'a>, Fault> {
        let head = self.head()?;
        if head.kind != Kind::Pointer {
            return Ok(*self);
        }
        let target = Value::at(self.section, head.size);
        if target.head()?.kind == Kind::Pointer {
            return Err(CHAIN);
        }
        Ok(target)
    }

    /// The bytes of the text of the value, which are not looked at.
    fn text_bytes(&self) -> Result<&'a [u8], Fault> {
        let value = self.resolved()?;
        let head = value.head()?;
        if head.kind != Kind::Text {
            return Err(NOT_TEXT);
        }
        self.section.get(head.body..head.end).ok_or(CUT)
    }

    /// The text of the value.
    pub fn text(&self) -> Result<&'a str, Fault> {
        std::str::from_utf8(self.text_bytes()?).map_err(|_| NOT_UTF8)
    }

    /// The text of the value, after its cost has been taken off `budget`.
    fn text_within(&self, budget: &mut u32) -> Result<&'a str, Fault> {
        let bytes = self.text_bytes()?;
        let cost = u32::try_from(bytes.len() / TEXT_UNIT).map_err(|_| MANY)?;
        *budget = budget.checked_sub(cost).ok_or(MANY)?;
        std::str::from_utf8(bytes).map_err(|_| NOT_UTF8)
    }

    /// The number of a value of the type uint16, uint32 or uint64.
    pub fn unsigned(&self) -> Result<u64, Fault> {
        let value = self.resolved()?;
        let head = value.head()?;
        if !matches!(head.kind, Kind::Uint16 | Kind::Uint32 | Kind::Uint64) {
            return Err(NOT_NUMBER);
        }
        let bytes = self.section.get(head.body..head.end).ok_or(CUT)?;
        Ok(bytes.iter().fold(0, |sum, &b| (sum << 8) | u64::from(b)))
    }

    /// The value under `key` of the map that this value is, or `None` if the map has no such key. Reading goes on
    /// over the entries before the key and stops at it. The keys are compared as bytes, and not validated again:
    /// `check` has seen that they are UTF-8.
    pub fn get(&self, key: &str) -> Result<Option<Value<'a>>, Fault> {
        let map = self.resolved()?;
        let head = map.head()?;
        if head.kind != Kind::Map {
            return Err(NOT_MAP);
        }
        let mut at = head.body;
        for _ in 0..head.size {
            let name = Value::at(self.section, at);
            let text = name.text_bytes()?;
            let value = Value::at(self.section, name.head()?.end);
            if text == key.as_bytes() {
                return Ok(Some(value));
            }
            at = value.skip(1)?;
        }
        Ok(None)
    }

    /// Where the value ends. A pointer is the bytes of the pointer; it is not followed.
    fn skip(&self, depth: u32) -> Result<usize, Fault> {
        if depth > MAX_DEPTH {
            return Err(DEEP);
        }
        let head = self.head()?;
        let entries = match head.kind {
            Kind::Map => head.size.checked_mul(2).ok_or(CUT)?,
            Kind::Array => head.size,
            _ => return Ok(head.end),
        };
        let mut at = head.body;
        for _ in 0..entries {
            at = Value::at(self.section, at).skip(depth + 1)?;
        }
        Ok(at)
    }

    /// Goes through the value and everything its pointers lead to, and returns where the value ends.
    fn walk(&self, depth: u32, budget: &mut u32) -> Result<usize, Fault> {
        if depth > MAX_DEPTH {
            return Err(DEEP);
        }
        *budget = budget.checked_sub(1).ok_or(MANY)?;
        let head = self.head()?;
        match head.kind {
            Kind::Pointer => {
                self.resolved()?.walk(depth + 1, budget)?;
                Ok(head.end)
            }
            Kind::Map => {
                let mut at = head.body;
                for _ in 0..head.size {
                    let name = Value::at(self.section, at);
                    name.text_within(budget)?;
                    at = Value::at(self.section, name.head()?.end).walk(depth + 1, budget)?;
                }
                Ok(at)
            }
            Kind::Array => {
                let mut at = head.body;
                for _ in 0..head.size {
                    at = Value::at(self.section, at).walk(depth + 1, budget)?;
                }
                Ok(at)
            }
            Kind::Text => {
                self.text_within(budget)?;
                Ok(head.end)
            }
            _ => Ok(head.end),
        }
    }

    /// Checks the value as far as it goes: see the module documentation for what is refused.
    pub fn check(&self) -> Result<(), Fault> {
        let mut budget = MAX_VALUES;
        self.walk(0, &mut budget).map(|_| ())
    }
}

/// Where a record of the tree leads.
enum Step {
    /// To another node of the tree.
    Node,
    /// Nowhere: nothing is known for the addresses below it.
    Nothing,
    /// To the value at this offset of the data section.
    Data(usize),
}

/// A database that was parsed.
pub struct Mmdb {
    bytes: Vec<u8>,
    nodes: u32,
    /// The bytes of a node: two records of 24, 28 or 32 bits.
    node_len: usize,
    record_bits: u32,
    ipv6: bool,
    /// The record where the walk of an IPv4 address starts: the node that 96 zero bits lead to in a tree of IPv6
    /// addresses (or the end of the walk, if a record leads away from the tree sooner), and the root in a tree of
    /// IPv4 addresses.
    ipv4_start: u32,
    /// Where the data section is in `bytes`.
    data: Range<usize>,
    kind: String,
}

impl Mmdb {
    /// Parses and checks the file `bytes`: the metadata, the length of the tree and every record of it. The values of
    /// the data section are not read here (see `Value::check` and `for_each_record`).
    pub fn parse(bytes: Vec<u8>) -> Result<Mmdb, Fault> {
        let window = bytes.len().saturating_sub(MAX_METADATA + MARKER.len());
        let marker = bytes
            .get(window..)
            .and_then(|tail| tail.windows(MARKER.len()).rposition(|part| part == MARKER))
            .ok_or(NO_METADATA)?
            + window;
        let metadata = bytes.get(marker + MARKER.len()..).ok_or(NO_METADATA)?;
        let map = Value::first(metadata);
        map.check().map_err(|_| BAD_METADATA)?;
        let field = |name: &str| map.get(name).ok().flatten().ok_or(BAD_METADATA);
        let number = |name: &str| field(name)?.unsigned().map_err(|_| BAD_METADATA);
        if number("binary_format_major_version")? != 2 {
            return Err(BAD_VERSION);
        }
        let nodes = u32::try_from(number("node_count")?).map_err(|_| BAD_METADATA)?;
        if nodes == 0 {
            return Err(NO_NODES);
        }
        let record_bits = match number("record_size")? {
            bits @ (24 | 28 | 32) => u32::try_from(bits).map_err(|_| BAD_RECORD_SIZE)?,
            _ => return Err(BAD_RECORD_SIZE),
        };
        let ipv6 = match number("ip_version")? {
            4 => false,
            6 => true,
            _ => return Err(BAD_IP_VERSION),
        };
        let kind = field("database_type")?
            .text()
            .map_err(|_| BAD_METADATA)?
            .to_owned();
        let node_len = usize::try_from(record_bits / 4).map_err(|_| BAD_RECORD_SIZE)?;
        let tree = usize::try_from(nodes)
            .ok()
            .and_then(|nodes| nodes.checked_mul(node_len))
            .ok_or(BAD_TREE)?;
        let data_start = tree.checked_add(SEPARATOR).ok_or(BAD_TREE)?;
        if data_start > marker {
            return Err(BAD_TREE);
        }
        let mut db = Mmdb {
            bytes,
            nodes,
            node_len,
            record_bits,
            ipv6,
            ipv4_start: 0,
            data: data_start..marker,
            kind,
        };
        for node in 0..nodes {
            for right in [false, true] {
                db.step(db.record(node, right)?)?;
            }
        }
        if ipv6 {
            let mut record = 0;
            for _ in 0..96 {
                if record >= nodes {
                    break;
                }
                record = db.record(record, false)?;
            }
            db.ipv4_start = record;
        }
        let limit = if ipv6 { 128 } else { 32 };
        let mut heights = vec![0; usize::try_from(nodes).map_err(|_| BAD_TREE)?];
        db.height(0, 0, limit, &mut heights)?;
        if ipv6 && db.ipv4_start < nodes {
            db.height(db.ipv4_start, 0, 32, &mut heights)?;
        }
        Ok(db)
    }

    /// How many nodes the longest walk from `node` passes, `node` being `depth` nodes below where the walk starts.
    /// A walk that goes round, or passes more than `limit` nodes in all, is a fault: no address has that many bits. A
    /// node that is reached from more than one place, as the IPv4 half of a tree of IPv6 addresses is, is gone over
    /// once; `heights` holds what is known of each node, 0 for nothing yet.
    fn height(
        &self,
        node: u32,
        depth: usize,
        limit: usize,
        heights: &mut [u8],
    ) -> Result<usize, Fault> {
        if depth >= limit {
            return Err(SHALLOW);
        }
        let slot = usize::try_from(node).map_err(|_| BAD_TREE)?;
        match heights.get(slot).copied().ok_or(BAD_TREE)? {
            0 => {}
            ON_PATH => return Err(SHALLOW),
            known if depth + usize::from(known) <= limit => return Ok(usize::from(known)),
            _ => return Err(SHALLOW),
        }
        *heights.get_mut(slot).ok_or(BAD_TREE)? = ON_PATH;
        let mut tallest = 0;
        for right in [false, true] {
            let record = self.record(node, right)?;
            if record < self.nodes {
                tallest = tallest.max(self.height(record, depth + 1, limit, heights)?);
            }
        }
        let height = tallest + 1;
        *heights.get_mut(slot).ok_or(BAD_TREE)? = u8::try_from(height).map_err(|_| SHALLOW)?;
        Ok(height)
    }

    /// The `database_type` of the metadata: the kind of database, which has `Country` in it if it is of countries.
    pub fn database_type(&self) -> &str {
        &self.kind
    }

    /// The data section.
    fn section(&self) -> &[u8] {
        self.bytes.get(self.data.clone()).unwrap_or_default()
    }

    /// The record on the left or the right of a node. The number of the node is below `nodes`.
    fn record(&self, node: u32, right: bool) -> Result<u32, Fault> {
        let start = usize::try_from(node)
            .ok()
            .and_then(|node| node.checked_mul(self.node_len))
            .ok_or(BAD_TREE)?;
        let end = start.checked_add(self.node_len).ok_or(BAD_TREE)?;
        let node = self.bytes.get(start..end).ok_or(BAD_TREE)?;
        let be = |bytes: &[u8]| bytes.iter().fold(0u32, |sum, &b| (sum << 8) | u32::from(b));
        let record = match self.record_bits {
            24 => {
                let (left, rest) = node.split_at_checked(3).ok_or(BAD_TREE)?;
                be(if right { rest } else { left })
            }
            28 => {
                // The middle byte holds the high four bits of the left record and of the right one.
                let (left, rest) = node.split_at_checked(3).ok_or(BAD_TREE)?;
                let (middle, right_bytes) = rest.split_first().ok_or(BAD_TREE)?;
                if right {
                    be(right_bytes) | (u32::from(middle & 0x0F) << 24)
                } else {
                    be(left) | (u32::from(middle & 0xF0) << 20)
                }
            }
            _ => {
                let (left, rest) = node.split_at_checked(4).ok_or(BAD_TREE)?;
                be(if right { rest } else { left })
            }
        };
        Ok(record)
    }

    /// Where `record` leads, once it is known to lead somewhere that exists.
    fn step(&self, record: u32) -> Result<Step, Fault> {
        if record < self.nodes {
            return Ok(Step::Node);
        }
        if record == self.nodes {
            return Ok(Step::Nothing);
        }
        let offset = (record - self.nodes)
            .checked_sub(u32::try_from(SEPARATOR).map_err(|_| OUTSIDE)?)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|&offset| offset < self.section().len())
            .ok_or(OUTSIDE)?;
        Ok(Step::Data(offset))
    }

    /// The record of the data section that holds for `ip`, or `None` if the tree knows nothing of it. An IPv4-mapped
    /// IPv6 address is looked up as the IPv4 address it holds, and an IPv6 address in a tree of IPv4 addresses is not
    /// found. A tree that `parse` took always ends within as many nodes as the address has bits; if one did not, this
    /// would fail rather than go on.
    pub fn find(&self, ip: IpAddr) -> Result<Option<Value<'_>>, Fault> {
        let (octets, bits, mut record) = match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let mut octets = [0; 16];
                octets[..4].copy_from_slice(&v4.octets());
                (octets, 32, if self.ipv6 { self.ipv4_start } else { 0 })
            }
            IpAddr::V6(v6) => {
                if !self.ipv6 {
                    return Ok(None);
                }
                (v6.octets(), 128, 0)
            }
        };
        for i in 0..bits {
            if record >= self.nodes {
                break;
            }
            let bit = octets
                .get(i / 8)
                .is_some_and(|b| (b >> (7 - i % 8)) & 1 == 1);
            record = self.record(record, bit)?;
        }
        match self.step(record)? {
            Step::Data(offset) => Ok(Some(Value::at(self.section(), offset))),
            Step::Nothing => Ok(None),
            Step::Node => Err(SHALLOW),
        }
    }

    /// Calls `visit` once for every distinct value of the data section that some record of the tree leads to, in the
    /// order of the nodes, and stops at the first fault.
    pub fn for_each_record(
        &self,
        mut visit: impl FnMut(Value<'_>) -> Result<(), Fault>,
    ) -> Result<(), Fault> {
        let section = self.section();
        let mut seen = vec![0u64; section.len() / 64 + 1];
        for node in 0..self.nodes {
            for right in [false, true] {
                let Step::Data(offset) = self.step(self.record(node, right)?)? else {
                    continue;
                };
                let word = seen.get_mut(offset / 64).ok_or(OUTSIDE)?;
                let bit = 1u64 << (offset % 64);
                if *word & bit != 0 {
                    continue;
                }
                *word |= bit;
                visit(Value::at(section, offset))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
