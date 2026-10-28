//! Which country an address is in, read from a country database in the MaxMind DB format that the operator put in
//! place (the `geo` object of the configuration names it, see `config`, and `mmdb` reads the format). The proxy never
//! fetches a database and ships none.
//!
//! The country of an address is `country.iso_code` of its record, or else `registered_country.iso_code`, and
//! `Country::Unknown` if the record has neither, if the code is not two upper-case letters, if the database knows
//! nothing of the address, if the lookup fails, or if the address is one that no database names a country for: a
//! loopback, private (10/8, 172.16/12, 192.168/16, fc00::/7), link-local or unspecified address. An IPv4-mapped IPv6
//! address is looked at as the IPv4 address it holds. The country comes only from the address that
//! `forward::client_ip` finds for the client, never from a header of the client.
//!
//! `Geo::open` checks a database whole when the proxy starts: the tree and the metadata (see `mmdb`), and then every
//! record that the tree leads to, which `mmdb::Value::check` must accept and which must be a map, with a map for its
//! `country` and its `registered_country` if it has them. A database needs `Country` in its `database_type`, or else at
//! least one record with an ISO code, so that a database of something else (the networks of providers, say) is not
//! taken for one of countries.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use super::mmdb::{Fault, Mmdb, Value};
use crate::forward::client_ip::Country;

const NO_COUNTRIES: Fault =
    Fault("the country database is not of countries: it has no country records");

/// A country database that was checked.
#[derive(Clone)]
pub struct Geo(Arc<Mmdb>);

impl fmt::Debug for Geo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Geo")
    }
}

/// Two handles are equal if they are the same database.
impl PartialEq for Geo {
    fn eq(&self, other: &Geo) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Geo {}

/// The ISO code of a record, if it has one: its country's, or else its registered country's. A code that is not
/// two upper-case letters is `Unknown`. A record, or a country in it, that is not a map is a fault.
fn code_of(record: Value<'_>) -> Result<Option<Country>, Fault> {
    for key in ["country", "registered_country"] {
        let Some(place) = record.get(key)? else {
            continue;
        };
        let Some(code) = place.get("iso_code")? else {
            continue;
        };
        return Ok(Some(
            Country::parse(code.text()?).unwrap_or(Country::Unknown),
        ));
    }
    Ok(None)
}

/// Whether no database names a country for `ip`.
fn unnamed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

impl Geo {
    /// Reads and checks the database in `bytes`, which are its whole file.
    pub fn open(bytes: Vec<u8>) -> Result<Geo, Fault> {
        let db = Mmdb::parse(bytes)?;
        let mut coded = false;
        db.for_each_record(|record| {
            record.check()?;
            coded |= code_of(record)?.is_some();
            Ok(())
        })?;
        if !coded && !db.database_type().contains("Country") {
            return Err(NO_COUNTRIES);
        }
        Ok(Geo(Arc::new(db)))
    }

    /// The country of `ip`.
    pub fn country(&self, ip: IpAddr) -> Country {
        let ip = ip.to_canonical();
        if unnamed(ip) {
            return Country::Unknown;
        }
        match self.0.find(ip) {
            Ok(Some(record)) => code_of(record).ok().flatten().unwrap_or(Country::Unknown),
            Ok(None) | Err(_) => Country::Unknown,
        }
    }
}

#[cfg(test)]
mod tests;
