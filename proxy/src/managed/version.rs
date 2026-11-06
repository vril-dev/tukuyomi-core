//! A version of the managed configuration, and the document of `managed import`, which is a version that names its
//! files by their paths.
//!
//! A version is one JSON object `{"sites": [..], "upstreams": {..}, "routes": [..], "default_upstream": "..",
//! "access"?: {..}, "rate_limit"?: {..}}`. `upstreams`, `routes`, `default_upstream`, `access` and `rate_limit` are
//! written and checked as in a main file without `managed` (see `config`, whose sentences the refusals are), except the
//! `tls` of a group, `{"ca", "server_name"?}`, whose `ca` is the SHA-256 of a file of the store: the file of the
//! authorities. `sites` is a list of 0 to 64 sites `{"name", "hosts", "certificate"}`: the name is written as the
//! name of a group is and no two sites have the same, the hosts are 1 to 64 as the hosts of a certificate of a listener
//! are written (a name, or `*.` and a name) and no host is in two sites, and the certificate is one of two forms and
//! nothing else. `{"chain", "key"}` names the files of the store that hold the certificate chain and the private key
//! by their SHA-256. `{"acme": {"renew_before_days"}}` (1 to 60) is a certificate that the command `acme renew`
//! issues and writes into `acme/` of the store, as for a certificate of a listener with `acme`: the hosts of such a
//! site are names only (no `*.`), and the main file has the `acme` object. A version has no path. An unknown,
//! repeated or missing key is refused as in the main file.
//!
//! A version is checked against the main file it comes with (`check`), after that file: the sites, that the main file
//! has `acme` if a site has, that no site has the host of the way to the admin process (`admin.route`; a `*.` host may
//! cover it, as the name comes first), that a main file with a TLS listener has some certificate for it (a site,
//! with `acme` or not, or the way), then the groups, the routes and
//! the default group with the addresses the proxy listens on and the `max_body` of the proxy, that no route has the
//! host of the way (with any port), that no server is at `admin.listen` (the way is the proxy's own; a name that comes
//! to that address is refused when it is looked up), then the `records` of the routes with the `records` of the main
//! file, then
//! `access` and `rate_limit`, and last that the main file has `geo` if a list of countries is there. The files that it
//! names are read by `load`.
//!
//! A version has one written form, which `encode` makes: JSON without white space, the keys of every object in byte
//! order (the form `serde_json` writes a value in). A version in another form is refused, so that the same content
//! is always the same version, under the same name.
//!
//! The document of `managed import` has the form of a version with paths in the place of the SHA-256: the
//! `certificate` of a site is `{"chain_file", "key_file"}` or `{"acme"}` (which names no file, and is the same in the
//! version) and the `tls` of a group `{"ca_file", "server_name"?}`, each path absolute and clean and of at most 3840
//! bytes. It is checked as a version is, and it may be in any form. `version_of` makes the version of a document whose
//! files are in the store.

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::store::MAX_BYTES;
use crate::config::{
    self, Address, CertificateAcme, ConfigError, ForwardSettings, GeoConfig, Groups, ListenerKind,
    MainFile, Object, PolicyConfig, RawAccess, RawCertificateAcme, RawRateLimit, RawRoute, RawTls,
    StoredTls, addresses, certificate_acme, clean_abs, ensure, host_ok_for_tls, name_ok, present,
    same, uses_countries,
};
use crate::forward::tls::Authorities;
use crate::rules::bundle::{Fingerprint, hex};

/// The most sites of a version, and the most hosts of a site.
const MAX_SITES: usize = 64;
const MAX_HOSTS: usize = 64;
/// The longest path of a document, as for the files of a listener.
const MAX_PATH: usize = 3840;

/// A version or a document as it is written. `C` is the `certificate` of a site and `T` the `tls` of a group.
#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(deserialize = "C: Deserialize<'de>, T: Deserialize<'de>")
)]
pub(crate) struct Raw<C, T> {
    sites: Vec<Object<RawSite<C>>>,
    upstreams: Groups<T>,
    routes: Vec<Object<RawRoute>>,
    default_upstream: String,
    #[serde(default, deserialize_with = "present")]
    access: Option<Object<RawAccess>>,
    #[serde(default, deserialize_with = "present")]
    rate_limit: Option<Object<RawRateLimit>>,
}

/// A version as the store keeps it.
pub(crate) type RawVersion = Raw<StoredCertificate, StoredTls>;
/// The document of `managed import`.
pub(crate) type RawDocument = Raw<FileCertificate, RawTls>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "C: Deserialize<'de>"))]
struct RawSite<C> {
    name: String,
    hosts: Vec<String>,
    certificate: Object<C>,
}

/// The `certificate` of a site of a version: `chain` and `key`, or `acme` (see `one_of`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredCertificate {
    #[serde(default, deserialize_with = "present")]
    chain: Option<String>,
    #[serde(default, deserialize_with = "present")]
    key: Option<String>,
    #[serde(default, deserialize_with = "present")]
    acme: Option<Object<RawCertificateAcme>>,
}

/// The `certificate` of a site of a document: `chain_file` and `key_file`, or `acme` (see `one_of`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileCertificate {
    #[serde(default, deserialize_with = "present")]
    chain_file: Option<String>,
    #[serde(default, deserialize_with = "present")]
    key_file: Option<String>,
    #[serde(default, deserialize_with = "present")]
    acme: Option<Object<RawCertificateAcme>>,
}

/// The `certificate` of a site as it is written, checked for a site with `hosts`; its files are named by `File`.
pub(crate) trait Certificate {
    type File;
    fn certificate(self, hosts: &[String]) -> Result<SiteCertificate<Self::File>, ConfigError>;
}

impl Certificate for StoredCertificate {
    type File = [u8; 32];

    fn certificate(self, hosts: &[String]) -> Result<SiteCertificate<[u8; 32]>, ConfigError> {
        let name = |text: String| {
            digest(&text).ok_or(ConfigError(
                "a site chain or key is not 64 lower-case hexadecimal digits",
            ))
        };
        one_of(self.chain, self.key, self.acme, hosts, name)
    }
}

impl Certificate for FileCertificate {
    type File = PathBuf;

    fn certificate(self, hosts: &[String]) -> Result<SiteCertificate<PathBuf>, ConfigError> {
        let path = |text: String| {
            let path = PathBuf::from(text);
            ensure(
                clean_abs(&path) && path.as_os_str().as_bytes().len() <= MAX_PATH,
                "a site chain_file or key_file is not an absolute clean path of at most 3840 bytes",
            )?;
            Ok(path)
        };
        one_of(self.chain_file, self.key_file, self.acme, hosts, path)
    }
}

/// The certificate that is written with both files (`chain` and `key`, each read by `file`) and no `acme`, or with
/// `acme` and no file. Any other form, both files and `acme` or one file only or nothing, is refused with one sentence.
fn one_of<F>(
    chain: Option<String>,
    key: Option<String>,
    acme: Option<Object<RawCertificateAcme>>,
    hosts: &[String],
    file: impl Fn(String) -> Result<F, ConfigError>,
) -> Result<SiteCertificate<F>, ConfigError> {
    match (chain, key, acme) {
        (Some(chain), Some(key), None) => Ok(SiteCertificate::Files {
            chain: file(chain)?,
            key: file(key)?,
        }),
        (None, None, Some(Object(acme))) => {
            Ok(SiteCertificate::Acme(certificate_acme(acme, hosts)?))
        }
        _ => Err(ConfigError(
            "a site certificate is neither chain and key nor acme",
        )),
    }
}

/// A site, checked: its name, the hosts it serves, and its certificate, whose files are named by `F`, the SHA-256 of a
/// file of the store in a version (`Site`) and a path in a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteOf<F> {
    pub name: String,
    /// In the form the hosts of a certificate of a listener have: a lowercase name, or `*.` and a name.
    pub hosts: Vec<String>,
    pub certificate: SiteCertificate<F>,
}

/// A site of a version.
pub type Site = SiteOf<[u8; 32]>;

/// The certificate of a site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteCertificate<F> {
    /// The certificate chain and the private key, in files of the store (a document names them by their paths).
    Files { chain: F, key: F },
    /// Issued by the command `acme renew`, into `acme/` of the store under the name of the hosts of the site (see
    /// `store`). Its files may not be there yet.
    Acme(CertificateAcme),
}

impl<F> SiteCertificate<F> {
    /// The chain and the key, for a certificate that is in files.
    pub fn files(&self) -> Option<(&F, &F)> {
        match self {
            SiteCertificate::Files { chain, key } => Some((chain, key)),
            SiteCertificate::Acme(_) => None,
        }
    }
}

/// A version or a document, checked with its main file.
pub(crate) struct Checked<F> {
    pub(crate) sites: Vec<SiteOf<F>>,
    /// The groups, the routes and the default group, with the `resolve_timeout` of the main file.
    pub(crate) forward: ForwardSettings,
    /// The `access` and the `rate_limit`, with the `geo` of the main file.
    pub(crate) policy: PolicyConfig,
}

impl<C: Certificate, T> Raw<C, T> {
    /// Checks the version, or the document, against `main`, whose `forward.resolve_timeout_ms` is `resolve_timeout`
    /// and whose `geo` is `geo`. `split` checks the `tls` of a group as it is written. The order is the one of the
    /// module documentation.
    pub(crate) fn check(
        self,
        main: &MainFile,
        resolve_timeout: Duration,
        geo: Option<GeoConfig>,
        split: impl Fn(T) -> Result<(Authorities, Option<String>), ConfigError>,
    ) -> Result<Checked<C::File>, ConfigError> {
        let sites = sites(self.sites)?;
        ensure(
            main.acme.is_some()
                || sites
                    .iter()
                    .all(|site| !matches!(site.certificate, SiteCertificate::Acme(_))),
            "a site has acme but the configuration has no acme object",
        )?;
        let admin = main.admin_route.as_ref().map(|route| route.host.as_str());
        ensure(
            sites
                .iter()
                .flat_map(|site| &site.hosts)
                .all(|host| Some(host.as_str()) != admin),
            "a site host is the host of the admin route",
        )?;
        let tls = main
            .proxy
            .listeners
            .iter()
            .any(|listener| matches!(listener.kind, ListenerKind::Tls(_)));
        ensure(
            !tls || !sites.is_empty() || admin.is_some(),
            "a tls listener has no certificate, for the version has no site and admin has no route",
        )?;
        // A server may not be at an address the proxy listens on, the one of the status listener included.
        let mut bound = addresses(&main.proxy.listeners);
        bound.extend(main.status.map(|status| status.listen));
        let forward = config::routing(
            resolve_timeout,
            self.upstreams,
            self.routes,
            &self.default_upstream,
            &bound,
            main.proxy.max_body,
            split,
        )?;
        ensure(
            forward
                .routes
                .rules()
                .filter_map(|rule| rule.host())
                .all(|host| host.split(':').next() != admin),
            "a route host is the host of the admin route",
        )?;
        // The way to the admin process is the proxy's own, by its host: no group of a version reaches it.
        if let Some(listen) = main.admin.as_ref().map(|admin| admin.listen) {
            ensure(
                forward.groups.iter().flat_map(|group| &group.servers).all(
                    |server| !matches!(server.address, Address::Literal(at) if same(listen, at)),
                ),
                "a server is at the address of the admin process",
            )?;
        }
        config::consistent(main.records.as_ref(), &forward)?;
        let policy = config::routed(self.access, self.rate_limit, geo)?;
        ensure(
            policy.geo.is_some() || !uses_countries(&policy, &forward),
            "access has a list of countries while geo is left out",
        )?;
        Ok(Checked {
            sites,
            forward,
            policy,
        })
    }
}

/// The 32 bytes that 64 lowercase hexadecimal digits write.
fn digest(text: &str) -> Option<[u8; 32]> {
    Fingerprint::from_hex(text.as_bytes()).map(|name| name.bytes())
}

/// The sites, in the order they are written.
fn sites<C: Certificate>(
    raw: Vec<Object<RawSite<C>>>,
) -> Result<Vec<SiteOf<C::File>>, ConfigError> {
    ensure(raw.len() <= MAX_SITES, "sites has more than 64 sites")?;
    let mut sites: Vec<SiteOf<C::File>> = Vec::with_capacity(raw.len());
    for Object(site) in raw {
        ensure(
            name_ok(&site.name),
            "a site name is not 1 to 64 letters, digits, - and _",
        )?;
        ensure(
            sites.iter().all(|other| other.name != site.name),
            "a site name is written twice",
        )?;
        ensure(
            (1..=MAX_HOSTS).contains(&site.hosts.len()),
            "a site has no host or more than 64",
        )?;
        ensure(
            site.hosts.iter().all(|host| host_ok_for_tls(host)),
            "a site host is not a name, or * and a name",
        )?;
        let Object(certificate) = site.certificate;
        let certificate = certificate.certificate(&site.hosts)?;
        sites.push(SiteOf {
            name: site.name,
            hosts: site.hosts,
            certificate,
        });
    }
    let mut hosts: Vec<&String> = sites.iter().flat_map(|site| &site.hosts).collect();
    hosts.sort();
    ensure(
        hosts.windows(2).all(|pair| pair[0] != pair[1]),
        "a site host is written twice in the sites",
    )?;
    Ok(sites)
}

/// The `tls` of a group of a version: the file of the authorities is the file of the store that `ca` names.
pub(crate) fn stored_tls(tls: StoredTls) -> Result<(Authorities, Option<String>), ConfigError> {
    let name = digest(&tls.ca).ok_or(ConfigError(
        "an upstream tls ca is not 64 lower-case hexadecimal digits",
    ))?;
    Ok((Authorities::Stored(name), tls.server_name))
}

/// The text of `bytes` as JSON of the form `T`, at most 1 MiB and UTF-8. `too_large` and `not_text` are the sentences
/// of the size and of UTF-8; the other sentences are those of the main file.
fn read<'a, T: DeserializeOwned>(
    bytes: &'a [u8],
    too_large: &'static str,
    not_text: &'static str,
) -> Result<(T, &'a str), ConfigError> {
    ensure(
        u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_BYTES),
        too_large,
    )?;
    let text = std::str::from_utf8(bytes).map_err(|_| ConfigError(not_text))?;
    let Object(raw): Object<T> = serde_json::from_str(text).map_err(|e| config::refusal(&e))?;
    Ok((raw, text))
}

/// The bytes of a version, in the form of a version and in its one written form.
pub(crate) fn parse(bytes: &[u8]) -> Result<RawVersion, ConfigError> {
    let (raw, text) = read::<RawVersion>(
        bytes,
        "the managed version is over 1 MiB",
        "the managed version is not UTF-8",
    )?;
    // The text is valid JSON without a repeated key, for the version was read from it.
    let value: Value = serde_json::from_str(text).map_err(|e| config::refusal(&e))?;
    ensure(
        encode(&value).is_some_and(|written| written == bytes),
        "the managed version is not in its one written form",
    )?;
    Ok(raw)
}

/// The bytes of a document, in the form of a document.
pub(crate) fn parse_document(bytes: &[u8]) -> Result<RawDocument, ConfigError> {
    read::<RawDocument>(
        bytes,
        "the managed document is over 1 MiB",
        "the managed document is not UTF-8",
    )
    .map(|(raw, _)| raw)
}

/// The one written form of a version (see the module documentation).
pub(crate) fn encode(value: &Value) -> Option<Vec<u8>> {
    serde_json::to_vec(value).ok()
}

/// The version of the document `bytes`, which `parse_document` accepted, whose files are in the store under the names
/// that `names` gives for their paths: the path of a certificate and of a file of authorities in the place of its name.
pub(crate) fn version_of(
    bytes: &[u8],
    names: &BTreeMap<PathBuf, [u8; 32]>,
) -> Result<Vec<u8>, ConfigError> {
    const LOST: ConfigError = ConfigError("the managed document cannot be made into a version");
    let mut value: Value = serde_json::from_slice(bytes).map_err(|e| config::refusal(&e))?;
    let name = |object: &mut serde_json::Map<String, Value>, from: &str| {
        let path = object.remove(from).ok_or(LOST)?;
        let path = path.as_str().ok_or(LOST)?;
        names
            .get(&PathBuf::from(path))
            .map(|name| hex(name))
            .ok_or(LOST)
    };
    let sites = value.get_mut("sites").and_then(Value::as_array_mut);
    for site in sites.ok_or(LOST)? {
        let certificate = site.get_mut("certificate").and_then(Value::as_object_mut);
        let certificate = certificate.ok_or(LOST)?;
        // A certificate with `acme` names no file: the version has it as the document does.
        if certificate.contains_key("acme") {
            continue;
        }
        let chain = name(certificate, "chain_file")?;
        let key = name(certificate, "key_file")?;
        certificate.insert("chain".to_owned(), Value::String(chain));
        certificate.insert("key".to_owned(), Value::String(key));
    }
    let groups = value.get_mut("upstreams").and_then(Value::as_object_mut);
    for group in groups.ok_or(LOST)?.values_mut() {
        if let Some(tls) = group.get_mut("tls").and_then(Value::as_object_mut) {
            let ca = name(tls, "ca_file")?;
            tls.insert("ca".to_owned(), Value::String(ca));
        }
    }
    encode(&value).ok_or(LOST)
}

#[cfg(test)]
mod tests;
