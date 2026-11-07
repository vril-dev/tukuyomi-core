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
//! A refusal of `check` is its sentence alone, as for the main file. The admin process checks a version that a request
//! sends with `check_sent`, the same check, whose refusal (`Objection`) also tells the place in the version it is
//! about: a path of the keys and the numbers (from 0) of the version, such as `sites[1].hosts[0]`,
//! `upstreams.app.servers[2].address`, `routes[3].path` or `rate_limit.rate`. The path goes down to a key of an item
//! and stops at the key above where one sentence is about a list or about two keys: an access list
//! (`routes[3].access`), the edits of the fields and of the query (`routes[3].rewrite.request_headers`) and `stream`. A
//! group is named by its name, and only by one that passed the rule of a name (a refusal about a group whose name did
//! not is about `upstreams`); a site and a route are named by their number. No value of the version is in a place. A
//! refusal about two items (a name or a host written twice, two routes with the same host and path) is about the later
//! one, and one about a rule that some items break together is about the first item that breaks it. A refusal that the
//! main file is to be changed for (`records` with too few `files`) is about no place, and so is one about the version
//! as a whole.
//!
//! `sent` reads the version that a request sends in the form of a version. A repeated key, and a text that is not JSON,
//! are refused about no place. For any other refusal of that reading, the version is read again item by item, in the
//! order of the check: the keys at the top (an unknown one is about no place, a missing one about its key), then each
//! site, each group in the byte order of the names, each route, `default_upstream`, `access` and `rate_limit`, each
//! read in its form; the first item that is refused gives both the sentence and the place, which is the item
//! (`sites[1]`, `upstreams.app`, `routes[0]`). When no item is refused, the refusal is the sentence of the first
//! reading, about no place.
//!
//! A version has one written form, which `encode` makes: JSON without white space, the keys of every object in byte
//! order (the form `serde_json` writes a value in). A version in another form is refused, so that the same content
//! is always the same version, under the same name. A version that a request sends to the admin process may be in any
//! form, and is written in this one (`sent`).
//!
//! The document of `managed import` has the form of a version with paths in the place of the SHA-256: the
//! `certificate` of a site is `{"chain_file", "key_file"}` or `{"acme"}` (which names no file, and is the same in the
//! version) and the `tls` of a group `{"ca_file", "server_name"?}`, each path absolute and clean and of at most 3840
//! bytes. It is checked as a version is, and it may be in any form. `version_of` makes the version of a document whose
//! files are in the store.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde::de::{self, DeserializeOwned, IgnoredAny};
use serde_json::Value;

use super::store::MAX_BYTES;
use crate::config::{
    self, Address, At, CertificateAcme, ConfigError, ForwardSettings, GeoConfig, Groups,
    ListenerKind, MainFile, Object, PolicyConfig, RawAccess, RawCertificateAcme, RawRateLimit,
    RawRoute, RawTls, RouteKeep, StoredTls, addresses, certificate_acme, clean_abs, ensure,
    host_ok_for_tls, name_ok, present, same, uses_countries,
};
use crate::forward::tls::Authorities;
use crate::rules::bundle::{Fingerprint, hex};

/// The most sites of a version, and the most hosts of a site.
const MAX_SITES: usize = 64;
const MAX_HOSTS: usize = 64;
/// The longest path of a document, as for the files of a listener.
const MAX_PATH: usize = 3840;
/// The keys at the top of a version: the four that it has, then the two that it may leave out.
const KEYS: [&str; 6] = [
    "sites",
    "upstreams",
    "routes",
    "default_upstream",
    "access",
    "rate_limit",
];
const REQUIRED: usize = 4;
/// The key of `rate_limit` that each sentence of its check is about.
const RATE_KEYS: [(&str, &str); 5] = [
    ("rate_limit rate is not 1 to 100000", "rate"),
    ("rate_limit burst is not 0 to 100000", "burst"),
    ("rate_limit keys is not 1024 to 1048576", "keys"),
    (
        "rate_limit exempt_cidrs has more than 256 entries",
        "exempt_cidrs",
    ),
    (
        "rate_limit exempt_cidrs has an entry that is not a network",
        "exempt_cidrs",
    ),
];
/// The sentence of a certificate with `acme` and a `*.` host, which is about the first such host.
const WILDCARD: &str = "a certificate with acme has a wildcard host";

/// A refusal of a version that a request sent, and the place that it is about (see the module documentation): what the
/// admin process answers. The place is a path in the version, or `files` or `files[k]` for the files that the request
/// brings (see `import`); none when the refusal is about the version as a whole or about the main file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Objection {
    pub why: &'static str,
    pub at: Option<String>,
}

impl Objection {
    /// A refusal about no place.
    pub(crate) fn whole(why: &'static str) -> Objection {
        Objection { why, at: None }
    }

    /// A refusal about `at`, in a version whose groups are named `groups`, in order.
    pub(crate) fn of(why: &'static str, at: Option<At>, groups: &[String]) -> Objection {
        Objection {
            why,
            at: at.map(|at| path(at, groups)),
        }
    }

    /// A refusal about the files of the request, or about the one at `file` (from 0).
    pub(crate) fn files(why: &'static str, file: Option<usize>) -> Objection {
        let at = match file {
            Some(file) => format!("files[{file}]"),
            None => "files".to_owned(),
        };
        Objection { why, at: Some(at) }
    }
}

/// `at` as a path, a group by its name in `groups`; a group whose name is not a name stops the path at `upstreams`.
fn path(at: At, groups: &[String]) -> String {
    let keyed = |item: String, key: Option<&str>| match key {
        Some(key) => format!("{item}.{key}"),
        None => item,
    };
    let group = |at: usize| groups.get(at).filter(|name| name_ok(name));
    match at {
        At::Top(key, inner) => keyed(key.to_owned(), inner),
        At::Site(site, key) => keyed(format!("sites[{site}]"), key),
        At::Host(site, host) => format!("sites[{site}].hosts[{host}]"),
        At::Group(at, key) => match group(at) {
            Some(name) => keyed(format!("upstreams.{name}"), key),
            None => "upstreams".to_owned(),
        },
        At::Server(at, server, key) => match group(at) {
            Some(name) => format!("upstreams.{name}.servers[{server}].{key}"),
            None => "upstreams".to_owned(),
        },
        At::Route(route, key) => keyed(format!("routes[{route}]"), key),
    }
}

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

/// The `certificate` of a site as it is written, checked for a site with `hosts`; its files are named by `File`. A
/// refusal comes with the key of the site it is about (`certificate`, or a key in it).
pub(crate) trait Certificate {
    type File;
    fn certificate(
        self,
        hosts: &[String],
    ) -> Result<SiteCertificate<Self::File>, (ConfigError, &'static str)>;
}

impl Certificate for StoredCertificate {
    type File = [u8; 32];

    fn certificate(
        self,
        hosts: &[String],
    ) -> Result<SiteCertificate<[u8; 32]>, (ConfigError, &'static str)> {
        let name = |text: String| {
            digest(&text).ok_or(ConfigError(
                "a site chain or key is not 64 lower-case hexadecimal digits",
            ))
        };
        let keys = ["certificate.chain", "certificate.key"];
        one_of(self.chain, self.key, self.acme, hosts, keys, name)
    }
}

impl Certificate for FileCertificate {
    type File = PathBuf;

    fn certificate(
        self,
        hosts: &[String],
    ) -> Result<SiteCertificate<PathBuf>, (ConfigError, &'static str)> {
        let path = |text: String| {
            let path = PathBuf::from(text);
            ensure(
                clean_abs(&path) && path.as_os_str().as_bytes().len() <= MAX_PATH,
                "a site chain_file or key_file is not an absolute clean path of at most 3840 bytes",
            )?;
            Ok(path)
        };
        let keys = ["certificate.chain_file", "certificate.key_file"];
        one_of(self.chain_file, self.key_file, self.acme, hosts, keys, path)
    }
}

/// The certificate that is written with both files (`chain` and `key`, each read by `file`, whose keys in the site are
/// `keys`) and no `acme`, or with `acme` and no file. Any other form, both files and `acme` or one file only or
/// nothing, is refused with one sentence.
fn one_of<F>(
    chain: Option<String>,
    key: Option<String>,
    acme: Option<Object<RawCertificateAcme>>,
    hosts: &[String],
    keys: [&'static str; 2],
    file: impl Fn(String) -> Result<F, ConfigError>,
) -> Result<SiteCertificate<F>, (ConfigError, &'static str)> {
    let [chain_key, key_key] = keys;
    match (chain, key, acme) {
        (Some(chain), Some(key), None) => Ok(SiteCertificate::Files {
            chain: file(chain).map_err(|e| (e, chain_key))?,
            key: file(key).map_err(|e| (e, key_key))?,
        }),
        (None, None, Some(Object(acme))) => Ok(SiteCertificate::Acme(
            certificate_acme(acme, hosts).map_err(|e| (e, "certificate.acme"))?,
        )),
        _ => Err((
            ConfigError("a site certificate is neither chain and key nor acme"),
            "certificate",
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
    /// module documentation, and a refusal is the sentence of `located`.
    pub(crate) fn check(
        self,
        main: &MainFile,
        resolve_timeout: Duration,
        geo: Option<GeoConfig>,
        split: impl Fn(T) -> Result<(Authorities, Option<String>), ConfigError>,
    ) -> Result<Checked<C::File>, ConfigError> {
        self.located(main, resolve_timeout, geo, split)
            .map_err(|(e, _)| e)
    }

    /// The check of `check`, whose refusal also tells the place in the version it is about (see the module
    /// documentation); none for a refusal that is about the main file.
    fn located(
        self,
        main: &MainFile,
        resolve_timeout: Duration,
        geo: Option<GeoConfig>,
        split: impl Fn(T) -> Result<(Authorities, Option<String>), ConfigError>,
    ) -> Result<Checked<C::File>, (ConfigError, Option<At>)> {
        let placed = |(e, at): (ConfigError, At)| (e, Some(at));
        let refuse = |why: &'static str, at: At| (ConfigError(why), Some(at));
        let sites = sites(self.sites).map_err(placed)?;
        let acme = sites
            .iter()
            .position(|site| matches!(site.certificate, SiteCertificate::Acme(_)));
        if let Some(site) = acme.filter(|_| main.acme.is_none()) {
            return Err(refuse(
                "a site has acme but the configuration has no acme object",
                At::Site(site, Some("certificate")),
            ));
        }
        let admin = main.admin_route.as_ref().map(|route| route.host.as_str());
        for (at, site) in sites.iter().enumerate() {
            if let Some(host) = site
                .hosts
                .iter()
                .position(|host| Some(host.as_str()) == admin)
            {
                return Err(refuse(
                    "a site host is the host of the admin route",
                    At::Host(at, host),
                ));
            }
        }
        let tls = main
            .proxy
            .listeners
            .iter()
            .any(|listener| matches!(listener.kind, ListenerKind::Tls(_)));
        if tls && sites.is_empty() && admin.is_none() {
            return Err(refuse(
                "a tls listener has no certificate, for the version has no site and admin has no route",
                At::Top("sites", None),
            ));
        }
        // A server may not be at an address the proxy listens on, the one of the status listener included.
        let mut bound = addresses(&main.proxy.listeners);
        bound.extend(main.status.map(|status| status.listen));
        let forward = config::located(
            resolve_timeout,
            self.upstreams,
            self.routes,
            &self.default_upstream,
            &bound,
            main.proxy.max_body,
            split,
        )?;
        if let Some(at) = forward.routes.rules().position(|rule| {
            rule.host()
                .is_some_and(|host| host.split(':').next() == admin)
        }) {
            return Err(refuse(
                "a route host is the host of the admin route",
                At::Route(at, Some("host")),
            ));
        }
        // The way to the admin process is the proxy's own, by its host: no group of a version reaches it.
        if let Some(listen) = main.admin.as_ref().map(|admin| admin.listen) {
            for (at, group) in forward.groups.iter().enumerate() {
                if let Some(server) = group.servers.iter().position(
                    |server| matches!(server.address, Address::Literal(literal) if same(listen, literal)),
                ) {
                    return Err(refuse(
                        "a server is at the address of the admin process",
                        At::Server(at, server, "address"),
                    ));
                }
            }
        }
        config::consistent(main.records.as_ref(), &forward).map_err(|e| {
            // Without `records`, the refusal is about the first route whose records are required; with it, it is
            // about the files that the main file keeps.
            let required = forward
                .routes
                .targets()
                .position(|route| route.records == Some(RouteKeep::Required));
            let at = required.filter(|_| main.records.is_none());
            (e, at.map(|at| At::Route(at, Some("records"))))
        })?;
        let policy = config::routed(self.access, self.rate_limit, geo).map_err(|(e, key)| {
            // A sentence of `rate_limit` is about one of its keys; one of `access` is about its lists.
            let inner = RATE_KEYS
                .iter()
                .find(|(text, _)| key == "rate_limit" && *text == e.0);
            (e, Some(At::Top(key, inner.map(|(_, inner)| *inner))))
        })?;
        if policy.geo.is_none() && uses_countries(&policy, &forward) {
            // The first list of countries: the one of the version, then the one of a route.
            let route = forward
                .routes
                .targets()
                .position(|route| route.access.has_countries());
            let at = match route {
                Some(at) if !policy.access.has_countries() => At::Route(at, Some("access")),
                _ => At::Top("access", None),
            };
            return Err(refuse(
                "access has a list of countries while geo is left out",
                at,
            ));
        }
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
) -> Result<Vec<SiteOf<C::File>>, (ConfigError, At)> {
    ensure(raw.len() <= MAX_SITES, "sites has more than 64 sites")
        .map_err(|e| (e, At::Top("sites", None)))?;
    let mut sites: Vec<SiteOf<C::File>> = Vec::with_capacity(raw.len());
    for (at, Object(site)) in raw.into_iter().enumerate() {
        let key = |key: &'static str| move |e: ConfigError| (e, At::Site(at, Some(key)));
        ensure(
            name_ok(&site.name),
            "a site name is not 1 to 64 letters, digits, - and _",
        )
        .map_err(key("name"))?;
        ensure(
            sites.iter().all(|other| other.name != site.name),
            "a site name is written twice",
        )
        .map_err(key("name"))?;
        ensure(
            (1..=MAX_HOSTS).contains(&site.hosts.len()),
            "a site has no host or more than 64",
        )
        .map_err(key("hosts"))?;
        if let Some(host) = site.hosts.iter().position(|host| !host_ok_for_tls(host)) {
            return Err((
                ConfigError("a site host is not a name, or * and a name"),
                At::Host(at, host),
            ));
        }
        let Object(certificate) = site.certificate;
        let certificate = certificate.certificate(&site.hosts).map_err(|(e, key)| {
            let wildcard = site.hosts.iter().position(|host| host.starts_with("*."));
            match wildcard.filter(|_| e.0 == WILDCARD) {
                Some(host) => (e, At::Host(at, host)),
                None => (e, At::Site(at, Some(key))),
            }
        })?;
        sites.push(SiteOf {
            name: site.name,
            hosts: site.hosts,
            certificate,
        });
    }
    // The later place of a host that is written twice.
    let mut seen = BTreeSet::new();
    for (at, site) in sites.iter().enumerate() {
        if let Some(host) = site.hosts.iter().position(|host| !seen.insert(host)) {
            return Err((
                ConfigError("a site host is written twice in the sites"),
                At::Host(at, host),
            ));
        }
    }
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

/// The version that a request sends as the value of `version` in its JSON object `body`, in its one written form. The
/// value is read twice: in the form of a version, so that a repeated, unknown or missing key and a value of the wrong
/// type are refused with the sentences of the main file (a value read as JSON keeps the last of two keys of the same
/// name), and then as JSON, which `encode` writes. A refusal of the first reading is looked for item by item (see the
/// module documentation). The other keys of `body` are not looked at here.
pub(crate) fn sent(body: &[u8]) -> Result<Vec<u8>, Objection> {
    #[derive(Deserialize)]
    struct Typed {
        #[serde(rename = "version")]
        _version: Object<RawVersion>,
    }
    #[derive(Deserialize)]
    struct Untyped {
        version: Value,
    }
    let untyped = || {
        serde_json::from_slice(body)
            .map(|Object(Untyped { version })| version)
            .map_err(|e| Objection::whole(config::refusal(&e).0))
    };
    if let Err(e) = serde_json::from_slice::<Object<Typed>>(body) {
        let why = config::refusal(&e).0;
        // A value read as JSON has lost a repeated key, and a text that is not JSON has no items.
        if matches!(
            why,
            "configuration has a repeated key" | "configuration is not valid JSON"
        ) {
            return Err(Objection::whole(why));
        }
        return Err(item(&untyped()?).unwrap_or(Objection::whole(why)));
    }
    let bytes = encode(&untyped()?).ok_or(Objection::whole(
        "the managed version cannot be written in its one written form",
    ))?;
    if !u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_BYTES) {
        return Err(Objection::whole("the managed version is over 1 MiB"));
    }
    Ok(bytes)
}

/// The first item of `version` that is refused when it is read in its form, in the order of the module documentation;
/// none when `version` is not an object, or every item is read.
fn item(version: &Value) -> Option<Objection> {
    let top = version.as_object()?;
    if top.keys().any(|key| !KEYS.contains(&key.as_str())) {
        return Some(Objection::whole(told(de::Error::unknown_field("", &[]))));
    }
    let mut required = KEYS[..REQUIRED].iter().copied();
    if let Some(key) = required.find(|key| !top.contains_key(*key)) {
        let why = told(de::Error::missing_field(key));
        return Some(Objection::of(why, Some(At::Top(key, None)), &[]));
    }
    let one = |key: &'static str, read: Read| {
        let why = top.get(key).and_then(|value| read(value).err())?;
        Some(Objection::of(why, Some(At::Top(key, None)), &[]))
    };
    let list = |key: &'static str, at: Number, read: Read| {
        top.get(key).and_then(|value| entries(value, key, at, read))
    };
    let site = reads::<Object<RawSite<StoredCertificate>>>;
    let route = reads::<Object<RawRoute>>;
    list("sites", At::Site, site)
        .or_else(|| top.get("upstreams").and_then(groups))
        .or_else(|| list("routes", At::Route, route))
        .or_else(|| one("default_upstream", reads::<String>))
        .or_else(|| one("access", reads::<Object<RawAccess>>))
        .or_else(|| one("rate_limit", reads::<Object<RawRateLimit>>))
}

/// The reading of an item of a version in its form, a refusal as its sentence.
type Read = fn(&Value) -> Result<(), &'static str>;
/// The place of an entry of a list of a version by its number.
type Number = fn(usize, Option<&'static str>) -> At;

/// The first entry of the list `value`, the `key` of a version, that `read` refuses, about its place (`at` with its
/// number); a `value` that is not a list is about `key`.
fn entries(value: &Value, key: &'static str, at: Number, read: Read) -> Option<Objection> {
    let Some(list) = value.as_array() else {
        let why = reads::<Vec<IgnoredAny>>(value).err()?;
        return Some(Objection::of(why, Some(At::Top(key, None)), &[]));
    };
    list.iter().enumerate().find_map(|(number, entry)| {
        let why = read(entry).err()?;
        Some(Objection::of(why, Some(at(number, None)), &[]))
    })
}

/// The first group of `value`, the `upstreams` of a version, that is refused when it is read as a group, in the byte
/// order of the names; a `value` that is not an object is about `upstreams`.
fn groups(value: &Value) -> Option<Objection> {
    let Some(groups) = value.as_object() else {
        let why = reads::<Groups<StoredTls>>(value).err()?;
        return Some(Objection::of(why, Some(At::Top("upstreams", None)), &[]));
    };
    let names: Vec<String> = groups.keys().cloned().collect();
    groups.values().enumerate().find_map(|(at, group)| {
        let why = Groups::<StoredTls>::read_one(group).err()?;
        Some(Objection::of(why.0, Some(At::Group(at, None)), &names))
    })
}

/// Reads `value` as a `T`, a refusal as its sentence.
fn reads<T: DeserializeOwned>(value: &Value) -> Result<(), &'static str> {
    T::deserialize(value)
        .map(drop)
        .map_err(|e| config::refusal(&e).0)
}

/// The sentence of the reading for the fault `e`, which tells a kind of fault and no key.
fn told(e: serde_json::Error) -> &'static str {
    config::refusal(&e).0
}

/// The version `bytes` that a request sent, in its one written form (see `sent`), checked with the main file as
/// `check` checks it, its refusal with the place it is about: the check of the admin process. The names of the groups
/// for the place are taken before the check uses the version.
pub(crate) fn check_sent(
    bytes: &[u8],
    main: &MainFile,
    resolve_timeout: Duration,
    geo: Option<GeoConfig>,
) -> Result<Checked<[u8; 32]>, Objection> {
    let raw = parse(bytes).map_err(|e| Objection::whole(e.0))?;
    let groups = raw.upstreams.names();
    raw.located(main, resolve_timeout, geo, stored_tls)
        .map_err(|(e, at)| Objection::of(e.0, at, &groups))
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
