//! What a version names outside itself, read as it is written, without a main file: an older version may not pass the
//! check with the main file of now, and still names what it names. `names` gives the files of the store and the
//! directories of `acme/` that it names, for the cleaning of the store, and `site_certificates` the certificates of its
//! sites, for the certificates of the store that the admin process shows (see `certificates`).

use std::collections::BTreeSet;

use super::{RawVersion, digest};
use crate::config::Object;
use crate::managed::store::acme_name;

/// The certificate of a site of a version as it is written (see `RawVersion::site_certificates`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::managed) enum WrittenCertificate {
    /// `chain` and `key`, each 64 lowercase hexadecimal digits, and no `acme`: the names of two files of the store.
    Files { chain: [u8; 32], key: [u8; 32] },
    /// `acme`, and neither `chain` nor `key`.
    Acme,
    /// Any other form, which the check refuses: both, neither, one of the files only, or a file that is not named by 64
    /// lowercase digits.
    Unknown,
}

/// A site of a version as it is written: its name and its hosts as they are, and the form of its certificate.
#[derive(Clone, Copy, Debug)]
pub(in crate::managed) struct WrittenSite<'a> {
    pub(in crate::managed) name: &'a str,
    pub(in crate::managed) hosts: &'a [String],
    pub(in crate::managed) certificate: WrittenCertificate,
}

impl RawVersion {
    /// What the version names outside itself, put in `files` (the names of the files of the store) and `issued` (the
    /// names of the directories of `acme/`), read without a main file, for the cleaning of the store: an older version
    /// may not pass the check with the main file of now, and still names what it names. Every `chain`, `key` and `ca`
    /// of 64 lowercase digits counts, and every site with `acme` counts with `acme_name` of its hosts as they are
    /// written, which the check passes on as they are; a site with both, which the check refuses, counts with both.
    pub(crate) fn names(&self, files: &mut BTreeSet<[u8; 32]>, issued: &mut BTreeSet<[u8; 32]>) {
        for Object(site) in &self.sites {
            let Object(certificate) = &site.certificate;
            let named = [&certificate.chain, &certificate.key].into_iter().flatten();
            files.extend(named.filter_map(|text| digest(text)));
            if certificate.acme.is_some() {
                issued.insert(acme_name(&site.hosts));
            }
        }
        files.extend(self.upstreams.authorities().filter_map(digest));
    }

    /// The sites, in the order they are written, each with its name, its hosts and the form of its certificate, which
    /// is one of the two forms that the check takes (see `one_of`) or none. Nothing else is checked: not the number of
    /// the sites, nor the number or the form of the hosts, nor the name.
    pub(in crate::managed) fn site_certificates(
        &self,
    ) -> impl ExactSizeIterator<Item = WrittenSite<'_>> {
        self.sites.iter().map(|Object(site)| {
            let Object(certificate) = &site.certificate;
            let written = match (&certificate.chain, &certificate.key, &certificate.acme) {
                (Some(chain), Some(key), None) => match (digest(chain), digest(key)) {
                    (Some(chain), Some(key)) => WrittenCertificate::Files { chain, key },
                    _ => WrittenCertificate::Unknown,
                },
                (None, None, Some(_)) => WrittenCertificate::Acme,
                _ => WrittenCertificate::Unknown,
            };
            WrittenSite {
                name: &site.name,
                hosts: &site.hosts,
                certificate: written,
            }
        })
    }
}
