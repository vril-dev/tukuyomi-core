#!/usr/bin/env bash
# Fetch the pinned release of the OWASP Core Rule Set into a new directory, in
# the form that "rules import --crs" takes: crs-setup.conf, crs-setup.conf.example
# and rules/*.conf and rules/*.data.
#
# Usage: scripts/fetch-crs.sh <new directory>
#
# The version and the sha256 of its release archive are pinned below; they are
# not arguments. The archive is the asset that the release publishes, not the
# tarball that GitHub builds again for a tag. The sha256 is the one of the
# archive whose signature was checked against the release key (fingerprint
# 3600 6F0E 0BA1 6783 2158 8211 38EE ACA1 AB8A 6E72) when it was pinned; this
# script checks the sha256 only. To use another version, pin its archive here
# after checking the signature again.
#
# The archive is fetched over https only, into a temporary directory next to
# the new directory, and checked against the pinned sha256 before anything is
# read from it. An archive that holds a link or any entry that is not a regular
# file or a directory is refused. Only crs-setup.conf.example, rules/*.conf and
# rules/*.data are extracted, and crs-setup.conf is a copy of the example. The
# new directory appears with one rename at the end, so a failure leaves nothing
# behind. An existing directory is never touched.
#
# FETCH_CRS_ARCHIVE_FILE (optional): a local copy of the pinned archive, used in
# place of the download, for a host that cannot reach GitHub and for tests of this
# script. The sha256 check and every other check apply to it unchanged.
set -euo pipefail
umask 077

readonly VERSION="4.23.0"
readonly ARCHIVE="coreruleset-${VERSION}-minimal.tar.gz"
readonly URL="https://github.com/coreruleset/coreruleset/releases/download/v${VERSION}/${ARCHIVE}"
readonly SHA256="e5b11ae86a5a36bbf5d52a3e8f453c217e11cbcd8a3ae150be790c9c35fd7058"
readonly MAX_BYTES=4194304 # the archive is about 260 KB
readonly TOP="coreruleset-${VERSION}"

die() {
  echo "[CRS] $*" >&2
  exit 1
}

[[ $# -eq 1 && -n $1 ]] || die "usage: $0 <new directory>"
dest=$1
while [[ $dest == */ && $dest != / ]]; do
  dest=${dest%/}
done
[[ ! -e $dest && ! -L $dest ]] || die "$dest exists"
parent=$(dirname -- "$dest")

# The temporary directory is next to the new directory, so that the last step is
# a rename on one file system and not a copy that a failure could leave half done.
work=""
cleanup() {
  [[ -z $work ]] || rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
work=$(mktemp -d -- "${parent}/.fetch-crs.XXXXXX") || die "cannot create a temporary directory in ${parent}"

archive="${work}/${ARCHIVE}"
if [[ -n ${FETCH_CRS_ARCHIVE_FILE:-} ]]; then
  [[ -f $FETCH_CRS_ARCHIVE_FILE && ! -L $FETCH_CRS_ARCHIVE_FILE ]] || die "FETCH_CRS_ARCHIVE_FILE is not a regular file"
  echo "[CRS] Using the local archive ${FETCH_CRS_ARCHIVE_FILE}"
  cp -- "$FETCH_CRS_ARCHIVE_FILE" "$archive" || die "cannot copy the local archive"
else
  echo "[CRS] Downloading ${URL}"
  curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 \
    --fail --silent --show-error --location \
    --connect-timeout 20 --max-time 300 --max-filesize "$MAX_BYTES" \
    --output "$archive" "$URL" || die "download failed"
fi

echo "[CRS] Checking the sha256"
(cd "$work" && printf '%s  %s\n' "$SHA256" "$ARCHIVE" | sha256sum -c --strict --status -) ||
  die "the sha256 of the archive differs from the pinned value"

echo "[CRS] Checking the entries"
listing=$(tar -tzvf "$archive") || die "cannot list the archive"
# The first character of a line of the listing is the type of the entry.
others=$(printf '%s\n' "$listing" | cut -c1 | grep -vc '^[-d]$' || true)
[[ $others -eq 0 ]] || die "the archive holds a link or an entry that is not a regular file or a directory"
# The names that are taken are exactly these shapes, so that nothing else is
# extracted, and each is a name that the path of a bundle allows.
top_re=${TOP//./[.]}
members=$(tar -tzf "$archive" | grep -E "^${top_re}/(crs-setup[.]conf[.]example|rules/[A-Za-z0-9_-][A-Za-z0-9._-]*[.](conf|data))\$" || true)
grep -qx "${top_re}/crs-setup[.]conf[.]example" <<<"$members" || die "no crs-setup.conf.example in the archive"
printf '%s\n' "$members" >"${work}/members"

echo "[CRS] Extracting"
out="${work}/crs"
mkdir -m 0700 -- "$out"
tar -xzf "$archive" -C "$out" --strip-components=1 --no-same-owner --no-same-permissions \
  --no-wildcards --verbatim-files-from -T "${work}/members" || die "cannot extract the archive"
stray=$(cd "$out" && find . -mindepth 1 -not -type f -not -path ./rules)
[[ -z $stray ]] || die "the extracted files are not as expected"
cp -- "${out}/crs-setup.conf.example" "${out}/crs-setup.conf"

mv -T -- "$out" "$dest" || die "cannot create ${dest}"
echo "[CRS] Installed ${VERSION} into ${dest}"
echo "[CRS] Next: tukuyomi-proxy rules import <config> --crs ${dest}"
