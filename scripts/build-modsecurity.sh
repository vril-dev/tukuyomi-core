#!/usr/bin/env bash
# Build the pinned release of libmodsecurity (ModSecurity v3) as static libraries
# into a new directory (a prefix): include/modsecurity/*.h and lib/libmodsecurity.a.
#
# Usage: scripts/build-modsecurity.sh <new prefix directory>
#
# The version and the sha256 of its release archive are pinned below; they are
# not arguments. The archive is the asset that the release publishes (it holds
# the generated configure script), not the tarball that GitHub builds again for a
# tag. The sha256 is the one of the archive whose signature was checked against
# the release key of OWASP ModSecurity (fingerprint 0B2B A192 4065 B446 9120 2A2A
# D286 E022 149F 0F6E) when it was pinned; this script checks the sha256 only. To
# use another version, pin its archive here after checking the signature again.
#
# The archive is fetched over https only, into a temporary directory next to the
# new directory, and checked against the pinned sha256 before anything is read
# from it. Every entry must be a regular file or a directory with a plain name
# inside the one top directory; the only other entries allowed are the relative
# symbolic links of the examples of a bundled library, which are not extracted.
# The build runs in the temporary directory with an empty environment and fixed
# configure flags, and the configure summary must show that only YAJL and PCRE2
# were found among the optional dependencies. The install is staged and the new
# directory appears with one rename at the end, so a failure leaves nothing
# behind. An existing directory is never touched.
#
# Needed on the host: a C and C++ compiler, make, libyajl-dev (static YAJL) and
# libpcre2-dev (static PCRE2). The build takes a few minutes.
#
# BUILD_MODSECURITY_ARCHIVE_FILE (optional): a local copy of the pinned archive,
# used in place of the download, for a host that cannot reach GitHub and for tests
# of this script. The sha256 check and every other check apply to it unchanged.
set -euo pipefail
umask 077

readonly VERSION="3.0.17"
readonly TOP="modsecurity-v${VERSION}"
readonly ARCHIVE="${TOP}.tar.gz"
readonly URL="https://github.com/owasp-modsecurity/ModSecurity/releases/download/v${VERSION}/${ARCHIVE}"
readonly SHA256="f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50"
readonly MAX_BYTES=67108864      # the archive is about 12 MB
readonly MAX_ENTRIES=20000       # the archive holds about 6300
readonly MAX_UNPACKED=268435456  # about 80 MB
# The directory of the only symbolic links of the archive: examples of a bundled
# library, 147 relative links, none of which the build reads.
readonly LINK_DIR="${TOP}/others/mbedtls/tf-psa-crypto/drivers/pqcp/mldsa-native/examples"

die() {
  echo "[MSC] $*" >&2
  exit 1
}

[[ $# -eq 1 && -n $1 ]] || die "usage: $0 <new prefix directory>"
dest=$1
while [[ $dest == */ && $dest != / ]]; do
  dest=${dest%/}
done
[[ $dest == /* ]] || dest="${PWD}/${dest}"
# The prefix is written into the installed files and passed to configure and make,
# so it is a plain absolute path: no space, quote, dollar sign or dot component.
[[ $dest =~ ^(/[A-Za-z0-9_+-][A-Za-z0-9._+-]*)+$ ]] ||
  die "the prefix must be an absolute path of letters, digits and . _ + - only"
[[ ! -e $dest && ! -L $dest ]] || die "$dest exists"
parent=$(dirname -- "$dest")

# The temporary directory is next to the new directory, so that the last step is
# a rename on one file system and not a copy that a failure could leave half done.
# A step that runs long is started in its own session and waited for, so that a
# signal reaches the whole step at once: a shell runs a trap only after the
# command in the foreground has returned.
work=""
child=0
cleanup() {
  cd / || true
  if [[ $child -ne 0 ]]; then
    kill -TERM -- "-${child}" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
    kill -KILL -- "-${child}" 2>/dev/null || true
  fi
  [[ -z $work ]] || rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
work=$(mktemp -d -- "${parent}/.build-modsecurity.XXXXXX") || die "cannot create a temporary directory in ${parent}"

# step <name> <log file> <command...>: the command runs with an empty environment
# but the search path, its output goes to the log file, and the last lines of the
# log are shown when it fails.
step() {
  local what=$1 log=$2 rc=0
  shift 2
  setsid env -i PATH="$PATH" LC_ALL=C TMPDIR="${work}/tmp" "$@" >"$log" 2>&1 &
  child=$!
  wait "$child" || rc=$?
  child=0
  if [[ $rc -ne 0 ]]; then
    tail -n 30 -- "$log" >&2
    die "${what} failed"
  fi
}

archive="${work}/${ARCHIVE}"
if [[ -n ${BUILD_MODSECURITY_ARCHIVE_FILE:-} ]]; then
  [[ -f $BUILD_MODSECURITY_ARCHIVE_FILE && ! -L $BUILD_MODSECURITY_ARCHIVE_FILE ]] || die "BUILD_MODSECURITY_ARCHIVE_FILE is not a regular file"
  echo "[MSC] Using the local archive ${BUILD_MODSECURITY_ARCHIVE_FILE}"
  cp -- "$BUILD_MODSECURITY_ARCHIVE_FILE" "$archive" || die "cannot copy the local archive"
else
  echo "[MSC] Downloading ${URL}"
  curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 \
    --fail --silent --show-error --location \
    --connect-timeout 20 --max-time 600 --max-filesize "$MAX_BYTES" \
    --output "$archive" "$URL" || die "download failed"
fi
size=$(stat -c %s -- "$archive") || die "cannot read the archive"
[[ $size -gt 0 && $size -le $MAX_BYTES ]] || die "the archive is empty or larger than ${MAX_BYTES} bytes"

echo "[MSC] Checking the sha256"
(cd "$work" && printf '%s  %s\n' "$SHA256" "$ARCHIVE" | sha256sum -c --strict --status -) ||
  die "the sha256 of the archive differs from the pinned value"

echo "[MSC] Checking the entries"
# One line per entry: the type, the owner, the size, the date, the name, and for a
# link its target. A name outside the letters below (a space, a backslash, a quote),
# an absolute name, an empty or dot component, or a name outside the top directory
# is refused.
tar --numeric-owner --quoting-style=escape -tzvf "$archive" >"${work}/listing" || die "cannot list the archive"
entries=$(wc -l <"${work}/listing")
[[ $entries -gt 0 && $entries -le $MAX_ENTRIES ]] || die "the archive holds no entry or more than ${MAX_ENTRIES}"
awk -v top="$TOP" -v linkdir="$LINK_DIR" -v max="$MAX_UNPACKED" '
  function chars(s) { return s ~ "^[A-Za-z0-9._+~@/-]+$" && s !~ "//" }
  function plain(s) { return chars(s) && s !~ "(^|/)[.][.]?(/|$)" }
  {
    type = substr($0, 1, 1)
    name = $0; sub(/^[^ ]+ +[^ ]+ +[0-9]+ +[^ ]+ +[^ ]+ +/, "", name)
    target = ""
    if (type == "l") {
      i = index(name, " -> "); if (i == 0) { print "link without a target"; bad = 1; exit }
      target = substr(name, i + 4); name = substr(name, 1, i - 1)
    }
    if (type != "-" && type != "d" && type != "l") { print "entry that is not a file, a directory or a link"; bad = 1; exit }
    if (!plain(name)) { print "name that is not plain"; bad = 1; exit }
    if (name != top && substr(name, 1, length(top) + 1) != top "/") { print "name outside the top directory"; bad = 1; exit }
    if (type == "l" && (substr(name, 1, length(linkdir) + 1) != linkdir "/" || !chars(target) || substr(target, 1, 1) == "/")) { print "link that is not one of the known relative links"; bad = 1; exit }
    if (type == "-") total += $3
    if (total > max) { print "unpacked size over the limit"; bad = 1; exit }
  }
  END { exit bad }' "${work}/listing" >"${work}/entry-error" || die "the archive is refused: $(cat "${work}/entry-error")"
# The members that are extracted are the files and directories, one by one, so
# that nothing that was not checked is extracted and no link is created.
awk '$1 ~ /^[-d]/ { sub(/^[^ ]+ +[^ ]+ +[0-9]+ +[^ ]+ +[^ ]+ +/, ""); print }' "${work}/listing" >"${work}/members"

echo "[MSC] Extracting"
mkdir -m 0700 -- "${work}/src" "${work}/tmp" "${work}/stage"
tar -xzf "$archive" -C "${work}/src" --no-same-owner --no-same-permissions \
  --no-recursion --no-wildcards --verbatim-files-from -T "${work}/members" || die "cannot extract the archive"
stray=$(find "${work}/src" -mindepth 1 -not -type f -not -type d)
[[ -z $stray ]] || die "the extracted files are not as expected"
src="${work}/src/${TOP}"
[[ -x ${src}/configure ]] || die "no configure script in the archive"

echo "[MSC] Configuring"
cd -- "$src"
step configure "${work}/configure.log" CFLAGS=-O2 CXXFLAGS=-O2 ./configure "--prefix=${dest}" \
  --disable-shared --enable-static --disable-examples --disable-doxygen-doc --disable-debug-logs \
  --with-yajl --without-lmdb --without-curl --without-lua --without-maxmind --without-geoip \
  --without-ssdeep --without-libxml
! grep -q 'unrecognized options' "${work}/configure.log" || die "configure did not know a flag"
# The summary lines are "   + NAME      ....status": exactly these eight, and only YAJL
# and PCRE2 found.
optional=$(awk '/^ Optional dependencies/ { on = 1; next } on && /^ [A-Za-z]/ { exit } on && /^   [+] / { print }' "${work}/configure.log" |
  sed -E 's/^   [+] ([^ ]+( [^ ]+)*) +[.]+([a-z]+).*$/\1=\3/')
expected=$'GeoIP/MaxMind=disabled\nLibCURL=disabled\nYAJL=found\nLMDB=disabled\nLibXML2=disabled\nSSDEEP=disabled\nLUA=disabled\nPCRE2=found'
[[ $optional == "$expected" ]] || die "the configure summary does not show YAJL and PCRE2 as the only optional dependencies"

echo "[MSC] Building (this takes a while)"
step make "${work}/make.log" make -j2
echo "[MSC] Installing"
stage="${work}/stage"
step install "${work}/install.log" make install "DESTDIR=${stage}"
staged="${stage}${dest}"
[[ -s ${staged}/lib/libmodsecurity.a && -s ${staged}/include/modsecurity/modsecurity.h ]] || die "the build did not install the library and its headers"
grep -qx "Version: ${VERSION}" "${staged}/lib/pkgconfig/modsecurity.pc" || die "the installed version is not ${VERSION}"
outside=$(find "$stage" -not -type d -not -path "${staged}/*")
[[ -z $outside ]] || die "the install wrote outside the prefix"

mv -T -- "$staged" "$dest" || die "cannot create ${dest}"
echo "[MSC] Installed ${VERSION} into ${dest}"
echo "[MSC] Next: TUKUYOMI_MODSECURITY_PREFIX=${dest} cargo build (in inspector-modsecurity)"
