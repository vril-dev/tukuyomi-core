package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"syscall"
	"time"
)

// Limits of a rule bundle. They stop mistakes and load; they are not tuning
// values. The path form is checked again here whatever wrote the manifest.
const (
	manifestName     = "manifest.json"
	maxManifestBytes = 64 << 10
	maxBundleFiles   = 128
	maxFileBytes     = 2 << 20
	maxBundleBytes   = 8 << 20
	maxPathBytes     = 255
	maxPathParts     = 4
	maxPartBytes     = 128
)

// The versions of a manifest. A bundle of version 1 blocks. One of version 2
// has the mode "detect", the only mode: its rules only detect, and a match
// that would have blocked is reported with the Continue of the request.
const (
	versionBlock  = 1
	versionDetect = 2
)

// bundle is a rule bundle that readBundle verified: the bytes of manifest.json,
// its fingerprint, the rule files in the order they are loaded and the bytes of
// every file by path.
type bundle struct {
	manifestBytes []byte
	fingerprint   [32]byte // sha256 of manifestBytes
	detect        bool     // the rules only detect (the manifest is of version 2)
	load          []string
	files         map[string][]byte
}

// manifest is the content of manifest.json. The fields are exported only for
// encoding/json; the writer is encode. The mode of version 2 has no field: it
// is "detect" or the manifest is not canonical.
type manifest struct {
	Version int            `json:"version"`
	Files   []manifestFile `json:"files"`
	Load    []string       `json:"load"`
}

type manifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"` // lowercase hex
}

// encode writes the one canonical form: the keys in the order version, mode
// (version 2 only, always "detect"), files, load (path, size, sha256 inside a
// file), no white space, numbers in decimal, strings between quotes without any
// escape, and one newline at the end. It does not use encoding/json to write,
// so the bytes do not depend on its escaping. Go only uses it to check a
// manifest it read.
func (m manifest) encode() []byte {
	b := append([]byte(nil), `{"version":`...)
	b = strconv.AppendInt(b, int64(m.Version), 10)
	if m.Version == versionDetect {
		b = append(b, `,"mode":"detect"`...)
	}
	b = append(b, `,"files":[`...)
	for i, f := range m.Files {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"path":"`...)
		b = append(b, f.Path...)
		b = append(b, `","size":`...)
		b = strconv.AppendInt(b, f.Size, 10)
		b = append(b, `,"sha256":"`...)
		b = append(b, f.SHA256...)
		b = append(b, `"}`...)
	}
	b = append(b, `],"load":[`...)
	for i, p := range m.Load {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '"')
		b = append(b, p...)
		b = append(b, '"')
	}
	return append(b, "]}\n"...)
}

// parseManifest checks the bytes of a manifest.json. encoding/json is loose
// (it ignores the case of a key, takes the last of a repeated key and accepts
// white space, escapes and anything after the value), so the manifest is
// decoded, written again in the canonical form and required to be the very
// bytes that were read; one comparison closes every such spelling. The values
// are then checked without trusting the writer. A key that is not a field
// (the mode of version 2, or a mode in version 1) is dropped by the decoding
// and so is not in the bytes that are written again: the manifest is refused,
// as is a version 2 whose mode is not "detect". The errors are fixed
// sentences that hold no value of the manifest.
func parseManifest(b []byte) (manifest, error) {
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return manifest{}, errors.New("not a manifest of the expected types")
	}
	if !bytes.Equal(m.encode(), b) {
		return manifest{}, errors.New("not in the canonical form")
	}
	if m.Version != versionBlock && m.Version != versionDetect {
		return manifest{}, errors.New("version is not 1 or 2")
	}
	if len(m.Files) == 0 {
		return manifest{}, errors.New("no files")
	}
	if len(m.Files) > maxBundleFiles {
		return manifest{}, errors.New("too many files")
	}
	in := make(map[string]bool, len(m.Files))
	var total int64 // each size is at most maxFileBytes and there are at most maxBundleFiles of them: no overflow
	for i, f := range m.Files {
		if !validPath(f.Path) {
			return manifest{}, errors.New("a path is malformed")
		}
		if i > 0 && m.Files[i-1].Path >= f.Path {
			return manifest{}, errors.New("paths are not in strictly increasing byte order")
		}
		if f.Size < 0 || f.Size > maxFileBytes {
			return manifest{}, errors.New("a size is out of range")
		}
		if total += f.Size; total > maxBundleBytes {
			return manifest{}, errors.New("the sizes add up to more than the limit")
		}
		if !validSHA256(f.SHA256) {
			return manifest{}, errors.New("a sha256 is malformed")
		}
		in[f.Path] = true
	}
	if len(m.Load) == 0 {
		return manifest{}, errors.New("load is empty")
	}
	seen := make(map[string]bool, len(m.Load))
	for _, p := range m.Load {
		if !in[p] {
			return manifest{}, errors.New("load names a path that is not in files")
		}
		if seen[p] {
			return manifest{}, errors.New("load names a path twice")
		}
		seen[p] = true
	}
	return m, nil
}

// nameByte reports whether c may stand in a component of a path of a bundle
// and in the name of a marker.
func nameByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-'
}

// validPath reports whether p is a path of a bundle: relative, 1 to 4
// components separated by "/", each of 1 to 128 bytes of nameByte that does not
// start with ".", at most 255 bytes in all, and not manifest.json.
func validPath(p string) bool {
	if p == "" || len(p) > maxPathBytes || p == manifestName {
		return false
	}
	parts, start := 0, 0
	for i := 0; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			if !nameByte(p[i]) {
				return false
			}
			continue
		}
		if n := i - start; n == 0 || n > maxPartBytes || p[start] == '.' {
			return false
		}
		if parts++; parts > maxPathParts {
			return false
		}
		start = i + 1
	}
	return true
}

// validSHA256 reports whether s is 64 lowercase hex digits.
func validSHA256(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		if _, ok := hexVal(s[i]); !ok {
			return false
		}
	}
	return true
}

// readBundle reads the bundle in dir once: manifest.json first, then the files
// of the manifest in its order. Each file is a regular file inside the
// directory (os.Root does not follow a link out of it), of the size the
// manifest gives, and has the sha256 the manifest gives; nothing is handed to
// Coraza before all of that holds. The fingerprint is the sha256 of the
// manifest bytes that were read.
func readBundle(dir string) (*bundle, error) {
	// os.OpenRoot opens the path for reading and so waits for a writer on a
	// FIFO. The type is looked at first, without opening the path. (A FIFO put
	// there between the two calls would still wait: the process that starts the
	// inspector bounds the start.)
	st, err := os.Stat(dir)
	if err != nil {
		return nil, withoutPath(err)
	}
	if !st.IsDir() {
		return nil, errors.New("not a directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, withoutPath(err)
	}
	defer root.Close()
	mb, err := readBundleFile(root, manifestName, maxManifestBytes)
	if err != nil {
		return nil, err
	}
	m, err := parseManifest(mb)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", manifestName, err)
	}
	b := &bundle{manifestBytes: mb, fingerprint: sha256.Sum256(mb), detect: m.Version == versionDetect, load: m.Load, files: make(map[string][]byte, len(m.Files))}
	for _, f := range m.Files {
		data, err := readBundleFile(root, f.Path, f.Size)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != f.Size {
			return nil, fmt.Errorf("%s: size differs from the manifest", f.Path)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, fmt.Errorf("%s: sha256 differs from the manifest", f.Path)
		}
		b.files[f.Path] = data
	}
	return b, nil
}

// readBundleFile reads one file of the root once: a regular file of at most
// limit bytes, and the bytes read must match the size seen by fstat. The name
// is the bundle path (or manifest.json), which may appear in a diagnostic; the
// error of the system is kept without the name that os puts in it.
func readBundleFile(root *os.Root, name string, limit int64) ([]byte, error) {
	// O_NONBLOCK: opening a FIFO must not wait for a writer; the fstat check
	// below then rejects it. It does not affect reads of a regular file.
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, withoutPath(err))
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, withoutPath(err))
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s: too large", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, withoutPath(err))
	}
	if int64(len(b)) != st.Size() {
		return nil, fmt.Errorf("%s: size changed while reading", name)
	}
	return b, nil
}

// bundleFS is the root file system of the rules: the files of the bundle, as
// verified by readBundle, and nothing else. Every file read that a rule causes
// (the file of @pmFromFile, @pmf, @ipMatchFromFile, @ipMatchF and
// @validateSchema, and the rule files themselves) goes through the root of the
// Coraza parser, so a rule that names any other file fails NewWAF and nothing
// outside the bundle, which the fingerprint covers, is read. A name that is
// not valid for io/fs (absolute, "..", empty, a trailing "/"), manifest.json,
// a name that is not in the bundle and a directory (also "." and a component
// in the middle of a path) do not exist.
type bundleFS struct{ files map[string][]byte }

func (b bundleFS) Open(name string) (fs.File, error) {
	data, ok := b.files[name]
	if !ok || !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &bundleFile{r: bytes.NewReader(data), info: bundleInfo{name: path.Base(name), size: int64(len(data))}}, nil
}

// bundleFile is a read-only file of a bundleFS.
type bundleFile struct {
	r    *bytes.Reader
	info bundleInfo
}

func (f *bundleFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *bundleFile) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *bundleFile) Close() error               { return nil }

// bundleInfo is the fs.FileInfo of a regular file with mode 0444 and no time.
type bundleInfo struct {
	name string
	size int64
}

func (i bundleInfo) Name() string     { return i.name }
func (i bundleInfo) Size() int64      { return i.size }
func (bundleInfo) Mode() fs.FileMode  { return 0o444 }
func (bundleInfo) ModTime() time.Time { return time.Time{} }
func (bundleInfo) IsDir() bool        { return false }
func (bundleInfo) Sys() any           { return nil }
