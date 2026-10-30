package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

const sumABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" // sha256 of "abc"

// canon is the canonical text of the manifest of the files, with the load.
func canon(files []manifestFile, load ...string) string {
	return string(manifest{Version: 1, Files: files, Load: load}.encode())
}

func oneFile(path string, size int64) []manifestFile {
	return []manifestFile{{Path: path, Size: size, SHA256: sumABC}}
}

// numbered is n files in the byte order of their paths, each of the size.
func numbered(n int, size int64) []manifestFile {
	var out []manifestFile
	for i := 0; i < n; i++ {
		out = append(out, manifestFile{Path: fmt.Sprintf("rules/f%03d.conf", i), Size: size, SHA256: sumABC})
	}
	return out
}

// The manifest must be the one canonical text, and its values must be in range.
func TestParseManifest(t *testing.T) {
	const canonical = "not in the canonical form"
	a := "rules/a.conf"
	base := canon(oneFile(a, 3), a)
	detect := string(manifest{Version: versionDetect, Files: oneFile(a, 3), Load: []string{a}}.encode())
	rows := []struct{ name, in, want string }{
		{"white space after a colon", strings.Replace(base, `"version":1`, `"version": 1`, 1), canonical},
		{"key case", strings.Replace(base, `"version"`, `"Version"`, 1), canonical},
		{"repeated key", strings.Replace(base, `{"version":1,`, `{"version":1,"version":1,`, 1), canonical},
		{"version 2 without the mode", strings.Replace(base, `"version":1`, `"version":2`, 1), canonical},
		{"version 1 with the mode", strings.Replace(detect, `"version":2`, `"version":1`, 1), canonical},
		{"mode block", strings.Replace(detect, `"detect"`, `"block"`, 1), canonical},
		{"version 4", strings.Replace(base, `"version":1`, `"version":4`, 1), "version is not 1, 2 or 3"},
		{"dot dot component", canon(oneFile("rules/../a.conf", 3), "rules/../a.conf"), "a path is malformed"},
		{"paths out of order", canon([]manifestFile{{Path: "rules/b.conf", Size: 3, SHA256: sumABC}, {Path: a, Size: 3, SHA256: sumABC}}, a), "strictly increasing"},
		{"size 2 MiB + 1", canon(oneFile(a, maxFileBytes+1), a), "a size is out of range"},
		{"load names a path that is not in files", canon(oneFile(a, 3), "rules/b.conf"), "not in files"},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseManifest([]byte(c.in))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want a part %q", err, c.want)
			}
		})
	}
}

// The golden files are the forms that the writer of a manifest has to produce:
// each is read, written again to the same bytes, and has the sha256 of its
// file. The one of version 2 is the one of version 1 with the mode, and a
// variant of it is refused: another mode, or the keys in another order. The
// one of version 3 is the one of version 1 with the mode and two routes.
func TestManifestGolden(t *testing.T) {
	for _, g := range []struct {
		file    string
		version int
		routes  int
	}{
		{"testdata/manifest-v1-golden.json", versionBlock, 0},
		{"testdata/manifest-v2-golden.json", versionDetect, 0},
		{"testdata/manifest-v3-golden.json", versionRoutes, 2},
	} {
		t.Run(g.file, func(t *testing.T) {
			b, err := os.ReadFile(g.file)
			if err != nil {
				t.Fatal(err)
			}
			m, err := parseManifest(b)
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !bytes.Equal(m.encode(), b) {
				t.Fatalf("written again: %q", m.encode())
			}
			if m.Version != g.version || len(m.Files) != 10 || len(m.Load) != 7 || len(m.Routes) != g.routes {
				t.Fatalf("version %d, %d files, %d in load, %d routes", m.Version, len(m.Files), len(m.Load), len(m.Routes))
			}
			want, err := os.ReadFile(g.file + ".sha256")
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(b)
			if string(want) != hex.EncodeToString(sum[:])+"\n" {
				t.Fatalf("sha256 of the golden file is %x, the file has %q", sum, want)
			}
		})
	}
	g, err := os.ReadFile("testdata/manifest-v2-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	const mode = `"mode":"detect"`
	variants := map[string]string{
		"mode block":            strings.Replace(string(g), mode, `"mode":"block"`, 1),
		"mode with a capital":   strings.Replace(string(g), mode, `"mode":"Detect"`, 1),
		"mode empty":            strings.Replace(string(g), mode, `"mode":""`, 1),
		"keys in another order": strings.Replace(string(g), `{"version":2,`+mode+`,`, `{`+mode+`,"version":2,`, 1),
	}
	for name, in := range variants {
		if in == string(g) {
			t.Fatalf("%s: the variant is the golden file", name)
		}
		if _, err := parseManifest([]byte(in)); err == nil || !strings.Contains(err.Error(), "not in the canonical form") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A manifest of version 3 is refused unless it is the one canonical form with
// a mode and routes in the form that the proxy accepts. The rows put their own
// routes (or another key) into the golden file; an empty want is a manifest
// that is read.
func TestParseManifestRoutes(t *testing.T) {
	const canonical = "not in the canonical form"
	const badPath, badHost, twice = "a route path is malformed", "a route host is malformed", "twice"
	gb, err := os.ReadFile("testdata/manifest-v3-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	g := string(gb)
	const routes = `[{"path":"/static/","action":"bypass"},{"host":"example.test","path":"/health","action":"bypass"}]`
	if !strings.Contains(g, routes) || !strings.Contains(g, `{"version":3,"mode":"block",`) {
		t.Fatal("the golden file is not the one these rows change")
	}
	with := func(r string) string { return strings.Replace(g, routes, r, 1) }
	one := func(p string) string { return `[{"path":"` + p + `","action":"bypass"}]` }
	onHost := func(h string) string { return `[{"host":"` + h + `","path":"/a","action":"bypass"}]` }
	many := func(n int) string {
		var rs []string
		for i := 0; i < n; i++ {
			rs = append(rs, fmt.Sprintf(`{"path":"/r%03d","action":"bypass"}`, i))
		}
		return "[" + strings.Join(rs, ",") + "]"
	}
	long := "/" + strings.Repeat("a", 254) // 255 bytes
	rows := []struct{ name, in, want string }{
		{"no routes key", strings.Replace(g, `,"routes":`+routes, "", 1), canonical},
		{"keys in another order", strings.Replace(g, `{"version":3,"mode":"block",`, `{"mode":"block","version":3,`, 1), canonical},
		{"route keys in another order", with(`[{"path":"/static/","action":"bypass"},{"path":"/health","host":"example.test","action":"bypass"}]`), canonical},
		{"action is not bypass", with(`[{"path":"/static/","action":"deny"}]`), canonical},
		{"host given and empty", with(`[{"host":"","path":"/static/","action":"bypass"}]`), canonical},
		{"version 1 with routes", strings.Replace(g, `{"version":3,"mode":"block",`, `{"version":1,`, 1), canonical},
		{"version 2 with routes", strings.Replace(g, `"version":3,"mode":"block"`, `"version":2,"mode":"detect"`, 1), canonical},
		{"mode with a capital", strings.Replace(g, `"mode":"block"`, `"mode":"Block"`, 1), "mode is not block or detect"},
		{"routes empty", with(`[]`), "no routes"},
		{"256 routes", with(many(256)), ""},
		{"257 routes", with(many(257)), "too many routes"},
		{"path is /", with(one("/")), badPath},
		{"path is /a", with(one("/a")), ""},
		{"path without a leading /", with(one("static/")), badPath},
		{"path of 255 bytes", with(one(long)), ""},
		{"path of 256 bytes", with(one(long + "a")), badPath},
		{"path with an escape", with(one("/a%41%7e/")), ""},
		{"path with a ;", with(one("/a;b")), badPath},
		{"escape cut short", with(one("/a%2")), badPath},
		{"escape that is not hex", with(one("/a%zz")), badPath},
		{"escaped /", with(one("/a%2f")), badPath},
		{"escaped . with a capital", with(one("/a%2E")), badPath},
		{"escaped backslash", with(one("/a%5c")), badPath},
		{"escaped zero byte", with(one("/a%00")), badPath},
		{"escaped %", with(one("/a%252e")), badPath},
		{"dot dot component", with(one("/a/../b")), badPath},
		{"empty component", with(one("/a//b")), badPath},
		{"host of 253 bytes", with(onHost(strings.Repeat("a", 253))), ""},
		{"host of 254 bytes", with(onHost(strings.Repeat("a", 254))), badHost},
		{"host with a capital", with(onHost("Example.test")), badHost},
		{"host ends with a dot", with(onHost("example.test.")), badHost},
		{"port 65535", with(onHost("example.test:65535")), ""},
		{"port 65536", with(onHost("example.test:65536")), badHost},
		{"port 0", with(onHost("example.test:0")), badHost},
		{"same path twice", with(`[{"path":"/a","action":"bypass"},{"path":"/a","action":"bypass"}]`), twice},
		{"same host and path twice", with(`[{"host":"h","path":"/a","action":"bypass"},{"host":"h","path":"/a","action":"bypass"}]`), twice},
		{"same path with and without a host", with(`[{"path":"/a","action":"bypass"},{"host":"h","path":"/a","action":"bypass"}]`), ""},
		{"mode detect", strings.Replace(g, `"mode":"block"`, `"mode":"detect"`, 1), ""},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			m, err := parseManifest([]byte(c.in))
			switch {
			case c.want == "" && (err != nil || !bytes.Equal(m.encode(), []byte(c.in))):
				t.Fatalf("rejected or written again in another form: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("error %v, want a part %q", err, c.want)
			}
		})
	}
}

// writeRoutesBundle writes the bundle like writeBundle, then replaces its
// manifest with one of version 3 that has the mode and one route. It returns
// the fingerprint.
func writeRoutesBundle(t *testing.T, dir, mode string, files map[string]string, load ...string) [32]byte {
	t.Helper()
	writeBundle(t, dir, files, load...)
	m := testManifest(files, load)
	m.Version, m.Mode, m.Routes = versionRoutes, mode, []manifestRoute{{Path: "/static/"}}
	mb := m.encode()
	if err := os.WriteFile(filepath.Join(dir, manifestName), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(mb)
}

// A bundle of version 3 knows its mode from the key "mode", and carries the
// sha256 of its manifest bytes. The WAF of the mode "detect" has the two rules
// around the files and the one of the mode "block" has not: a file that takes
// the id of one of them stops the build in the first only.
func TestReadBundleRoutes(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	files := map[string]string{ruleFile: fmt.Sprintf("SecAction \"id:%d,phase:1,pass\"\n", detectBeginID)}
	for _, mode := range []string{"block", "detect"} {
		detect := mode == "detect"
		dir := t.TempDir()
		sum := writeRoutesBundle(t, dir, mode, files, ruleFile)
		b, err := readBundle(dir)
		if err != nil || b.detect != detect || b.fingerprint != sum {
			t.Fatalf("mode %s: detect %v, fingerprint %x, error %v", mode, b != nil && b.detect, sum, err)
		}
		if _, err := newWAF(b); (err != nil) != detect {
			t.Errorf("mode %s: the build of a file with the id of the rule before the files: %v", mode, err)
		}
	}
}

// The bundle knows its mode from the version of its manifest, and carries the
// sha256 of the manifest bytes of that version.
func TestReadBundleMode(t *testing.T) {
	files := map[string]string{ruleFile: "SecRuleEngine On\n"}
	for _, c := range []struct {
		version int
		detect  bool
	}{{versionBlock, false}, {versionDetect, true}} {
		dir := t.TempDir()
		sum := writeBundleVersion(t, dir, c.version, files, ruleFile)
		b, err := readBundle(dir)
		if err != nil || b.detect != c.detect || b.fingerprint != sum {
			t.Errorf("version %d: detect %v, fingerprint %x, error %v", c.version, b != nil && b.detect, sum, err)
		}
	}
}

// The bundle that the kernel tests use is read with the product's reader: a
// change to rules/basic.conf without the manifest fails here, and not as an
// exit 11 of the inspector with no visible cause.
func TestKernelBundle(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	dir, err := filepath.Abs("../kernel/tests/rules")
	if err != nil {
		t.Fatal(err)
	}
	b, err := readBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.load, []string{"rules/basic.conf"}) || len(b.files) != 1 {
		t.Fatalf("load %q, %d files", b.load, len(b.files))
	}
	if err := checkRules(string(b.files["rules/basic.conf"])); err != nil {
		t.Fatal(err)
	}
	if p, err := checkMarkers(b); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	if _, err := newWAF(b); err != nil {
		t.Fatal(err)
	}
}

// readBundleIn runs readBundle in the background and fails when it waits on the
// FIFO (that no writer opens) instead of returning.
func readBundleIn(t *testing.T, dir, fifo string) error {
	t.Helper()
	res := make(chan error, 1)
	go func() { _, err := readBundle(dir); res <- err }()
	select {
	case err := <-res:
		return err
	case <-time.After(5 * time.Second):
		// Release the open that waits for a writer so no goroutine is left.
		if w, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			syscall.Close(w)
		}
		select {
		case <-res:
		case <-time.After(5 * time.Second):
		}
		t.Fatal("readBundle waited on a FIFO")
	}
	return nil
}

func TestReadBundle(t *testing.T) {
	files := map[string]string{
		"crs/rules/b.conf": "SecRuleEngine On\n",
		"rules/a.conf":     "SecRequestBodyAccess On\n",
	}
	load := []string{"rules/a.conf", "crs/rules/b.conf"}
	write := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		writeBundle(t, dir, files, load...)
		return dir
	}
	fail := []struct {
		name   string
		mutate func(t *testing.T, dir string)
		want   string
	}{
		{"sha256 differs", func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, "rules/a.conf"), []byte(strings.Replace(files["rules/a.conf"], "On", "Of", 1)), 0o600)
		}, "rules/a.conf: sha256 differs from the manifest"},
		{"size differs", func(t *testing.T, dir string) {
			os.Truncate(filepath.Join(dir, "rules/a.conf"), int64(len(files["rules/a.conf"])-1))
		}, "rules/a.conf: size differs from the manifest"},
		{"file is a link out of the bundle", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "rules/a.conf")
			os.Remove(p)
			os.Symlink(filepath.Join(write(t), "rules/a.conf"), p) // the very bytes of the manifest, in another directory
		}, "path escapes from parent"},
	}
	for _, c := range fail {
		t.Run(c.name, func(t *testing.T) {
			dir := write(t)
			c.mutate(t, dir)
			b, err := readBundle(dir)
			if err == nil || b != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("bundle %v, error %v, want a part %q", b != nil, err, c.want)
			}
			if strings.Contains(err.Error(), dir) {
				t.Fatalf("the error holds the directory: %q", err)
			}
		})
	}
	// A FIFO must be rejected without waiting for a writer.
	t.Run("manifest is a FIFO", func(t *testing.T) {
		dir := write(t)
		fifo := filepath.Join(dir, manifestName)
		os.Remove(fifo)
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := readBundleIn(t, dir, fifo); err == nil || !strings.Contains(err.Error(), "manifest.json: not a regular file") {
			t.Fatalf("err %v, want the fstat rejection (not a regular file)", err)
		}
	})
	t.Run("129 files", func(t *testing.T) {
		dir := t.TempDir()
		many := map[string]string{}
		for _, f := range numbered(129, 1) {
			many[f.Path] = "x"
		}
		writeBundle(t, dir, many, "rules/f000.conf")
		if _, err := readBundle(dir); err == nil || !strings.Contains(err.Error(), "too many files") {
			t.Fatalf("err %v", err)
		}
	})
}

// The root of the rules holds the files of the bundle and nothing else.
func TestBundleFS(t *testing.T) {
	files := map[string]string{"crs/rules/a.conf": "SecRuleEngine On\n", "rules/b.conf": ""}
	dir := t.TempDir()
	writeBundle(t, dir, files, "crs/rules/a.conf", "rules/b.conf")
	b, err := readBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	root := bundleFS{files: b.files}
	for name, want := range files {
		if got, err := fs.ReadFile(root, name); err != nil || string(got) != want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	for _, name := range []string{"manifest.json", "/crs/rules/a.conf", "..", "crs/rules/missing.data"} {
		f, err := root.Open(name)
		var pe *fs.PathError
		if f != nil || !errors.As(err, &pe) || pe.Op != "open" || pe.Path != name || pe.Err != fs.ErrNotExist {
			t.Errorf("%q: %v %v", name, f, err)
		}
	}
}

// A manifest of version 4 is the form of a bundle of an engine other than
// Coraza, which is the engine of this inspector: the engine key is not one that
// the reader writes again, so the manifest is not the canonical form of
// anything it knows and is refused. readBundle gives that error, which main
// reports as a refusal of the rules (exit 11) before the sandbox or any rule is
// touched. The same holds for a version 4 that names Coraza, which the proxy
// refuses as well.
func TestManifestOfVersion4IsRefused(t *testing.T) {
	g, err := os.ReadFile("testdata/manifest-v4-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	coraza := bytes.Replace(g, []byte(`"engine":"modsecurity"`), []byte(`"engine":"coraza"`), 1)
	if bytes.Equal(coraza, g) {
		t.Fatal("the variant is the golden file")
	}
	for name, in := range map[string][]byte{"golden file": g, "engine coraza": coraza} {
		if _, err := parseManifest(in); err == nil || !strings.Contains(err.Error(), "not in the canonical form") {
			t.Errorf("%s: %v", name, err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, manifestName), g, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBundle(dir); err == nil || !strings.Contains(err.Error(), manifestName+": not in the canonical form") {
		t.Errorf("readBundle: %v", err)
	}
}
