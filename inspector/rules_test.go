package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func TestCheckRules(t *testing.T) {
	const act = `SecAction "id:1,phase:1,pass,`
	// One row per guard, and the spellings that only the reduction to logical
	// directives catches. Some rows are false rejects by design (the guard is
	// a textual over-approximation).
	reject := []struct{ name, rules string }{
		{"ctl ruleEngine", act + "ctl:ruleEngine=Off\"\n"},
		{"ctl ruleEngine split by a continuation", act + "ctl:rule\\\nEngine=Off\"\n"},
		{"ctl ruleEngine in a backtick block", "SecAction id:1,phase:1,pass,msg:'`\n',ctl:\nruleEngine=Off,msg:'\n`'\n"},
		{"ctl requestBodyAccess", act + "ctl:requestBodyAccess=Off\"\n"},
		{"Include", "Include /x/extra.conf\n"},
		{"Include with a dotted capital I", "İnclude /x/extra.conf\n"},
		{"SecIgnoreRuleCompilationErrors On", "SecIgnoreRuleCompilationErrors On\n"},
		{"SecIgnoreRuleCompilationErrors Off", "SecIgnoreRuleCompilationErrors Off\n"},
		{"SecAuditLog", "SecAuditLog /x\n"},
		{"SecDebugLogLevel (the start of the name decides)", "SecDebugLogLevel 0\n"},
		{"SecUploadDir", "SecUploadDir /x\n"},
		{"@inspectFile", `SecRule ARGS "@inspectFile /x" "id:5,phase:1,pass"` + "\n"},
		{"@rbl", `SecRule REMOTE_ADDR "@rbl sbl.example.net" "id:5,phase:1,pass"` + "\n"},
		{"setenv", act + "setenv:A=B\"\n"},
		{"setenv split by a continuation", act + "set\\\nenv:A=B\"\n"},
		{"ctl requestBodyLimit", act + "ctl:requestBodyLimit=1\"\n"},
		{"open continuation", "SecRuleEngine On\nSecAction \"id:1,phase:1,pass\" \\"},
		{"open backtick", "SecDataset x `\na\n"},
		{"line over 64 KiB", act + "msg:'" + strings.Repeat("a", 70000) + "'\"\n"},
	}
	for _, c := range reject {
		t.Run("reject/"+c.name, func(t *testing.T) {
			if err := checkRules(c.rules); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Accepted: a comment line has no effect in Coraza, the engine and limit
	// directives are replaced by the reserved ones, the file operators are
	// stopped by the root of newWAF, and the other rows hold none of what the
	// guards look for.
	accept := []struct{ name, rules string }{
		{"base rules", baseRules},
		{"comment line", "# " + act + "ctl:ruleEngine=Off\"\n"},
		{"comment line in a continuation", act + "\\\n# ctl:ruleEngine=Off\npass\"\n"},
		{"engine and limit directives", "SecRuleEngine DetectionOnly\nSecRequestBodyLimitAction ProcessPartial\nSecRequestBodyAccess Off\nSecRequestBodyJsonDepthLimit 1024\n"},
		{"other ctl", act + "ctl:requestBodyProcessor=JSON\"\n"},
		{"word include as an argument", "SecRule ARGS \"@contains include\" \"id:5,phase:1,pass\"\n"},
		{"SecAuditEngine", "SecAuditEngine RelevantOnly\n"},
		{"@pmFromFile", "SecRule ARGS \"@pmFromFile /x/words.data\" \"id:5,phase:1,pass\"\n"},
	}
	for _, c := range accept {
		t.Run("accept/"+c.name, func(t *testing.T) {
			if err := checkRules(c.rules); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

// The rules read no file outside the bundle: newWAF gives them the root of the
// bundle, so a name that it does not hold fails the build, by an absolute name
// and by a relative one (which would be found from the working directory).
func TestNewWAFReadsNoFile(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	words := filepath.Join(t.TempDir(), "words.data")
	if err := os.WriteFile(words, []byte("attack\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, arg := range map[string]string{"absolute": words, "relative": "testdata/v0-golden.txt"} {
		_, err := newWAF(ruleBundle(`SecRule ARGS "@pmFromFile ` + arg + `" "id:5,phase:1,pass"` + "\n"))
		if err == nil || !strings.Contains(err.Error(), "file does not exist") {
			t.Errorf("%s name: %v", name, err)
		}
	}
}

// getQuery runs a GET of /?query through phase 1 and returns the interruption.
func getQuery(waf coraza.WAF, query string) *types.Interruption {
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("127.0.0.1", 1, "127.0.0.1", 2)
	tx.ProcessURI("/?"+query, "GET", "HTTP/1.1")
	it := tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	return it
}

// The rules read the data file of the bundle that sits in the directory of the
// rule file that names it, and a name that the bundle does not hold fails the
// build. (The data files have names of their own: Coraza keeps what it built
// from a data file by its name for the whole process.)
func TestNewWAFReadsBundleData(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	rule := func(id int, arg string) string {
		return fmt.Sprintf("SecRule ARGS \"@pmFromFile %s\" \"id:%d,phase:1,deny,status:403\"\n", arg, id)
	}
	waf, err := newWAF(testBundle(map[string]string{
		"crs/rules/crs-words.data": "# words\nattack\n",
		"crs/rules/crs-rule.conf":  rule(910001, "crs-words.data"),
		"rules/local-words.data":   "forbidden\n",
		"rules/local-rule.conf":    rule(910002, "local-words.data"),
	}, "crs/rules/crs-rule.conf", "rules/local-rule.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		query string
		rule  int
	}{{"q=attack", 910001}, {"q=forbidden", 910002}, {"q=fine", 0}} {
		it := getQuery(waf, c.query)
		if c.rule == 0 && it != nil || c.rule != 0 && (it == nil || it.RuleID != c.rule) {
			t.Errorf("%s: %+v", c.query, it)
		}
	}
	if _, err := newWAF(ruleBundle(rule(910003, "missing-words.data"))); err == nil || !strings.Contains(err.Error(), "file does not exist") {
		t.Fatalf("a data file that the bundle does not hold: %v", err)
	}
}

// Coraza panics on SecRuleRemoveByMsg after a SecMarker (the msg of a marker is
// empty). newWAF returns a fixed error, so the start fails with exit 11.
func TestNewWAFPanicIsError(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	waf, err := newWAF(ruleBundle("SecMarker X\nSecRuleRemoveByMsg x\n"))
	if waf != nil || err == nil || err.Error() != "the rules made the WAF build panic" {
		t.Fatalf("%v %v", waf, err)
	}
}

func TestCheckMarkers(t *testing.T) {
	skipper := func(name string) string {
		return fmt.Sprintf(`SecRule REQUEST_METHOD "@streq GET" "id:1,phase:1,pass,skipAfter:%s"`+"\n", name)
	}
	const noMarker = "skipAfter names no marker after it"
	const unreadable = "a skipAfter or SecMarker cannot be read"
	rows := []struct {
		name  string
		files []string // the rule files, in the order of load
		want  string   // "": accepted; else a part of the error
		in    int      // the number of the file that the error names
	}{
		{name: "form of the rule set", files: []string{skipper("END-X") + "SecMarker \"END-X\"\n"}},
		{name: "marker in a later file", files: []string{skipper("X"), "SecMarker X\n"}},
		{name: "no marker", files: []string{skipper("NOWHERE")}, want: noMarker, in: 1},
		{name: "marker before", files: []string{"SecMarker X\n" + skipper("X")}, want: noMarker, in: 1},
		{name: "skipAfter in SecDefaultAction", files: []string{`SecDefaultAction "phase:1,log,pass,skipAfter:X"` + "\nSecMarker X\n"}, want: "skipAfter in SecDefaultAction is not allowed", in: 1},
		{name: "SecMarker with two spaces", files: []string{skipper("X") + "SecMarker  X\n"}, want: unreadable, in: 1},
		{name: "skipAfter key with U+212A", files: []string{strings.Replace(skipper("X"), "skipAfter", "s\u212aipAfter", 1) + "SecMarker X\n"}, want: unreadable, in: 1},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{}
			var load []string
			for i, text := range c.files {
				p := fmt.Sprintf("rules/f%d.conf", i+1)
				files[p] = text
				load = append(load, p)
			}
			p, err := checkMarkers(testBundle(files, load...))
			if c.want == "" {
				if err != nil || p != "" {
					t.Fatalf("rejected at %q: %v", p, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want a part %q", err, c.want)
			}
			if want := fmt.Sprintf("rules/f%d.conf", c.in); p != want {
				t.Fatalf("stopped at %q, want %q", p, want)
			}
		})
	}
}
