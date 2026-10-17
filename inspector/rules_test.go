package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func TestReadRules(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "r.conf")
	os.WriteFile(p, []byte("SecRuleEngine On\n"), 0o400)
	if b, err := readRules(p); err != nil || string(b) != "SecRuleEngine On\n" {
		t.Fatalf("%q %v", b, err)
	}
	big := filepath.Join(d, "big.conf")
	os.WriteFile(big, make([]byte, maxRulesBytes+1), 0o400)
	if _, err := readRules(big); err == nil {
		t.Error("oversized rules accepted")
	}
	exact := filepath.Join(d, "exact.conf")
	os.WriteFile(exact, make([]byte, maxRulesBytes), 0o400)
	if _, err := readRules(exact); err != nil {
		t.Errorf("rules at the limit: %v", err)
	}
	link := filepath.Join(d, "link.conf")
	os.Symlink(p, link)
	if _, err := readRules(link); err == nil {
		t.Error("symlink accepted")
	}
	if _, err := readRules(d); err == nil {
		t.Error("directory accepted")
	}
	if _, err := readRules(filepath.Join(d, "missing")); err == nil {
		t.Error("missing accepted")
	}
	// Several reads: the bytes must be exactly the file (the descriptor is
	// opened non-blocking).
	patt := filepath.Join(d, "patt.conf")
	want := bytes.Repeat([]byte("SecRuleEngine On\n"), 4000)
	os.WriteFile(patt, want, 0o400)
	if b, err := readRules(patt); err != nil || !bytes.Equal(b, want) {
		t.Errorf("multi-read rules: %d bytes, err %v", len(b), err)
	}
	// A FIFO must be rejected without waiting for a writer.
	fifo := filepath.Join(d, "r.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	res := make(chan error, 1)
	go func() { _, err := readRules(fifo); res <- err }()
	select {
	case err := <-res:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("FIFO: err %v, want the fstat rejection (not a regular file)", err)
		}
	case <-time.After(5 * time.Second):
		// Release the open that waits for a writer so no goroutine is left.
		if w, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			syscall.Close(w)
		}
		select {
		case <-res:
		case <-time.After(5 * time.Second):
		}
		t.Fatal("readRules waited on a FIFO")
	}
}

// ---- checkRules, withoutPath ----

// rawEffect builds the text with Coraza alone (no reserved directives), runs
// the headers phase and reports whether the effect that checkRules guards
// against happened: the rule engine is off ("engine"), the body access is off
// ("body"), a rule of an included file blocked the GET ("include") or, for
// "ignore", two rules with one id after the text build: Coraza reads the text
// as SecIgnoreRuleCompilationErrors On and drops the second rule (no
// transaction is run).
func rawEffect(t *testing.T, kind, rules string) bool {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	if kind == "ignore" {
		rules += dupPass + dupDeny
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\nSecRequestBodyAccess On\n" + rules))
	if kind == "ignore" {
		return err == nil
	}
	if err != nil {
		t.Fatalf("Coraza does not accept the text: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("127.0.0.1", 1, "127.0.0.1", 2)
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	it := tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	switch kind {
	case "engine":
		return tx.IsRuleEngineOff()
	case "body":
		return !tx.IsRequestBodyAccessible()
	}
	return it != nil
}

func TestCheckRules(t *testing.T) {
	inc := filepath.Join(t.TempDir(), "extra.conf")
	if err := os.WriteFile(inc, []byte("SecRule REQUEST_METHOD \"@streq GET\" \"id:77,phase:1,deny\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const act = `SecAction "id:1,phase:1,pass,`
	// Every row is rejected. A row with a kind is a spelling that Coraza v3.8.1
	// evaluates as the ctl, the Include or the SecIgnoreRuleCompilationErrors On
	// that checkRules guards against: rawEffect shows its effect in Coraza. A row
	// without a kind is either a false reject by design: Coraza gets no
	// observable effect from it, or does not read it as the directive with On
	// (Off, no argument), and telling On from Off would need a parser of the
	// argument; or a row of the name and word guards (the SecAuditLog,
	// SecDebugLog and SecUpload directives, @inspectFile, @rbl, setenv and
	// ctl:requestBodyLimit), whose effect is a file, a program, a DNS query or
	// the environment and is not run here.
	reject := []struct{ name, kind, rules string }{
		{"plain", "engine", act + "ctl:ruleEngine=Off\"\n"},
		{"DetectionOnly value (no observable effect)", "", act + "ctl:ruleEngine=DetectionOnly\"\n"},
		{"space before colon", "engine", act + "ctl :ruleEngine=Off\"\n"},
		{"space after colon", "engine", act + "ctl: ruleEngine=Off\"\n"},
		{"single quotes", "engine", act + "ctl:'ruleEngine=Off'\"\n"},
		{"no-break space", "engine", act + "ctl: ruleEngine=Off\"\n"},
		{"upper case key", "engine", act + "CTL:ruleEngine=Off\"\n"},
		{"continuation inside the name", "engine", act + "ctl:rule\\\nEngine=Off\"\n"},
		{"comment line inside a continuation", "engine", act + "ctl:rule\\\n# note\nEngine=Off\"\n"},
		{"backtick block", "engine", "SecAction id:1,phase:1,pass,msg:'`\n',ctl:\nruleEngine=Off,msg:'\n`'\n"},
		{"body access", "body", act + "ctl:requestBodyAccess=Off\"\n"},
		{"body access split", "body", act + "ctl:request\\\nBodyAccess=Off\"\n"},
		{"Include", "include", "Include " + inc + "\n"},
		{"include lower case", "include", "include " + inc + "\n"},
		{"dotted capital I", "include", "İnclude " + inc + "\n"},
		{"Include split by a continuation", "include", "Inc\\\nlude " + inc + "\n"},
		{"Include after a comment line", "include", "# note\nInclude " + inc + "\n"},
		{"SecIgnoreRuleCompilationErrors On", "ignore", "SecIgnoreRuleCompilationErrors On\n"},
		{"SecIgnoreRuleCompilationErrors Off", "", "SecIgnoreRuleCompilationErrors Off\n"},
		{"ignore errors without an argument", "", "SecIgnoreRuleCompilationErrors\n"},
		{"ignore errors with a quoted argument", "ignore", "SecIgnoreRuleCompilationErrors \"On\"\n"},
		{"ignore errors mixed case", "ignore", "secIGNORErulecompilationERRORS on\n"},
		{"ignore errors upper case", "", "SECIGNORERULECOMPILATIONERRORS OFF\n"},
		{"ignore errors dotted capital I", "ignore", "Secİgnorerulecompilationerrors On\n"},
		{"ignore errors split by a continuation", "ignore", "SecIgnoreRule\\\nCompilationErrors On\n"},
		{"ignore errors after a comment line", "ignore", "# note\nSecIgnoreRuleCompilationErrors On\n"},
		{"ignore errors after white space", "ignore", " \t SecIgnoreRuleCompilationErrors On\n"},
		{"ignore errors after rules", "", baseRules + "SecRule ARGS \"@contains a\" \"id:5,phase:1,pass\"\nSecIgnoreRuleCompilationErrors Off\n"},
		// A directive that starts with SecAuditLog, SecDebugLog or SecUpload:
		// the start of the name decides, whatever the argument.
		{"audit log", "", "SecAuditLog /x\n"},
		{"audit log type", "", "SecAuditLogType HTTPS\n"},
		{"audit log format", "", "SecAuditLogFormat JSON\n"},
		{"audit log storage dir", "", "SecAuditLogStorageDir /x\n"},
		{"audit log dir mode", "", "SecAuditLogDirMode 0700\n"},
		{"audit log file mode", "", "SecAuditLogFileMode 0600\n"},
		{"audit log parts", "", "SecAuditLogParts ABZ\n"},
		{"audit log relevant status", "", "SecAuditLogRelevantStatus ^5\n"},
		{"debug log", "", "SecDebugLog /x\n"},
		{"debug log level", "", "SecDebugLogLevel 0\n"},
		{"upload dir", "", "SecUploadDir /x\n"},
		{"upload keep files", "", "SecUploadKeepFiles On\n"},
		{"upload file mode", "", "SecUploadFileMode 0600\n"},
		{"upload file limit", "", "SecUploadFileLimit 10\n"},
		{"audit log without an argument", "", "SecAuditLog\n"},
		{"audit log mixed case", "", "secAUDITlog /x\n"},
		{"debug log upper case", "", "SECDEBUGLOG /x\n"},
		{"upload dir mixed case", "", "sEcUpLoAdDiR /x\n"},
		{"audit log dotted capital I", "", "SecAudİtLog /x\n"},
		{"audit log split by a continuation", "", "SecAudit\\\nLog /x\n"},
		{"debug log split by a continuation", "", "SecDebug\\\nLog /x\n"},
		{"upload dir split by a continuation", "", "SecUpload\\\nDir /x\n"},
		{"audit log after a comment line", "", "# note\nSecAuditLog /x\n"},
		{"audit log after white space", "", " \t SecAuditLog /x\n"},
		{"audit log after rules", "", baseRules + "SecAuditLog /x\n"},
		// @inspectFile, @rbl, setenv: and ctl:requestBodyLimit: the word decides,
		// wherever it stands in the reduced text.
		{"@inspectFile", "", `SecRule ARGS "@inspectFile /x" "id:5,phase:1,pass"` + "\n"},
		{"@inspectFile negated", "", `SecRule ARGS "!@inspectFile /x" "id:5,phase:1,pass"` + "\n"},
		{"@inspectFile after a space", "", `SecRule ARGS " @inspectFile /x" "id:5,phase:1,pass"` + "\n"},
		{"@inspectFile split by a continuation", "", "SecRule ARGS \"@inspect\\\nFile /x\" \"id:5,phase:1,pass\"\n"},
		{"@inspectFile mixed case (a false reject: operator names have a case)", "", `SecRule ARGS "@InspectFILE /x" "id:5,phase:1,pass"` + "\n"},
		{"@rbl", "", `SecRule REMOTE_ADDR "@rbl sbl.example.net" "id:5,phase:1,pass"` + "\n"},
		{"@rbl negated", "", `SecRule REMOTE_ADDR "!@rbl sbl.example.net" "id:5,phase:1,pass"` + "\n"},
		{"setenv", "", act + "setenv:A=B\"\n"},
		{"setenv with single quotes", "", act + "setenv:'A=B'\"\n"},
		{"setenv with a space before the colon", "", act + "setenv :A=B\"\n"},
		{"setenv upper case with spaces", "", act + "SETENV : A=B\"\n"},
		{"setenv with a no-break space", "", act + "setenv: A=B\"\n"},
		{"setenv split by a continuation", "", act + "set\\\nenv:A=B\"\n"},
		{"setenv in a backtick block", "", "SecAction id:1,phase:1,pass,msg:'`\n',setenv:\nA=B,msg:'\n`'\n"},
		{"ctl requestBodyLimit", "", act + "ctl:requestBodyLimit=1\"\n"},
		{"ctl requestBodyLimit with spaces", "", act + "ctl : requestBodyLimit = 1\"\n"},
		{"ctl requestBodyLimit with single quotes", "", act + "ctl:'requestBodyLimit=1'\"\n"},
		{"ctl requestBodyLimit upper case key", "", act + "CTL:requestBodyLimit=1\"\n"},
		{"ctl requestBodyLimit split by a continuation", "", act + "ctl:requestBody\\\nLimit=1\"\n"},
		{"ctl requestBodyLimit in a backtick block", "", "SecAction id:1,phase:1,pass,msg:'`\n',ctl:\nrequestBodyLimit=1,msg:'\n`'\n"},
		{"ctl requestBodyLimit mixed case (a false reject: ctl names have a case)", "", act + "ctl:REQUESTbodyLIMIT=1\"\n"},
		{"setenv after rules", "", baseRules + act + "setenv:A=B\"\n"},
		{"word setenv: in a string (a false reject)", "", "SecRule ARGS \"@contains setenv:\" \"id:5,phase:1,pass\"\n"},
		{"word @rbl in msg (a false reject)", "", act + "msg:'see @rbl'\"\n"},
	}
	for _, c := range reject {
		t.Run("reject/"+c.name, func(t *testing.T) {
			if c.kind != "" && !rawEffect(t, c.kind, c.rules) {
				t.Fatal("the text has no effect in Coraza: it does not show the need for the guard")
			}
			if err := checkRules(c.rules); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Not closed: Coraza drops a continuation silently and fails on a block.
	for name, rules := range map[string]string{
		"open continuation": "SecRuleEngine On\nSecAction \"id:1,phase:1,pass\" \\",
		"lone backslash":    "SecRuleEngine On\n\\",
		"open backtick":     "SecDataset x `\na\n",
		"line over 64 KiB":  act + "msg:'" + strings.Repeat("a", 70000) + "'\"\n",
	} {
		t.Run("reject/"+name, func(t *testing.T) {
			if err := checkRules(rules); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Accepted: the same conditions as Coraza leave a comment line without
	// effect, and the other rows hold none of what the guards look for. The
	// file operators are accepted too: the root of newWAF stops them (see
	// TestNewWAFReadsNoFile).
	accept := []struct{ name, rules string }{
		{"base rules", baseRules},
		{"comment line", "# " + act + "ctl:ruleEngine=Off\"\n"},
		{"comment line in a continuation", act + "\\\n# ctl:ruleEngine=Off\npass\"\n"},
		{"engine and limit directives", "SecRuleEngine DetectionOnly\nSecRequestBodyLimitAction ProcessPartial\nSecRequestBodyAccess Off\n"},
		{"other ctl", act + "ctl:requestBodyProcessor=JSON\"\n"},
		{"JSON depth limit (the reserved directives replace it)", "SecRequestBodyJsonDepthLimit 1024\n"},
		{"word include as an argument", "SecRule ARGS \"@contains include\" \"id:5,phase:1,pass\"\n"},
		{"word SecIgnoreRuleCompilationErrors as an argument", "SecRule ARGS \"@contains SecIgnoreRuleCompilationErrors\" \"id:5,phase:1,pass\"\n"},
		{"comment line with the ignore errors directive", "# SecIgnoreRuleCompilationErrors On\n"},
		{"comment line with a SecAuditLog directive", "# SecAuditLog /x\n"},
		{"comment line with the operators", "# SecRule ARGS \"@inspectFile /x\" \"id:5,phase:1,pass\"\n# SecRule REMOTE_ADDR \"@rbl sbl.example.net\" \"id:6,phase:1,pass\"\n"},
		{"comment line with setenv", "# " + act + "setenv:A=B\"\n"},
		{"comment line with ctl requestBodyLimit", "# " + act + "ctl:requestBodyLimit=1\"\n"},
		{"comment line in a continuation with setenv", act + "\\\n# setenv:A=B\npass\"\n"},
		{"SecDefaultAction line", "SecDefaultAction \"phase:1,log,auditlog,pass\"\n"},
		{"SecAuditEngine line (not a name that starts with SecAuditLog)", "SecAuditEngine RelevantOnly\n"},
		{"word SecAuditLog as an argument", "SecRule ARGS \"@contains SecAuditLog\" \"id:5,phase:1,pass\"\n"},
		{"@pm", "SecRule ARGS \"@pm a b\" \"id:5,phase:1,pass\"\n"},
		{"@pmFromFile (newWAF stops it)", "SecRule ARGS \"@pmFromFile /x/words.data\" \"id:5,phase:1,pass\"\n"},
		{"ctl ruleRemoveByTag", act + "ctl:ruleRemoveByTag=x\"\n"},
		{"ctl forceRequestBodyVariable", act + "ctl:forceRequestBodyVariable=On\"\n"},
	}
	for _, c := range accept {
		t.Run("accept/"+c.name, func(t *testing.T) {
			if err := checkRules(c.rules); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if strings.HasPrefix(c.name, "comment") && (rawEffect(t, "engine", c.rules) || rawEffect(t, "body", c.rules) || rawEffect(t, "ignore", c.rules)) {
				t.Fatal("a comment line had an effect in Coraza")
			}
		})
	}
}

// With the directive, Coraza builds dupText and the deny rule is gone: a
// urlencoded body that it should block is not interrupted. Its own id gives a
// block, and without the directive the duplicate id stops NewWAF.
func TestCheckRulesDroppedRule(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	post := func(rules string) *types.Interruption {
		t.Helper()
		waf, err := newWAF(rules)
		if err != nil {
			t.Fatalf("Coraza does not accept the text: %v", err)
		}
		tx := waf.NewTransaction()
		defer tx.Close()
		tx.ProcessConnection("127.0.0.1", 1, "127.0.0.1", 2)
		tx.ProcessURI("/", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		if it := tx.ProcessRequestHeaders(); it != nil {
			t.Fatalf("interrupted in phase 1: %+v", it)
		}
		if it, _, err := tx.WriteRequestBody([]byte("probe=block")); it != nil || err != nil {
			t.Fatalf("write: %+v %v", it, err)
		}
		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Fatal(err)
		}
		return it
	}
	if it := post(dupText); it != nil {
		t.Fatalf("the deny rule was not dropped: %+v", it)
	}
	if it := post(dupPass + strings.Replace(dupDeny, "9202", "9203", 1)); it == nil || it.RuleID != 9203 {
		t.Fatalf("the deny rule with its own id did not block: %+v", it)
	}
	if _, err := newWAF(dupPass + dupDeny); err == nil {
		t.Fatal("the duplicate id was accepted without the directive")
	}
	if err := checkRules(dupText); err == nil {
		t.Fatal("accepted")
	}
}

// The root of the rules answers every name with "does not exist" and never
// returns a file.
func TestNoFiles(t *testing.T) {
	for _, name := range []string{"", ".", "x", "/abs/x", "../x", "a/*.conf"} {
		f, err := noFiles{}.Open(name)
		var pe *os.PathError
		if f != nil || !errors.As(err, &pe) || pe.Op != "open" || pe.Path != name || pe.Err != os.ErrNotExist {
			t.Errorf("%q: %v %v", name, f, err)
		}
	}
}

// The rules read no file: newWAF gives them a root without files. Each row
// names a file that exists, and Coraza builds the same rule without that root,
// so the root is what stops the read; newWAF fails with the answer of the root.
// The relative name is found from the directory of the package, which is the
// directory of a test.
func TestNewWAFReadsNoFile(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	dir := t.TempDir()
	write := func(name, data string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	words := write("words.data", "attack\n")
	ips := write("ips.data", "192.0.2.1\n")
	schema := write("schema.json", "{}\n")
	rows := []struct{ name, rules string }{
		{"@pmFromFile by an absolute name", `SecRule ARGS "@pmFromFile ` + words + `" "id:5,phase:1,pass"` + "\n"},
		{"@pmFromFile by a relative name", `SecRule ARGS "@pmFromFile testdata/v0-golden.txt" "id:5,phase:1,pass"` + "\n"},
		{"@ipMatchFromFile", `SecRule REMOTE_ADDR "@ipMatchFromFile ` + ips + `" "id:5,phase:1,pass"` + "\n"},
		{"@validateSchema", `SecRule REQUEST_BODY "@validateSchema ` + schema + `" "id:5,phase:2,pass"` + "\n"},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + c.rules)); err != nil {
				t.Fatalf("Coraza does not build the rule without the root: %v", err)
			}
			_, err := newWAF(c.rules)
			if err == nil {
				t.Fatal("the rule that reads a file was built")
			}
			if !strings.Contains(err.Error(), "file does not exist") {
				t.Fatalf("not the answer of the root: %v", err)
			}
		})
	}
}

func TestWithoutPath(t *testing.T) {
	pe := &os.PathError{Op: "read", Path: "/secret/rules.conf", Err: syscall.EIO}
	if got := withoutPath(fmt.Errorf("wrapped: %w", pe)); got != syscall.EIO {
		t.Fatalf("got %v", got)
	}
	plain := errors.New("not a regular file")
	if got := withoutPath(plain); got != plain {
		t.Fatalf("got %v", got)
	}
}
