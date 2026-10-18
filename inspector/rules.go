package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/corazawaf/coraza/v3"
)

// withoutPath drops the path of an *os.PathError, so that the start-up
// diagnostic does not print where the bundle directory is.
func withoutPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// reservedDirectives follow the operator's rules in a separate WithDirectives
// call. Coraza parses every call apart from the others (no continuation
// or backtick state is carried over), and a later SecRuleEngine,
// SecRequestBodyAccess, SecRequestBodyLimitAction or
// SecRequestBodyJsonDepthLimit replaces an earlier one.
// So the engine is On, the body is accessible, a body over the limit is
// rejected and a JSON body nests at most 64 levels, whatever the operator's
// rules or a recommended configuration set (the recommended one sets 1024,
// and the JSON processor reads the nested parts of a body again at every
// level, so a deep body costs much more than a flat one).
// The last SecRuleEngine On also avoids the switch of the body limit action to
// ProcessPartial that NewWAF makes for DetectionOnly. A parse failure of the
// body (a JSON body nested deeper than the limit is one), a dropped argument
// and an unparsable URI become a block of phase 2.
// Ids 4000001 to 4000003 are reserved for these rules (4000010 and 4000011 for
// the rules of detectBegin and detectEnd). The start path rejects
// SecIgnoreRuleCompilationErrors (checkRules) before newWAF, so a rule of the
// operator with one of these ids stops NewWAF instead of displacing a reserved rule
// silently. The rules can still be skipped at run time (allow, skipAfter,
// ctl:ruleRemoveById), so the owner reads the flags itself before a phase 2
// Continue (requestComplete). t:none keeps the rules independent of a default
// transformation (v3.8.1 refuses one in SecDefaultAction anyway).
const reservedDirectives = `SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 64
SecRule REQBODY_ERROR "!@eq 0" "id:4000001,phase:2,t:none,deny"
SecRule ARGUMENTS_LIMIT_REACHED "!@eq 0" "id:4000002,phase:2,t:none,deny"
SecRule URI_PARSE_ERROR "!@eq 0" "id:4000003,phase:2,t:none,deny"
`

// A bundle that only detects (detect of the bundle) puts two rules around the
// files of the operator, each in a WithDirectives of its own like the reserved
// directives. detectBegin runs first in phase 1 and makes the engine of the
// transaction DetectionOnly: a rule of the operator that would block keeps its
// first match in the transaction (DetectionOnlyInterruption) and the request
// goes on. detectEnd runs after the rules of the operator in phase 2 and makes
// the engine On again, so the reserved rules that follow block. The engine of
// the WAF stays On (see reservedDirectives), so the limit of the body rejects
// as before. A rule of the operator can still remove or skip these two, so the
// owner reads the matched rules before a phase 2 Continue (detectionOf). The
// two ids are the ones in the two texts.
const (
	detectBeginID = 4000010
	detectEndID   = 4000011
	detectBegin   = `SecAction "id:4000010,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"` + "\n"
	detectEnd     = `SecAction "id:4000011,phase:2,pass,nolog,ctl:ruleEngine=On"` + "\n"
)

// locateBudget bounds the search of failingFile. The process that starts the
// inspector waits a limited time for the HELLO; a search that outlasts it would
// end with the process killed, not with exit 11 and this diagnostic.
const locateBudget = 2 * time.Second

// newWAF builds the WAF from the bundle: the rule files of load in their
// order (inside detectBegin and detectEnd for a bundle that only detects), then
// the reserved directives. Coraza reads the files while it builds
// the WAF only, so the bundle lets go of the bytes when newWAF returns. The
// error of Coraza does not name a file, so when the build fails the error
// starts with the path of the file that failingFile finds, if any.
func newWAF(b *bundle) (coraza.WAF, error) {
	defer func() { b.files = nil }()
	waf, err := buildWAF(b.files, b.load, b.detect)
	if err != nil {
		if p := failingFile(b.files, b.load, b.detect, locateBudget); p != "" {
			err = fmt.Errorf("%s: %w", p, err)
		}
		return nil, err
	}
	return waf, nil
}

// buildWAF builds the WAF from the files of load, in their order, then the
// reserved directives; with detect, detectBegin comes before the files and
// detectEnd after them. The rules get the files as their root (bundleFS):
// without a root Coraza reads files from the operating system, and the root is
// set before any rule is read. Every rule file is read through that root, one
// call each, so Coraza closes its continuation and backtick state at the end of
// every file, as checkRules assumes. A panic inside Coraza (SecRuleRemoveByMsg
// after a SecMarker is one) becomes a fixed error, so the start fails for good
// with exit 11 and not with the exit code 2 of a panic; the panic value is
// dropped.
func buildWAF(files map[string][]byte, load []string, detect bool) (waf coraza.WAF, err error) {
	defer func() {
		if recover() != nil {
			waf, err = nil, errors.New("the rules made the WAF build panic")
		}
	}()
	cfg := coraza.NewWAFConfig().WithRootFS(bundleFS{files: files})
	if detect {
		cfg = cfg.WithDirectives(detectBegin)
	}
	for _, p := range load {
		cfg = cfg.WithDirectivesFromFile(p)
	}
	if detect {
		cfg = cfg.WithDirectives(detectEnd)
	}
	return coraza.NewWAF(cfg.WithDirectives(reservedDirectives))
}

// failingFile returns the first file of load that makes the build fail: it
// builds again with load[:i], from none to all, and the first build that fails
// names load[i-1]. Every build has the same detect as the one that failed, so
// the rules around the files are in the search. It returns "" when the build
// fails with no file (the reserved directives alone, for example when TMPDIR
// cannot be written), when every build succeeds, and when the search is not
// finished within budget.
func failingFile(files map[string][]byte, load []string, detect bool, budget time.Duration) string {
	start := time.Now()
	for i := 0; i <= len(load); i++ {
		if time.Since(start) >= budget {
			return ""
		}
		if _, err := buildWAF(files, load[:i], detect); err != nil {
			if i == 0 {
				return ""
			}
			return load[i-1]
		}
	}
	return ""
}

// checkRules is the start-up guard for one rule file of the operator. A ctl
// action can switch the rule engine or the request body access of one
// transaction (DetectionOnly never interrupts, so a match would read as Allow),
// Include reads a file that this guard does not run on, and with
// SecIgnoreRuleCompilationErrors On a rule that fails to build (for example
// one with a duplicate id) is dropped silently: a deny rule of the operator
// can be missing, and nothing added after the operator's rules can bring it
// back. checkRules rejects rules that may contain any of the three.
//
// It also rejects what lets a rule reach outside the process or change the
// body limit of a transaction. A directive whose name starts with
// SecAuditLog, SecDebugLog or SecUpload creates or writes files, sends the
// audit log to a remote server or changes where uploads are kept.
// @inspectFile starts a program, @rbl asks a DNS server, setenv changes the
// environment of the whole process, and ctl:requestBodyLimit sets the body
// limit of one transaction. The operators that read a file (@pmFromFile,
// @pmf, @ipMatchFromFile, @ipMatchF and @validateSchema) are not rejected
// here: newWAF gives the rules a root that holds the files of the bundle only,
// so a rule that names any other file fails NewWAF.
//
// It is a textual over-approximation, not a SecLang parser. False rejects are
// accepted: a rejected text may be harmless in Coraza, for example the ctl
// name inside the argument of an operator or a spelling that Coraza would not
// read as a ctl action. SecIgnoreRuleCompilationErrors is rejected whatever
// its argument, Off (Coraza's default) too: telling On from Off would need a
// parser of the argument (case, quotes, continuation), and a later occurrence
// of the directive replaces an earlier one. Rejecting every argument keeps the
// guard independent of how the argument is read and of the directive order.
// A directive name is matched by its start whatever its argument, so
// SecDebugLogLevel, SecUploadFileMode and SecUploadFileLimit, which have no
// effect of their own, are rejected too. The words @inspectFile, @rbl, setenv:
// and ctl:requestBodyLimit are looked for in the whole reduced text with the
// case folded, while Coraza reads operator and ctl names with their case, so
// a word that stands only in an argument or in a string such as msg is
// rejected too.
//
// The text is first reduced to its logical directives (logicalDirectives).
// Coraza removes no backslash between the directive text and the comparison of
// a ctl name (a quoted action value is unquoted, only the argument of an
// operator has \" resolved), so the ctl check does not remove backslashes.
func checkRules(rules string) error {
	logical, err := logicalDirectives(rules)
	if err != nil {
		return err
	}
	for _, l := range logical {
		first := l
		if i := strings.IndexFunc(l, unicode.IsSpace); i >= 0 {
			first = l[:i]
		}
		// Coraza cuts at an ASCII space only and compares strings.ToLower
		// (which maps U+0130 to "i"); the first unicode.IsSpace is never later.
		if strings.ToLower(first) == "include" {
			return errors.New("the Include directive is not allowed")
		}
		if strings.ToLower(first) == "secignorerulecompilationerrors" {
			return errors.New("the SecIgnoreRuleCompilationErrors directive is not allowed")
		}
		if name := strings.ToLower(first); strings.HasPrefix(name, "secauditlog") || strings.HasPrefix(name, "secdebuglog") || strings.HasPrefix(name, "secupload") {
			return errors.New("the SecAuditLog, SecDebugLog and SecUpload directives are not allowed")
		}
	}
	// Whole text, not per directive: no space, quote or line break is kept.
	text := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r), r == '\'', r == '"':
			return -1
		case 'A' <= r && r <= 'Z':
			return r + 'a' - 'A'
		}
		return r
	}, strings.Join(logical, "\n"))
	if strings.Contains(text, "ctl:ruleengine") || strings.Contains(text, "ctl:requestbodyaccess") {
		return errors.New("ctl of ruleEngine or requestBodyAccess is not allowed")
	}
	if strings.Contains(text, "@inspectfile") || strings.Contains(text, "@rbl") ||
		strings.Contains(text, "setenv:") || strings.Contains(text, "ctl:requestbodylimit") {
		return errors.New("@inspectFile, @rbl, setenv and ctl of requestBodyLimit are not allowed")
	}
	return nil
}

// logicalDirectives reduces the text of one rule file to the logical
// directives that Coraza v3.8.1 evaluates, with the same conditions in the same
// order as its parseString: the same line splitting and per-line TrimSpace, a
// line that starts with "#" is skipped (also inside a continuation or a
// backtick block), a line that ends with a backtick opens and a line that
// starts with one closes a block, and a trailing backslash joins the next line
// without a separator. Coraza silently drops a continuation that is open at the
// end and stops at a line over the Scanner limit; both are errors here. Coraza
// closes the continuation and the backtick state at the end of every file, so
// the guards run on one file at a time.
func logicalDirectives(rules string) ([]string, error) {
	sc := bufio.NewScanner(strings.NewReader(rules))
	var logical []string
	var buf strings.Builder
	inBackticks, joined := false, false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		last := len(line) - 1
		if !inBackticks && line[last] == '`' {
			inBackticks = true
		} else if inBackticks && line[0] == '`' {
			inBackticks = false
		}
		if inBackticks {
			buf.WriteString(line)
			buf.WriteByte('\n')
			continue
		}
		if line[last] == '\\' {
			buf.WriteString(line[:last])
			joined = true
			continue
		}
		buf.WriteString(line)
		logical = append(logical, buf.String())
		buf.Reset()
		joined = false
	}
	if sc.Err() != nil {
		return nil, errors.New("a line is too long")
	}
	if inBackticks || joined {
		return nil, errors.New("a continuation or a backtick block is not closed")
	}
	return logical, nil
}

var errUnreadable = errors.New("a skipAfter or SecMarker cannot be read")

// checkMarkers is the start-up guard for skipAfter, over the rule files of load
// in their order. A skipAfter whose marker does not follow it is no error in
// Coraza, neither when the WAF is built nor in a transaction: the rest of the
// phase is skipped silently, the blocking rules of the operator and of a rule
// set with it. So every skipAfter has to name a SecMarker that comes later, in
// the same file or in a later one (never in its own directive), and what cannot
// be read with certainty is rejected. It returns the path of the file where it
// stopped.
//
// It is a textual over-approximation like checkRules, on the logical
// directives of logicalDirectives. The argument of a SecMarker is read as
// Coraza reads it (markerName) and has to be a name of nameByte. Every
// "skipafter" in a directive, in any case of the ASCII letters and wherever it
// stands (a string such as msg too), has to be followed by optional ASCII white
// space, ":", optional white space, a name or a name between single quotes,
// optional white space, and then "," or a double quote or the end of the text.
// Other spellings that Coraza may read (a name between double quotes, a name of
// other bytes) are rejected, and so is every skipAfter in SecDefaultAction,
// which Coraza merges into the rules that follow, where its position is lost.
// Coraza compares action keys after strings.ToLower, which also folds U+212A to
// "k" and U+0130 to "i": a directive where that finds more "skipafter" than the
// ASCII fold does is rejected. ASCII white space is the ASCII part of
// unicode.IsSpace, the white space that Coraza trims around an action value.
// Names are compared by their bytes, as Coraza compares them.
func checkMarkers(b *bundle) (string, error) {
	type use struct {
		name, path string
		at         int
	}
	var uses []use
	markers := make(map[string]int) // name -> position of the last SecMarker of that name
	at := 0                         // position of the directive in the order of load
	for _, p := range b.load {
		logical, err := logicalDirectives(string(b.files[p]))
		if err != nil {
			return p, err
		}
		for _, l := range logical {
			at++
			first := l
			if i := strings.IndexFunc(l, unicode.IsSpace); i >= 0 {
				first = l[:i]
			}
			directive := strings.ToLower(first) // as in checkRules: Coraza compares strings.ToLower
			if directive == "secmarker" {
				m, ok := markerName(l)
				if !ok {
					return p, errUnreadable
				}
				markers[m] = at
			}
			lower, folded := strings.ToLower(l), asciiLower(l)
			if directive == "secdefaultaction" && strings.Count(lower, "skipafter") > 0 {
				return p, errors.New("skipAfter in SecDefaultAction is not allowed")
			}
			if strings.Count(lower, "skipafter") != strings.Count(folded, "skipafter") {
				return p, errUnreadable
			}
			for off := 0; ; {
				i := strings.Index(folded[off:], "skipafter")
				if i < 0 {
					break
				}
				off += i + len("skipafter")
				m, ok := skipAfterName(l[off:])
				if !ok {
					return p, errUnreadable
				}
				uses = append(uses, use{m, p, at})
			}
		}
	}
	for _, u := range uses {
		if markers[u.name] <= u.at { // no marker: 0
			return u.path, errors.New("skipAfter names no marker after it")
		}
	}
	return "", nil
}

// asciiLower folds the ASCII capitals and keeps every other byte, so an offset
// in the result is an offset in s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

const asciiSpace = " \t\n\v\f\r"

// markerName reads the name of the SecMarker directive l as Coraza does: the
// text after the first space (none: empty) is the argument; one of 3 bytes or
// more that starts and ends with a double quote loses all double quotes at both
// ends; no white space is trimmed, so "SecMarker  X" names " X", which no
// skipAfter reaches. The name has to be of nameByte.
func markerName(l string) (string, bool) {
	arg := ""
	if i := strings.IndexByte(l, ' '); i >= 0 {
		arg = l[i+1:]
	}
	if len(arg) >= 3 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		arg = strings.Trim(arg, "\"")
	}
	return arg, isName(arg)
}

// skipAfterName reads what follows the word skipafter: ":", a name or a name
// between single quotes, and then "," or a double quote or the end. The name is
// returned as written.
func skipAfterName(rest string) (string, bool) {
	rest = strings.TrimLeft(rest, asciiSpace)
	if rest == "" || rest[0] != ':' {
		return "", false
	}
	rest = strings.TrimLeft(rest[1:], asciiSpace)
	quoted := rest != "" && rest[0] == '\''
	if quoted {
		rest = rest[1:]
	}
	n := 0
	for n < len(rest) && nameByte(rest[n]) {
		n++
	}
	name := rest[:n]
	rest = rest[n:]
	if quoted {
		if rest == "" || rest[0] != '\'' {
			return "", false
		}
		rest = rest[1:]
	}
	rest = strings.TrimLeft(rest, asciiSpace)
	if name == "" || rest != "" && rest[0] != ',' && rest[0] != '"' {
		return "", false
	}
	return name, true
}

// isName reports whether s is 1 or more bytes of nameByte.
func isName(s string) bool {
	for i := 0; i < len(s); i++ {
		if !nameByte(s[i]) {
			return false
		}
	}
	return s != ""
}
