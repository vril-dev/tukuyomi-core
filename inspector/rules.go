package main

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"unicode"

	"github.com/corazawaf/coraza/v3"
)

const maxRulesBytes = 1 << 20

// readRules reads the rules file once: no symlink, a regular file, bounded
// size, and the bytes read must match the size seen by fstat.
func readRules(p string) ([]byte, error) {
	// O_NONBLOCK: opening a FIFO must not wait for a writer; the fstat check
	// below then rejects it. It does not affect reads of a regular file.
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > maxRulesBytes {
		return nil, errors.New("too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRulesBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != st.Size() {
		return nil, errors.New("size changed while reading")
	}
	return b, nil
}

// withoutPath drops the path of an *os.PathError, so that the start-up
// diagnostic does not print where the rules file is.
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
// Ids 4000001 to 4000003 are reserved for these rules. The start path rejects
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

// noFiles is the root file system of the rules: no name exists in it. Every
// file read that a rule causes (Include, and the file of @pmFromFile, @pmf,
// @ipMatchFromFile, @ipMatchF and @validateSchema) goes through the root of
// the Coraza parser, so a rule that names a file fails NewWAF, and nothing
// outside the rules file, which rules_sha256 covers, is read. (An Include
// with a glob matches nothing and reads nothing.)
type noFiles struct{}

func (noFiles) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// newWAF builds the WAF from the operator's rules and the reserved directives.
// The rules get noFiles as their root: without a root Coraza reads files from
// the operating system, and the root is set before any rule is read.
func newWAF(rules string) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(noFiles{}).WithDirectives(rules).WithDirectives(reservedDirectives))
}

// checkRules is the start-up guard for the operator's rules. A ctl action
// can switch the rule engine or the request body access of one transaction
// (DetectionOnly never interrupts, so a match would read as Allow), Include
// reads files that rules_sha256 does not cover, and with
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
// here: newWAF gives the rules a root without files, so a rule that uses one
// fails NewWAF.
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
// The text is first reduced to the logical directives that Coraza v3.8.1
// evaluates, with the same conditions in the same order as its parseString:
// the same line splitting and per-line TrimSpace, a line that starts with "#"
// is skipped (also inside a continuation or a backtick block), a line that
// ends with a backtick opens and a line that starts with one closes a block,
// and a trailing backslash joins the next line without a separator. Coraza
// silently drops a continuation that is open at the end and stops at a line
// over the Scanner limit; both are rejected here. Coraza removes no backslash
// between the directive text and the comparison of a ctl name (a quoted action
// value is unquoted, only the argument of an operator has \" resolved), so the
// ctl check does not remove backslashes.
func checkRules(rules string) error {
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
		return errors.New("a line is too long")
	}
	if inBackticks || joined {
		return errors.New("a continuation or a backtick block is not closed")
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
