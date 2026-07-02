package spec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Row is one checklist entry from a spec.
type Row struct {
	ID       string // e.g. "C1", "C2.5.1"
	Category string // e.g. "file", "sysctl", "service"
	Check    string // human description
	Expected string // machine-comparable expected value
	Command  string // one-line shell command, executed on target host
	// line is the 1-based source line (used for diagnostics).
	Line int
}

// Spec is the parsed content of one verification markdown file.
type Spec struct {
	Path       string // absolute path on disk
	Title      string // "# Verification Spec — <title>"
	Version    string // `> 版本：vX.Y`
	Alignment  string // `> 對齊規範：...`
	Maintainer string
	Rows       []Row
	// Hosts are parsed from the optional `## 1. Targets` markdown
	// table (or any H2 whose body is a Hosts table). Used by
	// `Spec.GenerateInventory` to emit an ansible inventory
	// directly from the spec without an external inventory file.
	Hosts []Host
	// rawChecklist keeps the markdown table so we can re-emit it
	// in reports without reparsing.
	rawChecklist []string
}

// Parse reads a markdown spec file and returns a Spec.
func Parse(path string) (*Spec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("spec: open %s: %w", path, err)
	}
	defer f.Close()
	s, err := ParseReader(f)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(path)
	s.Path = abs
	return s, nil
}

// ParseReader parses a spec from any io.Reader. Used by tests and
// when reading specs from stdin.
func ParseReader(r io.Reader) (*Spec, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	s := &Spec{}
	state := stateNormal
	checklistHeaders := []string{}
	targetsBuf := []string{}
	targetsBase := 0
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := scanner.Text()
		switch state {
		case stateNormal:
			switch {
			case strings.HasPrefix(line, "# "):
				if s.Title == "" {
					s.Title = strings.TrimSpace(strings.TrimPrefix(line, "# "))
				}
			case strings.HasPrefix(line, "> 版本："):
				s.Version = strings.TrimSpace(strings.TrimPrefix(line, "> 版本："))
			case strings.HasPrefix(line, "> 對齊規範："):
				s.Alignment = strings.TrimSpace(strings.TrimPrefix(line, "> 對齊規範："))
			case strings.HasPrefix(line, "> 維護者："):
				s.Maintainer = strings.TrimSpace(strings.TrimPrefix(line, "> 維護者："))
			case strings.HasPrefix(line, "## 2. Checklist"):
				state = stateChecklist
			case strings.HasPrefix(line, "## "):
				// Any H2 other than Checklist may carry a Targets table.
				state = stateTargets
				targetsBuf = nil
				targetsBase = lineNo
			}
		case stateTargets:
			if strings.HasPrefix(line, "## ") {
				// Flush what we collected so far.
				if err := commitTargetsTable(s, &targetsBuf, targetsBase); err != nil {
					return nil, err
				}
				targetsBuf = nil
				// Decide the next state based on the H2 text and re-emit
				// this line by falling through to stateNormal, where the
				// outer cases will route it appropriately.
				if strings.HasPrefix(line, "## 2. Checklist") {
					state = stateChecklist
				} else {
					state = stateNormal
				}
				// Fall through: process the same line in the new state.
				goto fallthrough_process
			}
			if len(targetsBuf) == 0 && strings.TrimSpace(line) == "" {
				continue
			}
			targetsBuf = append(targetsBuf, line)
			continue
		fallthrough_process:
			_ = line
		case stateChecklist:
			if strings.HasPrefix(line, "## ") {
				state = stateNormal
				continue
			}
			if !strings.HasPrefix(line, "|") {
				continue
			}
			s.rawChecklist = append(s.rawChecklist, line)
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "|----") || strings.HasPrefix(trimmed, "| ---") {
				continue
			}
			cols := splitRow(line)
			if len(cols) < 5 {
				continue // malformed row — Lint will report
			}
			if len(checklistHeaders) == 0 {
				checklistHeaders = cols
				continue
			}
			// If the row has more than the canonical 5 columns, treat
			// the extra columns as part of the Command (the spec author
			// was forced to split because the command itself contained
			// a `|` which would otherwise terminate the markdown table
			// cell). Re-join with ` | ` so the verifier sees the
			// intended whole command.
			cmd := cols[4]
			if len(cols) > 5 {
				cmd = cols[4] + " | " + strings.Join(cols[5:], " | ")
			}
			row := Row{
				ID:       cols[0],
				Category: cols[1],
				Check:    cols[2],
				Expected: cols[3],
				Command:  stripBackticks(cmd),
				Line:     lineNo,
			}
			s.Rows = append(s.Rows, row)
		}
	}
	// Final commit: any buffer still in targetsBuf at EOF must be
	// flushed so the trailing Hosts table is not silently lost.
	if state == stateTargets && len(targetsBuf) > 0 {
		if err := commitTargetsTable(s, &targetsBuf, targetsBase); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("spec: read: %w", err)
	}
	if s.Title == "" {
		return nil, errors.New("spec: missing top-level `# Verification Spec — <title>` heading")
	}
	if len(s.Rows) == 0 {
		return nil, errors.New("spec: no checklist rows found under `## 2. Checklist`")
	}
	return s, nil
}

const (
	stateNormal = iota
	stateChecklist
	stateTargets // scanning body of a Targets markdown table
)

// splitRow splits a markdown table row "| a | b | c |" into its
// trimmed column values. Empty leading/trailing pipes are tolerated.
//
// Pipes inside single-quoted strings, double-quoted strings, or
// backslash-escaped positions are NOT treated as column separators
// (so a spec row can legitimately contain an awk regex with `|`
// in the pattern).
func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	var parts []string
	var cur strings.Builder
	inSingle, inDouble, escaped := false, false, false
	for _, c := range line {
		switch {
		case escaped:
			escaped = false
			cur.WriteRune(c)
		case c == '\\' && !inSingle:
			escaped = true
			cur.WriteRune(c)
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteRune(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteRune(c)
		case c == '|' && !inSingle && !inDouble:
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	parts = append(parts, strings.TrimSpace(cur.String()))
	return parts
}

// stripBackticks removes a single layer of surrounding backticks
// from a cell value. spec-runner.py and Lint both treat `…` and `…`
// identically.
func stripBackticks(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' {
		return s[1 : len(s)-1]
	}
	return s
}

// IDPattern matches valid spec IDs like "C1", "C2.5.1", "REQ-001".
var IDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)

// commitTargetsTable is the single place that turns a buffered
// H2-body into a Hosts slice. Errors are propagated only when the
// buffer really did look like a Targets table (had a Hostname
// header); otherwise it's metadata and we drop silently.
func commitTargetsTable(s *Spec, buf *[]string, base int) error {
	if len(*buf) == 0 {
		return nil
	}
	hosts, err := parseTargetsTable((*buf)[0], (*buf)[1:], base)
	if err != nil && hasHostnameHeader((*buf)[0]) {
		return err
	}
	if hosts != nil {
		s.Hosts = append(s.Hosts, hosts...)
	}
	return nil
}

// hasHostnameHeader is a tiny predicate so commitTargetsTable can
// decide whether to surface parse errors.
func hasHostnameHeader(line string) bool {
	if _, ok := matchInventoryHeader(splitRow(line)[0]); ok {
		return true
	}
	// regex fallback already covered by matchInventoryHeader.
	return false
}
