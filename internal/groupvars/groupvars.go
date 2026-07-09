// Package groupvars is a line-oriented editor for the flat
// "key: value" YAML files under group_vars/*.yml (see
// group_vars/dns.example.yml, group_vars/freeipa.example.yml).
//
// These files carry most of their value as Chinese-language comments
// explaining each setting — a full YAML parse-and-re-marshal would
// throw that away. Instead Doc treats the file as a slice of raw
// lines and only ever rewrites the single line a caller asks it to,
// leaving every comment, blank line, and unrelated setting byte-for-
// byte untouched.
package groupvars

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// keyLineRe matches a (possibly comment-prefixed) "key: value" line:
// group 1 = leading indent, group 2 = "# " prefix if commented out
// (empty if active), group 3 = key, group 4 = value. It deliberately
// requires an ASCII identifier right after the optional "#" so it
// never matches a prose comment line (which in this repo always
// starts with Chinese text or a banner) or a nested block value.
var keyLineRe = regexp.MustCompile(`^(\s*)(#\s*)?([A-Za-z_][A-Za-z0-9_]*):\s+(\S.*?)\s*$`)

// Entry is one editable "key: value" line, found either active or
// commented-out (i.e. shown only as an example of what could be set).
type Entry struct {
	Key         string
	Value       string
	Active      bool
	Description string // the free-text comment paragraph immediately above, if any
	Line        int    // index into the Doc's lines; pass back to SetValue/CommentOut
}

// Doc is a group_vars file loaded for editing.
type Doc struct {
	lines []string
}

// Parse loads data for editing. It never fails — an unparseable line
// simply isn't offered as an editable Entry.
func Parse(data []byte) *Doc {
	return &Doc{lines: strings.Split(string(data), "\n")}
}

// Bytes renders the document back out, byte-identical to the input
// except for lines touched by SetValue/CommentOut.
func (d *Doc) Bytes() []byte {
	return []byte(strings.Join(d.lines, "\n"))
}

// Entries returns every editable key line, in file order.
func (d *Doc) Entries() []Entry {
	var out []Entry
	for i, line := range d.lines {
		m := keyLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, Entry{
			Key:         m[3],
			Value:       unquote(m[4]),
			Active:      m[2] == "",
			Description: precedingComment(d.lines, i),
			Line:        i,
		})
	}
	return out
}

// SetValue rewrites the line at lineIdx to "<key>: <value>" (activating
// it if it was previously commented out), preserving its original
// indent and key.
func (d *Doc) SetValue(lineIdx int, newValue string) error {
	indent, _, key, err := d.splitKeyLine(lineIdx)
	if err != nil {
		return err
	}
	d.lines[lineIdx] = fmt.Sprintf("%s%s: %s", indent, key, formatValue(newValue))
	return nil
}

// CommentOut turns an active line back into a "# key: value" comment
// (falling back to whatever built-in default the playbook uses) — a
// no-op if the line is already commented out.
func (d *Doc) CommentOut(lineIdx int) error {
	indent, hash, key, err := d.splitKeyLine(lineIdx)
	if err != nil {
		return err
	}
	if hash != "" {
		return nil
	}
	m := keyLineRe.FindStringSubmatch(d.lines[lineIdx])
	d.lines[lineIdx] = fmt.Sprintf("%s# %s: %s", indent, key, m[4])
	return nil
}

func (d *Doc) splitKeyLine(lineIdx int) (indent, hash, key string, err error) {
	if lineIdx < 0 || lineIdx >= len(d.lines) {
		return "", "", "", fmt.Errorf("groupvars: line %d out of range", lineIdx)
	}
	m := keyLineRe.FindStringSubmatch(d.lines[lineIdx])
	if m == nil {
		return "", "", "", fmt.Errorf("groupvars: line %d is not a key: value line", lineIdx)
	}
	return m[1], m[2], m[3], nil
}

// precedingComment collects the contiguous block of free-text comment
// lines directly above lines[idx], stopping at the first blank line,
// non-comment line, or another key: value declaration (active or
// commented) — so an entry's description never bleeds into a
// neighboring entry's own line or a decorative "====" banner.
func precedingComment(lines []string, idx int) string {
	var collected []string
	for i := idx - 1; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "#") || keyLineRe.MatchString(line) {
			break
		}
		collected = append(collected, trimmed)
	}
	var cleaned []string
	for i := len(collected) - 1; i >= 0; i-- {
		c := strings.TrimSpace(strings.TrimPrefix(collected[i], "#"))
		if isBannerLine(c) {
			continue
		}
		cleaned = append(cleaned, c)
	}
	return strings.Join(cleaned, "\n")
}

// isBannerLine reports whether s is a purely decorative "====...="
// section-divider line, which carries no explanatory content.
func isBannerLine(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '=' {
			return false
		}
	}
	return true
}

func unquote(raw string) string {
	if len(raw) >= 2 {
		if raw[0] == '"' && raw[len(raw)-1] == '"' {
			if s, err := strconv.Unquote(raw); err == nil {
				return s
			}
		}
		if raw[0] == '\'' && raw[len(raw)-1] == '\'' {
			return strings.ReplaceAll(raw[1:len(raw)-1], "''", "'")
		}
	}
	return raw
}

// formatValue renders v the way inventory.Generate quotes scalars:
// bare when it's an unambiguous plain scalar, double-quoted otherwise.
func formatValue(v string) string {
	if v == "" || !looksLikePlainScalar(v) {
		return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
	}
	return v
}

func looksLikePlainScalar(v string) bool {
	switch v {
	case "true", "false", "null", "~":
		return true
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return true
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r == '.' || r == '-' || r == '_' || r == '/' || r == ':':
		default:
			return false
		}
	}
	return true
}
