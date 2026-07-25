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

// blockScalarRe matches a bare YAML block-scalar header as a key's
// "value" — "|", "|-", "|+", ">", ">-", ">+", optionally followed by an
// explicit indentation-indicator digit (e.g. "|2"). This is the whole
// value token keyLineRe captures for a line like
// "alertmanager_config: |"; the real content lives in the indented
// lines below it, which keyLineRe's m[1]=="" requirement already
// excludes from ever being treated as their own key.
var blockScalarRe = regexp.MustCompile(`^[|>][+-]?[0-9]?$`)

// flowListRe/flowMapRe match a bare single-line YAML flow collection as a
// key's "value" — "[a, b]" or "{a: 1}". keyLineRe's (\S.*?) capture treats
// these as an ordinary scalar token exactly like blockScalarRe's case, but
// SetValue's formatValue/looksLikePlainScalar only allow bare
// alphanumeric-ish scalars — anything else gets double-quoted, so
// "editing" one of these here would turn a real YAML list/map into a YAML
// *string* (e.g. `restic_backup_paths: ["/etc"]` -> `restic_backup_paths:
// "[\"/etc\"]"`). See ListEntries/SetList for the list-editable
// replacement and FlowMapKeys for surfacing maps (no editor for those yet).
var (
	flowListRe = regexp.MustCompile(`^\[.*\]$`)
	flowMapRe  = regexp.MustCompile(`^\{.*\}$`)
)

// Entry is one editable "key: value" line, found either active or
// commented-out (i.e. shown only as an example of what could be set).
type Entry struct {
	Key         string
	Value       string
	Active      bool
	Description string // the free-text comment paragraph immediately above, if any
	Line        int    // index into the Doc's lines; pass back to SetValue/CommentOut
}

// ListEntry is one editable "key: [a, b, ...]" flow-list line — the
// list-shaped counterpart to Entry (see ListEntries/SetList).
type ListEntry struct {
	Key         string
	Values      []string
	Active      bool
	Description string
	Line        int // pass back to SetList/CommentOut
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
//
// Only top-level lines qualify — `key: value` or `# key: value` with
// no indentation before the key (nor, for comments, after the "#").
// Indented lines are never real flat vars: active ones are the body
// of a block scalar like alertmanager_config's embedded YAML, and
// commented ones are the illustrations the example files embed in
// prose (host_vars snippets, alert-rule bodies). Offering those as
// editable rows produced phantom duplicates like three
// prometheus_site_label entries, and "setting" one rewrote a line of
// documentation. A commented default is also suppressed once the same
// key is set for real (or already offered by an earlier commented
// line), so a key never appears twice in the editor.
//
// A key whose value is a bare block-scalar header (e.g.
// "alertmanager_config: |") is excluded outright, active or commented:
// SetValue only ever rewrites the single line it's given, so "editing"
// one here would replace the "key: |" line with a plain scalar while
// leaving the block's indented body stranded as orphaned raw lines
// immediately below it — corrupt YAML, not a hypothetical (reproduced
// against group_vars/alertmanager.example.yml's alertmanager_config).
// See BlockScalarKeys for surfacing these to the user instead. A key
// whose value is a bare flow list ("[a, b]") or flow map ("{a: 1}") is
// excluded the same way — SetValue would quote it into a YAML string
// instead of leaving it a list/map. Flow lists get their own editable
// ListEntries/SetList API instead; flow maps are only surfaced via
// FlowMapKeys (no editor for those yet).
func (d *Doc) Entries() []Entry {
	var out []Entry
	seen := map[string]bool{}
	activeKeys := map[string]bool{}
	for _, line := range d.lines {
		if m := keyLineRe.FindStringSubmatch(line); m != nil && m[1] == "" && m[2] == "" {
			activeKeys[m[3]] = true
		}
	}
	for i, line := range d.lines {
		m := keyLineRe.FindStringSubmatch(line)
		if m == nil || m[1] != "" {
			continue
		}
		if blockScalarRe.MatchString(m[4]) || flowListRe.MatchString(m[4]) || flowMapRe.MatchString(m[4]) {
			continue
		}
		active := m[2] == ""
		if !active {
			if len(m[2]) > 2 { // indented illustration inside a comment block
				continue
			}
			if activeKeys[m[3]] || seen[m[3]] { // the key is already offered
				continue
			}
		}
		seen[m[3]] = true
		out = append(out, Entry{
			Key:         m[3],
			Value:       unquote(m[4]),
			Active:      active,
			Description: precedingComment(d.lines, i),
			Line:        i,
		})
	}
	return out
}

// BlockScalarKeys returns the key names of every top-level, active
// "key: |"/"key: >" block-scalar header in the document — the settings
// Entries deliberately excludes because editing them here would corrupt
// the file. Callers should surface these to the user as "edit the file
// directly for this one" rather than silently omitting them.
func (d *Doc) BlockScalarKeys() []string {
	return d.keysMatching(blockScalarRe)
}

// FlowMapKeys returns the key names of every top-level, active
// "key: {a: 1}" flow-map header in the document — excluded from Entries
// for the same reason as BlockScalarKeys, but with no editor of its own
// yet (no known setting needs one); surface these as "edit the file
// directly" too.
func (d *Doc) FlowMapKeys() []string {
	return d.keysMatching(flowMapRe)
}

func (d *Doc) keysMatching(re *regexp.Regexp) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range d.lines {
		m := keyLineRe.FindStringSubmatch(line)
		if m == nil || m[1] != "" || m[2] != "" {
			continue
		}
		if re.MatchString(m[4]) && !seen[m[3]] {
			seen[m[3]] = true
			out = append(out, m[3])
		}
	}
	return out
}

// ListEntries returns every editable flow-list ("key: [a, b]") line, in
// file order — the SetList-editable counterpart to Entries, whose plain-
// scalar detection deliberately excludes these values (see Entries).
// Active/commented-default handling mirrors Entries exactly.
func (d *Doc) ListEntries() []ListEntry {
	var out []ListEntry
	seen := map[string]bool{}
	activeKeys := map[string]bool{}
	for _, line := range d.lines {
		if m := keyLineRe.FindStringSubmatch(line); m != nil && m[1] == "" && m[2] == "" && flowListRe.MatchString(m[4]) {
			activeKeys[m[3]] = true
		}
	}
	for i, line := range d.lines {
		m := keyLineRe.FindStringSubmatch(line)
		if m == nil || m[1] != "" || !flowListRe.MatchString(m[4]) {
			continue
		}
		active := m[2] == ""
		if !active {
			if len(m[2]) > 2 {
				continue
			}
			if activeKeys[m[3]] || seen[m[3]] {
				continue
			}
		}
		seen[m[3]] = true
		out = append(out, ListEntry{
			Key:         m[3],
			Values:      parseFlowList(m[4]),
			Active:      active,
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

// SetList rewrites the line at lineIdx to "<key>: [v1, v2, ...]"
// (activating it if it was previously commented out), preserving its
// original indent and key — the flow-list counterpart to SetValue.
func (d *Doc) SetList(lineIdx int, values []string) error {
	indent, _, key, err := d.splitKeyLine(lineIdx)
	if err != nil {
		return err
	}
	d.lines[lineIdx] = fmt.Sprintf("%s%s: %s", indent, key, formatList(values))
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

// formatList renders values as a single-line YAML flow sequence, quoting
// each element the same way formatValue quotes a lone scalar.
func formatList(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = formatValue(v)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// parseFlowList splits a bare "[a, b, ...]" flow-sequence body into its
// element strings, respecting quoted commas (e.g. "a, b") so an element
// value containing a comma isn't split apart.
func parseFlowList(raw string) []string {
	inner := strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return nil
	}
	var out []string
	var buf strings.Builder
	var inQuote byte
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case inQuote != 0:
			buf.WriteByte(c)
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
			buf.WriteByte(c)
		case c == ',':
			out = append(out, unquote(strings.TrimSpace(buf.String())))
			buf.Reset()
		default:
			buf.WriteByte(c)
		}
	}
	out = append(out, unquote(strings.TrimSpace(buf.String())))
	return out
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
