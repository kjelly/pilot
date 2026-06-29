package ansible

import (
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// FileDiff is one parsed file-level diff from `ansible-playbook --diff`.
// The LLM and human can read this directly without parsing color codes
// or knowing the module boundary format.
//
// Field shapes match what most LLM agents already understand:
//   - Path: absolute or playbook-relative path
//   - Before: file content before the change (may be empty for new files)
//   - After: file content after the change (may be empty for deletes)
//   - IsNew, IsDeleted, IsSensitive flag the obvious cases.
//   - UnifiedDiff: the raw unified diff fragment, for humans who want
//     to see context.
type FileDiff struct {
	Path        string `json:"path"`
	Before      string `json:"before,omitempty"`
	After       string `json:"after,omitempty"`
	IsNew       bool   `json:"is_new,omitempty"`
	IsDeleted   bool   `json:"is_deleted,omitempty"`
	IsSensitive bool   `json:"is_sensitive,omitempty"`
	// UnifiedDiff is the raw `--- before\n+++ after\n@@ ... @@` block
	// as emitted by ansible-playbook. Useful for humans reviewing
	// approval; the LLM generally only needs Before/After.
	UnifiedDiff string `json:"unified_diff,omitempty"`
}

// DiffSummary is what tools/agent/loop consume. It bundles the parsed
// per-file diffs with totals and the raw stdout/stderr for debugging.
//
// Sensitive files (ssh keys, shadow, sudoers, etc.) are detected by
// path prefix; their Before/After is replaced by a redacted marker.
type DiffSummary struct {
	Diffs       []FileDiff `json:"diffs"`
	FilesTotal  int        `json:"files_total"`
	FilesNew    int        `json:"files_new"`
	FilesChanged int       `json:"files_changed"`
	FilesDeleted int       `json:"files_deleted"`
	FilesSensitive int     `json:"files_sensitive"`
	Truncated   bool       `json:"truncated"`
	Raw         string     `json:"raw,omitempty"`
}

const (
	diffMarker     = "--- before"
	diffMarkerAlt  = "+++ after"
	diffMaxFiles   = 64   // hard cap on files we extract
	diffMaxFileLen = 4096 // hard cap per file body (before/after)
)

// sensitivePathPrefixes is the list of path prefixes whose content we
// MUST NOT echo back to the LLM (or to the proposal YAML the user sees
// in TTY) without redaction. The check is intentionally conservative;
// false positives (we mark an innocuous file sensitive) are fine.
var sensitivePathPrefixes = []string{
	"/etc/shadow",
	"/etc/shadow-",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/ssh/ssh_host_",
	"/etc/ssh/ssh_host_dsa_key",
	"/etc/ssh/ssh_host_ecdsa_key",
	"/etc/ssh/ssh_host_ed25519_key",
	"/etc/ssh/ssh_host_rsa_key",
	"/root/.ssh/id_",
	"/home/*/.ssh/id_",
	"/home/*/.ssh/authorized_keys",
	"/home/*/.aws/credentials",
	"/home/*/.gnupg/",
	"/var/log/auth.log",
	"/var/log/secure",
	"/proc/",
	"/sys/",
}

// ParseDiff parses `ansible-playbook --check --diff` stdout into a
// DiffSummary. The parsing is intentionally lenient: ansible's diff
// format varies across versions and modules, so we tolerate extra
// whitespace and missing markers. Anything we can't classify becomes
// part of the raw buffer.
func ParseDiff(stdout string) DiffSummary {
	s := DiffSummary{Raw: stdout}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)

	var current *FileDiff
	flush := func() {
		if current == nil {
			return
		}
		s.Diffs = append(s.Diffs, *current)
		current = nil
	}
	var beforeLines, afterLines []string
	var inDiff bool

	flushFile := func() {
		if current == nil {
			return
		}
		current.Before = strings.Join(beforeLines, "\n")
		current.After = strings.Join(afterLines, "\n")
		// Redact sensitive file contents.
		if isSensitivePath(current.Path) {
			current.IsSensitive = true
			current.Before = "[REDACTED: sensitive file]"
			current.After = "[REDACTED: sensitive file]"
		}
		// Cap body length.
		if len(current.Before) > diffMaxFileLen {
			current.Before = current.Before[:diffMaxFileLen] + "\n... [truncated]"
		}
		if len(current.After) > diffMaxFileLen {
			current.After = current.After[:diffMaxFileLen] + "\n... [truncated]"
		}
		flush()
		beforeLines = nil
		afterLines = nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		// Diff block markers: ansible prints either:
		//   "--- before\n+++ after\n@@ ... @@\n...content..."
		// or per-file "TASK [name]" headers with diff blocks below.
		if strings.HasPrefix(trimmed, diffMarker) {
			inDiff = true
			flushFile()
			if len(s.Diffs) >= diffMaxFiles {
				s.Truncated = true
				continue
			}
			current = &FileDiff{}
			// Extract path from "--- before: /path/to/file" or "--- /path/to/file"
			if idx := strings.Index(trimmed, "before:"); idx >= 0 {
				current.Path = extractPath(trimmed[idx+7:])
			} else if idx := strings.Index(trimmed, "before "); idx >= 0 {
				current.Path = extractPath(trimmed[idx+7:])
			} else if len(trimmed) > 4 {
				p := extractPath(trimmed[4:])
				if p != "before" && p != "" {
					current.Path = p
				}
			}
			continue
		}
		if strings.HasPrefix(trimmed, diffMarkerAlt) {
			// For new files, before path is /dev/null; try extracting from after marker
			if current != nil && (current.Path == "" || current.Path == "/dev/null" || strings.Contains(current.Path, "dev/null")) {
				if idx := strings.Index(trimmed, "after:"); idx >= 0 {
					current.Path = extractPath(trimmed[idx+6:])
				} else if idx := strings.Index(trimmed, "after "); idx >= 0 {
					current.Path = extractPath(trimmed[idx+6:])
				} else if len(trimmed) > 4 {
					p := extractPath(trimmed[4:])
					if p != "after" && p != "" {
						current.Path = p
					}
				}
			}
			continue
		}
		if !inDiff {
			continue
		}
		if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") {
			continue
		}
		// First non-marker line is usually the path.
		if current != nil && current.Path == "" {
			if !strings.HasPrefix(trimmed, "@@") {
				current.Path = extractPath(trimmed)
			}
			current.UnifiedDiff = line + "\n"
			continue
		}
		if current == nil {
			continue
		}
		current.UnifiedDiff += line + "\n"
		// Approximate + vs - line split (lines starting with '+' are
		// after, '-' are before). Unified diff doesn't always carry
		// those prefixes from ansible's output, but when it does we
		// capture both sides.
		switch {
		case strings.HasPrefix(line, "+"):
			afterLines = append(afterLines, strings.TrimPrefix(line, "+"))
		case strings.HasPrefix(line, "-"):
			beforeLines = append(beforeLines, strings.TrimPrefix(line, "-"))
		default:
			// Context line: add to both sides.
			beforeLines = append(beforeLines, line)
			afterLines = append(afterLines, line)
		}
	}
	flushFile()

	// Tally counts.
	for _, d := range s.Diffs {
		s.FilesTotal++
		switch {
		case d.IsNew:
			s.FilesNew++
		case d.IsDeleted:
			s.FilesDeleted++
		default:
			s.FilesChanged++
		}
		if d.IsSensitive {
			s.FilesSensitive++
		}
	}
	return s
}

// extractPath pulls a path out of a line. ansible's diff often wraps
// paths in `path/to/file:` form. Fall back to the whole line.
func extractPath(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	// Handle "path:" (ansible uses trailing colon for many modules)
	line = strings.TrimSuffix(line, ":")
	// Strip any leading diff prefix
	for _, p := range []string{"+++ ", "--- "} {
		line = strings.TrimPrefix(line, p)
	}
	if strings.HasPrefix(line, "/") {
		return line
	}
	if abs, err := filepath.Abs(line); err == nil {
		return abs
	}
	return line
}

// isSensitivePath returns true for any path under one of the
// sensitive prefixes (literal or with a glob segment).
func isSensitivePath(path string) bool {
	if path == "" {
		return false
	}
	// Normalize: strip trailing slash, lowercase.
	path = strings.TrimSuffix(path, "/")
	for _, prefix := range sensitivePathPrefixes {
		// Handle glob prefix like "/home/*/.ssh/id_".
		if strings.Contains(prefix, "*") {
			re := globToRegex(prefix)
			if re != nil && re.MatchString(path) {
				return true
			}
			continue
		}
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

var globCache = map[string]*regexp.Regexp{}

func globToRegex(glob string) *regexp.Regexp {
	if re, ok := globCache[glob]; ok {
		return re
	}
	// Convert "/*/ " → /[^/]+/
	// Escape other regex meta.
	var sb strings.Builder
	sb.WriteString("^")
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			sb.WriteString("[^/]+")
		case '?':
			sb.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '\\':
			sb.WriteString("\\")
			sb.WriteByte(c)
		default:
			sb.WriteByte(c)
		}
	}
	re, err := regexp.Compile(sb.String())
	if err != nil {
		globCache[glob] = nil
		return nil
	}
	globCache[glob] = re
	return re
}

// RenderMarkdown renders a DiffSummary as a small markdown block
// suitable for the proposal preview. Sensitive files are clearly
// marked as REDACTED.
func (s DiffSummary) RenderMarkdown() string {
	if s.FilesTotal == 0 {
		return "(ansible --check produced no diff; the playbook would be a no-op)"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "**Diff summary:** %d files changed (%d new, %d modified, %d deleted)", s.FilesTotal, s.FilesNew, s.FilesChanged-s.FilesNew, s.FilesDeleted)
	if s.FilesSensitive > 0 {
		fmt.Fprintf(&sb, "; %d sensitive (redacted)", s.FilesSensitive)
	}
	sb.WriteString("\n\n")
	for _, d := range s.Diffs {
		marker := "modified"
		switch {
		case d.IsNew:
			marker = "new"
		case d.IsDeleted:
			marker = "deleted"
		}
		fmt.Fprintf(&sb, "### `%s` (%s)\n", d.Path, marker)
		if d.IsSensitive {
			sb.WriteString("_contents redacted (sensitive path)_\n\n")
			continue
		}
		if d.Before != "" {
			fmt.Fprintf(&sb, "**Before:**\n```\n%s\n```\n\n", d.Before)
		}
		if d.After != "" {
			fmt.Fprintf(&sb, "**After:**\n```\n%s\n```\n\n", d.After)
		}
	}
	if s.Truncated {
		sb.WriteString("\n_... truncated (more than 64 files affected)_\n")
	}
	return sb.String()
}
