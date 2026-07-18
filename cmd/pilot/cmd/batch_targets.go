package cmd

// Batch-target helpers shared by `pilot vm-target run --from-stdin/--discover`.
// Extracted from the (removed 2026-07-17) `pilot run` agent executor — the
// target-list parsing is deterministic and stays; the LLM loop went away.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// playbookTarget is a single playbook to run, possibly with overrides.
// All optional fields are pointer-typed (or omitempty) so that JSON
// Lines that pre-date this struct keep working: an absent field
// decodes to the zero value and the corresponding ansible-playbook
// flag is simply not added.
type playbookTarget struct {
	Playbook string `json:"playbook"`

	// Host targeting
	Inventory string `json:"inventory,omitempty"`
	Limit     string `json:"limit,omitempty"`

	// Tag / var selection
	Tags         []string       `json:"tags,omitempty"`
	SkipTags     []string       `json:"skip_tags,omitempty"`
	ExtraVars    map[string]any `json:"extra_vars,omitempty"`
	RawExtraVars string         `json:"extra_vars_raw,omitempty"`

	// Privilege / connection
	Become     *bool  `json:"become,omitempty"`
	Forks      *int   `json:"forks,omitempty"`
	User       string `json:"user,omitempty"`
	Connection string `json:"connection,omitempty"`

	// Security / cache
	VaultPasswordFile string `json:"vault_password_file,omitempty"`
	Diff              *bool  `json:"diff,omitempty"`

	// Execution control
	Timeout    *int  `json:"timeout,omitempty"`
	FlushCache *bool `json:"flush_cache,omitempty"`
}

func indentString(s string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

// readTargetsFromStdin reads playbook paths from stdin. Auto-detects
// JSON Lines if the first non-empty line starts with '{'. Empty lines
// and lines starting with '#' are ignored.
//
// defaultInventory / defaultLimit are the env- or CLI-fallback values
// used for plain-path lines; JSON lines keep their per-line overrides
// and only inherit these when their inventory/limit is empty.
func readTargetsFromStdin(defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no input on stdin")
	}

	// Auto-detect JSON vs plain paths
	if strings.HasPrefix(lines[0], "{") {
		return parseJSONLines(lines, defaultInventory, defaultLimit)
	}
	return parsePlainLines(lines, defaultInventory, defaultLimit)
}

func parsePlainLines(lines []string, defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	var out []playbookTarget
	for _, line := range lines {
		// Expand globs
		matches, err := filepath.Glob(line)
		if err != nil {
			return nil, fmt.Errorf("bad glob %q: %w", line, err)
		}
		if len(matches) == 0 {
			// Not a glob and file doesn't exist; treat as literal
			matches = []string{line}
		}
		for _, m := range matches {
			out = append(out, playbookTarget{
				Playbook:  m,
				Inventory: defaultInventory,
				Limit:     defaultLimit,
			})
		}
	}
	return out, nil
}

func parseJSONLines(lines []string, defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	var out []playbookTarget
	for _, line := range lines {
		var t playbookTarget
		if err := json.Unmarshal([]byte(line), &t); err != nil {
			return nil, fmt.Errorf("invalid JSON line %q: %w", line, err)
		}
		if t.Playbook == "" {
			return nil, fmt.Errorf("JSON line missing 'playbook': %q", line)
		}
		if t.Inventory == "" {
			t.Inventory = defaultInventory
		}
		if t.Limit == "" {
			t.Limit = defaultLimit
		}
		out = append(out, t)
	}
	return out, nil
}

// discoverTargets handles --discover. If the input looks like a glob
// (contains *, ?, [) it's expanded; otherwise if it's a directory,
// all *.yml and *.yaml files under it are listed; otherwise treated
// as a literal file path.
//
// defaultInventory / defaultLimit are applied to every discovered
// target (same semantics as positional mode).
func discoverTargets(pattern, defaultInventory, defaultLimit string) ([]playbookTarget, error) {
	if hasGlobMeta(pattern) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("bad glob: %w", err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("glob %q matched no files", pattern)
		}
		return toTargets(matches, defaultInventory, defaultLimit), nil
	}
	// Directory or file
	info, err := os.Stat(pattern)
	if err != nil {
		return nil, fmt.Errorf("--discover %q: %w", pattern, err)
	}
	if info.IsDir() {
		entries, err := os.ReadDir(pattern)
		if err != nil {
			return nil, err
		}
		var matches []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".yml" || ext == ".yaml" {
				matches = append(matches, filepath.Join(pattern, e.Name()))
			}
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no *.yml/*.yaml files found in %q", pattern)
		}
		return toTargets(matches, defaultInventory, defaultLimit), nil
	}
	// Single file
	return []playbookTarget{{Playbook: pattern, Inventory: defaultInventory, Limit: defaultLimit}}, nil
}

func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func toTargets(paths []string, defaultInventory, defaultLimit string) []playbookTarget {
	out := make([]playbookTarget, 0, len(paths))
	for _, p := range paths {
		out = append(out, playbookTarget{
			Playbook:  p,
			Inventory: defaultInventory,
			Limit:     defaultLimit,
		})
	}
	return out
}
