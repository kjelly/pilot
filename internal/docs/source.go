package docs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// ModuleDoc is the structured representation of an Ansible module
// extracted from `ansible-doc --json`.
//
// Two parallel option views are kept:
//   - RichOptions carries the full type/choices/default/required/aliases/
//     version_added/suboptions tree. The LLM chunker reads from this.
//   - Options is the legacy simplified map (name → description only).
//     Kept so any old caller that only reads the description keeps
//     compiling. Both are populated by parseSingleModule.
type ModuleDoc struct {
	Name         string `json:"name"`
	ShortDesc    string `json:"short_description"`
	Description  string `json:"description"`
	Synopsis     string `json:"-"`
	Examples     string `json:"examples"`
	Notes        string `json:"notes"`
	Requirements string `json:"requirements"`
	Category     string `json:"-"`
	Version      string `json:"-"`
	Filename     string `json:"filename"`

	RichOptions map[string]OptionDoc `json:"-"`
	Options     map[string]string    `json:"-"`
}

// OptionDoc is the structured shape of one entry under
// `doc.options.<name>` in the ansible-doc JSON output.
//
// ansible-doc is loose about types: descriptions may arrive as []string
// or string, defaults may be any JSON scalar, choices are arrays of any.
// parseOptionEntry coerces these defensively.
type OptionDoc struct {
	Name         string               `json:"-"`
	Description  string               `json:"-"`
	Type         string               `json:"type,omitempty"`
	Required     bool                 `json:"required,omitempty"`
	Default      any                  `json:"default,omitempty"`
	Choices      []any                `json:"choices,omitempty"`
	Aliases      []string             `json:"aliases,omitempty"`
	Elements     string               `json:"elements,omitempty"`
	VersionAdded string               `json:"version_added,omitempty"`
	SubOptions   map[string]OptionDoc `json:"suboptions,omitempty"`
}

// FetchAllModules invokes `ansible-doc --metadata-dump` and parses
// the result. This is the modern replacement for the deprecated
// `-t module --json` form. The optional binaryOverride lets tests
// use a mock.
func FetchAllModules(ctx context.Context, binaryOverride string) ([]ModuleDoc, error) {
	bin := binaryOverride
	if bin == "" {
		bin = "ansible-doc"
	}
	cmd := exec.CommandContext(ctx, bin, "--metadata-dump", "--no-fail-on-errors")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Some ansible versions still accept the old form; fall back.
		cmd2 := exec.CommandContext(ctx, bin, "-t", "module", "--json")
		var stdout2, stderr2 bytes.Buffer
		cmd2.Stdout = &stdout2
		cmd2.Stderr = &stderr2
		if err2 := cmd2.Run(); err2 == nil {
			return ParseModuleJSON(stdout2.Bytes())
		}
		return nil, fmt.Errorf("ansible-doc failed: %w (stderr: %s)", err, stderr.String())
	}
	return ParseModuleJSON(stdout.Bytes())
}

// ParseModuleJSON parses the JSON output of `ansible-doc --json`.
// The structure is:
//
//	{
//	  "<module_name>": {
//	    "doc": { ... module doc ... },
//	    "filename": "...",
//	    "category": "...",
//	    ...
//	  },
//	  ...
//	}
func ParseModuleJSON(data []byte) ([]ModuleDoc, error) {
	// ansible-core 2.18+ uses --metadata-dump which wraps everything under
	// an "all" envelope keyed by plugin type:
	//	{ "all": { "module": { "<module>": { doc: {...} } } } }
	// Older ansible-doc --json returned a flat dict. Detect and unwrap the
	// new envelope so we get back the legacy shape.
	// Probe for the ansible-core 2.18+ envelope shape:
	//   { "all": { "module": { "<plugin>": { doc: {...} } } } }
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err == nil {
		if _, ok := probe["all"]; ok {
			// ansible-core 2.18+ metadata-dump shape:
			//   { "all": { "<category>": { "<plugin>": { doc, examples, metadata, return } } } }
			// Normalise every entry under "module" to the legacy --json shape
			// (filename/category/collection at top level, examples inside doc)
			// so the unmarshal below Just Works.
			var wrapped struct {
				All map[string]map[string]struct {
					Doc      map[string]json.RawMessage `json:"doc"`
					Examples json.RawMessage            `json:"examples"`
					Metadata map[string]json.RawMessage `json:"metadata"`
				} `json:"all"`
			}
			if err := json.Unmarshal(data, &wrapped); err == nil {
				if mods, ok := wrapped.All["module"]; ok {
					flattened := make(map[string]map[string]any, len(mods))
					for name, entry := range mods {
						// Ensure doc is a real object (might be missing or wrong type).
						doc := entry.Doc
						if doc == nil {
							doc = map[string]json.RawMessage{}
						}
						// Examples: prefer top-level (more reliable in metadata-dump);
						// fall back to doc.examples.
						docCopy := make(map[string]json.RawMessage, len(doc)+1)
						for k, v := range doc {
							docCopy[k] = v
						}
						if len(entry.Examples) > 0 && string(entry.Examples) != "null" {
							docCopy["examples"] = entry.Examples
						} else if v, ok := doc["examples"]; ok {
							docCopy["examples"] = v
						}
						// Build the legacy-shaped entry: filename/category/collection
						// at the top level, plus the doc with examples merged in.
						legacyEntry := map[string]any{
							"doc":      docCopy,
							"category": "module",
						}
						if v, ok := doc["filename"]; ok {
							legacyEntry["filename"] = jsonString(v)
						}
						if v, ok := doc["collection"]; ok {
							legacyEntry["collection"] = jsonString(v)
						} else if entry.Metadata != nil {
							if v, ok := entry.Metadata["collection"]; ok {
								legacyEntry["collection"] = jsonString(v)
							}
						}
						flattened[name] = legacyEntry
					}
					if re, err := json.Marshal(flattened); err == nil {
						data = re
					}
				}
			}
		}
	}

	var raw map[string]struct {
		Doc        json.RawMessage `json:"doc"`
		Filename   string          `json:"filename"`
		Category   string          `json:"category"`
		Collection string          `json:"collection"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse ansible-doc JSON: %w", err)
	}
	out := make([]ModuleDoc, 0, len(raw))
	for name, entry := range raw {
		doc := parseSingleModule(name, entry.Doc)
		doc.Filename = entry.Filename
		doc.Category = entry.Category
		// collection is part of "version" naming
		if entry.Collection != "" {
			doc.Version = entry.Collection
		}
		out = append(out, doc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// jsonString takes a json.RawMessage that is expected to encode a string
// and returns the unquoted string. If unquoting fails it returns the raw
// payload verbatim so the caller still gets something useful.
func jsonString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// parseSingleModule unpacks a single module's "doc" subdocument.
// ansible-doc is flexible about types (string, list, dict), so we
// defensively coerce. Populates both RichOptions and the legacy
// Options map.
func parseSingleModule(name string, raw json.RawMessage) ModuleDoc {
	m := ModuleDoc{
		Name:        name,
		Options:     map[string]string{},
		RichOptions: map[string]OptionDoc{},
	}
	if len(raw) == 0 {
		return m
	}
	// First parse into a free-form map.
	var fmap map[string]any
	if err := json.Unmarshal(raw, &fmap); err != nil {
		return m
	}
	m.ShortDesc = stringOf(fmap["short_description"])
	m.Description = stringOf(fmap["description"])
	m.Synopsis = stringOf(fmap["synopsis"])
	m.Examples = stringOf(fmap["examples"])
	m.Notes = stringOf(fmap["notes"])
	m.Requirements = stringOf(fmap["requirements"])
	if opts, ok := fmap["options"].(map[string]any); ok {
		for k, v := range opts {
			if sub, ok := v.(map[string]any); ok {
				m.RichOptions[k] = parseOptionEntry(k, sub)
				// Legacy view: just the description string.
				m.Options[k] = stringOf(sub["description"])
			}
		}
	}
	return m
}

// parseOptionEntry walks a single option's value (a map under
// `doc.options.<name>`) and pulls every field the LLM chunker needs.
// Recurses into suboptions so nested params (e.g. `validate.remote_addr`)
// get full structured metadata too.
func parseOptionEntry(name string, raw map[string]any) OptionDoc {
	o := OptionDoc{Name: name}
	if v, ok := raw["type"].(string); ok {
		o.Type = v
	}
	if v, ok := raw["required"].(bool); ok {
		o.Required = v
	}
	if v, ok := raw["description"]; ok {
		o.Description = stringOf(v)
	}
	if v, ok := raw["default"]; ok {
		// Defaults can be nil/0/""/false legitimately; keep them.
		if v != nil {
			o.Default = v
		}
	}
	if v, ok := raw["choices"].([]any); ok {
		o.Choices = v
	}
	if v, ok := raw["aliases"].([]any); ok {
		o.Aliases = coerceStringList(v)
	}
	if v, ok := raw["elements"].(string); ok {
		o.Elements = v
	}
	if v, ok := raw["version_added"].(string); ok {
		o.VersionAdded = v
	}
	if v, ok := raw["suboptions"].(map[string]any); ok && len(v) > 0 {
		o.SubOptions = make(map[string]OptionDoc, len(v))
		for k, sv := range v {
			if sub, ok := sv.(map[string]any); ok {
				o.SubOptions[k] = parseOptionEntry(name+"."+k, sub)
			}
		}
	}
	return o
}

// coerceStringList turns a []any of mostly-string values into a []string.
// ansible-doc emits aliases as ["dest","destfile","name"]; coerce fails
// silently on each element rather than dropping the whole list.
func coerceStringList(v []any) []string {
	out := make([]string, 0, len(v))
	for _, e := range v {
		if s, ok := e.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, fmt.Sprintf("%v", e))
		}
	}
	return out
}

// stringOf coerces any JSON value into a single-line string.
func stringOf(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		var parts []string
		for _, e := range x {
			parts = append(parts, stringOf(e))
		}
		return strings.Join(parts, " ")
	case map[string]any:
		// best-effort: dump the map as key=value
		var parts []string
		for k, v := range x {
			parts = append(parts, fmt.Sprintf("%s=%s", k, stringOf(v)))
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%v", v)
}

// ansibleVersionTimeout bounds a single `ansible`/`ansible-doc`
// invocation. Without this, a stuck subprocess (or a slow first
// invocation on a cold ansible-core install) would hang the whole
// agent loop forever because exec.CommandContext only fires when
// the subprocess polls Go's runtime — which ansible-doc does not.
// 30s is generous: a warm run is ~50 ms, a cold one is ~8s.
const ansibleVersionTimeout = 30 * time.Second

// AnsibleVersion returns the installed ansible-core version string.
func AnsibleVersion(ctx context.Context) (string, error) {
	timedCtx, cancel := context.WithTimeout(ctx, ansibleVersionTimeout)
	defer cancel()
	cmd := exec.CommandContext(timedCtx, "ansible", "--version")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ansible --version: %w", err)
	}
	// Output format: "ansible [core 2.14.5]\n  config file = ...\n..."
	first := strings.SplitN(stdout.String(), "\n", 2)[0]
	return strings.TrimSpace(first), nil
}

// ModuleNames returns a sorted list of module names by invoking
// `ansible-doc -t module -l`. Used for version-hash computation.
func ModuleNames(ctx context.Context) ([]string, error) {
	timedCtx, cancel := context.WithTimeout(ctx, ansibleVersionTimeout)
	defer cancel()
	cmd := exec.CommandContext(timedCtx, "ansible-doc", "-t", "module", "-l")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			names = append(names, fields[0])
		}
	}
	sort.Strings(names)
	return names, nil
}
