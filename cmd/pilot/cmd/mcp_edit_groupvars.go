package cmd

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"

	"github.com/kjelly/pilot/internal/contract"
	"go.yaml.in/yaml/v3"
)

const inspectRedactedValue = "[REDACTED]"

type inspectGroupVarMetadata struct {
	Present  bool   `json:"present"`
	IsSet    bool   `json:"is_set"`
	Source   string `json:"source"`
	Redacted bool   `json:"redacted"`
	Reason   string `json:"reason,omitempty"`
}

type inspectGroupVars struct {
	Values   map[string]map[string]string
	Metadata map[string]map[string]inspectGroupVarMetadata
	Status   map[string]string
}

type inspectGroupVarPolicy struct {
	Inputs   []contract.GroupVar
	Selected bool
}

// All declarations participate in sensitivity decisions, even when a component
// filter is used: a secret declaration always wins over a public declaration.
// A missing/invalid catalog grants no permission to disclose values. Never send
// loader/parser errors to clients: YAML diagnostics can contain the input value.
func inspectGroupVarPolicies(component string) map[string]inspectGroupVarPolicy {
	policies := map[string]inspectGroupVarPolicy{}
	catalog, ok := loadContractCatalogBestEffort()
	if !ok {
		return policies
	}
	for _, c := range catalog.Components() {
		for _, input := range c.GroupVars {
			p := policies[input.Name]
			p.Inputs = append(p.Inputs, input)
			p.Selected = p.Selected || c.ID == component
			policies[input.Name] = p
		}
	}
	return policies
}

// buildInspectGroupVars is the only group_vars value export boundary. Preserve
// the existing filename/key/string shape, with an additive metadata view. Parse
// actual YAML so comments never become values and maps, sequences, nulls, block
// scalars and aliases cannot evade the policy via the line-oriented editor.
func buildInspectGroupVars(dir string, in inspectInput) inspectGroupVars {
	out := inspectGroupVars{
		Values:   map[string]map[string]string{},
		Metadata: map[string]map[string]inspectGroupVarMetadata{},
		Status:   map[string]string{},
	}
	policies := inspectGroupVarPolicies(in.GroupVarsComponent)
	entries, err := managedFileEntries(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		file := filepath.Base(e.RelPath)
		if filepath.Dir(e.RelPath) != "group_vars" || (in.GroupVarsFile != "" && file != in.GroupVarsFile) {
			continue
		}
		root, valid := inspectGroupVarsDocument(e.Content)
		if !valid {
			out.Status[file] = "invalid_yaml"
			continue
		}
		values := map[string]string{}
		metadata := map[string]inspectGroupVarMetadata{}
		for i := 0; i < len(root.Content); i += 2 {
			key, node := root.Content[i].Value, root.Content[i+1]
			p := policies[key]
			if (in.GroupVarsKey != "" && key != in.GroupVarsKey) || (in.GroupVarsComponent != "" && !p.Selected) {
				continue
			}
			reason := inspectGroupVarRedaction(p, node)
			value := inspectRedactedValue
			if reason == "" {
				value = node.Value
			}
			values[key] = value
			metadata[key] = inspectGroupVarMetadata{
				Present: true, IsSet: inspectGroupVarIsSet(node), Source: e.RelPath,
				Redacted: reason != "", Reason: reason,
			}
		}
		if len(values) > 0 || (in.GroupVarsComponent == "" && in.GroupVarsKey == "") {
			out.Values[file], out.Metadata[file], out.Status[file] = values, metadata, "ok"
		}
	}
	return out
}

func inspectGroupVarsDocument(data []byte) (*yaml.Node, bool) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc, extra yaml.Node
	if decoder.Decode(&doc) != nil || len(doc.Content) != 1 || decoder.Decode(&extra) != io.EOF {
		return nil, false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, false
	}
	// Decode only for structural validation (including duplicate keys). Never
	// export this decoded map, which resolves aliases and YAML merge keys.
	var values map[string]any
	if root.Decode(&values) != nil {
		return nil, false
	}
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Tag != "!!str" {
			return nil, false
		}
	}
	return root, true
}

func inspectGroupVarRedaction(p inspectGroupVarPolicy, node *yaml.Node) string {
	if len(p.Inputs) == 0 {
		return "unknown_input"
	}
	for _, input := range p.Inputs {
		if input.Secret {
			return "secret"
		}
	}
	// Contracts have no per-child sensitivity metadata. Redact entire
	// collections and embedded configuration rather than guessing which children
	// are safe. Aliases must not copy a secret into an otherwise public key.
	if node.Kind != yaml.ScalarNode || node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return "unclassified_structure"
	}
	if node.Tag == "!!str" && inspectGroupVarContainsConfiguration(node.Value) {
		return "unclassified_structure"
	}
	if node.Tag != "!!str" && node.Tag != "!!int" && node.Tag != "!!bool" && node.Tag != "!!null" {
		return "unclassified_type"
	}
	var value any
	if node.Decode(&value) != nil {
		return "invalid_value"
	}
	for _, input := range p.Inputs {
		if !contract.ValueMatchesType(input.Type, value) {
			return "invalid_type"
		}
	}
	return ""
}

// A public string input can carry an entire configuration (for example
// alertmanager_config). Quoting a map/list or escaping its newlines must not
// turn unclassified children into public scalars. Never expose decode errors.
func inspectGroupVarContainsConfiguration(value string) bool {
	if strings.ContainsAny(value, "\r\n") {
		return true
	}
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return true
	}
	var doc yaml.Node
	return yaml.Unmarshal([]byte(value), &doc) == nil && len(doc.Content) == 1 &&
		(doc.Content[0].Kind == yaml.MappingNode || doc.Content[0].Kind == yaml.SequenceNode)
}

func inspectGroupVarIsSet(node *yaml.Node) bool {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Tag != "!!null" && strings.TrimSpace(node.Value) != ""
	case yaml.MappingNode, yaml.SequenceNode:
		return len(node.Content) > 0
	default:
		return false // do not follow aliases
	}
}
