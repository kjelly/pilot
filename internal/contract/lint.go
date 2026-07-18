package contract

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	verification "github.com/anomalyco/pilot/internal/spec"
	"gopkg.in/yaml.v3"
)

// ValidateBundleReferences validates cross-file facts that cannot be checked
// while decoding one YAML document. It is read-only and deliberately does not
// infer missing selectors or dependencies.
func ValidateBundleReferences(root string, catalog Catalog) error {
	components := catalog.Components()
	byID := make(map[string]Contract, len(components))
	rowOwners := make(map[string]string)
	applyOwners := make(map[string]bool)
	for _, component := range components {
		byID[component.ID] = component
		ownedRows, err := validateContractFiles(root, component)
		if err != nil {
			return fmt.Errorf("component %q: %w", component.ID, err)
		}
		for _, row := range ownedRows {
			if owner, exists := rowOwners[row]; exists {
				return fmt.Errorf("verification row %s is owned by both %q and %q", row, owner, component.ID)
			}
			rowOwners[row] = component.ID
		}
		applyOwners[component.Playbooks.Apply] = true
	}
	if err := validateApplyCoverage(root, applyOwners); err != nil {
		return err
	}
	if err := validateDependencyCycles(byID); err != nil {
		return err
	}
	return validateBindingEndpoints(byID)
}

func validateContractFiles(root string, component Contract) ([]string, error) {
	for _, playbook := range []string{component.Playbooks.Apply, valueOrEmpty(component.Playbooks.Rollback), valueOrEmpty(component.Playbooks.Upgrade), valueOrEmpty(component.Playbooks.Decommission)} {
		if playbook == "" {
			continue
		}
		if err := requireFile(root, playbook); err != nil {
			return nil, fmt.Errorf("playbook %s: %w", playbook, err)
		}
	}
	for _, testPath := range component.RegressionTests {
		if err := requireFile(root, testPath); err != nil {
			return nil, fmt.Errorf("regression test %s: %w", testPath, err)
		}
	}
	playbookTags, err := loadPlaybookTags(filepath.Join(root, component.Playbooks.Apply))
	if err != nil {
		return nil, err
	}
	selectedRefs := make(map[string]bool)
	for _, entry := range component.Specs {
		if err := requireFile(root, entry.Path); err != nil {
			return nil, fmt.Errorf("spec %s: %w", entry.Path, err)
		}
		parsed, err := verification.Parse(filepath.Join(root, entry.Path))
		if err != nil {
			return nil, fmt.Errorf("parse spec %s: %w", entry.Path, err)
		}
		selected, err := selectContractRows(parsed.Rows, entry.Rows)
		if err != nil {
			return nil, fmt.Errorf("spec %s: %w", entry.Path, err)
		}
		for _, row := range selected {
			ref := entry.Path + "#" + row.ID
			selectedRefs[ref] = true
			if err := validateRowTraceability(component.Traceability, ref, row.ID, playbookTags); err != nil {
				return nil, err
			}
		}
	}
	for ref := range component.Traceability.Rows {
		if !selectedRefs[ref] {
			return nil, fmt.Errorf("traceability row %s is not selected by this component", ref)
		}
	}
	for ref := range component.Traceability.Exemptions {
		if !selectedRefs[ref] {
			return nil, fmt.Errorf("traceability exemption %s is not selected by this component", ref)
		}
	}
	owned := make([]string, 0, len(selectedRefs))
	for ref := range selectedRefs {
		owned = append(owned, ref)
	}
	return owned, nil
}

func validateRowTraceability(trace Traceability, ref, rowID string, playbookTags map[string]bool) error {
	mapped, hasMapped := trace.Rows[ref]
	exemption, exempt := trace.Exemptions[ref]
	if hasMapped && exempt {
		return fmt.Errorf("traceability %s cannot be both mapped and exempt", ref)
	}
	switch trace.Mode {
	case "rowTags":
		if trace.Tag == nil {
			return fmt.Errorf("traceability %s: rowTags requires tag strategy", ref)
		}
		expected, err := derivedRowTag(*trace.Tag, rowID)
		if err != nil {
			return fmt.Errorf("traceability %s: %w", ref, err)
		}
		if exempt {
			if exemption.Reason == "" {
				return fmt.Errorf("traceability exemption %s requires a reason", ref)
			}
			if playbookTags[expected] {
				return fmt.Errorf("traceability exemption %s is stale: playbook now has tag %s", ref, expected)
			}
			return requireTraceTags(ref, exemption.Tags, playbookTags)
		}
		if !playbookTags[expected] {
			return fmt.Errorf("traceability %s requires missing playbook tag %s", ref, expected)
		}
	case "mapped":
		if exempt {
			if exemption.Reason == "" {
				return fmt.Errorf("traceability exemption %s requires a reason", ref)
			}
			return requireTraceTags(ref, exemption.Tags, playbookTags)
		}
		if !hasMapped {
			return fmt.Errorf("traceability %s has no mapped tags or exemption", ref)
		}
		if mapped.Reason == "" || len(mapped.Tags) == 0 {
			return fmt.Errorf("traceability mapping %s requires tags and reason", ref)
		}
		return requireTraceTags(ref, mapped.Tags, playbookTags)
	default:
		return fmt.Errorf("traceability %s has invalid mode %q", ref, trace.Mode)
	}
	return nil
}

func derivedRowTag(strategy TagStrategy, rowID string) (string, error) {
	switch strategy.Kind {
	case "bare":
		if strategy.Prefix != "" {
			return "", fmt.Errorf("bare tag strategy cannot set prefix")
		}
		return rowID, nil
	case "rolePrefixed":
		if strategy.Prefix == "" {
			return "", fmt.Errorf("rolePrefixed tag strategy requires prefix")
		}
		return strategy.Prefix + "-" + rowID, nil
	default:
		return "", fmt.Errorf("invalid tag strategy %q", strategy.Kind)
	}
}

func requireTraceTags(ref string, tags []string, playbookTags map[string]bool) error {
	for _, tag := range tags {
		if !playbookTags[tag] {
			return fmt.Errorf("traceability %s references missing playbook tag %s", ref, tag)
		}
	}
	return nil
}

func loadPlaybookTags(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read playbook tags: %w", err)
	}
	tags := make(map[string]bool)
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parse playbook tags: %w", err)
		}
		collectYAMLTags(&document, tags)
	}
	return tags, nil
}

func collectYAMLTags(node *yaml.Node, tags map[string]bool) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Value == "tags" {
				switch value.Kind {
				case yaml.ScalarNode:
					tags[value.Value] = true
				case yaml.SequenceNode:
					for _, item := range value.Content {
						tags[item.Value] = true
					}
				}
			}
		}
	}
	for _, child := range node.Content {
		collectYAMLTags(child, tags)
	}
}

func validateApplyCoverage(root string, owners map[string]bool) error {
	paths, err := filepath.Glob(filepath.Join(root, "playbooks", "apply", "*-apply.yml"))
	if err != nil {
		return fmt.Errorf("list apply playbooks: %w", err)
	}
	for _, path := range paths {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !owners[rel] {
			return fmt.Errorf("apply playbook %s has no component contract", rel)
		}
	}
	return nil
}

func validateBindingEndpoints(components map[string]Contract) error {
	for _, component := range components {
		for _, binding := range component.Bindings {
			provider := components[binding.From.Component]
			found := false
			for _, endpoint := range provider.Endpoints {
				if endpoint.Name == binding.From.Endpoint {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("component %q binding %s references unknown endpoint %s.%s", component.ID, binding.Input, binding.From.Component, binding.From.Endpoint)
			}
		}
	}
	return nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func requireFile(root, path string) error {
	if filepath.IsAbs(path) {
		return fmt.Errorf("must be repository-relative")
	}
	if strings.Contains(filepath.ToSlash(filepath.Clean(path)), "../") {
		return fmt.Errorf("must not escape repository root")
	}
	full := filepath.Join(root, path)
	info, err := os.Stat(full)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("is a directory")
	}
	return nil
}

func selectContractRows(rows []verification.Row, selector RowSelector) ([]verification.Row, error) {
	modes := 0
	if selector.All {
		modes++
	}
	if len(selector.IDs) > 0 {
		modes++
	}
	if len(selector.Categories) > 0 {
		modes++
	}
	if modes != 1 {
		return nil, fmt.Errorf("selector must set exactly one mode")
	}
	ids := make(map[string]bool, len(selector.IDs))
	for _, id := range selector.IDs {
		ids[id] = true
	}
	categories := make(map[string]bool, len(selector.Categories))
	for _, category := range selector.Categories {
		categories[category] = true
	}
	selected := make([]verification.Row, 0)
	for _, row := range rows {
		if selector.All || ids[row.ID] || categories[row.Category] {
			selected = append(selected, row)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("selector resolves no rows")
	}
	for id := range ids {
		found := false
		for _, row := range selected {
			if row.ID == id {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("selected row id %q does not exist", id)
		}
	}
	return selected, nil
}

func validateDependencyCycles(components map[string]Contract) error {
	state := make(map[string]uint8, len(components))
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case 1:
			return fmt.Errorf("dependency cycle at %q", id)
		case 2:
			return nil
		}
		state[id] = 1
		for _, dependency := range components[id].Dependencies {
			// The six-contract bootstrap catalog intentionally contains
			// dependencies whose contracts are scheduled for M1.2. Only edges
			// represented in this catalog can participate in a detectable cycle.
			if _, ok := components[dependency.Component]; !ok {
				continue
			}
			if err := visit(dependency.Component); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for id := range components {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}
