package contract

import (
	"fmt"
	"os"
	"path/filepath"

	verification "github.com/anomalyco/pilot/internal/spec"
)

// ValidateBundleReferences validates cross-file facts that cannot be checked
// while decoding one YAML document. It is read-only and deliberately does not
// infer missing selectors or dependencies.
func ValidateBundleReferences(root string, catalog Catalog) error {
	components := catalog.Components()
	byID := make(map[string]Contract, len(components))
	for _, component := range components {
		byID[component.ID] = component
		if err := validateContractFiles(root, component); err != nil {
			return fmt.Errorf("component %q: %w", component.ID, err)
		}
	}
	return validateDependencyCycles(byID)
}

func validateContractFiles(root string, component Contract) error {
	for _, playbook := range []string{component.Playbooks.Apply, valueOrEmpty(component.Playbooks.Rollback), valueOrEmpty(component.Playbooks.Upgrade), valueOrEmpty(component.Playbooks.Decommission)} {
		if playbook == "" {
			continue
		}
		if err := requireFile(root, playbook); err != nil {
			return fmt.Errorf("playbook %s: %w", playbook, err)
		}
	}
	for _, testPath := range component.RegressionTests {
		if err := requireFile(root, testPath); err != nil {
			return fmt.Errorf("regression test %s: %w", testPath, err)
		}
	}
	for _, entry := range component.Specs {
		if err := requireFile(root, entry.Path); err != nil {
			return fmt.Errorf("spec %s: %w", entry.Path, err)
		}
		parsed, err := verification.Parse(filepath.Join(root, entry.Path))
		if err != nil {
			return fmt.Errorf("parse spec %s: %w", entry.Path, err)
		}
		if _, err := selectContractRows(parsed.Rows, entry.Rows); err != nil {
			return fmt.Errorf("spec %s: %w", entry.Path, err)
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
