package contract

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	verification "github.com/kjelly/pilot/internal/spec"
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
		if err := validateDecommissionPolicy(component); err != nil {
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
	if err := validateBindingEndpoints(byID); err != nil {
		return err
	}
	return validateDependencyEndpoints(byID)
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

// validateDependencyEndpoints checks that every name in a providerEndpoint
// dependency's optional Endpoints filter (see Dependency.Endpoints) exists in
// the referenced provider component's own Endpoints. An empty filter means
// "check every endpoint the provider declares" and needs no cross-reference.
func validateDependencyEndpoints(components map[string]Contract) error {
	for _, component := range components {
		for _, dependency := range component.Dependencies {
			if len(dependency.Endpoints) == 0 {
				continue
			}
			provider, ok := components[dependency.Component]
			if !ok {
				return fmt.Errorf("component %q dependency %q endpoints filter references unknown component", component.ID, dependency.Component)
			}
			known := make(map[string]bool, len(provider.Endpoints))
			for _, endpoint := range provider.Endpoints {
				known[endpoint.Name] = true
			}
			for _, name := range dependency.Endpoints {
				if !known[name] {
					return fmt.Errorf("component %q dependency %q references unknown endpoint %s.%s", component.ID, dependency.Component, dependency.Component, name)
				}
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

// componentsWithBespokeDecommissionProvider is the fixed, compile-time-
// known set of component IDs that have a hand-written Go
// internal/decommission/providers.Provider (Phase 3/4) rather than
// relying on the generic playbooks.decommission executor (Phase 5). Lint
// runs statically over the contract catalog alone, with no access to a
// live CLI provider registry — spec.md §14.1 rule 1's "or a registered
// central decommission provider exists" clause is checked against this
// list instead. Keep it in sync with cmd/pilot/cmd/host_decommission.go's
// buildHostDecommissionProviders: adding a new bespoke provider there
// without adding its component ID here would make this lint wrongly
// demand a playbooks.decommission entry that provider doesn't need.
var componentsWithBespokeDecommissionProvider = map[string]bool{
	"freeipa-client":    true,
	"wazuh-fim":         true,
	"internal-endpoint": true,
}

// validateDecommissionPolicy implements spec.md §14.1's contract linter
// rules for the typed Lifecycle.Decommission (rules 1-3; rule 4 is a
// planner-time requirement — see internal/decommission's
// applyUnreachablePolicy/ComponentPlan.RequiresReachableHost — not a
// static lint; rule 5 is already covered by validateContractFiles's
// requireFile call over every Playbooks field including Decommission;
// rule 6, "null lifecycle remains valid", is true by construction — a nil
// Decommission trivially skips every check below).
func validateDecommissionPolicy(component Contract) error {
	policy := component.Lifecycle.Decommission
	if policy == nil {
		return nil
	}

	// Rule 1: ExternalState=true requires a real removal path — either a
	// declared decommission playbook, or one of the fixed bespoke Go
	// providers above.
	if policy.ExternalState &&
		component.Playbooks.Decommission == nil &&
		!componentsWithBespokeDecommissionProvider[component.ID] {
		return fmt.Errorf("lifecycle.decommission.externalState=true requires playbooks.decommission to be set, or a registered bespoke decommission provider (spec.md §14.1 rule 1)")
	}

	// Rule 2: a stateful component cannot declare retention=none — if it
	// truly manages no persistent data it should not be marked stateful at
	// all (spec.md §14.1 rule 2).
	if policy.Class == "stateful" && (policy.Retention == "" || policy.Retention == "none") {
		return fmt.Errorf("lifecycle.decommission.class=stateful cannot declare retention=%q — a stateful component must declare retention: required or operator_choice (spec.md §14.1 rule 2)", policy.Retention)
	}

	// Rule 3: control_plane components cannot expose a generic removal
	// path — a dedicated, separately-designed workflow is required
	// (mirrors INV-13's hard FreeIPA server/replica exclusion; a future
	// phase may introduce one, but it is never this generic executor).
	if policy.Class == "control_plane" && component.Playbooks.Decommission != nil {
		return fmt.Errorf("lifecycle.decommission.class=control_plane cannot also declare playbooks.decommission — control-plane components require a dedicated decommission workflow, never the generic executor (spec.md §14.1 rule 3)")
	}

	return nil
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
