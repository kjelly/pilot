package inventory

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// RosterSudoCommandGroupNames returns the sudo.command_groups names in file
// order. The roster editor uses this for selectable, validated references.
func RosterSudoCommandGroupNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(mapField(root, "sudo"), "command_groups")), nil
}

// RosterSudoCommandGroup returns one canonical sudo command-group entry.
func RosterSudoCommandGroup(path, name string) (map[string]any, bool, error) {
	return rosterSudoEntry(path, "command_groups", name)
}

// RosterSudoRuleNames returns the sudo.rules names in file order.
func RosterSudoRuleNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(mapField(root, "sudo"), "rules")), nil
}

// RosterSudoRule returns one canonical sudo rule entry.
func RosterSudoRule(path, name string) (map[string]any, bool, error) {
	return rosterSudoEntry(path, "rules", name)
}

func rosterSudoEntry(path, listKey, name string) (map[string]any, bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	entries := listField(mapField(root, "sudo"), listKey)
	idx, _ := findNamedEntry(entries, name)
	if idx < 0 {
		return nil, false, nil
	}
	return asMap(entries[idx]), true, nil
}

func SimulateAddRosterSudoCommandGroup(path string, entry map[string]any) ([]RosterViolation, error) {
	return simulateAddRosterSudoEntry(path, "command_groups", entry)
}

func SimulateSetRosterSudoCommandGroup(path, name string, entry map[string]any) ([]RosterViolation, bool, error) {
	return simulateSetRosterSudoEntry(path, "command_groups", name, entry, "sudo command group")
}

func AppendRosterSudoCommandGroup(path string, entry map[string]any) error {
	return appendRosterSudoEntry(path, "command_groups", entry)
}

func SetRosterSudoCommandGroup(path, name string, entry map[string]any) error {
	return setRosterSudoEntry(path, "command_groups", name, entry, "sudo command group")
}

func SimulateAddRosterSudoRule(path string, entry map[string]any) ([]RosterViolation, error) {
	return simulateAddRosterSudoEntry(path, "rules", entry)
}

func SimulateSetRosterSudoRule(path, name string, entry map[string]any) ([]RosterViolation, bool, error) {
	return simulateSetRosterSudoEntry(path, "rules", name, entry, "sudo rule")
}

func AppendRosterSudoRule(path string, entry map[string]any) error {
	return appendRosterSudoEntry(path, "rules", entry)
}

func SetRosterSudoRule(path, name string, entry map[string]any) error {
	return setRosterSudoEntry(path, "rules", name, entry, "sudo rule")
}

func simulateAddRosterSudoEntry(path, listKey string, entry map[string]any) ([]RosterViolation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	sudo := mapField(root, "sudo")
	sudo[listKey] = append(listField(sudo, listKey), entry)
	root["sudo"] = sudo
	return ValidateRoster(root), nil
}

func simulateSetRosterSudoEntry(path, listKey, name string, entry map[string]any, kind string) ([]RosterViolation, bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	sudo := mapField(root, "sudo")
	entries := listField(sudo, listKey)
	idx, ambiguous := findNamedEntry(entries, name)
	if ambiguous {
		return nil, true, fmt.Errorf("roster %s: %s %q is ambiguous", path, kind, name)
	}
	if idx < 0 {
		return nil, false, nil
	}
	entries[idx] = entry
	sudo[listKey] = entries
	root["sudo"] = sudo
	return ValidateRoster(root), true, nil
}

func appendRosterSudoEntry(path, listKey string, entry map[string]any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return ErrRosterEncrypted
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse roster %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("roster %s: expected a top-level YAML mapping", path)
	}
	sudo := mappingChild(root.Content[0], "sudo", yaml.MappingNode, "!!map")
	entries := mappingChild(sudo, listKey, yaml.SequenceNode, "!!seq")
	var node yaml.Node
	if err := node.Encode(entry); err != nil {
		return err
	}
	entries.Content = append(entries.Content, &node)
	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return os.WriteFile(path, rendered, 0o600)
}

func setRosterSudoEntry(path, listKey, name string, entry map[string]any, kind string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return ErrRosterEncrypted
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("roster %s: expected a top-level YAML mapping", path)
	}
	sudo := findMappingChild(root.Content[0], "sudo")
	if sudo == nil {
		return fmt.Errorf("roster %s: no sudo map", path)
	}
	entries := findMappingChild(sudo, listKey)
	if entries == nil || entries.Kind != yaml.SequenceNode {
		return fmt.Errorf("roster %s: no sudo.%s list", path, listKey)
	}
	idx := -1
	for i, item := range entries.Content {
		var current map[string]any
		if err := item.Decode(&current); err != nil {
			return err
		}
		if stringField(current, "name") == name {
			if idx >= 0 {
				return fmt.Errorf("roster %s: %s %q is ambiguous", path, kind, name)
			}
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("roster %s: no %s named %q", path, kind, name)
	}
	var node yaml.Node
	if err := node.Encode(entry); err != nil {
		return err
	}
	entries.Content[idx] = &node
	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return os.WriteFile(path, rendered, 0o600)
}
