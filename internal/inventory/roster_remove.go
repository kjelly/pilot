// roster_remove.go implements the roster-local half of `pilot roster
// remove-user`/`remove-group` (spec.md §14/§15): undoing a never-applied
// local roster edit. It deliberately never talks to FreeIPA — the
// FreeIPA "has this ever been applied" historical guard lives in the
// internal/freeipa probe package and the Cobra command that calls it
// before SimulateRemoveRosterUser/Group ever runs; this file's job is
// purely the roster-local structural safety spec.md §15 requires:
// exactly one match, never a state: absent target, reference handling
// that matches the caller's cascade choice, and a final candidate that
// always passes ValidateRoster before anything is written.
//
// Following the same split every other roster mutation in this package
// uses (SimulateAddRosterUser/AppendRosterUser,
// SimulateSetRosterUser/SetRosterUser): Simulate* operates on a generic
// map[string]any decode (readRosterAsMap) purely to report what would
// happen, and only Remove* re-parses the file as a yaml.Node tree to
// perform the actual surgical, formatting-preserving mutation.
package inventory

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrRosterUserAbsentLifecycle/ErrRosterGroupAbsentLifecycle are returned
// (wrapped) when a remove command's target is already state: absent — a
// declarative deprovision tombstone, never eligible for hard removal
// regardless of FreeIPA state (spec.md §2.5).
var (
	ErrRosterUserAbsentLifecycle  = errors.New("inventory: roster user is already in state: absent lifecycle")
	ErrRosterGroupAbsentLifecycle = errors.New("inventory: roster group is already in state: absent lifecycle")
)

type RemoveRosterUserOptions struct {
	CascadeReferences bool
}

type RemoveRosterUserSimulation struct {
	Found             bool
	References        []RosterReference
	RemovedReferences []RosterReference
	Violations        []RosterViolation
}

type RemoveRosterGroupOptions struct {
	CascadeReferences bool
}

type RemoveRosterGroupSimulation struct {
	Found             bool
	References        []RosterReference
	RemovedReferences []RosterReference
	Violations        []RosterViolation
}

// SimulateRemoveRosterUser reports what would happen if username were
// hard-removed from the roster at path — without writing anything. It
// does not contact FreeIPA; callers must have already established the
// historical guard (§16 Phase B) before treating a clean simulation as
// license to call RemoveRosterUser.
func SimulateRemoveRosterUser(path, username string, opts RemoveRosterUserOptions) (RemoveRosterUserSimulation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return RemoveRosterUserSimulation{}, err
	}
	users := listField(root, "users")
	idx, ambiguous := findNamedEntry(users, username)
	if ambiguous {
		return RemoveRosterUserSimulation{}, fmt.Errorf("roster %s: name %q is ambiguous (more than one user already has it); fix the duplicate by hand first", path, username)
	}
	if idx < 0 {
		return RemoveRosterUserSimulation{Found: false}, nil
	}
	if stateOrDefault(asMap(users[idx]), "present") == "absent" {
		return RemoveRosterUserSimulation{}, fmt.Errorf("roster %s: user %q is already state: absent: %w", path, username, ErrRosterUserAbsentLifecycle)
	}

	refs := RosterUserReferences(root, username)
	if len(refs) > 0 && !opts.CascadeReferences {
		return RemoveRosterUserSimulation{Found: true, References: refs}, nil
	}

	removed := cascadeRemoveUserReferences(root, username)
	users = listField(root, "users")
	root["users"] = append(users[:idx:idx], users[idx+1:]...)

	return RemoveRosterUserSimulation{
		Found:             true,
		References:        refs,
		RemovedReferences: removed,
		Violations:        ValidateRoster(root),
	}, nil
}

// SimulateRemoveRosterGroup is SimulateRemoveRosterUser's group
// counterpart. A blocked reference (e.g. an NFS share's
// ownership.group) always aborts, even with CascadeReferences set — see
// spec.md §18.1.
func SimulateRemoveRosterGroup(path, groupname string, opts RemoveRosterGroupOptions) (RemoveRosterGroupSimulation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return RemoveRosterGroupSimulation{}, err
	}
	groups := listField(root, "groups")
	idx, ambiguous := findNamedEntry(groups, groupname)
	if ambiguous {
		return RemoveRosterGroupSimulation{}, fmt.Errorf("roster %s: name %q is ambiguous (more than one group already has it); fix the duplicate by hand first", path, groupname)
	}
	if idx < 0 {
		return RemoveRosterGroupSimulation{Found: false}, nil
	}
	if stateOrDefault(asMap(groups[idx]), "present") == "absent" {
		return RemoveRosterGroupSimulation{}, fmt.Errorf("roster %s: group %q is already state: absent: %w", path, groupname, ErrRosterGroupAbsentLifecycle)
	}

	refs := RosterGroupReferences(root, groupname)
	hasBlocked := false
	for _, ref := range refs {
		if ref.Cascade == RosterReferenceCascadeBlocked {
			hasBlocked = true
			break
		}
	}
	if hasBlocked || (len(refs) > 0 && !opts.CascadeReferences) {
		return RemoveRosterGroupSimulation{Found: true, References: refs}, nil
	}

	removed := cascadeRemoveGroupReferences(root, groupname)
	groups = listField(root, "groups")
	root["groups"] = append(groups[:idx:idx], groups[idx+1:]...)

	return RemoveRosterGroupSimulation{
		Found:             true,
		References:        refs,
		RemovedReferences: removed,
		Violations:        ValidateRoster(root),
	}, nil
}

// ---- map-world cascade mutation (feeds Simulate* only) -------------------

func removeStringValue(list []string, target string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v != target {
			out = append(out, v)
		}
	}
	return out
}

func cascadeRemoveUserReferences(root map[string]any, username string) []RosterReference {
	var removed []RosterReference
	for _, raw := range listField(root, "groups") {
		g := asMap(raw)
		if m := mapField(g, "membership"); m != nil {
			if users := stringListField(m, "users"); contains(users, username) {
				m["users"] = removeStringValue(users, username)
				removed = append(removed, RosterReference{Kind: "group membership", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("groups[%s].membership.users", stringField(g, "name"))})
			}
		}
	}
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		r := asMap(raw)
		if s := mapField(r, "subjects"); s != nil {
			if users := stringListField(s, "users"); contains(users, username) {
				s["users"] = removeStringValue(users, username)
				removed = append(removed, RosterReference{Kind: "hbac subject", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("hbac.rules[%s].subjects.users", stringField(r, "name"))})
			}
		}
	}
	for _, raw := range listField(mapField(root, "sudo"), "rules") {
		r := asMap(raw)
		if s := mapField(r, "subjects"); s != nil {
			if users := stringListField(s, "users"); contains(users, username) {
				s["users"] = removeStringValue(users, username)
				removed = append(removed, RosterReference{Kind: "sudo subject", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("sudo.rules[%s].subjects.users", stringField(r, "name"))})
			}
		}
	}
	for _, raw := range listField(root, "netgroups") {
		ng := asMap(raw)
		if m := mapField(ng, "membership"); m != nil {
			if users := stringListField(m, "users"); contains(users, username) {
				m["users"] = removeStringValue(users, username)
				removed = append(removed, RosterReference{Kind: "netgroup membership", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("netgroups[%s].membership.users", stringField(ng, "name"))})
			}
		}
	}
	sortRosterReferences(removed)
	return removed
}

func cascadeRemoveGroupReferences(root map[string]any, groupname string) []RosterReference {
	var removed []RosterReference
	for _, raw := range listField(root, "groups") {
		g := asMap(raw)
		if m := mapField(g, "membership"); m != nil {
			if groups := stringListField(m, "groups"); contains(groups, groupname) {
				m["groups"] = removeStringValue(groups, groupname)
				removed = append(removed, RosterReference{Kind: "group membership", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("groups[%s].membership.groups", stringField(g, "name"))})
			}
		}
	}
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		r := asMap(raw)
		if s := mapField(r, "subjects"); s != nil {
			if groups := stringListField(s, "groups"); contains(groups, groupname) {
				s["groups"] = removeStringValue(groups, groupname)
				removed = append(removed, RosterReference{Kind: "hbac subject", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("hbac.rules[%s].subjects.groups", stringField(r, "name"))})
			}
		}
	}
	for _, raw := range listField(mapField(root, "sudo"), "rules") {
		r := asMap(raw)
		label := stringField(r, "name")
		if s := mapField(r, "subjects"); s != nil {
			if groups := stringListField(s, "groups"); contains(groups, groupname) {
				s["groups"] = removeStringValue(groups, groupname)
				removed = append(removed, RosterReference{Kind: "sudo subject", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("sudo.rules[%s].subjects.groups", label)})
			}
		}
		if ra := mapField(r, "run_as"); ra != nil {
			if groups := stringListField(ra, "groups"); contains(groups, groupname) {
				ra["groups"] = removeStringValue(groups, groupname)
				removed = append(removed, RosterReference{Kind: "sudo run_as", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("sudo.rules[%s].run_as.groups", label)})
			}
		}
	}
	for _, raw := range listField(root, "netgroups") {
		ng := asMap(raw)
		if m := mapField(ng, "membership"); m != nil {
			if groups := stringListField(m, "groups"); contains(groups, groupname) {
				m["groups"] = removeStringValue(groups, groupname)
				removed = append(removed, RosterReference{Kind: "netgroup membership", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("netgroups[%s].membership.groups", stringField(ng, "name"))})
			}
		}
	}
	for _, rawServer := range listField(mapField(root, "nfs"), "servers") {
		server := asMap(rawServer)
		serverLabel := stringField(server, "host")
		for _, rawShare := range listField(server, "shares") {
			share := asMap(rawShare)
			shareLabel := labelOf(share)
			acl := mapField(share, "acl")
			for _, section := range []string{"access", "default"} {
				sectionMap := mapField(acl, section)
				if sectionMap == nil {
					continue
				}
				namedGroups := listField(sectionMap, "named_groups")
				kept := namedGroups[:0:0]
				changed := false
				for _, rawNG := range namedGroups {
					if stringField(asMap(rawNG), "name") == groupname {
						changed = true
						continue
					}
					kept = append(kept, rawNG)
				}
				if changed {
					sectionMap["named_groups"] = kept
					removed = append(removed, RosterReference{Kind: "nfs acl named_group", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("nfs.servers[%s].shares[%s].acl.%s.named_groups[%s]", serverLabel, shareLabel, section, groupname)})
				}
			}
		}
	}
	sortRosterReferences(removed)
	return removed
}

// ---- yaml.Node-world mutation (RemoveRosterUser/RemoveRosterGroup only) --

// RemoveRosterUser hard-removes username from the roster at path via
// yaml.Node surgery — same technique as SetRosterUser/AppendRosterUser,
// so unrelated content survives untouched. It re-derives everything from
// a fresh read (it does not trust a caller's earlier
// SimulateRemoveRosterUser result) and refuses to write if the candidate
// would not validate. It performs no FreeIPA probe — callers must have
// already established the historical guard.
func RemoveRosterUser(path, username string, opts RemoveRosterUserOptions) error {
	lock, err := acquireMutationLock(path + ".pilot-remove.lock")
	if err != nil {
		return err
	}
	defer lock.release()

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
	top := root.Content[0]

	fields, err := findSequenceEntryFields(top, "users", username)
	if err != nil {
		return fmt.Errorf("roster %s: %w", path, err)
	}
	if stateOrDefault(fields, "present") == "absent" {
		return fmt.Errorf("roster %s: user %q is already state: absent: %w", path, username, ErrRosterUserAbsentLifecycle)
	}

	var current map[string]any
	if err := top.Decode(&current); err != nil {
		return fmt.Errorf("roster %s: %w", path, err)
	}
	if refs := RosterUserReferences(current, username); len(refs) > 0 && !opts.CascadeReferences {
		return fmt.Errorf("roster %s: cannot remove user %q: still referenced (%d reference(s)); rerun with --cascade-references", path, username, len(refs))
	}

	if opts.CascadeReferences {
		removeUserReferencesFromNode(top, username)
	}
	deleteSequenceEntryByName(top, "users", username)

	violations, err := validateRosterNode(top)
	if err != nil {
		return fmt.Errorf("roster %s: %w", path, err)
	}
	if len(violations) > 0 {
		return fmt.Errorf("roster %s: candidate would be invalid after removing user %q: %s", path, username, violations[0].String())
	}

	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("render roster %s: %w", path, err)
	}
	return os.WriteFile(path, rendered, 0o600)
}

// RemoveRosterGroup is RemoveRosterUser's group counterpart. A blocked
// reference always aborts before any mutation, regardless of
// opts.CascadeReferences (spec.md §18.1).
func RemoveRosterGroup(path, groupname string, opts RemoveRosterGroupOptions) error {
	lock, err := acquireMutationLock(path + ".pilot-remove.lock")
	if err != nil {
		return err
	}
	defer lock.release()

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
	top := root.Content[0]

	fields, err := findSequenceEntryFields(top, "groups", groupname)
	if err != nil {
		return fmt.Errorf("roster %s: %w", path, err)
	}
	if stateOrDefault(fields, "present") == "absent" {
		return fmt.Errorf("roster %s: group %q is already state: absent: %w", path, groupname, ErrRosterGroupAbsentLifecycle)
	}

	var current map[string]any
	if err := top.Decode(&current); err != nil {
		return fmt.Errorf("roster %s: %w", path, err)
	}
	refs := RosterGroupReferences(current, groupname)
	for _, ref := range refs {
		if ref.Cascade == RosterReferenceCascadeBlocked {
			return fmt.Errorf("roster %s: cannot remove group %q: blocked reference %s (%s)", path, groupname, ref.Path, ref.Explanation)
		}
	}
	if len(refs) > 0 && !opts.CascadeReferences {
		return fmt.Errorf("roster %s: cannot remove group %q: still referenced (%d reference(s)); rerun with --cascade-references", path, groupname, len(refs))
	}

	if opts.CascadeReferences {
		removeGroupReferencesFromNode(top, groupname)
	}
	deleteSequenceEntryByName(top, "groups", groupname)

	violations, err := validateRosterNode(top)
	if err != nil {
		return fmt.Errorf("roster %s: %w", path, err)
	}
	if len(violations) > 0 {
		return fmt.Errorf("roster %s: candidate would be invalid after removing group %q: %s", path, groupname, violations[0].String())
	}

	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("render roster %s: %w", path, err)
	}
	return os.WriteFile(path, rendered, 0o600)
}

// findSequenceEntryFields locates the item named name within the
// top-level listKey sequence and returns its decoded fields, without
// mutating anything. Mirrors replaceTopLevelRosterEntry's lookup loop.
func findSequenceEntryFields(top *yaml.Node, listKey, name string) (map[string]any, error) {
	listNode := findMappingChild(top, listKey)
	if listNode == nil || listNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("no %s entry named %q (no %s: list)", listKey, name, listKey)
	}
	found := false
	var fields map[string]any
	for _, item := range listNode.Content {
		var m map[string]any
		if err := item.Decode(&m); err != nil {
			return nil, fmt.Errorf("decode %s entry: %w", listKey, err)
		}
		if stringField(m, "name") != name {
			continue
		}
		if found {
			return nil, fmt.Errorf("name %q is ambiguous (more than one %s entry already has it); fix the duplicate by hand first", name, listKey)
		}
		found = true
		fields = m
	}
	if !found {
		return nil, fmt.Errorf("no %s entry named %q", listKey, name)
	}
	return fields, nil
}

// deleteSequenceEntryByName removes the item named name from the
// top-level listKey sequence. Callers must have already verified exactly
// one match exists (via findSequenceEntryFields) — this silently no-ops
// if the list or the entry is missing.
func deleteSequenceEntryByName(top *yaml.Node, listKey, name string) {
	listNode := findMappingChild(top, listKey)
	if listNode == nil {
		return
	}
	for i, item := range listNode.Content {
		var m map[string]any
		if err := item.Decode(&m); err != nil {
			continue
		}
		if stringField(m, "name") == name {
			listNode.Content = append(listNode.Content[:i], listNode.Content[i+1:]...)
			return
		}
	}
}

// validateRosterNode decodes top (the roster's top-level mapping node)
// directly into a generic map and runs it through ValidateRoster — the
// same validator every other roster write path gates on, run here on the
// exact node tree that is about to be marshaled and written.
func validateRosterNode(top *yaml.Node) ([]RosterViolation, error) {
	var m map[string]any
	if err := top.Decode(&m); err != nil {
		return nil, err
	}
	return ValidateRoster(m), nil
}

// sequenceEntries returns listKey's sequence items under mapNode, or nil
// if mapNode/the list is absent or not a sequence. mapNode may be nil.
func sequenceEntries(mapNode *yaml.Node, listKey string) []*yaml.Node {
	seq := findMappingChild(mapNode, listKey)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	return seq.Content
}

// findNestedSequence resolves entry.key1.key2 as a sequence node, or nil
// if any hop is absent. entry/intermediate nodes may be nil.
func findNestedSequence(entry *yaml.Node, key1, key2 string) *yaml.Node {
	return findMappingChild(findMappingChild(entry, key1), key2)
}

// removeScalarFromNodeSequence deletes every scalar item equal to value
// from seq in place. seq may be nil.
func removeScalarFromNodeSequence(seq *yaml.Node, value string) {
	if seq == nil {
		return
	}
	kept := seq.Content[:0]
	for _, item := range seq.Content {
		if item.Kind == yaml.ScalarNode && item.Value == value {
			continue
		}
		kept = append(kept, item)
	}
	seq.Content = kept
}

// removeNamedGroupFromNodeSequence deletes every {name: groupname, ...}
// mapping item from seq in place (nfs acl named_groups' shape). seq may
// be nil.
func removeNamedGroupFromNodeSequence(seq *yaml.Node, groupname string) {
	if seq == nil {
		return
	}
	kept := seq.Content[:0]
	for _, item := range seq.Content {
		var m map[string]any
		if err := item.Decode(&m); err == nil && stringField(m, "name") == groupname {
			continue
		}
		kept = append(kept, item)
	}
	seq.Content = kept
}

// removeUserReferencesFromNode deletes every cascadeable reference to
// username from top's groups/hbac/sudo/netgroups sections, in place.
func removeUserReferencesFromNode(top *yaml.Node, username string) {
	for _, entry := range sequenceEntries(top, "groups") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "membership", "users"), username)
	}
	hbac := findMappingChild(top, "hbac")
	for _, entry := range sequenceEntries(hbac, "rules") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "subjects", "users"), username)
	}
	sudo := findMappingChild(top, "sudo")
	for _, entry := range sequenceEntries(sudo, "rules") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "subjects", "users"), username)
	}
	for _, entry := range sequenceEntries(top, "netgroups") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "membership", "users"), username)
	}
}

// removeGroupReferencesFromNode deletes every cascadeable reference to
// groupname from top's groups/hbac/sudo/netgroups/nfs-acl sections, in
// place. It never touches nfs ownership.group — that reference is always
// RosterReferenceCascadeBlocked and callers must reject it before this
// is ever called.
func removeGroupReferencesFromNode(top *yaml.Node, groupname string) {
	for _, entry := range sequenceEntries(top, "groups") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "membership", "groups"), groupname)
	}
	hbac := findMappingChild(top, "hbac")
	for _, entry := range sequenceEntries(hbac, "rules") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "subjects", "groups"), groupname)
	}
	sudo := findMappingChild(top, "sudo")
	for _, entry := range sequenceEntries(sudo, "rules") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "subjects", "groups"), groupname)
		removeScalarFromNodeSequence(findNestedSequence(entry, "run_as", "groups"), groupname)
	}
	for _, entry := range sequenceEntries(top, "netgroups") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "membership", "groups"), groupname)
	}
	nfs := findMappingChild(top, "nfs")
	for _, server := range sequenceEntries(nfs, "servers") {
		for _, share := range sequenceEntries(server, "shares") {
			acl := findMappingChild(share, "acl")
			removeNamedGroupFromNodeSequence(findNestedSequence(acl, "access", "named_groups"), groupname)
			removeNamedGroupFromNodeSequence(findNestedSequence(acl, "default", "named_groups"), groupname)
		}
	}
}
