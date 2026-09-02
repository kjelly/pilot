// roster_host_remove.go implements the roster-local half of host
// decommission's canonical FreeIPA host lifecycle completion (spec.md
// §16.3/§16.4): converging a roster host entry from state: present to
// state: absent and pruning every direct hostgroup/netgroup/HBAC/sudo
// reference to it — the Go-side counterpart
// playbooks/apply/freeipa-identity-apply.yml's new absent-host section
// converges server-side (host-del, DNS, service-principal check).
//
// This deliberately mirrors roster_remove.go's SimulateRemoveRosterUser/
// Group + RemoveRosterUser/Group split (Simulate* on a generic
// readRosterAsMap decode reporting what WOULD happen; the yaml.Node-world
// mutator performing the real formatting-preserving write) rather than
// inventing a new convention, per spec.md §16.4's explicit instruction to
// follow the established idiom.
//
// One structural difference from the user/group siblings: a roster host
// is never hard-deleted from hosts[] by this package (spec.md §16.4: "set
// the matching entry's state: absent rather than deleting the roster
// entry outright, matching how other roster entities represent
// 'convergent delete'" — the same declarative-tombstone convention
// SetRosterGrant already uses). So there is no RemoveRosterHost that
// deletes the hosts[] entry outright; SetRosterHostAbsent only flips its
// state field, and RemoveRosterHostReferences only prunes OTHER objects'
// membership/target lists that point at it.
package inventory

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SimulateRemoveRosterHost reports what validating the roster at path
// would say if hostName's canonical hosts[] entry were converged to
// state: absent and every hostgroup/netgroup/HBAC/sudo direct reference
// to it were pruned — without writing anything (spec.md §16.4).
// found=false means no such host exists in hosts[] (nothing to plan for
// on the roster side — a mismatched short-name/FQDN is the caller's to
// reconcile, not a fatal error here). err is non-nil (not a violation)
// when hostName is ambiguous — more than one hosts[] entry already shares
// the name, a pre-existing corruption this refuses to guess through.
//
// Unlike SimulateRemoveRosterUser/Group, a host entry ALREADY in state:
// absent is not rejected as a distinct lifecycle error: a partially
// completed prior decommission attempt may have already converged the
// roster side before failing at a later central-cleanup step (INV-9), and
// re-simulating that same convergence must be a safe, idempotent no-op,
// not an error.
func SimulateRemoveRosterHost(path, hostName string) (violations []RosterViolation, found bool, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	hosts := listField(root, "hosts")
	idx, ambiguous := findNamedEntry(hosts, hostName)
	if ambiguous {
		return nil, true, fmt.Errorf("roster %s: host %q is ambiguous (more than one host entry already has it); fix the duplicate by hand first", path, hostName)
	}
	if idx < 0 {
		return nil, false, nil
	}

	updated := map[string]any{}
	for k, v := range asMap(hosts[idx]) {
		updated[k] = v
	}
	updated["state"] = "absent"
	hosts[idx] = updated
	root["hosts"] = hosts

	cascadeRemoveHostReferences(root, hostName)

	return ValidateRoster(root), true, nil
}

// RosterHostAbsentAndUnreferenced reports whether hostName's roster entry
// is already state: absent AND no hostgroup/netgroup/HBAC/sudo direct
// reference to it remains — i.e. a prior RemoveRosterHostReferences +
// SetRosterHostAbsent call already converged this host, so calling them
// again would be a pure no-op. found=false (no such host entry at all)
// also counts as converged: there is nothing left to prune. Used by host
// decommission's step execution (internal/decommission/providers) to
// avoid re-mutating an already-converged roster on resume (INV-9/HD18) —
// this is a plain read, it never writes.
func RosterHostAbsentAndUnreferenced(path, hostName string) (bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return false, err
	}
	hosts := listField(root, "hosts")
	idx, ambiguous := findNamedEntry(hosts, hostName)
	if ambiguous {
		return false, fmt.Errorf("roster %s: host %q is ambiguous (more than one host entry already has it); fix the duplicate by hand first", path, hostName)
	}
	if idx < 0 {
		return true, nil
	}
	state, _ := asMap(hosts[idx])["state"].(string)
	if state != "absent" {
		return false, nil
	}
	return !rosterHostHasAnyReference(root, hostName), nil
}

// rosterHostHasAnyReference reports whether hostName still appears in any
// hostgroup/netgroup membership or HBAC/sudo rule target — the read-only
// counterpart of cascadeRemoveHostReferences below (detects, never
// mutates).
func rosterHostHasAnyReference(root map[string]any, hostName string) bool {
	for _, raw := range listField(root, "hostgroups") {
		if m := mapField(asMap(raw), "membership"); m != nil && contains(stringListField(m, "hosts"), hostName) {
			return true
		}
	}
	for _, raw := range listField(root, "netgroups") {
		if m := mapField(asMap(raw), "membership"); m != nil && contains(stringListField(m, "hosts"), hostName) {
			return true
		}
	}
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		if t := mapField(asMap(raw), "targets"); t != nil && contains(stringListField(t, "hosts"), hostName) {
			return true
		}
	}
	for _, raw := range listField(mapField(root, "sudo"), "rules") {
		if t := mapField(asMap(raw), "targets"); t != nil && contains(stringListField(t, "hosts"), hostName) {
			return true
		}
	}
	return false
}

// ---- map-world cascade mutation (feeds SimulateRemoveRosterHost only) ----

// cascadeRemoveHostReferences prunes hostName from every hostgroup/
// netgroup's membership.hosts and every HBAC/sudo rule's targets.hosts, in
// place on root (map-world, Simulate*-only — mirrors
// cascadeRemoveGroupReferences one level down: only this host's own
// membership/target entry is pruned, never the containing hostgroup/
// netgroup/rule object itself).
func cascadeRemoveHostReferences(root map[string]any, hostName string) []RosterReference {
	var removed []RosterReference
	for _, raw := range listField(root, "hostgroups") {
		hg := asMap(raw)
		if m := mapField(hg, "membership"); m != nil {
			if hosts := stringListField(m, "hosts"); contains(hosts, hostName) {
				m["hosts"] = removeStringValue(hosts, hostName)
				removed = append(removed, RosterReference{Kind: "hostgroup membership", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("hostgroups[%s].membership.hosts", stringField(hg, "name"))})
			}
		}
	}
	for _, raw := range listField(root, "netgroups") {
		ng := asMap(raw)
		if m := mapField(ng, "membership"); m != nil {
			if hosts := stringListField(m, "hosts"); contains(hosts, hostName) {
				m["hosts"] = removeStringValue(hosts, hostName)
				removed = append(removed, RosterReference{Kind: "netgroup membership", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("netgroups[%s].membership.hosts", stringField(ng, "name"))})
			}
		}
	}
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		r := asMap(raw)
		if t := mapField(r, "targets"); t != nil {
			if hosts := stringListField(t, "hosts"); contains(hosts, hostName) {
				t["hosts"] = removeStringValue(hosts, hostName)
				removed = append(removed, RosterReference{Kind: "hbac target", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("hbac.rules[%s].targets.hosts", stringField(r, "name"))})
			}
		}
	}
	for _, raw := range listField(mapField(root, "sudo"), "rules") {
		r := asMap(raw)
		if t := mapField(r, "targets"); t != nil {
			if hosts := stringListField(t, "hosts"); contains(hosts, hostName) {
				t["hosts"] = removeStringValue(hosts, hostName)
				removed = append(removed, RosterReference{Kind: "sudo target", Cascade: RosterReferenceCascadeRemovable, Path: fmt.Sprintf("sudo.rules[%s].targets.hosts", stringField(r, "name"))})
			}
		}
	}
	sortRosterReferences(removed)
	return removed
}

// ---- yaml.Node-world mutation (RemoveRosterHostReferences/SetRosterHostAbsent only) ----

// removeHostReferencesFromNode deletes every cascadeable reference to
// hostName from top's hostgroups/netgroups/hbac/sudo sections, in place.
// It never touches top's own "hosts" sequence (that convergence is
// SetRosterHostAbsent's job) and never deletes a hostgroup/netgroup/HBAC/
// sudo rule object itself, only hostName's membership/target entry in it.
func removeHostReferencesFromNode(top *yaml.Node, hostName string) {
	for _, entry := range sequenceEntries(top, "hostgroups") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "membership", "hosts"), hostName)
	}
	for _, entry := range sequenceEntries(top, "netgroups") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "membership", "hosts"), hostName)
	}
	hbac := findMappingChild(top, "hbac")
	for _, entry := range sequenceEntries(hbac, "rules") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "targets", "hosts"), hostName)
	}
	sudo := findMappingChild(top, "sudo")
	for _, entry := range sequenceEntries(sudo, "rules") {
		removeScalarFromNodeSequence(findNestedSequence(entry, "targets", "hosts"), hostName)
	}
}

// RemoveRosterHostReferences prunes every direct hostgroup/netgroup/HBAC/
// sudo reference to hostName from the roster at path via yaml.Node
// surgery (spec.md §16.4) — the same formatting-preserving technique
// RemoveRosterUser/Group use. It does NOT touch hostName's own hosts[]
// entry (see SetRosterHostAbsent, a deliberately separate call so a
// caller can inspect/persist each step of the saga independently — spec.md
// §16.3's required order prunes references before the host object itself
// converges) and never deletes a hostgroup/netgroup/HBAC/sudo rule object,
// only hostName's membership/target entry within each. Refuses to write
// (fail-closed) if the resulting roster would not validate.
func RemoveRosterHostReferences(path, hostName string) error {
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

	removeHostReferencesFromNode(top, hostName)

	violations, err := validateRosterNode(top)
	if err != nil {
		return fmt.Errorf("roster %s: %w", path, err)
	}
	if len(violations) > 0 {
		return fmt.Errorf("roster %s: candidate would be invalid after removing host %q's references: %s", path, hostName, violations[0].String())
	}

	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("render roster %s: %w", path, err)
	}
	return os.WriteFile(path, rendered, 0o600)
}

// SetRosterHostAbsent converges hostName's canonical hosts[] entry to
// state: absent (spec.md §16.3/§16.4) — a declarative tombstone, mirroring
// how grants/netgroups/HBAC/sudo rules already represent "convergent
// delete" in this schema (SetRosterGrant's own doc comment), never a
// physical removal of the hosts[] entry itself.
// playbooks/apply/freeipa-identity-apply.yml's absent-host section is what
// completes the deletion server-side (host-del) once this state is
// written and its own direct references have already been pruned (see
// RemoveRosterHostReferences — call that first). Errors rather than
// guessing if hostName doesn't exist or is ambiguous.
func SetRosterHostAbsent(path, hostName string) error {
	root, err := readRosterAsMap(path)
	if err != nil {
		return err
	}
	hosts := listField(root, "hosts")
	idx, ambiguous := findNamedEntry(hosts, hostName)
	if ambiguous {
		return fmt.Errorf("roster %s: host %q is ambiguous (more than one host entry already has it); fix the duplicate by hand first", path, hostName)
	}
	if idx < 0 {
		return fmt.Errorf("roster %s: no host entry named %q", path, hostName)
	}

	updated := map[string]any{}
	for k, v := range asMap(hosts[idx]) {
		updated[k] = v
	}
	updated["state"] = "absent"
	return replaceTopLevelRosterEntry(path, "hosts", hostName, updated)
}
