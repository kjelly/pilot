// roster_nfs_remove.go implements the roster-local half of host
// decommission's freeipa-nfs-server lifecycle completion (spec.md §20.2,
// Phase 6): converging an nfs.servers[] entry from state: present to
// state: absent, mirroring roster_host_remove.go's SetRosterHostAbsent
// split (Simulate* on a map-world decode reporting what WOULD happen; the
// yaml.Node-world mutator performing the real formatting-preserving
// write) — same idiom, one nesting level deeper (nfs.servers, not a
// top-level list) and matched by "host", not "name" (this schema's own
// primary key for an nfs.servers[] entry, see roster.go's
// nfsServerStub).
//
// Deliberately does NOT touch entry.shares — per spec.md §20.2/§20.3,
// share/export DEFINITIONS (paths, client ACLs) are not data, and
// leaving them declared-but-inactive (the whole point of state: absent)
// costs nothing and preserves the exact configuration a future re-add
// would restore; this package never deletes the actual NFS share data
// directories, which is out of scope for v1 entirely (spec.md §4).
package inventory

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SimulateRemoveRosterNFSServer reports what validating the roster at
// path would say if fqdn's nfs.servers[] entry (matched by
// service_principal.principal == "nfs/<fqdn>", the schema's own natural
// unique key, same as RosterHasNFSServer) were converged to state:
// absent — without writing anything. found=false means no such entry
// exists (nothing to do on the roster side).
func SimulateRemoveRosterNFSServer(path, fqdn string) (violations []RosterViolation, found bool, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	nfs := mapField(root, "nfs")
	servers := listField(nfs, "servers")
	idx, ambiguous := findNFSServerEntry(servers, fqdn)
	if ambiguous {
		return nil, true, fmt.Errorf("roster %s: nfs server %q is ambiguous (more than one entry already has it); fix the duplicate by hand first", path, fqdn)
	}
	if idx < 0 {
		return nil, false, nil
	}

	updated := map[string]any{}
	for k, v := range asMap(servers[idx]) {
		updated[k] = v
	}
	updated["state"] = "absent"
	servers[idx] = updated
	nfs["servers"] = servers
	root["nfs"] = nfs

	return ValidateRoster(root), true, nil
}

// RosterNFSServerAbsent reports whether fqdn's nfs.servers[] entry is
// already state: absent (or does not exist at all) — used by host
// decommission's step execution to avoid re-mutating an already-converged
// roster on resume (INV-9/HD18). A plain read, never a write.
func RosterNFSServerAbsent(path, fqdn string) (bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return false, err
	}
	servers := listField(mapField(root, "nfs"), "servers")
	idx, ambiguous := findNFSServerEntry(servers, fqdn)
	if ambiguous {
		return false, fmt.Errorf("roster %s: nfs server %q is ambiguous (more than one entry already has it); fix the duplicate by hand first", path, fqdn)
	}
	if idx < 0 {
		return true, nil
	}
	state, _ := asMap(servers[idx])["state"].(string)
	return state == "absent", nil
}

// findNFSServerEntry finds the nfs.servers[] entry whose
// service_principal.principal equals "nfs/<fqdn>" — this schema's own
// natural unique key (roster.go's RosterHasNFSServer uses the same
// match), since an nfs.servers[] entry has no separate "name" field the
// way hosts[]/hostgroups[]/users[] do (it is keyed by "host" for display,
// but the principal is what freeipa-nfs-server-apply.yml itself asserts
// must be unique per host, roster.go:118).
func findNFSServerEntry(servers []any, fqdn string) (idx int, ambiguous bool) {
	want := "nfs/" + fqdn
	idx = -1
	for i, raw := range servers {
		m := asMap(raw)
		sp := mapField(m, "service_principal")
		if stringField(sp, "principal") != want {
			continue
		}
		if idx >= 0 {
			return idx, true
		}
		idx = i
	}
	return idx, false
}

// SetRosterNFSServerAbsent converges fqdn's nfs.servers[] entry to
// state: absent via yaml.Node surgery (same technique as
// SetRosterHostAbsent, one level deeper: nfs: -> servers: rather than a
// top-level list). Callers should run SimulateRemoveRosterNFSServer
// first. Errors rather than guessing if fqdn doesn't exist or is
// ambiguous.
func SetRosterNFSServerAbsent(path, fqdn string) error {
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

	nfsNode := findMappingChild(top, "nfs")
	if nfsNode == nil {
		return fmt.Errorf("roster %s: no nfs entry for %q (no nfs: section)", path, fqdn)
	}
	serversNode := findMappingChild(nfsNode, "servers")
	if serversNode == nil || serversNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("roster %s: no nfs entry for %q (no nfs.servers: list)", path, fqdn)
	}

	want := "nfs/" + fqdn
	idx := -1
	for i, item := range serversNode.Content {
		var m map[string]any
		if err := item.Decode(&m); err != nil {
			return fmt.Errorf("decode roster %s nfs.servers entry %d: %w", path, i, err)
		}
		sp, _ := m["service_principal"].(map[string]any)
		principal, _ := sp["principal"].(string)
		if principal != want {
			continue
		}
		if idx >= 0 {
			return fmt.Errorf("roster %s: nfs server %q is ambiguous (more than one entry already has it); fix the duplicate by hand first", path, fqdn)
		}
		idx = i
	}
	if idx < 0 {
		return fmt.Errorf("roster %s: no nfs.servers entry for %q", path, fqdn)
	}

	var updated map[string]any
	if err := serversNode.Content[idx].Decode(&updated); err != nil {
		return fmt.Errorf("decode roster %s nfs.servers entry %d: %w", path, idx, err)
	}
	updated["state"] = "absent"

	var entryNode yaml.Node
	if err := entryNode.Encode(updated); err != nil {
		return fmt.Errorf("encode roster nfs.servers entry: %w", err)
	}
	serversNode.Content[idx] = &entryNode

	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("render roster %s: %w", path, err)
	}
	return os.WriteFile(path, rendered, 0o600)
}
