package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrRosterEncrypted is returned by the roster helpers below when the file
// at the given path is an ansible-vault-encrypted blob rather than plain
// YAML. Callers should treat this as "cannot verify" — not as a missing-nfs
// violation and not as license to rewrite the file — since Go has no vault
// password to look inside it here; the roster may well already be correct.
var ErrRosterEncrypted = errors.New("inventory: roster file is ansible-vault encrypted, cannot inspect without a vault password")

// rosterHead is a read-only partial decode of just the fields the nfs:
// auto-completion needs — never remarshaled as a whole, so it can't lose or
// reorder any of the roster's other content (users/groups/hbac/sudo/...).
type rosterHead struct {
	FreeIPA struct {
		Domain string `yaml:"domain"`
	} `yaml:"freeipa"`
	NFS struct {
		Servers []struct {
			ServicePrincipal struct {
				Principal string `yaml:"principal"`
			} `yaml:"service_principal"`
		} `yaml:"servers"`
	} `yaml:"nfs"`
}

// FreeIPADomain reads the deployment domain from group_vars/freeipa.yml.
// The domain is inventory configuration, not roster data; keeping this
// lookup here lets controller-side helpers derive FQDNs without duplicating
// the value in .vault/ipa-identity.yaml.
func FreeIPADomain(workspaceDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(workspaceDir, "group_vars", "freeipa.yml"))
	if err != nil {
		return "", err
	}
	var vars map[string]any
	if err := yaml.Unmarshal(data, &vars); err != nil {
		return "", fmt.Errorf("parse FreeIPA group vars: %w", err)
	}
	domain, _ := vars["freeipa_domain"].(string)
	if strings.TrimSpace(domain) == "" {
		return "", fmt.Errorf("freeipa_domain is missing from group_vars/freeipa.yml")
	}
	return strings.TrimSpace(domain), nil
}

func readRosterHead(path string) (rosterHead, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return rosterHead{}, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return rosterHead{}, ErrRosterEncrypted
	}
	var head rosterHead
	if err := yaml.Unmarshal(data, &head); err != nil {
		return rosterHead{}, fmt.Errorf("parse roster %s: %w", path, err)
	}
	return head, nil
}

// RosterDomain returns the roster's freeipa.domain field.
func RosterDomain(path string) (string, error) {
	head, err := readRosterHead(path)
	if err != nil {
		return "", err
	}
	return head.FreeIPA.Domain, nil
}

// RosterHostFQDN derives the NFS service principal FQDN pilot assumes for a
// host: <inventory hostname>.<roster's freeipa.domain>. This matches every
// case seen in this codebase's fixtures but is an assumption — if a host's
// real ansible_fqdn differs, an auto-generated stub needs manual correction.
func RosterHostFQDN(hostName, domain string) string {
	return hostName + "." + domain
}

// RosterHasNFSServer reports whether the roster at path already has an
// nfs.servers entry whose service_principal.principal matches "nfs/<fqdn>".
func RosterHasNFSServer(path, fqdn string) (bool, error) {
	head, err := readRosterHead(path)
	if err != nil {
		return false, err
	}
	want := "nfs/" + fqdn
	for _, s := range head.NFS.Servers {
		if s.ServicePrincipal.Principal == want {
			return true, nil
		}
	}
	return false, nil
}

// nfsServerStub mirrors playbooks/apply/freeipa-identity.roster.example.yaml's
// nfs.servers[] entry shape (field order matches the example exactly).
// shares is intentionally left empty — actual NFS share definitions
// (paths/ACLs) are genuine site-specific content, explicitly out of scope
// for auto-generation; this stub only supplies what
// freeipa-nfs-server-apply.yml's gate needs to stop crashing on an
// undefined nfs: key.
type nfsServerStub struct {
	Host             string              `yaml:"host"`
	State            string              `yaml:"state"`
	ServicePrincipal nfsServicePrincipal `yaml:"service_principal"`
	Shares           []map[string]any    `yaml:"shares"`
}

type nfsServicePrincipal struct {
	Ensure    bool   `yaml:"ensure"`
	Principal string `yaml:"principal"`
	Keytab    string `yaml:"keytab"`
}

// AppendMissingNFSServerStub appends a minimal, fully-derived nfs.servers
// entry for hostName to the roster at path if one matching its principal
// isn't already present. It never touches or reorders any existing content
// — appended=false, nil means the roster already had a matching entry.
// ErrRosterEncrypted is returned unchanged (via RosterHasNFSServer)
// when the file can't be inspected at all, so callers can tell "nothing to
// do" apart from "couldn't check."
func AppendMissingNFSServerStub(path, hostName, domain string) (appended bool, err error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false, fmt.Errorf("FreeIPA domain is required from group_vars/freeipa.yml")
	}
	fqdn := RosterHostFQDN(hostName, domain)
	has, err := RosterHasNFSServer(path, fqdn)
	if err != nil {
		return false, err
	}
	if has {
		return false, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("parse roster %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return false, fmt.Errorf("roster %s: expected a top-level YAML mapping", path)
	}
	top := root.Content[0]

	nfsNode := mappingChild(top, "nfs", yaml.MappingNode, "!!map")
	serversNode := mappingChild(nfsNode, "servers", yaml.SequenceNode, "!!seq")

	stub := nfsServerStub{
		Host:  fqdn,
		State: "present",
		ServicePrincipal: nfsServicePrincipal{
			Ensure:    true,
			Principal: "nfs/" + fqdn,
			Keytab:    "/etc/krb5.keytab",
		},
		Shares: []map[string]any{},
	}
	var entryNode yaml.Node
	if err := entryNode.Encode(stub); err != nil {
		return false, fmt.Errorf("encode nfs server stub: %w", err)
	}
	entryNode.HeadComment = "auto-generated from inventory hostname + roster domain — adjust if this host's real FQDN differs"
	serversNode.Content = append(serversNode.Content, &entryNode)

	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return false, fmt.Errorf("render roster %s: %w", path, err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return false, fmt.Errorf("write roster %s: %w", path, err)
	}
	return true, nil
}

// mappingChild finds mapNode's child value for key, creating it (and the
// key, as an empty node of the given kind/tag) if absent. Used to
// locate-or-create nfs: (a mapping) and nfs.servers: (a sequence) without
// disturbing any other key already present.
func mappingChild(mapNode *yaml.Node, key string, kind yaml.Kind, tag string) *yaml.Node {
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			return mapNode.Content[i+1]
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: kind, Tag: tag}
	mapNode.Content = append(mapNode.Content, keyNode, valNode)
	return valNode
}

// findMappingChild is mappingChild's read-only sibling: it never creates a
// missing key, since replaceTopLevelRosterEntry treats "nothing to replace"
// as an error, not something to scaffold.
func findMappingChild(mapNode *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			return mapNode.Content[i+1]
		}
	}
	return nil
}

// readRosterAsMap reads and generically decodes the roster at path — the
// same read-only, cannot-lose-content posture as readRosterHead/
// ValidateRosterFile, just decoded as a plain map instead of a fixed
// struct or yaml.Node tree, for the append-simulation helpers below.
func readRosterAsMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return nil, ErrRosterEncrypted
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse roster %s: %w", path, err)
	}
	return root, nil
}

// RosterUserNames returns every user name in the roster at path, in file
// order — for display only (see ValidateRosterFile for real validation).
func RosterUserNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(root, "users")), nil
}

// RosterGroupNames returns every group name in the roster at path, in file
// order — for display only.
func RosterGroupNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(root, "groups")), nil
}

// RosterHostgroupNames returns every canonical hostgroup name in file order.
func RosterHostgroupNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(root, "hostgroups")), nil
}

// RosterHostgroup returns one canonical hostgroup entry.
func RosterHostgroup(path, name string) (map[string]any, bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	entries := listField(root, "hostgroups")
	idx, _ := findNamedEntry(entries, name)
	if idx < 0 {
		return nil, false, nil
	}
	return asMap(entries[idx]), true, nil
}

// RosterHBACRuleNames returns canonical HBAC rule names in file order.
func RosterHBACRuleNames(path string) ([]string, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(mapField(root, "hbac"), "rules")), nil
}

// RosterHBACRule returns one canonical HBAC rule entry.
func RosterHBACRule(path, name string) (map[string]any, bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	entries := listField(mapField(root, "hbac"), "rules")
	idx, _ := findNamedEntry(entries, name)
	if idx < 0 {
		return nil, false, nil
	}
	return asMap(entries[idx]), true, nil
}

func RosterHBACDisableAllowAll(path string) (bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return false, err
	}
	return boolFieldDefault(mapField(root, "hbac"), "disable_allow_all", false), nil
}

func SetRosterHBACDisableAllowAll(path string, value bool) error {
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
	hbac := mappingChild(root.Content[0], "hbac", yaml.MappingNode, "!!map")
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "disable_allow_all"}
	val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprintf("%t", value)}
	for i := 0; i+1 < len(hbac.Content); i += 2 {
		if hbac.Content[i].Value == "disable_allow_all" {
			hbac.Content[i+1] = val
			goto render
		}
	}
	hbac.Content = append(hbac.Content, key, val)
render:
	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return os.WriteFile(path, rendered, 0o600)
}

func SimulateSetRosterHostgroup(path, name string, updated map[string]any) ([]RosterViolation, bool, error) {
	return simulateSetRosterNested(path, "hostgroups", name, updated, "hostgroup")
}

func SimulateSetRosterHBACRule(path, name string, updated map[string]any) ([]RosterViolation, bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	hbac := mapField(root, "hbac")
	rules := listField(hbac, "rules")
	idx, ambiguous := findNamedEntry(rules, name)
	if ambiguous {
		return nil, true, fmt.Errorf("roster %s: HBAC rule %q is ambiguous", path, name)
	}
	if idx < 0 {
		return nil, false, nil
	}
	rules[idx] = updated
	hbac["rules"] = rules
	root["hbac"] = hbac
	return ValidateRoster(root), true, nil
}

func AppendRosterHostgroup(path, name string) error {
	return appendTopLevelRosterEntry(path, "hostgroups", map[string]any{
		"name": name, "state": "present", "description": name,
		"membership": map[string]any{"authoritative": true, "hosts": []string{}, "hostgroups": []string{}},
	})
}

func AppendRosterHBACRule(path string, rule map[string]any) error {
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
	hbac := mappingChild(top, "hbac", yaml.MappingNode, "!!map")
	rules := mappingChild(hbac, "rules", yaml.SequenceNode, "!!seq")
	var node yaml.Node
	if err := node.Encode(rule); err != nil {
		return err
	}
	rules.Content = append(rules.Content, &node)
	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return os.WriteFile(path, rendered, 0o600)
}

func SimulateAddRosterHBACRule(path string, rule map[string]any) ([]RosterViolation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	hbac := mapField(root, "hbac")
	if hbac == nil {
		// mapField returns nil, not an empty map, when "hbac" is absent
		// (e.g. a roster that has never had an HBAC rule before) —
		// assigning into a nil map panics, so it must be initialized
		// before the "rules" write below.
		hbac = map[string]any{}
	}
	hbac["rules"] = append(listField(hbac, "rules"), rule)
	root["hbac"] = hbac
	return ValidateRoster(root), nil
}

func SetRosterHostgroup(path, name string, updated map[string]any) error {
	return replaceTopLevelRosterEntry(path, "hostgroups", name, updated)
}

func SetRosterHBACRule(path, name string, updated map[string]any) error {
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
	top := root.Content[0]
	hbac := findMappingChild(top, "hbac")
	if hbac == nil {
		return fmt.Errorf("roster %s: no hbac map", path)
	}
	rules := findMappingChild(hbac, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return fmt.Errorf("roster %s: no hbac.rules list", path)
	}
	idx := -1
	for i, item := range rules.Content {
		var m map[string]any
		if err := item.Decode(&m); err != nil {
			return err
		}
		if stringField(m, "name") == name {
			if idx >= 0 {
				return fmt.Errorf("roster %s: HBAC rule %q is ambiguous", path, name)
			}
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("roster %s: no HBAC rule named %q", path, name)
	}
	var node yaml.Node
	if err := node.Encode(updated); err != nil {
		return err
	}
	rules.Content[idx] = &node
	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return os.WriteFile(path, rendered, 0o600)
}

func simulateSetRosterNested(path, listKey, name string, updated map[string]any, kind string) ([]RosterViolation, bool, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	entries := listField(root, listKey)
	idx, ambiguous := findNamedEntry(entries, name)
	if ambiguous {
		return nil, true, fmt.Errorf("roster %s: %s %q is ambiguous", path, kind, name)
	}
	if idx < 0 {
		return nil, false, nil
	}
	entries[idx] = updated
	root[listKey] = entries
	return ValidateRoster(root), true, nil
}

// findNamedEntry returns the index of the entry named name within list (a
// users[]/groups[]-shaped []any of map[string]any decodes), or -1 if none
// match. ambiguous is true when more than one entry already shares the
// name — a pre-existing corruption ValidateRoster's "unique user/group
// names" rule would already flag; the write path (SimulateSetRosterUser/
// Group, SetRosterUser/Group) treats this as its own error rather than
// guessing which entry was meant. The read path (RosterUser/RosterGroup
// below) is display-only, so it just takes the first match.
func findNamedEntry(list []any, name string) (idx int, ambiguous bool) {
	idx = -1
	for i, raw := range list {
		if stringField(asMap(raw), "name") == name {
			if idx >= 0 {
				return idx, true
			}
			idx = i
		}
	}
	return idx, false
}

// RosterUser returns the named user's full field map, exactly as
// readRosterAsMap already decodes it (matching the shape
// roster_validate.go's checkUsers reads: name/state/first/last/
// display_name/email/uid/gid/login_shell/home_directory/password/
// ssh_keys/enabled). found=false when no such user exists.
func RosterUser(path, name string) (fields map[string]any, found bool, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	users := listField(root, "users")
	idx, _ := findNamedEntry(users, name)
	if idx < 0 {
		return nil, false, nil
	}
	return asMap(users[idx]), true, nil
}

// RosterGroup is RosterUser's group counterpart.
func RosterGroup(path, name string) (fields map[string]any, found bool, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	groups := listField(root, "groups")
	idx, _ := findNamedEntry(groups, name)
	if idx < 0 {
		return nil, false, nil
	}
	return asMap(groups[idx]), true, nil
}

// SimulateAddRosterUser reports what ValidateRoster would say about the
// roster at path if name were added as a minimal user stub (name + state:
// present only, matching AppendRosterUser exactly) — without writing
// anything. Callers should only call AppendRosterUser once this returns no
// violations, so a roster never gets a mutation that would fail
// freeipa-identity-apply.yml's real gates.
func SimulateAddRosterUser(path, name string) ([]RosterViolation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	root["users"] = append(listField(root, "users"), map[string]any{"name": name, "state": "present", "enabled": true})
	return ValidateRoster(root), nil
}

// SimulateAddRosterGroup is SimulateAddRosterUser's group counterpart —
// see AppendRosterGroup for the stub shape this mirrors.
func SimulateAddRosterGroup(path, name, category string) ([]RosterViolation, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	root["groups"] = append(listField(root, "groups"), map[string]any{"name": name, "state": "present", "category": category})
	return ValidateRoster(root), nil
}

// SimulateSetRosterUser reports what ValidateRoster would say about the
// roster at path if the named user's entry were replaced by updated —
// without writing anything. found=false means no such user exists. err is
// non-nil (not a violation) when name is ambiguous — more than one user
// already shares it, a pre-existing corruption this refuses to guess
// through rather than silently picking one. Callers should only call
// SetRosterUser once this returns no violations.
func SimulateSetRosterUser(path, name string, updated map[string]any) (violations []RosterViolation, found bool, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	users := listField(root, "users")
	idx, ambiguous := findNamedEntry(users, name)
	if ambiguous {
		return nil, true, fmt.Errorf("roster %s: name %q is ambiguous (more than one user already has it); fix the duplicate by hand first", path, name)
	}
	if idx < 0 {
		return nil, false, nil
	}
	users[idx] = updated
	root["users"] = users
	return ValidateRoster(root), true, nil
}

// SimulateSetRosterGroup is SimulateSetRosterUser's group counterpart.
func SimulateSetRosterGroup(path, name string, updated map[string]any) (violations []RosterViolation, found bool, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, false, err
	}
	groups := listField(root, "groups")
	idx, ambiguous := findNamedEntry(groups, name)
	if ambiguous {
		return nil, true, fmt.Errorf("roster %s: name %q is ambiguous (more than one group already has it); fix the duplicate by hand first", path, name)
	}
	if idx < 0 {
		return nil, false, nil
	}
	groups[idx] = updated
	root["groups"] = groups
	return ValidateRoster(root), true, nil
}

// rosterUserStub is the minimal, valid shape AppendRosterUser writes —
// every other user field (email/ssh_keys/password/...) is optional per
// the roster schema and left for the operator to fill in by hand
// afterward; see freeipa-identity.roster.example.yaml for the full shape.
// Enabled is written explicitly (mirroring the HBAC/sudo rule stubs) rather
// than left absent: freeipa-identity-apply.yml defaults a missing `enabled`
// to true, but the roster manager's own detail screen displayed the field
// as "false" when absent — a brand-new user showed as disabled in the
// editor while reconcile actually left them enabled (confirmed live against
// a real FreeIPA server: kinit succeeded). Writing it explicitly keeps the
// persisted value and the editor's display in agreement.
type rosterUserStub struct {
	Name    string `yaml:"name"`
	State   string `yaml:"state"`
	Enabled bool   `yaml:"enabled"`
}

// rosterGroupStub is AppendRosterGroup's minimal, valid shape — category
// is required (it drives the name-prefix gate), everything else optional.
type rosterGroupStub struct {
	Name     string `yaml:"name"`
	State    string `yaml:"state"`
	Category string `yaml:"category"`
}

// AppendRosterUser appends a minimal user stub to the roster's top-level
// users: list, preserving all other content exactly (yaml.Node surgery,
// same technique as AppendMissingNFSServerStub — never a full-struct
// remarshal, so nothing else in the file is disturbed). Callers should run
// SimulateAddRosterUser first and only call this once it reports no
// violations — this function does not validate anything itself.
func AppendRosterUser(path, name string) error {
	return appendTopLevelRosterEntry(path, "users", rosterUserStub{Name: name, State: "present", Enabled: true})
}

// AppendRosterGroup is AppendRosterUser's group counterpart. See
// SimulateAddRosterGroup.
func AppendRosterGroup(path, name, category string) error {
	return appendTopLevelRosterEntry(path, "groups", rosterGroupStub{Name: name, State: "present", Category: category})
}

func appendTopLevelRosterEntry(path, listKey string, stub any) error {
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
	listNode := mappingChild(top, listKey, yaml.SequenceNode, "!!seq")

	var entryNode yaml.Node
	if err := entryNode.Encode(stub); err != nil {
		return fmt.Errorf("encode roster %s entry: %w", listKey, err)
	}
	listNode.Content = append(listNode.Content, &entryNode)

	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("render roster %s: %w", path, err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return fmt.Errorf("write roster %s: %w", path, err)
	}
	return nil
}

// SetRosterUser replaces the named user's entry in the roster at path with
// updated, via yaml.Node surgery — same technique as
// AppendMissingNFSServerStub/appendTopLevelRosterEntry, "replace at index"
// instead of "append": every other line in the file (formatting, comments,
// other users/groups/hbac/sudo/nfs/...) survives untouched. Two trade-offs
// specific to replacing an existing entry that appending never had: yaml.v3
// sorts map keys on Encode, so updated's fields render in alphabetical
// order regardless of how the original entry was ordered — deterministic,
// just visually different, not a bug; and any inline comment or anchor
// that lived on specifically this entry is lost (append only ever adds a
// brand-new node, so it never had anything to lose). Callers should run
// SimulateSetRosterUser first and only call this once it reports no
// violations — this function does not validate anything itself, and
// errors rather than guessing if name doesn't exist or is ambiguous.
func SetRosterUser(path, name string, updated map[string]any) error {
	return replaceTopLevelRosterEntry(path, "users", name, updated)
}

// SetRosterGroup is SetRosterUser's group counterpart.
func SetRosterGroup(path, name string, updated map[string]any) error {
	return replaceTopLevelRosterEntry(path, "groups", name, updated)
}

func replaceTopLevelRosterEntry(path, listKey, name string, updated map[string]any) error {
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

	listNode := findMappingChild(top, listKey)
	if listNode == nil || listNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("roster %s: no %s entry named %q (no %s: list)", path, listKey, name, listKey)
	}

	idx := -1
	for i, item := range listNode.Content {
		var m map[string]any
		if err := item.Decode(&m); err != nil {
			return fmt.Errorf("decode roster %s %s entry %d: %w", path, listKey, i, err)
		}
		if stringField(m, "name") != name {
			continue
		}
		if idx >= 0 {
			return fmt.Errorf("roster %s: name %q is ambiguous (more than one %s entry already has it); fix the duplicate by hand first", path, name, listKey)
		}
		idx = i
	}
	if idx < 0 {
		return fmt.Errorf("roster %s: no %s entry named %q", path, listKey, name)
	}

	var entryNode yaml.Node
	if err := entryNode.Encode(updated); err != nil {
		return fmt.Errorf("encode roster %s entry: %w", listKey, err)
	}
	listNode.Content[idx] = &entryNode

	rendered, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("render roster %s: %w", path, err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return fmt.Errorf("write roster %s: %w", path, err)
	}
	return nil
}
