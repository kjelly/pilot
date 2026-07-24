package inventory

import (
	"errors"
	"fmt"
	"os"
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
// ErrRosterEncrypted is returned unchanged (via RosterDomain/RosterHasNFSServer)
// when the file can't be inspected at all, so callers can tell "nothing to
// do" apart from "couldn't check."
func AppendMissingNFSServerStub(path, hostName string) (appended bool, err error) {
	domain, err := RosterDomain(path)
	if err != nil {
		return false, err
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
