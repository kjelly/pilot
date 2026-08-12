// roster_migrate.go implements the pure, filesystem-free half of the v1 ->
// v2 roster schema migration: transforming a parsed yaml.Node document and
// proving the transformation didn't change what the roster actually
// authorizes. Locking, backup, atomic replacement, and the CLI live in
// later phases — nothing here reads or writes a file.
package inventory

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// MigrateRosterV1ToV2 converts a parsed schema-v1 roster document (root is
// the *yaml.Node from yaml.Unmarshal(data, &root)) into schema v2, in
// memory only. The only unconditional structural changes are:
//
//	schema_version: 1 -> 2
//	netgroups: [] appended if absent
//	NFS client selectors normalized where needed to preserve old rendered
//	    output (see normalizeNFSClientSelectors)
//
// Every other node is left exactly as parsed: this mutates the existing
// yaml.Node tree in place rather than remarshaling through map[string]any,
// so comments, anchors/aliases, scalar style, and section/list order all
// survive untouched. Callers should validate root as v1 (ValidateRosterV1)
// before calling this, and the result as v2 (ValidateRosterV2) after.
func MigrateRosterV1ToV2(root *yaml.Node) (*yaml.Node, error) {
	top, err := rosterDocumentTop(root)
	if err != nil {
		return nil, fmt.Errorf("migrate roster: %w", err)
	}

	versionNode := findMappingChild(top, "schema_version")
	if versionNode == nil {
		return nil, fmt.Errorf("migrate roster: schema_version is missing")
	}
	n, err := strconv.Atoi(strings.TrimSpace(versionNode.Value))
	if err != nil {
		return nil, fmt.Errorf("migrate roster: schema_version %q is not an integer", versionNode.Value)
	}
	if RosterSchemaVersion(n) != RosterSchemaV1 {
		return nil, fmt.Errorf("migrate roster: MigrateRosterV1ToV2 requires schema_version: %d, got %d", RosterSchemaV1, n)
	}
	versionNode.Value = strconv.Itoa(int(RosterSchemaV2))
	versionNode.Tag = "!!int"
	versionNode.Style = 0

	// mappingChild no-ops if netgroups already exists rather than
	// duplicating the key; a valid v1 document never has one (netgroups
	// fails closed as an unknown top-level key under ValidateRosterV1), but
	// staying idempotent here costs nothing.
	mappingChild(top, "netgroups", yaml.SequenceNode, "!!seq")

	normalizeNFSClientSelectors(top)

	return root, nil
}

// rosterDocumentTop returns doc's top-level mapping node, the same
// "document node -> mapping node" unwrap AppendMissingNFSServerStub and
// loadDNSYAMLDoc each inline for themselves.
func rosterDocumentTop(doc *yaml.Node) (*yaml.Node, error) {
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected a top-level YAML mapping")
	}
	return doc.Content[0], nil
}

// normalizeNFSClientSelectors walks nfs.servers[].shares[].export.clients[]
// and rewrites each entry's type per the v1 -> v2 migration rule (see
// RenderNFSClientSelector): v1 rendering ignored type entirely and always
// printed the bare value, so only "network" and "host" survive migration
// unchanged — those are the only two types that still render as a bare
// value under the v2 type-aware renderer. Every other type (missing,
// unrecognized, or a hand-written "hostgroup"/"netgroup" that v1 never
// actually acted on) becomes "raw", which also renders as a bare value,
// preserving the old output exactly. A section that doesn't exist at any
// level is left alone — a roster without nfs.servers has nothing to do
// here.
func normalizeNFSClientSelectors(top *yaml.Node) {
	for _, serverNode := range sequenceChildren(findMappingChild(top, "nfs"), "servers") {
		for _, shareNode := range sequenceChildren(serverNode, "shares") {
			exportNode := findMappingChild(shareNode, "export")
			if exportNode == nil || exportNode.Kind != yaml.MappingNode {
				continue
			}
			for _, clientNode := range sequenceChildren(exportNode, "clients") {
				normalizeNFSClientSelectorNode(clientNode)
			}
		}
	}
}

// sequenceChildren returns mapNode.<key>'s sequence items, or nil if
// mapNode is nil or <key> isn't a sequence — the shared "descend one level,
// tolerate anything missing" step normalizeNFSClientSelectors repeats for
// nfs->servers, server->shares, and export->clients.
func sequenceChildren(mapNode *yaml.Node, key string) []*yaml.Node {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil
	}
	seq := findMappingChild(mapNode, key)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	return seq.Content
}

func normalizeNFSClientSelectorNode(clientNode *yaml.Node) {
	if clientNode.Kind != yaml.MappingNode {
		return
	}
	typeNode := findMappingChild(clientNode, "type")
	if typeNode != nil && (typeNode.Value == "network" || typeNode.Value == "host") {
		return
	}
	if typeNode == nil {
		typeNode = mappingChild(clientNode, "type", yaml.ScalarNode, "!!str")
	}
	typeNode.Kind = yaml.ScalarNode
	typeNode.Tag = "!!str"
	typeNode.Style = 0
	typeNode.Value = "raw"
}

// RenderNFSClientSelector implements the schema-v2 NFS client selector
// rendering contract (one shared rule for both the NFSv4 pseudo-root export
// and every individual share export — see
// playbooks/apply/templates/freeipa-nfs-exports.j2, which must apply the
// exact same mapping):
//
//	network   -> value
//	host      -> value
//	hostgroup -> @value
//	netgroup  -> @value
//	raw       -> value
//	anything else (including missing/empty) -> value, as a compatibility
//	    fallback for pre-v2 data this Go code has never seen before
func RenderNFSClientSelector(clientType, value string) string {
	switch clientType {
	case "hostgroup", "netgroup":
		return "@" + value
	default:
		return value
	}
}

// RosterSemanticFingerprint snapshots everything a v1 -> v2 migration must
// not change: every section listed in the roster-schema-v2 migration
// spec's semantic-equivalence guard. Two fingerprints being equal
// (RosterSemanticFingerprintsEqual) is migration's correctness gate. It
// deliberately excludes schema_version and netgroups — those are the only
// two differences a valid v1 -> v2 migration is allowed to introduce.
type RosterSemanticFingerprint struct {
	Users            any
	Groups           any
	Hosts            any
	Hostgroups       any
	FreeIPA          any
	NFSClients       any
	PolicyExceptions any

	EffectiveHBAC []EffectiveHBACAccess
	EffectiveSudo []EffectiveSudoAccess

	NFSServers []nfsServerFingerprint
}

type nfsServerFingerprint struct {
	Host             string
	State            string
	ServicePrincipal any
	Shares           []nfsShareFingerprint
}

type nfsShareFingerprint struct {
	Name            string
	State           string
	SourcePath      string
	Ownership       any
	ACL             any
	ExportOptions   []string
	RenderedClients []string
	Automount       any
}

// ComputeRosterSemanticFingerprint builds root's fingerprint. root is a
// plain map[string]any (e.g. from yaml.Unmarshal(data, &root)) — this never
// needs yaml.Node, since fingerprinting only reads values, never rewrites
// them preserving formatting.
func ComputeRosterSemanticFingerprint(root map[string]any) RosterSemanticFingerprint {
	fp := RosterSemanticFingerprint{
		Users:            root["users"],
		Groups:           root["groups"],
		Hosts:            root["hosts"],
		Hostgroups:       root["hostgroups"],
		FreeIPA:          root["freeipa"],
		NFSClients:       root["nfs_clients"],
		PolicyExceptions: root["policy_exceptions"],
		EffectiveHBAC:    EffectiveHBACAccessFromRoster(root),
		EffectiveSudo:    EffectiveSudoAccessFromRoster(root),
	}

	for _, rawServer := range listField(mapField(root, "nfs"), "servers") {
		server := asMap(rawServer)
		var shares []nfsShareFingerprint
		for _, rawShare := range listField(server, "shares") {
			share := asMap(rawShare)
			export := mapField(share, "export")

			var rendered []string
			for _, rawClient := range listField(export, "clients") {
				client := asMap(rawClient)
				rendered = append(rendered, RenderNFSClientSelector(stringField(client, "type"), stringField(client, "value")))
			}

			shares = append(shares, nfsShareFingerprint{
				Name:            stringField(share, "name"),
				State:           stateOrDefault(share, "present"),
				SourcePath:      stringField(share, "source_path"),
				Ownership:       share["ownership"],
				ACL:             share["acl"],
				ExportOptions:   stringListField(export, "options"),
				RenderedClients: rendered,
				Automount:       share["automount"],
			})
		}
		fp.NFSServers = append(fp.NFSServers, nfsServerFingerprint{
			Host:             stringField(server, "host"),
			State:            stateOrDefault(server, "present"),
			ServicePrincipal: server["service_principal"],
			Shares:           shares,
		})
	}

	return fp
}

// RosterSemanticFingerprintsEqual reports whether a and b represent
// identical authorization and NFS-export behavior. reflect.DeepEqual is
// sufficient: every field is built from values yaml.Unmarshal already
// decoded into map[string]any/[]any/string/bool, so there are no yaml.Node
// pointers or Go-map key orderings to normalize first — reflect.DeepEqual
// already ignores map iteration order and compares map/slice content.
func RosterSemanticFingerprintsEqual(a, b RosterSemanticFingerprint) bool {
	return reflect.DeepEqual(a, b)
}
