package inventory

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// internalEndpointManifestStub is the skeleton CreateMinimalInternalEndpointManifest
// writes — no endpoints yet, matching spec.md §9's schema exactly. Unlike
// the freeipa-dns manifest, internal-endpoints.yaml declares no
// freeipa.{domain,realm,server} identity block of its own (spec.md §8/§9),
// so there is nothing to prompt for beyond the path itself.
type internalEndpointManifestStub struct {
	SchemaVersion int                          `yaml:"schema_version"`
	Defaults      internalEndpointStubDefaults `yaml:"defaults"`
	Safety        internalEndpointStubSafety   `yaml:"safety"`
	Endpoints     []any                        `yaml:"endpoints"`
}

type internalEndpointStubDefaults struct {
	DNS internalEndpointStubDNSDefaults `yaml:"dns"`
}

type internalEndpointStubDNSDefaults struct {
	TTL int `yaml:"ttl"`
}

type internalEndpointStubSafety struct {
	AllowEndpointDelete bool `yaml:"allow_endpoint_delete"`
}

// CreateMinimalInternalEndpointManifest writes a brand-new, schema-valid
// internal-endpoints manifest with no endpoints declared yet. Refuses to
// overwrite an existing file — same create-only posture as
// CreateMinimalDNSManifest/WriteMinimalRosterSkeleton.
func CreateMinimalInternalEndpointManifest(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("internal-endpoints manifest %s already exists", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat internal-endpoints manifest %s: %w", path, err)
	}
	stub := internalEndpointManifestStub{
		SchemaVersion: 1,
		Defaults:      internalEndpointStubDefaults{DNS: internalEndpointStubDNSDefaults{TTL: 300}},
		Safety:        internalEndpointStubSafety{AllowEndpointDelete: false},
		Endpoints:     []any{},
	}
	rendered, err := yaml.Marshal(stub)
	if err != nil {
		return fmt.Errorf("encode internal-endpoints manifest: %w", err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return fmt.Errorf("write internal-endpoints manifest %s: %w", path, err)
	}
	return nil
}

// InternalEndpointManifestFQDNs returns every endpoint fqdn in the manifest
// at path, in file order — for display only.
func InternalEndpointManifestFQDNs(path string) ([]string, error) {
	root, err := LoadInternalEndpointManifest(path)
	if err != nil {
		return nil, err
	}
	endpoints := listField(root, "endpoints")
	out := make([]string, 0, len(endpoints))
	for _, raw := range endpoints {
		out = append(out, stringField(asMap(raw), "fqdn"))
	}
	return out, nil
}

// InternalEndpointManifestEndpoint returns one endpoint's full field map,
// matched by its canonical FQDN (the manifest's own primary key, spec.md
// §10.2) — the raw manifest fqdn field, not lower/trim-normalized, since
// this is a read of what's literally on disk for TUI display/editing.
func InternalEndpointManifestEndpoint(path, fqdn string) (fields map[string]any, found bool, err error) {
	root, err := LoadInternalEndpointManifest(path)
	if err != nil {
		return nil, false, err
	}
	endpoints := listField(root, "endpoints")
	idx, _ := findFQDNEntry(endpoints, fqdn)
	if idx < 0 {
		return nil, false, nil
	}
	return asMap(endpoints[idx]), true, nil
}

// SimulateAddInternalEndpoint reports what ValidateInternalEndpointManifest
// would say about the manifest at path if endpoint were appended to
// endpoints: — without writing anything. Callers should only call
// AppendInternalEndpoint once this returns zero violations.
func SimulateAddInternalEndpoint(path string, endpoint map[string]any, opts InternalEndpointValidateOptions) ([]InternalEndpointViolation, error) {
	root, err := LoadInternalEndpointManifest(path)
	if err != nil {
		return nil, err
	}
	root["endpoints"] = append(listField(root, "endpoints"), endpoint)
	return ValidateInternalEndpointManifest(root, opts), nil
}

// SimulateSetInternalEndpoint is SimulateAddInternalEndpoint's edit
// counterpart: reports what ValidateInternalEndpointManifest would say if
// the endpoint identified by fqdn were replaced by updated. found=false
// means no such endpoint exists; a non-nil err (not a violation) means
// fqdn is ambiguous — more than one endpoint already shares it, a
// pre-existing corruption this refuses to guess through.
func SimulateSetInternalEndpoint(path, fqdn string, updated map[string]any, opts InternalEndpointValidateOptions) (violations []InternalEndpointViolation, found bool, err error) {
	root, err := LoadInternalEndpointManifest(path)
	if err != nil {
		return nil, false, err
	}
	endpoints := listField(root, "endpoints")
	idx, ambiguous := findFQDNEntry(endpoints, fqdn)
	if ambiguous {
		return nil, true, fmt.Errorf("internal-endpoints manifest %s: fqdn %q is ambiguous (fix the duplicate by hand first)", path, fqdn)
	}
	if idx < 0 {
		return nil, false, nil
	}
	endpoints[idx] = updated
	root["endpoints"] = endpoints
	return ValidateInternalEndpointManifest(root, opts), true, nil
}

// AppendInternalEndpoint appends endpoint to the manifest's endpoints: list
// via yaml.Node surgery, preserving all other content exactly — same
// technique as freeipa_dns_write.go's AppendDNSZone, one level shallower
// (endpoints live at the document top level, not nested under a namespace
// key like freeipa-dns's dns:). Callers should run
// SimulateAddInternalEndpoint first and only call this once it reports no
// violations.
func AppendInternalEndpoint(path string, endpoint map[string]any) error {
	root, top, err := loadInternalEndpointYAMLDoc(path)
	if err != nil {
		return err
	}
	endpointsNode := mappingChild(top, "endpoints", yaml.SequenceNode, "!!seq")
	var entryNode yaml.Node
	if err := entryNode.Encode(endpoint); err != nil {
		return fmt.Errorf("encode internal-endpoints manifest endpoint: %w", err)
	}
	endpointsNode.Content = append(endpointsNode.Content, &entryNode)
	return writeInternalEndpointYAMLDoc(path, root)
}

// SetInternalEndpoint replaces the named endpoint's entry (matched by
// fqdn) via yaml.Node surgery. Callers should run
// SimulateSetInternalEndpoint first — see SetDNSZone's doc comment for the
// two trade-offs this shares with every "replace, not append" write:
// yaml.v3 alphabetizes the replaced entry's fields, and any inline
// comment/anchor specific to that entry is lost.
func SetInternalEndpoint(path, fqdn string, updated map[string]any) error {
	root, top, err := loadInternalEndpointYAMLDoc(path)
	if err != nil {
		return err
	}
	endpointsNode := findMappingChild(top, "endpoints")
	if endpointsNode == nil || endpointsNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("internal-endpoints manifest %s: no endpoints list", path)
	}
	idx, err := findSequenceItemIndexByField(endpointsNode, "fqdn", fqdn)
	if err != nil {
		return fmt.Errorf("internal-endpoints manifest %s: %w", path, err)
	}
	if idx < 0 {
		return fmt.Errorf("internal-endpoints manifest %s: no endpoint with fqdn %q", path, fqdn)
	}
	var entryNode yaml.Node
	if err := entryNode.Encode(updated); err != nil {
		return fmt.Errorf("encode internal-endpoints manifest endpoint: %w", err)
	}
	endpointsNode.Content[idx] = &entryNode
	return writeInternalEndpointYAMLDoc(path, root)
}

// ---- yaml.Node surgery primitives --------------------------------------

// loadInternalEndpointYAMLDoc reads path and returns both the document node
// (for re-marshaling) and its top-level mapping node (for
// mappingChild/findMappingChild navigation) — the internal-endpoints
// counterpart of freeipa_dns_write.go's loadDNSYAMLDoc.
func loadInternalEndpointYAMLDoc(path string) (root *yaml.Node, top *yaml.Node, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	root = &yaml.Node{}
	if err := yaml.Unmarshal(data, root); err != nil {
		return nil, nil, fmt.Errorf("parse internal-endpoints manifest %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("internal-endpoints manifest %s: expected a top-level YAML mapping", path)
	}
	return root, root.Content[0], nil
}

func writeInternalEndpointYAMLDoc(path string, root *yaml.Node) error {
	rendered, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("render internal-endpoints manifest %s: %w", path, err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return fmt.Errorf("write internal-endpoints manifest %s: %w", path, err)
	}
	return nil
}

// findFQDNEntry is roster.go's findNamedEntry, keyed on "fqdn" instead of
// "name" — internal-endpoints.yaml's primary key (spec.md §10.2).
func findFQDNEntry(list []any, fqdn string) (idx int, ambiguous bool) {
	idx = -1
	for i, raw := range list {
		if stringField(asMap(raw), "fqdn") == fqdn {
			if idx >= 0 {
				return idx, true
			}
			idx = i
		}
	}
	return idx, false
}
