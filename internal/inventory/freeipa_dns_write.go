package inventory

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// dnsManifestStub is the skeleton CreateMinimalDNSManifest writes — no
// zones yet, matching docs/specs/freeipa-dns.md §4's schema exactly.
// domain/realm/server come from the caller (the deployment's own inventory
// group_vars), never invented here, since a mismatch fails closed before
// kinit (playbooks/apply/freeipa-dns-apply.yml's own gate).
type dnsManifestStub struct {
	SchemaVersion int                `yaml:"schema_version"`
	FreeIPA       dnsManifestFreeIPA `yaml:"freeipa"`
	DNS           dnsManifestDNS     `yaml:"dns"`
}

type dnsManifestFreeIPA struct {
	Domain string `yaml:"domain"`
	Realm  string `yaml:"realm"`
	Server string `yaml:"server"`
}

type dnsManifestDNS struct {
	Defaults dnsManifestDefaults `yaml:"defaults"`
	Safety   dnsManifestSafety   `yaml:"safety"`
	Zones    []any               `yaml:"zones"`
}

type dnsManifestDefaults struct {
	TTL         int    `yaml:"ttl"`
	RecordsMode string `yaml:"records_mode"`
}

type dnsManifestSafety struct {
	AllowShadowExistingZone bool `yaml:"allow_shadow_existing_zone"`
	AllowAuthoritativePrune bool `yaml:"allow_authoritative_prune"`
	AllowZoneDelete         bool `yaml:"allow_zone_delete"`
}

// CreateMinimalDNSManifest writes a brand-new, schema-valid freeipa-dns
// manifest with no zones declared yet. Refuses to overwrite an existing
// file — same create-only posture as WriteMinimalRosterSkeleton.
func CreateMinimalDNSManifest(path, domain, realm, server string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("freeipa-dns manifest %s already exists", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat freeipa-dns manifest %s: %w", path, err)
	}
	stub := dnsManifestStub{
		SchemaVersion: 1,
		FreeIPA:       dnsManifestFreeIPA{Domain: domain, Realm: realm, Server: server},
		DNS: dnsManifestDNS{
			Defaults: dnsManifestDefaults{TTL: 300, RecordsMode: "merge"},
			Zones:    []any{},
		},
	}
	rendered, err := yaml.Marshal(stub)
	if err != nil {
		return fmt.Errorf("encode freeipa-dns manifest: %w", err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return fmt.Errorf("write freeipa-dns manifest %s: %w", path, err)
	}
	return nil
}

// DNSManifestZoneNames returns every zone name in the manifest at path, in
// file order — for display only.
func DNSManifestZoneNames(path string) ([]string, error) {
	root, err := LoadDNSManifest(path)
	if err != nil {
		return nil, err
	}
	return namesOf(listField(mapField(root, "dns"), "zones")), nil
}

// DNSManifestDomain reads the manifest's freeipa.domain field — used by
// callers (e.g. the `pilot edit` DNS manifest screens) to compute the
// protected-zone list for DNSValidateOptions without each needing to
// duplicate LoadDNSManifest + field lookup.
func DNSManifestDomain(path string) (string, error) {
	root, err := LoadDNSManifest(path)
	if err != nil {
		return "", err
	}
	return stringField(mapField(root, "freeipa"), "domain"), nil
}

// DNSManifestZone returns one zone's full field map.
func DNSManifestZone(path, name string) (fields map[string]any, found bool, err error) {
	root, err := LoadDNSManifest(path)
	if err != nil {
		return nil, false, err
	}
	zones := listField(mapField(root, "dns"), "zones")
	idx, _ := findNamedEntry(zones, name)
	if idx < 0 {
		return nil, false, nil
	}
	return asMap(zones[idx]), true, nil
}

// DNSManifestRecords returns zoneName's records, in file order. Returns nil
// (not an error) when the zone doesn't exist.
func DNSManifestRecords(path, zoneName string) ([]map[string]any, error) {
	zone, found, err := DNSManifestZone(path, zoneName)
	if err != nil || !found {
		return nil, err
	}
	raw := listField(zone, "records")
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, asMap(r))
	}
	return out, nil
}

// DNSManifestRecord returns one record within zoneName, matched by the
// manifest's real record identity: (name, type) — not name alone, since a
// single owner may legitimately have both an A and an AAAA record
// (docs/specs/freeipa-dns.md §8.2 gate 10 rejects duplicate (zone,name,type),
// not duplicate name).
func DNSManifestRecord(path, zoneName, recordName, recordType string) (fields map[string]any, found bool, err error) {
	records, err := DNSManifestRecords(path, zoneName)
	if err != nil {
		return nil, false, err
	}
	for _, m := range records {
		if stringField(m, "name") == recordName && strings.EqualFold(stringField(m, "type"), recordType) {
			return m, true, nil
		}
	}
	return nil, false, nil
}

// SimulateAddDNSZone reports what ValidateDNSManifest would say about the
// manifest at path if zone were appended to dns.zones — without writing
// anything. Callers should only call AppendDNSZone once this returns zero
// violations.
func SimulateAddDNSZone(path string, zone map[string]any, opts DNSValidateOptions) ([]DNSViolation, error) {
	root, err := LoadDNSManifest(path)
	if err != nil {
		return nil, err
	}
	dns := mapField(root, "dns")
	dns["zones"] = append(listField(dns, "zones"), zone)
	root["dns"] = dns
	return ValidateDNSManifest(root, opts), nil
}

// SimulateSetDNSZone is SimulateAddDNSZone's edit counterpart: reports what
// ValidateDNSManifest would say if the zone named name were replaced by
// updated. found=false means no such zone exists; a non-nil err (not a
// violation) means name is ambiguous — more than one zone already shares
// it, a pre-existing corruption this refuses to guess through.
func SimulateSetDNSZone(path, name string, updated map[string]any, opts DNSValidateOptions) (violations []DNSViolation, found bool, err error) {
	root, err := LoadDNSManifest(path)
	if err != nil {
		return nil, false, err
	}
	dns := mapField(root, "dns")
	zones := listField(dns, "zones")
	idx, ambiguous := findNamedEntry(zones, name)
	if ambiguous {
		return nil, true, fmt.Errorf("freeipa-dns manifest %s: zone %q is ambiguous (fix the duplicate by hand first)", path, name)
	}
	if idx < 0 {
		return nil, false, nil
	}
	zones[idx] = updated
	dns["zones"] = zones
	root["dns"] = dns
	return ValidateDNSManifest(root, opts), true, nil
}

// SimulateAddDNSRecord is SimulateAddDNSZone's per-record counterpart:
// reports what ValidateDNSManifest would say if record were appended to
// zoneName's records list. zoneFound=false means zoneName doesn't exist.
func SimulateAddDNSRecord(path, zoneName string, record map[string]any, opts DNSValidateOptions) (violations []DNSViolation, zoneFound bool, err error) {
	root, err := LoadDNSManifest(path)
	if err != nil {
		return nil, false, err
	}
	dns := mapField(root, "dns")
	zones := listField(dns, "zones")
	idx, ambiguous := findNamedEntry(zones, zoneName)
	if ambiguous {
		return nil, true, fmt.Errorf("freeipa-dns manifest %s: zone %q is ambiguous (fix the duplicate by hand first)", path, zoneName)
	}
	if idx < 0 {
		return nil, false, nil
	}
	zone := asMap(zones[idx])
	zone["records"] = append(listField(zone, "records"), record)
	zones[idx] = zone
	dns["zones"] = zones
	root["dns"] = dns
	return ValidateDNSManifest(root, opts), true, nil
}

// SimulateSetDNSRecord is SimulateSetDNSZone's per-record counterpart,
// matching the record by (recordName, recordType) — see DNSManifestRecord.
func SimulateSetDNSRecord(path, zoneName, recordName, recordType string, updated map[string]any, opts DNSValidateOptions) (violations []DNSViolation, found bool, err error) {
	root, err := LoadDNSManifest(path)
	if err != nil {
		return nil, false, err
	}
	dns := mapField(root, "dns")
	zones := listField(dns, "zones")
	zidx, ambiguous := findNamedEntry(zones, zoneName)
	if ambiguous {
		return nil, true, fmt.Errorf("freeipa-dns manifest %s: zone %q is ambiguous (fix the duplicate by hand first)", path, zoneName)
	}
	if zidx < 0 {
		return nil, false, nil
	}
	zone := asMap(zones[zidx])
	records := listField(zone, "records")
	ridx := -1
	for i, raw := range records {
		m := asMap(raw)
		if stringField(m, "name") != recordName || !strings.EqualFold(stringField(m, "type"), recordType) {
			continue
		}
		if ridx >= 0 {
			return nil, true, fmt.Errorf("freeipa-dns manifest %s: zone %q record (%s,%s) is ambiguous (fix the duplicate by hand first)", path, zoneName, recordName, recordType)
		}
		ridx = i
	}
	if ridx < 0 {
		return nil, false, nil
	}
	records[ridx] = updated
	zone["records"] = records
	zones[zidx] = zone
	dns["zones"] = zones
	root["dns"] = dns
	return ValidateDNSManifest(root, opts), true, nil
}

// AppendDNSZone appends zone to the manifest's dns.zones: list via
// yaml.Node surgery, preserving all other content exactly — same technique
// as roster.go's appendTopLevelRosterEntry, one level deeper (zones live
// under dns:, not at the document top level). Callers should run
// SimulateAddDNSZone first and only call this once it reports no
// violations.
func AppendDNSZone(path string, zone map[string]any) error {
	root, top, err := loadDNSYAMLDoc(path)
	if err != nil {
		return err
	}
	dnsNode := mappingChild(top, "dns", yaml.MappingNode, "!!map")
	zonesNode := mappingChild(dnsNode, "zones", yaml.SequenceNode, "!!seq")
	var entryNode yaml.Node
	if err := entryNode.Encode(zone); err != nil {
		return fmt.Errorf("encode freeipa-dns manifest zone: %w", err)
	}
	zonesNode.Content = append(zonesNode.Content, &entryNode)
	return writeDNSYAMLDoc(path, root)
}

// SetDNSZone replaces the named zone's entry via yaml.Node surgery. Callers
// should run SimulateSetDNSZone first — see SetRosterUser's doc comment for
// the two trade-offs this shares with every "replace, not append" write:
// yaml.v3 alphabetizes the replaced entry's fields, and any inline
// comment/anchor specific to that entry is lost.
func SetDNSZone(path, name string, updated map[string]any) error {
	root, top, err := loadDNSYAMLDoc(path)
	if err != nil {
		return err
	}
	dnsNode := findMappingChild(top, "dns")
	if dnsNode == nil {
		return fmt.Errorf("freeipa-dns manifest %s: no dns map", path)
	}
	zonesNode := findMappingChild(dnsNode, "zones")
	if zonesNode == nil || zonesNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("freeipa-dns manifest %s: no dns.zones list", path)
	}
	idx, err := findSequenceItemIndexByField(zonesNode, "name", name)
	if err != nil {
		return fmt.Errorf("freeipa-dns manifest %s: %w", path, err)
	}
	if idx < 0 {
		return fmt.Errorf("freeipa-dns manifest %s: no zone named %q", path, name)
	}
	var entryNode yaml.Node
	if err := entryNode.Encode(updated); err != nil {
		return fmt.Errorf("encode freeipa-dns manifest zone: %w", err)
	}
	zonesNode.Content[idx] = &entryNode
	return writeDNSYAMLDoc(path, root)
}

// AppendDNSRecord appends record to zoneName's records: list via yaml.Node
// surgery. Errors (rather than silently no-oping) if zoneName doesn't
// exist or is ambiguous — callers should run SimulateAddDNSRecord first.
func AppendDNSRecord(path, zoneName string, record map[string]any) error {
	root, top, err := loadDNSYAMLDoc(path)
	if err != nil {
		return err
	}
	dnsNode := mappingChild(top, "dns", yaml.MappingNode, "!!map")
	zonesNode := findMappingChild(dnsNode, "zones")
	if zonesNode == nil || zonesNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("freeipa-dns manifest %s: no dns.zones list", path)
	}
	zoneNode, err := findSequenceItemByField(zonesNode, "name", zoneName)
	if err != nil {
		return fmt.Errorf("freeipa-dns manifest %s: %w", path, err)
	}
	if zoneNode == nil {
		return fmt.Errorf("freeipa-dns manifest %s: no zone named %q", path, zoneName)
	}
	recordsNode := mappingChild(zoneNode, "records", yaml.SequenceNode, "!!seq")
	var entryNode yaml.Node
	if err := entryNode.Encode(record); err != nil {
		return fmt.Errorf("encode freeipa-dns manifest record: %w", err)
	}
	recordsNode.Content = append(recordsNode.Content, &entryNode)
	return writeDNSYAMLDoc(path, root)
}

// SetDNSRecord replaces one record (matched by name+type, see
// DNSManifestRecord) within zoneName via yaml.Node surgery. Callers should
// run SimulateSetDNSRecord first.
func SetDNSRecord(path, zoneName, recordName, recordType string, updated map[string]any) error {
	root, top, err := loadDNSYAMLDoc(path)
	if err != nil {
		return err
	}
	dnsNode := findMappingChild(top, "dns")
	if dnsNode == nil {
		return fmt.Errorf("freeipa-dns manifest %s: no dns map", path)
	}
	zonesNode := findMappingChild(dnsNode, "zones")
	if zonesNode == nil || zonesNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("freeipa-dns manifest %s: no dns.zones list", path)
	}
	zoneNode, err := findSequenceItemByField(zonesNode, "name", zoneName)
	if err != nil {
		return fmt.Errorf("freeipa-dns manifest %s: %w", path, err)
	}
	if zoneNode == nil {
		return fmt.Errorf("freeipa-dns manifest %s: no zone named %q", path, zoneName)
	}
	recordsNode := findMappingChild(zoneNode, "records")
	if recordsNode == nil || recordsNode.Kind != yaml.SequenceNode {
		return fmt.Errorf("freeipa-dns manifest %s: zone %q has no records list", path, zoneName)
	}
	idx, err := findSequenceItemIndexByNameType(recordsNode, recordName, recordType)
	if err != nil {
		return fmt.Errorf("freeipa-dns manifest %s: zone %q: %w", path, zoneName, err)
	}
	if idx < 0 {
		return fmt.Errorf("freeipa-dns manifest %s: zone %q has no record (name=%q, type=%q)", path, zoneName, recordName, recordType)
	}
	var entryNode yaml.Node
	if err := entryNode.Encode(updated); err != nil {
		return fmt.Errorf("encode freeipa-dns manifest record: %w", err)
	}
	recordsNode.Content[idx] = &entryNode
	return writeDNSYAMLDoc(path, root)
}

// ---- yaml.Node surgery primitives --------------------------------------

// loadDNSYAMLDoc reads path and returns both the document node (for
// re-marshaling) and its top-level mapping node (for mappingChild/
// findMappingChild navigation) — the freeipa-dns-manifest equivalent of
// what roster.go's Append*/Set* functions each inline for themselves.
func loadDNSYAMLDoc(path string) (root *yaml.Node, top *yaml.Node, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	root = &yaml.Node{}
	if err := yaml.Unmarshal(data, root); err != nil {
		return nil, nil, fmt.Errorf("parse freeipa-dns manifest %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("freeipa-dns manifest %s: expected a top-level YAML mapping", path)
	}
	return root, root.Content[0], nil
}

func writeDNSYAMLDoc(path string, root *yaml.Node) error {
	rendered, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("render freeipa-dns manifest %s: %w", path, err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return fmt.Errorf("write freeipa-dns manifest %s: %w", path, err)
	}
	return nil
}

// findSequenceItemByField returns the single item in seqNode whose decoded
// map has fieldKey == fieldValue, or nil (not an error) if none match.
// Returns an error if more than one item matches — an ambiguity this
// refuses to guess through rather than silently picking one.
func findSequenceItemByField(seqNode *yaml.Node, fieldKey, fieldValue string) (*yaml.Node, error) {
	idx, err := findSequenceItemIndexByField(seqNode, fieldKey, fieldValue)
	if err != nil || idx < 0 {
		return nil, err
	}
	return seqNode.Content[idx], nil
}

func findSequenceItemIndexByField(seqNode *yaml.Node, fieldKey, fieldValue string) (int, error) {
	idx := -1
	for i, item := range seqNode.Content {
		var m map[string]any
		if err := item.Decode(&m); err != nil {
			return -1, fmt.Errorf("decode entry %d: %w", i, err)
		}
		if stringField(m, fieldKey) != fieldValue {
			continue
		}
		if idx >= 0 {
			return -1, fmt.Errorf("%s %q is ambiguous (fix the duplicate by hand first)", fieldKey, fieldValue)
		}
		idx = i
	}
	return idx, nil
}

// findSequenceItemIndexByNameType is findSequenceItemIndexByField's
// two-key counterpart for records, identified by (name, type) rather than
// name alone — see DNSManifestRecord.
func findSequenceItemIndexByNameType(seqNode *yaml.Node, name, recordType string) (int, error) {
	idx := -1
	for i, item := range seqNode.Content {
		var m map[string]any
		if err := item.Decode(&m); err != nil {
			return -1, fmt.Errorf("decode record %d: %w", i, err)
		}
		if stringField(m, "name") != name || !strings.EqualFold(stringField(m, "type"), recordType) {
			continue
		}
		if idx >= 0 {
			return -1, fmt.Errorf("record (name=%q, type=%q) is ambiguous (fix the duplicate by hand first)", name, recordType)
		}
		idx = i
	}
	return idx, nil
}
