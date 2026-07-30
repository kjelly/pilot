package inventory

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadDNSManifest reads and YAML-decodes a freeipa-dns manifest into a plain
// map, the same representation ValidateDNSManifest and NormalizeDNSManifest
// operate on. The manifest is never ansible-vault encrypted (schema forbids
// secrets — see docs/specs/freeipa-dns.md §3.2), so unlike the roster loader
// there is no encrypted-file detection to perform here.
func LoadDNSManifest(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse freeipa-dns manifest %s: %w", path, err)
	}
	return root, nil
}

// NormalizedDNSManifest is the deterministic desired-state view of a manifest
// that has already passed ValidateDNSManifest with zero violations. It is
// the Phase 1 "read-only plan" artifact: what SHOULD exist, fully resolved
// (inventory_host targets turned into concrete IPs), before any comparison
// against FreeIPA's actual live state (which needs a real kinit'd session —
// see playbooks/apply/freeipa-dns-apply.yml §8.4/§8.5).
type NormalizedDNSManifest struct {
	Zones []NormalizedDNSZone
}

// NormalizedDNSZone is one zone's fully-resolved desired state.
type NormalizedDNSZone struct {
	Name        string // lowercase, trailing-dot
	State       string // present|absent
	RecordsMode string // merge|authoritative
	Records     []NormalizedDNSRecord
}

// NormalizedDNSRecord is one RRset's fully-resolved desired state.
type NormalizedDNSRecord struct {
	Name   string // zone-relative owner, lowercase ("@" for apex)
	Type   string // A|AAAA|CNAME
	State  string // present|absent
	TTL    int
	Values []string // sorted, deduped, canonical textual form
}

// NormalizeDNSManifest resolves and sorts a manifest into deterministic
// desired state. Callers must run ValidateDNSManifest first and only
// normalize when it returns zero violations — this function assumes the
// input already satisfies the schema contract (docs/specs/freeipa-dns.md §4)
// and does not re-validate it.
func NormalizeDNSManifest(root map[string]any, hostvars map[string]map[string]any) NormalizedDNSManifest {
	dns := mapField(root, "dns")
	defaults := mapField(dns, "defaults")
	defaultTTL, _ := toInt(defaults["ttl"])

	zonesIn := listField(dns, "zones")
	zones := make([]NormalizedDNSZone, 0, len(zonesIn))
	for _, rawZone := range zonesIn {
		z := asMap(rawZone)
		nz := NormalizedDNSZone{
			Name:        normalizeZoneName(stringField(z, "name")),
			State:       stateOrDefault(z, "present"),
			RecordsMode: recordsModeOrDefault(z, defaults),
		}
		for _, rawRecord := range listField(z, "records") {
			r := asMap(rawRecord)
			ttl := defaultTTL
			if t, ok := toInt(r["ttl"]); ok {
				ttl = t
			}
			values := resolveRecordValues(r, hostvars)
			sort.Strings(values)
			nz.Records = append(nz.Records, NormalizedDNSRecord{
				Name:   strings.ToLower(strings.TrimSpace(stringField(r, "name"))),
				Type:   strings.ToUpper(strings.TrimSpace(stringField(r, "type"))),
				State:  stateOrDefault(r, "present"),
				TTL:    ttl,
				Values: values,
			})
		}
		sort.Slice(nz.Records, func(i, j int) bool {
			if nz.Records[i].Name != nz.Records[j].Name {
				return nz.Records[i].Name < nz.Records[j].Name
			}
			return nz.Records[i].Type < nz.Records[j].Type
		})
		zones = append(zones, nz)
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	return NormalizedDNSManifest{Zones: zones}
}

func recordsModeOrDefault(zone, defaults map[string]any) string {
	if m := stringField(zone, "records_mode"); m != "" {
		return m
	}
	if m := stringField(defaults, "records_mode"); m != "" {
		return m
	}
	return "merge"
}

// normalizeZoneName applies docs/specs/freeipa-dns.md §5.3's normalization:
// lowercase, and a single trailing dot.
func normalizeZoneName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return name
	}
	return strings.TrimSuffix(name, ".") + "."
}

// resolveRecordValues returns the record's canonical, deduped value set:
// either the manifest's explicit `values`, or the IP resolved from
// `target.inventory_host` via hostvars[host].ansible_host.
func resolveRecordValues(record map[string]any, hostvars map[string]map[string]any) []string {
	if values := stringListField(record, "values"); len(values) > 0 {
		return dedupe(canonicalizeValues(values))
	}
	target := mapField(record, "target")
	host := stringField(target, "inventory_host")
	if host == "" {
		return nil
	}
	hv := hostvars[host]
	if hv == nil {
		return nil
	}
	ansibleHost, _ := hv["ansible_host"].(string)
	if ansibleHost == "" {
		return nil
	}
	return []string{ansibleHost}
}

// canonicalizeValues lowercases FQDN-shaped values (CNAME targets); IP
// literals are left as-is since net.ParseIP-driven textual canonicalization
// happens once real current-state comparison exists (Phase 2+).
func canonicalizeValues(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		v = strings.TrimSpace(v)
		// FQDN-shaped values (CNAME targets are required to end in ".", per
		// §5.6) get case-folded; IP literals never end in "." so are left as-is.
		if strings.HasSuffix(v, ".") {
			v = strings.ToLower(v)
		}
		out[i] = v
	}
	return out
}
