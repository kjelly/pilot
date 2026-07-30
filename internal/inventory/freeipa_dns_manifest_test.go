package inventory

import (
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustParseDNSManifest(t *testing.T, doc string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return root
}

const minimalValidDNSManifest = `
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
  realm: IPA.PILOT.INTERNAL
  server: ipa1.ipa.pilot.internal
dns:
  defaults: {ttl: 300, records_mode: merge}
  safety: {allow_shadow_existing_zone: false, allow_authoritative_prune: false, allow_zone_delete: false}
  zones:
    - name: example.com.
      state: present
      records:
        - {name: grafana, type: A, state: present, target: {inventory_host: nexus}}
        - {name: wazuh, type: A, state: present, target: {inventory_host: nexus}}
        - {name: s3, type: A, state: present, target: {inventory_host: nexus}}
`

func nexusHostvars(ip string) map[string]map[string]any {
	return map[string]map[string]any{"nexus": {"ansible_host": ip}}
}

func TestNormalizeDNSManifest_ResolvesInventoryTarget(t *testing.T) {
	root := mustParseDNSManifest(t, minimalValidDNSManifest)
	n := NormalizeDNSManifest(root, nexusHostvars("192.168.122.81"))
	if len(n.Zones) != 1 {
		t.Fatalf("zones = %d, want 1", len(n.Zones))
	}
	zone := n.Zones[0]
	if zone.Name != "example.com." {
		t.Fatalf("zone name = %q, want %q", zone.Name, "example.com.")
	}
	if len(zone.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(zone.Records))
	}
	for _, r := range zone.Records {
		if len(r.Values) != 1 || r.Values[0] != "192.168.122.81" {
			t.Errorf("record %q values = %v, want [192.168.122.81]", r.Name, r.Values)
		}
		if r.TTL != 300 {
			t.Errorf("record %q ttl = %d, want 300", r.Name, r.TTL)
		}
	}
}

// TestNormalizeDNSManifest_ReResolvesAfterInventoryChange is the Phase 1
// embodiment of docs/specs/freeipa-dns.md §1's core promise: re-running
// reconcile after nexus's DHCP lease changes converges to the new IP,
// without touching the manifest at all.
func TestNormalizeDNSManifest_ReResolvesAfterInventoryChange(t *testing.T) {
	root := mustParseDNSManifest(t, minimalValidDNSManifest)
	before := NormalizeDNSManifest(root, nexusHostvars("192.168.122.81"))
	after := NormalizeDNSManifest(root, nexusHostvars("192.168.122.99"))
	for i := range before.Zones[0].Records {
		if before.Zones[0].Records[i].Values[0] != "192.168.122.81" {
			t.Fatalf("before: got %v", before.Zones[0].Records[i].Values)
		}
		if after.Zones[0].Records[i].Values[0] != "192.168.122.99" {
			t.Fatalf("after: got %v", after.Zones[0].Records[i].Values)
		}
	}
}

func TestNormalizeDNSManifest_Deterministic(t *testing.T) {
	root := mustParseDNSManifest(t, minimalValidDNSManifest)
	hv := nexusHostvars("192.168.122.81")
	a := NormalizeDNSManifest(root, hv)
	b := NormalizeDNSManifest(root, hv)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("NormalizeDNSManifest is not deterministic:\na=%+v\nb=%+v", a, b)
	}
}

func TestNormalizeDNSManifest_SortsZonesAndRecordsRegardlessOfInputOrder(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  defaults: {ttl: 300, records_mode: merge}
  zones:
    - name: z2.example.com.
      records:
        - {name: b, type: A, values: [10.0.0.2]}
        - {name: a, type: A, values: [10.0.0.1]}
    - name: z1.example.com.
      records: []
`
	root := mustParseDNSManifest(t, doc)
	n := NormalizeDNSManifest(root, nil)
	if n.Zones[0].Name != "z1.example.com." || n.Zones[1].Name != "z2.example.com." {
		t.Fatalf("zones not sorted: %v", n.Zones)
	}
	recs := n.Zones[1].Records
	if recs[0].Name != "a" || recs[1].Name != "b" {
		t.Fatalf("records not sorted: %v", recs)
	}
}

func TestNormalizeDNSManifest_ZoneNameNormalization(t *testing.T) {
	doc := `
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  zones:
    - name: EXAMPLE.COM
      records: []
`
	root := mustParseDNSManifest(t, doc)
	n := NormalizeDNSManifest(root, nil)
	if n.Zones[0].Name != "example.com." {
		t.Fatalf("zone name = %q, want %q", n.Zones[0].Name, "example.com.")
	}
}

func TestValidateDNSManifest_RealShippedExamplePassesClean(t *testing.T) {
	path := filepath.Join("..", "..", "playbooks", "apply", "freeipa-dns.manifest.example.yaml")
	violations, err := ValidateDNSManifestFile(path, DNSValidateOptions{
		Hostvars: nexusHostvars("192.168.122.81"),
	})
	if err != nil {
		t.Skipf("real manifest example not found: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the real shipped manifest example to pass clean, got: %v", violations)
	}
}
