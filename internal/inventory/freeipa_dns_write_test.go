package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dnsManifestFixtureOneZone = `---
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
  realm: IPA.PILOT.INTERNAL
  server: ipa1.ipa.pilot.internal
dns:
  defaults:
    ttl: 300
    records_mode: merge
  safety:
    allow_shadow_existing_zone: false
    allow_authoritative_prune: false
    allow_zone_delete: false
  zones:
    - name: example.com.
      state: present
      records:
        - {name: grafana, type: A, state: present, target: {inventory_host: nexus}}
`

func writeDNSManifestFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "freeipa-dns.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func dnsHostvarsFixture(ip string) map[string]map[string]any {
	return map[string]map[string]any{"nexus": {"ansible_host": ip}}
}

func TestCreateMinimalDNSManifest_WritesValidSkeleton(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freeipa-dns.yaml")
	if err := CreateMinimalDNSManifest(path, "ipa.pilot.internal", "IPA.PILOT.INTERNAL", "ipa1.ipa.pilot.internal"); err != nil {
		t.Fatalf("CreateMinimalDNSManifest() error = %v", err)
	}
	v, err := ValidateDNSManifestFile(path, DNSValidateOptions{})
	if err != nil {
		t.Fatalf("ValidateDNSManifestFile() error = %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("expected the created skeleton to pass clean, got: %v", v)
	}
	names, err := DNSManifestZoneNames(path)
	if err != nil {
		t.Fatalf("DNSManifestZoneNames() error = %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected zero zones in a fresh skeleton, got: %v", names)
	}
}

func TestCreateMinimalDNSManifest_RefusesToOverwrite(t *testing.T) {
	path := writeDNSManifestFixture(t, dnsManifestFixtureOneZone)
	if err := CreateMinimalDNSManifest(path, "ipa.pilot.internal", "IPA.PILOT.INTERNAL", "ipa1.ipa.pilot.internal"); err == nil {
		t.Fatal("expected an error when the manifest already exists, got nil")
	}
}

func TestDNSManifestZoneNames_ReturnsFileOrder(t *testing.T) {
	path := writeDNSManifestFixture(t, dnsManifestFixtureOneZone)
	names, err := DNSManifestZoneNames(path)
	if err != nil {
		t.Fatalf("DNSManifestZoneNames() error = %v", err)
	}
	if len(names) != 1 || names[0] != "example.com." {
		t.Fatalf("DNSManifestZoneNames() = %v, want [example.com.]", names)
	}
}

func TestDNSManifestRecord_MatchesByNameAndType(t *testing.T) {
	path := writeDNSManifestFixture(t, dnsManifestFixtureOneZone)
	fields, found, err := DNSManifestRecord(path, "example.com.", "grafana", "A")
	if err != nil {
		t.Fatalf("DNSManifestRecord() error = %v", err)
	}
	if !found {
		t.Fatal("DNSManifestRecord() found = false, want true")
	}
	if stringField(fields, "type") != "A" {
		t.Fatalf("record type = %q, want A", stringField(fields, "type"))
	}
	if _, found, err := DNSManifestRecord(path, "example.com.", "grafana", "AAAA"); err != nil || found {
		t.Fatalf("DNSManifestRecord(AAAA) found=%v err=%v, want false/nil", found, err)
	}
}

func TestSimulateAddDNSZone_ReportsViolationsWithoutWriting(t *testing.T) {
	path := writeDNSManifestFixture(t, dnsManifestFixtureOneZone)
	before := readFileHelper(t, path)

	v, err := SimulateAddDNSZone(path, map[string]any{"name": "not..valid", "records": []any{}}, DNSValidateOptions{})
	if err != nil {
		t.Fatalf("SimulateAddDNSZone() error = %v", err)
	}
	if len(v) == 0 {
		t.Fatal("expected violations for an invalid zone name, got none")
	}
	if got := readFileHelper(t, path); got != before {
		t.Fatal("SimulateAddDNSZone must not write to disk")
	}
}

func TestAppendDNSZone_PreservesExistingContentAndComments(t *testing.T) {
	fixture := "---\n" +
		"schema_version: 1\n" +
		"freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}\n" +
		"dns:\n" +
		"  defaults: {ttl: 300, records_mode: merge}\n" +
		"  zones:\n" +
		"    # this comment must survive appending a sibling zone\n" +
		"    - name: example.com.\n" +
		"      records: []\n"
	path := writeDNSManifestFixture(t, fixture)

	v, err := SimulateAddDNSZone(path, map[string]any{"name": "svc.example.com.", "records": []any{}}, DNSValidateOptions{})
	if err != nil {
		t.Fatalf("SimulateAddDNSZone() error = %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("expected the new zone to pass clean, got: %v", v)
	}
	if err := AppendDNSZone(path, map[string]any{"name": "svc.example.com.", "records": []any{}}); err != nil {
		t.Fatalf("AppendDNSZone() error = %v", err)
	}

	got := readFileHelper(t, path)
	if !strings.Contains(got, "# this comment must survive appending a sibling zone") {
		t.Fatalf("AppendDNSZone lost a sibling comment; got:\n%s", got)
	}
	names, err := DNSManifestZoneNames(path)
	if err != nil {
		t.Fatalf("DNSManifestZoneNames() error = %v", err)
	}
	if len(names) != 2 || names[0] != "example.com." || names[1] != "svc.example.com." {
		t.Fatalf("DNSManifestZoneNames() = %v, want [example.com. svc.example.com.]", names)
	}
}

func TestSetDNSZone_ReplacesOnlyTheNamedZone(t *testing.T) {
	fixture := "---\n" +
		"schema_version: 1\n" +
		"freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}\n" +
		"dns:\n" +
		"  defaults: {ttl: 300, records_mode: merge}\n" +
		"  zones:\n" +
		"    - name: example.com.\n" +
		"      records: []\n" +
		"    - name: svc.example.com.\n" +
		"      records: []\n"
	path := writeDNSManifestFixture(t, fixture)

	updated := map[string]any{"name": "example.com.", "state": "present", "records_mode": "authoritative", "records": []any{}}
	if err := SetDNSZone(path, "example.com.", updated); err != nil {
		t.Fatalf("SetDNSZone() error = %v", err)
	}
	zone, found, err := DNSManifestZone(path, "example.com.")
	if err != nil {
		t.Fatalf("DNSManifestZone() error = %v", err)
	}
	if !found || stringField(zone, "records_mode") != "authoritative" {
		t.Fatalf("zone example.com. records_mode = %v, want authoritative", zone)
	}
	other, found, err := DNSManifestZone(path, "svc.example.com.")
	if err != nil || !found || stringField(other, "records_mode") != "" {
		t.Fatalf("sibling zone svc.example.com. was disturbed: %v (err=%v)", other, err)
	}
}

func TestSetDNSZone_ErrorsWhenZoneMissing(t *testing.T) {
	path := writeDNSManifestFixture(t, dnsManifestFixtureOneZone)
	if err := SetDNSZone(path, "does-not-exist.example.com.", map[string]any{"name": "does-not-exist.example.com."}); err == nil {
		t.Fatal("expected an error for a missing zone, got nil")
	}
}

func TestSimulateAddDNSRecord_ReportsZoneNotFound(t *testing.T) {
	path := writeDNSManifestFixture(t, dnsManifestFixtureOneZone)
	_, zoneFound, err := SimulateAddDNSRecord(path, "does-not-exist.example.com.", map[string]any{"name": "x", "type": "A"}, DNSValidateOptions{})
	if err != nil {
		t.Fatalf("SimulateAddDNSRecord() error = %v", err)
	}
	if zoneFound {
		t.Fatal("expected zoneFound = false for a nonexistent zone")
	}
}

func TestAppendDNSRecord_AddsToTheNamedZoneOnly(t *testing.T) {
	fixture := "---\n" +
		"schema_version: 1\n" +
		"freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}\n" +
		"dns:\n" +
		"  defaults: {ttl: 300, records_mode: merge}\n" +
		"  zones:\n" +
		"    - name: example.com.\n" +
		"      records: []\n" +
		"    - name: svc.example.com.\n" +
		"      records: []\n"
	path := writeDNSManifestFixture(t, fixture)

	record := map[string]any{"name": "grafana", "type": "A", "state": "present", "target": map[string]any{"inventory_host": "nexus"}}
	v, zoneFound, err := SimulateAddDNSRecord(path, "example.com.", record, DNSValidateOptions{Hostvars: dnsHostvarsFixture("192.168.122.81")})
	if err != nil {
		t.Fatalf("SimulateAddDNSRecord() error = %v", err)
	}
	if !zoneFound || len(v) != 0 {
		t.Fatalf("expected zoneFound=true and no violations, got zoneFound=%v v=%v", zoneFound, v)
	}
	if err := AppendDNSRecord(path, "example.com.", record); err != nil {
		t.Fatalf("AppendDNSRecord() error = %v", err)
	}

	got, err := DNSManifestRecords(path, "example.com.")
	if err != nil || len(got) != 1 {
		t.Fatalf("DNSManifestRecords(example.com.) = %v (err=%v), want 1 record", got, err)
	}
	other, err := DNSManifestRecords(path, "svc.example.com.")
	if err != nil || len(other) != 0 {
		t.Fatalf("sibling zone svc.example.com. was disturbed: %v (err=%v)", other, err)
	}
}

func TestSetDNSRecord_ReplacesOnlyTheMatchingRecord(t *testing.T) {
	fixture := "---\n" +
		"schema_version: 1\n" +
		"freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}\n" +
		"dns:\n" +
		"  defaults: {ttl: 300, records_mode: merge}\n" +
		"  zones:\n" +
		"    - name: example.com.\n" +
		"      records:\n" +
		"        - {name: grafana, type: A, values: [\"10.0.0.1\"]}\n" +
		"        - {name: grafana, type: AAAA, values: [\"2001:db8::1\"]}\n"
	path := writeDNSManifestFixture(t, fixture)

	updated := map[string]any{"name": "grafana", "type": "A", "state": "present", "values": []any{"10.0.0.2"}}
	if err := SetDNSRecord(path, "example.com.", "grafana", "A", updated); err != nil {
		t.Fatalf("SetDNSRecord() error = %v", err)
	}
	a, found, err := DNSManifestRecord(path, "example.com.", "grafana", "A")
	if err != nil || !found {
		t.Fatalf("DNSManifestRecord(A) found=%v err=%v", found, err)
	}
	if got := stringListField(a, "values"); len(got) != 1 || got[0] != "10.0.0.2" {
		t.Fatalf("A record values = %v, want [10.0.0.2]", got)
	}
	aaaa, found, err := DNSManifestRecord(path, "example.com.", "grafana", "AAAA")
	if err != nil || !found {
		t.Fatalf("DNSManifestRecord(AAAA) found=%v err=%v", found, err)
	}
	if got := stringListField(aaaa, "values"); len(got) != 1 || got[0] != "2001:db8::1" {
		t.Fatalf("sibling AAAA record was disturbed: %v", got)
	}
}

func TestSetDNSRecord_ErrorsWhenRecordMissing(t *testing.T) {
	path := writeDNSManifestFixture(t, dnsManifestFixtureOneZone)
	if err := SetDNSRecord(path, "example.com.", "does-not-exist", "A", map[string]any{"name": "does-not-exist", "type": "A"}); err == nil {
		t.Fatal("expected an error for a missing record, got nil")
	}
}
