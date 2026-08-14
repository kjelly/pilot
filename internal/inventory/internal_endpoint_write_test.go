package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const internalEndpointManifestFixtureOneEndpoint = `---
schema_version: 1
defaults:
  dns:
    ttl: 300
safety:
  allow_endpoint_delete: false
endpoints:
  - fqdn: direct.apps.pilot.internal
    state: present
    dns:
      zone: apps.pilot.internal.
    route:
      mode: direct
      target:
        inventory_host: app01
    tls:
      mode: disabled
`

func writeInternalEndpointManifestFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "internal-endpoints.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestCreateMinimalInternalEndpointManifest_WritesValidSkeleton(t *testing.T) {
	path := filepath.Join(t.TempDir(), "internal-endpoints.yaml")
	if err := CreateMinimalInternalEndpointManifest(path); err != nil {
		t.Fatalf("CreateMinimalInternalEndpointManifest() error = %v", err)
	}
	v, err := ValidateInternalEndpointManifestFile(path, InternalEndpointValidateOptions{})
	if err != nil {
		t.Fatalf("ValidateInternalEndpointManifestFile() error = %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("expected the created skeleton to pass clean, got: %v", v)
	}
	fqdns, err := InternalEndpointManifestFQDNs(path)
	if err != nil {
		t.Fatalf("InternalEndpointManifestFQDNs() error = %v", err)
	}
	if len(fqdns) != 0 {
		t.Fatalf("expected zero endpoints in a fresh skeleton, got: %v", fqdns)
	}
}

func TestCreateMinimalInternalEndpointManifest_RefusesToOverwrite(t *testing.T) {
	path := writeInternalEndpointManifestFixture(t, internalEndpointManifestFixtureOneEndpoint)
	if err := CreateMinimalInternalEndpointManifest(path); err == nil {
		t.Fatal("expected an error when the manifest already exists, got nil")
	}
}

func TestInternalEndpointManifestFQDNs_ReturnsFileOrder(t *testing.T) {
	path := writeInternalEndpointManifestFixture(t, internalEndpointManifestFixtureOneEndpoint)
	fqdns, err := InternalEndpointManifestFQDNs(path)
	if err != nil {
		t.Fatalf("InternalEndpointManifestFQDNs() error = %v", err)
	}
	if len(fqdns) != 1 || fqdns[0] != "direct.apps.pilot.internal" {
		t.Fatalf("InternalEndpointManifestFQDNs() = %v, want [direct.apps.pilot.internal]", fqdns)
	}
}

func TestInternalEndpointManifestEndpoint_MatchesByFQDN(t *testing.T) {
	path := writeInternalEndpointManifestFixture(t, internalEndpointManifestFixtureOneEndpoint)
	fields, found, err := InternalEndpointManifestEndpoint(path, "direct.apps.pilot.internal")
	if err != nil {
		t.Fatalf("InternalEndpointManifestEndpoint() error = %v", err)
	}
	if !found {
		t.Fatal("InternalEndpointManifestEndpoint() found = false, want true")
	}
	if stringField(fields, "state") != "present" {
		t.Fatalf("endpoint state = %q, want present", stringField(fields, "state"))
	}
	if _, found, err := InternalEndpointManifestEndpoint(path, "nope.apps.pilot.internal"); err != nil || found {
		t.Fatalf("InternalEndpointManifestEndpoint(nope) found=%v err=%v, want false/nil", found, err)
	}
}

func TestSimulateAddInternalEndpoint_ReportsViolationsWithoutWriting(t *testing.T) {
	path := writeInternalEndpointManifestFixture(t, internalEndpointManifestFixtureOneEndpoint)
	before := readFileHelper(t, path)

	bad := map[string]any{"fqdn": "not a valid fqdn!!", "state": "present"}
	v, err := SimulateAddInternalEndpoint(path, bad, InternalEndpointValidateOptions{})
	if err != nil {
		t.Fatalf("SimulateAddInternalEndpoint() error = %v", err)
	}
	if len(v) == 0 {
		t.Fatal("expected violations for a malformed endpoint, got none")
	}
	if got := readFileHelper(t, path); got != before {
		t.Fatal("SimulateAddInternalEndpoint must not write to disk")
	}
}

func TestAppendInternalEndpoint_PreservesExistingContentAndComments(t *testing.T) {
	fixture := "---\n" +
		"schema_version: 1\n" +
		"safety: {allow_endpoint_delete: false}\n" +
		"endpoints:\n" +
		"  # this comment must survive appending a sibling endpoint\n" +
		"  - fqdn: direct.apps.pilot.internal\n" +
		"    state: present\n" +
		"    dns: {zone: apps.pilot.internal.}\n" +
		"    route: {mode: direct, target: {inventory_host: app01}}\n" +
		"    tls: {mode: disabled}\n"
	path := writeInternalEndpointManifestFixture(t, fixture)

	second := map[string]any{
		"fqdn":  "aaa.xxx.apps.pilot.internal",
		"state": "present",
		"dns":   map[string]any{"zone": "apps.pilot.internal."},
		"route": map[string]any{"mode": "direct", "target": map[string]any{"inventory_host": "app01"}},
		"tls":   map[string]any{"mode": "disabled"},
	}
	v, err := SimulateAddInternalEndpoint(path, second, InternalEndpointValidateOptions{})
	if err != nil {
		t.Fatalf("SimulateAddInternalEndpoint() error = %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("expected the new endpoint to pass clean, got: %v", v)
	}
	if err := AppendInternalEndpoint(path, second); err != nil {
		t.Fatalf("AppendInternalEndpoint() error = %v", err)
	}

	got := readFileHelper(t, path)
	if !strings.Contains(got, "# this comment must survive appending a sibling endpoint") {
		t.Fatalf("AppendInternalEndpoint lost a sibling comment; got:\n%s", got)
	}
	fqdns, err := InternalEndpointManifestFQDNs(path)
	if err != nil {
		t.Fatalf("InternalEndpointManifestFQDNs() error = %v", err)
	}
	if len(fqdns) != 2 || fqdns[0] != "direct.apps.pilot.internal" || fqdns[1] != "aaa.xxx.apps.pilot.internal" {
		t.Fatalf("InternalEndpointManifestFQDNs() = %v, want [direct.apps.pilot.internal aaa.xxx.apps.pilot.internal]", fqdns)
	}
}

func TestSetInternalEndpoint_ReplacesOnlyTheNamedEndpoint(t *testing.T) {
	fixture := "---\n" +
		"schema_version: 1\n" +
		"safety: {allow_endpoint_delete: false}\n" +
		"endpoints:\n" +
		"  - fqdn: direct.apps.pilot.internal\n" +
		"    state: present\n" +
		"    dns: {zone: apps.pilot.internal.}\n" +
		"    route: {mode: direct, target: {inventory_host: app01}}\n" +
		"    tls: {mode: disabled}\n" +
		"  - fqdn: aaa.xxx.apps.pilot.internal\n" +
		"    state: present\n" +
		"    dns: {zone: apps.pilot.internal.}\n" +
		"    route: {mode: direct, target: {inventory_host: app01}}\n" +
		"    tls: {mode: disabled}\n"
	path := writeInternalEndpointManifestFixture(t, fixture)

	updated := map[string]any{
		"fqdn":  "direct.apps.pilot.internal",
		"state": "present",
		"dns":   map[string]any{"zone": "apps.pilot.internal.", "ttl": 600},
		"route": map[string]any{"mode": "direct", "target": map[string]any{"inventory_host": "app01"}},
		"tls":   map[string]any{"mode": "disabled"},
	}
	if err := SetInternalEndpoint(path, "direct.apps.pilot.internal", updated); err != nil {
		t.Fatalf("SetInternalEndpoint() error = %v", err)
	}
	fields, found, err := InternalEndpointManifestEndpoint(path, "direct.apps.pilot.internal")
	if err != nil {
		t.Fatalf("InternalEndpointManifestEndpoint() error = %v", err)
	}
	if !found || toIntOrZero(mapField(fields, "dns")["ttl"]) != 600 {
		t.Fatalf("endpoint direct.apps.pilot.internal dns.ttl = %v, want 600", fields)
	}
	other, found, err := InternalEndpointManifestEndpoint(path, "aaa.xxx.apps.pilot.internal")
	if err != nil || !found {
		t.Fatalf("sibling endpoint aaa.xxx.apps.pilot.internal missing: %v (err=%v)", other, err)
	}
	if _, hasTTL := mapField(other, "dns")["ttl"]; hasTTL {
		t.Fatalf("sibling endpoint aaa.xxx.apps.pilot.internal was disturbed: %v", other)
	}
}

func toIntOrZero(v any) int {
	n, _ := toInt(v)
	return n
}

func TestSetInternalEndpoint_ErrorsWhenFQDNMissing(t *testing.T) {
	path := writeInternalEndpointManifestFixture(t, internalEndpointManifestFixtureOneEndpoint)
	if err := SetInternalEndpoint(path, "does-not-exist.apps.pilot.internal", map[string]any{"fqdn": "does-not-exist.apps.pilot.internal"}); err == nil {
		t.Fatal("expected an error for a missing fqdn, got nil")
	}
}

func TestSimulateSetInternalEndpoint_ReportsNotFound(t *testing.T) {
	path := writeInternalEndpointManifestFixture(t, internalEndpointManifestFixtureOneEndpoint)
	_, found, err := SimulateSetInternalEndpoint(path, "does-not-exist.apps.pilot.internal", map[string]any{}, InternalEndpointValidateOptions{})
	if err != nil {
		t.Fatalf("SimulateSetInternalEndpoint() error = %v", err)
	}
	if found {
		t.Fatal("SimulateSetInternalEndpoint() found = true, want false for a missing fqdn")
	}
}
