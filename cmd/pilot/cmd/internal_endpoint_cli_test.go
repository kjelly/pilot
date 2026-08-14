package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const iepCLIValidManifest = `---
schema_version: 1
endpoints:
  - fqdn: direct.apps.pilot.internal
    state: present
    dns:
      zone: apps.pilot.internal.
    route:
      mode: direct
      target:
        address: 10.0.0.1
    tls:
      mode: disabled
`

const iepCLIUnknownKeyManifest = `---
schema_version: 1
not_a_real_top_level_key: true
endpoints: []
`

const iepCLINestedFQDNManifest = `---
schema_version: 1
endpoints:
  - fqdn: aaa.xxx.apps.pilot.internal
    state: present
    dns:
      zone: apps.pilot.internal.
    route:
      mode: direct
      target:
        address: 10.0.0.1
    tls:
      mode: disabled
`

const iepCLIDuplicateFQDNManifest = `---
schema_version: 1
endpoints:
  - fqdn: dup.apps.pilot.internal
    state: present
    dns: {zone: apps.pilot.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
  - fqdn: DUP.apps.pilot.internal.
    state: present
    dns: {zone: apps.pilot.internal.}
    route: {mode: direct, target: {address: 10.0.0.2}}
    tls: {mode: disabled}
`

const iepCLIMissingVerifyManifest = `---
schema_version: 1
endpoints:
  - fqdn: badverify.apps.pilot.internal
    state: present
    dns: {zone: apps.pilot.internal.}
    route:
      mode: reverse_proxy
      proxy: {provider: nginx, inventory_host: proxyhost}
      upstream: {scheme: https, address: 10.0.0.9, port: 8443}
    tls: {mode: disabled}
`

func iepCLIWriteFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func iepCLIRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	return out.String(), err
}

func TestInternalEndpointValidateCmd_ValidManifestPrintsOK(t *testing.T) {
	path := iepCLIWriteFixture(t, iepCLIValidManifest)
	out, err := iepCLIRun(t, "internal-endpoint", "validate", "--manifest", path)
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, "manifest OK") {
		t.Fatalf("output = %q, want manifest OK", out)
	}
}

func TestInternalEndpointValidateCmd_UnknownKeyRejected(t *testing.T) {
	path := iepCLIWriteFixture(t, iepCLIUnknownKeyManifest)
	out, err := iepCLIRun(t, "internal-endpoint", "validate", "--manifest", path)
	if err == nil {
		t.Fatalf("expected a non-nil error, output: %s", out)
	}
	if !strings.Contains(strings.ToLower(out), "unknown") {
		t.Fatalf("output = %q, want it to mention the unknown key", out)
	}
}

func TestInternalEndpointValidateCmd_PrintNormalizedShowsRelativeOwner(t *testing.T) {
	path := iepCLIWriteFixture(t, iepCLINestedFQDNManifest)
	out, err := iepCLIRun(t, "internal-endpoint", "validate", "--manifest", path, "--print-normalized")
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	count := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "aaa.xxx ") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("output = %q, want exactly one line starting with %q", out, "aaa.xxx ")
	}
}

func TestInternalEndpointValidateCmd_DuplicateFQDNRejected(t *testing.T) {
	path := iepCLIWriteFixture(t, iepCLIDuplicateFQDNManifest)
	out, err := iepCLIRun(t, "internal-endpoint", "validate", "--manifest", path)
	if err == nil {
		t.Fatalf("expected a non-nil error, output: %s", out)
	}
	if !strings.Contains(strings.ToLower(out), "duplicate") {
		t.Fatalf("output = %q, want it to mention the duplicate fqdn", out)
	}
}

func TestInternalEndpointValidateCmd_MissingUpstreamVerifyRejected(t *testing.T) {
	path := iepCLIWriteFixture(t, iepCLIMissingVerifyManifest)
	out, err := iepCLIRun(t, "internal-endpoint", "validate", "--manifest", path)
	if err == nil {
		t.Fatalf("expected a non-nil error, output: %s", out)
	}
	if !strings.Contains(strings.ToLower(out), "verify") {
		t.Fatalf("output = %q, want it to mention tls.verify", out)
	}
}

func TestInternalEndpointValidateCmd_DNSOwnershipCollisionRejected(t *testing.T) {
	dnsPath := iepCLIWriteFixture(t, `---
schema_version: 1
freeipa: {domain: ipa.pilot.internal, realm: IPA.PILOT.INTERNAL, server: ipa1.ipa.pilot.internal}
dns:
  zones:
    - name: apps.pilot.internal.
      state: present
      records_mode: merge
      records:
        - {name: reserved, type: A, state: present, values: ["10.0.0.1"]}
`)
	iepPath := iepCLIWriteFixture(t, `---
schema_version: 1
endpoints:
  - fqdn: reserved.apps.pilot.internal
    state: present
    dns: {zone: apps.pilot.internal.}
    route: {mode: direct, target: {address: 10.0.0.1}}
    tls: {mode: disabled}
`)

	out, err := iepCLIRun(t, "internal-endpoint", "validate", "--manifest", iepPath, "--freeipa-dns-manifest", dnsPath)
	if err == nil {
		t.Fatalf("expected a non-nil error, output: %s", out)
	}
	if !strings.Contains(strings.ToLower(out), "ownership conflict") {
		t.Fatalf("output = %q, want it to mention the ownership conflict", out)
	}
}
