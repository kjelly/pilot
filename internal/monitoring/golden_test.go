package monitoring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCompileGolden compares Compile's output against a checked-in
// testdata/<case>/expected.json fixture (spec.md §71) — literal byte
// comparison after re-marshaling both sides through the same
// MarshalIndent call, so an unintentional field/ordering change in Compile
// fails loudly instead of only being caught by the narrower assertions in
// compile_test.go. There is no established golden-fixture convention
// elsewhere in this repo to match (checked: no other package uses a
// -update flag or byte-diff testdata harness), so this is a fresh,
// minimal one: plain JSON, no diff tooling.
func TestCompileGolden(t *testing.T) {
	cases := []string{"basic", "multi-profile", "disabled"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("testdata", name)
			tf, err := LoadTargets(filepath.Join(dir, "targets.yml"))
			if err != nil {
				t.Fatalf("LoadTargets: %v", err)
			}
			pf, err := LoadProfiles(filepath.Join(dir, "scrape-profiles.yml"))
			if err != nil {
				t.Fatalf("LoadProfiles: %v", err)
			}
			if r := Validate(tf, pf, SNMPCatalog{}); !r.OK() {
				t.Fatalf("fixture %s is not itself valid: %v", name, r.Errors)
			}

			got, err := json.MarshalIndent(Compile(tf, pf, ""), "", "  ")
			if err != nil {
				t.Fatalf("marshal Compile() output: %v", err)
			}
			want, err := os.ReadFile(filepath.Join(dir, "expected.json"))
			if err != nil {
				t.Fatalf("read expected.json: %v", err)
			}
			if string(got)+"\n" != string(want) {
				t.Fatalf("Compile() output for %s does not match testdata/%s/expected.json.\ngot:\n%s\nwant:\n%s", name, name, got, want)
			}
		})
	}
}

// TestCompileGolden_SNMPv2 is the SNMP monitoring integration spec §7.6/§8.1
// worked example: a schemaVersion:2 registry with one kind:snmp profile
// (core-switch) and one kind:prometheus profile (external-linux, unused —
// proves mixed-kind files compile independently), and three targets across
// two sites. Locks AC8/AC9's "wrong-site target not compiled" requirement:
// core-sw-03 (site: branch-1) must never appear when compiling for hq.
func TestCompileGolden_SNMPv2(t *testing.T) {
	dir := filepath.Join("testdata", "snmp-v2")
	tf, err := LoadTargets(filepath.Join(dir, "targets.yml"))
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	pf, err := LoadProfiles(filepath.Join(dir, "scrape-profiles.yml"))
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	catalog := SNMPCatalog{
		SchemaVersion: SNMPCatalogSchemaVersion,
		Modules: map[string]SNMPModule{
			"if_mib":             {File: "generated/if_mib.yml"},
			"vendor_core_switch": {File: "generated/vendor-core-switch.yml"},
		},
		AuthProfiles: map[string]SNMPAuthProfile{
			"core-switch-v3": {Version: 3, SecurityLevel: "authPriv", AuthProtocol: "SHA256", PrivProtocol: "AES", CredentialRef: "core-switch-v3"},
		},
	}
	if r := Validate(tf, pf, catalog); !r.OK() {
		t.Fatalf("fixture is not itself valid: %v", r.Errors)
	}

	got, err := json.MarshalIndent(Compile(tf, pf, "hq"), "", "  ")
	if err != nil {
		t.Fatalf("marshal Compile() output: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	if string(got)+"\n" != string(want) {
		t.Fatalf("Compile() output for site=hq does not match testdata/snmp-v2/expected.json.\ngot:\n%s\nwant:\n%s", got, want)
	}

	// AC8/AC9: a target whose site doesn't match localSite is excluded.
	wrongSite := Compile(tf, pf, "branch-2")
	if len(wrongSite["snmp-core-switch"]) != 0 {
		t.Fatalf("expected zero snmp-core-switch entries for a site with no matching targets, got %+v", wrongSite["snmp-core-switch"])
	}
	forBranch1 := Compile(tf, pf, "branch-1")
	if len(forBranch1["snmp-core-switch"]) != 1 || forBranch1["snmp-core-switch"][0].Labels["pilot_target"] != "core-sw-03" {
		t.Fatalf("expected exactly core-sw-03 when compiling for site=branch-1, got %+v", forBranch1["snmp-core-switch"])
	}
}

// TestValidateGolden locks the exact error messages Validate produces for a
// known-invalid registry (spec.md §71's "invalid" case, and spec.md §74's
// error-message-quality requirement — a wording regression here would
// silently make the CLI/TUI/MCP surfaces all worse at once, since they all
// funnel through this one function).
func TestValidateGolden(t *testing.T) {
	dir := filepath.Join("testdata", "invalid")
	tf, err := LoadTargets(filepath.Join(dir, "targets.yml"))
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	pf, err := LoadProfiles(filepath.Join(dir, "scrape-profiles.yml"))
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	r := Validate(tf, pf, SNMPCatalog{})
	if r.OK() {
		t.Fatalf("expected the invalid fixture to fail validation")
	}

	got, err := json.MarshalIndent(r.Errors, "", "  ")
	if err != nil {
		t.Fatalf("marshal errors: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "expected-errors.json"))
	if err != nil {
		t.Fatalf("read expected-errors.json: %v", err)
	}
	if string(got)+"\n" != string(want) {
		t.Fatalf("Validate() errors do not match testdata/invalid/expected-errors.json.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
