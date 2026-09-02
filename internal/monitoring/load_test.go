package monitoring

import (
	"path/filepath"
	"testing"
)

func TestLoadTargets_MissingFile(t *testing.T) {
	tf, err := LoadTargets(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if tf.SchemaVersion != SchemaVersion || len(tf.Targets) != 0 {
		t.Fatalf("missing file should be an empty registry, got %+v", tf)
	}
}

func TestLoadTargets_EmptyPath(t *testing.T) {
	tf, err := LoadTargets("")
	if err != nil {
		t.Fatalf("LoadTargets(\"\"): %v", err)
	}
	if len(tf.Targets) != 0 {
		t.Fatalf("empty path should be an empty registry, got %+v", tf)
	}
}

func TestLoadTargets_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	content := []byte(`schemaVersion: 1
targets:
  - name: nas01
    address: nas01.pilot.internal:9633
    profile: storage-exporter
    site: taipei
    enabled: true
    labels:
      owner: storage
`)
	if err := writeFile(path, content); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	tf, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(tf.Targets) != 1 || tf.Targets[0].Name != "nas01" {
		t.Fatalf("unexpected parse result: %+v", tf)
	}
	if !tf.Targets[0].IsEnabled() {
		t.Fatalf("expected enabled target")
	}
}

func TestLoadTargets_EmptyFileIsEmptyRegistry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	if err := writeFile(path, []byte("")); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	tf, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets on empty file: %v", err)
	}
	if len(tf.Targets) != 0 {
		t.Fatalf("expected empty targets, got %+v", tf)
	}
}

func TestLoadTargets_InvalidSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	if err := writeFile(path, []byte("schemaVersion: not-a-number\n")); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := LoadTargets(path); err == nil {
		t.Fatalf("expected a parse error for a non-numeric schemaVersion")
	}
}

func TestLoadProfiles_MissingFile(t *testing.T) {
	pf, err := LoadProfiles(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	if len(pf.Profiles) != 0 {
		t.Fatalf("missing file should be an empty profile registry, got %+v", pf)
	}
}

func TestLoadTargets_RejectsSecretKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	content := []byte(`schemaVersion: 1
targets:
  - name: nas01
    address: nas01.pilot.internal:9633
    profile: storage-exporter
    password: leaked-in-plaintext
`)
	if err := writeFile(path, content); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := LoadTargets(path); err == nil {
		t.Fatal("LoadTargets should reject a target containing an unknown/secret-like key")
	}
}

func TestLoadProfiles_RejectsSecretKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scrape-profiles.yml")
	content := []byte(`schemaVersion: 1
profiles:
  p:
    jobName: j
    community: leaked-in-plaintext
`)
	if err := writeFile(path, content); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := LoadProfiles(path); err == nil {
		t.Fatal("LoadProfiles should reject a profile containing an unknown/secret-like key")
	}
}

func TestLoadProfiles_V2SNMPFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scrape-profiles.yml")
	content := []byte(`schemaVersion: 2
profiles:
  core-switch:
    kind: snmp
    jobName: snmp-core-switch
    subjectKind: network_device
    diagnosticProfile: network-device-ifmib-v1
    snmp:
      modules: [if_mib, vendor_core_switch]
      authProfile: core-switch-v3
`)
	if err := writeFile(path, content); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	pf, err := LoadProfiles(path)
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	if pf.SchemaVersion != 2 {
		t.Fatalf("SchemaVersion = %d, want 2", pf.SchemaVersion)
	}
	p, ok := pf.Profiles["core-switch"]
	if !ok || !p.IsSNMP() || p.SubjectKind != "network_device" || p.DiagnosticProfile != "network-device-ifmib-v1" {
		t.Fatalf("unexpected parse result: %+v (ok=%v)", p, ok)
	}
	if p.SNMP == nil || len(p.SNMP.Modules) != 2 || p.SNMP.AuthProfile != "core-switch-v3" {
		t.Fatalf("unexpected snmp block: %+v", p.SNMP)
	}
}

func TestLoadTargets_V2DetectionCohort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	content := []byte(`schemaVersion: 2
targets:
  - name: core-sw-01
    address: 10.20.0.11
    profile: core-switch
    site: hq
    detectionCohort: arista-core-7050
`)
	if err := writeFile(path, content); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	tf, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(tf.Targets) != 1 || tf.Targets[0].DetectionCohort != "arista-core-7050" {
		t.Fatalf("unexpected parse result: %+v", tf)
	}
}

func TestSaveTargets_V1FieldsOnlyStaysV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	tf := TargetFile{Targets: []Target{{Name: "a", Address: "1.2.3.4:9100", Profile: "p"}}}
	if err := SaveTargets(path, tf); err != nil {
		t.Fatalf("SaveTargets: %v", err)
	}
	got, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if got.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1 (no v2-only fields used)", got.SchemaVersion)
	}
}

func TestSaveTargets_DetectionCohortForcesV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	tf := TargetFile{Targets: []Target{{Name: "a", Address: "1.2.3.4", Profile: "p", DetectionCohort: "cohort-1"}}}
	if err := SaveTargets(path, tf); err != nil {
		t.Fatalf("SaveTargets: %v", err)
	}
	got, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if got.SchemaVersion != 2 {
		t.Fatalf("SchemaVersion = %d, want 2 (detectionCohort is a v2-only field)", got.SchemaVersion)
	}
}

func TestSaveProfiles_SNMPKindForcesV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scrape-profiles.yml")
	pf := ProfileFile{Profiles: map[string]Profile{
		"core-switch": {Kind: "snmp", JobName: "j", SubjectKind: "network_device", SNMP: &SNMPProfile{Modules: []string{"if_mib"}, AuthProfile: "a"}},
	}}
	if err := SaveProfiles(path, pf); err != nil {
		t.Fatalf("SaveProfiles: %v", err)
	}
	got, err := LoadProfiles(path)
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	if got.SchemaVersion != 2 {
		t.Fatalf("SchemaVersion = %d, want 2 (kind:snmp is a v2-only field)", got.SchemaVersion)
	}
}

func TestSaveTargets_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "targets.yml")
	enabled := false
	tf := TargetFile{Targets: []Target{{Name: "a", Address: "1.2.3.4:9100", Profile: "p", Enabled: &enabled}}}
	if err := SaveTargets(path, tf); err != nil {
		t.Fatalf("SaveTargets: %v", err)
	}
	got, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets after save: %v", err)
	}
	if len(got.Targets) != 1 || got.Targets[0].Name != "a" || got.Targets[0].IsEnabled() {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
