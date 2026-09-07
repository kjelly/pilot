package workspaceintegrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMonitoringReportsMissingReferencedAssets(t *testing.T) {
	root := t.TempDir()
	monitoringDir := filepath.Join(root, "monitoring")
	if err := os.MkdirAll(monitoringDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(monitoringDir, "targets.yml"), []byte("targets:\n- name: fw\n  address: 10.0.0.1\n  profile: snmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(monitoringDir, "scrape-profiles.yml"), []byte("profiles:\n  snmp:\n    kind: snmp\n    diagnosticProfile: missing\n    snmp:\n      modules: [if_mib]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := Monitoring(root)
	if report.Verdict != "incomplete" {
		t.Fatalf("verdict = %q", report.Verdict)
	}
	if len(report.References) != 3 {
		t.Fatalf("references = %d, want 3", len(report.References))
	}
}

func TestMonitoringDistinguishesMissingSource(t *testing.T) {
	report := Monitoring(t.TempDir())
	if report.Verdict != "incomplete" || len(report.References) != 1 || report.References[0].Status != "missing" {
		t.Fatalf("report = %+v", report)
	}
}

func TestMonitoringSkipsSNMPReferencesForPrometheusProfile(t *testing.T) {
	root := t.TempDir()
	monitoringDir := filepath.Join(root, "monitoring")
	if err := os.MkdirAll(monitoringDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(monitoringDir, "targets.yml"), []byte("targets:\n- name: app\n  address: 127.0.0.1:9090\n  profile: prom\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(monitoringDir, "scrape-profiles.yml"), []byte("profiles:\n  prom:\n    jobName: app\n    kind: prometheus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if report := Monitoring(root); report.Verdict != "complete" {
		t.Fatalf("prometheus report = %+v, want complete", report)
	}
}

func TestMonitoringDistinguishesEmptySource(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "monitoring")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "targets.yml"), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := Monitoring(root)
	if report.Verdict != "incomplete" || len(report.References) != 1 || report.References[0].Status != "empty" {
		t.Fatalf("report = %+v", report)
	}
}
