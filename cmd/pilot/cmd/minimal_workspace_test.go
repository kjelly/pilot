package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useRepositoryTemplates(t *testing.T) {
	t.Helper()
	t.Chdir(filepath.Join("..", "..", ".."))
}

func TestPrepareMinimalWorkspace_CreatesArtifactsAndPrefillsDerivedHosts(t *testing.T) {
	useRepositoryTemplates(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.10
    roles: [seaweedfs-s3, prometheus, thanos-query, alertmanager, dashboard, restic-backup]
`)

	if err := prepareMinimalWorkspace(dir); err != nil {
		t.Fatalf("prepareMinimalWorkspace() error = %v", err)
	}
	for _, path := range []string{
		"inventory.yml",
		"group_vars/prometheus.yml",
		"group_vars/thanos-query.yml",
		"group_vars/restic-backup.yml",
		".vault/main.yaml",
		"host_vars/nexus.yml",
	} {
		if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
			t.Errorf("%s not created: %v", path, err)
		}
	}
	for _, path := range []string{
		"group_vars/prometheus.yml",
		"group_vars/thanos-query.yml",
		"group_vars/restic-backup.yml",
	} {
		data, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "10.0.0.10") {
			t.Errorf("%s did not contain the derived host:\n%s", path, data)
		}
	}
}

func TestPrepareMinimalWorkspace_DoesNotReplaceActiveOverride(t *testing.T) {
	useRepositoryTemplates(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  s3:
    ansible_host: 10.0.0.10
    roles: [seaweedfs-s3]
  metrics:
    ansible_host: 10.0.0.11
    roles: [prometheus]
`)
	writeFile(t, filepath.Join(dir, "group_vars", "prometheus.yml"), "---\nthanos_s3_target_host: \"s3.external.example\"\n")

	if err := prepareMinimalWorkspace(dir); err != nil {
		t.Fatalf("prepareMinimalWorkspace() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "group_vars", "prometheus.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "s3.external.example") {
		t.Fatalf("active override was replaced:\n%s", data)
	}
}

func TestMinimalWorkspaceReadiness_ReportsBlockingChecks(t *testing.T) {
	useRepositoryTemplates(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.10
    roles: [prometheus]
`)

	checks, err := minimalWorkspaceReadiness(dir)
	if err != nil {
		t.Fatalf("minimalWorkspaceReadiness() error = %v", err)
	}
	c := findCheck(t, checks, filepath.Join("host_vars", "nexus.yml"))
	if c.OK {
		t.Fatalf("host_vars/nexus.yml = %+v, want missing prometheus_site_label", c)
	}
}
