package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeVarsFixture(t *testing.T, base string, files ...string) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(base, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x: 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestShadowedVarsFiles_ReportsFileNextToSameNamedDirectory(t *testing.T) {
	base := t.TempDir()
	writeVarsFixture(t, base,
		"group_vars/dns.yml", "group_vars/dns/zones.yaml",
		"group_vars/ntp.yaml", "group_vars/ntp/main.yml",
		"host_vars/tier-1.json", "host_vars/tier-1/x.yml",
	)
	got, err := ShadowedVarsFiles(base)
	if err != nil {
		t.Fatal(err)
	}
	want := []VarsShadow{
		{File: filepath.Join(base, "group_vars", "dns.yml"), Dir: filepath.Join(base, "group_vars", "dns")},
		{File: filepath.Join(base, "group_vars", "ntp.yaml"), Dir: filepath.Join(base, "group_vars", "ntp")},
		{File: filepath.Join(base, "host_vars", "tier-1.json"), Dir: filepath.Join(base, "host_vars", "tier-1")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ShadowedVarsFiles = %+v\nwant %+v", got, want)
	}
}

func TestShadowedVarsFiles_NothingWhenFilesAndDirectoriesDoNotCollide(t *testing.T) {
	base := t.TempDir()
	writeVarsFixture(t, base,
		"group_vars/dns.yml", "group_vars/freeipa.yml", "group_vars/dns.example.yml",
		"group_vars/prometheus/main.yml",
		"host_vars/tier-1.yml", "host_vars/tier-2/x.yml",
	)
	got, err := ShadowedVarsFiles(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("ShadowedVarsFiles = %+v, want none", got)
	}
}

func TestShadowedVarsFiles_MissingVarsDirectoriesAreNotAnError(t *testing.T) {
	got, err := ShadowedVarsFiles(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Fatalf("ShadowedVarsFiles(empty) = %+v, %v; want none, nil", got, err)
	}
}
