package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// repoRootForTest walks up from the current package directory until it
// finds go.mod. Tests run with cwd == the package's source directory,
// so deployCatalog's playbook paths (repo-root-relative) need this to
// actually stat the files on disk.
func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) above " + dir)
		}
		dir = parent
	}
}

func TestDeployCatalog_PlaybooksExistAndAreWellFormed(t *testing.T) {
	root := repoRootForTest(t)
	seen := map[string]bool{}
	for _, p := range deployCatalog {
		if p.Key == "" {
			t.Fatalf("catalog entry %q has an empty Key", p.Label)
		}
		if seen[p.Key] {
			t.Fatalf("duplicate catalog Key %q", p.Key)
		}
		seen[p.Key] = true

		if p.StageVar != "stage" && p.StageVar != "patch_stage" {
			t.Fatalf("%s: StageVar must be \"stage\" or \"patch_stage\", got %q", p.Key, p.StageVar)
		}

		full := filepath.Join(root, p.Playbook)
		if _, err := os.Stat(full); err != nil {
			t.Fatalf("%s: playbook %s does not exist: %v", p.Key, p.Playbook, err)
		}
	}
	// AGENTS.md §4.3 tracks this count; keep the two in sync deliberately
	// rather than silently drifting.
	if len(deployCatalog) != 20 {
		t.Fatalf("expected 20 apply playbooks in the catalog (see AGENTS.md §4.3), got %d", len(deployCatalog))
	}
}

func TestValidateOptionalKV(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"  ", false},
		{"a=b", false},
		{"a=b c=d", false},
		{"a=b  c=d", false},
		{"noequals", true},
		{"a=b bad", true},
	}
	for _, c := range cases {
		err := validateOptionalKV(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validateOptionalKV(%q) error=%v, wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestValidateHoursWithinWeek(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"0", false},
		{"168", false},
		{"169", true},
		{"-1", true},
		{"abc", true},
	}
	for _, c := range cases {
		err := validateHoursWithinWeek(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validateHoursWithinWeek(%q) error=%v, wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestValidateFileExists(t *testing.T) {
	root := repoRootForTest(t)
	if err := validateFileExists(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("expected go.mod to exist: %v", err)
	}
	if err := validateFileExists(""); err == nil {
		t.Error("expected error for empty path")
	}
	if err := validateFileExists("/does/not/exist/nope"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestIsVaultEncrypted(t *testing.T) {
	dir := t.TempDir()

	encrypted := filepath.Join(dir, "encrypted.yaml")
	if err := os.WriteFile(encrypted, []byte("$ANSIBLE_VAULT;1.1;AES256\n62353933...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isVaultEncrypted(encrypted) {
		t.Error("expected an ansible-vault header to be detected as encrypted")
	}

	plaintext := filepath.Join(dir, "plaintext.yaml")
	if err := os.WriteFile(plaintext, []byte("ipa_admin_password: hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if isVaultEncrypted(plaintext) {
		t.Error("expected plaintext YAML to not be detected as encrypted")
	}

	if isVaultEncrypted(filepath.Join(dir, "does-not-exist.yaml")) {
		t.Error("expected a missing file to not be detected as encrypted")
	}
}

func TestParseGroupHostFromInventoryList(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		group    string
		wantHost string
		wantOK   bool
	}{
		{
			name: "resolves ansible_host over the bare hostname",
			json: `{
				"seaweedfs-s3": {"hosts": ["it-service"]},
				"_meta": {"hostvars": {"it-service": {"ansible_host": "10.1.58.12"}}}
			}`,
			group:    "seaweedfs-s3",
			wantHost: "10.1.58.12",
			wantOK:   true,
		},
		{
			name: "falls back to the inventory hostname with no ansible_host",
			json: `{
				"seaweedfs-s3": {"hosts": ["s3-gateway"]},
				"_meta": {"hostvars": {"s3-gateway": {}}}
			}`,
			group:    "seaweedfs-s3",
			wantHost: "s3-gateway",
			wantOK:   true,
		},
		{
			name: "resolves a different group name",
			json: `{
				"wazuh-manager": {"hosts": ["wazuh-mgr"]},
				"seaweedfs-s3": {"hosts": ["it-service"]},
				"_meta": {"hostvars": {"wazuh-mgr": {"ansible_host": "10.1.58.20"}, "it-service": {"ansible_host": "10.1.58.12"}}}
			}`,
			group:    "wazuh-manager",
			wantHost: "10.1.58.20",
			wantOK:   true,
		},
		{
			name:     "group absent",
			json:     `{"_meta": {"hostvars": {}}}`,
			group:    "seaweedfs-s3",
			wantHost: "",
			wantOK:   false,
		},
		{
			name:     "group present but empty",
			json:     `{"seaweedfs-s3": {"hosts": []}, "_meta": {"hostvars": {}}}`,
			group:    "seaweedfs-s3",
			wantHost: "",
			wantOK:   false,
		},
		{
			name:     "unparseable JSON",
			json:     `not json`,
			group:    "seaweedfs-s3",
			wantHost: "",
			wantOK:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, ok := parseGroupHostFromInventoryList(c.json, c.group)
			if host != c.wantHost || ok != c.wantOK {
				t.Errorf("got (%q, %v), want (%q, %v)", host, ok, c.wantHost, c.wantOK)
			}
		})
	}
}

func TestDefaultVaultFile(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inv, []byte("all:\n  hosts: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := defaultVaultFile(inv); got != "" {
		t.Errorf("expected no vault file detected yet, got %q", got)
	}

	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	vaultFile := filepath.Join(vaultDir, "main.yaml")
	if err := os.WriteFile(vaultFile, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := defaultVaultFile(inv); got != vaultFile {
		t.Errorf("expected %q, got %q", vaultFile, got)
	}
}
