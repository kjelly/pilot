package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/anomalyco/pilot/internal/inventory"
)

func TestCopyMissingGroupVars_CopiesExampleForUsedStemOnly(t *testing.T) {
	t.Chdir(t.TempDir())

	mustWriteFile(t, "group_vars/dns.example.yml", "dns_forwarders: []\n")
	mustWriteFile(t, "group_vars/freeipa.example.yml", "freeipa_domain: ipa.pilot.internal\n")
	mustWriteFile(t, "group_vars/unused.example.yml", "should_not_be_copied: true\n")

	var buf bytes.Buffer
	copyMissingGroupVars(&buf, ".", []string{"dns", "freeipa"})

	assertFileContent(t, "group_vars/dns.yml", "dns_forwarders: []\n")
	assertFileContent(t, "group_vars/freeipa.yml", "freeipa_domain: ipa.pilot.internal\n")
	if _, err := os.Stat("group_vars/unused.yml"); !os.IsNotExist(err) {
		t.Fatalf("group_vars/unused.yml should not have been created (stem was never requested), stat err=%v", err)
	}
}

func TestCopyMissingGroupVars_DestinationFollowsBaseDirSourceStaysFixed(t *testing.T) {
	t.Chdir(t.TempDir())

	// The shipped example lives at the fixed ./group_vars location
	// (mirroring where the Docker image bakes it in, or a local repo
	// checkout's root) — NOT inside the output bundle directory.
	mustWriteFile(t, "group_vars/dns.example.yml", "dns_forwarders: []\n")

	var buf bytes.Buffer
	copyMissingGroupVars(&buf, filepath.Join("envs", "staging"), []string{"dns"})

	assertFileContent(t, filepath.Join("envs", "staging", "group_vars", "dns.yml"), "dns_forwarders: []\n")
	if _, err := os.Stat(filepath.Join("group_vars", "dns.yml")); !os.IsNotExist(err) {
		t.Fatalf("group_vars/dns.yml (CWD-relative) should NOT have been created; only the baseDir copy should exist, stat err=%v", err)
	}
}

func TestGroupVarsBaseDir(t *testing.T) {
	cases := map[string]string{
		"":                           ".",
		"-":                          ".",
		"inventory.yml":              ".",
		"envs/staging/inventory.yml": filepath.Join("envs", "staging"),
	}
	for in, want := range cases {
		if got := groupVarsBaseDir(in); got != want {
			t.Errorf("groupVarsBaseDir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCopyMissingGroupVars_NeverOverwritesExistingFile(t *testing.T) {
	t.Chdir(t.TempDir())

	mustWriteFile(t, "group_vars/dns.example.yml", "dns_forwarders: []\n")
	mustWriteFile(t, "group_vars/dns.yml", "dns_forwarders: [\"10.0.0.1\"]\n") // already filled in by the operator

	var buf bytes.Buffer
	copyMissingGroupVars(&buf, ".", []string{"dns"})

	assertFileContent(t, "group_vars/dns.yml", "dns_forwarders: [\"10.0.0.1\"]\n")
	if got := buf.String(); !bytes.Contains([]byte(got), []byte("already exists")) {
		t.Fatalf("expected a message noting dns.yml was left untouched, got: %q", got)
	}
}

func TestCopyMissingGroupVars_RoleWithNoExampleIsSkippedSilently(t *testing.T) {
	t.Chdir(t.TempDir())

	var buf bytes.Buffer
	copyMissingGroupVars(&buf, ".", []string{"docker"}) // "docker" has no group_vars example anywhere in this repo

	if _, err := os.Stat("group_vars/docker.yml"); !os.IsNotExist(err) {
		t.Fatalf("group_vars/docker.yml should not have been created, stat err=%v", err)
	}
	if got := buf.String(); got != "" {
		t.Fatalf("expected no output for a role with no group_vars example, got: %q", got)
	}
}

func TestResolveGenPaths_DefaultDirLeavesPathsAlone(t *testing.T) {
	in, out := resolveGenPaths(".", "hosts.yml", "inventory.yml", false, false)
	if in != "hosts.yml" || out != "inventory.yml" {
		t.Fatalf("got (%q, %q), want (%q, %q)", in, out, "hosts.yml", "inventory.yml")
	}
}

func TestResolveGenPaths_DirRelocatesUnchangedDefaults(t *testing.T) {
	in, out := resolveGenPaths(filepath.Join("envs", "staging"), "hosts.yml", "inventory.yml", false, false)
	wantIn := filepath.Join("envs", "staging", "hosts.yml")
	wantOut := filepath.Join("envs", "staging", "inventory.yml")
	if in != wantIn || out != wantOut {
		t.Fatalf("got (%q, %q), want (%q, %q)", in, out, wantIn, wantOut)
	}
}

func TestResolveGenPaths_ExplicitInOutOverrideDir(t *testing.T) {
	in, out := resolveGenPaths(filepath.Join("envs", "staging"), "custom-hosts.yml", "custom-out.yml", true, true)
	if in != "custom-hosts.yml" || out != "custom-out.yml" {
		t.Fatalf("explicit --in/--out should win over --dir, got (%q, %q)", in, out)
	}
}

func TestResolveGenPaths_StdoutNeverGetsDirPrefix(t *testing.T) {
	_, out := resolveGenPaths(filepath.Join("envs", "staging"), "hosts.yml", "-", false, false)
	if out != "-" {
		t.Fatalf("out = %q, want %q (stdout has no directory)", out, "-")
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s content = %q, want %q", path, string(got), want)
	}
}

func TestResolveGenArtifactPath(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		path    string
		changed bool
		want    string
	}{
		{name: "stdout bundle falls back to cwd", out: "-", path: ".vault/main.yaml", want: filepath.Join(".", ".vault", "main.yaml")},
		{name: "inventory bundle relocates default", out: filepath.Join("envs", "staging", "inventory.yml"), path: ".vault/main.yaml", want: filepath.Join("envs", "staging", ".vault", "main.yaml")},
		{name: "explicit path wins", out: filepath.Join("envs", "staging", "inventory.yml"), path: "custom/vault.yaml", changed: true, want: "custom/vault.yaml"},
	}
	for _, tc := range cases {
		if got := resolveGenArtifactPath(tc.out, tc.path, tc.changed); got != tc.want {
			t.Fatalf("%s: resolveGenArtifactPath(%q, %q, %v) = %q, want %q", tc.name, tc.out, tc.path, tc.changed, got, tc.want)
		}
	}
}

func TestWriteMissingVaultSkeleton_WritesOnlyForVaultRoles(t *testing.T) {
	t.Chdir(t.TempDir())

	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", Roles: []string{"freeipa-server", "restic-backup"}},
	}}

	var buf bytes.Buffer
	writeMissingVaultSkeleton(&buf, filepath.Join("envs", "staging", ".vault", "main.yaml"), hf)

	path := filepath.Join("envs", "staging", ".vault", "main.yaml")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	content := string(got)
	for _, want := range []string{"ipa_admin_password:", "restic_password:"} {
		if !bytes.Contains(got, []byte(want)) {
			t.Fatalf("vault skeleton missing %q:\n%s", want, content)
		}
	}
	if bytes.Contains(got, []byte("grafana_admin_password:")) {
		t.Fatalf("vault skeleton unexpectedly included unrelated key:\n%s", content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("vault file mode = %o, want 600", perm)
	}
	if got := buf.String(); !bytes.Contains([]byte(got), []byte("vault: wrote")) {
		t.Fatalf("expected a write message, got %q", got)
	}
}

func TestWriteMissingVaultSkeleton_NeverOverwritesExistingFile(t *testing.T) {
	t.Chdir(t.TempDir())

	mustWriteFile(t, filepath.Join(".vault", "main.yaml"), "keep: true\n")
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "dash-1", Roles: []string{"dashboard"}}}}

	var buf bytes.Buffer
	writeMissingVaultSkeleton(&buf, filepath.Join(".vault", "main.yaml"), hf)

	assertFileContent(t, filepath.Join(".vault", "main.yaml"), "keep: true\n")
	if got := buf.String(); !bytes.Contains([]byte(got), []byte("already exists")) {
		t.Fatalf("expected an already exists message, got %q", got)
	}
}

func TestWriteMissingVaultSkeleton_NoApplicableRolesIsSilent(t *testing.T) {
	t.Chdir(t.TempDir())

	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "web-1", Roles: []string{"linux-servers"}}}}

	var buf bytes.Buffer
	writeMissingVaultSkeleton(&buf, filepath.Join(".vault", "main.yaml"), hf)

	if _, err := os.Stat(filepath.Join(".vault", "main.yaml")); !os.IsNotExist(err) {
		t.Fatalf("vault skeleton should not have been created, stat err=%v", err)
	}
	if got := buf.String(); got != "" {
		t.Fatalf("expected no output, got %q", got)
	}
}
