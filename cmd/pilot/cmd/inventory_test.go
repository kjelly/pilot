package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
