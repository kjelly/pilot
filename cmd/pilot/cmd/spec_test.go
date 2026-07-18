package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSpecGenerate_Pipeline exercises the end-to-end pipeline:
// 1) parse a spec from a temp file
// 2) generate a playbook
// 3) ensure the file was written and contains one task per row
// 4) ensure syntax is acceptable as YAML by Round-tripping it
//
// This is a smoke test for the spec/parser + generator wiring that
// backs `pilot spec --generate`. It does NOT shell out to ansible.
func TestSpecGenerate_Pipeline(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "x.md")
	pbPath := filepath.Join(tmp, "out.yml")

	specBody := `# Verification Spec — pipeline test

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | sshd | present | ` + "`test -f /etc/ssh/sshd_config`" + ` |
| C2 | sysctl | ip_forward | "0" | ` + "`sysctl -n net.ipv4.ip_forward`" + ` |
| C3 | service | sshd | active | ` + "`systemctl is-active sshd`" + ` |
`
	if err := os.WriteFile(specPath, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseSpecForTest(specPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Rows) != 3 {
		t.Fatalf("rows=%d want=3", len(parsed.Rows))
	}
	pb, err := generateSpecPlaybookForTest(parsed)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(pb.Tasks) != 3 {
		t.Fatalf("tasks=%d want=3", len(pb.Tasks))
	}
	out := pb.RenderYAML()
	if err := os.WriteFile(pbPath, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(pbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"hosts: localhost",
		"ansible.builtin.stat:",
		"ansible.posix.sysctl:",
		"ansible.builtin.systemd:",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("generated playbook missing %q\n%s", want, got)
		}
	}
}

// TestSpecGenerate_RejectsDeprecatedVerifyDir locks the 2026-07-17
// deprecation of playbooks/verify/: `pilot spec --generate` must refuse to
// write there (relative or absolute), while playbooks/generated/ stays fine.
func TestSpecGenerate_RejectsDeprecatedVerifyDir(t *testing.T) {
	for _, out := range []string{
		"playbooks/verify/docker.yml",
		"/repo/playbooks/verify/docker.yml",
	} {
		err := checkGenerateOutPath(out, "docs/verification/docker.md")
		if err == nil {
			t.Fatalf("outPath=%q: want deprecation error, got nil", out)
		}
		if !strings.Contains(err.Error(), "deprecated") {
			t.Fatalf("outPath=%q: error %q does not mention deprecation", out, err)
		}
	}
	if err := checkGenerateOutPath("/repo/playbooks/generated/docker.yml", "docs/verification/docker.md"); err != nil {
		t.Fatalf("playbooks/generated must stay allowed, got: %v", err)
	}
}
