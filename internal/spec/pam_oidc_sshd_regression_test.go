package spec

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_PamOidcSshdSpec v2.0 — aligned with kha7iq/kc-ssh-pam upstream.
// Key changes from v1:
//   - 9 rows (C1..C9), not 7 (added C6 monitor binary, C8/C9 config validation)
//   - PAM module is pam_keycloak_device.so (not pam_kc_ssh.so)
//   - Config path is /etc/keycloak-ssh/ (not /etc/kc-ssh-pam/)
//   - Backup suffix is .kcsssh.bak (not .pamoidc.bak)
func TestRegression_PamOidcSshdSpec(t *testing.T) {
	const specPath = "../../docs/verification/pam-oidc-sshd.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// 1. Row count is locked at 9.
	if len(s.Rows) != 9 {
		t.Fatalf("rows=%d want=9 (spec must cover C1..C9 inclusive)", len(s.Rows))
	}

	// 2. IDs are C1..C9 with no gaps and no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"}
	gotIDs := make([]string, 0, len(s.Rows))
	seen := map[string]bool{}
	for _, r := range s.Rows {
		if seen[r.ID] {
			t.Errorf("duplicate row ID %q", r.ID)
		}
		seen[r.ID] = true
		gotIDs = append(gotIDs, r.ID)
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("row IDs = %v, want %v", gotIDs, wantIDs)
	}

	// 3. No vague expected values, no empty fields.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", fsToString(fs))
	}
	for _, r := range s.Rows {
		if strings.TrimSpace(r.Expected) == "" {
			t.Errorf("row %s has empty Expected", r.ID)
		}
		if strings.TrimSpace(r.Command) == "" {
			t.Errorf("row %s has empty Command", r.ID)
		}
	}

	// 4. Generated playbook must be runnable YAML AND cover every row.
	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := pb.RenderYAML()
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(out), &plays); err != nil {
		t.Fatalf("generated playbook does not parse as YAML: %v\n--- output ---\n%s", err, out)
	}
	if len(plays) != 1 {
		t.Fatalf("generated playbook plays=%d, want 1", len(plays))
	}
	raw, _ := plays[0]["tasks"].([]any)
	if len(raw) == 0 || len(raw) > len(s.Rows) {
		t.Errorf("generated tasks=%d, expected 1..%d (dedup <= rows)", len(raw), len(s.Rows))
	}
	// Every spec row must appear in at least one task's SourceIDs.
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}
}

// TestRegression_PamOidcSshdSpec_BackupBeforeEdit — lockout-safety invariant.
// C3 (backup file present) must be evaluated before C4 (sshd PAM contains new module).
func TestRegression_PamOidcSshdSpec_BackupBeforeEdit(t *testing.T) {
	const specPath = "../../docs/verification/pam-oidc-sshd.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	lineOf := map[string]int{}
	for _, r := range s.Rows {
		lineOf[r.ID] = r.Line
	}
	if _, ok := lineOf["C3"]; !ok {
		t.Fatal("C3 row missing")
	}
	if _, ok := lineOf["C4"]; !ok {
		t.Fatal("C4 row missing")
	}
	if lineOf["C3"] >= lineOf["C4"] {
		t.Errorf("lockout-safety order violated: C3 (backup) at line %d, "+
			"C4 (modify sshd) at line %d — C3 MUST come before C4", lineOf["C3"], lineOf["C4"])
	}
}

// TestRegression_PamOidcSshdSpec_ServerUrlHTTPS — C8 must require https in server_url.
func TestRegression_PamOidcSshdSpec_ServerUrlHTTPS(t *testing.T) {
	const specPath = "../../docs/verification/pam-oidc-sshd.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	for _, r := range s.Rows {
		if r.ID != "C8" {
			continue
		}
		if !strings.Contains(r.Command, "https?://") {
			t.Errorf("C8 must require an http(s) URL: got %q", r.Command)
		}
		return
	}
	t.Fatal("C8 row missing from spec")
}

// TestRegression_PamOidcSshdSpec_CorrectModuleName — C2/C4 must reference
// pam_keycloak_device.so (not pam_kc_ssh.so which doesn't exist upstream).
func TestRegression_PamOidcSshdSpec_CorrectModuleName(t *testing.T) {
	const specPath = "../../docs/verification/pam-oidc-sshd.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	for _, r := range s.Rows {
		if r.ID == "C2" || r.ID == "C4" {
			if !strings.Contains(r.Command, "pam_keycloak_device.so") && !strings.Contains(r.Command, "pam_keycloak_device\\.so") {
				t.Errorf("row %s must reference pam_keycloak_device.so: got %q", r.ID, r.Command)
			}
			if strings.Contains(r.Command, "pam_kc_ssh.so") {
				t.Errorf("row %s must NOT reference non-existent pam_kc_ssh.so: got %q", r.ID, r.Command)
			}
		}
	}
}

// TestRegression_PamOidcSshdSpec_CorrectConfigPath — C8/C9 must reference
// /etc/keycloak-ssh/ (the real upstream path, not /etc/kc-ssh-pam/).
func TestRegression_PamOidcSshdSpec_CorrectConfigPath(t *testing.T) {
	const specPath = "../../docs/verification/pam-oidc-sshd.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	for _, r := range s.Rows {
		if r.ID == "C8" || r.ID == "C9" {
			if !strings.Contains(r.Command, "/etc/keycloak-ssh/") {
				t.Errorf("row %s must reference /etc/keycloak-ssh/: got %q", r.ID, r.Command)
			}
			if strings.Contains(r.Command, "/etc/kc-ssh-pam/") {
				t.Errorf("row %s must NOT reference wrong path /etc/kc-ssh-pam/: got %q", r.ID, r.Command)
			}
		}
	}
}

// fsToString mirrors the joinFindings helper from the old test file.
// Since Finding.String() is a method on a type defined in lint.go, we
// format the slice ourselves here.
func fsToString(fs []Finding) string {
	var sb strings.Builder
	for _, f := range fs {
		sb.WriteString(f.String())
		sb.WriteByte('\n')
	}
	return sb.String()
}
