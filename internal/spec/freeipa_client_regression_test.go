package spec

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaClientSpec locks the structural contract of
// docs/verification/freeipa-client.md: 10 rows C1..C10, lint-clean, and a
// generated verify playbook that covers every row.
//
// Note on inventory alignment: like freeipa-server.md, this spec's §1 Targets
// table declares group `freeipa-client`, but the vm-target reference
// environment puts the single host in group `all` (run/verify with
// `-e target_group=all`). We therefore do NOT assert SpecAndInventoryAgree
// here — the alignment responsibility lives in the `-e target_group=` override
// documented in the spec, not in a fixed group name.
func TestRegression_FreeipaClientSpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-client.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// 1. Row count is locked at 10.
	if len(s.Rows) != 10 {
		t.Fatalf("rows=%d want=10 (spec must cover C1..C10 inclusive)", len(s.Rows))
	}

	// 2. IDs are C1..C10 with no gaps and no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"}
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

// TestRegression_FreeipaClientSpec_AAACoverage — the spec's reason for
// existing is that FreeIPA supplies this Ubuntu client with Authentication,
// Authorization AND Audit. Lock one concrete, non-substitutable check per leg
// so a future edit can't quietly drop a whole AAA dimension.
func TestRegression_FreeipaClientSpec_AAACoverage(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-client.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	cmd := map[string]string{}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
	}

	// Authentication: C5 must resolve an IPA identity via SSSD (the id lookup).
	if !strings.HasPrefix(cmd["C5"], "id ") {
		t.Errorf("C5 (authentication) must be an `id <ipa-user>` lookup, got %q", cmd["C5"])
	}
	// Authentication: C4 must inspect the host Kerberos keytab.
	if !strings.Contains(cmd["C4"], "krb5.keytab") {
		t.Errorf("C4 (authentication) must check /etc/krb5.keytab, got %q", cmd["C4"])
	}
	// Authorization: C6 must assert SSSD delegates access control to IPA (HBAC).
	if !strings.Contains(cmd["C6"], "access_provider") || !strings.Contains(cmd["C6"], "ipa") {
		t.Errorf("C6 (authorization/HBAC) must assert access_provider=ipa, got %q", cmd["C6"])
	}
	// Authorization: C8 must query centrally-defined sudo as root without
	// invoking runuser/PAM, because canonical HBAC may intentionally deny the
	// fixture account's login while its sudo policy remains valid.
	if !strings.Contains(cmd["C8"], "sudo -l -U pilotuser") {
		t.Errorf("C8 (authorization/sudo) must use `sudo -l -U <user>`, got %q", cmd["C8"])
	}
	if strings.Contains(cmd["C8"], "runuser") {
		t.Errorf("C8 must not invoke runuser/PAM when isolating central sudo policy, got %q", cmd["C8"])
	}
	// Audit: C9 must check the audit daemon.
	if !strings.Contains(cmd["C9"], "auditd") {
		t.Errorf("C9 (audit) must check auditd, got %q", cmd["C9"])
	}
	// Audit: C10 must inspect kernel auditing state.
	if !strings.Contains(cmd["C10"], "auditctl") {
		t.Errorf("C10 (audit) must use auditctl, got %q", cmd["C10"])
	}
}

// TestRegression_FreeipaClientSpec_EnrollBeforeAAA — you cannot verify AAA
// before the host is enrolled and SSSD is up. C1 (enrolled) and C2 (sssd
// active) must precede every authn/authz/audit row.
func TestRegression_FreeipaClientSpec_EnrollBeforeAAA(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-client.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	lineOf := map[string]int{}
	for _, r := range s.Rows {
		lineOf[r.ID] = r.Line
	}
	for _, base := range []string{"C1", "C2"} {
		if _, ok := lineOf[base]; !ok {
			t.Fatalf("%s row missing", base)
		}
	}
	for _, aaa := range []string{"C4", "C5", "C6", "C7", "C8", "C9", "C10"} {
		if lineOf["C1"] >= lineOf[aaa] {
			t.Errorf("ordering: C1 (enrolled) at line %d must precede %s at line %d",
				lineOf["C1"], aaa, lineOf[aaa])
		}
		if lineOf["C2"] >= lineOf[aaa] {
			t.Errorf("ordering: C2 (sssd active) at line %d must precede %s at line %d",
				lineOf["C2"], aaa, lineOf[aaa])
		}
	}
}
