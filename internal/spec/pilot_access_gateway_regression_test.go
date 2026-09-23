package spec

import (
	"os"
	"strings"
	"testing"
)

// This spec intentionally supports a target_group override for disposable
// multi-VM topologies, so the vm-target reference inventory is not expected to
// expose a literal pilot-access-gateway group. Alignment is owned by the
// topology inventory used by the evidence run (AGENTS.md §3 exception).
func TestRegression_PilotAccessGatewaySpec(t *testing.T) {
	const specPath = "../../docs/verification/pilot-access-gateway.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	wantIDs := []string{"AG01", "AG02", "AG03", "AG04", "AG06", "AG09", "AG12", "AG19", "AG30", "AG32", "AG33", "AG34", "AG35", "AG36", "AG37", "AG38", "AG39", "AG40", "AG41", "AG42", "AG43", "AG44", "AG45", "AG46", "AG47", "AG48", "AG49", "AG56"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, row := range s.Rows {
		if row.ID != wantIDs[i] {
			t.Errorf("row[%d].ID=%q want=%q", i, row.ID, wantIDs[i])
		}
		if strings.TrimSpace(row.Expected) == "" || strings.TrimSpace(row.Command) == "" {
			t.Errorf("row %s has empty expected or command", row.ID)
		}
	}
	if findings := Lint(s); HasErrors(findings) {
		t.Fatalf("spec lint errors:\n%s", fsToString(findings))
	}
}

func TestRegression_PilotAccessGatewayGSSAPIOnlyContract(t *testing.T) {
	const specPath = "../../docs/verification/pilot-access-gateway.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	rows := map[string]Row{}
	for _, row := range s.Rows {
		rows[row.ID] = row
	}
	for _, required := range []string{
		"gssapiauthentication yes",
		"gssapidelegatecredentials no",
		"preferredauthentications gssapi-with-mic",
		"batchmode yes",
		"passwordauthentication no",
		"kbdinteractiveauthentication no",
		"pubkeyauthentication false",
	} {
		if !strings.Contains(strings.ToLower(rows["AG32"].Command), required) {
			t.Errorf("AG32 command must enforce %q", required)
		}
	}
	for _, binary := range []string{"/usr/bin/kinit", "/usr/bin/klist", "/usr/bin/kdestroy"} {
		if !strings.Contains(rows["AG33"].Command, binary) {
			t.Errorf("AG33 command missing %s", binary)
		}
	}

	playbook, err := os.ReadFile("../../playbooks/apply/pilot-access-gateway-apply.yml")
	if err != nil {
		t.Fatalf("read playbook: %v", err)
	}
	text := strings.ToLower(string(playbook))
	for _, required := range []string{
		"gssapidelegatecredentials no",
		"preferredauthentications gssapi-with-mic",
		"batchmode yes",
		"pubkeyauthentication no",
		"kbdinteractiveauthentication no",
		"passwordauthentication no",
		"tags: [ag_config, ag32]",
		"tags: [ag33]",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("playbook missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"gssapidelegatecredentials yes",
		"kbdinteractiveauthentication yes",
		"passwordauthentication yes",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("playbook must not allow Portal SSH fallback %q", forbidden)
		}
	}
}
