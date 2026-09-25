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
	wantIDs := []string{"AG01", "AG02", "AG03", "AG04", "AG06", "AG09", "AG12", "AG19", "AG30", "AG32", "AG33", "AG34", "AG41", "AG42", "AG43", "AG44", "AG81", "AG82", "AG83", "AG84", "AG85", "AG86", "AG87", "AG88", "AG89", "AG90", "AG91", "AG92", "AG93", "AG94", "AG95", "AG96"}
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

// AG01 checks the deployed gateway_id/gateway_scope, supplied as required
// Spec v2 inputs, instead of a hardcoded example deployment.
func TestRegression_PilotAccessGatewayAG01UsesInputs(t *testing.T) {
	const specPath = "../../docs/verification/pilot-access-gateway.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	if s.SchemaVersion != 2 {
		t.Fatalf("schemaVersion=%d want 2", s.SchemaVersion)
	}
	required := map[string]bool{}
	for _, in := range s.Inputs {
		required[in.Name] = in.Required
	}
	for _, name := range []string{"gateway_id", "gateway_scope"} {
		if !required[name] {
			t.Errorf("input %s must be declared and required", name)
		}
	}
	var ag01 Row
	for _, row := range s.Rows {
		if row.ID == "AG01" {
			ag01 = row
		}
	}
	for _, want := range []string{
		`"  id: $PILOT_VAR_GATEWAY_ID"`,
		`"  scope: $PILOT_VAR_GATEWAY_SCOPE"`,
		`"  target_hostgroup: pilot-target-$PILOT_VAR_GATEWAY_SCOPE"`,
	} {
		if !strings.Contains(ag01.Command, want) {
			t.Errorf("AG01 probe must match the whole config line %s", want)
		}
	}
	if strings.Contains(ag01.Command, "gpu") {
		t.Errorf("AG01 must not hardcode an example deployment: %q", ag01.Command)
	}
}

// TestRegression_PilotAccessGatewayTransportContract locks the gateway-side
// deployment invariants of the captive SSH transport (docs/superpowers/
// specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md
// §12.3-§12.5): transport defaults off, the wrapper no longer carries the
// shell TTY check (Go enforces it per state), the ForceCommand drop-in
// states AllowStreamLocalForwarding and never puts PermitUserEnvironment
// inside Match (sshd -t rejects it there), and the AG43/AG44 probes check
// exactly that.
func TestRegression_PilotAccessGatewayTransportContract(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/pilot-access-gateway-apply.yml")
	if err != nil {
		t.Fatalf("read playbook: %v", err)
	}
	playbook := string(raw)
	for _, required := range []string{
		"pilot_access_gateway_transport_enabled | default(false)",
		"            transport:\n              enabled: {{ pilot_access_gateway_effective_transport_enabled | bool | to_json }}",
		"              AllowStreamLocalForwarding no\n",
		"tags: [AG_forcecommand, AG43]",
		"tags: [AG_service, AG34, AG44]",
		"tags: [AG_config, AG01, AG41, AG42]",
	} {
		if !strings.Contains(playbook, required) {
			t.Errorf("playbook missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"[ -t 0 ] || exit 1",
		"              PermitUserEnvironment",
	} {
		if strings.Contains(playbook, forbidden) {
			t.Errorf("playbook must not contain %q", forbidden)
		}
	}

	s, err := Parse("../../docs/verification/pilot-access-gateway.md")
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	rows := map[string]Row{}
	for _, row := range s.Rows {
		rows[row.ID] = row
	}
	for id, tokens := range map[string][]string{
		"AG42": {"transport:", "enabled: (true|false)"},
		"AG43": {"AllowStreamLocalForwarding no", "! grep -q PermitUserEnvironment"},
		"AG44": {"exec /usr/bin/pilot portal-session", `! grep -q "\[ -t 0 \]"`},
	} {
		for _, tok := range tokens {
			if !strings.Contains(rows[id].Command, tok) {
				t.Errorf("%s command must contain %q, got %q", id, tok, rows[id].Command)
			}
		}
	}
}
