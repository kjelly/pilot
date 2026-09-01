package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_AgentControllerSpec locks the structure of
// docs/verification/agent-controller.md (Phase 1, spec §15's C1-C13) and
// a handful of playbook-source invariants that must never regress:
//
//	C1  dedicated pilot-agent account + active service
//	C2  private/network-scoped listener (never 0.0.0.0)
//	C3  invalid webhook auth rejected with 401
//	C4  config schema validates
//	C5  SQLite integrity + ownership/mode
//	C6  status/textfile parseable and secret-free
//	C7  replay/escalation dedup scenario (verifyOnly)
//	C8  observe-only MCP capability boundary (verifyOnly)
//	C9  valid diagnosis persists scenario (verifyOnly)
//	C10 malformed output never a partial diagnosis (verifyOnly)
//	C11 restart preserves incident state scenario (verifyOnly)
//	C12 no SSH key / vault password file
//	C13 idempotent reapply changed=0 (verifyOnly)
func TestRegression_AgentControllerSpec(t *testing.T) {
	const specPath = "../../docs/verification/agent-controller.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	wantVerifyOnly := map[string]bool{"C7": true, "C8": true, "C9": true, "C10": true, "C11": true, "C13": true}
	for _, r := range s.Rows {
		if wantVerifyOnly[r.ID] && !r.VerifyOnly {
			t.Errorf("%s must be verifyOnly — its scenario evidence comes from the disposable-lane topology test, not a single already-applied host", r.ID)
		}
		if !wantVerifyOnly[r.ID] && r.VerifyOnly {
			t.Errorf("%s must NOT be verifyOnly", r.ID)
		}
	}

	// Every non-verifyOnly row must declare an isolatedMutation-free
	// (readOnly) action — Phase 1 verification never mutates the target.
	for _, r := range s.Rows {
		if r.Action == nil {
			continue
		}
		if r.Action.Mode != "readOnly" {
			t.Errorf("%s: action mode = %q, want readOnly (Phase 1 verification is read-only)", r.ID, r.Action.Mode)
		}
	}

	// No credentials belong in a spec (AGENTS.md).
	for _, r := range s.Rows {
		lower := strings.ToLower(r.Command)
		for _, forbidden := range []string{"secret_key", "access_key", "api_key=", "password="} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s must not reference %q (no credentials in spec); got %q", r.ID, forbidden, r.Command)
			}
		}
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	playbookRaw, err := os.ReadFile("../../playbooks/apply/agent-controller-apply.yml")
	if err != nil {
		t.Fatalf("read agent-controller-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)

	// spec §5.2: the listener must never bind to the wildcard address —
	// it is resolved from this host's own default route, not hardcoded.
	if strings.Contains(applyRaw, `listenAddr: "0.0.0.0`) {
		t.Error("agent-controller-apply.yml must never bind the webhook listener to 0.0.0.0 (spec §5.2's private/network-scoped requirement)")
	}
	if !strings.Contains(applyRaw, "ansible_default_ipv4.address") {
		t.Error("agent-controller-apply.yml must resolve agent_controller_listen_addr from ansible_default_ipv4.address when not explicitly overridden")
	}

	// spec §14: controller-side artifact existence/SHA256/version must be
	// gated before any mutation, and re-verified again on the target
	// after copy — same discipline as detection-engine-apply.yml.
	for _, want := range []string{
		"agent_controller_artifact_abs_path",
		"checksum_algorithm: sha256",
		"agent_controller_artifact_sha256",
	} {
		if !strings.Contains(applyRaw, want) {
			t.Errorf("agent-controller-apply.yml must reference %q (artifact verification)", want)
		}
	}

	// spec §5: unauthenticated webhooks must fail closed — the shared
	// secret is required with no default, and never lands in config.yaml
	// itself (only the env var NAME it arrives through).
	if strings.Contains(applyRaw, "agent_controller_webhook_secret:") && !strings.Contains(applyRaw, "agent_controller_webhook_secret is defined") {
		t.Error("agent-controller-apply.yml must gate on agent_controller_webhook_secret being defined, not default it")
	}
	if !strings.Contains(applyRaw, "webhookSecretEnv:") {
		t.Error("agent-controller-apply.yml's rendered config.yaml must carry webhookSecretEnv, never the secret value itself")
	}

	// The webhook-secret.env-rendering task (the one place the real
	// secret value is templated) must be no_log: true within its own
	// task body, before the next task starts.
	if idx := strings.Index(applyRaw, `"Step 9: render webhook-secret.env`); idx < 0 {
		t.Error(`agent-controller-apply.yml missing the "Step 9: render webhook-secret.env" task`)
	} else {
		rest := applyRaw[idx:]
		nextTask := strings.Index(rest[1:], "\n        - name:")
		if nextTask < 0 {
			nextTask = len(rest)
		} else {
			nextTask++
		}
		if !strings.Contains(rest[:nextTask], "no_log: true") {
			t.Error("webhook-secret.env's render task must be no_log: true within its own task body (never logs the real secret value)")
		}
	}

	// spec §8: minimum required systemd hardening directives.
	for _, want := range []string{
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=",
	} {
		if !strings.Contains(applyRaw, want) {
			t.Errorf("agent-controller-apply.yml systemd unit must set %q", want)
		}
	}

	// idempotency: `state: restarted` must stay conditional on something
	// actually changing — never unconditional.
	if strings.Contains(applyRaw, "state: restarted\n          when: not ansible_check_mode\n") {
		t.Error("pilot-agent-controller.service restart must be gated on an actual change, not unconditional")
	}

	// spec §2: the controller must never be handed an SSH credential or
	// Ansible vault password file by its OWN apply playbook — no task may
	// copy/template anything under a vault or ssh key path for this role.
	for _, forbidden := range []string{"id_rsa", "id_ed25519", ".vault"} {
		if strings.Contains(applyRaw, forbidden) {
			t.Errorf("agent-controller-apply.yml must never reference %q — the controller holds no SSH credential or vault password file (spec §2)", forbidden)
		}
	}
}
