package inventory

import (
	"testing"
	"time"
)

func breakglassGrant(t *testing.T, doc string) map[string]any {
	t.Helper()
	root := grantsRoster(t, doc)
	grants := listField(root, "grants")
	if len(grants) != 1 {
		t.Fatalf("expected exactly one grant, got %d", len(grants))
	}
	return asMap(grants[0])
}

const breakglassFixture = `
grants:
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    activation: {max_duration: 1h, require_reason: true, require_ticket: true}
`

func TestValidateBreakglassActivationRequest_RejectsNonBreakglassGrant(t *testing.T) {
	grant := mustGrant(t, `
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
`)
	if err := ValidateBreakglassActivationRequest(grant, mustParseAccessDuration(t, "30m"), "reason", "TICKET-1"); err == nil {
		t.Fatal("expected an error for a non-breakglass grant")
	}
}

func TestValidateBreakglassActivationRequest_RejectsDurationOverMax(t *testing.T) {
	grant := breakglassGrant(t, breakglassFixture)
	if err := ValidateBreakglassActivationRequest(grant, mustParseAccessDuration(t, "2h"), "outage", "INC-1"); err == nil {
		t.Fatal("expected an error when duration exceeds activation.max_duration")
	}
}

func TestValidateBreakglassActivationRequest_RejectsNonPositiveDuration(t *testing.T) {
	grant := breakglassGrant(t, breakglassFixture)
	if err := ValidateBreakglassActivationRequest(grant, 0, "outage", "INC-1"); err == nil {
		t.Fatal("expected an error for a zero duration")
	}
}

func TestValidateBreakglassActivationRequest_RequiresReasonAndTicketWhenPolicyDemandsThem(t *testing.T) {
	grant := breakglassGrant(t, breakglassFixture)
	if err := ValidateBreakglassActivationRequest(grant, mustParseAccessDuration(t, "30m"), "", "INC-1"); err == nil {
		t.Fatal("expected an error when reason is required but missing")
	}
	if err := ValidateBreakglassActivationRequest(grant, mustParseAccessDuration(t, "30m"), "outage", ""); err == nil {
		t.Fatal("expected an error when ticket is required but missing")
	}
	if err := ValidateBreakglassActivationRequest(grant, mustParseAccessDuration(t, "30m"), "outage", "INC-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBreakglassActivationRequest_AllowsOptionalReasonTicketWhenPolicyDoesNot(t *testing.T) {
	grant := breakglassGrant(t, `
grants:
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [alice], groups: []}
    targets: {hosts: [], hostgroups: [production-db]}
    services: [sshd]
    activation: {max_duration: 1h, require_reason: false, require_ticket: false}
`)
	if err := ValidateBreakglassActivationRequest(grant, mustParseAccessDuration(t, "30m"), "", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustParseAccessDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	parsed, err := ParseAccessDuration(s)
	if err != nil {
		t.Fatalf("parse duration %q: %v", s, err)
	}
	return parsed
}
