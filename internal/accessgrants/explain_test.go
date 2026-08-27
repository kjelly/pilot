package accessgrants

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const explainTestRoster = `
schema_version: 3
freeipa:
  domain: ipa.pilot.internal
  admin: {principal: admin, password: x}
users:
  - name: vendor01
    ssh_keys: {authoritative: true, values: []}
  - name: emergency-admin
    ssh_keys: {authoritative: true, values: []}
groups: []
hosts:
  - name: db-special.ipa.pilot.internal
    ip_address: 10.0.0.5
hostgroups: []
hbac:
  rules:
    - name: static-rule
      subjects: {users: [vendor01], groups: []}
      targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
      services: [sshd]
sudo:
  rules: []
grants:
  - name: vendor-project-x
    kind: temporary_grant
    subjects: {users: [vendor01], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    validity: {not_after: "2026-12-31T00:00:00Z"}
    justification: {reason: "explain test"}
  - name: infra-emergency
    kind: breakglass
    subjects: {users: [emergency-admin], groups: []}
    targets: {hosts: [db-special.ipa.pilot.internal], hostgroups: []}
    services: [sshd]
    activation: {max_duration: 1h, require_reason: true, require_ticket: true}
`

func writeExplainTestRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(explainTestRoster), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

func TestExplain_CombinesStaticHBACAndTemporaryGrant(t *testing.T) {
	rosterPath := writeExplainTestRoster(t)
	sources, err := Explain(rosterPath, t.TempDir(), "vendor01", "db-special.ipa.pilot.internal", "sshd", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kinds := map[string]bool{}
	for _, s := range sources {
		kinds[s.Kind] = true
	}
	if !kinds["static_hbac"] || !kinds["temporary_grant"] {
		t.Fatalf("expected both static_hbac and temporary_grant sources, got: %+v", sources)
	}
}

func TestExplain_BreakglassOnlyAppearsWhenActivated(t *testing.T) {
	rosterPath := writeExplainTestRoster(t)
	stateDir := t.TempDir()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	before, err := Explain(rosterPath, stateDir, "emergency-admin", "db-special.ipa.pilot.internal", "sshd", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range before {
		if s.Kind == "breakglass" {
			t.Fatalf("expected no breakglass source before activation, got: %+v", before)
		}
	}

	if _, err := Activate(context.Background(), ActivateOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", StateDir: stateDir,
		Name: "infra-emergency", Duration: 45 * time.Minute, Reason: "x", Ticket: "y",
		Now: now, Runner: &fakeRunner{exitCode: 0},
	}); err != nil {
		t.Fatalf("activate: %v", err)
	}

	after, err := Explain(rosterPath, stateDir, "emergency-admin", "db-special.ipa.pilot.internal", "sshd", now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, s := range after {
		if s.Kind == "breakglass" {
			found = true
			if s.NextTransition == nil || !s.NextTransition.Equal(now.Add(45*time.Minute)) {
				t.Fatalf("expected NextTransition to equal the activation's expiry, got: %+v", s)
			}
		}
	}
	if !found {
		t.Fatalf("expected a breakglass source once activated, got: %+v", after)
	}

	// After the activation expires, it must drop out again.
	expired, err := Explain(rosterPath, stateDir, "emergency-admin", "db-special.ipa.pilot.internal", "sshd", now.Add(46*time.Minute))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range expired {
		if s.Kind == "breakglass" {
			t.Fatalf("expected no breakglass source once the activation has expired, got: %+v", expired)
		}
	}
}
