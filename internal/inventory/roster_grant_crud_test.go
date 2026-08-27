package inventory

import "testing"

func TestRosterGrantNames_EmptyWhenNoGrants(t *testing.T) {
	path := writeRosterFixture(t, grantsRosterBase)
	names, err := RosterGrantNames(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no grants, got: %v", names)
	}
}

func TestSimulateAddRosterGrant_ReportsCleanForValidGrant(t *testing.T) {
	path := writeRosterFixture(t, grantsRosterBase)
	grant := map[string]any{
		"name": "vendor-project-x",
		"kind": "temporary_grant",
		"subjects": map[string]any{
			"users": []string{"vendor01"}, "groups": []string{},
		},
		"targets": map[string]any{
			"hosts": []string{"db-special.ipa.pilot.internal"}, "hostgroups": []string{},
		},
		"services": []string{"sshd"},
		"validity": map[string]any{"not_after": "2026-12-31T00:00:00Z"},
		"justification": map[string]any{
			"reason": "test",
		},
	}
	violations, err := SimulateAddRosterGrant(path, grant)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected a clean simulation, got: %v", violations)
	}

	// The file itself must be untouched by a Simulate call.
	names, err := RosterGrantNames(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected SimulateAddRosterGrant to write nothing, got grants: %v", names)
	}
}

func TestSimulateAddRosterGrant_ReportsViolationsForInvalidGrant(t *testing.T) {
	path := writeRosterFixture(t, grantsRosterBase)
	violations, err := SimulateAddRosterGrant(path, map[string]any{
		"name": "broken",
		"kind": "temporary_grant",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("expected violations for a grant missing subjects/targets/validity/justification")
	}
}

func TestAppendRosterGrant_ThenReadBack(t *testing.T) {
	path := writeRosterFixture(t, grantsRosterBase)
	grant := map[string]any{
		"name": "vendor-project-x",
		"kind": "temporary_grant",
		"subjects": map[string]any{
			"users": []string{"vendor01"}, "groups": []string{},
		},
		"targets": map[string]any{
			"hosts": []string{"db-special.ipa.pilot.internal"}, "hostgroups": []string{},
		},
		"services": []string{"sshd"},
		"validity": map[string]any{"not_after": "2026-12-31T00:00:00Z"},
		"justification": map[string]any{
			"reason": "test",
		},
	}
	if err := AppendRosterGrant(path, grant); err != nil {
		t.Fatalf("AppendRosterGrant() error = %v", err)
	}

	names, err := RosterGrantNames(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 1 || names[0] != "vendor-project-x" {
		t.Fatalf("expected [vendor-project-x], got: %v", names)
	}

	got, found, err := RosterGrant(path, "vendor-project-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected to find the appended grant")
	}
	if stringField(got, "kind") != "temporary_grant" {
		t.Fatalf("unexpected grant: %+v", got)
	}

	if violations, err := ValidateRosterFile(path); err != nil || len(violations) != 0 {
		t.Fatalf("expected the roster to still validate cleanly after append, violations=%v err=%v", violations, err)
	}
}

func TestRosterGrant_NotFound(t *testing.T) {
	path := writeRosterFixture(t, grantsRosterBase)
	_, found, err := RosterGrant(path, "does-not-exist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false for a nonexistent grant")
	}
}

func TestSimulateSetRosterGrant_UpdatesAndValidates(t *testing.T) {
	path := writeRosterFixture(t, grantsRosterBase)
	grant := map[string]any{
		"name": "vendor-project-x",
		"kind": "temporary_grant",
		"subjects": map[string]any{
			"users": []string{"vendor01"}, "groups": []string{},
		},
		"targets": map[string]any{
			"hosts": []string{"db-special.ipa.pilot.internal"}, "hostgroups": []string{},
		},
		"services": []string{"sshd"},
		"validity": map[string]any{"not_after": "2026-12-31T00:00:00Z"},
		"justification": map[string]any{
			"reason": "test",
		},
	}
	if err := AppendRosterGrant(path, grant); err != nil {
		t.Fatalf("AppendRosterGrant() error = %v", err)
	}

	updated := map[string]any{
		"name": "vendor-project-x",
		"kind": "temporary_grant",
		"subjects": map[string]any{
			"users": []string{"vendor01"}, "groups": []string{},
		},
		"targets": map[string]any{
			"hosts": []string{"db-special.ipa.pilot.internal"}, "hostgroups": []string{},
		},
		"services": []string{"sshd"},
		"validity": map[string]any{"not_after": "2099-12-31T00:00:00Z"},
		"justification": map[string]any{
			"reason": "extended",
		},
	}
	violations, ok, err := SimulateSetRosterGrant(path, "vendor-project-x", updated)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected to find the grant to update")
	}
	if len(violations) != 0 {
		t.Fatalf("expected a clean simulation, got: %v", violations)
	}

	// The file itself must be untouched by a Simulate call.
	got, _, err := RosterGrant(path, "vendor-project-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stringField(mapField(got, "justification"), "reason") != "test" {
		t.Fatalf("expected SimulateSetRosterGrant to write nothing, got: %+v", got)
	}
}

func TestSetRosterGrant_PersistsUpdate(t *testing.T) {
	path := writeRosterFixture(t, grantsRosterBase)
	grant := map[string]any{
		"name": "vendor-project-x",
		"kind": "temporary_grant",
		"subjects": map[string]any{
			"users": []string{"vendor01"}, "groups": []string{},
		},
		"targets": map[string]any{
			"hosts": []string{"db-special.ipa.pilot.internal"}, "hostgroups": []string{},
		},
		"services": []string{"sshd"},
		"validity": map[string]any{"not_after": "2026-12-31T00:00:00Z"},
		"justification": map[string]any{
			"reason": "test",
		},
	}
	if err := AppendRosterGrant(path, grant); err != nil {
		t.Fatalf("AppendRosterGrant() error = %v", err)
	}

	updated := map[string]any{
		"name": "vendor-project-x",
		"kind": "temporary_grant",
		"subjects": map[string]any{
			"users": []string{"vendor01"}, "groups": []string{},
		},
		"targets": map[string]any{
			"hosts": []string{"db-special.ipa.pilot.internal"}, "hostgroups": []string{},
		},
		"services": []string{"sshd"},
		"validity": map[string]any{"not_after": "2026-12-31T00:00:00Z"},
		"justification": map[string]any{
			"reason": "test",
		},
		"state": "absent",
	}
	if err := SetRosterGrant(path, "vendor-project-x", updated); err != nil {
		t.Fatalf("SetRosterGrant() error = %v", err)
	}

	got, found, err := RosterGrant(path, "vendor-project-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected to still find the grant after soft-delete (state: absent)")
	}
	if stringField(got, "state") != "absent" {
		t.Fatalf("expected state: absent to persist, got: %+v", got)
	}
}

func TestSetRosterGrant_ErrorsForUnknownName(t *testing.T) {
	path := writeRosterFixture(t, grantsRosterBase)
	err := SetRosterGrant(path, "does-not-exist", map[string]any{"name": "does-not-exist"})
	if err == nil {
		t.Fatal("expected an error for a nonexistent grant name")
	}
}
