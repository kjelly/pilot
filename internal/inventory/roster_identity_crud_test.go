package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRosterToTempFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(grantsRosterBase), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path
}

func TestPasswordPolicyCRUD_AppendGetSimulateSet(t *testing.T) {
	path := writeRosterToTempFile(t)

	if err := AppendRosterPasswordPolicy(path, "privileged-users"); err != nil {
		t.Fatalf("AppendRosterPasswordPolicy() error = %v", err)
	}
	names, err := RosterPasswordPolicyNames(path)
	if err != nil || len(names) != 1 || names[0] != "privileged-users" {
		t.Fatalf("RosterPasswordPolicyNames() = %v, %v", names, err)
	}

	f, found, err := RosterPasswordPolicy(path, "privileged-users")
	if err != nil || !found {
		t.Fatalf("RosterPasswordPolicy() found=%v err=%v", found, err)
	}
	f["group"] = "role-production-operator"
	f["priority"] = 10

	// The second return value is true whenever the entry was matched at
	// all (found-and-clean or found-but-ambiguous) — every existing
	// caller (e.g. pushRosterHostgroupEdit) discards it and keys off
	// err/violations instead, so this test does the same.
	violations, _, err := SimulateSetRosterPasswordPolicy(path, "privileged-users", f)
	if err != nil || len(violations) != 0 {
		t.Fatalf("SimulateSetRosterPasswordPolicy() violations=%v, err=%v", violations, err)
	}
	if err := SetRosterPasswordPolicy(path, "privileged-users", f); err != nil {
		t.Fatalf("SetRosterPasswordPolicy() error = %v", err)
	}

	if v, err := ValidateRosterFile(path); err != nil || len(v) != 0 {
		t.Fatalf("expected the roster to validate clean after set, got: %v, err=%v", v, err)
	}
}

func TestPasswordPolicyCRUD_UnknownNameNotFound(t *testing.T) {
	path := writeRosterToTempFile(t)
	_, found, err := RosterPasswordPolicy(path, "does-not-exist")
	if err != nil || found {
		t.Fatalf("expected found=false, got found=%v err=%v", found, err)
	}
}

func TestCredentialPolicyCRUD_AppendGetSimulateSet(t *testing.T) {
	path := writeRosterToTempFile(t)

	if err := AppendRosterCredentialPolicy(path, "privileged-ssh"); err != nil {
		t.Fatalf("AppendRosterCredentialPolicy() error = %v", err)
	}
	names, err := RosterCredentialPolicyNames(path)
	if err != nil || len(names) != 1 || names[0] != "privileged-ssh" {
		t.Fatalf("RosterCredentialPolicyNames() = %v, %v", names, err)
	}

	f, found, err := RosterCredentialPolicy(path, "privileged-ssh")
	if err != nil || !found {
		t.Fatalf("RosterCredentialPolicy() found=%v err=%v", found, err)
	}
	f["match"] = map[string]any{"users": []string{}, "groups": []string{"role-production-operator"}}

	violations, _, err := SimulateSetRosterCredentialPolicy(path, "privileged-ssh", f)
	if err != nil || len(violations) != 0 {
		t.Fatalf("SimulateSetRosterCredentialPolicy() violations=%v, err=%v", violations, err)
	}
	if err := SetRosterCredentialPolicy(path, "privileged-ssh", f); err != nil {
		t.Fatalf("SetRosterCredentialPolicy() error = %v", err)
	}

	if v, err := ValidateRosterFile(path); err != nil || len(v) != 0 {
		t.Fatalf("expected the roster to validate clean after set, got: %v, err=%v", v, err)
	}
}

func TestKnownUserAuthTypes_ReturnsSpecSet(t *testing.T) {
	got := KnownUserAuthTypes()
	if len(got) != 4 || !contains(got, "otp") || !contains(got, "pkinit") {
		t.Fatalf("KnownUserAuthTypes() = %v, want the spec.md §8 set", got)
	}
	// Must be a defensive copy — mutating the return value must not
	// corrupt the package-level validation list.
	got[0] = "corrupted"
	if knownUserAuthTypes[0] == "corrupted" {
		t.Fatal("KnownUserAuthTypes() leaked the internal slice — caller mutation corrupted validation state")
	}
}
