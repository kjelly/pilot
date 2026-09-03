package inventory

import (
	"strings"
	"testing"
)

func TestSimulateRemoveRosterNFSServer_FoundAndNoViolations(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureWithNFS)
	violations, found, err := SimulateRemoveRosterNFSServer(path, "nfs1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("SimulateRemoveRosterNFSServer() error = %v", err)
	}
	if !found {
		t.Fatalf("found = false, want true")
	}
	if len(violations) != 0 {
		t.Fatalf("violations = %+v, want none", violations)
	}
	// Simulate must not have written anything.
	data := readFileHelper(t, path)
	if strings.Contains(data, "state: absent") {
		t.Fatalf("Simulate must not mutate the file:\n%s", data)
	}
}

func TestSimulateRemoveRosterNFSServer_NotFound(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	_, found, err := SimulateRemoveRosterNFSServer(path, "nfs1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("SimulateRemoveRosterNFSServer() error = %v", err)
	}
	if found {
		t.Fatalf("found = true, want false (no nfs section at all)")
	}
}

func TestRosterNFSServerAbsent_TrueWhenNoSuchEntryOrAlreadyAbsent(t *testing.T) {
	// No nfs section at all -> converged (nothing to prune).
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	absent, err := RosterNFSServerAbsent(path, "nfs1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("RosterNFSServerAbsent() error = %v", err)
	}
	if !absent {
		t.Fatalf("absent = false, want true")
	}

	// Present entry -> not converged.
	path2 := writeRosterFixture(t, rosterFixtureWithNFS)
	absent2, err := RosterNFSServerAbsent(path2, "nfs1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("RosterNFSServerAbsent() error = %v", err)
	}
	if absent2 {
		t.Fatalf("absent = true, want false (entry is state: present)")
	}
}

func TestSetRosterNFSServerAbsent_ConvergesAndPreservesOtherContent(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureWithNFS)

	if err := SetRosterNFSServerAbsent(path, "nfs1.ipa.pilot.internal"); err != nil {
		t.Fatalf("SetRosterNFSServerAbsent() error = %v", err)
	}

	absent, err := RosterNFSServerAbsent(path, "nfs1.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("RosterNFSServerAbsent() error = %v", err)
	}
	if !absent {
		t.Fatalf("expected the entry to converge to state: absent")
	}

	data := readFileHelper(t, path)
	if !strings.Contains(data, "principal: nfs/nfs1.ipa.pilot.internal") {
		t.Fatalf("expected the service_principal to survive convergence (tombstone, not delete):\n%s", data)
	}
	if !strings.Contains(data, "domain: ipa.pilot.internal") {
		t.Fatalf("expected unrelated content (freeipa.domain) to survive untouched:\n%s", data)
	}

	// Idempotent re-run (INV-9/HD18): calling it again on an already-absent
	// entry must not error.
	if err := SetRosterNFSServerAbsent(path, "nfs1.ipa.pilot.internal"); err != nil {
		t.Fatalf("second SetRosterNFSServerAbsent() error = %v, want idempotent no-op", err)
	}
}

func TestSetRosterNFSServerAbsent_NoSuchEntryErrors(t *testing.T) {
	path := writeRosterFixture(t, rosterFixtureNoNFS)
	if err := SetRosterNFSServerAbsent(path, "nfs1.ipa.pilot.internal"); err == nil {
		t.Fatalf("expected an error for a non-existent nfs.servers entry")
	}
}
