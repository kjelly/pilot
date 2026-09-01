package agentcontroller

import (
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/policy"
)

func TestAutonomyMode_DefaultsToDisabled(t *testing.T) {
	s := newTestStore(t)
	st, err := s.AutonomyMode()
	if err != nil {
		t.Fatalf("AutonomyMode: %v", err)
	}
	if st.Mode != policy.ModeDisabled {
		t.Errorf("Mode = %q, want disabled — a fresh deployment must never auto-execute", st.Mode)
	}
}

func TestSetAutonomyMode_RequiresActor(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SetAutonomyMode(policy.ModeShadow, "", "testing", time.Now()); err == nil {
		t.Fatal("expected an error: actor is required")
	}
}

func TestSetAutonomyMode_RejectsInvalidMode(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SetAutonomyMode("bogus", "alice", "testing", time.Now()); err == nil {
		t.Fatal("expected an error: invalid mode")
	}
}

func TestSetAutonomyMode_PersistsAndSurvivesReopen(t *testing.T) {
	dbPath := t.TempDir() + "/state.db"
	s1, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	now := time.Now()
	if _, err := s1.SetAutonomyMode(policy.ModeEnforced, "alice", "sandbox go-ahead", now); err != nil {
		t.Fatalf("SetAutonomyMode: %v", err)
	}
	s1.Close()

	s2, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	st, err := s2.AutonomyMode()
	if err != nil {
		t.Fatalf("AutonomyMode after reopen: %v", err)
	}
	if st.Mode != policy.ModeEnforced || st.Actor != "alice" {
		t.Errorf("got %+v, want mode=enforced actor=alice", st)
	}
}
