package agentcontroller

import (
	"testing"
	"time"
)

func TestBreaker_DefaultClosed(t *testing.T) {
	s := newTestStore(t)
	b, err := s.BreakerState(BreakerScopeGlobal)
	if err != nil {
		t.Fatalf("BreakerState: %v", err)
	}
	if b.State != BreakerClosed {
		t.Errorf("State = %q, want CLOSED for a breaker that never tripped", b.State)
	}
}

func TestBreaker_TripAndReset(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	scope := BreakerScopeComponent("prometheus")

	if err := s.TripBreaker(scope, "repeated verification failure", now); err != nil {
		t.Fatalf("TripBreaker: %v", err)
	}
	b, err := s.BreakerState(scope)
	if err != nil {
		t.Fatalf("BreakerState: %v", err)
	}
	if b.State != BreakerOpen || b.TrippedAt == nil {
		t.Fatalf("got %+v, want OPEN with TrippedAt set", b)
	}

	// Reset without actor must fail — an operator reset must be audited.
	if err := s.ResetBreaker(scope, "", "manual clear", now); err == nil {
		t.Fatal("expected an error: actor is required")
	}

	if err := s.ResetBreaker(scope, "bob", "root cause fixed", now.Add(time.Minute)); err != nil {
		t.Fatalf("ResetBreaker: %v", err)
	}
	b, _ = s.BreakerState(scope)
	if b.State != BreakerClosed || b.ResetActor != "bob" {
		t.Errorf("got %+v, want CLOSED reset by bob", b)
	}
}

func TestResetBreaker_NotOpenIsError(t *testing.T) {
	s := newTestStore(t)
	if err := s.ResetBreaker(BreakerScopeHost("web-1"), "alice", "no-op", time.Now()); err == nil {
		t.Fatal("expected an error: cannot reset a breaker that never tripped")
	}
}

func TestListBreakers_OnlyReturnsTrippedScopes(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	if err := s.TripBreaker(BreakerScopeGlobal, "kill switch drill", now); err != nil {
		t.Fatalf("TripBreaker: %v", err)
	}
	got, err := s.ListBreakers()
	if err != nil {
		t.Fatalf("ListBreakers: %v", err)
	}
	if len(got) != 1 || got[0].Scope != BreakerScopeGlobal {
		t.Fatalf("got %+v, want exactly one global breaker", got)
	}
}
