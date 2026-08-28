package detection

import (
	"testing"
	"time"
)

func TestScheduler_UsesFlooredEvaluationTime(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// now = base + 47s; raw = now - 20s(evaluation_delay) = base + 27s;
	// floor(27/15)*15 = 1*15 = 15s past base.
	now := base.Add(47 * time.Second)
	want := base.Unix() + 15
	if got := EvaluationTime(now); got != want {
		t.Errorf("EvaluationTime(base+47s) = %d, want %d (base+15s)", got, want)
	}
}

func TestScheduler_OverrunSkipsInsteadOfBacklogging(t *testing.T) {
	s := NewScheduler(CycleInterval)

	if !s.Tick() {
		t.Fatal("first tick must be allowed to start")
	}
	if s.Tick() {
		t.Fatal("a tick while the previous cycle is still running must be skipped, not started")
	}
	if got := s.Overruns.Load(); got != 1 {
		t.Errorf("Overruns = %d, want 1", got)
	}

	s.Done()
	if !s.Tick() {
		t.Fatal("after Done, the next tick must be allowed to start")
	}
	if got := s.Overruns.Load(); got != 1 {
		t.Errorf("Overruns must not have incremented again on a normal tick, got %d", got)
	}
}
