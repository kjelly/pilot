package loginprobe

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduler_OverrunSkipsInsteadOfBacklogging(t *testing.T) {
	s := NewScheduler(time.Minute)
	if !s.Tick() {
		t.Fatal("first tick must start")
	}
	if s.Tick() {
		t.Fatal("a tick while a round is running must be skipped")
	}
	if got := s.Overruns.Load(); got != 1 {
		t.Errorf("Overruns = %d, want 1", got)
	}
	s.Done()
	if !s.Tick() {
		t.Fatal("after Done the next tick must start")
	}
	if got := s.Overruns.Load(); got != 1 {
		t.Errorf("Overruns = %d after a normal tick, want 1", got)
	}
}

func TestScheduler_RunFiresImmediatelyThenOnCadenceAndWaitsForTheLastRound(t *testing.T) {
	s := NewScheduler(20 * time.Millisecond)
	var rounds atomic.Int32
	var finished atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(110 * time.Millisecond)
		cancel()
	}()
	s.Run(ctx, func(ctx context.Context) {
		rounds.Add(1)
		time.Sleep(5 * time.Millisecond)
		finished.Add(1)
	})
	if n := rounds.Load(); n < 3 {
		t.Errorf("rounds = %d, want the immediate round plus several ticks", n)
	}
	if rounds.Load() != finished.Load() {
		t.Errorf("Run returned before the last round finished: started=%d finished=%d", rounds.Load(), finished.Load())
	}
}
