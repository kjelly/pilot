package loginprobe

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Scheduler drives rounds on a fixed cadence and skips a tick while the
// previous round is still running instead of queueing it (the same
// overrun contract as internal/detection's Scheduler).
type Scheduler struct {
	Interval time.Duration
	// Overruns counts ticks that were skipped because a round was running.
	Overruns atomic.Int64

	mu      sync.Mutex
	running bool
}

// NewScheduler returns a scheduler for interval.
func NewScheduler(interval time.Duration) *Scheduler { return &Scheduler{Interval: interval} }

// Tick returns false (and counts an overrun) while a round is running; on
// true the caller must call Done when the round finishes.
func (s *Scheduler) Tick() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		s.Overruns.Add(1)
		return false
	}
	s.running = true
	return true
}

// Done marks the current round finished.
func (s *Scheduler) Done() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

// Run calls round immediately and then every Interval until ctx ends. A
// round runs in its own goroutine so a slow one never blocks the ticker;
// the overrun gate keeps at most one round in flight.
func (s *Scheduler) Run(ctx context.Context, round func(ctx context.Context)) {
	var wg sync.WaitGroup
	start := func() {
		if !s.Tick() {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.Done()
			round(ctx)
		}()
	}
	start()
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-ticker.C:
			start()
		}
	}
}
