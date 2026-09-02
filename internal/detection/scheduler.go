package detection

import (
	"context"
	"sync/atomic"
	"time"
)

// Scheduler constants (spec §11).
const (
	CycleInterval       = 15 * time.Second
	EvaluationDelay     = 20 * time.Second
	QueryTimeout        = 5 * time.Second
	QueryConcurrency    = 8
	// MaxSampleAge/FutureSkewTolerance are the spec §9.3 backward-compatible
	// defaults for a feature profile that never sets `sampling:` — see
	// FeatureProfile.MaxSampleAge()/FutureSkewTolerance(), which every
	// caller actually uses since Phase 4 (these two constants are kept
	// only as the historical spec §11 reference values).
	MaxSampleAge        = 45 * time.Second
	FutureSkewTolerance = 5 * time.Second
)

// EvaluationTime implements spec §11.1: the evaluation timestamp for a
// cycle starting at wall-clock now is (now - evaluation_delay), floored to
// the nearest cycle_interval boundary. Every instant feature query in that
// cycle uses this exact timestamp.
func EvaluationTime(now time.Time) int64 {
	raw := now.Add(-EvaluationDelay).Unix()
	interval := int64(CycleInterval.Seconds())
	// Integer division truncates toward zero; raw is always a large
	// positive unix timestamp in practice, so truncation is floor here.
	return (raw / interval) * interval
}

// cycleGate is a concurrency-safe "is a cycle currently running" latch
// used to implement spec §11.2's overrun rule.
type cycleGate struct {
	running atomic.Bool
}

func (g *cycleGate) tryStart() bool { return g.running.CompareAndSwap(false, true) }
func (g *cycleGate) finish()        { g.running.Store(false) }

// Scheduler enforces spec §11.2's cadence rule: if the previous cycle has
// not finished by the next fixed-cadence deadline, the new cycle is
// skipped (never queued/backlogged) and pilot_detection_cycle_overrun_total
// increments; the next deadline still lands on the same fixed cadence.
type Scheduler struct {
	Interval time.Duration
	gate     cycleGate
	Overruns atomic.Int64
}

// NewScheduler returns a scheduler for the given fixed cadence (spec §11:
// 15s in production).
func NewScheduler(interval time.Duration) *Scheduler {
	return &Scheduler{Interval: interval}
}

// Tick reports whether a new cycle may start now. A false result means the
// previous cycle is still running — this tick is skipped and Overruns is
// incremented. On true, the caller MUST call Done once the cycle finishes.
func (s *Scheduler) Tick() bool {
	if !s.gate.tryStart() {
		s.Overruns.Add(1)
		return false
	}
	return true
}

// Done marks the current cycle finished, allowing the next tick to start.
func (s *Scheduler) Done() { s.gate.finish() }

// Run drives cycleFn on the fixed cadence using a real (monotonic) ticker,
// applying the Tick/Done overrun gate around each invocation. cycleFn runs
// in its own goroutine so a slow cycle cannot block the ticker itself.
func (s *Scheduler) Run(ctx context.Context, cycleFn func(ctx context.Context, evaluationTime int64)) {
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if !s.Tick() {
				continue
			}
			go func() {
				defer s.Done()
				cycleFn(ctx, EvaluationTime(now))
			}()
		}
	}
}
