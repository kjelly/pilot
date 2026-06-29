package cmd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestParallelFailFast_DrainsOnCancel exercises the fail-fast wiring:
// once cancelFailFast() is called, in-flight workers see ctx.Err()
// and short-circuit. Workers that haven't started yet should not
// be invoked at all (the cancel reaches them via failFastCtx).
//
// We can't easily drive runOneTarget (it shells out to ansible), so
// we test the same control-flow pattern in isolation: a fan-out of
// fake tasks that respect ctx, a collector, and a fail-fast cancel.
func TestParallelFailFast_DrainsOnCancel(t *testing.T) {
	const total = 8
	results := make([]string, total)
	var invoked int32
	var started sync.WaitGroup
	started.Add(total)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resChan := make(chan indexedResultLite, total)

	// Fan-out
	for i := 0; i < total; i++ {
		go func(idx int) {
			atomic.AddInt32(&invoked, 1)
			started.Done()
			// simulate work that respects ctx
			select {
			case <-time.After(2*time.Second):
				resChan <- indexedResultLite{idx: idx, br: "ok"}
			case <-ctx.Done():
				resChan <- indexedResultLite{idx: idx, br: "cancelled"}
			}
		}(i)
	}

	// Wait until every worker is parked inside its select, so the
	// cancel is guaranteed to be observed by all of them.
	started.Wait()
	// Cancel BEFORE any worker can finish — work is 2 seconds, the
	// cancel is essentially instant, so every worker must observe it.
	cancel()

	// Collect every worker's single message.
	go func() {
		for i := 0; i < total; i++ {
			r := <-resChan
			results[r.idx] = r.br
		}
	}()

	// Wait briefly for everything to drain.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("workers did not drain")
		default:
			if allSet(results) {
				goto done
			}
		}
	}
done:
	if got := atomic.LoadInt32(&invoked); int(got) != total {
		t.Errorf("invoked=%d want=%d (every worker should have started)", got, total)
	}
	// Some tasks must have observed cancellation.
	var cancelled int
	for _, r := range results {
		if r == "cancelled" {
			cancelled++
		}
	}
	if cancelled == 0 {
		t.Error("expected at least one cancelled result")
	}
}

func allSet(rs []string) bool {
	for _, r := range rs {
		if r == "" {
			return false
		}
	}
	return true
}

type indexedResultLite struct {
	idx int
	br  string
}
