package agentcontroller

import (
	"context"
	"sync"
	"time"
)

// Scheduler implements spec §13's dispatch semantics: bounded global and
// per-host concurrency, one active run per incident (enforced at the
// store layer), retry-with-backoff for transport/runtime failures only,
// and no automatic retry of a valid (even insufficient_evidence)
// diagnosis.
type Scheduler struct {
	Store      *Store
	Dispatcher AgentDispatcher

	MaxConcurrentRuns   int
	MaxRunsPerHost      int
	MaxDispatchAttempts int
	BaseBackoff         time.Duration
	MaxBackoff          time.Duration
	DispatchTimeout     time.Duration

	// Now is overridable for tests; nil = time.Now.
	Now func() time.Time
}

func (q *Scheduler) now() time.Time {
	if q.Now != nil {
		return q.Now()
	}
	return time.Now()
}

// RunOnce performs one scheduling pass: dispatch as many eligible
// incidents as the current concurrency budget allows, and returns how
// many it actually dispatched. Errors from individual dispatches are not
// fatal to the pass — RunOnce keeps going so one bad incident does not
// starve the rest of the queue.
//
// Each eligible incident is dispatched in its own goroutine: the slow
// part (waiting on the Agent Runtime's response) genuinely overlaps —
// "max Agent concurrency" (spec §13) would be a pointless knob otherwise
// — while every store write still serializes safely through the single
// SQLite connection (store.go's SetMaxOpenConns(1)). The one known race
// this leaves open: two different incidents on the SAME host can both
// pass the "max 1 active run per host" check before either has enqueued
// its run, briefly exceeding MaxRunsPerHost — acceptable for the MVP bar
// spec §13 sets, and self-correcting on the next tick regardless.
func (q *Scheduler) RunOnce(ctx context.Context) (dispatched int, err error) {
	active, err := q.Store.CountActiveRuns()
	if err != nil {
		return 0, err
	}
	budget := q.MaxConcurrentRuns - active
	if budget <= 0 {
		return 0, nil
	}

	incidents, err := q.Store.ListIncidentsNeedingDispatch(q.now(), budget)
	if err != nil {
		return 0, err
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		hostBusy = map[string]bool{}
	)
	for _, inc := range incidents {
		inc := inc
		if inc.Host != "" {
			n, hostErr := q.Store.CountActiveRunsForHost(inc.Host)
			mu.Lock()
			alreadyClaimed := hostBusy[inc.Host]
			if hostErr == nil && (n >= q.MaxRunsPerHost || alreadyClaimed) {
				mu.Unlock()
				continue
			}
			hostBusy[inc.Host] = true
			mu.Unlock()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if dispatchErr := q.dispatchOne(ctx, inc); dispatchErr == nil {
				mu.Lock()
				dispatched++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return dispatched, nil
}

func (q *Scheduler) dispatchOne(ctx context.Context, inc Incident) error {
	envelope := NewIncidentEnvelopeV1(inc.ID, IncidentEvent{
		Source:    inc.Source,
		Status:    "firing",
		AlertName: inc.AlertName,
		Severity:  inc.Severity,
		Host:      inc.Host,
		Site:      inc.Site,
		Component: inc.Component,
	})

	runID, err := q.Store.EnqueueRun(inc.ID, envelope, q.now())
	if err != nil {
		// The partial unique index on agent_runs means this is either a
		// genuine store error or a benign race with another pass that
		// already claimed this incident — either way, nothing to do.
		return err
	}
	if err := q.Store.StartRun(runID, inc.ID, q.now()); err != nil {
		return err
	}

	dctx, cancel := context.WithTimeout(ctx, q.DispatchTimeout)
	defer cancel()
	result, dispatchErr := q.Dispatcher.Diagnose(dctx, envelope)

	// inc.DispatchAttempts was read before EnqueueRun's own increment, so
	// the attempt just consumed is inc.DispatchAttempts+1.
	attemptJustUsed := inc.DispatchAttempts + 1

	if dispatchErr != nil {
		_, failErr := q.Store.FailRunAndMaybeRetry(runID, inc.ID, "transport_error", dispatchErr.Error(),
			attemptJustUsed, q.MaxDispatchAttempts, q.backoffFor(attemptJustUsed), q.now())
		if failErr != nil {
			return failErr
		}
		return dispatchErr
	}

	if validateErr := result.Validate(); validateErr != nil {
		_, failErr := q.Store.FailRunAndMaybeRetry(runID, inc.ID, "invalid_output", validateErr.Error(),
			attemptJustUsed, q.MaxDispatchAttempts, q.backoffFor(attemptJustUsed), q.now())
		if failErr != nil {
			return failErr
		}
		return validateErr
	}

	// A valid diagnosis — including insufficient_evidence — is never
	// retried automatically (spec §13).
	return q.Store.CompleteRunDiagnosed(runID, inc.ID, result, q.now())
}

// backoffFor returns BaseBackoff * 2^(attempts-1), capped at MaxBackoff.
func (q *Scheduler) backoffFor(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := q.BaseBackoff
	for i := 1; i < attempts; i++ {
		d *= 2
		if d > q.MaxBackoff {
			return q.MaxBackoff
		}
	}
	if d <= 0 || d > q.MaxBackoff {
		return q.MaxBackoff
	}
	return d
}
