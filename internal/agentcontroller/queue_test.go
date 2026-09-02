package agentcontroller

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func newTestScheduler(store *Store, dispatcher AgentDispatcher) *Scheduler {
	return &Scheduler{
		Store:               store,
		Dispatcher:          dispatcher,
		MaxConcurrentRuns:   10,
		MaxRunsPerHost:      1,
		MaxDispatchAttempts: 2,
		BaseBackoff:         time.Millisecond,
		MaxBackoff:          10 * time.Millisecond,
		DispatchTimeout:     time.Second,
	}
}

func TestScheduler_DispatchesOpenIncidentToDiagnosed(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := store.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	fake := &FakeDispatcher{Handler: func(in IncidentEnvelopeV2) (DiagnosisResult, error) {
		return DiagnosisResult{Verdict: VerdictExplained, Confidence: 1, Evidence: []DiagnosisEvidence{{Tool: "t", Summary: "s"}}}, nil
	}}
	sched := newTestScheduler(store, fake)

	dispatched, err := sched.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("dispatched = %d, want 1", dispatched)
	}

	inc, err := store.GetIncident(out.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.Status != StatusDiagnosed {
		t.Errorf("status = %q, want DIAGNOSED", inc.Status)
	}
}

func TestScheduler_DispatchesIncidentEnvelopeV2WithSubject(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-snmp-1", "fp-snmp-1", "", "critical", now)
	ev.Site = "hq"
	ev.Component = "snmp"
	ev.Subject = IncidentSubject{ID: "core-sw-01", Kind: "network_device", Site: "hq", Managed: false}
	ev.AlertBodySHA256 = identityHash(ev)
	if _, err := store.IngestEvent(ev, now); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	fake := &FakeDispatcher{}
	sched := newTestScheduler(store, fake)
	if _, err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	calls := fake.Calls()
	if len(calls) != 1 {
		t.Fatalf("dispatcher calls = %d, want 1", len(calls))
	}
	got := calls[0]
	if got.SchemaVersion != 2 {
		t.Errorf("schema_version = %d, want 2 (FakeDispatcher must receive V2)", got.SchemaVersion)
	}
	want := IncidentSubject{ID: "core-sw-01", Kind: "network_device", Site: "hq", Managed: false}
	if got.Subject != want {
		t.Errorf("subject = %+v, want %+v", got.Subject, want)
	}
	if got.DiagnosticPolicy.ExternalSubjectMutationAllowed {
		t.Error("external_subject_mutation_allowed must be false")
	}
}

func TestScheduler_MalformedOutputBecomesAgentFailed(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := store.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// Verdict "bogus" is not one of the five allowed values -> Validate() fails.
	fake := &FakeDispatcher{Handler: func(in IncidentEnvelopeV2) (DiagnosisResult, error) {
		return DiagnosisResult{Verdict: "bogus"}, nil
	}}
	sched := newTestScheduler(store, fake)
	sched.MaxDispatchAttempts = 1 // exhaust immediately for this test

	if _, err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	inc, err := store.GetIncident(out.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.Status != StatusAgentFailed {
		t.Errorf("status = %q, want AGENT_FAILED (malformed output is never a partial diagnosis)", inc.Status)
	}
}

func TestScheduler_InsufficientEvidenceIsNotRetried(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := store.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	calls := 0
	fake := &FakeDispatcher{Handler: func(in IncidentEnvelopeV2) (DiagnosisResult, error) {
		calls++
		return DiagnosisResult{Verdict: VerdictInsufficientEvidence, Evidence: []DiagnosisEvidence{{Tool: "t", Summary: "s"}}}, nil
	}}
	sched := newTestScheduler(store, fake)

	if _, err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (1st): %v", err)
	}
	if _, err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (2nd): %v", err)
	}
	if calls != 1 {
		t.Errorf("dispatcher called %d times, want exactly 1 — a valid insufficient_evidence result must never be auto-retried", calls)
	}

	inc, err := store.GetIncident(out.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.Status != StatusDiagnosed {
		t.Errorf("status = %q, want DIAGNOSED", inc.Status)
	}
}

func TestScheduler_TransportFailureRetriesThenGivesUp(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := store.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	calls := 0
	fake := &FakeDispatcher{Handler: func(in IncidentEnvelopeV2) (DiagnosisResult, error) {
		calls++
		return DiagnosisResult{}, fmt.Errorf("simulated transport error")
	}}
	sched := newTestScheduler(store, fake)
	sched.MaxDispatchAttempts = 2
	sched.BaseBackoff = 0 // no real wait needed in this test

	// First pass: attempt 1 fails, incident goes back to OPEN with
	// next_dispatch_at cleared (backoff=0) so it's immediately eligible.
	if _, err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (1st): %v", err)
	}
	inc1, _ := store.GetIncident(out.IncidentID)
	if inc1.Status != StatusOpen {
		t.Fatalf("status after 1st failure = %q, want OPEN (still has a retry budget)", inc1.Status)
	}

	// Second pass: attempt 2 fails, budget exhausted.
	if _, err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (2nd): %v", err)
	}
	inc2, _ := store.GetIncident(out.IncidentID)
	if inc2.Status != StatusAgentFailed {
		t.Fatalf("status after 2nd failure = %q, want AGENT_FAILED", inc2.Status)
	}
	if calls != 2 {
		t.Errorf("dispatcher called %d times, want 2", calls)
	}
}

func TestScheduler_RespectsGlobalConcurrencyCap(t *testing.T) {
	store := newTestStore(t)
	now := time.Now()
	for i := 0; i < 3; i++ {
		ev := firingEvent("prometheus-rule", fmt.Sprintf("fp-%d", i), fmt.Sprintf("fp-%d", i), fmt.Sprintf("host-%d", i), "critical", now)
		if _, err := store.IngestEvent(ev, now); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}

	blocked := make(chan struct{})
	fake := &FakeDispatcher{Handler: func(in IncidentEnvelopeV2) (DiagnosisResult, error) {
		<-blocked
		return DiagnosisResult{Verdict: VerdictExplained, Confidence: 1, Evidence: []DiagnosisEvidence{{Tool: "t", Summary: "s"}}}, nil
	}}
	sched := newTestScheduler(store, fake)
	sched.MaxConcurrentRuns = 1

	done := make(chan int, 1)
	go func() {
		n, _ := sched.RunOnce(context.Background())
		done <- n
	}()

	// Give the goroutine a moment to enqueue+start exactly one run, then
	// unblock it and check no MORE than the cap was ever active at once.
	time.Sleep(20 * time.Millisecond)
	active, err := store.CountActiveRuns()
	if err != nil {
		t.Fatalf("CountActiveRuns: %v", err)
	}
	if active > sched.MaxConcurrentRuns {
		t.Errorf("active runs = %d, exceeds cap %d", active, sched.MaxConcurrentRuns)
	}
	close(blocked)
	<-done
}
