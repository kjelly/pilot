package agentcontroller

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func firingEvent(source, episode, fingerprint, host, severity string, at time.Time) IncidentEvent {
	ev := IncidentEvent{
		Source:      source,
		GroupKey:    "group-1",
		Fingerprint: fingerprint,
		Episode:     episode,
		Status:      "firing",
		AlertName:   "TestAlert",
		Severity:    severity,
		Host:        host,
		StartsAt:    at,
		ReceivedAt:  at,
	}
	ev.AlertBodySHA256 = identityHash(ev)
	return ev
}

func TestOpenStore_MigratesAndReopens(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	s1, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("first OpenStore: %v", err)
	}
	s1.Close()

	s2, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("reopen OpenStore: %v", err)
	}
	defer s2.Close()
	if result, err := s2.IntegrityCheck(); err != nil || result != "ok" {
		t.Fatalf("IntegrityCheck = %q, %v", result, err)
	}
}

func TestIngestEvent_CreatesNewIncident(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)

	out, err := s.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("IngestEvent: %v", err)
	}
	if !out.Created || !out.Changed || !out.NeedsDispatch {
		t.Fatalf("unexpected outcome: %+v", out)
	}

	inc, err := s.GetIncident(out.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.Status != StatusOpen {
		t.Errorf("status = %q, want OPEN", inc.Status)
	}
	if inc.Host != "web-1" {
		t.Errorf("host = %q, want web-1", inc.Host)
	}
}

func TestIngestEvent_ReplayIsNoOp(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)

	first, err := s.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	// Replay the SAME alert body three times (spec §7/C5).
	for i := 0; i < 3; i++ {
		out, err := s.IngestEvent(ev, now.Add(time.Duration(i+1)*time.Second))
		if err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
		if out.IncidentID != first.IncidentID {
			t.Fatalf("replay %d created a different incident: %s vs %s", i, out.IncidentID, first.IncidentID)
		}
		if out.Changed {
			t.Fatalf("replay %d unexpectedly reported Changed=true", i)
		}
	}

	inc, err := s.GetIncident(first.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.CurrentRevision != 1 {
		t.Errorf("current_revision = %d, want 1 (replay must not bump revision)", inc.CurrentRevision)
	}
}

func TestIngestEvent_EscalationBumpsRevision(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	warn := firingEvent("detection-engine", "sig-1", "am-fp-warn", "web-1", "warning", now)
	warn.Annotations = map[string]string{"signal_id": "sig-1"}
	warn.AlertBodySHA256 = identityHash(warn)

	out1, err := s.IngestEvent(warn, now)
	if err != nil {
		t.Fatalf("ingest warning: %v", err)
	}

	crit := firingEvent("detection-engine", "sig-1", "am-fp-crit", "web-1", "critical", now)
	crit.Annotations = map[string]string{"signal_id": "sig-1"}
	crit.AlertBodySHA256 = identityHash(crit)

	out2, err := s.IngestEvent(crit, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ingest critical: %v", err)
	}
	if out2.IncidentID != out1.IncidentID {
		t.Fatalf("severity escalation created a NEW incident (%s) instead of reusing %s — Detection Engine identity must be annotations.signal_id, not Alertmanager's own fingerprint", out2.IncidentID, out1.IncidentID)
	}
	if !out2.Changed {
		t.Fatal("escalation must be reported as Changed")
	}

	inc, err := s.GetIncident(out1.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.CurrentRevision != 2 {
		t.Errorf("current_revision = %d, want 2", inc.CurrentRevision)
	}
	if inc.Severity != "critical" {
		t.Errorf("severity = %q, want critical", inc.Severity)
	}
}

func TestIngestEvent_ResolveClosesIncident(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	fire := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := s.IngestEvent(fire, now)
	if err != nil {
		t.Fatalf("ingest firing: %v", err)
	}

	resolve := fire
	resolve.Status = "resolved"
	resolve.AlertBodySHA256 = identityHash(resolve)
	out2, err := s.IngestEvent(resolve, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ingest resolve: %v", err)
	}
	if out2.IncidentID != out.IncidentID {
		t.Fatalf("resolve created a different incident")
	}

	inc, err := s.GetIncident(out.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.Status != StatusResolvedExternal {
		t.Errorf("status = %q, want RESOLVED_EXTERNAL", inc.Status)
	}
	if inc.ResolvedAt == nil {
		t.Error("resolved_at must be set")
	}

	// A NEW firing for the same identity after resolution must open a
	// fresh incident (the unique active-identity index only excludes
	// resolved/closed rows), not resurrect the resolved one.
	refire := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now.Add(2*time.Minute))
	out3, err := s.IngestEvent(refire, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("ingest refire: %v", err)
	}
	if out3.IncidentID == out.IncidentID {
		t.Error("refire after resolve must open a NEW incident, not reuse the resolved one")
	}
	if !out3.Created {
		t.Error("refire after resolve must be Created=true")
	}
}

func TestIngestEvent_OrphanResolveIsRecorded(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	resolve := firingEvent("prometheus-rule", "fp-never-seen", "fp-never-seen", "web-1", "critical", now)
	resolve.Status = "resolved"
	resolve.AlertBodySHA256 = identityHash(resolve)

	out, err := s.IngestEvent(resolve, now)
	if err != nil {
		t.Fatalf("ingest orphan resolve: %v", err)
	}
	if !out.Created {
		t.Fatal("orphan resolve must still create a (terminal) incident row for evidence")
	}
	inc, err := s.GetIncident(out.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.Status != StatusResolvedExternal {
		t.Errorf("status = %q, want RESOLVED_EXTERNAL", inc.Status)
	}
}

func TestEnqueueRun_OnlyOneActiveRunPerIncident(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := s.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	envelope := NewIncidentEnvelopeV1(out.IncidentID, ev)

	if _, err := s.EnqueueRun(out.IncidentID, envelope, now); err != nil {
		t.Fatalf("first EnqueueRun: %v", err)
	}
	if _, err := s.EnqueueRun(out.IncidentID, envelope, now); err == nil {
		t.Fatal("second EnqueueRun for the same incident must fail (unique active-run index)")
	}
}

func TestCompleteRunDiagnosed_PersistsEvidence(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := s.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	envelope := NewIncidentEnvelopeV1(out.IncidentID, ev)
	runID, err := s.EnqueueRun(out.IncidentID, envelope, now)
	if err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}
	if err := s.StartRun(runID, out.IncidentID, now); err != nil {
		t.Fatalf("StartRun: %v", err)
	}

	result := DiagnosisResult{
		Verdict:    VerdictExplained,
		Confidence: 0.9,
		Summary:    "disk full",
		Evidence:   []DiagnosisEvidence{{Tool: "pilot_diagnose_host_health", Summary: "disk 100% full"}},
	}
	if err := s.CompleteRunDiagnosed(runID, out.IncidentID, result, now); err != nil {
		t.Fatalf("CompleteRunDiagnosed: %v", err)
	}

	inc, err := s.GetIncident(out.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.Status != StatusDiagnosed {
		t.Errorf("status = %q, want DIAGNOSED", inc.Status)
	}

	// A new run can be enqueued now that the previous one is terminal.
	if _, err := s.EnqueueRun(out.IncidentID, envelope, now); err != nil {
		t.Errorf("EnqueueRun after DIAGNOSED should succeed: %v", err)
	}
}

func TestFailRunAndMaybeRetry_RetriesThenGivesUp(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := s.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	envelope := NewIncidentEnvelopeV1(out.IncidentID, ev)

	const maxAttempts = 2
	runID, err := s.EnqueueRun(out.IncidentID, envelope, now)
	if err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}
	retried, err := s.FailRunAndMaybeRetry(runID, out.IncidentID, "transport_error", "boom", 1, maxAttempts, time.Second, now)
	if err != nil {
		t.Fatalf("FailRunAndMaybeRetry (1st): %v", err)
	}
	if !retried {
		t.Fatal("first failure (attempt 1 of 2) must be retried")
	}
	inc, _ := s.GetIncident(out.IncidentID)
	if inc.Status != StatusOpen {
		t.Errorf("status after retryable failure = %q, want OPEN", inc.Status)
	}

	// Second attempt also fails, and attempts are now exhausted.
	runID2, err := s.EnqueueRun(out.IncidentID, envelope, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("EnqueueRun (2nd attempt): %v", err)
	}
	retried2, err := s.FailRunAndMaybeRetry(runID2, out.IncidentID, "transport_error", "boom again", 2, maxAttempts, time.Second, now)
	if err != nil {
		t.Fatalf("FailRunAndMaybeRetry (2nd): %v", err)
	}
	if retried2 {
		t.Fatal("second failure (attempt 2 of 2) must NOT be retried")
	}
	inc2, _ := s.GetIncident(out.IncidentID)
	if inc2.Status != StatusAgentFailed {
		t.Errorf("status after exhausted retries = %q, want AGENT_FAILED", inc2.Status)
	}
}

func TestRecoverInFlightRuns_ReopensForFreshDispatch(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	ev := firingEvent("prometheus-rule", "fp-1", "fp-1", "web-1", "critical", now)
	out, err := s.IngestEvent(ev, now)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	envelope := NewIncidentEnvelopeV1(out.IncidentID, ev)
	runID, err := s.EnqueueRun(out.IncidentID, envelope, now)
	if err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}
	if err := s.StartRun(runID, out.IncidentID, now); err != nil {
		t.Fatalf("StartRun: %v", err)
	}

	// Simulate an unclean shutdown: the run is left INVESTIGATING.
	recovered, err := s.RecoverInFlightRuns(now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecoverInFlightRuns: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered = %d, want 1", recovered)
	}

	inc, err := s.GetIncident(out.IncidentID)
	if err != nil || inc == nil {
		t.Fatalf("GetIncident: %v, %+v", err, inc)
	}
	if inc.Status != StatusOpen {
		t.Errorf("status after recovery = %q, want OPEN (reopened for fresh dispatch)", inc.Status)
	}

	dispatchable, err := s.ListIncidentsNeedingDispatch(now.Add(time.Minute), 10)
	if err != nil {
		t.Fatalf("ListIncidentsNeedingDispatch: %v", err)
	}
	found := false
	for _, d := range dispatchable {
		if d.ID == out.IncidentID {
			found = true
		}
	}
	if !found {
		t.Error("recovered incident must be dispatchable again (the stale run is terminal AGENT_FAILED, not blocking a new one)")
	}
}
