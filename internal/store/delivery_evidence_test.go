package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestRunWriterAppendOnlyIdempotencyAndFinish(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w, err := StartRun(context.Background(), s, RunStarted{RunID: "run-1", OperationID: "start-1", Hosts: []string{"host-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AppendEvent(context.Background(), Event{OperationID: "step-1", Type: EventStepFinished, Payload: map[string]any{"step": "apply"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.AppendEvent(context.Background(), Event{OperationID: "step-1", Type: EventStepFinished, Payload: map[string]any{"step": "apply"}}); err != nil {
		t.Fatalf("same operation retry: %v", err)
	}
	if err := w.AppendEvent(context.Background(), Event{OperationID: "step-1", Type: EventStepFinished, Payload: map[string]any{"step": "different"}}); !errors.Is(err, ErrEvidenceConflict) {
		t.Fatalf("conflict err=%v", err)
	}

	row := VerifyEvidence{SpecPath: "spec.md", RowID: "C1", Host: "host-a", Attempt: 1, OperationID: "evidence-1", Command: "true", Expected: "present", ProbeStatus: "ok", Verdict: "pass"}
	if err := w.AppendEvidence(context.Background(), []VerifyEvidence{row}); err != nil {
		t.Fatal(err)
	}
	if err := w.AppendEvidence(context.Background(), []VerifyEvidence{row}); err != nil {
		t.Fatalf("same evidence retry: %v", err)
	}
	retryWithNewOperation := row
	retryWithNewOperation.OperationID = "evidence-1-retry"
	if err := w.AppendEvidence(context.Background(), []VerifyEvidence{retryWithNewOperation}); err != nil {
		t.Fatalf("same host-row-attempt retry: %v", err)
	}
	row.Stdout = "different"
	if err := w.AppendEvidence(context.Background(), []VerifyEvidence{row}); !errors.Is(err, ErrEvidenceConflict) {
		t.Fatalf("evidence conflict err=%v", err)
	}
	if err := w.AppendEvidence(context.Background(), []VerifyEvidence{{SpecPath: "spec.md", RowID: "C1", Host: "host-b", Attempt: 1, OperationID: "outside", Command: "true", ProbeStatus: "ok", Verdict: "pass"}}); err == nil {
		t.Fatal("expected host outside scope to fail")
	}

	if err := w.Finish(context.Background(), RunFinished{Outcome: "success", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	if err := w.AppendEvent(context.Background(), Event{OperationID: "late", Type: EventStepFinished, Payload: map[string]any{}}); !errors.Is(err, ErrRunFinished) {
		t.Fatalf("late append err=%v", err)
	}
	var events, evidence int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM delivery_events WHERE run_id='run-1'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM verify_evidence WHERE run_id='run-1'`).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if events != 3 || evidence != 1 {
		t.Fatalf("events=%d evidence=%d", events, evidence)
	}
	var outcome string
	if err := s.db.QueryRow(`SELECT outcome FROM delivery_runs WHERE run_id='run-1'`).Scan(&outcome); err != nil || outcome != "success" {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
}

func TestDeliveryEvidenceTriggersAndHeartbeat(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	w, err := StartRun(context.Background(), s, RunStarted{RunID: "run-2", Hosts: []string{"host-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AppendEvidence(context.Background(), []VerifyEvidence{{SpecPath: "x", RowID: "C1", Host: "host-a", Attempt: 1, OperationID: "evidence", Command: "true", ProbeStatus: "ok", Verdict: "pass"}}); err != nil {
		t.Fatal(err)
	}
	w.StartHeartbeat(context.Background(), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if err := w.Finish(context.Background(), RunFinished{Outcome: "cancelled", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE delivery_events SET step='x' WHERE run_id='run-2'`); err == nil {
		t.Fatal("delivery event UPDATE unexpectedly succeeded")
	}
	if _, err := s.db.Exec(`DELETE FROM delivery_events WHERE run_id='run-2'`); err == nil {
		t.Fatal("delivery event DELETE unexpectedly succeeded")
	}
	if _, err := s.db.Exec(`UPDATE verify_evidence SET stdout='x' WHERE run_id='run-2'`); err == nil {
		t.Fatal("verification evidence UPDATE unexpectedly succeeded")
	}
	if _, err := s.db.Exec(`DELETE FROM verify_evidence WHERE run_id='run-2'`); err == nil {
		t.Fatal("verification evidence DELETE unexpectedly succeeded")
	}
}
