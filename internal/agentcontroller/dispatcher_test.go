package agentcontroller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFakeDispatcher_DefaultResponse(t *testing.T) {
	f := &FakeDispatcher{}
	result, err := f.Diagnose(context.Background(), IncidentEnvelopeV2{IncidentID: "inc-1"})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if result.Verdict != VerdictInsufficientEvidence {
		t.Errorf("verdict = %q, want %q", result.Verdict, VerdictInsufficientEvidence)
	}
	if len(f.Calls()) != 1 || f.Calls()[0].IncidentID != "inc-1" {
		t.Errorf("Calls() = %+v, want one call for inc-1", f.Calls())
	}
}

func TestFakeDispatcher_CustomHandler(t *testing.T) {
	f := &FakeDispatcher{Handler: func(in IncidentEnvelopeV2) (DiagnosisResult, error) {
		return DiagnosisResult{
			Verdict:    VerdictExplained,
			Confidence: 0.8,
			Evidence:   []DiagnosisEvidence{{Tool: "pilot_diagnose_host_health", Summary: "ok"}},
		}, nil
	}}
	result, err := f.Diagnose(context.Background(), IncidentEnvelopeV2{})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if result.Verdict != VerdictExplained {
		t.Errorf("verdict = %q, want explained", result.Verdict)
	}
}

func TestHTTPDispatcher_SuccessRoundTrip(t *testing.T) {
	var gotBody IncidentEnvelopeV2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DiagnosisResult{
			Verdict:    VerdictProbable,
			Confidence: 0.5,
			Evidence:   []DiagnosisEvidence{{Tool: "pilot_diagnose_metrics", Summary: "cpu high"}},
		})
	}))
	defer srv.Close()

	d := NewHTTPDispatcher(srv.URL, time.Second)
	result, err := d.Diagnose(context.Background(), IncidentEnvelopeV2{IncidentID: "inc-42"})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if result.Verdict != VerdictProbable {
		t.Errorf("verdict = %q, want probable", result.Verdict)
	}
	if gotBody.IncidentID != "inc-42" {
		t.Errorf("server saw incident_id = %q, want inc-42", gotBody.IncidentID)
	}
}

func TestHTTPDispatcher_NonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := NewHTTPDispatcher(srv.URL, time.Second)
	if _, err := d.Diagnose(context.Background(), IncidentEnvelopeV2{}); err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
}

func TestHTTPDispatcher_TimeoutIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewHTTPDispatcher(srv.URL, 5*time.Millisecond)
	if _, err := d.Diagnose(context.Background(), IncidentEnvelopeV2{}); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestHTTPDispatcher_MalformedResponseIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	d := NewHTTPDispatcher(srv.URL, time.Second)
	if _, err := d.Diagnose(context.Background(), IncidentEnvelopeV2{}); err == nil {
		t.Fatal("expected an error for a malformed JSON response")
	}
}
