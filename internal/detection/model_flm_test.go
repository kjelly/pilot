package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseFLMFields_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{"canonical", "ANOMALY|HIGH|memory_pressure|HIGH", []string{"ANOMALY", "HIGH", "memory_pressure", "HIGH"}, false},
		{"result prefix", "Result: ANOMALY|HIGH|memory_pressure|HIGH", []string{"ANOMALY", "HIGH", "memory_pressure", "HIGH"}, false},
		{"code fence", "```ANOMALY|HIGH|memory_pressure|HIGH```", []string{"ANOMALY", "HIGH", "memory_pressure", "HIGH"}, false},
		{"multiline code fence", "```\nANOMALY|HIGH|memory_pressure|HIGH\n```", []string{"ANOMALY", "HIGH", "memory_pressure", "HIGH"}, false},
		{"compatibility form", "VERDICT: ANOMALY\nSEVERITY: HIGH\nCATEGORY: memory_pressure\nCONFIDENCE: HIGH", []string{"ANOMALY", "HIGH", "memory_pressure", "HIGH"}, false},
		{"prose, no pipe or fields", "maybe anomaly", nil, true},
		{"empty", "", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseFLMFields(c.raw)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got fields=%v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("fields = %v, want %v", got, c.want)
			}
			for i := range c.want {
				if strings.TrimSpace(got[i]) != c.want[i] {
					t.Errorf("field[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestParseAndValidateFLM_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"valid", "ANOMALY|HIGH|memory_pressure|HIGH", false},
		{"valid benign", "BENIGN|INFO|scheduled_workload|MEDIUM", false},
		{"invalid severity", "ANOMALY|VERY_BAD|memory|LOW", true},
		{"invalid confidence enum (numeric)", "ANOMALY|HIGH|memory|99", true},
		{"invalid category (uppercase)", "ANOMALY|HIGH|Memory_Pressure|HIGH", true},
		{"invalid verdict", "MAYBE|HIGH|memory_pressure|HIGH", true},
		{"oversized", strings.Repeat("A", flmMaxResponseBytes+1), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseAndValidateFLM(c.raw)
			if c.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// FuzzParseAndValidateFLM (spec1.md §54): never panic, never return an
// invalid enum.
func FuzzParseAndValidateFLM(f *testing.F) {
	f.Add("ANOMALY|HIGH|memory_pressure|HIGH")
	f.Add("VERDICT: ANOMALY\nSEVERITY: HIGH\nCATEGORY: x\nCONFIDENCE: HIGH")
	f.Add("")
	f.Add("|||")
	f.Add(strings.Repeat("x", 10000))
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := parseAndValidateFLM(raw)
		if err != nil {
			return
		}
		if !flmVerdicts[v.Verdict] || !flmSeverities[v.Severity] || !flmConfidences[v.Confidence] || !flmCategoryPattern.MatchString(v.Category) {
			t.Fatalf("parseAndValidateFLM accepted invalid enum: %+v (raw=%q)", v, raw)
		}
	})
}

func flmChatHandler(t *testing.T, respond func(userContent string) string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		var req flmChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		// The FIRST user message always carries the original candidate
		// evidence, even on a corrective retry (where a second user
		// message — the "your previous response was invalid" reprompt —
		// gets appended after it), so callers that need to identify which
		// candidate this exchange is about must look here, not at the
		// last user message.
		var userContent string
		for _, m := range req.Messages {
			if m.Role == "user" {
				userContent = m.Content
				break
			}
		}
		content := respond(userContent)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(flmChatResponse{Message: &ollamaChatMessage{Role: "assistant", Content: content}})
	}
}

func flmValidRequest() ModelBatchRequest {
	return ModelBatchRequest{
		SchemaVersion: 1, RequestID: "req-1", PromptVersion: 1, WindowSeconds: 600,
		Candidates: []ModelCandidateRequest{
			{CandidateID: "host-a", PilotHost: "host-a", Site: "site-1", EvaluationTime: 1000, Current: map[string]float64{"cpu": 0.9}},
		},
	}
}

func TestFLMProvider_HappyPath(t *testing.T) {
	srv := httptest.NewServer(flmChatHandler(t, func(string) string {
		return "ANOMALY|HIGH|cpu_saturation|HIGH"
	}))
	defer srv.Close()
	provider := &FLMProvider{BaseURL: srv.URL, Model: "qwen3.5-4b-FLM", HTTPClient: srv.Client()}

	resp, err := provider.Score(context.Background(), flmValidRequest())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if resp.RequestID != "req-1" || resp.Status != "ok" || len(resp.Candidates) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	c := resp.Candidates[0]
	if c.CandidateID != "host-a" || c.CategoryHint != "cpu_saturation" {
		t.Errorf("unexpected candidate: %+v", c)
	}
	if c.Score != flmSeverityScore["HIGH"] || c.Confidence != flmConfidenceScore["HIGH"] {
		t.Errorf("unexpected score/confidence: %+v", c)
	}
}

// TestFLMProvider_BenignAndUncertainNeverEscalate (spec §19: model can
// only escalate, never suppress — BENIGN/UNCERTAIN must not carry a
// nonzero score/confidence that could ever clear the fusion margin).
func TestFLMProvider_BenignAndUncertainNeverEscalate(t *testing.T) {
	for _, verdict := range []string{"BENIGN", "UNCERTAIN"} {
		t.Run(verdict, func(t *testing.T) {
			srv := httptest.NewServer(flmChatHandler(t, func(string) string {
				return fmt.Sprintf("%s|CRITICAL|whatever|HIGH", verdict)
			}))
			defer srv.Close()
			provider := &FLMProvider{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()}

			resp, err := provider.Score(context.Background(), flmValidRequest())
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			c := resp.Candidates[0]
			if c.Score != 0 || c.Confidence != 0 || c.CategoryHint != "" {
				t.Errorf("%s must zero out score/confidence/category regardless of reported SEVERITY, got %+v", verdict, c)
			}
		})
	}
}

// TestFLMProvider_MultiCandidateSequentialCalls (spec1.md has no
// multi-candidate batch shape — verify each candidate gets its own HTTP
// call and its own correct verdict).
func TestFLMProvider_MultiCandidateSequentialCalls(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(flmChatHandler(t, func(userContent string) string {
		calls++
		if strings.Contains(userContent, "candidate_id=host-a") {
			return "ANOMALY|HIGH|cpu|HIGH"
		}
		return "BENIGN|INFO|x|LOW"
	}))
	defer srv.Close()
	provider := &FLMProvider{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()}

	req := ModelBatchRequest{RequestID: "r", Candidates: []ModelCandidateRequest{
		{CandidateID: "host-a", PilotHost: "host-a", Site: "s", Current: map[string]float64{}},
		{CandidateID: "host-b", PilotHost: "host-b", Site: "s", Current: map[string]float64{}},
	}}
	resp, err := provider.Score(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 sequential HTTP calls, got %d", calls)
	}
	if len(resp.Candidates) != 2 {
		t.Fatalf("expected 2 candidates in response, got %d", len(resp.Candidates))
	}
	byID := map[string]ModelCandidateResponse{}
	for _, c := range resp.Candidates {
		byID[c.CandidateID] = c
	}
	if byID["host-a"].Score == 0 {
		t.Error("host-a should have escalated (ANOMALY/HIGH/HIGH)")
	}
	if byID["host-b"].Score != 0 {
		t.Error("host-b (BENIGN) must not escalate")
	}
}

// TestFLMProvider_RetriesOnceOnMalformedThenSucceeds (spec1.md §33: 1
// initial + 1 corrective retry, entirely within the adapter — never
// touching ManagedProvider's transport-level retry).
func TestFLMProvider_RetriesOnceOnMalformedThenSucceeds(t *testing.T) {
	attempt := 0
	srv := httptest.NewServer(flmChatHandler(t, func(string) string {
		attempt++
		if attempt == 1 {
			return "this is not a valid pipe response"
		}
		return "ANOMALY|WARNING|disk_io|MEDIUM"
	}))
	defer srv.Close()
	provider := &FLMProvider{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()}

	resp, err := provider.Score(context.Background(), flmValidRequest())
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if attempt != 2 {
		t.Errorf("expected exactly 2 attempts (1 initial + 1 corrective retry), got %d", attempt)
	}
	if resp.Candidates[0].CategoryHint != "disk_io" {
		t.Errorf("expected the retry's valid response to be used, got %+v", resp.Candidates[0])
	}
}

// TestFLMProvider_DegradesSingleCandidateWithoutFailingBatch: one
// candidate's response never parses even after retry — it degrades to a
// zero score, but the OTHER candidate's real result is preserved.
func TestFLMProvider_DegradesSingleCandidateWithoutFailingBatch(t *testing.T) {
	srv := httptest.NewServer(flmChatHandler(t, func(userContent string) string {
		if strings.Contains(userContent, "candidate_id=host-bad") {
			return "garbage, always garbage"
		}
		return "ANOMALY|CRITICAL|memory|HIGH"
	}))
	defer srv.Close()
	provider := &FLMProvider{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()}

	req := ModelBatchRequest{RequestID: "r", Candidates: []ModelCandidateRequest{
		{CandidateID: "host-good", PilotHost: "host-good", Site: "s", Current: map[string]float64{}},
		{CandidateID: "host-bad", PilotHost: "host-bad", Site: "s", Current: map[string]float64{}},
	}}
	resp, err := provider.Score(context.Background(), req)
	if err != nil {
		t.Fatalf("expected the batch to still succeed (one good candidate), got %v", err)
	}
	byID := map[string]ModelCandidateResponse{}
	for _, c := range resp.Candidates {
		byID[c.CandidateID] = c
	}
	if byID["host-good"].Score == 0 {
		t.Error("host-good's real result must not be discarded because host-bad failed to parse")
	}
	if byID["host-bad"].Score != 0 || byID["host-bad"].Confidence != 0 {
		t.Errorf("host-bad should degrade to a zero score, got %+v", byID["host-bad"])
	}
}

// TestFLMProvider_AllCandidatesMalformedReturnsError: if EVERY candidate
// fails to parse, Score() must return an error so the circuit breaker can
// still see a persistently broken backend (spec1.md §52's "malformed
// output rate" must be observable, not silently absorbed).
func TestFLMProvider_AllCandidatesMalformedReturnsError(t *testing.T) {
	srv := httptest.NewServer(flmChatHandler(t, func(string) string {
		return "garbage"
	}))
	defer srv.Close()
	provider := &FLMProvider{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()}

	_, err := provider.Score(context.Background(), flmValidRequest())
	if err == nil {
		t.Fatal("expected an error when no candidate in the batch parses")
	}
	if classify(err) != KindInvalidStructured {
		t.Errorf("kind = %v, want KindInvalidStructured", classify(err))
	}
}

func TestFLMProvider_HTTP500IsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	provider := &FLMProvider{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()}

	_, err := provider.Score(context.Background(), flmValidRequest())
	if err == nil {
		t.Fatal("expected an error")
	}
	kind := classify(err)
	if kind != KindServerError || !kind.retryable() || !kind.healthFailure() {
		t.Errorf("kind = %v, want retryable+health-failure KindServerError", kind)
	}
}
