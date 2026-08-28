package detection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEngine_RunCycle_ModelEscalatesSeverity is an end-to-end wiring test
// for spec §19/§35: a host whose local baseline score already clears
// CandidateThreshold gets batched to the (fake) model provider, and the
// model's higher effective score/category wins the fused result that
// actually drives the lifecycle/episode.
func TestEngine_RunCycle_ModelEscalatesSeverity(t *testing.T) {
	now := time.Now().Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// testProfile's PromQL is "x" for every feature, so this handler
		// answers identically for cpu/memory/thermal: 0.6 against
		// cpu_utilization's seeded low-variance history below lands
		// local_score around 0.72 (candidate-eligible but NOT saturated
		// at 1.0, leaving headroom for the model to clearly escalate
		// above it) while staying inside both cpu's (1.05) and memory's
		// (1.0) ValidMax range with margin.
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":"web-1","site":"site-a"},"value":[%d,"0.6"]}]}}`, now)
	}))
	defer server.Close()

	profile := testProfile()
	client := NewThanosClient(server.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)

	// Seed 120 minutes of low-variance cpu_utilization history so its
	// robust baseline is ready and a current value of 1.0 is a huge
	// z-score outlier (well past the score=1.0 ceiling at z=8), while
	// staying inside cpu_utilization's own ValidMax=1.05 source-range gate.
	for i := 120; i >= 1; i-- {
		ts := now - int64(i*60)
		v := 0.05
		if i%2 == 0 {
			v = 0.15
		}
		engine.Baselines.Observe("web-1", "cpu_utilization", ts, v)
	}

	fake := &FakeModelProvider{ScoreFunc: func(ctx context.Context, req ModelBatchRequest) (ModelBatchResponse, error) {
		if len(req.Candidates) != 1 || req.Candidates[0].CandidateID != "web-1" {
			t.Fatalf("unexpected batch request: %+v", req)
		}
		return ModelBatchResponse{
			SchemaVersion: 1, RequestID: req.RequestID, Status: "ok",
			Candidates: []ModelCandidateResponse{{
				CandidateID: "web-1", Score: 1.0, Confidence: 1.0, CategoryHint: "model-escalated-cpu",
				Contributors: []ModelContributor{{Feature: "cpu_utilization", Score: 1.0}},
			}},
		}, nil
	}}
	engine.Provider = NewManagedProvider(fake, "openai-responses", time.Second)
	engine.ProviderProtocol = "openai-responses"

	// spec §20: warning requires 3-of-4 candidate-or-higher readings, so a
	// single cycle only advances the lifecycle toward "candidate" — run
	// enough cycles for it to actually fire and persist an episode.
	var lastOutcomes []HostCycleOutcome
	for cycle := 0; cycle < 4; cycle++ {
		outcomes, err := engine.RunCycle(context.Background(), now)
		if err != nil {
			t.Fatalf("RunCycle[%d]: %v", cycle, err)
		}
		lastOutcomes = outcomes
	}
	if len(lastOutcomes) != 1 {
		t.Fatalf("outcomes = %+v, want exactly 1 host", lastOutcomes)
	}
	o := lastOutcomes[0]
	if !o.Valid || !o.LocalScore.Valid {
		t.Fatalf("expected a valid, candidate-eligible cycle: %+v", o)
	}
	if o.LocalScore.Score < CandidateThreshold {
		t.Fatalf("expected local score >= %v to trigger the model, got %v", CandidateThreshold, o.LocalScore.Score)
	}
	if o.Fused.Source != "model" || o.Fused.Category != "model-escalated-cpu" {
		t.Fatalf("expected the model result to win fusion, got %+v", o.Fused)
	}
	if engine.LastModelStats.CandidatesTotal != 1 {
		t.Errorf("LastModelStats.CandidatesTotal = %d, want 1", engine.LastModelStats.CandidatesTotal)
	}
	if engine.LastModelStats.RequestTotal[[2]string{"openai-responses", "ok"}] != 1 {
		t.Errorf("expected one ok request recorded, got %+v", engine.LastModelStats.RequestTotal)
	}

	active, err := store.ListActiveEpisodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].CategoryHint != "model-escalated-cpu" {
		t.Fatalf("expected one episode carrying the model-escalated category, got %+v", active)
	}
}

// TestEngine_RunCycle_ProviderDisabledMatchesLocalOnly is a regression
// guard: with no provider wired (Stage A default), Fused must exactly
// mirror LocalScore for every outcome.
func TestEngine_RunCycle_ProviderDisabledMatchesLocalOnly(t *testing.T) {
	now := time.Now().Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":"web-1","site":"site-a"},"value":[%d,"0.5"]}]}}`, now)
	}))
	defer server.Close()

	profile := testProfile()
	client := NewThanosClient(server.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)

	outcomes, err := engine.RunCycle(context.Background(), now)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if len(outcomes) != 1 {
		t.Fatalf("outcomes = %+v", outcomes)
	}
	o := outcomes[0]
	if o.Valid && o.LocalScore.Valid && o.Fused.Score != o.LocalScore.Score {
		t.Fatalf("provider-disabled Fused must equal LocalScore, got local=%v fused=%v", o.LocalScore.Score, o.Fused.Score)
	}
	s := engine.LastModelStats
	if s.CandidatesTotal != 0 || len(s.DroppedTotal) != 0 || len(s.RequestTotal) != 0 || len(s.RequestDuration) != 0 || s.ProviderUp || s.CircuitOpen {
		t.Errorf("expected zero-value LastModelStats when provider disabled, got %+v", s)
	}
}
