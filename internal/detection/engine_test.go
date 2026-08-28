package detection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestEngine_RunCycle_ColdStartProducesNoTransition is a wiring smoke test:
// a single host with a valid source reading but no baseline history and no
// cohort peers must be classified source-valid yet local-score-invalid
// (spec §18: both detectors invalid -> no transition, nothing persisted).
func TestEngine_RunCycle_ColdStartProducesNoTransition(t *testing.T) {
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
		t.Fatalf("outcomes = %+v, want exactly 1 host", outcomes)
	}
	if !outcomes[0].Valid {
		t.Fatalf("host cycle should be source-valid (all required features present/in-range): %+v", outcomes[0])
	}
	if outcomes[0].LocalScore.Valid {
		t.Fatalf("cold start (no baseline history, no cohort peers) must be local-score-invalid: %+v", outcomes[0])
	}

	active, err := store.ListActiveEpisodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("no episode should have been created on an invalid-local-score cycle: %v", active)
	}
}

// TestEngine_RunCycle_MissingRequiredFeatureSkipsHost proves the engine
// itself (not just ClassifySample in isolation) treats a host with zero
// samples for a required feature as source-invalid and never advances its
// lifecycle or touches the store.
func TestEngine_RunCycle_MissingRequiredFeatureSkipsHost(t *testing.T) {
	now := time.Now().Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		query := r.URL.Query().Get("query")
		if query == "memory_used_ratio_query" {
			// Simulate this one required feature never returning any
			// series for the host at all.
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
			return
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":"web-1","site":"site-a"},"value":[%d,"0.5"]}]}}`, now)
	}))
	defer server.Close()

	profile := testProfile()
	for i, f := range profile.Features {
		if f.Name == "memory_used_ratio" {
			profile.Features[i].PromQL = "memory_used_ratio_query"
		}
	}
	client := NewThanosClient(server.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)

	outcomes, err := engine.RunCycle(context.Background(), now)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if len(outcomes) != 1 || outcomes[0].Valid {
		t.Fatalf("host with a missing required feature must be source-invalid: %+v", outcomes)
	}
}

// TestEngine_RunCycle_BaselineWarmsUpWithoutCohortOrLog is a regression
// test for a real cold-start deadlock: baseline history accumulation
// (e.Baselines.Observe) used to only run for hosts already in `pending`,
// which requires local.Valid==true — but baseline only becomes Valid
// after 120 buckets of Observe'd history (spec §14.1), production wires
// no cohort assignment mechanism at all (Cohorts is always nil, so
// cohort-outlier-v1 is permanently Valid=false), and here the log source
// is disabled too. Before the fix, local.Valid could NEVER become true
// even once, so this test would loop 120 times and still see
// LocalScore.Valid==false on cycle 121 — the detector could never engage
// in a stock, log-source-disabled deployment.
func TestEngine_RunCycle_BaselineWarmsUpWithoutCohortOrLog(t *testing.T) {
	value := "0.5"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at := r.URL.Query().Get("time")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":"web-1","site":"site-a"},"value":[%s,%q]}]}}`, at, value)
	}))
	defer server.Close()

	profile := testProfile()
	client := NewThanosClient(server.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil) // cohorts=nil, matches production; LogSource left nil too

	base := (int64(1_700_000_000) / 60) * 60
	for i := 0; i < minReadyBuckets; i++ {
		evalTime := base + int64(i)*60
		outcomes, err := engine.RunCycle(context.Background(), evalTime)
		if err != nil {
			t.Fatalf("RunCycle cycle %d: %v", i, err)
		}
		if outcomes[0].LocalScore.Valid {
			t.Fatalf("cycle %d: LocalScore already Valid with only %d prior observations — expected still warming up", i, i)
		}
	}

	// The 121st cycle: 120 prior cycles have now been Observed, so
	// robust-baseline-v1 should have just become Ready.
	outcomes, err := engine.RunCycle(context.Background(), base+int64(minReadyBuckets)*60)
	if err != nil {
		t.Fatalf("RunCycle final cycle: %v", err)
	}
	if !outcomes[0].LocalScore.Valid {
		t.Fatal("after 120 warm cycles with no cohort/log rescue, LocalScore must be Valid — this is exactly the cold-start deadlock this test guards against")
	}

	// And it must actually be usable: a clear spike now scores high.
	value = "0.99"
	outcomes, err = engine.RunCycle(context.Background(), base+int64(minReadyBuckets+1)*60)
	if err != nil {
		t.Fatalf("RunCycle spike cycle: %v", err)
	}
	if !outcomes[0].LocalScore.Valid || outcomes[0].LocalScore.Score < 0.9 {
		t.Fatalf("spike cycle: LocalScore = %+v, want Valid with a high score", outcomes[0].LocalScore)
	}
}
