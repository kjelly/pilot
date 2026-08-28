package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// thanosStubNormal returns a metrics server whose every feature reads a
// steady, non-anomalous value for a single host — used so these tests
// isolate the LOG detector's contribution (metrics/cohort never fire).
func thanosStubNormal(host, site string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":%q,"site":%q},"value":[%d,"0.5"]}]}}`, host, site, time.Now().Unix())
	}))
}

func lokiStub(t *testing.T, streams []lokiStreamFixture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type valuesEntry = [2]string
		type resultEntry struct {
			Stream map[string]string `json:"stream"`
			Values []valuesEntry     `json:"values"`
		}
		results := make([]resultEntry, 0, len(streams))
		for _, s := range streams {
			values := make([]valuesEntry, 0, len(s.lines))
			for _, line := range s.lines {
				values = append(values, valuesEntry{fmt.Sprintf("%d", time.Now().UnixNano()), line})
			}
			results = append(results, resultEntry{Stream: s.labels, Values: values})
		}
		body, _ := json.Marshal(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "streams",
				"result":     results,
			},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
}

type lokiStreamFixture struct {
	labels map[string]string
	lines  []string
}

// TestEngine_RunCycle_LogSourceDisabledMatchesLocalOnly is a regression
// guard: with LogSource nil (the default), RunCycle must be byte-
// identical to before the log pipeline existed.
func TestEngine_RunCycle_LogSourceDisabledMatchesLocalOnly(t *testing.T) {
	now := time.Now().Unix()
	metricsSrv := thanosStubNormal("web-1", "site-a")
	defer metricsSrv.Close()

	profile := testProfile()
	client := NewThanosClient(metricsSrv.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)

	outcomes, err := engine.RunCycle(context.Background(), now)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if len(outcomes) != 1 {
		t.Fatalf("outcomes = %+v", outcomes)
	}
}

// TestEngine_RunCycle_LogBurstAloneTriggersCandidate proves a log-only
// anomaly (metrics show nothing unusual) still reaches the candidate
// threshold via ComputeLocalScore's 3-way max.
func TestEngine_RunCycle_LogBurstAloneTriggersCandidate(t *testing.T) {
	now := time.Now().Unix()
	metricsSrv := thanosStubNormal("web-1", "site-a")
	defer metricsSrv.Close()

	var burstLines []string
	for i := 0; i < 200; i++ {
		burstLines = append(burstLines, "connection retry to backend timed out")
	}
	lokiSrv := lokiStub(t, []lokiStreamFixture{
		{labels: map[string]string{"pilot_host": "web-1", "site": "site-a"}, lines: burstLines},
	})
	defer lokiSrv.Close()

	profile := testProfile()
	client := NewThanosClient(metricsSrv.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)
	engine.LogSource = NewLokiClient(lokiSrv.URL, 5*time.Second)
	engine.LogQuery = `{job=~".+"}`
	engine.LogCurrentWindow = 10 * time.Minute
	engine.LogBaselineWindow = 6 * time.Hour

	outcomes, err := engine.RunCycle(context.Background(), now)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}
	if len(outcomes) != 1 {
		t.Fatalf("outcomes = %+v", outcomes)
	}
	o := outcomes[0]
	if !o.Valid || !o.LocalScore.Valid {
		t.Fatalf("expected a valid cycle, got %+v", o)
	}
	if o.LocalScore.Source != "log" {
		t.Fatalf("expected the log detector to win (metrics/cohort are flat), got source=%q score=%v", o.LocalScore.Source, o.LocalScore.Score)
	}
	if o.LocalScore.Score < CandidateThreshold {
		t.Errorf("expected the log burst to clear the candidate threshold, got score=%v", o.LocalScore.Score)
	}
}

// TestEngine_RunCycle_LogHardTriggerForcesScoreOne proves spec1.md §37's
// Option B: a known-critical-pattern log line forces the log detector's
// score to 1.0 for the cycle it appears in, driving a real episode after
// enough consecutive cycles clear the existing lifecycle hysteresis
// (spec §20) — no lifecycle bypass code needed, since ComputeLocalScore's
// max() already lets a 1.0 dominate.
func TestEngine_RunCycle_LogHardTriggerForcesScoreOne(t *testing.T) {
	now := time.Now().Unix()
	metricsSrv := thanosStubNormal("web-1", "site-a")
	defer metricsSrv.Close()

	lokiSrv := lokiStub(t, []lokiStreamFixture{
		{labels: map[string]string{"pilot_host": "web-1", "site": "site-a"}, lines: []string{
			"kernel: Out of memory: Killed process 4821 (worker)",
		}},
	})
	defer lokiSrv.Close()

	profile := testProfile()
	client := NewThanosClient(metricsSrv.URL, 5*time.Second)
	store := openTestStore(t)
	engine := NewEngine(profile, client, store, nil)
	engine.LogSource = NewLokiClient(lokiSrv.URL, 5*time.Second)
	engine.LogQuery = `{job=~".+"}`

	var lastOutcomes []HostCycleOutcome
	for cycle := 0; cycle < 4; cycle++ {
		outcomes, err := engine.RunCycle(context.Background(), now)
		if err != nil {
			t.Fatalf("RunCycle[%d]: %v", cycle, err)
		}
		lastOutcomes = outcomes
	}
	o := lastOutcomes[0]
	if o.LocalScore.Score != 1.0 {
		t.Fatalf("expected the hard trigger to force score=1.0 every cycle, got %v", o.LocalScore.Score)
	}
	if o.LocalScore.Category != "known_critical_pattern" {
		t.Errorf("expected category=known_critical_pattern, got %q", o.LocalScore.Category)
	}

	active, err := store.ListActiveEpisodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].CategoryHint != "known_critical_pattern" {
		t.Fatalf("expected one episode carrying the hard-trigger category, got %+v", active)
	}
}
