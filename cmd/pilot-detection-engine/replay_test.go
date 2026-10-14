package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/detection"
)

func fakeThanosRangeServer(t *testing.T, start time.Time, quietValue, spikeValue string, quietBuckets, spikeBuckets int) *httptest.Server {
	t.Helper()
	total := quietBuckets + spikeBuckets
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := make([][2]any, 0, total)
		for i := 0; i < total; i++ {
			ts := start.Unix() + int64(i)*60
			v := quietValue
			if i >= quietBuckets {
				v = spikeValue
			}
			values = append(values, [2]any{ts, v})
		}
		resp := map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "matrix",
				"result": []map[string]any{
					{"metric": map[string]string{"pilot_host": "web-1", "site": "site-a"}, "values": values},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode fake response: %v", err)
		}
	}))
}

func replayTestProfile() detection.FeatureProfile {
	return detection.FeatureProfile{
		ID: "replay-test-v1", Version: 1,
		Features: []detection.Feature{
			{Name: "cpu_utilization", Required: true, Category: "cpu", ScaleFloor: 0.02, ValidMin: 0, ValidMax: 1.05, PromQL: "x"},
		},
	}
}

func TestRunReplay_DetectsSpikeAfterWarmup(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const quiet, spike = 121, 5 // 121 clears the 120-bucket warm-up requirement
	server := fakeThanosRangeServer(t, start, "0.1", "0.99", quiet, spike)
	defer server.Close()

	client := detection.NewThanosClient(server.URL, detection.QueryTimeout)
	end := start.Add(time.Duration(quiet+spike) * time.Minute)

	var out bytes.Buffer
	if err := runReplay(context.Background(), &out, client, replayTestProfile(), start, end); err != nil {
		t.Fatalf("runReplay: %v", err)
	}

	got := out.String()
	transitionLog, _, found := strings.Cut(got, "\nsummary:\n")
	if !found {
		t.Fatalf("output missing the summary section:\n%s", got)
	}
	if !strings.Contains(transitionLog, "create_critical") && !strings.Contains(transitionLog, "create_warning") {
		t.Fatalf("expected a logged warning/critical transition, got:\n%s", got)
	}
}

func TestRunReplay_QuietHistoryProducesNoTransitions(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const quiet = 200
	server := fakeThanosRangeServer(t, start, "0.1", "0.1", quiet, 0)
	defer server.Close()

	client := detection.NewThanosClient(server.URL, detection.QueryTimeout)
	end := start.Add(time.Duration(quiet) * time.Minute)

	var out bytes.Buffer
	if err := runReplay(context.Background(), &out, client, replayTestProfile(), start, end); err != nil {
		t.Fatalf("runReplay: %v", err)
	}

	got := out.String()
	transitionLog, _, found := strings.Cut(got, "\nsummary:\n")
	if !found {
		t.Fatalf("output missing the summary section:\n%s", got)
	}
	for _, action := range []string{"create_warning", "create_critical", "escalate_critical"} {
		if strings.Contains(transitionLog, action) {
			t.Fatalf("flat history must never log a %q transition, got:\n%s", action, got)
		}
	}
}

func TestRunReplay_RejectsEndBeforeStart(t *testing.T) {
	cmd := newReplayCmd()
	cmd.SetArgs([]string{
		"--thanos", "http://127.0.0.1:1",
		"--profile", "/nonexistent/profile.yaml",
		"--start", "2026-01-02T00:00:00Z",
		"--end", "2026-01-01T00:00:00Z",
	})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --end is before --start")
	}
}

func TestRunReplay_ResolvesAnomalyLastingOver24Hours(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const quiet, spike, recovery = 121, 1500, 8
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := make([][2]any, 0, quiet+spike+recovery)
		for i := 0; i < quiet+spike+recovery; i++ {
			value := "0.1"
			if i >= quiet && i < quiet+spike {
				value = "0.99"
			}
			values = append(values, [2]any{start.Unix() + int64(i)*60, value})
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"status": "success", "data": map[string]any{
				"resultType": "matrix", "result": []map[string]any{{
					"metric": map[string]string{"pilot_host": "web-1", "site": "site-a"}, "values": values,
				}},
			},
		}); err != nil {
			t.Errorf("encode range response: %v", err)
		}
	}))
	defer server.Close()
	var out bytes.Buffer
	if err := runReplay(context.Background(), &out, detection.NewThanosClient(server.URL, detection.QueryTimeout),
		replayTestProfile(), start, start.Add((quiet+spike+recovery)*time.Minute)); err != nil {
		t.Fatal(err)
	}
	transitions, _, _ := strings.Cut(out.String(), "\nsummary:\n")
	if !strings.Contains(transitions, "create_critical") || !strings.Contains(transitions, "enter_recovering") || !strings.Contains(transitions, "resolve") {
		t.Fatalf("long-running replay did not complete fire -> recovery -> resolution:\n%s", out.String())
	}
}
