package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the real source -> baseline -> lifecycle -> SQLite/outbox chain.
// No cohort or log detector can rescue an expired baseline in these cases.
func TestEngine_LongRunningEpisodeRetainsBaselineAndResolves(t *testing.T) {
	for _, severity := range []Severity{SeverityWarning, SeverityCritical} {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%t", severity, restart), func(t *testing.T) {
				var value atomic.Int64
				var missing atomic.Bool
				value.Store(20)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if missing.Load() {
						fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
						return
					}
					fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pilot_host":"web-1","site":"site-a"},"value":[%s,%q]}]}}`,
						r.URL.Query().Get("time"), fmt.Sprint(float64(value.Load())/100))
				}))
				defer server.Close()
				warningFloor, criticalFloor := 0.60, 0.95
				profile := FeatureProfile{
					ID: "test-v1", Version: 1,
					Lifecycle: LifecyclePolicy{WarningWindowCycles: 8, WarningRequiredCycles: 6, CriticalConsecutiveCycles: 4, RecoveryConsecutiveCycles: 8},
					Features: []Feature{{Name: "cpu_utilization", Required: true, Category: "cpu", ScaleFloor: 0.02,
						ValidMin: 0, ValidMax: 1.05, PromQL: "cpu", WarningMinValue: &warningFloor, CriticalMinValue: &criticalFloor}},
				}
				store := openTestStore(t)
				client := NewThanosClient(server.URL, 5*time.Second)
				engine := NewEngine(profile, client, store, nil)
				base := BucketOf(1_700_000_000)
				run := func(at int64) HostCycleOutcome {
					t.Helper()
					outcomes, err := engine.RunCycle(context.Background(), at)
					if err != nil || len(outcomes) != 1 {
						t.Fatalf("RunCycle(%d): outcomes=%+v err=%v", at, outcomes, err)
					}
					return outcomes[0]
				}
				for i := 0; i < minReadyBuckets; i++ {
					run(base + int64(i)*60)
				}
				if severity == SeverityCritical {
					value.Store(99)
				} else {
					value.Store(85)
				}
				fireTime := base + minReadyBuckets*60
				for i := 0; i < profile.Lifecycle.WarningWindowCycles; i++ {
					run(fireTime + int64(i)*15)
				}
				active, err := store.ListActiveEpisodes()
				if err != nil || len(active) != 1 || active[0].Severity != string(severity) {
					t.Fatalf("expected one %s episode: %+v, %v", severity, active, err)
				}
				signalID := active[0].SignalID
				restartEngine := func(at int64) {
					t.Helper()
					path := store.path
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
					store, err = OpenStore(path)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = store.Close() })
					engine = NewEngine(profile, client, store, nil)
					engine.Baselines, err = store.LoadBaselineHistory(time.Unix(at, 0), SubjectKindManagedHost)
					if err != nil {
						t.Fatal(err)
					}
					if err := RestoreActiveEpisodes([]*Engine{engine}, store, time.Unix(at, 0)); err != nil {
						t.Fatal(err)
					}
				}
				later := fireTime + 25*60*60
				if restart {
					restartEngine(later)
				}
				// Two cycles catch eviction after the first successful score.
				for i := 0; i < 2; i++ {
					outcome := run(later + int64(i)*15)
					if !outcome.LocalScore.Valid || engine.lifecycleFor("web-1").State != StateFiring {
						t.Fatalf("long-running anomaly stopped scoring: %+v", outcome)
					}
				}
				for _, sample := range engine.Baselines.History("web-1", "cpu_utilization") {
					if sample != 0.20 {
						t.Fatalf("anomaly contaminated frozen baseline: %v", sample)
					}
				}
				value.Store(20)
				if outcome := run(later + 30); outcome.Transition.Action != ActionEnterRecovering {
					t.Fatalf("normal telemetry did not enter recovery: %+v", outcome)
				}
				if restart {
					restartEngine(later + 45) // also preserve a recovering episode's reference
				}
				missing.Store(true)
				if _, err := engine.RunCycle(context.Background(), later+45); err != nil {
					t.Fatal(err)
				}
				if engine.lifecycleFor("web-1").RecoveryStreak != 1 {
					t.Fatal("missing telemetry advanced the recovery streak")
				}
				missing.Store(false)
				for i := 1; i < profile.Lifecycle.RecoveryConsecutiveCycles; i++ {
					outcome := run(later + 45 + int64(i)*15)
					if !outcome.LocalScore.Valid {
						t.Fatalf("recovery lost its baseline: %+v", outcome)
					}
					if i == profile.Lifecycle.RecoveryConsecutiveCycles-1 && outcome.Transition.Action != ActionResolve {
						t.Fatalf("normal telemetry did not resolve episode: %+v", outcome)
					}
				}
				active, err = store.ListActiveEpisodes()
				if err != nil || len(active) != 0 {
					t.Fatalf("episode still active after recovery: %+v, %v", active, err)
				}
				var raw string
				if err := store.db.QueryRow(`SELECT payload_json FROM outbox WHERE signal_id=? AND kind='resolve'`, signalID).Scan(&raw); err != nil {
					t.Fatalf("missing durable resolution: %v", err)
				}
				var payload AlertmanagerPayload
				if err := json.Unmarshal([]byte(raw), &payload); err != nil {
					t.Fatal(err)
				}
				if payload.Labels["signal_id"] != signalID || payload.Labels["severity"] != string(severity) {
					t.Fatalf("resolution changed alert identity: %+v", payload)
				}
				// Once resolved, the normal rolling window resumes; old frozen
				// samples must no longer be retained or loaded on restart.
				warm, err := store.LoadBaselineHistory(time.Unix(later+180, 0), SubjectKindManagedHost)
				if err != nil || len(warm.History("web-1", "cpu_utilization")) != 1 {
					t.Fatalf("resolved host kept stale reference: %+v, %v", warm, err)
				}
			})
		}
	}
}
