package detection

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMetricsSnapshot_RenderAndWriteTextfile(t *testing.T) {
	snap := MetricsSnapshot{
		Up:                  true,
		SubjectsTotal:       3,
		SubjectSkippedTotal: map[string]int64{"stale": 1},
		AnomalyScore:        map[[2]string]float64{{"web-1", "baseline"}: 0.42},
		OutboxPending:       2,
	}
	text := snap.Render()
	for _, want := range []string{
		"pilot_detection_engine_up 1",
		`pilot_detection_subject_skipped_total{reason="stale"} 1`,
		`pilot_detection_anomaly_score{pilot_host="web-1",detector="baseline"} 0.42`,
		"pilot_detection_outbox_pending 2",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered metrics missing %q; got:\n%s", want, text)
		}
	}

	path := filepath.Join(t.TempDir(), "pilot_detection_engine.prom")
	if err := snap.WriteTextfile(path); err != nil {
		t.Fatalf("WriteTextfile: %v", err)
	}
}

func TestStatus_WriteReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	want := Status{
		SchemaVersion: 1,
		State:         "healthy",
		Source:        StatusSource{Healthy: true},
		ModelProvider: NewDisabledProviderStatus(),
		LastCycle:     StatusLastCycle{Success: true},
	}
	if err := WriteStatus(path, want); err != nil {
		t.Fatalf("WriteStatus: %v", err)
	}
	got, err := ReadStatus(path)
	if err != nil {
		t.Fatalf("ReadStatus: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, want)
	}
}
