package promtext

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetricsTextfileRender(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("pilot_test_requests_total", "Requests by result.", "result", "reason")
	g := r.Gauge("pilot_test_last_write_timestamp_seconds", "Last write.")
	empty := r.Counter("pilot_test_empty_total", "No series yet.", "kind")
	_ = empty
	c.Inc("denied", "recording_policy_invalid")
	c.Inc("allowed", "none")
	c.Add(2, "allowed", "none")
	c.Inc("denied", `we"ird\value`)
	g.Set(1700000000)

	want := `# HELP pilot_test_requests_total Requests by result.
# TYPE pilot_test_requests_total counter
pilot_test_requests_total{result="allowed",reason="none"} 3
pilot_test_requests_total{result="denied",reason="recording_policy_invalid"} 1
pilot_test_requests_total{result="denied",reason="we\"ird\\value"} 1
# HELP pilot_test_last_write_timestamp_seconds Last write.
# TYPE pilot_test_last_write_timestamp_seconds gauge
pilot_test_last_write_timestamp_seconds 1.7e+09
# HELP pilot_test_empty_total No series yet.
# TYPE pilot_test_empty_total counter
`
	if got := r.Render(); got != want {
		t.Fatalf("Render:\n%s\nwant:\n%s", got, want)
	}
	if c.Value("allowed", "none") != 3 {
		t.Fatalf("Value = %v", c.Value("allowed", "none"))
	}
}

func TestMetricsTextfileWrongLabelCountPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a wrong label count did not panic")
		}
	}()
	NewRegistry().Counter("x_total", "x", "a").Inc()
}

func TestMetricsTextfileAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pilot_test.prom")
	r := NewRegistry()
	r.Counter("pilot_test_total", "t").Inc()
	if err := r.WriteTextfile(path); err != nil {
		t.Fatalf("WriteTextfile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o, want 0644", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the metrics file (no temp leftovers)", len(entries))
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "pilot_test_total 1\n") {
		t.Fatalf("file = %q", b)
	}
	if err := r.WriteTextfile(filepath.Join(dir, "missing", "x.prom")); err == nil {
		t.Fatal("writing into a missing directory succeeded")
	}
}

func TestMetricsTextfileWriteLoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loop.prom")
	r := NewRegistry()
	c := r.Counter("pilot_test_total", "t")
	last := r.Gauge("pilot_test_metrics_last_write_timestamp_seconds", "t")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.WriteLoop(ctx, path, time.Hour, last, func(err error) { t.Errorf("write: %v", err) })
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("WriteLoop did not write at start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.Inc()
	cancel()
	<-done
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "pilot_test_total 1\n") {
		t.Fatalf("final write missing the last increment: %q", b)
	}
	if last.Value() == 0 {
		t.Fatal("last-write gauge was never set")
	}
}
