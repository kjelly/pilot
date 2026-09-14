package agentcontroller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMetricsSnapshot_WriteTextfilePublishesReadableMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pilot_agent_controller.prom")
	if err := (MetricsSnapshot{Up: true}).WriteTextfile(path); err != nil {
		t.Fatalf("WriteTextfile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat metrics file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("metrics file mode = %o, want 644", got)
	}
}
