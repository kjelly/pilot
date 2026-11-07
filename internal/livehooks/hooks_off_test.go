//go:build !identity_live_hooks

package livehooks

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Without the tag there is no stop and no wrapper, whatever the environment says: a
// pilot that is released, or built by anyone who did not ask for the tag, cannot be
// made to stop by setting two variables (spec D31).
func TestWithoutTheTagNothingStopsAndNothingIsWrapped(t *testing.T) {
	if Enabled {
		t.Fatal("Enabled is true in a build without identity_live_hooks")
	}
	dir := t.TempDir()
	t.Setenv(EnvDir, dir)
	t.Setenv(EnvPoints, "after_entry,before_stage:S3,before_batch:S3:1,after_send:S3:1")

	done := make(chan struct{})
	go func() {
		defer close(done)
		Pause(context.Background(), "after_entry")
		Pause(context.Background(), "before_stage:S3")
		Arm("after_send:S3:1")
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pause waited in a build without the tag")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a build without the tag wrote %d files to the driver's directory", len(entries))
	}
	if _, err := os.Stat(filepath.Join(dir, "notify")); err == nil {
		t.Fatal("a notify file exists")
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if got := WrapConn(a); got != a {
		t.Fatal("WrapConn wrapped a connection in a build without the tag")
	}
	ctx := context.Background()
	if got := RequestContext(ctx); got != ctx {
		t.Fatal("RequestContext attached a trace in a build without the tag")
	}
}
