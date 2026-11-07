//go:build identity_live_hooks

package identityreconcile

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/livehooks"
)

// armSpy records what the next request is armed for at the moment each command goes out.
type armSpy struct {
	*fakeIPA
	mu    sync.Mutex
	armed []string
}

func (s *armSpy) note() {
	s.mu.Lock()
	s.armed = append(s.armed, livehooks.Armed())
	s.mu.Unlock()
}

func (s *armSpy) Batch(ctx context.Context, cmds []freeiparpc.Command) ([]freeiparpc.BatchItem, error) {
	// The re-reads of the checks are batches too, of reads: only a write's batch is armed.
	if len(cmds) > 0 && !strings.HasSuffix(cmds[0].Method, "_show") {
		s.note()
	}
	return s.fakeIPA.Batch(ctx, cmds)
}

func (s *armSpy) Call(ctx context.Context, cmd freeiparpc.Command) (json.RawMessage, error) {
	s.note()
	return s.fakeIPA.Call(ctx, cmd)
}

// The executor stops where the live driver's arms need it to (spec §10.2, D31), in this
// order, and arms the request of each batch or call with its own name just before it goes
// out. The arms rest on these names, so a renamed or moved stop fails here and not in a live run.
func TestExecuteStopsAtThePointsTheLiveDriverNames(t *testing.T) {
	dir := t.TempDir()
	points := []string{
		"after_entry", "before_stage:S1", "before_batch:S1:1", "before_stage:S3", "before_batch:S3:1",
		"before_stage:S4", "before_batch:S4:1", "before_stage:S6", "before_batch:S6:1",
		"after_send:S1:1", "after_send:S3:1", "after_send:S4:1", "after_send:S6:1",
	}
	t.Setenv(livehooks.EnvDir, dir)
	t.Setenv(livehooks.EnvPoints, strings.Join(points, ","))

	roster := rosterWith("  - {name: ua, "+pw("a")+"}\n", "  - {name: team-b, category: team, membership: {users: [ua]}}\n")
	e := newRunEnv(t, roster)
	spy := &armSpy{fakeIPA: e.f}

	// The driver: answer every stop as it is notified.
	stop := make(chan struct{})
	var seen []string
	var seenMu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		answered := 0
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			f, err := os.Open(filepath.Join(dir, "notify"))
			if err != nil {
				continue
			}
			var lines []string
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				lines = append(lines, sc.Text())
			}
			f.Close()
			for ; answered < len(lines); answered++ {
				var n int
				var p string
				fmt.Sscanf(lines[answered], "%d %s", &n, &p)
				seenMu.Lock()
				seen = append(seen, p)
				seenMu.Unlock()
				_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("go.%d", n)), []byte("resume\n"), 0o600)
			}
		}
	}()
	res, err := executeWithin(e.ctx, spy, e.opts)
	close(stop)
	<-done
	if err != nil {
		t.Fatalf("Execute: %v%s", err, describeOps(res))
	}
	seenMu.Lock()
	defer seenMu.Unlock()
	// The stops of the stages that have operations, in the order of the run.
	for _, want := range []string{"after_entry", "before_stage:S1", "before_batch:S1:1", "before_stage:S3", "before_batch:S3:1", "before_stage:S4", "before_batch:S4:1", "before_stage:S6", "before_batch:S6:1"} {
		if !slices.Contains(seen, want) {
			t.Errorf("no stop at %s: stops were %v", want, seen)
		}
	}
	if len(seen) == 0 || seen[0] != "after_entry" {
		t.Errorf("the first stop is %v, want after_entry (the entry has run, nothing is written)", seen)
	}
	if i, j := slices.Index(seen, "before_stage:S3"), slices.Index(seen, "before_batch:S3:1"); i < 0 || j < i {
		t.Errorf("before_batch:S3:1 must come after before_stage:S3: %v", seen)
	}
	// The writes were armed with their own names, in the order they went out.
	var armed []string
	spy.mu.Lock()
	armed = slices.Clone(spy.armed)
	spy.mu.Unlock()
	for _, want := range []string{"after_send:S1:1", "after_send:S3:1", "after_send:S4:1", "after_send:S6:1"} {
		if !slices.Contains(armed, want) {
			t.Errorf("no request was armed for %s: armed %v", want, armed)
		}
	}
}
