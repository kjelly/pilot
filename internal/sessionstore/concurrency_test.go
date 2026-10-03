package sessionstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestStoreConcurrentFinishAndIngestStayConsistent races
// IngestEvents(seq=1) against FinishSession(complete=true, lastSeq=0) on
// the same open session, through the public Store methods and a real
// SQLite file. Both used to check EndedAt before their write, so both
// could see an open session and both succeed: the session ended up
// finished with last_seq=0, event_count=1 and complete=true, and Replay
// returned one event while reporting Complete=true (PR #19 review). The
// race detector cannot see this: it is an ordering race inside the
// database, not a Go data race.
//
// Exactly one call may win. Ingest first: the finish sees the stored
// seq 1 and fails with ErrLastSeqTooLow. Finish first: the ingest fails
// with ErrSessionFinished.
func TestStoreConcurrentFinishAndIngestStayConsistent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	const rounds = 200
	var ingestWon, finishWon int
	violations := map[string]int{}
	for i := range rounds {
		id := fmt.Sprintf("sess-race-%d", i)
		startTestSession(t, store, id)

		var ingestErr, finishErr error
		var wg sync.WaitGroup
		release := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-release
			_, ingestErr = store.IngestEvents(ctx, id, []IngestEvent{{Seq: 1, Stream: "tty_output", Data: []byte("x")}})
		}()
		go func() {
			defer wg.Done()
			<-release
			finishErr = store.FinishSession(ctx, id, time.Now().UTC(), true, 0)
		}()
		close(release)
		wg.Wait()

		switch {
		case ingestErr == nil && finishErr == nil:
			violations["both IngestEvents and FinishSession succeeded (event accepted after completion)"]++
		case ingestErr == nil && errors.Is(finishErr, ErrLastSeqTooLow):
			ingestWon++
		case finishErr == nil && errors.Is(ingestErr, ErrSessionFinished):
			finishWon++
		default:
			violations[fmt.Sprintf("unexpected result: ingest=%v finish=%v", ingestErr, finishErr)]++
		}

		sum, err := store.GetSession(ctx, id)
		if err != nil {
			t.Fatalf("round %d: GetSession: %v", i, err)
		}
		replay, err := store.Replay(ctx, id)
		if err != nil {
			t.Fatalf("round %d: Replay: %v", i, err)
		}
		if sum.EventCount != len(replay.Events) {
			violations["event_count differs from the replayed events"]++
		}
		if sum.EndedAt != nil {
			for _, ev := range replay.Events {
				if ev.Seq > sum.LastSeq {
					violations["finished session holds an event above last_seq"]++
				}
			}
		}
		if replay.Complete && (sum.EndedAt == nil || len(replay.Events) != int(sum.LastSeq)) {
			violations["replay Complete=true does not match last_seq and the stored events"]++
		}
	}
	for v, n := range violations {
		t.Errorf("%d of %d rounds: %s", n, rounds, v)
	}
	t.Logf("%d rounds: ingest won %d, finish won %d", rounds, ingestWon, finishWon)
}

// TestStoreConcurrentIdenticalStartsAreIdempotent races two identical
// StartSession retries. StartSession looked the session up and inserted
// in separate statements, so both retries could miss the row and the
// second INSERT failed on the primary key instead of being the no-op the
// retry contract promises (spec.md §28.1).
func TestStoreConcurrentIdenticalStartsAreIdempotent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	for i := range 200 {
		in := SessionStart{
			SessionID: fmt.Sprintf("sess-start-%d", i), User: "alice", DirectoryID: "dir01", GatewayID: "gw01",
			Scope: "gpu", Target: "target01.example.test", RecordingMode: "terminal_output",
			StartedAt: time.Now().UTC(),
		}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		release := make(chan struct{})
		for j := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-release
				errs[j] = store.StartSession(ctx, in)
			}()
		}
		close(release)
		wg.Wait()
		for j, err := range errs {
			if err != nil {
				t.Fatalf("round %d: identical StartSession retry %d = %v, want nil", i, j, err)
			}
		}
	}
}
