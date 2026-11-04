package statefile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMutateContextCancellationPreservesStateAndRetry(t *testing.T) {
	store, e := New[string](t.TempDir(), "state.json", 1, "test")
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Save([]string{"old"}); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(store.Path())
	ctx, cancel := context.WithCancel(context.Background())
	e = store.MutateContext(ctx, func(old []string) ([]string, error) { cancel(); return []string{"canceled"}, nil })
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("callback cancellation published: %v", e)
	}
	after, _ := os.ReadFile(store.Path())
	if !bytes.Equal(before, after) {
		t.Fatal("callback cancellation replaced old bytes")
	}
	tmp, _ := filepath.Glob(filepath.Join(store.dir, ".test-*.json.tmp"))
	if len(tmp) != 0 {
		t.Fatal("cancellation leaked temporary files")
	}
	if e = store.MutateContext(context.Background(), func(old []string) ([]string, error) { return []string{"retry"}, nil }); e != nil {
		t.Fatal(e)
	}
	got, e := store.Load()
	if e != nil || len(got) != 1 || got[0] != "retry" {
		t.Fatalf("successful retry failed: %v %v", got, e)
	}
}
func TestMutateContextLockWaitCanceled(t *testing.T) {
	store, e := New[string](t.TempDir(), "state.json", 1, "test")
	if e != nil {
		t.Fatal(e)
	}
	held, e := store.lock(syscall.LOCK_EX)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	called := false
	start := time.Now()
	e = store.MutateContext(ctx, func(old []string) ([]string, error) { called = true; return old, nil })
	if !errors.Is(e, context.DeadlineExceeded) || called || time.Since(start) > time.Second {
		t.Fatalf("lock wait ignored cancellation: %v called=%t", e, called)
	}
}

// A test marshaler cancels during actual JSON serialization after the callback.
// It proves the persistence path checks cancellation even when callback guards pass.
type cancelOnMarshal struct{ cancel context.CancelFunc }

func (v cancelOnMarshal) MarshalJSON() ([]byte, error) {
	if v.cancel != nil {
		v.cancel()
	}
	return []byte(`"value"`), nil
}
func TestMutateContextSerializationCancellationDoesNotRename(t *testing.T) {
	store, e := New[cancelOnMarshal](t.TempDir(), "state.json", 1, "test")
	if e != nil {
		t.Fatal(e)
	}
	before := []byte(`{"version":1,"targets":[]}`)
	if e = os.WriteFile(store.Path(), before, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e = store.MutateContext(ctx, func(old []cancelOnMarshal) ([]cancelOnMarshal, error) {
		return []cancelOnMarshal{{cancel: cancel}}, nil
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("serialization cancellation published: %v", e)
	}
	after, _ := os.ReadFile(store.Path())
	if !bytes.Equal(before, after) {
		t.Fatal("serialization cancellation replaced state")
	}
	tmp, _ := filepath.Glob(filepath.Join(store.dir, ".test-*.json.tmp"))
	if len(tmp) != 0 {
		t.Fatal("serialization cancellation left temp file")
	}
}
