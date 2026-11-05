package statefile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestContextPublicationProcessHelper(t *testing.T) {
	target := os.Getenv("PILOT_STATE_CONTEXT_TARGET")
	if target == "" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	store, e := New[string](filepath.Dir(target), filepath.Base(target), 1, "context-native")
	if e != nil {
		t.Fatal(e)
	}
	e = store.MutateContext(ctx, func(old []string) ([]string, error) { return []string{"candidate-before-rename"}, nil })
	if !errors.Is(e, context.Canceled) {
		t.Fatalf("pre-rename cancellation published state: %v", e)
	}
}

// Delay the real temporary-file close, and cancel after its bytes are written.
// The context check must run after persistence and before entering rename.
func TestMutateContextNativeCancellationBeforeRename(t *testing.T) {
	strace, e := exec.LookPath("strace")
	if e != nil {
		t.Skip("strace required for native pre-rename persistence window")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	old := []byte(`{"version":1,"targets":["old"]}`)
	if e = os.WriteFile(target, old, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, strace, "-f", "--kill-on-exit", "-e", "trace=close,rename,renameat,renameat2", "-e", "inject=close:delay_enter=400ms", "-o", filepath.Join(dir, "trace"), os.Args[0], "-test.run=^TestContextPublicationProcessHelper$")
	command.Env = append(os.Environ(), "PILOT_STATE_CONTEXT_TARGET="+target)
	log, e := os.Create(filepath.Join(dir, "output"))
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	command.Stdout, command.Stderr = log, log
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	for {
		files, _ := filepath.Glob(filepath.Join(dir, ".context-native-*.json.tmp"))
		if len(files) == 1 {
			data, _ := os.ReadFile(files[0])
			if strings.Contains(string(data), "candidate-before-rename") {
				break
			}
		}
		select {
		case e := <-done:
			out, _ := os.ReadFile(filepath.Join(dir, "output"))
			t.Fatalf("helper exited before native persistence window: %v %s", e, out)
		case <-ctx.Done():
			t.Fatal("native persistence checkpoint timeout")
		case <-time.After(5 * time.Millisecond):
		}
	}
	children, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", command.Process.Pid, command.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	ids := strings.Fields(string(children))
	if len(ids) != 1 {
		t.Fatalf("expected one native helper, got %d", len(ids))
	}
	pid, e := strconv.Atoi(ids[0])
	if e != nil {
		t.Fatal(e)
	}
	if e = syscall.Kill(pid, syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e != nil {
			out, _ := os.ReadFile(filepath.Join(dir, "output"))
			t.Fatalf("native publication cancellation: %v %s", e, out)
		}
	case <-ctx.Done():
		t.Fatal("native cancellation did not finish")
	}
	after, e := os.ReadFile(target)
	if e != nil || string(after) != string(old) {
		t.Fatal("pre-rename cancellation replaced original state")
	}
	files, _ := filepath.Glob(filepath.Join(dir, ".context-native-*.json.tmp"))
	if len(files) != 0 {
		t.Fatal("native cancellation leaked temp state")
	}
	store, e := New[string](dir, "state.json", 1, "context-native")
	if e != nil {
		t.Fatal(e)
	}
	if e = store.MutateContext(context.Background(), func(old []string) ([]string, error) { return []string{"retry"}, nil }); e != nil {
		t.Fatal(e)
	}
	got, e := store.Load()
	if e != nil || len(got) != 1 || got[0] != "retry" {
		t.Fatal("retry after native cancellation failed")
	}
}
