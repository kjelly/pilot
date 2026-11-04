package services

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

func TestCredentialPublicationProcessHelper(t *testing.T) {
	target := os.Getenv("PILOT_CREDENTIAL_PUBLICATION_TARGET")
	if target == "" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	err := writeAtomicModeContext(ctx, target, []byte("validated-candidate\n"), 0600)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("precommit cancellation ignored: %v", err)
	}
}

// Delay the actual temporary-file fsync, then deliver a real graceful signal.
// A synthetic canceled context at function entry cannot cover this boundary.
func TestCredentialPublicationCancellationDuringSync(t *testing.T) {
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Skip("strace required to exercise the real precommit persistence boundary")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "admin-password")
	old := []byte("old-association\n")
	if err := os.WriteFile(target, old, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, strace, "-f", "--kill-on-exit", "-e", "trace=fsync,rename,renameat,renameat2", "-e", "inject=fsync:delay_enter=1s", "-o", filepath.Join(dir, "trace"), os.Args[0], "-test.run=^TestCredentialPublicationProcessHelper$")
	command.Env = append(os.Environ(), "PILOT_CREDENTIAL_PUBLICATION_TARGET="+target)
	output := filepath.Join(dir, "output")
	log, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	for {
		files, err := filepath.Glob(filepath.Join(dir, ".pilot-service-*.tmp"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 1 {
			data, err := os.ReadFile(files[0])
			if err == nil && string(data) == "validated-candidate\n" {
				break
			}
		}
		select {
		case err := <-done:
			data, _ := os.ReadFile(output)
			t.Fatalf("helper exited before persistence checkpoint: %v %s", err, data)
		case <-ctx.Done():
			t.Fatal("helper did not reach temporary-file persistence")
		case <-time.After(5 * time.Millisecond):
		}
	}
	children, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", command.Process.Pid, command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	ids := strings.Fields(string(children))
	if len(ids) != 1 {
		t.Fatalf("expected one traced helper, found %d", len(ids))
	}
	pid, err := strconv.Atoi(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			data, _ := os.ReadFile(output)
			t.Fatalf("precommit signal regression: %v %s", err, data)
		}
	case <-ctx.Done():
		t.Fatal("canceled persistence did not finish")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != string(old) {
		t.Fatal("precommit cancellation replaced the previous association")
	}
	files, _ := filepath.Glob(filepath.Join(dir, ".pilot-service-*.tmp"))
	if len(files) != 0 {
		t.Fatal("graceful cancellation left uncommitted secret temporary files")
	}
	if err := writeAtomicModeContext(context.Background(), target, []byte("validated-candidate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(target)
	if err != nil || string(data) != "validated-candidate\n" {
		t.Fatal("successful retry did not publish the candidate")
	}
}
