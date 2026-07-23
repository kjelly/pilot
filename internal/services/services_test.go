package services

import (
	"context"
	"net"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls []string
	code  int
}

func (f *fakeRunner) Run(_ context.Context, dir, name string, args ...string) (CommandResult, error) {
	f.calls = append(f.calls, strings.Join(append([]string{dir, name}, args...), " "))
	return CommandResult{Stdout: "Docker Compose version v2.30\n", ExitCode: f.code}, nil
}

func TestManagerPurgeRequiresConfirmation(t *testing.T) {
	m, err := NewManager(t.TempDir(), &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Purge(context.Background(), false); err == nil {
		t.Fatal("purge without confirmation must fail")
	}
}

func TestManagerRequiresComposeV2(t *testing.T) {
	runner := &fakeRunner{code: 1}
	m, err := NewManager(t.TempDir(), runner)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Up(context.Background(), BuiltInDevLite(), net.ParseIP("192.168.122.1"))
	if err == nil || !strings.Contains(err.Error(), "Compose v2") {
		t.Fatalf("want Compose v2 error, got %v", err)
	}
}
