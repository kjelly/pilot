package sandbox

import (
	"strings"
	"testing"
)

func TestParseSandboxMode(t *testing.T) {
	cases := []struct {
		in      string
		want    SandboxMode
		wantErr bool
	}{
		{"", SandboxModeDocker, false},
		{"docker", SandboxModeDocker, false},
		{"DOCKER", SandboxModeDocker, false},
		{"  docker  ", SandboxModeDocker, false},
		{"docker-conn", SandboxModeDocker, false},
		{"docker-connection", SandboxModeDocker, false},
		{"docker-exec", SandboxModeDockerExec, false},
		{"docker_exec", SandboxModeDockerExec, false},
		{"DOCKER-EXEC", SandboxModeDockerExec, false},
		{"exec", SandboxModeDockerExec, false},
		{"unknown", SandboxModeUnset, true},
		{"ssh", SandboxModeUnset, true},
	}
	for _, c := range cases {
		got, err := ParseSandboxMode(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseSandboxMode(%q): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSandboxMode(%q): unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseSandboxMode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSandboxModeString(t *testing.T) {
	cases := map[SandboxMode]string{
		SandboxModeUnset:      "",
		SandboxModeDocker:     "docker",
		SandboxModeDockerExec: "docker-exec",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("SandboxMode(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestUnknownSandboxModeError_Message(t *testing.T) {
	_, err := ParseSandboxMode("weird")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"weird"`) {
		t.Errorf("error should quote the value: %s", msg)
	}
	for _, want := range []string{"docker", "docker-exec"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention accepted value %q: %s", want, msg)
		}
	}
}
