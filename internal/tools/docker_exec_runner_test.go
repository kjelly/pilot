package tools

import (
	"testing"

	"github.com/anomalyco/pilot/internal/sandbox"
)

func TestParseSandboxMode_Alias(t *testing.T) {
	// Tool-level smoke test: the parse helper accepts the same
	// aliases the previous resolveSandboxMode accepted.
	cases := []struct {
		in   string
		want sandbox.SandboxMode
	}{
		{"", sandbox.SandboxModeDocker},
		{"docker", sandbox.SandboxModeDocker},
		{"DOCKER", sandbox.SandboxModeDocker},
		{"  docker  ", sandbox.SandboxModeDocker},
		{"docker-conn", sandbox.SandboxModeDocker},
		{"docker-connection", sandbox.SandboxModeDocker},
		{"docker-exec", sandbox.SandboxModeDockerExec},
		{"docker_exec", sandbox.SandboxModeDockerExec},
		{"DOCKER-EXEC", sandbox.SandboxModeDockerExec},
		{"exec", sandbox.SandboxModeDockerExec},
	}
	for _, c := range cases {
		got, err := sandbox.ParseSandboxMode(c.in)
		if err != nil {
			t.Errorf("ParseSandboxMode(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSandboxMode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestFindFlagValue(t *testing.T) {
	cases := []struct {
		args  []string
		flag  string
		wantI int
		want  bool
	}{
		{[]string{"play.yml", "-i", "inv.yml"}, "-i", 2, true},
		{[]string{"-i", "inv.yml", "play.yml"}, "-i", 1, true},
		{[]string{"play.yml"}, "-i", -1, false},
		{[]string{"-i"}, "-i", -1, false}, // value missing
		{[]string{"--inventory", "inv.yml"}, "-i", -1, false},
	}
	for _, c := range cases {
		gotI, got := findFlagValue(c.args, c.flag)
		if got != c.want || (got && gotI != c.wantI) {
			t.Errorf("findFlagValue(%v, %q) = (%d, %v), want (%d, %v)",
				c.args, c.flag, gotI, got, c.wantI, c.want)
		}
	}
}

func TestFindExtraVarsFile(t *testing.T) {
	cases := []struct {
		args  []string
		wantI int
		want  bool
	}{
		{[]string{"play.yml", "-e", "@vars.json"}, 2, true},
		{[]string{"play.yml", "-e", "k=v"}, -1, false}, // raw, not file
		{[]string{"play.yml"}, -1, false},
		{[]string{"play.yml", "-e"}, -1, false}, // no value
	}
	for _, c := range cases {
		gotI, got := findExtraVarsFile(c.args)
		if got != c.want || (got && gotI != c.wantI) {
			t.Errorf("findExtraVarsFile(%v) = (%d, %v), want (%d, %v)",
				c.args, gotI, got, c.wantI, c.want)
		}
	}
}

// fakeDockerExec is a test-only stub used by tests that need
// to drive dockerExecRunner.cpInto / execRm without actually
// invoking the docker binary. The current runner always shells
// out to "docker", so this test just covers the helper logic
// (findFlagValue, findExtraVarsFile) which doesn't need docker.
//
// The end-to-end docker-cp / docker-exec paths are exercised
// manually in the sandbox smoke test (see TESTING.md and the
// README's "Sandbox mode (Docker container)" section).
var _ = newDockerExecRunner
