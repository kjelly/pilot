package mcpclient

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// TestMain doubles as a fake ssh: when PILOT_MCP_FAKE_SSH is set, the test
// binary plays the deploy node for the scenario it names.
func TestMain(m *testing.M) {
	if scenario := os.Getenv("PILOT_MCP_FAKE_SSH"); scenario != "" {
		os.Exit(fakeSSH(scenario))
	}
	if os.Getenv("PILOT_MCP_FAKE_DOCKER") != "" {
		os.Exit(fakeDocker())
	}
	if opts := os.Getenv("PILOT_MCP_RUN_CONNECT"); opts != "" {
		os.Exit(runConnectChild(opts))
	}
	os.Exit(m.Run())
}

func fakeSSH(scenario string) int {
	if log := os.Getenv("PILOT_MCP_FAKE_SSH_LOG"); log != "" {
		_ = os.WriteFile(log, []byte(strings.Join(os.Args[1:], "\n")), 0o600)
	}
	switch scenario {
	case "exit255":
		fmt.Fprintln(os.Stderr, "ssh: connect to host deploy port 22: Connection refused")
		return 255
	case "exit125":
		fmt.Fprintln(os.Stderr, "Unable to find image 'pilot-cli:nope' locally")
		return 125
	case "panic":
		fmt.Fprintln(os.Stderr, "panic: boom")
		return 2
	case "changes":
		data, _ := os.ReadFile(os.Getenv("PILOT_MCP_FAKE_CHANGES"))
		_, _ = os.Stdout.Write(data)
		return 0
	case "hang":
		// A remote that never answers and never closes stdout.
		writeFakePID(os.Getpid())
		time.Sleep(time.Minute)
		return 0
	case "hang-child":
		// ssh ends, but a helper it started keeps stdout open.
		child := exec.Command("sleep", "60")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			return 1
		}
		writeFakePID(child.Process.Pid)
		return 0
	case "changes-flood":
		// Keep writing, as a remote with an unbounded export would.
		chunk := make([]byte, 1<<20)
		for {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return 0
			}
		}
	case "version":
		fmt.Printf(`{"protocol":%q,"pilot_binary_sha256":%q}`+"\n", mcpwire.Protocol, strings.Repeat("ab", 32))
		return 0
	}
	br := bufio.NewReader(os.Stdin)
	header, err := br.ReadString('\n')
	if err != nil {
		return 66
	}
	n, err := mcpwire.ParseSnapshotHeader(header)
	if err != nil {
		return 66
	}
	if _, err := io.CopyN(io.Discard, br, n); err != nil {
		return 66
	}
	switch scenario {
	case "reject":
		fmt.Fprint(os.Stderr, mcpwire.ErrorLine(mcpwire.CodeEnvMismatch, "host web-1 has env prod, this session is staging"))
		return 65
	case "noise", "echo", "wrong-mode":
		if scenario == "noise" {
			fmt.Println("Welcome to the deploy node")
		}
		mode := os.Getenv("PILOT_MCP_FAKE_MODE")
		if scenario == "wrong-mode" {
			mode = mcpwire.ModeEdit
		}
		line, _ := mcpwire.FormatReady(mcpwire.Ready{Protocol: mcpwire.Protocol, SessionID: strings.Repeat("c", 32),
			Mode: mode, Env: os.Getenv("PILOT_MCP_FAKE_ENV"), CommitSHA: "fake", Files: 1})
		// Write the ready line and the first MCP reply in one write, so
		// the client must forward bytes it buffered past the ready line.
		fmt.Print(line + "early\n")
		_, _ = io.Copy(os.Stdout, br)
		return 0
	}
	return 66
}

// writeFakePID records a fake ssh process's pid for the test to check.
func writeFakePID(pid int) {
	if path := os.Getenv("PILOT_MCP_FAKE_PID"); path != "" {
		_ = os.WriteFile(path, []byte(strconv.Itoa(pid)), 0o600)
	}
}

// useFakeSSH points sshBinary at the test binary for scenario.
func useFakeSSH(t *testing.T, scenario string, p Profile) string {
	t.Helper()
	prev := sshBinary
	sshBinary = os.Args[0]
	t.Cleanup(func() { sshBinary = prev })
	t.Setenv("PILOT_MCP_FAKE_SSH", scenario)
	t.Setenv("PILOT_MCP_FAKE_MODE", p.Mode)
	t.Setenv("PILOT_MCP_FAKE_ENV", p.Target.Env)
	log := filepath.Join(t.TempDir(), "argv")
	t.Setenv("PILOT_MCP_FAKE_SSH_LOG", log)
	return log
}

// allowLocalRepos enables the local bare-repository test seam.
func allowLocalRepos(t *testing.T) {
	t.Helper()
	allowLocalGitRemote = true
	t.Cleanup(func() { allowLocalGitRemote = false })
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// makeRepo commits files to a new repository and returns a bare clone's
// path (the "remote") and the commit SHA.
func makeRepo(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	work := t.TempDir()
	git(t, work, "init", "--quiet")
	writeTree(t, work, files)
	git(t, work, "add", "-A")
	git(t, work, "commit", "--quiet", "-m", "config")
	bare := filepath.Join(t.TempDir(), "config.git")
	git(t, work, "clone", "--quiet", "--bare", work, bare)
	return bare, git(t, work, "rev-parse", "HEAD")
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func testProfile(url, subdir, mode string) Profile {
	p := Profile{
		Source: SourceConfig{URL: url, Ref: "main", Subdir: subdir},
		Target: TargetConfig{SSHHost: "deploy", Env: "prod", EnvRoot: "/srv/env", Image: "pilot-cli:latest"},
		Mode:   mode,
	}
	p.applyDefaults()
	return p
}
