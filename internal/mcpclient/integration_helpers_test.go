package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// fakeDocker stands in for docker on the test "deploy node" (spec §13.2):
// it maps the --mount sources pilot-mcp chose onto pilot mcp remote's
// test flags and execs the real pilot binary, so the remote side runs for
// real without containers. It records every invocation's argv.
func fakeDocker() int {
	args := os.Args[1:]
	if log := os.Getenv("PILOT_MCP_FAKE_DOCKER_LOG"); log != "" {
		if f, err := os.OpenFile(log, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
			data, _ := json.Marshal(args)
			_, _ = f.Write(append(data, '\n'))
			f.Close()
		}
	}
	if len(args) == 0 || args[0] != "run" {
		fmt.Fprintln(os.Stderr, "fake docker: only run is supported")
		return 125
	}
	withValue := map[string]bool{"--pull": true, "--log-driver": true, "--cap-drop": true, "--cap-add": true, "--security-opt": true, "--network": true, "--mount": true, "--entrypoint": true}
	mounts := map[string]string{}
	i := 1
	for ; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			break
		}
		if withValue[a] {
			i++
			if a == "--mount" {
				var source, target string
				for _, kv := range strings.Split(args[i], ",") {
					k, v, _ := strings.Cut(kv, "=")
					switch k {
					case "source":
						source = v
					case "target":
						target = v
					}
				}
				if _, err := os.Stat(source); err != nil {
					fmt.Fprintf(os.Stderr, "docker: invalid mount source %s\n", source)
					return 125
				}
				mounts[target] = source
			}
		}
	}
	if i+1 >= len(args) {
		return 125
	}
	command := args[i+1:] // drop the image
	pilotArgs := []string{os.Getenv("PILOT_MCP_FAKE_DOCKER_PILOT")}
	if d, ok := mounts[mcpwire.ContainerDataDir]; ok {
		pilotArgs = append(pilotArgs, "--data-dir", d)
	}
	pilotArgs = append(pilotArgs, command...)
	if len(command) > 2 && (command[2] == "session" || command[2] == "changes") {
		pilotArgs = append(pilotArgs, "--tmp-dir", os.Getenv("PILOT_MCP_FAKE_DOCKER_TMP"),
			"--pilot-root", os.Getenv("PILOT_MCP_FAKE_DOCKER_ROOT"), "--config-link", "")
		if v, ok := mounts[mcpwire.ContainerVaultDir]; ok {
			pilotArgs = append(pilotArgs, "--vault-dir", v)
		}
	}
	if os.Getenv("PILOT_MCP_FAKE_DOCKER_NOISE") == "1" {
		fmt.Println("Last login: from the fake login shell")
	}
	if pidfile := os.Getenv("PILOT_MCP_FAKE_DOCKER_PIDFILE"); pidfile != "" && len(command) > 2 && command[2] == "session" {
		_ = os.WriteFile(pidfile, []byte(strconv.Itoa(os.Getpid())), 0o600)
	}
	if err := syscall.Exec(pilotArgs[0], pilotArgs, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "fake docker:", err)
		return 126
	}
	return 0
}

// runConnectChild runs Connect in its own process so a test can SIGKILL it.
func runConnectChild(encoded string) int {
	var o Options
	if err := json.Unmarshal([]byte(encoded), &o); err != nil {
		return 2
	}
	allowLocalGitRemote = true
	o.Stdin, o.Stdout, o.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := Connect(context.Background(), &o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitCodeOf(err)
	}
	return 0
}

// requireSSHD skips without an sshd; PILOT_REQUIRE_SSHD_TESTS=1 (CI) turns
// the skip into a failure. Root also skips: the read-only .vault is
// simulated with file modes, which root ignores.
func requireSSHD(t *testing.T) string {
	t.Helper()
	fail := func(msg string) {
		if os.Getenv("PILOT_REQUIRE_SSHD_TESTS") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	if testing.Short() {
		fail("integration test")
	}
	path, err := exec.LookPath("sshd")
	if err != nil {
		if _, statErr := os.Stat("/usr/sbin/sshd"); statErr != nil {
			fail("sshd not installed")
		}
		path = "/usr/sbin/sshd"
	}
	if os.Geteuid() == 0 {
		fail("running as root: the read-only .vault simulation needs a non-root user")
	}
	return path
}

var (
	pilotOnce sync.Once
	pilotPath string
	pilotErr  error
)

func repoRootDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// buildPilot builds cmd/pilot once for the remote side.
func buildPilot(t *testing.T) string {
	t.Helper()
	pilotOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pilot-mcp-it")
		if err != nil {
			pilotErr = err
			return
		}
		pilotPath = filepath.Join(dir, "pilot")
		cmd := exec.Command("go", "build", "-o", pilotPath, "./cmd/pilot")
		cmd.Dir = repoRootDir(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			pilotErr = fmt.Errorf("build pilot: %v\n%s", err, out)
		}
	})
	if pilotErr != nil {
		t.Fatal(pilotErr)
	}
	return pilotPath
}

// deployNode is a test sshd on 127.0.0.1 plus the fake docker behind it.
type deployNode struct {
	sshConfig string
	host      string
	docker    string // the fake docker wrapper
	envRoot   string
	dockerLog string
	pidFile   string
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func startDeployNode(t *testing.T, noise bool) *deployNode {
	t.Helper()
	sshd := requireSSHD(t)
	pilot := buildPilot(t)
	dir := t.TempDir()
	keygen := func(name string) {
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, name)).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v\n%s", err, out)
		}
	}
	keygen("host_key")
	keygen("client_key")
	pub, err := os.ReadFile(filepath.Join(dir, "client_key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), append([]byte("restrict "), pub...), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	cfg := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nLogLevel ERROR\n",
		port, filepath.Join(dir, "host_key"), filepath.Join(dir, "sshd.pid"), filepath.Join(dir, "authorized_keys"))
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sshd, "-D", "-e", "-f", filepath.Join(dir, "sshd_config"))
	// A file, not a pipe: session processes inherit sshd's stderr, and
	// Wait on a pipe would block until every one of them exits.
	logFile, err := os.Create(filepath.Join(dir, "sshd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(filepath.Join(dir, "sshd.log"))
			t.Fatalf("sshd did not start: %s", log)
		}
		time.Sleep(50 * time.Millisecond)
	}

	hostPub, err := os.ReadFile(filepath.Join(dir, "host_key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(hostPub))
	known := fmt.Sprintf("[127.0.0.1]:%d %s %s\n", port, fields[0], fields[1])
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(known), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	node := &deployNode{host: "test-deploy", envRoot: filepath.Join(dir, "env"), dockerLog: filepath.Join(dir, "docker.log"), pidFile: filepath.Join(dir, "remote.pid")}
	node.sshConfig = filepath.Join(dir, "ssh_config")
	sshCfg := fmt.Sprintf("Host test-deploy\n  HostName 127.0.0.1\n  Port %d\n  User %s\n  IdentityFile %s\n  IdentitiesOnly yes\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile /dev/null\n",
		port, u.Username, filepath.Join(dir, "client_key"), filepath.Join(dir, "known_hosts"))
	if err := os.WriteFile(node.sshConfig, []byte(sshCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	noiseFlag := "0"
	if noise {
		noiseFlag = "1"
	}
	tmp := filepath.Join(dir, "container-tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	node.docker = filepath.Join(dir, "docker")
	script := "#!/bin/sh\n" + strings.Join([]string{
		"PILOT_MCP_FAKE_DOCKER=1",
		"PILOT_MCP_FAKE_DOCKER_PILOT=" + shellQuote(pilot),
		"PILOT_MCP_FAKE_DOCKER_ROOT=" + shellQuote(repoRootDir(t)),
		"PILOT_MCP_FAKE_DOCKER_TMP=" + shellQuote(tmp),
		"PILOT_MCP_FAKE_DOCKER_LOG=" + shellQuote(node.dockerLog),
		"PILOT_MCP_FAKE_DOCKER_PIDFILE=" + shellQuote(node.pidFile),
		"PILOT_MCP_FAKE_DOCKER_NOISE=" + noiseFlag,
		"PATH=" + shellQuote(os.Getenv("PATH")),
		"export PILOT_MCP_FAKE_DOCKER PILOT_MCP_FAKE_DOCKER_PILOT PILOT_MCP_FAKE_DOCKER_ROOT PILOT_MCP_FAKE_DOCKER_TMP PILOT_MCP_FAKE_DOCKER_LOG PILOT_MCP_FAKE_DOCKER_PIDFILE PILOT_MCP_FAKE_DOCKER_NOISE PATH",
		"exec " + shellQuote(os.Args[0]) + ` "$@"`,
	}, "\n") + "\n"
	if err := os.WriteFile(node.docker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, env := range []string{"prod", "staging"} {
		vault := filepath.Join(node.envRoot, env, ".vault")
		if err := os.MkdirAll(vault, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(node.envRoot, env, ".pilot-data"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vault, "main.yaml"), []byte("vault_token: not-a-real-secret\n"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(vault, 0o500); err != nil { // read-only, as the mount is
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(vault, 0o700) })
	}
	return node
}

// profileFor points a profile at the test deploy node.
func (n *deployNode) profileFor(repoURL, subdir, mode, env string) Profile {
	p := testProfile(repoURL, subdir, mode)
	p.Target.SSHHost = n.host
	p.Target.SSHConfig = n.sshConfig
	p.Target.EnvRoot = n.envRoot
	p.Target.Docker = n.docker
	p.Target.Env = env
	p.Target.Image = "pilot-cli:test"
	p.Timeouts.StartupSeconds = 120
	return p
}

// dockerInvocations returns the argv of every fake docker run.
func (n *deployNode) dockerInvocations(t *testing.T) [][]string {
	t.Helper()
	data, err := os.ReadFile(n.dockerLog)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var argv []string
		if err := json.Unmarshal([]byte(line), &argv); err != nil {
			t.Fatal(err)
		}
		out = append(out, argv)
	}
	return out
}
