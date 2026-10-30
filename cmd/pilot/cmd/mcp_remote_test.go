package cmd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/mcpremote"
	"github.com/kjelly/pilot/internal/mcpwire"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRemoteServeOptionsMatchTheWireToolLists is the AGENTS.md §5.7
// consistency check between remoteServeOptions (which flags a remote
// session gets) and mcpwire's tool lists (what pilot-mcp doctor asserts):
// both modes are built through the real newMCPServer and listed.
func TestRemoteServeOptionsMatchTheWireToolLists(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	for _, mode := range []string{mcpwire.ModeObserve, mcpwire.ModeEdit} {
		dir := t.TempDir()
		opts := remoteServeOptions(mcpremote.ServeOptions{
			Dir: dir, AuditDir: t.TempDir(), DiagnoseInventory: filepath.Join(dir, "inventory.yml"),
			AllowWrite: mode == mcpwire.ModeEdit,
		})
		names := serveMCPToolNames(t, opts)
		if err := mcpwire.CheckTools(mode, names); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRemoteServeOptionsNeverEnableRawActiveOrRepair(t *testing.T) {
	for _, allowWrite := range []bool{false, true} {
		o := remoteServeOptions(mcpremote.ServeOptions{AllowWrite: allowWrite})
		if o.EnableDiagnoseRaw || o.EnableDiagnoseActive || o.EnableRepair || !o.EnableDiagnose || o.AllowWrite != allowWrite {
			t.Fatalf("remoteServeOptions(%v) = %+v", allowWrite, o)
		}
	}
}

// remoteTestSnapshot frames files as the snapshot pilot-mcp sends.
func remoteTestSnapshot(t *testing.T, env string, files map[string]string) []byte {
	t.Helper()
	m := mcpwire.Manifest{Protocol: mcpwire.Protocol, Env: env, ClientVersion: "test",
		Source: mcpwire.Source{URL: "https://example.invalid/org/config", Ref: "main", CommitSHA: strings.Repeat("ab", 20), Subdir: "."}}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		m.Files = append(m.Files, mcpwire.FileEntry{Path: p, Size: int64(len(files[p])), SHA256: mcpwire.SHA256Hex([]byte(files[p]))})
	}
	digest, err := mcpwire.ContentDigest(m.Files)
	if err != nil {
		t.Fatal(err)
	}
	m.ContentDigest = digest
	mdata, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write(mcpwire.ManifestName, mdata)
	for _, p := range paths {
		write(p, []byte(files[p]))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(mcpwire.SnapshotHeader(int64(buf.Len()))), buf.Bytes()...)
}

const remoteTestHosts = "vars:\n  ansible_ssh_private_key_file: \"/pilot/config/.vault/id_ed25519\"\nhosts:\n  web-1:\n    ansible_host: \"192.0.2.10\"\n    roles: [docker]\n    env: prod\n"

type remoteProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *bytes.Buffer
	data   string
}

// startRemote runs the real `pilot mcp remote session` binary the way the
// container would, with the container paths pointed at temp directories.
func startRemote(t *testing.T, mode, env string) *remoteProc {
	t.Helper()
	binary := buildPilotBinary(t)
	vault := t.TempDir()
	data := t.TempDir()
	cmd := exec.Command(binary, "--data-dir", data, "mcp", "remote", "session",
		"--protocol", mcpwire.ProtocolFlag, "--mode", mode, "--env", env,
		"--vault-dir", vault, "--tmp-dir", t.TempDir(), "--pilot-root", repoRootForTest(t), "--config-link", "")
	cmd.Env = hostToolEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &remoteProc{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: &bytes.Buffer{}, data: data}
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = cmd.Process.Kill()
		cmd.Wait() //nolint:errcheck
	})
	return p
}

type pipeReadCloser struct{ *bufio.Reader }

func (pipeReadCloser) Close() error { return nil }

func TestMCPRemoteSessionServesTheRealMCPServerAfterTheSnapshot(t *testing.T) {
	for _, mode := range []string{mcpwire.ModeObserve, mcpwire.ModeEdit} {
		t.Run(mode, func(t *testing.T) {
			p := startRemote(t, mode, "prod")
			snap := remoteTestSnapshot(t, "prod", map[string]string{"hosts.yml": remoteTestHosts, "group_vars/all.yml": "a: 1\n"})
			if _, err := p.stdin.Write(snap); err != nil {
				t.Fatal(err)
			}
			line, err := p.stdout.ReadString('\n')
			if err != nil {
				t.Fatalf("read ready line: %v\nstderr: %s", err, p.stderr.String())
			}
			ready, err := mcpwire.ParseReady(line)
			if err != nil || ready.Mode != mode || ready.Env != "prod" {
				t.Fatalf("ready = %+v, %v (line %q)", ready, err, line)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			client := mcp.NewClient(&mcp.Implementation{Name: "remote-test", Version: "1"}, nil)
			session, err := client.Connect(ctx, &mcp.IOTransport{Reader: pipeReadCloser{p.stdout}, Writer: p.stdin}, nil)
			if err != nil {
				t.Fatalf("connect: %v\nstderr: %s", err, p.stderr.String())
			}
			result, err := session.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			names := map[string]bool{}
			for _, tool := range result.Tools {
				names[tool.Name] = true
			}
			if err := mcpwire.CheckTools(mode, names); err != nil {
				t.Fatal(err)
			}
			session.Close() //nolint:errcheck
			if err := p.cmd.Wait(); err != nil {
				t.Fatalf("remote exit: %v\nstderr: %s", err, p.stderr.String())
			}
			if _, err := os.Stat(filepath.Join(p.data, "mcp", "audit")); err != nil {
				t.Fatalf("audit dir under the data dir: %v", err)
			}
		})
	}
}

func TestMCPRemoteFailuresPrintOneCodeLineAndExitWithItsCode(t *testing.T) {
	binary := buildPilotBinary(t)
	cases := []struct {
		name  string
		args  []string
		stdin []byte
		code  string
		exit  int
	}{
		{"unsupported protocol", []string{"session", "--protocol", "v9", "--mode", "observe", "--env", "prod"}, nil, mcpwire.CodeProtocolUnsupported, 64},
		{"unknown flag", []string{"session", "--enable-repair"}, nil, mcpwire.CodeCommandInvalid, 64},
		{"bad env", []string{"session", "--protocol", "v1", "--mode", "observe", "--env", "production"}, nil, mcpwire.CodeCommandInvalid, 64},
		{"env mismatch", []string{"session", "--protocol", "v1", "--mode", "observe", "--env", "staging"},
			remoteTestSnapshot(t, "prod", map[string]string{"hosts.yml": remoteTestHosts}), mcpwire.CodeEnvMismatch, 65},
		{"changes bad id", []string{"changes", "--protocol", "v1", "--env", "prod", "nope"}, nil, mcpwire.CodeCommandInvalid, 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--data-dir", t.TempDir(), "mcp", "remote"}, tc.args...)
			if tc.args[0] == "session" && tc.code != mcpwire.CodeCommandInvalid {
				args = append(args, "--tmp-dir", t.TempDir(), "--pilot-root", repoRootForTest(t), "--config-link", "", "--vault-dir", t.TempDir())
			}
			cmd := exec.Command(binary, args...)
			cmd.Env = hostToolEnv()
			cmd.Stdin = bytes.NewReader(tc.stdin)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != tc.exit {
				t.Fatalf("exit = %v, want %d\nstderr: %s", err, tc.exit, stderr.String())
			}
			code, _, ok := mcpwire.ParseErrorLine(stderr.String())
			if !ok || code != tc.code {
				t.Fatalf("error line code = %q (%v), want %s\nstderr: %s", code, ok, tc.code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want nothing on failure", stdout.String())
			}
		})
	}
}
