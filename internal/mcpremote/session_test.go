package mcpremote

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeSession struct {
	cfg      *Config
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	served   ServeOptions
	received string
}

// newFakeSession wires a Config whose Serve callback reads the MCP stream
// to EOF, optionally edits the workspace, and answers "pong".
func newFakeSession(t *testing.T, mode, env string, edit func(dir string)) *fakeSession {
	t.Helper()
	fs := &fakeSession{}
	vault := t.TempDir()
	if err := os.WriteFile(filepath.Join(vault, "main.yaml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs.cfg = &Config{
		Mode: mode, Env: env,
		VaultDir: vault, DataDir: t.TempDir(), TmpDir: t.TempDir(),
		PilotRoot: repoRoot(t), ConfigLink: "",
		Stdout: &fs.stdout, Stderr: &fs.stderr,
		GenerateInventory: func(configDir string, _ io.Writer) error {
			// Stand-in for pilot's generator, including a backfill.
			if err := os.WriteFile(filepath.Join(configDir, "inventory.yml"), []byte("all: {}\n"), 0o600); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(configDir, "group_vars", "backfilled.yml"), []byte("filled: true\n"), 0o600)
		},
		Serve: func(_ context.Context, opts ServeOptions) error {
			fs.served = opts
			tr := opts.Transport.(*mcp.IOTransport)
			data, err := io.ReadAll(tr.Reader)
			if err != nil {
				return err
			}
			fs.received = string(data)
			if edit != nil {
				edit(opts.Dir)
			}
			_, err = tr.Writer.Write([]byte("pong\n"))
			return err
		},
	}
	return fs
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sessionFiles(env string) map[string]string {
	return map[string]string{"hosts.yml": hostsFor(env), "group_vars/all.yml": "a: 1\n"}
}

func TestRunSessionObserveServesAfterTheReadyLineAndLeavesNothing(t *testing.T) {
	fs := newFakeSession(t, mcpwire.ModeObserve, "prod", nil)
	fs.cfg.Stdin = bytes.NewReader(append(snapshot(t, "prod", sessionFiles("prod")), "ping\n"...))
	if err := RunSession(context.Background(), fs.cfg); err != nil {
		t.Fatalf("RunSession: %v\nstderr: %s", err, fs.stderr.String())
	}
	line, rest, ok := strings.Cut(fs.stdout.String(), "\n")
	if !ok || rest != "pong\n" {
		t.Fatalf("stdout = %q, want ready line then the MCP reply", fs.stdout.String())
	}
	ready, err := mcpwire.ParseReady(line)
	if err != nil || ready.Mode != mcpwire.ModeObserve || ready.Env != "prod" || ready.Files != 2 {
		t.Fatalf("ready = %+v, %v", ready, err)
	}
	if fs.received != "ping\n" {
		t.Fatalf("server read %q, want only the bytes after the snapshot", fs.received)
	}
	if fs.served.AllowWrite {
		t.Fatal("observe session served with AllowWrite")
	}
	if fs.served.AuditDir != filepath.Join(fs.cfg.DataDir, "mcp", "audit") {
		t.Fatalf("audit dir = %s", fs.served.AuditDir)
	}
	if target, err := os.Readlink(filepath.Join(fs.served.Dir, ".vault")); err == nil {
		t.Fatalf("workspace still exists after the session (vault link → %s)", target)
	}
	if entries, _ := os.ReadDir(fs.cfg.TmpDir); len(entries) != 0 {
		t.Fatalf("observe session left %d entries", len(entries))
	}
	if _, err := os.Stat(filepath.Join(fs.cfg.DataDir, "mcp", "sessions")); !os.IsNotExist(err) {
		t.Fatal("observe session created edit session state")
	}
}

func TestRunSessionBuildsTheWorkspace(t *testing.T) {
	var vaultTarget, contractFile string
	fs := newFakeSession(t, mcpwire.ModeObserve, "prod", func(dir string) {
		vaultTarget, _ = os.Readlink(filepath.Join(dir, ".vault"))
		contractFile = filepath.Join(dir, "contracts", "docker.yaml")
		if _, err := os.Stat(contractFile); err != nil {
			contractFile = ""
		}
	})
	fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", sessionFiles("prod")))
	if err := RunSession(context.Background(), fs.cfg); err != nil {
		t.Fatal(err)
	}
	if vaultTarget != fs.cfg.VaultDir {
		t.Fatalf(".vault → %q, want %q", vaultTarget, fs.cfg.VaultDir)
	}
	if contractFile == "" {
		t.Fatal("the image's contracts were not copied into the workspace")
	}
	if !strings.HasSuffix(fs.served.DiagnoseInventory, "/inventory.yml") {
		t.Fatalf("diagnose inventory = %s", fs.served.DiagnoseInventory)
	}
}

func TestRunSessionFailuresBeforeReadyLeaveNoStdoutAndNoSession(t *testing.T) {
	cases := map[string]struct {
		env   string
		files map[string]string
		code  string
	}{
		"env mismatch":  {"staging", sessionFiles("prod"), mcpwire.CodeEnvMismatch},
		"path scope":    {"prod", map[string]string{"hosts.yml": hostsFor("prod"), "group_vars/x.yml": "k: /pilot/data/x\n"}, mcpwire.CodePathOutOfScope},
		"plain secret":  {"prod", map[string]string{"hosts.yml": hostsFor("prod"), "group_vars/dashboard.yml": "grafana_admin_password: \"hunter2\"\n"}, mcpwire.CodeSecretPolicyViolation},
		"no hosts file": {"prod", map[string]string{"group_vars/all.yml": "a: 1\n"}, mcpwire.CodeSnapshotInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{mcpwire.ModeObserve, mcpwire.ModeEdit} {
				fs := newFakeSession(t, mode, "prod", nil)
				fs.cfg.Stdin = bytes.NewReader(snapshot(t, tc.env, tc.files))
				err := RunSession(context.Background(), fs.cfg)
				if CodeOf(err) != tc.code {
					t.Fatalf("%s: err = %v, want %s", mode, err, tc.code)
				}
				if fs.stdout.Len() != 0 {
					t.Fatalf("%s: stdout = %q, want nothing", mode, fs.stdout.String())
				}
				for _, dir := range []string{fs.cfg.TmpDir, filepath.Join(fs.cfg.DataDir, "mcp", "sessions")} {
					if entries, _ := os.ReadDir(dir); len(entries) != 0 {
						t.Fatalf("%s: %d session entries left in %s", mode, len(entries), dir)
					}
				}
			}
		})
	}
}

func TestRunSessionEditKeepsOnlySessionsWithChangesAndExportsThem(t *testing.T) {
	// No edit: the generator's backfill is not a change, so nothing is kept.
	idle := newFakeSession(t, mcpwire.ModeEdit, "prod", nil)
	idle.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", sessionFiles("prod")))
	if err := RunSession(context.Background(), idle.cfg); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(filepath.Join(idle.cfg.DataDir, "mcp", "sessions")); len(entries) != 0 {
		t.Fatalf("idle edit session kept %d entries", len(entries))
	}

	fs := newFakeSession(t, mcpwire.ModeEdit, "prod", func(dir string) {
		mustWrite(t, filepath.Join(dir, "group_vars", "all.yml"), []byte("a: 2\n"))
		mustWrite(t, filepath.Join(dir, "host_vars", "web-1.yml"), []byte("b: 1\n"))
		mustWrite(t, filepath.Join(dir, "inventory.yml"), []byte("regenerated: true\n"))
	})
	if err := os.MkdirAll(filepath.Join(fs.cfg.TmpDir, "unused"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := sessionFiles("prod")
	files["host_vars/.keep"] = ""
	fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", files))
	if err := RunSession(context.Background(), fs.cfg); err != nil {
		t.Fatal(err)
	}
	if !fs.served.AllowWrite {
		t.Fatal("edit session served without AllowWrite")
	}
	ready, err := mcpwire.ParseReady(strings.SplitN(fs.stdout.String(), "\n", 2)[0])
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cfg := *fs.cfg
	cfg.Stdout = &out
	if err := RunChanges(&cfg, ready.SessionID); err != nil {
		t.Fatalf("RunChanges: %v", err)
	}
	manifest, contents := readChanges(t, out.Bytes())
	got := map[string]string{}
	for _, c := range manifest.Changes {
		got[c.Path] = c.Op
	}
	want := map[string]string{"group_vars/all.yml": mcpwire.OpModify, "host_vars/web-1.yml": mcpwire.OpAdd}
	if len(got) != len(want) || got["group_vars/all.yml"] != want["group_vars/all.yml"] || got["host_vars/web-1.yml"] != want["host_vars/web-1.yml"] {
		t.Fatalf("changes = %v, want %v (backfill and inventory.yml excluded)", got, want)
	}
	if contents["group_vars/all.yml"] != "a: 2\n" {
		t.Fatalf("exported content = %q", contents["group_vars/all.yml"])
	}
	if manifest.BaseCommitSHA == "" || manifest.SessionID != ready.SessionID || manifest.Env != "prod" {
		t.Fatalf("changes manifest = %+v", manifest)
	}

	// Wrong env and unknown ids are refused.
	cfg.Env = "staging"
	if err := RunChanges(&cfg, ready.SessionID); CodeOf(err) != mcpwire.CodeSessionNotFound {
		t.Fatalf("other env: %v", err)
	}
	cfg.Env = "prod"
	if err := RunChanges(&cfg, strings.Repeat("0", 32)); CodeOf(err) != mcpwire.CodeSessionNotFound {
		t.Fatalf("unknown id: %v", err)
	}
	if err := RunChanges(&cfg, "not-an-id"); CodeOf(err) != mcpwire.CodeCommandInvalid {
		t.Fatalf("malformed id: %v", err)
	}
}

func TestRunChangesRejectsSessionInternalPaths(t *testing.T) {
	fs := newFakeSession(t, mcpwire.ModeEdit, "prod", func(dir string) {
		mustWrite(t, filepath.Join(dir, "group_vars", "all.yml"), []byte("roster: /pilot/data/mcp/sessions/x/work/r.yaml\n"))
	})
	fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", sessionFiles("prod")))
	if err := RunSession(context.Background(), fs.cfg); err != nil {
		t.Fatal(err)
	}
	id := mustReadyID(t, fs.stdout.String())
	cfg := *fs.cfg
	cfg.Stdout = io.Discard
	if err := RunChanges(&cfg, id); CodeOf(err) != mcpwire.CodeChangesetInvalid {
		t.Fatalf("err = %v, want CHANGESET_INVALID", err)
	}
}

func mustReadyID(t *testing.T, stdout string) string {
	t.Helper()
	ready, err := mcpwire.ParseReady(strings.SplitN(stdout, "\n", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	return ready.SessionID
}

func readChanges(t *testing.T, data []byte) (mcpwire.ChangesManifest, map[string]string) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	var manifest mcpwire.ChangesManifest
	contents := map[string]string{}
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if hdr.Name != mcpwire.ChangesManifestName {
				t.Fatalf("first entry = %s", hdr.Name)
			}
			if err := json.Unmarshal(body, &manifest); err != nil {
				t.Fatal(err)
			}
			continue
		}
		contents[hdr.Name] = string(body)
	}
	return manifest, contents
}

func TestCollectEditSessions(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	cfg := &Config{DataDir: t.TempDir(), Now: func() time.Time { return now }}
	root := cfg.sessionsRoot()
	mk := func(name string, st *SessionState, mtime time.Time, workFile string) string {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Join(dir, "work"), 0o700); err != nil {
			t.Fatal(err)
		}
		if workFile != "" {
			mustWrite(t, filepath.Join(dir, "work", "hosts.yml"), []byte(workFile))
		}
		if st != nil {
			if err := saveSession(dir, *st); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chtimes(dir, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	id := func(c byte) string { return strings.Repeat(string(c), 32) }
	base := map[string]string{"hosts.yml": mcpwire.SHA256Hex([]byte("orig"))}
	orphan := mk(id('1'), nil, now.Add(-time.Hour), "")
	young := mk(id('2'), nil, now.Add(-time.Minute), "")
	expired := mk(id('3'), &SessionState{ID: id('3'), Mode: "edit", State: stateEnded, CreatedAt: now.Add(-8 * 24 * time.Hour), EndedAt: now.Add(-8 * 24 * time.Hour)}, now, "")
	recent := mk(id('4'), &SessionState{ID: id('4'), Mode: "edit", State: stateEnded, CreatedAt: now.Add(-time.Hour), EndedAt: now.Add(-time.Hour)}, now, "")
	strandedIdle := mk(id('5'), &SessionState{ID: id('5'), Mode: "edit", State: stateServing, CreatedAt: now.Add(-time.Hour), SourceFiles: base, Baseline: base}, now, "orig")
	strandedEdited := mk(id('6'), &SessionState{ID: id('6'), Mode: "edit", State: stateServing, CreatedAt: now.Add(-time.Hour), SourceFiles: base, Baseline: base}, now, "edited")
	held := mk(id('7'), nil, now.Add(-time.Hour), "")
	lock, err := tryLock(filepath.Join(held, ".lock"))
	if err != nil || lock == nil {
		t.Fatalf("lock: %v", err)
	}
	defer lock.Close()
	ancient := mk(id('8'), &SessionState{ID: id('8'), Mode: "edit", State: stateEnded, CreatedAt: now.Add(-31 * 24 * time.Hour), EndedAt: now.Add(-time.Hour)}, now, "")

	CollectEditSessions(cfg)

	exists := func(dir string) bool { _, err := os.Stat(dir); return err == nil }
	for dir, want := range map[string]bool{orphan: false, young: true, expired: false, recent: true, strandedIdle: false, strandedEdited: true, held: true, ancient: false} {
		if exists(dir) != want {
			t.Errorf("%s exists = %v, want %v", filepath.Base(dir), !want, want)
		}
	}
	st, ok, err := loadSession(strandedEdited)
	if err != nil || !ok || st.State != stateEnded || st.EndedAt.IsZero() {
		t.Fatalf("stranded edited session = %+v %v %v, want ended", st, ok, err)
	}
}
