package mcpremote

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	var vaultTarget, contractFile, specFile string
	fs := newFakeSession(t, mcpwire.ModeObserve, "prod", func(dir string) {
		vaultTarget, _ = os.Readlink(filepath.Join(dir, ".vault"))
		contractFile = filepath.Join(dir, "contracts", "docker.yaml")
		if _, err := os.Stat(contractFile); err != nil {
			contractFile = ""
		}
		specFile = filepath.Join(dir, "docs", "verification", "docker.md")
		if _, err := os.Stat(specFile); err != nil {
			specFile = ""
		}
	})
	fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", sessionFiles("prod")))
	if err := RunSession(context.Background(), fs.cfg); err != nil {
		t.Fatal(err)
	}
	if vaultTarget != fs.cfg.VaultDir {
		t.Fatalf(".vault → %q, want %q", vaultTarget, fs.cfg.VaultDir)
	}
	if contractFile == "" || specFile == "" {
		t.Fatal("the image's contracts and verification specs were not copied into the workspace")
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

// An exported change is committed to the config repository and becomes
// the next session's snapshot, so `changes` refuses anything that snapshot
// would be refused for, and keeps the session so it can say why.
func TestRunChangesRejectsWhatTheNextSnapshotWouldReject(t *testing.T) {
	big := bytes.Repeat([]byte("x"), mcpwire.MaxFileBytes+1)
	cases := map[string]struct {
		file string
		data []byte
		want string
	}{
		"vault path":   {"group_vars/all.yml", []byte("roster: /pilot/vault/ipa-identity.yaml\n"), "/pilot/vault"},
		"data path":    {"host_vars/web-1.yml", []byte("x: /pilot/data/./x\n"), "/pilot/data"},
		"invalid yaml": {"group_vars/all.yml", []byte("a: [\n"), "not valid YAML"},
		"too large":    {"files/blob.bin", big, "larger than"},
		// An added host without env is a sandbox host in a prod config.
		"host env":     {"hosts.yml", []byte(hostsFor("prod") + "  web-2:\n    ansible_host: \"192.0.2.11\"\n    roles: [docker]\n"), "ENV_MISMATCH"},
		"case only":    {"group_vars/ALL.yml", []byte("b: 1\n"), "differ only in case"},
		"ignorable":    {"group_vars/a\u200cll.yml", []byte("b: 1\n"), "differ only in case"},
		"plain secret": {"group_vars/dashboard.yml", []byte("grafana_admin_password: \"hunter2\"\n"), "SECRET_POLICY_VIOLATION"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fs := newFakeSession(t, mcpwire.ModeEdit, "prod", func(dir string) {
				if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(tc.file)), 0o700); err != nil {
					t.Fatal(err)
				}
				mustWrite(t, filepath.Join(dir, tc.file), tc.data)
			})
			fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", sessionFiles("prod")))
			if err := RunSession(context.Background(), fs.cfg); err != nil {
				t.Fatal(err)
			}
			id := mustReadyID(t, fs.stdout.String())
			cfg := *fs.cfg
			var out bytes.Buffer
			cfg.Stdout = &out
			err := RunChanges(&cfg, id)
			if CodeOf(err) != mcpwire.CodeChangesetInvalid || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want CHANGESET_INVALID mentioning %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Fatalf("wrote %d bytes of changes", out.Len())
			}
			if st, ok, err := loadSession(filepath.Join(cfg.sessionsRoot(), id)); err != nil || !ok || st.State != stateEnded {
				t.Fatalf("session = %+v %v %v, want kept as ended", st, ok, err)
			}
		})
	}
}

// Every check runs on the whole next snapshot: a base that already fails
// (an image upgraded since the session started now flags a file the edit
// did not touch) refuses the export too, and never hides a failure the
// changes add.
func TestRunChangesRefusesWhenTheBaseAlreadyFails(t *testing.T) {
	run := func(t *testing.T, breakBase func(source string), edit func(work string)) error {
		fs := newFakeSession(t, mcpwire.ModeEdit, "prod", func(work string) {
			breakBase(filepath.Join(filepath.Dir(work), "source"))
			edit(work)
		})
		fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", sessionFiles("prod")))
		if err := RunSession(context.Background(), fs.cfg); err != nil {
			t.Fatal(err)
		}
		id := mustReadyID(t, fs.stdout.String())
		cfg := *fs.cfg
		cfg.Stdout = io.Discard
		return RunChanges(&cfg, id)
	}
	addHostVars := func(work string) {
		if err := os.MkdirAll(filepath.Join(work, "host_vars"), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(work, "host_vars", "web-1.yml"), []byte("b: 1\n"))
	}
	secret := []byte("grafana_admin_password: \"hunter2\"\n")
	cases := map[string]struct {
		breakBase func(source string)
		edit      func(work string)
		want      string
	}{
		"base secret, harmless edit": {
			func(source string) { mustWrite(t, filepath.Join(source, "group_vars", "all.yml"), secret) },
			addHostVars, "SECRET_POLICY_VIOLATION"},
		"base env, added secret": {
			func(source string) { mustWrite(t, filepath.Join(source, "hosts.yml"), []byte(hostsFor("staging"))) },
			func(work string) { mustWrite(t, filepath.Join(work, "group_vars", "dashboard.yml"), secret) }, "ENV_MISMATCH"},
		"base too large, added secret": {
			func(source string) {
				mustWrite(t, filepath.Join(source, "group_vars", "all.yml"), bytes.Repeat([]byte("#"), mcpwire.MaxFileBytes+1))
			},
			func(work string) { mustWrite(t, filepath.Join(work, "group_vars", "dashboard.yml"), secret) }, "SNAPSHOT_TOO_LARGE"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := run(t, tc.breakBase, tc.edit); CodeOf(err) != mcpwire.CodeChangesetInvalid || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want CHANGESET_INVALID for %s", err, tc.want)
			}
		})
	}
}

// A tracked inventory.yml is regenerated in the workspace and never
// exported; deleting it must not break the export of the real changes.
func TestRunChangesWithATrackedInventoryDeleted(t *testing.T) {
	fs := newFakeSession(t, mcpwire.ModeEdit, "prod", func(work string) {
		if err := os.Remove(filepath.Join(work, "inventory.yml")); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(work, "group_vars", "all.yml"), []byte("a: 2\n"))
	})
	files := sessionFiles("prod")
	files["inventory.yml"] = "all: {}\n"
	fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", files))
	if err := RunSession(context.Background(), fs.cfg); err != nil {
		t.Fatal(err)
	}
	id := mustReadyID(t, fs.stdout.String())
	cfg := *fs.cfg
	var out bytes.Buffer
	cfg.Stdout = &out
	if err := RunChanges(&cfg, id); err != nil {
		t.Fatalf("RunChanges: %v", err)
	}
	manifest, _ := readChanges(t, out.Bytes())
	if len(manifest.Changes) != 1 || manifest.Changes[0].Path != "group_vars/all.yml" {
		t.Fatalf("changes = %+v, want only group_vars/all.yml", manifest.Changes)
	}
}

// A session whose changes cannot be computed is kept as ended, so
// `changes` reports the error instead of "has not ended".
func TestEditSessionWithUncomputableChangesIsKeptAsEnded(t *testing.T) {
	fs := newFakeSession(t, mcpwire.ModeEdit, "prod", func(work string) {
		mustWrite(t, filepath.Join(work, "group_vars", "all.yml"), []byte("a: 2\n"))
		if err := os.Remove(filepath.Join(filepath.Dir(work), "source", "hosts.yml")); err != nil {
			t.Fatal(err)
		}
	})
	fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", sessionFiles("prod")))
	if err := RunSession(context.Background(), fs.cfg); err != nil {
		t.Fatal(err)
	}
	id := mustReadyID(t, fs.stdout.String())
	if st, ok, err := loadSession(filepath.Join(fs.cfg.sessionsRoot(), id)); err != nil || !ok || st.State != stateEnded {
		t.Fatalf("session = %+v %v %v, want kept as ended", st, ok, err)
	}
	cfg := *fs.cfg
	cfg.Stdout = io.Discard
	if err := RunChanges(&cfg, id); err == nil || CodeOf(err) != mcpwire.CodeRuntimeError || !strings.Contains(err.Error(), "read source hosts.yml") {
		t.Fatalf("RunChanges: %v, want the RUNTIME_ERROR that stops the export", err)
	}
}

// The changes stream is held to what the client reads.
func TestEncodeChangesLimits(t *testing.T) {
	state := SessionState{ID: strings.Repeat("a", 32), Env: "prod", Source: mcpwire.Source{CommitSHA: strings.Repeat("b", 40)}}
	var many []mcpwire.Change
	for i := range 4000 {
		many = append(many, mcpwire.Change{Path: fmt.Sprintf("d/%0200d.yml", i), Op: mcpwire.OpDelete, BaseSHA256: strings.Repeat("c", 64)})
	}
	if _, err := encodeChanges(state, many, nil); CodeOf(err) != mcpwire.CodeChangesetInvalid || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("large manifest: %v", err)
	}
	var tooMany []mcpwire.Change
	for i := range mcpwire.MaxFiles + 1 {
		tooMany = append(tooMany, mcpwire.Change{Path: fmt.Sprintf("d/%d", i), Op: mcpwire.OpDelete})
	}
	if _, err := encodeChanges(state, tooMany, nil); CodeOf(err) != mcpwire.CodeChangesetInvalid || !strings.Contains(err.Error(), "changes, more than") {
		t.Fatalf("too many changes: %v", err)
	}
}

// The audit directory is the last thing a session needs; failing to create
// it is a startup failure, reported before the ready line.
func TestRunSessionAuditDirFailureIsReportedBeforeReady(t *testing.T) {
	for _, mode := range []string{mcpwire.ModeObserve, mcpwire.ModeEdit} {
		fs := newFakeSession(t, mode, "prod", nil)
		if err := os.MkdirAll(filepath.Join(fs.cfg.DataDir, mcpwire.DataMCPDir), 0o700); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, fs.cfg.auditDir(), []byte("not a directory"))
		fs.cfg.Stdin = bytes.NewReader(snapshot(t, "prod", sessionFiles("prod")))
		err := RunSession(context.Background(), fs.cfg)
		if err == nil || CodeOf(err) != mcpwire.CodeRuntimeError || !strings.Contains(err.Error(), "audit directory") {
			t.Fatalf("%s: err = %v, want RUNTIME_ERROR about the audit directory", mode, err)
		}
		if fs.stdout.Len() != 0 {
			t.Fatalf("%s: stdout = %q, want no ready line", mode, fs.stdout.String())
		}
		for _, dir := range []string{fs.cfg.TmpDir, fs.cfg.sessionsRoot()} {
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("%s: %d session entries left in %s", mode, len(entries), dir)
			}
		}
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
	// A young directory without session.json may belong to a session that
	// has not locked it yet; collection must not take its lock.
	if _, err := os.Lstat(filepath.Join(young, ".lock")); !os.IsNotExist(err) {
		t.Errorf("collection created a lock in the young session directory: %v", err)
	}
	st, ok, err := loadSession(strandedEdited)
	if err != nil || !ok || st.State != stateEnded || st.EndedAt.IsZero() {
		t.Fatalf("stranded edited session = %+v %v %v, want ended", st, ok, err)
	}
}
