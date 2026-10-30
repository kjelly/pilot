package mcpremote

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
	"github.com/kjelly/pilot/internal/statefile"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session states recorded for edit sessions.
const (
	stateServing = "serving"
	stateEnded   = "ended"
)

// SessionState is an edit session's session.json.
type SessionState struct {
	ID                string            `json:"id"`
	Mode              string            `json:"mode"`
	Env               string            `json:"env"`
	State             string            `json:"state"`
	CreatedAt         time.Time         `json:"created_at"`
	EndedAt           time.Time         `json:"ended_at,omitempty"`
	Source            mcpwire.Source    `json:"source"`
	ClientUser        string            `json:"client_user"`
	ContentDigest     string            `json:"content_digest"`
	SourceFiles       map[string]string `json:"source_files"`
	Baseline          map[string]string `json:"baseline"`
	PilotBinarySHA256 string            `json:"pilot_binary_sha256"`
}

func sessionStore(dir string) (*statefile.Store[SessionState], error) {
	return statefile.New[SessionState](dir, "session.json", 1, "mcp session")
}

func loadSession(dir string) (SessionState, bool, error) {
	store, err := sessionStore(dir)
	if err != nil {
		return SessionState{}, false, err
	}
	states, err := store.Load()
	if err != nil {
		return SessionState{}, false, err
	}
	if len(states) != 1 {
		return SessionState{}, false, nil
	}
	return states[0], true, nil
}

func saveSession(dir string, st SessionState) error {
	store, err := sessionStore(dir)
	if err != nil {
		return err
	}
	return store.Save([]SessionState{st})
}

// RunSession is `pilot mcp remote session`: read and validate the
// snapshot, build the workspace, print the ready line, then serve MCP on
// the rest of stdin/stdout until the client disconnects.
func RunSession(ctx context.Context, cfg *Config) error {
	if !mcpwire.ValidMode(cfg.Mode) {
		return errorf(mcpwire.CodeCommandInvalid, "invalid --mode %q", cfg.Mode)
	}
	if !mcpwire.ValidEnv(cfg.Env) {
		return errorf(mcpwire.CodeCommandInvalid, "invalid --env %q", cfg.Env)
	}
	id, err := newSessionID()
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "session id: %v", err)
	}
	parent := cfg.TmpDir
	if cfg.Mode == mcpwire.ModeEdit {
		parent = cfg.sessionsRoot()
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "create %s: %v", parent, err)
	}
	dir := filepath.Join(parent, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "create session directory: %v", err)
	}
	lock, err := tryLock(filepath.Join(dir, ".lock"))
	if err != nil || lock == nil {
		os.RemoveAll(dir)
		if err == nil {
			err = errors.New("another process holds its lock")
		}
		return errorf(mcpwire.CodeRuntimeError, "lock session directory: %v", err)
	}
	defer lock.Close()
	if cfg.Mode == mcpwire.ModeEdit {
		CollectEditSessions(cfg)
	}

	ready := false
	defer func() {
		if !ready {
			os.RemoveAll(dir)
		}
	}()

	br := bufio.NewReaderSize(cfg.Stdin, 64<<10)
	source := filepath.Join(dir, "source")
	manifest, err := ReadSnapshot(br, source, cfg.Env)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(manifest.Files))
	sourceFiles := make(map[string]string, len(manifest.Files))
	for _, f := range manifest.Files {
		paths = append(paths, f.Path)
		sourceFiles[f.Path] = f.SHA256
	}
	sort.Strings(paths)
	if err := checkSnapshotContent(cfg, source, cfg.Env, paths); err != nil {
		return err
	}

	work := filepath.Join(dir, "work")
	configDir, err := buildWorkspace(cfg, source, work)
	if err != nil {
		return err
	}
	if err := cfg.GenerateInventory(configDir, cfg.Stderr); err != nil {
		return errorf(mcpwire.CodeWorkspaceInvalid, "generate inventory: %v", err)
	}

	binarySum, err := BinarySHA256()
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "hash pilot binary: %v", err)
	}
	state := SessionState{
		ID: id, Mode: cfg.Mode, Env: cfg.Env, State: stateServing, CreatedAt: cfg.now().UTC(),
		Source: manifest.Source, ClientUser: manifest.ClientUser, ContentDigest: manifest.ContentDigest,
		SourceFiles: sourceFiles, PilotBinarySHA256: binarySum,
	}
	if cfg.Mode == mcpwire.ModeEdit {
		baseline, err := hashTree(work)
		if err != nil {
			return errorf(mcpwire.CodeRuntimeError, "record baseline: %v", err)
		}
		state.Baseline = baseline
		if err := saveSession(dir, state); err != nil {
			return errorf(mcpwire.CodeRuntimeError, "save session: %v", err)
		}
	}

	// Everything that can still fail at startup happens before the ready
	// line, so the client sees a startup failure, not a session that ends.
	if err := os.MkdirAll(cfg.auditDir(), 0o700); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "create audit directory: %v", err)
	}

	line, err := mcpwire.FormatReady(mcpwire.Ready{
		Protocol: mcpwire.Protocol, SessionID: id, Mode: cfg.Mode, Env: cfg.Env,
		CommitSHA: manifest.Source.CommitSHA, ContentDigest: manifest.ContentDigest,
		Files: len(manifest.Files), PilotBinarySHA256: binarySum,
	})
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "ready line: %v", err)
	}
	if _, err := io.WriteString(cfg.Stdout, line); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "write ready line: %v", err)
	}
	ready = true
	fmt.Fprintf(cfg.Stderr, "pilot mcp remote: session %s ready (%s, %s, commit %s)\n", id, cfg.Mode, cfg.Env, manifest.Source.CommitSHA)

	serveCtx := ctx
	if cfg.MaxSessionDuration > 0 {
		var cancel context.CancelFunc
		serveCtx, cancel = context.WithTimeout(ctx, cfg.MaxSessionDuration)
		defer cancel()
	}
	serveErr := cfg.Serve(serveCtx, ServeOptions{
		Dir:               configDir,
		AuditDir:          cfg.auditDir(),
		DiagnoseInventory: filepath.Join(configDir, "inventory.yml"),
		AllowWrite:        cfg.Mode == mcpwire.ModeEdit,
		Transport:         &mcp.IOTransport{Reader: io.NopCloser(br), Writer: nopWriteCloser{cfg.Stdout}},
	})
	finishSession(cfg, dir, state)
	if serveErr != nil && !errors.Is(serveErr, io.EOF) && !errors.Is(serveErr, context.Canceled) {
		if errors.Is(serveErr, context.DeadlineExceeded) {
			fmt.Fprintf(cfg.Stderr, "pilot mcp remote: session %s reached --max-session-duration\n", id)
			return nil
		}
		return errorf(mcpwire.CodeRuntimeError, "serve: %v", serveErr)
	}
	return nil
}

// checkSnapshotContent runs the checks on a snapshot's files once they are
// on disk (§6.2): every host's env, the path scope and the secret policy.
// `changes` runs the same checks on the next snapshot (computeChanges).
func checkSnapshotContent(cfg *Config, root, env string, paths []string) error {
	if err := CheckHostsEnv(root, env); err != nil {
		return err
	}
	if err := CheckPathScope(root, paths); err != nil {
		return err
	}
	return CheckSecretPolicy(cfg.PilotRoot, root)
}

// finishSession removes an observe session, and an edit session with
// nothing to export; an edit session with changes is kept as ended.
func finishSession(cfg *Config, dir string, state SessionState) {
	if cfg.Mode != mcpwire.ModeEdit {
		os.RemoveAll(dir)
		return
	}
	if err := endEditSession(cfg, dir, state); err != nil {
		slog.Warn("mcp remote: finish edit session", "session", state.ID, "err", err)
	}
}

// endEditSession deletes dir when the work tree has no exportable change
// against the baseline; otherwise it records the session as ended.
func endEditSession(cfg *Config, dir string, state SessionState) error {
	changes, _, err := computeChanges(cfg, dir, state)
	switch {
	case CodeOf(err) == mcpwire.CodeChangesetInvalid:
		// There are changes, but they cannot be exported; keep the session
		// so `changes` reports why instead of the edit silently vanishing.
	case err != nil:
		return err
	case len(changes) == 0:
		return os.RemoveAll(dir)
	}
	state.State = stateEnded
	state.EndedAt = cfg.now().UTC()
	return saveSession(dir, state)
}
