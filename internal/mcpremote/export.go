package mcpremote

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// computeChanges lists the files an edit session changed: work files that
// differ from the baseline (taken after inventory generation, so its
// backfills are not changes), with the operation decided against the
// source the client sent. It also returns the new contents.
func computeChanges(cfg *Config, dir string, state SessionState) ([]mcpwire.Change, map[string][]byte, error) {
	work := filepath.Join(dir, "work")
	current, err := hashTree(work)
	if err != nil {
		return nil, nil, errorf(mcpwire.CodeRuntimeError, "hash work tree: %v", err)
	}
	if _, tracked := state.SourceFiles["inventory.yml"]; !tracked {
		delete(current, "inventory.yml")
	}
	candidates := map[string]bool{}
	for p, sum := range current {
		if state.Baseline[p] != sum {
			candidates[p] = true
		}
	}
	for p := range state.Baseline {
		if _, ok := current[p]; !ok && p != "inventory.yml" {
			candidates[p] = true
		}
	}
	var changes []mcpwire.Change
	contents := map[string][]byte{}
	for p := range candidates {
		srcSum, inSource := state.SourceFiles[p]
		newSum, inWork := current[p]
		var op string
		switch {
		case !inSource && inWork:
			op = mcpwire.OpAdd
		case inSource && !inWork:
			op = mcpwire.OpDelete
		case inSource && inWork:
			if newSum == srcSum {
				continue // back to what Git has
			}
			op = mcpwire.OpModify
		default:
			continue // only ever a generated file
		}
		if err := mcpwire.CheckSnapshotPath(p); err != nil {
			return nil, nil, errorf(mcpwire.CodeChangesetInvalid, "changed path: %v", err)
		}
		change := mcpwire.Change{Path: p, Op: op, BaseSHA256: srcSum}
		if inWork {
			data, err := os.ReadFile(filepath.Join(work, filepath.FromSlash(p)))
			if err != nil {
				return nil, nil, errorf(mcpwire.CodeRuntimeError, "read %s: %v", p, err)
			}
			if leak := internalPathIn(cfg, dir, data); leak != "" {
				return nil, nil, errorf(mcpwire.CodeChangesetInvalid, "%s contains the session-internal path %s", p, leak)
			}
			change.NewSHA256 = mcpwire.SHA256Hex(data)
			contents[p] = data
		}
		changes = append(changes, change)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	if err := checkExportable(work, changes, contents); err != nil {
		return nil, nil, err
	}
	return changes, contents, nil
}

// checkExportable holds the changed files to the rules the next session's
// snapshot is held to: the size limits (which also bound the changes
// stream the client reads) and the path scope, so a change that is
// exported and committed never makes every later session fail.
func checkExportable(work string, changes []mcpwire.Change, contents map[string][]byte) error {
	if len(changes) > mcpwire.MaxFiles {
		return errorf(mcpwire.CodeChangesetInvalid, "%d changed files, more than %d", len(changes), mcpwire.MaxFiles)
	}
	var total int64
	var written []string
	for _, c := range changes {
		data, ok := contents[c.Path]
		if !ok {
			continue
		}
		if int64(len(data)) > mcpwire.MaxFileBytes {
			return errorf(mcpwire.CodeChangesetInvalid, "%s is larger than %d bytes", c.Path, mcpwire.MaxFileBytes)
		}
		total += int64(len(data))
		written = append(written, c.Path)
	}
	if total > mcpwire.MaxTotalBytes {
		return errorf(mcpwire.CodeChangesetInvalid, "changed files total %d bytes, more than %d", total, mcpwire.MaxTotalBytes)
	}
	if err := CheckPathScope(work, written); err != nil {
		var e *Error
		if errors.As(err, &e) && e.Code != mcpwire.CodeRuntimeError {
			return &Error{Code: mcpwire.CodeChangesetInvalid, Err: e.Err}
		}
		return err
	}
	return nil
}

// internalPathIn reports a session-internal location written into a file.
func internalPathIn(cfg *Config, dir string, data []byte) string {
	for _, p := range []string{
		mcpwire.ContainerDataDir + "/" + mcpwire.DataMCPDir + "/",
		mcpwire.ContainerTmpDir + "/",
		dir,
	} {
		if p != "" && bytes.Contains(data, []byte(p)) {
			return strings.TrimSuffix(p, "/")
		}
	}
	return ""
}

// RunChanges is `pilot mcp remote changes <id>`: write the edit session's
// changes as a tar (manifest first) to stdout.
func RunChanges(cfg *Config, id string) error {
	if !mcpwire.ValidEnv(cfg.Env) {
		return errorf(mcpwire.CodeCommandInvalid, "invalid --env %q", cfg.Env)
	}
	if !mcpwire.ValidSessionID(id) {
		return errorf(mcpwire.CodeCommandInvalid, "invalid session id")
	}
	CollectEditSessions(cfg)
	dir := filepath.Join(cfg.sessionsRoot(), id)
	if _, err := os.Stat(dir); err != nil {
		return errorf(mcpwire.CodeSessionNotFound, "no edit session %s in env %s", id, cfg.Env)
	}
	lock, err := tryLock(filepath.Join(dir, ".lock"))
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "lock session: %v", err)
	}
	if lock == nil {
		return errorf(mcpwire.CodeSessionNotFound, "session %s is still being served", id)
	}
	defer lock.Close()
	state, ok, err := loadSession(dir)
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "load session: %v", err)
	}
	switch {
	case !ok:
		return errorf(mcpwire.CodeSessionNotFound, "session %s has no state", id)
	case state.Env != cfg.Env:
		return errorf(mcpwire.CodeSessionNotFound, "session %s belongs to env %s", id, state.Env)
	case state.Mode != mcpwire.ModeEdit:
		return errorf(mcpwire.CodeSessionNotFound, "session %s is not an edit session", id)
	case state.State != stateEnded:
		return errorf(mcpwire.CodeSessionNotFound, "session %s has not ended", id)
	}
	changes, contents, err := computeChanges(cfg, dir, state)
	if err != nil {
		return err
	}
	return writeChanges(cfg, state, changes, contents)
}

func writeChanges(cfg *Config, state SessionState, changes []mcpwire.Change, contents map[string][]byte) error {
	manifest, err := json.Marshal(mcpwire.ChangesManifest{
		Protocol: mcpwire.Protocol, SessionID: state.ID, Env: state.Env,
		BaseCommitSHA: state.Source.CommitSHA, Changes: changes,
	})
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "encode changes manifest: %v", err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write(mcpwire.ChangesManifestName, manifest); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "write changes: %v", err)
	}
	for _, c := range changes {
		if c.Op == mcpwire.OpDelete {
			continue
		}
		if err := write(c.Path, contents[c.Path]); err != nil {
			return errorf(mcpwire.CodeRuntimeError, "write changes: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "write changes: %v", err)
	}
	if _, err := cfg.Stdout.Write(buf.Bytes()); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "write changes: %v", err)
	}
	return nil
}
