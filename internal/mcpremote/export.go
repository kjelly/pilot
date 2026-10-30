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
	if err := checkNextSnapshot(cfg, dir, state, changes, contents); err != nil {
		return nil, nil, err
	}
	if _, err := encodeChanges(state, changes, contents); err != nil {
		return nil, nil, err
	}
	return changes, contents, nil
}

// checkNextSnapshot holds the source with these changes applied (what the
// config repository holds once they are committed, and so the next
// session's snapshot) to the same checks a snapshot gets on import: the
// file-list rules and the content checks. An exported change therefore
// never makes every later session fail. Unchanged files come from the
// session's source/, changed ones from contents. A failure in a file the
// edit did not touch (the image was upgraded since the session started,
// for example) refuses the export too: every check runs on the whole
// next snapshot, so none is skipped.
func checkNextSnapshot(cfg *Config, dir string, state SessionState, changes []mcpwire.Change, contents map[string][]byte) error {
	if len(changes) == 0 {
		return nil
	}
	sourceDir := filepath.Join(dir, "source")
	next := make(map[string]bool, len(state.SourceFiles)+len(changes))
	for p := range state.SourceFiles {
		next[p] = true
	}
	for _, c := range changes {
		next[c.Path] = c.Op != mcpwire.OpDelete
	}
	var paths []string
	for p, keep := range next {
		if keep {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	data := make(map[string][]byte, len(paths))
	files := make([]mcpwire.FileEntry, 0, len(paths))
	for _, p := range paths {
		b, changed := contents[p]
		if !changed {
			var err error
			if b, err = os.ReadFile(filepath.Join(sourceDir, filepath.FromSlash(p))); err != nil {
				return errorf(mcpwire.CodeRuntimeError, "next snapshot: read source %s: %v", p, err)
			}
		}
		data[p] = b
		files = append(files, mcpwire.FileEntry{Path: p, Size: int64(len(b))})
	}
	if err := checkFileSet(files); err != nil {
		return refusedNextSnapshot(err)
	}

	parent := cfg.TmpDir
	if parent != "" {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return errorf(mcpwire.CodeRuntimeError, "create %s: %v", parent, err)
		}
	}
	root, err := os.MkdirTemp(parent, "next-snapshot-")
	if err != nil {
		return errorf(mcpwire.CodeRuntimeError, "next snapshot: %v", err)
	}
	defer os.RemoveAll(root)
	for _, p := range paths {
		dst := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return errorf(mcpwire.CodeRuntimeError, "next snapshot: %v", err)
		}
		if err := os.WriteFile(dst, data[p], 0o600); err != nil {
			return errorf(mcpwire.CodeRuntimeError, "next snapshot: %v", err)
		}
	}
	if err := checkSnapshotContent(cfg, root, state.Env, paths); err != nil {
		return refusedNextSnapshot(err)
	}
	return nil
}

// refusedNextSnapshot reports a check the next snapshot fails as an
// invalid changeset, naming the code the import would return.
func refusedNextSnapshot(err error) error {
	var e *Error
	if !errors.As(err, &e) || e.Code == mcpwire.CodeRuntimeError {
		return err
	}
	return errorf(mcpwire.CodeChangesetInvalid, "the next session would refuse the configuration with these changes: %s: %v", e.Code, e.Err)
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
	out, err := encodeChanges(state, changes, contents)
	if err != nil {
		return err
	}
	if _, err := cfg.Stdout.Write(out); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "write changes: %v", err)
	}
	return nil
}

// encodeChanges builds the changes tar: the manifest, then the add and
// modify files. It holds the result to what the client reads: at most
// MaxFiles changes, a manifest of at most MaxManifestBytes and a stream of
// at most MaxStreamBytes.
func encodeChanges(state SessionState, changes []mcpwire.Change, contents map[string][]byte) ([]byte, error) {
	if len(changes) > mcpwire.MaxFiles {
		return nil, errorf(mcpwire.CodeChangesetInvalid, "%d changes, more than %d", len(changes), mcpwire.MaxFiles)
	}
	manifest, err := json.Marshal(mcpwire.ChangesManifest{
		Protocol: mcpwire.Protocol, SessionID: state.ID, Env: state.Env,
		BaseCommitSHA: state.Source.CommitSHA, Changes: changes,
	})
	if err != nil {
		return nil, errorf(mcpwire.CodeRuntimeError, "encode changes manifest: %v", err)
	}
	if len(manifest) > mcpwire.MaxManifestBytes {
		return nil, errorf(mcpwire.CodeChangesetInvalid, "changes manifest is %d bytes, more than %d", len(manifest), mcpwire.MaxManifestBytes)
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
		return nil, errorf(mcpwire.CodeRuntimeError, "write changes: %v", err)
	}
	for _, c := range changes {
		if c.Op == mcpwire.OpDelete {
			continue
		}
		if err := write(c.Path, contents[c.Path]); err != nil {
			return nil, errorf(mcpwire.CodeRuntimeError, "write changes: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, errorf(mcpwire.CodeRuntimeError, "write changes: %v", err)
	}
	if buf.Len() > mcpwire.MaxStreamBytes {
		return nil, errorf(mcpwire.CodeChangesetInvalid, "changes stream is %d bytes, more than %d", buf.Len(), mcpwire.MaxStreamBytes)
	}
	return buf.Bytes(), nil
}
