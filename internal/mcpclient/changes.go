package mcpclient

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// ChangesResult is what `pilot-mcp changes` wrote.
type ChangesResult struct {
	SessionID string
	Written   []string
	Deleted   []string
	Ignored   []string
}

// LatestEditSession is the newest edit session recorded for profile.
func LatestEditSession(statePath, profile string) (string, error) {
	records, err := ReadRecords(statePath, profile)
	if err != nil {
		return "", err
	}
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].Mode == mcpwire.ModeEdit {
			return records[i].SessionID, nil
		}
	}
	return "", &Error{Code: CodeProfileInvalid, Msg: fmt.Sprintf("no edit session recorded for profile %s; pass --session", profile)}
}

// Changes is `pilot-mcp changes`: fetch an ended edit session's changes and
// write them into the local clone at into, refusing on any conflict.
func Changes(ctx context.Context, o *Options, sessionID, into string) (*ChangesResult, error) {
	if !mcpwire.ValidSessionID(sessionID) {
		return nil, &Error{Code: CodeProfileInvalid, Msg: "session id must be 32 lowercase hex characters"}
	}
	image, err := o.image()
	if err != nil {
		return nil, err
	}
	proc, err := startSSH(o, changesCommand(o.Profile.Target, image, sessionID), false)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(proc.stdout, mcpwire.MaxStreamBytes+1))
	if readErr == nil && len(data) > mcpwire.MaxStreamBytes {
		// The remote is still writing into a pipe nobody reads; waiting
		// for it would never return.
		_ = proc.cmd.Process.Kill()
		proc.wait()
		return nil, &Error{Code: CodeChangesetInvalid, Msg: fmt.Sprintf("changes output is larger than %d bytes", mcpwire.MaxStreamBytes)}
	}
	if exit := proc.wait(); exit != 0 {
		return nil, remoteFailure(exit, proc.stderr.String())
	}
	if readErr != nil || len(data) > mcpwire.MaxStreamBytes {
		return nil, &Error{Code: CodeChangesetInvalid, Msg: "changes output is unreadable or too large"}
	}
	manifest, contents, err := parseChanges(data, sessionID, o.Profile.Target.Env)
	if err != nil {
		return nil, err
	}
	return applyChanges(ctx, o, manifest, contents, into)
}

// parseChanges validates the tar: manifest first, then exactly the add and
// modify files it lists, each matching its new_sha256.
func parseChanges(data []byte, sessionID, env string) (mcpwire.ChangesManifest, map[string][]byte, error) {
	invalid := func(format string, args ...any) error {
		return &Error{Code: CodeChangesetInvalid, Msg: fmt.Sprintf(format, args...)}
	}
	var m mcpwire.ChangesManifest
	tr := tar.NewReader(bytes.NewReader(data))
	hdr, err := tr.Next()
	if err != nil || hdr.Name != mcpwire.ChangesManifestName || hdr.Typeflag != tar.TypeReg {
		return m, nil, invalid("first entry must be %s", mcpwire.ChangesManifestName)
	}
	body, err := io.ReadAll(io.LimitReader(tr, mcpwire.MaxManifestBytes))
	if err != nil {
		return m, nil, invalid("read manifest: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, nil, invalid("decode manifest: %v", err)
	}
	if m.Protocol != mcpwire.Protocol || m.SessionID != sessionID || m.Env != env || m.BaseCommitSHA == "" {
		return m, nil, invalid("manifest does not belong to session %s in %s", sessionID, env)
	}
	want := map[string]mcpwire.Change{}
	folded := map[string]string{}
	for _, c := range m.Changes {
		if err := mcpwire.CheckSnapshotPath(c.Path); err != nil {
			return m, nil, invalid("%v", err)
		}
		if _, dup := want[c.Path]; dup {
			return m, nil, invalid("%s listed twice", c.Path)
		}
		// On a case-insensitive clone (macOS) these would be one file.
		if other, dup := folded[mcpwire.FoldPath(c.Path)]; dup {
			return m, nil, invalid("%s and %s differ only in case or ignorable characters", other, c.Path)
		}
		folded[mcpwire.FoldPath(c.Path)] = c.Path
		switch c.Op {
		case mcpwire.OpAdd, mcpwire.OpModify, mcpwire.OpDelete:
		default:
			return m, nil, invalid("%s has unknown op %q", c.Path, c.Op)
		}
		want[c.Path] = c
	}
	contents := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, nil, invalid("read changes: %v", err)
		}
		c, listed := want[hdr.Name]
		if hdr.Typeflag != tar.TypeReg || !listed || c.Op == mcpwire.OpDelete {
			return m, nil, invalid("unexpected entry %q", hdr.Name)
		}
		if _, dup := contents[hdr.Name]; dup {
			return m, nil, invalid("%s appears twice", hdr.Name)
		}
		body, err := io.ReadAll(io.LimitReader(tr, mcpwire.MaxFileBytes+1))
		if err != nil || len(body) > mcpwire.MaxFileBytes {
			return m, nil, invalid("%s is unreadable or too large", hdr.Name)
		}
		if mcpwire.SHA256Hex(body) != c.NewSHA256 {
			return m, nil, invalid("%s does not match its new_sha256", hdr.Name)
		}
		contents[hdr.Name] = body
	}
	for p, c := range want {
		if _, ok := contents[p]; !ok && c.Op != mcpwire.OpDelete {
			return m, nil, invalid("%s is missing from the changes", p)
		}
	}
	return m, contents, nil
}

// runGit runs git in dir and returns its exit status as well as stdout.
func runGit(ctx context.Context, o *Options, dir string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "SSH_ASKPASS_REQUIRE=never", "GCM_INTERACTIVE=never")
	detachFromTerminal(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return "", -1, err
	}
	return stdout.String(), 0, nil
}

func conflict(format string, args ...any) error {
	return &Error{Code: CodeChangesetConflict, Msg: fmt.Sprintf(format, args...)}
}

func applyChanges(ctx context.Context, o *Options, m mcpwire.ChangesManifest, contents map[string][]byte, into string) (*ChangesResult, error) {
	abs, err := filepath.Abs(into)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, conflict("%s: %v", into, err)
	}
	top, code, err := runGit(ctx, o, abs, "rev-parse", "--show-toplevel")
	if err != nil || code != 0 {
		return nil, conflict("%s is not a Git working tree", into)
	}
	if topReal, err := filepath.EvalSymlinks(strings.TrimSpace(top)); err != nil || topReal != abs {
		return nil, conflict("%s is not the top level of its repository (%s is)", into, strings.TrimSpace(top))
	}
	origin, code, err := runGit(ctx, o, abs, "remote", "get-url", "origin")
	if err != nil || code != 0 || !SameRepo(o.Profile.Source.URL, strings.TrimSpace(origin)) {
		return nil, conflict("%s's origin is not %s", into, o.Profile.Source.URL)
	}
	status, code, err := runGit(ctx, o, abs, "status", "--porcelain")
	if err != nil || code != 0 || strings.TrimSpace(status) != "" {
		return nil, conflict("%s has uncommitted changes; commit or stash them first", into)
	}
	base := m.BaseCommitSHA
	if _, code, _ := runGit(ctx, o, abs, "cat-file", "-e", base+"^{commit}"); code != 0 {
		if _, code, _ := runGit(ctx, o, abs, "fetch", "--quiet", "--no-tags", "origin", base); code != 0 {
			return nil, conflict("base commit %s is not available locally and could not be fetched from origin", base)
		}
	}

	type planned struct {
		change mcpwire.Change
		full   string // path in the clone (subdir + change path)
	}
	res := &ChangesResult{SessionID: m.SessionID}
	var apply []planned
	var conflicts []string
	for _, c := range m.Changes {
		full := c.Path
		if o.Profile.Source.Subdir != "." {
			full = path.Join(o.Profile.Source.Subdir, c.Path)
		}
		if _, code, _ := runGit(ctx, o, abs, "check-ignore", "-q", "--", full); code == 0 {
			res.Ignored = append(res.Ignored, full)
			continue
		}
		_, code, err := runGit(ctx, o, abs, "diff", "--quiet", base, "HEAD", "--", full)
		if err != nil || code > 1 {
			return nil, conflict("cannot compare %s between %s and HEAD", full, base)
		}
		if code == 1 {
			conflicts = append(conflicts, full)
		}
		apply = append(apply, planned{change: c, full: full})
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return nil, conflict("changed on HEAD since %s: %s", base, strings.Join(conflicts, ", "))
	}

	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck // read-mostly handle; writes are checked individually
	for _, a := range apply {
		if err := refuseSymlinkComponents(root, a.full); err != nil {
			return nil, err
		}
	}
	for _, a := range apply {
		name := filepath.FromSlash(a.full)
		if a.change.Op == mcpwire.OpDelete {
			if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, partlyApplied(res, a.full, err)
			}
			res.Deleted = append(res.Deleted, a.full)
			continue
		}
		if err := writeInRoot(root, name, contents[a.change.Path]); err != nil {
			return nil, partlyApplied(res, a.full, err)
		}
		res.Written = append(res.Written, a.full)
	}
	return res, nil
}

// partlyApplied reports a write that failed after others succeeded. The
// clone was clean before the import, so Git shows exactly what was done.
func partlyApplied(res *ChangesResult, failed string, err error) error {
	done := append(append([]string{}, res.Written...), res.Deleted...)
	if len(done) == 0 {
		return fmt.Errorf("%s: %w", failed, err)
	}
	return fmt.Errorf("%s: %w; already applied before the failure: %s (the clone was clean, so `git status` shows them)", failed, err, strings.Join(done, ", "))
}

// refuseSymlinkComponents rejects a target any of whose existing path
// components is a symlink: os.Root only stops escapes, it still follows
// a symlink that stays inside the root.
func refuseSymlinkComponents(root *os.Root, p string) error {
	parts := strings.Split(p, "/")
	for i := range parts {
		prefix := filepath.FromSlash(strings.Join(parts[:i+1], "/"))
		info, err := root.Lstat(prefix)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return conflict("%s: %v", prefix, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return conflict("%s is a symlink; refusing to write through it", filepath.ToSlash(prefix))
		}
	}
	return nil
}

func writeInRoot(root *os.Root, name string, data []byte) error {
	mode := fs.FileMode(0o644)
	if info, err := root.Lstat(name); err == nil {
		mode = info.Mode().Perm()
	}
	if dir := filepath.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// A random name: a temporary file left by a killed run must not block
	// every later import of the same path.
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(name), "."+filepath.Base(name)+"."+hex.EncodeToString(suffix[:])+".pilot-mcp-tmp")
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = root.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return nil
}
