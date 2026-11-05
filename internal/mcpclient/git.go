package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// gitRepo is the bare cache of one remote under the user's cache dir.
type gitRepo struct {
	dir     string
	url     string
	timeout time.Duration
}

// DefaultCacheDir is $XDG_CACHE_HOME/pilot-mcp, falling back to ~/.cache.
func DefaultCacheDir() (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "pilot-mcp"), nil
}

// openGitCache opens (creating it if needed) the bare cache of url. The
// wait for the cache lock and the git commands observe ctx, so a signal
// ends them. A process killed while changing the cache can leave it with
// stale lock files or half initialized; under the lock, which every
// changing command runs under, such leftovers are removed and a cache that
// does not have the structure of a bare repository is rebuilt (it is only
// a cache; the check never runs git, so a failing git cannot cause it).
func openGitCache(ctx context.Context, cacheDir, url string, timeout time.Duration) (*gitRepo, error) {
	key := sha256.Sum256([]byte(url))
	dir := filepath.Join(cacheDir, "git", hex.EncodeToString(key[:]))
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	r := &gitRepo{dir: dir, url: url, timeout: timeout}
	unlock, err := r.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := r.repair(ctx); err != nil {
		return nil, err
	}
	// The cache is keyed by URL, but set it every time so a hand-edited
	// cache cannot point elsewhere.
	if _, err := r.git(ctx, nil, "config", "remote.origin.url", url); err != nil {
		var e *Error
		if ctx.Err() == nil && errors.As(err, &e) {
			// valid() does not parse config; say which cache to delete.
			return nil, &Error{Code: e.Code, Msg: e.Msg + " (git cache " + dir + "; delete it to rebuild it)"}
		}
		return nil, err
	}
	return r, nil
}

// repair, run under the cache lock, removes what a killed git left behind
// and (re)creates the cache when it is not a valid bare repository. A new
// cache is initialized next to it and renamed into place, so it is never
// seen half made.
func (r *gitRepo) repair(ctx context.Context) error {
	if old, _ := filepath.Glob(r.dir + ".init-*"); len(old) > 0 {
		for _, p := range old {
			_ = os.RemoveAll(p)
		}
	}
	if r.valid() {
		return filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() && strings.HasSuffix(d.Name(), ".lock") {
				_ = os.Remove(p) // no git runs in the cache without our lock
			}
			return nil
		})
	}
	if err := os.RemoveAll(r.dir); err != nil {
		return &Error{Code: CodeGitFailed, Msg: "remove broken git cache: " + err.Error()}
	}
	tmp, err := os.MkdirTemp(filepath.Dir(r.dir), filepath.Base(r.dir)+".init-")
	if err != nil {
		return &Error{Code: CodeGitFailed, Msg: "git cache: " + err.Error()}
	}
	init := &gitRepo{dir: tmp, url: r.url, timeout: r.timeout}
	if _, err := init.git(ctx, nil, "init", "--bare", "--quiet"); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, r.dir); err != nil {
		_ = os.RemoveAll(tmp)
		return &Error{Code: CodeGitFailed, Msg: "git cache: " + err.Error()}
	}
	return nil
}

// valid reports whether the cache has the structure of an initialized
// bare repository. It looks at files only, never runs git: a slow or
// failing git must not make a healthy cache look broken and be deleted.
// git init writes HEAD before objects/, so a killed init fails this check.
func (r *gitRepo) valid() bool {
	for _, p := range []struct {
		name string
		dir  bool
	}{{"HEAD", false}, {"config", false}, {"objects", true}, {"refs", true}} {
		info, err := os.Lstat(filepath.Join(r.dir, p.name))
		if err != nil || info.IsDir() != p.dir || (!p.dir && !info.Mode().IsRegular()) {
			return false
		}
	}
	head, err := os.ReadFile(filepath.Join(r.dir, "HEAD"))
	h := strings.TrimSpace(string(head))
	return err == nil && (strings.HasPrefix(h, "ref: refs/") || fullSHAPattern.MatchString(h))
}

// lock serializes the commands that change the cache (init, config, and a
// fetch together with reading back what it fetched) between pilot-mcp
// processes: an agent starts the MCP servers of every profile at once, and
// profiles of one repository share its cache. Reading objects and asking
// the remote (ls-remote) need no lock. A holder runs at most three git
// commands under it, each bounded by the Git timeout, so a waiter waits
// three timeouts before it gives up. A cancelled parent ctx (a signal)
// ends the wait at once.
func (r *gitRepo) lock(parent context.Context) (func(), error) {
	ctx, cancel := context.WithTimeout(parent, 3*r.timeout)
	defer cancel()
	f, err := os.OpenFile(r.dir+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, &Error{Code: CodeGitFailed, Msg: "open git cache lock: " + err.Error()}
	}
	for {
		held, err := tryFlock(f)
		if err != nil {
			f.Close()
			return nil, &Error{Code: CodeGitFailed, Msg: "lock git cache: " + err.Error()}
		}
		if held {
			return func() { f.Close() }, nil
		}
		select {
		case <-ctx.Done():
			f.Close()
			if err := parent.Err(); err != nil {
				return nil, &Error{Code: CodeGitFailed, Msg: "waiting for the git cache: " + err.Error()}
			}
			return nil, &Error{Code: CodeGitFailed, Msg: "git cache " + r.dir + " is busy (another pilot-mcp is fetching)"}
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// git runs one non-interactive git command in the cache. It never prompts:
// no terminal (new session), prompts disabled, and askpass refused.
func (r *gitRepo) git(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	// --git-dir: git never searches upward from the cache for another
	// repository (a broken cache inside ~/.git must not reach it).
	// Automatic gc after a fetch runs in the foreground, under the cache
	// lock: a detached gc would outlive it. It never prunes: another
	// pilot-mcp may be about to read a commit that a later fetch made
	// unreachable (every resolve moves refs/pilot/fetched).
	cmd := boundedCommand(ctx, "git", append([]string{"--git-dir=" + r.dir, "-c", "gc.autoDetach=false", "-c", "maintenance.autoDetach=false", "-c", "gc.pruneExpire=never"}, args...)...)
	cmd.Env = gitEnv()
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil // git succeeded; a helper it started kept a pipe open
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return stdout.Bytes(), gitContextError(args, ctxErr, r.timeout)
		}
		return stdout.Bytes(), classifyGitError(args, stderr.String(), err)
	}
	return stdout.Bytes(), nil
}

// gitRepoEnv names the variables that tell git which repository to use.
// pilot-mcp says so itself (--git-dir, -C), so inherited ones are dropped:
// an inherited GIT_DIR or GIT_OBJECT_DIRECTORY would point git elsewhere.
var gitRepoEnv = map[string]bool{
	"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_INDEX_FILE": true, "GIT_OBJECT_DIRECTORY": true,
	"GIT_ALTERNATE_OBJECT_DIRECTORIES": true, "GIT_COMMON_DIR": true, "GIT_NAMESPACE": true,
	"GIT_CONFIG": true, "GIT_SHALLOW_FILE": true, "GIT_GRAFT_FILE": true, "GIT_REPLACE_REF_BASE": true,
	"GIT_NO_REPLACE_OBJECTS": true, "GIT_QUARANTINE_PATH": true,
}

// gitEnv is the environment for every git pilot-mcp runs: the user's,
// without repository-locating variables, and never prompting.
func gitEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !gitRepoEnv[k] {
			env = append(env, kv)
		}
	}
	return append(env, "GIT_TERMINAL_PROMPT=0", "SSH_ASKPASS_REQUIRE=never", "GCM_INTERACTIVE=never")
}

// gitContextError reports a git command ended by its timeout or by
// cancellation (its process group was killed).
func gitContextError(args []string, ctxErr error, timeout time.Duration) error {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return &Error{Code: CodeGitFailed, Msg: fmt.Sprintf("git %s did not finish within %s (timeouts.git_seconds)", args[0], timeout)}
	}
	return &Error{Code: CodeGitFailed, Msg: fmt.Sprintf("git %s: %v", args[0], ctxErr)}
}

func classifyGitError(args []string, stderr string, err error) error {
	msg := strings.TrimSpace(stderr)
	lower := strings.ToLower(msg)
	for _, auth := range []string{"authentication failed", "permission denied", "could not read username", "terminal prompts disabled", "host key verification failed", "could not read from remote repository"} {
		if strings.Contains(lower, auth) {
			return &Error{Code: CodeGitAuthRequired, Msg: fmt.Sprintf("git %s: %s", args[0], firstLine(msg))}
		}
	}
	if msg == "" {
		msg = err.Error()
	}
	return &Error{Code: CodeGitFailed, Msg: fmt.Sprintf("git %s: %s", args[0], firstLine(msg))}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// resolve fetches ref and returns the full commit SHA it names. The fetch
// and the read of the ref it updates run under the cache lock, so another
// process fetching another ref of the same repository cannot swap it.
func (r *gitRepo) resolve(ctx context.Context, ref string) (string, error) {
	if fullSHAPattern.MatchString(ref) {
		unlock, err := r.lock(ctx)
		if err != nil {
			return "", err
		}
		defer unlock()
		if _, err := r.git(ctx, nil, "fetch", "--quiet", "--no-tags", "origin", ref); err != nil {
			if _, err := r.git(ctx, nil, "fetch", "--quiet", "--no-tags", "origin", "+refs/heads/*:refs/pilot/heads/*", "+refs/tags/*:refs/pilot/tags/*"); err != nil {
				return "", err
			}
		}
		return r.commitOf(ctx, ref)
	}
	out, err := r.git(ctx, nil, "ls-remote", "origin", "refs/heads/"+ref, "refs/tags/"+ref)
	if err != nil {
		return "", err
	}
	var heads, tags bool
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		_, name, ok := strings.Cut(line, "\t")
		switch {
		case !ok:
		case name == "refs/heads/"+ref:
			heads = true
		case name == "refs/tags/"+ref:
			tags = true
		}
	}
	var remote string
	switch {
	case heads && tags:
		return "", &Error{Code: CodeGitRefNotFound, Msg: fmt.Sprintf("%q is both a branch and a tag; use the full commit SHA", ref)}
	case heads:
		remote = "refs/heads/" + ref
	case tags:
		remote = "refs/tags/" + ref
	default:
		return "", &Error{Code: CodeGitRefNotFound, Msg: fmt.Sprintf("no branch or tag named %q", ref)}
	}
	unlock, err := r.lock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	if _, err := r.git(ctx, nil, "fetch", "--quiet", "--no-tags", "origin", "+"+remote+":refs/pilot/fetched"); err != nil {
		return "", err
	}
	return r.commitOf(ctx, "refs/pilot/fetched")
}

func (r *gitRepo) commitOf(ctx context.Context, rev string) (string, error) {
	out, err := r.git(ctx, nil, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		return "", &Error{Code: CodeGitRefNotFound, Msg: fmt.Sprintf("%s is not a commit in the repository", rev)}
	}
	return strings.TrimSpace(string(out)), nil
}

// treeEntry is one line of `git ls-tree -r -l`. size is -1 for an entry
// that is not a blob (git prints "-").
type treeEntry struct {
	mode, kind, object, path string
	size                     int64
}

// listTree lists every entry under subdir of commit, paths relative to subdir.
func (r *gitRepo) listTree(ctx context.Context, commit, subdir string) ([]treeEntry, error) {
	tree := commit
	if subdir != "." {
		tree = commit + ":" + subdir
	}
	out, err := r.git(ctx, nil, "ls-tree", "-r", "-l", "-z", "--full-tree", tree)
	if err != nil {
		return nil, err
	}
	var entries []treeEntry
	for _, rec := range strings.Split(string(out), "\x00") {
		if rec == "" {
			continue
		}
		meta, p, ok := strings.Cut(rec, "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 4 {
			return nil, &Error{Code: CodeGitFailed, Msg: "unexpected git ls-tree output"}
		}
		size := int64(-1)
		if fields[3] != "-" {
			if size, err = strconv.ParseInt(fields[3], 10, 64); err != nil {
				return nil, &Error{Code: CodeGitFailed, Msg: "unexpected git ls-tree size"}
			}
		}
		entries = append(entries, treeEntry{mode: fields[0], kind: fields[1], object: fields[2], path: p, size: size})
	}
	return entries, nil
}

// readBlobs returns the contents of the given blob objects, in order,
// through one `git cat-file --batch`.
func (r *gitRepo) readBlobs(ctx context.Context, objects []string) ([][]byte, error) {
	var in bytes.Buffer
	for _, o := range objects {
		in.WriteString(o + "\n")
	}
	out, err := r.git(ctx, &in, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(bytes.NewReader(out))
	blobs := make([][]byte, 0, len(objects))
	for range objects {
		header, err := br.ReadString('\n')
		if err != nil {
			return nil, &Error{Code: CodeGitFailed, Msg: "short git cat-file output"}
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[1] != "blob" {
			return nil, &Error{Code: CodeGitFailed, Msg: "unexpected git cat-file output: " + strings.TrimSpace(header)}
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return nil, &Error{Code: CodeGitFailed, Msg: "unexpected git cat-file size"}
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(br, data); err != nil {
			return nil, &Error{Code: CodeGitFailed, Msg: "short git cat-file blob"}
		}
		if _, err := br.ReadByte(); err != nil { // trailing newline
			return nil, &Error{Code: CodeGitFailed, Msg: "short git cat-file output"}
		}
		blobs = append(blobs, data)
	}
	return blobs, nil
}
