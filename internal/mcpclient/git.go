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
// ends them.
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
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if _, err := r.git(ctx, nil, "init", "--bare", "--quiet"); err != nil {
			return nil, err
		}
	}
	// The cache is keyed by URL, but set it every time so a hand-edited
	// cache cannot point elsewhere.
	if _, err := r.git(ctx, nil, "config", "remote.origin.url", url); err != nil {
		return nil, err
	}
	return r, nil
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
	cmd := boundedCommand(ctx, "git", append([]string{"-C", r.dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "SSH_ASKPASS_REQUIRE=never", "GCM_INTERACTIVE=never")
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
