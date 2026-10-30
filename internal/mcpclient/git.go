package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func openGitCache(cacheDir, url string, timeout time.Duration) (*gitRepo, error) {
	key := sha256.Sum256([]byte(url))
	dir := filepath.Join(cacheDir, "git", hex.EncodeToString(key[:]))
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	r := &gitRepo{dir: dir, url: url, timeout: timeout}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if _, err := r.git(context.Background(), nil, "init", "--bare", "--quiet"); err != nil {
			return nil, err
		}
	}
	// The cache is keyed by URL, but set it every time so a hand-edited
	// cache cannot point elsewhere.
	if _, err := r.git(context.Background(), nil, "config", "remote.origin.url", url); err != nil {
		return nil, err
	}
	return r, nil
}

// git runs one non-interactive git command in the cache. It never prompts:
// no terminal (new session), prompts disabled, and askpass refused.
func (r *gitRepo) git(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", r.dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "SSH_ASKPASS_REQUIRE=never", "GCM_INTERACTIVE=never")
	detachFromTerminal(cmd)
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), classifyGitError(args, stderr.String(), err)
	}
	return stdout.Bytes(), nil
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

// resolve fetches ref and returns the full commit SHA it names.
func (r *gitRepo) resolve(ctx context.Context, ref string) (string, error) {
	if fullSHAPattern.MatchString(ref) {
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

// treeEntry is one line of `git ls-tree -r`.
type treeEntry struct {
	mode, kind, object, path string
}

// listTree lists every entry under subdir of commit, paths relative to subdir.
func (r *gitRepo) listTree(ctx context.Context, commit, subdir string) ([]treeEntry, error) {
	tree := commit
	if subdir != "." {
		tree = commit + ":" + subdir
	}
	out, err := r.git(ctx, nil, "ls-tree", "-r", "-z", "--full-tree", tree)
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
		if !ok || len(fields) != 3 {
			return nil, &Error{Code: CodeGitFailed, Msg: "unexpected git ls-tree output"}
		}
		entries = append(entries, treeEntry{mode: fields[0], kind: fields[1], object: fields[2], path: p})
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
