package mcpclient

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
)

func TestGitResolveBranchTagShaAndAmbiguity(t *testing.T) {
	allowLocalRepos(t)
	bare, first := makeRepo(t, map[string]string{"env/hosts.yml": "hosts: {}\n"})
	repo, err := openGitCache(t.TempDir(), bare, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := repo.resolve(ctx, "main"); err != nil || got != first {
		t.Fatalf("branch main = %s, %v; want %s", got, err, first)
	}
	if got, err := repo.resolve(ctx, first); err != nil || got != first {
		t.Fatalf("full sha = %s, %v", got, err)
	}
	if _, err := repo.resolve(ctx, "nope"); !hasCode(err, CodeGitRefNotFound) {
		t.Fatalf("unknown ref: %v", err)
	}

	// Advance main and add an ambiguous name; a new resolve follows main.
	work := t.TempDir()
	git(t, work, "clone", "--quiet", bare, ".")
	writeTree(t, work, map[string]string{"env/hosts.yml": "hosts: {a: {}}\n"})
	git(t, work, "commit", "--quiet", "-am", "advance")
	git(t, work, "tag", "v1")
	git(t, work, "branch", "v1")
	git(t, work, "push", "--quiet", "origin", "main", "refs/heads/v1:refs/heads/v1", "refs/tags/v1:refs/tags/v1")
	second := git(t, work, "rev-parse", "HEAD")
	if got, err := repo.resolve(ctx, "main"); err != nil || got != second {
		t.Fatalf("advanced main = %s, %v; want %s", got, err, second)
	}
	if _, err := repo.resolve(ctx, "v1"); !hasCode(err, CodeGitRefNotFound) || !strings.Contains(err.Error(), "both a branch and a tag") {
		t.Fatalf("ambiguous ref: %v", err)
	}
}

// Profiles of one repository share its cache, and an agent starts all
// their MCP servers together: concurrent processes fetching different refs
// must each get their own ref's commit, and a fresh cache must survive
// being opened by all of them at once.
func TestGitCacheIsSafeAcrossConcurrentProcesses(t *testing.T) {
	allowLocalRepos(t)
	bare, first := makeRepo(t, map[string]string{"env/hosts.yml": "hosts: {}\n"})
	work := t.TempDir()
	git(t, work, "clone", "--quiet", bare, ".")
	git(t, work, "tag", "release")
	writeTree(t, work, map[string]string{"env/hosts.yml": "hosts: {a: {}}\n"})
	git(t, work, "commit", "--quiet", "-am", "advance")
	git(t, work, "push", "--quiet", "origin", "refs/heads/main:refs/heads/main", "refs/tags/release:refs/tags/release")
	second := git(t, work, "rev-parse", "HEAD")

	cacheDir := t.TempDir()
	want := map[string]string{"main": second, "release": first}
	const workers = 8
	errs := make(chan error, workers*4)
	var wg sync.WaitGroup
	for i := range workers {
		ref := "main"
		if i%2 == 1 {
			ref = "release"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				// A handle per call, as a separate process would have.
				repo, err := openGitCache(cacheDir, bare, 30*time.Second)
				if err != nil {
					errs <- fmt.Errorf("open: %w", err)
					return
				}
				got, err := repo.resolve(context.Background(), ref)
				if err != nil {
					errs <- fmt.Errorf("resolve %s: %w", ref, err)
					return
				}
				if got != want[ref] {
					errs <- fmt.Errorf("resolve %s = %s, want %s", ref, got, want[ref])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// A holder may run up to three git commands under the cache lock, each
// with its own timeout, so a waiter must not give up after one timeout
// while the holder is still making progress.
func TestGitCacheWaiterOutlastsOneTimeout(t *testing.T) {
	allowLocalRepos(t)
	bare, commit := makeRepo(t, map[string]string{"env/hosts.yml": "hosts: {}\n"})
	const timeout = time.Second
	repo, err := openGitCache(t.TempDir(), bare, timeout)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(repo.dir+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if held, err := tryFlock(f); !held || err != nil {
		t.Fatalf("hold the cache lock: %v %v", held, err)
	}
	release := time.AfterFunc(timeout*3/2, func() { f.Close() })
	defer release.Stop()
	if got, err := repo.resolve(context.Background(), "main"); err != nil || got != commit {
		t.Fatalf("resolve while another process held the lock for 1.5 timeouts = %s, %v", got, err)
	}
}

func TestGitAuthFailureIsNonInteractive(t *testing.T) {
	repo, err := openGitCache(t.TempDir(), "https://127.0.0.1:9/org/repo", 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = repo.resolve(context.Background(), "main")
	if err == nil {
		t.Fatal("unreachable remote resolved")
	}
	if !hasCode(err, CodeGitFailed) && !hasCode(err, CodeGitAuthRequired) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("git did not fail fast")
	}
}

func hasCode(err error, code string) bool {
	e, ok := err.(*Error)
	return ok && e.Code == code
}

func buildFrom(t *testing.T, files map[string]string, subdir string) (*Snapshot, error) {
	t.Helper()
	allowLocalRepos(t)
	bare, commit := makeRepo(t, files)
	repo, err := openGitCache(t.TempDir(), bare, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.resolve(context.Background(), "main"); err != nil {
		t.Fatal(err)
	}
	return buildSnapshot(context.Background(), repo, SourceConfig{URL: bare, Ref: "main", Subdir: subdir}, commit, "prod", "test", "tester")
}

func TestBuildSnapshotNormalizesAndScopesToSubdir(t *testing.T) {
	snap, err := buildFrom(t, map[string]string{
		"prod/hosts.yml":         "hosts: {}\n",
		"prod/group_vars/b.yml":  "b: 1\n",
		"prod/.gitignore":        "/inventory.yml\n",
		"prod/contracts/x.yaml":  "no: 1\n",
		"staging/hosts.yml":      "hosts: {}\n",
		"prod/.pilot/audit/x":    "no\n",
		"prod/export-ignored.md": "kept\n",
		".gitattributes":         "prod/export-ignored.md export-ignore\n",
	}, "prod")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range snap.Manifest.Files {
		paths = append(paths, f.Path)
	}
	want := []string{".gitignore", "export-ignored.md", "group_vars/b.yml", "hosts.yml"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v, want %v (reserved removed, subdir only, export-ignore ignored)", paths, want)
	}
	if strings.Join(snap.Removed, ",") != ".pilot/audit/x,contracts/x.yaml" {
		t.Fatalf("removed = %v", snap.Removed)
	}
	n, err := mcpwire.ParseSnapshotHeader(strings.SplitAfterN(string(snap.Framed), "\n", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	body := snap.Framed[len(snap.Framed)-int(n):]
	tr := tar.NewReader(bytes.NewReader(body))
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Mode != 0o644 || !hdr.ModTime.IsZero() && hdr.ModTime.Unix() != 0 || hdr.Uid != 0 || hdr.Typeflag != tar.TypeReg {
			t.Fatalf("entry %s not normalized: %+v", hdr.Name, hdr)
		}
		names = append(names, hdr.Name)
	}
	if names[0] != mcpwire.ManifestName || strings.Join(names[1:], ",") != strings.Join(want, ",") {
		t.Fatalf("tar order = %v", names)
	}
	again, err := mcpwire.ContentDigest(snap.Manifest.Files)
	if err != nil || again != snap.Manifest.ContentDigest {
		t.Fatal("manifest digest does not match its files")
	}
}

func TestBuildSnapshotRejectsSymlinksAndLFS(t *testing.T) {
	if _, err := buildFrom(t, map[string]string{"env/hosts.yml": "version https://git-lfs.github.com/spec/v1\noid sha256:x\n"}, "env"); !hasCode(err, CodeSnapshotInvalid) {
		t.Fatalf("LFS pointer: %v", err)
	}
	allowLocalRepos(t)
	work := t.TempDir()
	git(t, work, "init", "--quiet")
	writeTree(t, work, map[string]string{"env/hosts.yml": "hosts: {}\n"})
	if err := os.Symlink("/etc/passwd", filepath.Join(work, "env", "link.yml")); err != nil {
		t.Fatal(err)
	}
	git(t, work, "add", "-A")
	git(t, work, "commit", "--quiet", "-m", "x")
	repo, err := openGitCache(t.TempDir(), work, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.resolve(context.Background(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildSnapshot(context.Background(), repo, SourceConfig{URL: work, Ref: "main", Subdir: "env"}, commit, "prod", "t", "t"); !hasCode(err, CodeSnapshotInvalid) {
		t.Fatalf("symlink: %v", err)
	}
}

func TestBuildSnapshotRefusesOversizedFilesAndSubmodules(t *testing.T) {
	// The limits are checked from the sizes ls-tree lists, before any blob
	// is read: a git that refuses cat-file must not be reached.
	allowLocalRepos(t)
	bare, commit := makeRepo(t, map[string]string{"env/hosts.yml": "hosts: {}\n", "env/big.bin": strings.Repeat("x", mcpwire.MaxFileBytes+1)})
	repo, err := openGitCache(t.TempDir(), bare, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.resolve(context.Background(), "main"); err != nil {
		t.Fatal(err)
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	wrapper := "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = cat-file ] && { echo 'cat-file must not run' >&2; exit 1; }; done\nexec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := buildSnapshot(context.Background(), repo, SourceConfig{URL: bare, Ref: "main", Subdir: "env"}, commit, "prod", "t", "t"); !hasCode(err, CodeSnapshotTooLarge) || !strings.Contains(err.Error(), "big.bin") {
		t.Fatalf("oversized file: %v", err)
	}
	// git ls-tree -l prints "-" as the size of a submodule (gitlink).
	allowLocalRepos(t)
	work := t.TempDir()
	git(t, work, "init", "--quiet")
	writeTree(t, work, map[string]string{"env/hosts.yml": "hosts: {}\n"})
	git(t, work, "add", "-A")
	git(t, work, "commit", "--quiet", "-m", "x")
	head := git(t, work, "rev-parse", "HEAD")
	git(t, work, "update-index", "--add", "--cacheinfo", "160000,"+head+",env/sub")
	git(t, work, "commit", "--quiet", "-m", "submodule")
	repo, err = openGitCache(t.TempDir(), work, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	commit, err = repo.resolve(context.Background(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildSnapshot(context.Background(), repo, SourceConfig{URL: work, Ref: "main", Subdir: "env"}, commit, "prod", "t", "t"); !hasCode(err, CodeSnapshotInvalid) || !strings.Contains(err.Error(), "commit") {
		t.Fatalf("submodule: %v", err)
	}
}

func TestDockerCommands(t *testing.T) {
	tgt := TargetConfig{Docker: "docker", Env: "prod", EnvRoot: "/srv/env"}
	session := strings.Join(sessionCommand(tgt, "pilot-cli:latest", "observe"), " ")
	want := "docker run --rm -i --init --pull never --log-driver none --cap-drop ALL --security-opt no-new-privileges " +
		"--mount type=bind,source=/srv/env/prod/.vault,target=/pilot/vault,readonly " +
		"--mount type=bind,source=/srv/env/prod/.pilot-data,target=/pilot/data " +
		"--entrypoint /usr/local/bin/pilot pilot-cli:latest mcp remote session --protocol v1 --mode observe --env prod"
	if session != want {
		t.Fatalf("session command\n got %s\nwant %s", session, want)
	}
	changes := strings.Join(changesCommand(tgt, "pilot-cli:latest", strings.Repeat("a", 32)), " ")
	if strings.Contains(changes, " -i ") || strings.Contains(changes, ".vault") || !strings.Contains(changes, "remote changes --protocol v1 --env prod "+strings.Repeat("a", 32)) {
		t.Fatalf("changes command = %s", changes)
	}
	tgt.NetworkHost = true
	if !strings.Contains(strings.Join(versionCommand(tgt, "pilot-cli:v2"), " "), "--network host --entrypoint /usr/local/bin/pilot pilot-cli:v2 mcp remote version") {
		t.Fatal("version command missing --network host")
	}
	for _, argv := range [][]string{sessionCommand(tgt, "pilot-cli:latest", "edit"), changesCommand(tgt, "pilot-cli:latest", "x")} {
		for _, a := range argv {
			if a == "-e" || a == "--env-file" || strings.HasPrefix(a, "-e=") {
				t.Fatalf("docker command passes environment: %v", argv)
			}
		}
	}
	quoted, err := shellJoin([]string{"docker", "run", "--mount", "type=bind,source=/a,target=/b,readonly"})
	if err != nil || quoted != "'docker' 'run' '--mount' 'type=bind,source=/a,target=/b,readonly'" {
		t.Fatalf("shellJoin = %q, %v", quoted, err)
	}
	if _, err := shellJoin([]string{"it's"}); err == nil {
		t.Fatal("a quote was quoted instead of refused")
	}
}

func TestSSHArgsAreFixed(t *testing.T) {
	p := testProfile("https://github.com/o/r", ".", "observe")
	args := strings.Join(sshArgs(p, "/home/u/.ssh/config", "'docker'"), " ")
	for _, want := range []string{"-T", "-e none", "BatchMode=yes", "ForwardAgent=no", "ClearAllForwardings=yes", "StrictHostKeyChecking=yes", "RemoteCommand=none", "RequestTTY=no", "ServerAliveInterval=30", "ConnectTimeout=15", "-F /home/u/.ssh/config"} {
		if !strings.Contains(args, want) {
			t.Errorf("ssh args missing %q: %s", want, args)
		}
	}
	if !strings.HasSuffix(args, "deploy 'docker'") {
		t.Fatalf("ssh args end = %s", args)
	}
}
