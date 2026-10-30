package mcpclient

import (
	"archive/tar"
	"bufio"
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
)

func connectOptions(t *testing.T, scenario, mode string) (*Options, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	allowLocalRepos(t)
	bare, _ := makeRepo(t, map[string]string{"prod/hosts.yml": "hosts: {}\n", "prod/group_vars/all.yml": "a: 1\n"})
	p := testProfile(bare, "prod", mode)
	log := useFakeSSH(t, scenario, p)
	var stdout, stderr bytes.Buffer
	return &Options{
		ProfileName: "prod-" + mode, Profile: p,
		Stdin: strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"), Stdout: &stdout, Stderr: &stderr,
		CacheDir: t.TempDir(), StatePath: filepath.Join(t.TempDir(), "sessions.jsonl"),
		ClientVersion: "test", ClientUser: "tester",
	}, &stdout, &stderr, log
}

func TestConnectRelaysOnlyMCPBytesAfterTheReadyLine(t *testing.T) {
	for _, scenario := range []string{"echo", "noise"} {
		t.Run(scenario, func(t *testing.T) {
			o, stdout, stderr, log := connectOptions(t, scenario, mcpwire.ModeObserve)
			if err := Connect(context.Background(), o); err != nil {
				t.Fatalf("Connect: %v\nstderr: %s", err, stderr.String())
			}
			want := "early\n" + `{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"
			if stdout.String() != want {
				t.Fatalf("agent stdout = %q, want only MCP bytes %q", stdout.String(), want)
			}
			if scenario == "noise" && !strings.Contains(stderr.String(), "Welcome to the deploy node") {
				t.Fatalf("pre-ready noise not reported on stderr: %s", stderr.String())
			}
			records, err := ReadRecords(o.StatePath, o.ProfileName)
			if err != nil || len(records) != 1 || records[0].SessionID != strings.Repeat("c", 32) || records[0].Image != "pilot-cli:latest" {
				t.Fatalf("records = %+v, %v", records, err)
			}
			argv, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			remote := string(argv[strings.LastIndex(string(argv), "\n")+1:])
			if !strings.HasPrefix(remote, "'docker' 'run' '--rm' '-i'") || !strings.Contains(remote, "'--mode' 'observe' '--env' 'prod'") {
				t.Fatalf("remote command = %s", remote)
			}
		})
	}
}

func TestConnectFailuresAreMappedAndNeverReachStdout(t *testing.T) {
	cases := []struct {
		scenario, code, remote string
		exit                   int
	}{
		{"exit255", CodeSSHFailed, "", 5},
		{"reject", CodeRemoteRejected, mcpwire.CodeEnvMismatch, 6},
		{"exit125", CodeDockerFailed, "", 7},
		{"panic", CodeRemoteRuntime, "", 7},
		{"wrong-mode", CodeRemoteRejected, "", 6},
	}
	for _, tc := range cases {
		t.Run(tc.scenario, func(t *testing.T) {
			o, stdout, _, _ := connectOptions(t, tc.scenario, mcpwire.ModeObserve)
			err := Connect(context.Background(), o)
			e, ok := err.(*Error)
			if !ok || e.Code != tc.code || e.RemoteCode != tc.remote || e.ExitCode() != tc.exit {
				t.Fatalf("err = %#v, want code %s remote %q exit %d", err, tc.code, tc.remote, tc.exit)
			}
			if stdout.Len() != 0 {
				t.Fatalf("agent stdout = %q on failure", stdout.String())
			}
		})
	}
}

func TestConnectRequiresAnImage(t *testing.T) {
	o, _, _, _ := connectOptions(t, "echo", mcpwire.ModeObserve)
	o.Profile.Target.Image = ""
	if err := Connect(context.Background(), o); !hasCode(err, CodeProfileInvalid) {
		t.Fatalf("err = %v", err)
	}
	o.Image = "pilot-cli:v2"
	if err := Connect(context.Background(), o); err != nil {
		t.Fatalf("--image override: %v", err)
	}
}

func TestReadReadyBoundsNoise(t *testing.T) {
	var stderr bytes.Buffer
	noise := strings.Repeat("x", maxPreReadyNoise+10) + "\n"
	if _, err := readReady(bufio.NewReader(strings.NewReader(noise)), &stderr); err == nil {
		t.Fatal("unbounded noise accepted")
	}
	long := strings.Repeat("y", 3*4096) // one long line without a newline
	if _, err := readReady(bufio.NewReaderSize(strings.NewReader(long), 4096), &stderr); err == nil {
		t.Fatal("EOF before ready accepted")
	}
}

func TestRemoteFailureMapping(t *testing.T) {
	cases := []struct {
		exit   int
		stderr string
		code   string
	}{
		{255, "ssh: Permission denied (publickey)", CodeSSHFailed},
		{65, mcpwire.ErrorLine(mcpwire.CodeChangesetInvalid, "x"), CodeChangesetInvalid},
		{66, mcpwire.ErrorLine(mcpwire.CodeRuntimeError, "x"), CodeRemoteRuntime},
		{64, "noise\n" + mcpwire.ErrorLine(mcpwire.CodeProtocolUnsupported, "x"), CodeRemoteRejected},
		{125, "docker: Error response from daemon", CodeDockerFailed},
		{127, "sh: docker: not found", CodeDockerFailed},
		{1, "Error: unknown command \"remote\" for \"pilot mcp\"", CodeRemoteRuntime},
	}
	for _, tc := range cases {
		if got := remoteFailure(tc.exit, tc.stderr); got.Code != tc.code {
			t.Errorf("exit %d %q → %s, want %s", tc.exit, tc.stderr, got.Code, tc.code)
		}
	}
	if got := remoteFailure(1, "unknown command"); !strings.Contains(got.Msg, "doctor") {
		t.Error("an old image's failure does not point at doctor")
	}
}

func TestDoctorStopsAtTheFirstFailure(t *testing.T) {
	o, _, _, _ := connectOptions(t, "exit255", mcpwire.ModeObserve)
	rep := Doctor(context.Background(), o)
	statuses := map[string]string{}
	for _, c := range rep.Checks {
		statuses[c.ID] = c.Status
	}
	if statuses["profile"] != "pass" || statuses["git"] != "pass" || statuses["snapshot"] != "pass" || statuses["remote-version"] != "fail" || statuses["session"] != "skip" || statuses["mcp-tools"] != "skip" {
		t.Fatalf("checks = %+v", rep.Checks)
	}
	if rep.OK() || rep.CommitSHA == "" || rep.ContentDigest == "" {
		t.Fatalf("report = %+v", rep)
	}
	for _, c := range rep.Checks {
		if c.ID == "remote-version" && c.ReasonCode != CodeSSHFailed {
			t.Fatalf("reason = %s", c.ReasonCode)
		}
	}
}

// changesTar builds what `pilot mcp remote changes` would print.
func changesTar(t *testing.T, m mcpwire.ChangesManifest, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	data, _ := json.Marshal(m)
	write := func(name, content string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, content); err != nil {
			t.Fatal(err)
		}
	}
	write(mcpwire.ChangesManifestName, string(data))
	for p, c := range files {
		write(p, c)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "changes.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func change(p, op, base, content string) mcpwire.Change {
	c := mcpwire.Change{Path: p, Op: op, BaseSHA256: base}
	if op != mcpwire.OpDelete {
		c.NewSHA256 = mcpwire.SHA256Hex([]byte(content))
	}
	return c
}

func TestChangesWritesIntoACleanCloneAndRefusesConflicts(t *testing.T) {
	allowLocalRepos(t)
	bare, base := makeRepo(t, map[string]string{
		"prod/hosts.yml": "hosts: {}\n", "prod/group_vars/all.yml": "a: 1\n", "prod/old.yml": "x\n", "prod/.gitignore": "/inventory.yml\n",
	})
	id := strings.Repeat("d", 32)
	m := mcpwire.ChangesManifest{Protocol: mcpwire.Protocol, SessionID: id, Env: "prod", BaseCommitSHA: base, Changes: []mcpwire.Change{
		change("group_vars/all.yml", mcpwire.OpModify, "", "a: 2\n"),
		change("host_vars/web-1.yml", mcpwire.OpAdd, "", "b: 1\n"),
		change("old.yml", mcpwire.OpDelete, "", ""),
		change("inventory.yml", mcpwire.OpAdd, "", "generated\n"),
	}}
	tarPath := changesTar(t, m, map[string]string{"group_vars/all.yml": "a: 2\n", "host_vars/web-1.yml": "b: 1\n", "inventory.yml": "generated\n"})

	run := func(clone string) (*ChangesResult, error) {
		p := testProfile(bare, "prod", mcpwire.ModeEdit)
		useFakeSSH(t, "changes", p)
		t.Setenv("PILOT_MCP_FAKE_CHANGES", tarPath)
		o := &Options{ProfileName: "prod-edit", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir()}
		return Changes(context.Background(), o, id, clone)
	}

	clone := t.TempDir()
	git(t, clone, "clone", "--quiet", bare, ".")
	res, err := run(clone)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Written, ",") != "prod/group_vars/all.yml,prod/host_vars/web-1.yml" || strings.Join(res.Deleted, ",") != "prod/old.yml" || strings.Join(res.Ignored, ",") != "prod/inventory.yml" {
		t.Fatalf("result = %+v", res)
	}
	got, _ := os.ReadFile(filepath.Join(clone, "prod", "group_vars", "all.yml"))
	if string(got) != "a: 2\n" {
		t.Fatalf("written content = %q", got)
	}
	if _, err := os.Stat(filepath.Join(clone, "prod", "old.yml")); !os.IsNotExist(err) {
		t.Fatal("deleted file still exists")
	}
	if _, err := os.Stat(filepath.Join(clone, "prod", "inventory.yml")); !os.IsNotExist(err) {
		t.Fatal("ignored file was written")
	}

	// A dirty clone, a clone whose HEAD changed the file, a symlinked
	// directory and a clone of another repository are all refused.
	dirty := t.TempDir()
	git(t, dirty, "clone", "--quiet", bare, ".")
	writeTree(t, dirty, map[string]string{"prod/scratch.txt": "x"})
	if _, err := run(dirty); !hasCode(err, CodeChangesetConflict) {
		t.Fatalf("dirty clone: %v", err)
	}
	moved := t.TempDir()
	git(t, moved, "clone", "--quiet", bare, ".")
	writeTree(t, moved, map[string]string{"prod/group_vars/all.yml": "a: 3\n"})
	git(t, moved, "commit", "--quiet", "-am", "someone else")
	if _, err := run(moved); !hasCode(err, CodeChangesetConflict) {
		t.Fatalf("moved HEAD: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(moved, "prod", "host_vars", "web-1.yml")); len(b) != 0 {
		t.Fatal("a refused import still wrote a file")
	}
	linked := t.TempDir()
	git(t, linked, "clone", "--quiet", bare, ".")
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, "prod", "host_vars")); err != nil {
		t.Fatal(err)
	}
	git(t, linked, "add", "-A")
	git(t, linked, "commit", "--quiet", "-m", "link")
	if _, err := run(linked); !hasCode(err, CodeChangesetConflict) || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked directory: %v", err)
	}
	other, _ := makeRepo(t, map[string]string{"x": "y"})
	otherClone := t.TempDir()
	git(t, otherClone, "clone", "--quiet", other, ".")
	if _, err := run(otherClone); !hasCode(err, CodeChangesetConflict) {
		t.Fatalf("other repository: %v", err)
	}
}

// A remote that keeps writing past the stream limit is stopped, not
// waited for: waiting on ssh blocked on a full pipe never returns.
func TestChangesStopsAnOversizedStream(t *testing.T) {
	p := testProfile("https://example.invalid/org/config.git", "prod", mcpwire.ModeEdit)
	useFakeSSH(t, "changes-flood", p)
	o := &Options{ProfileName: "prod-edit", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir()}
	done := make(chan error, 1)
	go func() {
		_, err := Changes(context.Background(), o, strings.Repeat("d", 32), t.TempDir())
		done <- err
	}()
	select {
	case err := <-done:
		if !hasCode(err, CodeChangesetInvalid) || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("err = %v, want CHANGESET_INVALID", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Changes hung on an oversized stream")
	}
}

// A failure part way through names what was already applied, and leaves
// no temporary file behind.
func TestChangesReportsAPartialImport(t *testing.T) {
	allowLocalRepos(t)
	bare, base := makeRepo(t, map[string]string{"prod/hosts.yml": "hosts: {}\n", "prod/b.yml/keep": "x\n"})
	id := strings.Repeat("d", 32)
	m := mcpwire.ChangesManifest{Protocol: mcpwire.Protocol, SessionID: id, Env: "prod", BaseCommitSHA: base, Changes: []mcpwire.Change{
		change("a.yml", mcpwire.OpAdd, "", "a: 1\n"),
		change("b.yml", mcpwire.OpAdd, "", "b: 1\n"), // a directory in the clone: the rename fails
	}}
	tarPath := changesTar(t, m, map[string]string{"a.yml": "a: 1\n", "b.yml": "b: 1\n"})
	p := testProfile(bare, "prod", mcpwire.ModeEdit)
	useFakeSSH(t, "changes", p)
	t.Setenv("PILOT_MCP_FAKE_CHANGES", tarPath)
	clone := t.TempDir()
	git(t, clone, "clone", "--quiet", bare, ".")
	o := &Options{ProfileName: "prod-edit", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir()}
	_, err := Changes(context.Background(), o, id, clone)
	if err == nil || !strings.Contains(err.Error(), "prod/b.yml") || !strings.Contains(err.Error(), "already applied before the failure: prod/a.yml") {
		t.Fatalf("err = %v, want the failed path and what was already applied", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(clone, "prod", ".*.pilot-mcp-tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
}

func TestParseChangesRejectsTamperedOutput(t *testing.T) {
	id := strings.Repeat("e", 32)
	base := mcpwire.ChangesManifest{Protocol: mcpwire.Protocol, SessionID: id, Env: "prod", BaseCommitSHA: "abc",
		Changes: []mcpwire.Change{change("a.yml", mcpwire.OpAdd, "", "ok\n")}}
	read := func(path string) []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, _, err := parseChanges(read(changesTar(t, base, map[string]string{"a.yml": "ok\n"})), id, "prod"); err != nil {
		t.Fatalf("valid changes rejected: %v", err)
	}
	cases := map[string][]byte{
		"sha mismatch":  read(changesTar(t, base, map[string]string{"a.yml": "tampered\n"})),
		"extra file":    read(changesTar(t, base, map[string]string{"a.yml": "ok\n", "b.yml": "x"})),
		"missing file":  read(changesTar(t, base, nil)),
		"other session": read(changesTar(t, mcpwire.ChangesManifest{Protocol: mcpwire.Protocol, SessionID: strings.Repeat("f", 32), Env: "prod", BaseCommitSHA: "abc"}, nil)),
		"escaping path": read(changesTar(t, mcpwire.ChangesManifest{Protocol: mcpwire.Protocol, SessionID: id, Env: "prod", BaseCommitSHA: "abc", Changes: []mcpwire.Change{change("../x", mcpwire.OpAdd, "", "x")}}, map[string]string{"../x": "x"})),
		"reserved path": read(changesTar(t, mcpwire.ChangesManifest{Protocol: mcpwire.Protocol, SessionID: id, Env: "prod", BaseCommitSHA: "abc", Changes: []mcpwire.Change{change(".vault/main.yaml", mcpwire.OpAdd, "", "x")}}, map[string]string{".vault/main.yaml": "x"})),
		// On a case-insensitive clone (macOS) this is the clone's .git.
		"case-folded .git": read(changesTar(t, mcpwire.ChangesManifest{Protocol: mcpwire.Protocol, SessionID: id, Env: "prod", BaseCommitSHA: "abc", Changes: []mcpwire.Change{change(".GIT/config", mcpwire.OpAdd, "", "x")}}, map[string]string{".GIT/config": "x"})),
		"not a tar":        []byte("garbage"),
		"wrong first":      read(changesTar(t, base, nil))[512:],
	}
	for name, data := range cases {
		if _, _, err := parseChanges(data, id, "prod"); !hasCode(err, CodeChangesetInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestLatestEditSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	for _, r := range []Record{
		{Time: time.Now(), Profile: "p", Mode: mcpwire.ModeEdit, SessionID: "old"},
		{Time: time.Now(), Profile: "p", Mode: mcpwire.ModeObserve, SessionID: "observe"},
		{Time: time.Now(), Profile: "q", Mode: mcpwire.ModeEdit, SessionID: "other"},
		{Time: time.Now(), Profile: "p", Mode: mcpwire.ModeEdit, SessionID: "new"},
	} {
		if err := appendRecord(path, r); err != nil {
			t.Fatal(err)
		}
	}
	if id, err := LatestEditSession(path, "p"); err != nil || id != "new" {
		t.Fatalf("latest = %s, %v", id, err)
	}
	if _, err := LatestEditSession(path, "none"); !hasCode(err, CodeProfileInvalid) {
		t.Fatalf("no session: %v", err)
	}
}
