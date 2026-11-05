package mcpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// These tests (spec §13.2) run pilot-mcp in process against a real sshd
// on 127.0.0.1 whose "docker" is the fake in integration_helpers_test.go,
// which execs the real pilot binary's `mcp remote`.

const itHosts = "vars:\n  ansible_ssh_private_key_file: \"/pilot/config/.vault/id_ed25519\"\nhosts:\n  web-1:\n    ansible_host: \"192.0.2.10\"\n    roles: [docker]\n    env: prod\n"

func itRepo(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := map[string]string{
		"prod/hosts.yml":          itHosts,
		"prod/group_vars/all.yml": "a: 1\n",
		"prod/.gitignore":         "/inventory.yml\n",
		"staging/hosts.yml":       strings.ReplaceAll(itHosts, "env: prod", "env: staging"),
	}
	for k, v := range extra {
		files[k] = v
	}
	bare, _ := makeRepo(t, files)
	return bare
}

// firstByte records the first byte written to the agent's stdout.
type firstByte struct {
	io.Writer
	mu    sync.Mutex
	first int
}

func (f *firstByte) Write(p []byte) (int, error) {
	f.mu.Lock()
	if f.first == 0 && len(p) > 0 {
		f.first = int(p[0])
	}
	f.mu.Unlock()
	return f.Writer.Write(p)
}

type liveSession struct {
	mcp    *mcp.ClientSession
	done   chan error
	stderr *lockedBuffer
	out    *firstByte
}

// connectLive runs Connect in process and attaches an MCP client to the
// agent side of its stdio.
func connectLive(t *testing.T, p Profile, profileName string) *liveSession {
	t.Helper()
	agentIn, clientIn := io.Pipe()   // agent writes requests; Connect reads them
	clientOut, agentOut := io.Pipe() // Connect writes replies; the agent reads them
	ls := &liveSession{done: make(chan error, 1), stderr: &lockedBuffer{}, out: &firstByte{Writer: agentOut}}
	o := &Options{ProfileName: profileName, Profile: p, Stdin: agentIn, Stdout: ls.out, Stderr: ls.stderr,
		CacheDir: t.TempDir(), StatePath: filepath.Join(t.TempDir(), "sessions.jsonl"), ClientVersion: "it", ClientUser: "tester"}
	go func() {
		err := Connect(context.Background(), o)
		_ = agentOut.Close()
		ls.done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "it-agent", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientOut, Writer: clientIn}, nil)
	if err != nil {
		select {
		case cerr := <-ls.done:
			t.Fatalf("connect: %v (pilot-mcp: %v)\nstderr: %s", err, cerr, ls.stderr.String())
		default:
		}
		t.Fatalf("MCP initialize: %v\nstderr: %s", err, ls.stderr.String())
	}
	ls.mcp = session
	// Even when the test fails early, close the agent side so the remote
	// session, ssh and Connect all end.
	t.Cleanup(func() { session.Close() }) //nolint:errcheck
	return ls
}

// end closes the agent side and waits for Connect to return.
func (ls *liveSession) end(t *testing.T) {
	t.Helper()
	ls.mcp.Close() //nolint:errcheck
	select {
	case err := <-ls.done:
		if err != nil {
			t.Fatalf("Connect: %v\nstderr: %s", err, ls.stderr.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Connect did not return after the agent closed")
	}
}

// lockedBuffer is a bytes.Buffer safe to write from one goroutine (or
// process pipe copier) while the test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func toolNames(t *testing.T, s *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

func callTool(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func structured(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	data, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("structured content %s: %v", data, err)
	}
	return out
}

func resultText(res *mcp.CallToolResult) string {
	data, _ := json.Marshal(res)
	return string(data)
}

func TestIntegrationObserveSession(t *testing.T) {
	allowLocalRepos(t)
	node := startDeployNode(t, true) // I04: the login shell prints noise first
	t.Setenv("GITHUB_TOKEN", "gh-marker-7f3a")
	t.Setenv("GH_TOKEN", "gh-marker-7f3a")
	repo := itRepo(t, map[string]string{"prod/.vault/stray.yaml": "x: 1\n"})
	p := node.profileFor(repo, "prod", mcpwire.ModeObserve, "prod")

	ls := connectLive(t, p, "prod-observe")
	// I01, I02: the real server answers, with the observe tool set.
	if err := mcpwire.CheckTools(mcpwire.ModeObserve, toolNames(t, ls.mcp)); err != nil {
		t.Fatal(err)
	}
	inspect := callTool(t, ls.mcp, "pilot_edit_inspect", map[string]any{})
	if inspect.IsError || !strings.Contains(resultText(inspect), "web-1") {
		t.Fatalf("inspect = %s", resultText(inspect))
	}
	// I16: delivery tools find the generated inventory and the catalog.
	delivery := callTool(t, ls.mcp, "pilot_diagnose_delivery", map[string]any{"host": "web-1", "component": "docker"})
	if text := resultText(delivery); delivery.IsError || strings.Contains(text, "inventory file not found") || strings.Contains(text, "contract root") {
		t.Fatalf("delivery = %s", text)
	}
	t.Logf("delivery: %.300s", resultText(delivery))
	ls.end(t)

	if ls.out.first != '{' {
		t.Fatalf("first byte to the agent = %q, want JSON-RPC", rune(ls.out.first))
	}
	stderr := ls.stderr.String()
	if !strings.Contains(stderr, "Last login: from the fake login shell") {
		t.Errorf("pre-ready noise not reported on stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "not sent (provided by the deploy node or reserved): .vault/stray.yaml") {
		t.Errorf("reserved path not reported (I09):\n%s", stderr)
	}
	if entries, _ := os.ReadDir(filepath.Join(node.envRoot, "prod", ".pilot-data", "mcp", "sessions")); len(entries) != 0 {
		t.Errorf("observe session left %d entries in the data dir", len(entries))
	}
	// I14: only the profile's environment was mounted, .vault read-only.
	for _, argv := range node.dockerInvocations(t) {
		joined := strings.Join(argv, " ")
		if strings.Contains(joined, "/staging/") {
			t.Errorf("staging mounted: %s", joined)
		}
		if strings.Contains(joined, "/prod/.vault") && !strings.Contains(joined, "/prod/.vault,target=/pilot/vault,readonly") {
			t.Errorf(".vault not read-only: %s", joined)
		}
	}
	// I11: the client's GitHub token never reaches the deploy node.
	assertMarkerAbsent(t, node, "gh-marker-7f3a")
}

func assertMarkerAbsent(t *testing.T, node *deployNode, marker string) {
	t.Helper()
	root := filepath.Dir(node.envRoot)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err == nil && bytes.Contains(data, []byte(marker)) {
			t.Errorf("%s contains the client token", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationEditSessionAndChanges(t *testing.T) {
	allowLocalRepos(t)
	node := startDeployNode(t, false)
	repo := itRepo(t, nil)
	p := node.profileFor(repo, "prod", mcpwire.ModeEdit, "prod")

	ls := connectLive(t, p, "prod-edit")
	if err := mcpwire.CheckTools(mcpwire.ModeEdit, toolNames(t, ls.mcp)); err != nil {
		t.Fatal(err)
	}
	rev := structured(t, callTool(t, ls.mcp, "pilot_edit_inspect", map[string]any{}))["workspace_revision"].(string)
	plan := callTool(t, ls.mcp, "pilot_edit_plan", map[string]any{"base_revision": rev, "scenario": map[string]any{
		"version": 1, "title": "it edit", "steps": []any{
			map[string]any{"action": "set_host_field", "host": "web-1", "field": "ansible_host", "value": "192.0.2.11"},
			map[string]any{"action": "save_hosts"},
		}}})
	if plan.IsError {
		t.Fatalf("plan = %s", resultText(plan))
	}
	planID := structured(t, plan)["plan_id"].(string)
	apply := callTool(t, ls.mcp, "pilot_edit_apply", map[string]any{"plan_id": planID, "expected_revision": rev})
	if apply.IsError || structured(t, apply)["result"] != "applied" {
		t.Fatalf("apply = %s", resultText(apply))
	}

	// I12: a vault write cannot land: there is no secret in the
	// environment and the .vault mount is read-only.
	vaultFile := filepath.Join(node.envRoot, "prod", ".vault", "main.yaml")
	before, _ := os.ReadFile(vaultFile)
	rev2 := structured(t, callTool(t, ls.mcp, "pilot_edit_inspect", map[string]any{}))["workspace_revision"].(string)
	vplan := callTool(t, ls.mcp, "pilot_edit_plan", map[string]any{"base_revision": rev2, "scenario": map[string]any{
		"version": 1, "title": "it vault", "steps": []any{
			map[string]any{"action": "set_vault_value", "file": "main.yaml", "key": "vault_token", "value_env": "HOME"},
			map[string]any{"action": "save_vault", "file": "main.yaml"},
		}}})
	t.Logf("vault plan: %.400s", resultText(vplan))
	if !vplan.IsError {
		if id, ok := structured(t, vplan)["plan_id"].(string); ok {
			vapply := callTool(t, ls.mcp, "pilot_edit_apply", map[string]any{"plan_id": id, "expected_revision": rev2})
			if !vapply.IsError && structured(t, vapply)["result"] == "applied" {
				t.Fatalf("a vault write was applied: %s", resultText(vapply))
			}
		}
	}
	if after, _ := os.ReadFile(vaultFile); !bytes.Equal(before, after) {
		t.Fatal(".vault changed")
	}
	ls.end(t)

	// I03: changes brings the hosts.yml edit (and nothing generated) back.
	clone := t.TempDir()
	git(t, clone, "clone", "--quiet", repo, ".")
	o := &Options{ProfileName: "prod-edit", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir()}
	id := sessionIDFrom(t, ls.stderr.String())
	res, err := Changes(context.Background(), o, id, clone)
	if err != nil {
		t.Fatalf("changes: %v", err)
	}
	if strings.Join(res.Written, ",") != "prod/hosts.yml" || len(res.Deleted) != 0 {
		t.Fatalf("changes = %+v, want only prod/hosts.yml", res)
	}
	hosts, _ := os.ReadFile(filepath.Join(clone, "prod", "hosts.yml"))
	if !strings.Contains(string(hosts), "192.0.2.11") {
		t.Fatalf("hosts.yml after changes:\n%s", hosts)
	}
}

func sessionIDFrom(t *testing.T, stderr string) string {
	t.Helper()
	const prefix = "pilot-mcp: session "
	i := strings.Index(stderr, prefix)
	if i < 0 {
		t.Fatalf("no session line in stderr:\n%s", stderr)
	}
	id := stderr[i+len(prefix) : i+len(prefix)+32]
	if !mcpwire.ValidSessionID(id) {
		t.Fatalf("session id %q", id)
	}
	return id
}

func TestIntegrationRejections(t *testing.T) {
	allowLocalRepos(t)
	node := startDeployNode(t, false)
	cases := []struct {
		name   string
		extra  map[string]string
		env    string
		remote string
	}{
		{"I13 env mismatch", nil, "staging", mcpwire.CodeEnvMismatch},
		{"I10 plaintext secret", map[string]string{"prod/group_vars/dashboard.yml": "grafana_admin_password: \"it-plaintext-77\"\n"}, "prod", mcpwire.CodeSecretPolicyViolation},
		{"I17 path out of scope", map[string]string{"prod/group_vars/all.yml": "freeipa_roster_file: /pilot/data/roster.yaml\n"}, "prod", mcpwire.CodePathOutOfScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := node.profileFor(itRepo(t, tc.extra), "prod", mcpwire.ModeObserve, tc.env)
			var stdout, stderr bytes.Buffer
			o := &Options{ProfileName: "x", Profile: p, Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
				CacheDir: t.TempDir(), StatePath: filepath.Join(t.TempDir(), "s.jsonl")}
			err := Connect(context.Background(), o)
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeRemoteRejected || e.RemoteCode != tc.remote {
				t.Fatalf("err = %v, want REMOTE_REJECTED/%s\nstderr: %s", err, tc.remote, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("agent stdout = %q", stdout.String())
			}
			if strings.Contains(err.Error()+stderr.String(), "it-plaintext-77") {
				t.Fatal("the secret value was printed")
			}
		})
	}
}

func TestIntegrationConcurrentSessionsSeeTheirOwnCommit(t *testing.T) {
	allowLocalRepos(t)
	node := startDeployNode(t, false)
	repo := itRepo(t, nil)
	work := t.TempDir()
	git(t, work, "clone", "--quiet", repo, ".")
	git(t, work, "checkout", "--quiet", "-b", "other")
	writeTree(t, work, map[string]string{"prod/hosts.yml": strings.ReplaceAll(itHosts, "web-1", "web-2")})
	git(t, work, "commit", "--quiet", "-am", "other host")
	git(t, work, "push", "--quiet", "origin", "other")

	main := node.profileFor(repo, "prod", mcpwire.ModeObserve, "prod")
	other := main
	other.Source.Ref = "other"
	a := connectLive(t, main, "a")
	b := connectLive(t, other, "b")
	ta := resultText(callTool(t, a.mcp, "pilot_edit_inspect", map[string]any{}))
	tb := resultText(callTool(t, b.mcp, "pilot_edit_inspect", map[string]any{}))
	if !strings.Contains(ta, "web-1") || strings.Contains(ta, "web-2") || !strings.Contains(tb, "web-2") || strings.Contains(tb, "web-1") {
		t.Fatalf("sessions see each other's configuration:\nA: %s\nB: %s", ta, tb)
	}
	a.end(t)
	b.end(t)
}

func TestIntegrationKilledClientEndsTheRemote(t *testing.T) {
	allowLocalRepos(t)
	node := startDeployNode(t, false)
	p := node.profileFor(itRepo(t, nil), "prod", mcpwire.ModeObserve, "prod")
	opts, err := json.Marshal(Options{ProfileName: "k", Profile: p, CacheDir: t.TempDir(), StatePath: filepath.Join(t.TempDir(), "s.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0])
	child.Env = append(os.Environ(), "PILOT_MCP_RUN_CONNECT="+string(opts))
	stdin, err := child.StdinPipe() // held open: the agent is "still there"
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var stderr lockedBuffer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	var pid int
	deadline := time.Now().Add(120 * time.Second)
	for pid == 0 || !strings.Contains(stderr.String(), "pilot-mcp: session ") {
		if time.Now().After(deadline) {
			t.Fatalf("session did not start:\n%s", stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
		if data, err := os.ReadFile(node.pidFile); err == nil {
			pid, _ = strconv.Atoi(string(data))
		}
	}
	if err := child.Process.Kill(); err != nil { // SIGKILL pilot-mcp
		t.Fatal(err)
	}
	_ = child.Wait()
	deadline = time.Now().Add(30 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("remote pilot (pid %d) still running 30s after pilot-mcp was killed", pid)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestIntegrationDoctor(t *testing.T) {
	allowLocalRepos(t)
	node := startDeployNode(t, false)
	for _, mode := range []string{mcpwire.ModeObserve, mcpwire.ModeEdit} {
		p := node.profileFor(itRepo(t, nil), "prod", mode, "prod")
		o := &Options{ProfileName: "d", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir(), StatePath: filepath.Join(t.TempDir(), "s.jsonl"), ClientVersion: "it"}
		rep := Doctor(context.Background(), o)
		if !rep.OK() {
			data, _ := json.MarshalIndent(rep, "", "  ")
			t.Fatalf("doctor %s failed:\n%s", mode, data)
		}
		if rep.PilotBinarySHA256 == "" || rep.CommitSHA == "" {
			t.Fatalf("report = %+v", rep)
		}
	}
}
