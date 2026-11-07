package identityreconcile

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sshdial"
)

// TestLiveGoApplyDriver is the Phase 2 part of the Go reconcile test driver (spec §10.2): the arms of
// the users-groups scope against a disposable FreeIPA server and an enrolled client, driving only the
// pilot binaries it builds. It runs only when PILOT_IDENTITY_ENGINE_LIVE_APPLY names the baseline
// snapshot of the two VMs (an enrolled client and its server; a paired snapshot of each):
//
//	PILOT_IDENTITY_ENGINE_LIVE_APPLY       the snapshot tag both VMs are first reverted to
//	PILOT_IDENTITY_ENGINE_LIVE_SERVER_VM   the server's vm-target name
//	PILOT_IDENTITY_ENGINE_LIVE_CLIENT_VM   the client's
//	PILOT_IDENTITY_ENGINE_LIVE_WORKSPACE   a workspace to copy: hosts.yml, inventory.yml, group_vars/freeipa.yml, .vault/main.yaml
//	PILOT_IDENTITY_ENGINE_LIVE_CLIENT_FQDN the client's FQDN as the workspace names it
//	PILOT_IDENTITY_ENGINE_LIVE_CLIENT_SSH  root@<address>, with _CLIENT_KEY and _CLIENT_OPTS as the server's
//	PILOT_IDENTITY_ENGINE_LIVE_VAULT_PASS  the file ansible reads the vault password from
//	PILOT_IDENTITY_ENGINE_LIVE_ARMS        optional: comma-separated arm names (a prefix matches), default all
//	PILOT_IDENTITY_ENGINE_LIVE_SUMMARY     optional: where to write the JSON summary
//	PILOT_FREEIPA_LIVE_SSH[_KEY|_OPTS], IPA_ADMIN_PASSWORD   the server, as for the other live tests
//
// A failed arm is recorded and the next one runs; the test fails when any arm did. Nothing here
// prints a password: they are generated, written to 0600 files of a temporary directory, and given to
// pilot and ssh through the roster, the vault file and an askpass-free key login.
func TestLiveGoApplyDriver(t *testing.T) {
	base := os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_APPLY")
	if base == "" {
		t.Skip("PILOT_IDENTITY_ENGINE_LIVE_APPLY is not set")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	cli := sshdial.Target{Options: map[string]string{}}
	dest := mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_CLIENT_SSH")
	cli.Host, cli.IdentityFile = dest, os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_CLIENT_KEY")
	if user, host, ok := strings.Cut(dest, "@"); ok {
		cli.User, cli.Host = user, host
	}
	for _, kv := range strings.Split(os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_CLIENT_OPTS"), ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			cli.Options[k] = v
		}
	}
	lv := &labEnv{
		t: t, repo: repo, tmp: tmp, cp: "/tmp/p26cp",
		srvVM: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_SERVER_VM"), cliVM: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_CLIENT_VM"),
		srv: liveSSHTarget(t), cli: cli, baseTag: base,
		template: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_WORKSPACE"), cliFQDN: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_CLIENT_FQDN"),
		vaultPass: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_VAULT_PASS"), adminPW: mustEnv(t, "IPA_ADMIN_PASSWORD"),
	}
	lv.pilot, lv.pilotHooks = filepath.Join(tmp, "pilot"), filepath.Join(tmp, "pilot-hooks")
	run(t, repo, "go", "build", "-o", lv.pilot, "./cmd/pilot")
	run(t, repo, "go", "build", "-tags", "identity_live_hooks", "-o", lv.pilotHooks, "./cmd/pilot")
	lv.key = filepath.Join(tmp, "oracle-key")
	run(t, tmp, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", lv.key, "-C", "p26-oracle")
	pub, err := os.ReadFile(lv.key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	lv.pub = strings.TrimSpace(string(pub))

	summary := &applySummary{Revision: gitOut(t, repo, "rev-parse", "HEAD"), Tree: gitOut(t, repo, "rev-parse", "HEAD^{tree}"), BaseSnapshot: base, MaxBatch: MaxBatch}
	defer func() { writeApplySummary(t, summary) }()
	want := map[string]bool{}
	for _, a := range strings.Split(os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_ARMS"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			want[a] = true
		}
	}
	selected := func(name string) bool {
		if len(want) == 0 {
			return true
		}
		for w := range want {
			if strings.HasPrefix(name, w) {
				return true
			}
		}
		return false
	}
	d := &applyDriver{lv: lv, summary: summary, selected: selected, pws: map[string]string{}}
	d.runAll()
	for _, arm := range summary.Arms {
		if !arm.Pass && !arm.Skipped {
			t.Errorf("arm %s failed: %s", arm.Name, strings.Join(arm.Failures, "; "))
		}
	}
}

// ---- the summary ----

type applyArm struct {
	Name     string         `json:"name"`
	Pass     bool           `json:"pass"`
	Skipped  bool           `json:"skipped,omitempty"`
	Seconds  float64        `json:"seconds"`
	Failures []string       `json:"failures,omitempty"`
	Facts    map[string]any `json:"facts,omitempty"`
}

type applySummary struct {
	Revision     string     `json:"tested_revision"`
	Tree         string     `json:"tested_tree"`
	BaseSnapshot string     `json:"base_snapshot"`
	MaxBatch     int        `json:"batch_limit"`
	Arms         []applyArm `json:"arms"`
}

func writeApplySummary(t *testing.T, s *applySummary) {
	data, _ := json.MarshalIndent(s, "", "  ")
	t.Logf("summary:\n%s", data)
	if path := os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_SUMMARY"); path != "" {
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Error(err)
		}
	}
}

// ---- the arms ----

type applyDriver struct {
	lv       *labEnv
	summary  *applySummary
	selected func(string) bool
	pws      map[string]string // the roster users' passwords, by name
	// ackedTag is the snapshot A1 takes once the roster is applied and acknowledged: every other
	// arm starts from it.
	ackedTag string
}

// armCtx is one arm: its failures and facts, and what it ran.
type armCtx struct {
	d     *applyDriver
	lv    *labEnv
	name  string
	fails []string
	facts map[string]any
	data  string // the arm's pilot data directory
}

func (a *armCtx) fail(format string, args ...any) {
	a.fails = append(a.fails, fmt.Sprintf(format, args...))
}
func (a *armCtx) fact(k string, v any) { a.facts[k] = v }
func (a *armCtx) ok(cond bool, format string, args ...any) bool {
	if !cond {
		a.fail(format, args...)
	}
	return cond
}

func (d *applyDriver) arm(name string, f func(a *armCtx)) {
	if !d.selected(name) {
		return
	}
	a := &armCtx{d: d, lv: d.lv, name: name, facts: map[string]any{}}
	a.data = filepath.Join(d.lv.tmp, "data-"+strings.NewReplacer("/", "-", " ", "-").Replace(name))
	if err := os.MkdirAll(a.data, 0o700); err != nil {
		d.lv.t.Fatal(err)
	}
	start := time.Now()
	func() {
		defer func() {
			if r := recover(); r != nil {
				a.fail("panic: %v", r)
			}
		}()
		f(a)
	}()
	if _, ok := a.facts["journal_after"]; !ok {
		a.fact("journal_after", d.lv.journal())
	}
	rec := applyArm{Name: name, Pass: len(a.fails) == 0, Seconds: time.Since(start).Seconds(), Failures: a.fails, Facts: a.facts}
	d.summary.Arms = append(d.summary.Arms, rec)
	d.lv.t.Logf("arm %s: pass=%v (%.0fs) %s", name, rec.Pass, rec.Seconds, strings.Join(a.fails, "; "))
	writeApplySummary(d.lv.t, d.summary)
}

// fresh reverts both VMs to the baseline and checks the arm starts acked.
func (a *armCtx) fresh() bool {
	if err := a.lv.rollback(a.d.ackedTag); err != nil {
		a.fail("rollback: %v", err)
		return false
	}
	return a.ok(!a.lv.journal().Pending, "the baseline is not acked: the journal says an obligation is owed")
}

// ---- the run of an apply ----

type applyRun struct {
	pilotResult
	Doc     ApplyDocument
	HasDoc  bool
	Result  string
	Writes  map[string]int
	WriteN  int
	LogFrom int64
}

// apply runs the Go apply on ws and reads what it left: the result file and the writes the server logged.
func (a *armCtx) apply(ws string, extra ...string) applyRun {
	a.lv.t.Helper()
	logAt, _ := serverLogSize(a.lv.srv)
	result := filepath.Join(a.lv.tmp, fmt.Sprintf("result-%s-%d.json", strings.NewReplacer("/", "-", " ", "-").Replace(a.name), time.Now().UnixNano()))
	args := append([]string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--force", "--scope", "users-groups", "--result-out", result, "--timeout", "10m"}, extra...)
	r := a.lv.runPilot(a.lv.pilot, a.data, args, "PILOT_W_TEST_TOKEN=lab-token")
	return a.collect(r, result, logAt)
}

// applyLocal runs the Go apply and reads only what is on this machine: nothing is asked of the server,
// so a count of the server's ssh sessions around it counts pilot's alone.
func (a *armCtx) applyLocal(ws string, extra ...string) applyRun {
	a.lv.t.Helper()
	result := filepath.Join(a.lv.tmp, fmt.Sprintf("result-local-%d.json", time.Now().UnixNano()))
	args := append([]string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--force", "--scope", "users-groups", "--result-out", result, "--timeout", "10m"}, extra...)
	r := a.lv.runPilot(a.lv.pilot, a.data, args, "PILOT_W_TEST_TOKEN=lab-token")
	run := applyRun{pilotResult: r, Result: result}
	if doc, err := readApplyResult(result); err == nil {
		run.Doc, run.HasDoc = doc, true
	}
	return run
}

func (a *armCtx) collect(r pilotResult, result string, logAt int64) applyRun {
	run := applyRun{pilotResult: r, Result: result, LogFrom: logAt}
	if doc, err := readApplyResult(result); err == nil {
		run.Doc, run.HasDoc = doc, true
	}
	if w, err := a.lv.writesSince(logAt); err == nil {
		run.Writes = w
		for _, n := range w {
			run.WriteN += n
		}
	}
	a.recordRun(run)
	return run
}

// recordRun puts what a run left in the arm's facts, so the summary carries the real exit code, the
// result file's verdict and outcome and the writes the server logged for every run of every arm.
func (a *armCtx) recordRun(r applyRun) {
	rec := map[string]any{"exit": r.ExitCode, "result_file": r.HasDoc, "server_writes": r.Writes}
	if r.HasDoc {
		rec["verdict"], rec["outcome"], rec["failed_step"] = r.Doc.Verdict, r.Doc.Outcome, r.Doc.FailedStep
		rec["entry_ran"] = r.Doc.Entry.Ran
		rec["operations"] = len(r.Doc.Ops)
	}
	runs, _ := a.facts["runs"].([]map[string]any)
	a.facts["runs"] = append(runs, rec)
}

func (a *armCtx) preview(ws string) (pilotResult, Document, bool) {
	plan := filepath.Join(a.lv.tmp, fmt.Sprintf("plan-%d.json", time.Now().UnixNano()))
	r := a.lv.runPilot(a.lv.pilot, a.data, []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--preview-only", "--plan-out", plan, "--timeout", "10m"})
	var doc Document
	data, err := os.ReadFile(plan)
	if err == nil && json.Unmarshal(data, &doc) == nil {
		return r, doc, true
	}
	return r, doc, false
}

// legacy runs the Ansible engine's apply (an acked run) and requires it to succeed.
func (a *armCtx) legacy(ws string) bool {
	r := a.lv.runPilot(a.lv.pilot, a.data, []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--force"})
	return a.ok(r.ExitCode == 0, "the legacy apply exited %d:\n%s", r.ExitCode, tail(r.Out, 1500))
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func (a *armCtx) exit(r applyRun, want int) bool {
	return a.ok(r.ExitCode == want, "exit %d, want %d:\n%s", r.ExitCode, want, tail(r.Out, 1800))
}

// ops are the executed plan's operations as "kind object", sorted.
func (a *armCtx) ops(r applyRun) []string {
	if !r.HasDoc {
		a.fail("no result file:\n%s", tail(r.Out, 1200))
		return nil
	}
	out := opLines(executedPlan(r.Doc))
	sort.Strings(out)
	return out
}

func (a *armCtx) opsAre(r applyRun, want ...string) bool {
	got := a.ops(r)
	w := slices.Clone(want)
	sort.Strings(w)
	return a.ok(slices.Equal(got, w), "operations %v, want %v", got, w)
}

func (a *armCtx) outcome(r applyRun, id string) Outcome {
	for _, o := range r.Doc.Ops {
		if o.Operation.ID == id {
			return o.Final()
		}
	}
	return ""
}

func (a *armCtx) writesAre(r applyRun, want map[string]int) bool {
	return a.ok(fmt.Sprint(r.Writes) == fmt.Sprint(want), "the server logged writes %v, want %v", r.Writes, want)
}

func (a *armCtx) verifyClean(r applyRun) bool {
	return r.HasDoc && a.ok(r.Doc.Verify.Done && r.Doc.Verify.OK() && (r.Doc.Plan3 == nil || len(r.Doc.Plan3.Operations) == 0),
		"the read after the writes is not clean: %+v", r.Doc.Verify)
}

func (a *armCtx) pending(want bool) bool {
	j := a.lv.journal()
	a.fact("journal_after", map[string]any{"exists": j.Exists, "pending": j.Pending})
	return a.ok(j.Pending == want, "the journal says pending=%v, want %v", j.Pending, want)
}

// ---- rosters ----

func (d *applyDriver) pw(user string) string {
	if p, ok := d.pws[user]; ok {
		return p
	}
	p := randomPassword()
	d.pws[user] = p
	return p
}

func randomPassword() string {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	b := make([]byte, 18)
	if _, err := io.ReadFull(f, b); err != nil {
		panic(err)
	}
	const alpha = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := []byte("Lab-")
	for _, c := range b {
		out = append(out, alpha[int(c)%len(alpha)])
	}
	return string(out)
}

// user is a roster user with the password and the oracle key given.
func (d *applyDriver) user(name string, opts ...func(m map[string]any)) map[string]any {
	m := map[string]any{"name": name, "first": "P26", "last": strings.TrimPrefix(name, "p26-"), "password": map[string]any{"initial": d.pw(name)}}
	for _, o := range opts {
		o(m)
	}
	return m
}

func withKey(pub string) func(map[string]any) {
	return func(m map[string]any) { m["ssh_keys"] = map[string]any{"authoritative": true, "values": []string{pub}} }
}
func with(k string, v any) func(map[string]any) { return func(m map[string]any) { m[k] = v } }
func noPassword(m map[string]any)               { delete(m, "password") }

func group(name, category string, users []string, groups []string, opts ...func(m map[string]any)) map[string]any {
	m := map[string]any{"name": name, "category": category, "description": "P26 " + name,
		"membership": map[string]any{"users": nonNilList(users), "groups": nonNilList(groups)}}
	for _, o := range opts {
		o(m)
	}
	return m
}

func nonNilList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// baseRoster is the roster the baseline is made from: the users and groups the arms change, the
// access rules the client's allow and deny come from (HBAC names the users; the sudo rule names a
// role group, so a revocation of that group is the one a login does not follow at once: K20), and the
// two logins the self-lockout arms use.
func (d *applyDriver) baseRoster(principal string) rosterDoc {
	lv := d.lv
	users := []map[string]any{
		d.user("p26-ann", withKey(lv.pub)), d.user("p26-ben", withKey(lv.pub)), d.user("p26-cat"), d.user("p26-dan"), d.user("p26-eve"),
		d.user("p26-adm"), d.user("p26-adn"),
	}
	allNames := []string{"p26-ann", "p26-ben", "p26-cat", "p26-dan", "p26-eve", "p26-adm", "p26-adn"}
	return rosterDoc{
		"schema_version": 3,
		"freeipa":        map[string]any{"domain": "ipa.pilot.internal", "server": "ipa1.ipa.pilot.internal", "admin": map[string]any{"principal": principal}},
		"users":          users,
		"groups": []map[string]any{
			group("team-p26", "team", []string{"p26-ann", "p26-ben", "p26-cat", "p26-dan"}, nil),
			group("role-p26", "role", []string{"p26-ann"}, nil),
			group("data-p26", "filesystem", []string{"p26-ann"}, nil, with("type", "nonposix")),
			// p26-adn reaches admins only through role-p26-old and role-p26-ops (the set-up puts
			// role-p26-ops in admins): the chain the nested-path arms cut or rebuild.
			group("role-p26-ops", "role", nil, []string{"role-p26-old"}),
			group("role-p26-old", "role", []string{"p26-adn"}, nil),
		},
		"hosts":      []map[string]any{{"name": lv.cliFQDN, "state": "present", "ip_address": hostIP(lv.cli), "description": "P26 client"}},
		"hostgroups": []map[string]any{{"name": "p26-targets", "state": "present", "description": "P26", "membership": map[string]any{"hosts": []string{lv.cliFQDN}, "hostgroups": []string{}}}},
		"hbac": map[string]any{"disable_allow_all": true, "services": []map[string]any{{"name": "sshd", "state": "present"}},
			"rules": []map[string]any{
				{"name": "p26-ssh", "state": "present", "enabled": true, "subjects": map[string]any{"users": allNames, "groups": []string{}},
					"targets": map[string]any{"hosts": []string{}, "hostgroups": []string{"p26-targets"}}, "services": []string{"sshd", "sudo"}},
				{"name": "p26-admin", "state": "present", "enabled": true, "subjects": map[string]any{"users": []string{"admin"}, "groups": []string{}},
					"targets": map[string]any{"hostcat": "all", "hosts": []string{}, "hostgroups": []string{}}, "services": []string{"sshd"}},
			}},
		"sudo": map[string]any{"command_groups": []map[string]any{{"name": "p26-cmds", "state": "present", "commands": []string{"/usr/bin/true"}}},
			"rules": []map[string]any{{"name": "p26-sudo", "state": "present", "enabled": true, "subjects": map[string]any{"users": []string{}, "groups": []string{"role-p26"}},
				"targets": map[string]any{"hostcat": "all", "hosts": []string{}, "hostgroups": []string{}},
				"allow":   map[string]any{"command_groups": []string{"p26-cmds"}, "commands": []string{}}, "deny": map[string]any{"command_groups": []string{}, "commands": []string{}},
				"run_as": map[string]any{"users": []string{"root"}, "groups": []string{}}, "options": []string{"!authenticate"}}}},
	}
}

func hostIP(t sshdial.Target) string { return t.Host }

// mutate returns a copy of the roster with f applied.
func (d *applyDriver) mutate(r rosterDoc, f func(r rosterDoc)) rosterDoc {
	raw, _ := json.Marshal(r)
	var out rosterDoc
	_ = json.Unmarshal(raw, &out)
	f(out)
	return out
}

func (d *applyDriver) addUser(r rosterDoc, u map[string]any) {
	raw, _ := json.Marshal(u)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	r["users"] = append(r["users"].([]any), m)
}

func (d *applyDriver) addGroup(r rosterDoc, g map[string]any) {
	raw, _ := json.Marshal(g)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	r["groups"] = append(r["groups"].([]any), m)
}

// find returns the named entry of a roster list.
func find(r rosterDoc, list, name string) map[string]any {
	for _, e := range r[list].([]any) {
		if m := e.(map[string]any); m["name"] == name {
			return m
		}
	}
	panic("no " + name + " in " + list)
}

func setMembers(r rosterDoc, groupName string, users ...string) {
	if users == nil {
		// An empty list, not a nil one: a roster copied through JSON (mutate of a mutated roster) would carry a null,
		// which the adapter refuses ("users must be a list, not null").
		users = []string{}
	}
	g := find(r, "groups", groupName)
	g["membership"].(map[string]any)["users"] = users
}

// ---- a webhook receiver: what the outbox's events are delivered to ----

type receiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
}

func newReceiver() *receiver {
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, b)
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	return r
}

func (r *receiver) events() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []map[string]any
	for _, b := range r.bodies {
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

// webhookFor writes an integrations.yaml to ws that sends reconcile failures to the receiver.
func (d *applyDriver) webhookFor(ws string, r *receiver) {
	content := "schema_version: 1\nsource_id: p26-driver\nwebhooks:\n  - name: p26-hook\n    enabled: true\n    endpoint: " + r.srv.URL + "\n" +
		"    projection: user_host_access_v1\n    events:\n      - operation: reconcile\n        result: failure\n        payload: snapshot\n" +
		"    auth:\n      type: bearer\n      secret_env: PILOT_W_TEST_TOKEN\n    tls:\n      allow_insecure_http: true\n"
	if err := os.WriteFile(filepath.Join(ws, "integrations.yaml"), []byte(content), 0o600); err != nil {
		d.lv.t.Fatal(err)
	}
}

// failureEvent waits for the receiver to hold a failure event and returns its class.
func (a *armCtx) failureClass(r *receiver) string {
	end := time.Now().Add(40 * time.Second)
	for time.Now().Before(end) {
		for _, ev := range r.events() {
			if op, _ := ev["operation"].(map[string]any); op["result"] == "failure" {
				f, _ := ev["failure"].(map[string]any)
				return fmt.Sprint(f["class"])
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

// ---- server observations ----

func (a *armCtx) serverHas(cmd string) string {
	out, _ := a.lv.ipaCLI(cmd)
	return out
}

func (a *armCtx) lockFree(within time.Duration) bool {
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if _, err := a.lv.onServer("flock --nonblock --conflict-exit-code 75 /etc/ipa true"); err == nil {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}

func (a *armCtx) lockHeld() bool {
	_, err := a.lv.onServer("flock --nonblock --conflict-exit-code 75 /etc/ipa true")
	return err != nil
}

// waitWrite waits until the server's log shows method since offset.
func (a *armCtx) waitWrite(method string, since int64, within time.Duration) bool {
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if w, err := a.lv.writesSince(since); err == nil && w[method] > 0 {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func (a *armCtx) loginCount() int {
	out, _ := a.lv.onServer("grep -c login_password /var/log/httpd/access_log 2>/dev/null || true")
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	return n
}

// sshAccepted counts the server's accepted public-key logins. The count's own connection is
// logged asynchronously, so it waits for the log before counting: a count includes the logins of
// every earlier count and its own, and sshOthersSince(before) is what the logins of everything else
// came to between two counts.
func (a *armCtx) sshAccepted() int {
	out, _ := a.lv.onServer("sleep 2; grep -c 'Accepted publickey' /var/log/secure 2>/dev/null || true")
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	return n
}

// sshOthersSince is the number of logins other than the second count's own since the count before.
func (a *armCtx) sshOthersSince(before int) int { return a.sshAccepted() - before - 1 }

// killChild kills pilot's child whose command line matches re (the tunnel's -W, the lock's flock).
func (a *armCtx) killChild(p *proc, re string) bool {
	pid, ok := p.childWith(re)
	if !ok {
		a.fail("pilot has no child matching %q: %v", re, p.children())
		return false
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return a.ok(false, "child %d did not end after SIGKILL", pid)
}
