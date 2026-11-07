package identityreconcile

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/kjelly/pilot/internal/sshdial"
)

// TestLiveGoPerfDriver is the performance part of the Go reconcile test driver (spec §10.2 row P, plan §6, P2-8): the
// datasets of the benchmark are created on a disposable FreeIPA server with the p28perf- prefix, and the runs of
// `pilot reconcile --engine golang` (and of the legacy engine) are timed from outside, as an operator sees them:
// the whole process, from ssh and the tunnel to the verification, with the entry playbook's own time shown apart.
// It drives only the pilot binary it builds, and counts what the server logged without asking pilot.
//
// It runs only when PILOT_IDENTITY_ENGINE_LIVE_PERF names the baseline snapshot of the two VMs (the same pair the
// apply driver uses) and takes the apply driver's environment (PILOT_IDENTITY_ENGINE_LIVE_SERVER_VM, _CLIENT_VM,
// _WORKSPACE, _CLIENT_FQDN, _CLIENT_SSH, _VAULT_PASS, PILOT_FREEIPA_LIVE_SSH[_KEY|_OPTS], IPA_ADMIN_PASSWORD) plus:
//
//	PILOT_IDENTITY_ENGINE_LIVE_PERF_SCENARIOS  comma-separated scenario names (a prefix matches), default none: env only
//	PILOT_IDENTITY_ENGINE_LIVE_PERF_N          override of every scenario's sample count (a dev run of the harness)
//	PILOT_IDENTITY_ENGINE_LIVE_PERF_OUT        the directory the samples (JSON lines) and the summary are written to
//
// A scenario that needs a snapshot another scenario takes (p28-d120, p28-d1000) fails when it is not there. Every
// mutation sample starts from the same snapshot: the server (and for a mixed run the client too) is reverted to it,
// which is the restore of the plan's §6 ("each mutation benchmark restored from the same starting state"). Nothing
// here prints a password.
func TestLiveGoPerfDriver(t *testing.T) {
	base := os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_PERF")
	if base == "" {
		t.Skip("PILOT_IDENTITY_ENGINE_LIVE_PERF is not set")
	}
	p := newPerfLab(t, base)
	var want []string
	for _, s := range strings.Split(os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_PERF_SCENARIOS"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			want = append(want, s)
		}
	}
	if len(want) == 0 {
		t.Fatal("PILOT_IDENTITY_ENGINE_LIVE_PERF_SCENARIOS names no scenario")
	}
	ran := 0
	for _, sc := range p.scenarios() {
		for _, w := range want {
			if strings.HasPrefix(sc.name, w) {
				start := time.Now()
				p.current = sc.name
				t.Logf("scenario %s: start", sc.name)
				sc.run()
				p.writeSummary()
				t.Logf("scenario %s: done in %.0fs", sc.name, time.Since(start).Seconds())
				ran++
				break
			}
		}
	}
	if ran == 0 {
		t.Fatalf("no scenario matches %v", want)
	}
	for _, s := range p.samples {
		if len(s.Failures) > 0 {
			t.Errorf("sample %s #%d: %s", s.Scenario, s.Index, strings.Join(s.Failures, "; "))
		}
	}
}

// ---- the lab ----

type perfLab struct {
	t       *testing.T
	lv      *labEnv
	out     string // the output directory
	base    string // the baseline snapshot the datasets are made from
	current string

	samples   []perfSample
	shapes    map[string]perfShape
	facts     map[string]any
	jsonl     *os.File
	bins      map[int]string // the pilot binary by batch limit; 0 is the one as committed
	clientIP  string
	scenarioN map[string]int
}

type perfScenario struct {
	name string
	run  func()
}

func newPerfLab(t *testing.T, base string) *perfLab {
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
	// The same environment as TestLiveGoApplyDriver reads (live_apply_test.go), with a mux directory of its own.
	lv := &labEnv{
		t: t, repo: repo, tmp: tmp, cp: "/tmp/p28cp",
		srvVM: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_SERVER_VM"), cliVM: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_CLIENT_VM"),
		srv: liveSSHTarget(t), cli: cli, baseTag: base,
		template: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_WORKSPACE"), cliFQDN: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_CLIENT_FQDN"),
		vaultPass: mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_VAULT_PASS"), adminPW: mustEnv(t, "IPA_ADMIN_PASSWORD"),
	}
	lv.pilot = filepath.Join(tmp, "pilot")
	run(t, repo, "go", "build", "-o", lv.pilot, "./cmd/pilot")
	if err := os.MkdirAll(lv.cp, 0o700); err != nil {
		t.Fatal(err)
	}
	out := os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_PERF_OUT")
	if out == "" {
		out = filepath.Join(tmp, "out")
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(out, "samples.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	p := &perfLab{t: t, lv: lv, out: out, base: base, shapes: map[string]perfShape{}, facts: map[string]any{}, jsonl: f,
		bins: map[int]string{0: lv.pilot}, clientIP: hostIP(cli), scenarioN: map[string]int{}}
	p.facts["revision"], p.facts["tree"] = gitOut(t, repo, "rev-parse", "HEAD"), gitOut(t, repo, "rev-parse", "HEAD^{tree}")
	p.facts["batch_limit_as_committed"] = MaxBatch
	p.facts["base_snapshot"] = base
	return p
}

// n is how many samples a scenario takes: the formal 20 unless the dev override says otherwise.
func (p *perfLab) n(def int) int {
	if v := os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_PERF_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return min(n, def)
		}
	}
	return def
}

func (p *perfLab) scenarios() []perfScenario {
	return []perfScenario{
		{"env", p.scEnv},
		{"d120-seed", p.scD120Seed},
		{"d120-nodiff", p.scD120NoDiff},
		{"d120-attr", p.scD120Attr},
		{"d120-create100", p.scD120Create100},
		{"d120-create100pw", p.scD120Create100PW},
		{"d120-modify100", p.scD120Modify100},
		{"batch-sweep", p.scBatchSweep},
		{"d120-mixed", p.scD120Mixed},
		{"d120w-seed", p.scD120WideSeed},
		{"d120w-mixed", p.scD120WideMixed},
		{"d1000-seed", p.scD1000Seed},
		{"d1000-nodiff", p.scD1000NoDiff},
		{"d1000-complete", p.scD1000Complete},
		{"d1000-attr", p.scD1000Attr},
		{"d1000-delete", p.scD1000Delete},
		{"d1000-bigmember", p.scD1000BigMember},
		{"profile", p.scProfile},
		{"legacy-d120w", p.scLegacy},
		{"controls", p.scControls},
	}
}

// ---- the VMs: restore, snapshot, clock ----

func (p *perfLab) setClock(t sshdial.Target) error {
	now := strconv.FormatInt(time.Now().Unix(), 10)
	var last error
	for i := 0; i < 24; i++ {
		if _, last = sshRun(t, "date -u -s @"+now+" >/dev/null"); last == nil {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("cannot set the clock of a VM: %w", last)
}

// revertBoth restores both VMs to tag (the starting state of a mixed run), sets their clocks and drops our mux sockets.
func (p *perfLab) revertBoth(tag string) {
	p.t.Helper()
	if err := p.lv.rollback(tag); err != nil {
		p.t.Fatalf("revert both VMs to %s: %v", tag, err)
	}
}

// countSSH makes the server's sshd log every command session (LogLevel VERBOSE), which is what the counts of ssh
// connections and of sessions that reused one are read from. It is a drop-in on the disposable server, made after the
// server was restored to the baseline snapshot and carried by every snapshot taken after it.
func (p *perfLab) countSSH() {
	p.t.Helper()
	const cmd = "printf 'LogLevel VERBOSE\\n' > /etc/ssh/sshd_config.d/00-p28-verbose.conf && sshd -t && systemctl reload sshd && grep -rh '^LogLevel' /etc/ssh/sshd_config.d/"
	out, err := sshRun(p.lv.srv, cmd)
	if err != nil || !strings.Contains(out, "LogLevel VERBOSE") {
		p.t.Fatalf("cannot make sshd log its sessions: %v %q", err, out)
	}
	p.facts["server_sshd_loglevel_set_by_driver"] = "VERBOSE"
}

// revertServer restores the server alone, for the runs that do not touch the client (the users-groups scope).
func (p *perfLab) revertServer(tag string) {
	p.t.Helper()
	lv := p.lv
	if err := lv.vmTarget("rollback", "--name", lv.srvVM, "--tag", tag); err != nil {
		p.t.Fatalf("revert the server to %s: %v", tag, err)
	}
	_ = os.RemoveAll(lv.cp)
	if err := os.MkdirAll(lv.cp, 0o700); err != nil {
		p.t.Fatal(err)
	}
	if err := p.setClock(lv.srv); err != nil {
		p.t.Fatal(err)
	}
}

func (p *perfLab) hasSnapshot(tag string) bool {
	for _, vm := range []string{p.lv.srvVM, p.lv.cliVM} {
		out, err := exec.Command("virsh", "-c", "qemu:///system", "snapshot-list", vm, "--name").Output()
		if err != nil || !slices.Contains(strings.Fields(string(out)), tag) {
			return false
		}
	}
	return true
}

func (p *perfLab) needSnapshot(tag string) {
	p.t.Helper()
	if !p.hasSnapshot(tag) {
		p.t.Fatalf("the snapshot %s of both VMs does not exist: run the seed scenario first", tag)
	}
}

// takeSnapshot replaces the snapshot tag of both VMs with the VMs' state now.
func (p *perfLab) takeSnapshot(tag string) {
	p.t.Helper()
	p.lv.deleteSnapshot(tag)
	if err := p.lv.snapshot(tag); err != nil {
		p.t.Fatalf("snapshot %s: %v", tag, err)
	}
}

// ---- what the server says of itself ----

type perfMarks struct{ errLog, accessLog, secure int64 }

func (p *perfLab) marks() perfMarks {
	p.t.Helper()
	out, err := sshRun(p.lv.srv, "stat -c %s /var/log/httpd/error_log /var/log/httpd/access_log; wc -l < /var/log/secure")
	f := strings.Fields(out)
	if err != nil || len(f) != 3 {
		p.t.Fatalf("server marks: %v %q", err, out)
	}
	var m perfMarks
	for i, dst := range []*int64{&m.errLog, &m.accessLog, &m.secure} {
		n, perr := strconv.ParseInt(f[i], 10, 64)
		if perr != nil {
			p.t.Fatalf("server marks: %q", out)
		}
		*dst = n
	}
	return m
}

// sshScript runs script on the server with args, the script on its stdin.
func sshScript(t sshdial.Target, script string, args ...string) (string, error) {
	cmd := exec.Command("ssh", append(sshArgs(t), sshHost(t), "bash -s -- "+strings.Join(args, " "))...)
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, tail(stderr.String(), 400))
	}
	return string(out), nil
}

func (p *perfLab) serverSince(m perfMarks) perfServer {
	p.t.Helper()
	out, err := sshScript(p.lv.srv, perfCountScript, strconv.FormatInt(m.errLog, 10), strconv.FormatInt(m.accessLog, 10), strconv.FormatInt(m.secure, 10))
	if err != nil {
		p.t.Fatalf("server counters: %v", err)
	}
	s, err := parsePerfServer(out)
	if err != nil {
		p.t.Fatal(err)
	}
	return s
}

var entriesReturned = regexp.MustCompile(`Number of entries returned (\d+)`)

// countFind is the number the ipa CLI says one find command returned.
func (p *perfLab) countFind(args string) int {
	p.t.Helper()
	out, err := p.lv.ipaCLI("ipa " + args)
	m := entriesReturned.FindStringSubmatch(out)
	if err != nil || m == nil {
		p.t.Fatalf("ipa %s: %v\n%s", args, err, tail(out, 400))
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// serverCount is how many users or groups the server holds, by the ipa CLI (an independent reader). The engine reads the
// active users and the preserved ones, so the server's count of users is both; a group is a group_find group (the
// private group of a user is not one).
func (p *perfLab) serverCount(kind string) int {
	n := p.countFind(kind + "-find --sizelimit=0 --pkey-only")
	if kind == "user" {
		n += p.countFind("user-find --preserved=true --sizelimit=0 --pkey-only")
	}
	return n
}

// serverNames are the names of the users or groups the server holds whose name contains perfPrefix.
func (p *perfLab) serverNames(kind string) []string {
	p.t.Helper()
	label := map[string]string{"user": "User login", "group": "Group name"}[kind]
	out, err := p.lv.ipaCLI("ipa " + kind + "-find " + perfPrefix + " --sizelimit=0 --pkey-only")
	if err != nil && !strings.Contains(out, "0 "+kind) {
		p.t.Fatalf("ipa %s-find: %v\n%s", kind, err, tail(out, 400))
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), label+": "); ok {
			names = append(names, v)
		}
	}
	sort.Strings(names)
	return names
}

// groupMemberCount is the number of direct user members of a group, from the raw entry.
func (p *perfLab) groupMemberCount(group string) int {
	p.t.Helper()
	out, err := p.lv.ipaCLI("ipa group-show " + group + " --raw --all | grep -c '^  member:'")
	n, _ := strconv.Atoi(strings.TrimSpace(out[strings.LastIndex(strings.TrimSpace(out), "\n")+1:]))
	if err != nil && n == 0 {
		return 0
	}
	return n
}

// ---- watching pilot's children ----

type seenProc struct {
	name        string
	check, skip bool
	first, last time.Time
}

type childWatch struct {
	pid  int
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
	seen map[int]*seenProc
}

// watchChildren polls the children of pid every 20 ms and notes the ansible-playbook processes among them: when each
// was first and last seen, and which playbook it ran. It reads /proc only, so it costs pilot nothing.
func watchChildren(pid int) *childWatch {
	w := &childWatch{pid: pid, stop: make(chan struct{}), done: make(chan struct{}), seen: map[int]*seenProc{}}
	go w.run()
	return w
}

func childPIDs(pid int) []int {
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil
	}
	var out []int
	for _, t := range tasks {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", pid, t.Name()))
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(f); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func (w *childWatch) run() {
	defer close(w.done)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-w.stop:
			return
		case now := <-tick.C:
			w.mu.Lock()
			for _, c := range childPIDs(w.pid) {
				if sp, ok := w.seen[c]; ok {
					if !sp.skip {
						sp.last = now
					}
					continue
				}
				raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", c))
				if err != nil || len(raw) == 0 {
					continue
				}
				name, check, ok := classifyPlaybook(strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"))
				w.seen[c] = &seenProc{name: name, check: check, skip: !ok, first: now, last: now}
			}
			w.mu.Unlock()
		}
	}
}

// finish stops the watch and returns the playbooks seen, in the order they started.
func (w *childWatch) finish() []perfPlaybook {
	close(w.stop)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	var procs []*seenProc
	for _, sp := range w.seen {
		if !sp.skip {
			procs = append(procs, sp)
		}
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].first.Before(procs[j].first) })
	var out []perfPlaybook
	for _, sp := range procs {
		out = append(out, perfPlaybook{Name: sp.name, Check: sp.check, Seconds: sp.last.Sub(sp.first).Seconds() + 0.02})
	}
	return out
}

// ---- the journal of the run: the events its own store holds ----

func maxEventID(dataDir string) int64 {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "history.db")+"?mode=ro")
	if err != nil {
		return 0
	}
	defer db.Close()
	var id sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(event_id) FROM delivery_events`).Scan(&id); err != nil {
		return 0
	}
	return id.Int64
}

func eventsAfter(dataDir string, after int64) ([]perfEvent, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "history.db")+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT event_id, type, operation_id, created_at, payload_json FROM delivery_events WHERE event_id > ? ORDER BY event_id`, after)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []perfEvent
	for rows.Next() {
		var e perfEvent
		var at string
		if err := rows.Scan(&e.ID, &e.Type, &e.Op, &at, &e.Payload); err != nil {
			return nil, err
		}
		if e.At, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return nil, fmt.Errorf("event %d: created_at %q: %w", e.ID, at, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// controllerLoad is the controller's one-minute load average (the host the VMs run on), 0 when it cannot be read.
func controllerLoad() float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// ---- one measured run ----

// perfRun is a measured run with the documents it left.
type perfRun struct {
	S    perfSample
	Doc  ApplyDocument
	Plan Document
	Out  string
}

type perfInput struct {
	scenario, kind string
	idx            int
	binary         string
	batchLimit     int
	data           string
	args           []string
	result         string // the --result-out file, "" when the command writes none
	plan           string // the --plan-out file of a preview
}

// measure runs pilot once and takes what the run left: the time from outside, the playbooks it started, its result file,
// the journal of the run, and the server's own counters between two marks taken around it. The marks and the journal
// state are read by ssh before the process starts and after it ended, so none of the driver's own connections falls in
// the window the counters cover (the script leaves out its own connection).
func (p *perfLab) measure(in perfInput) perfRun {
	p.t.Helper()
	lv := p.lv
	if in.binary == "" {
		in.binary = lv.pilot
	}
	if err := os.MkdirAll(in.data, 0o700); err != nil {
		p.t.Fatal(err)
	}
	jb := lv.journal()
	eventBase := maxEventID(in.data)
	loadStart := controllerLoad()
	m := p.marks()
	cmd := exec.Command(in.binary, append([]string{"--data-dir", in.data}, in.args...)...)
	cmd.Dir = lv.repo
	cmd.Env = lv.pilotEnv()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	if err := cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	w := watchChildren(cmd.Process.Pid)
	exit := exitCodeOf(cmd.Wait())
	wall := time.Since(start).Seconds()
	playbooks := w.finish()
	ja := lv.journal()
	server := p.serverSince(m)

	s := perfSample{Scenario: in.scenario, Index: in.idx, Kind: in.kind, BatchLimit: in.batchLimit, Exit: exit, Wall: wall,
		Playbooks: playbooks, Server: server, LoadStart: loadStart, LoadEnd: controllerLoad(),
		JournalBefore: fmt.Sprintf("pending=%v/%s", jb.Pending, jb.Hash), JournalAfter: fmt.Sprintf("pending=%v/%s", ja.Pending, ja.Hash)}
	for _, pb := range playbooks {
		switch {
		case strings.Contains(pb.Name, "auth-cache"):
			s.EntrySeconds += pb.Seconds
		case strings.Contains(pb.Name, "freeipa-identity-apply"):
			s.IdentitySeconds += pb.Seconds
		}
	}
	res := perfRun{S: s, Out: out.String()}
	if in.result != "" {
		if doc, err := readApplyResult(in.result); err == nil {
			res.Doc = doc
			res.S.fromDoc(doc)
		}
	}
	if in.plan != "" {
		if data, err := os.ReadFile(in.plan); err == nil && json.Unmarshal(data, &res.Plan) == nil {
			res.S.HasDoc = true
			res.S.HTTP, res.S.Reads, res.S.WriteCmds = res.Plan.Stats.HTTPRequests, res.Plan.Stats.Reads, res.Plan.Stats.Writes
			res.S.Relogins, res.S.ReadRetries = res.Plan.Stats.Relogins, res.Plan.Stats.ReadRetries
			res.S.ObservedUsers, res.S.ObservedGroups = res.Plan.Observation.Users, res.Plan.Observation.Groups
			res.S.PlanOps = len(res.Plan.Operations)
		}
	}
	if evs, err := eventsAfter(in.data, eventBase); err == nil {
		res.S.Batches, res.S.Phases = summarizeEvents(evs, start)
	} else {
		p.t.Logf("events of %s #%d: %v", in.scenario, in.idx, err)
	}
	return res
}

// fromDoc takes the client-side counts out of a result file.
func (s *perfSample) fromDoc(d ApplyDocument) {
	s.HasDoc = true
	s.Verdict, s.Outcome = d.Verdict, d.Outcome
	s.HTTP, s.Reads, s.WriteCmds = d.Stats.HTTPRequests, d.Stats.Reads, d.Stats.Writes
	s.Relogins, s.ReadRetries = d.Stats.Relogins, d.Stats.ReadRetries
	plan := executedPlan(d)
	s.PlanOps = len(plan.Operations)
	s.PlanKinds, s.PlanFields, s.Outcomes = map[string]int{}, map[string]int{}, map[string]int{}
	for _, op := range plan.Operations {
		s.PlanKinds[op.Kind]++
		if op.Kind == KindUserUpdate {
			for f := range op.Fields {
				s.PlanFields[f]++
			}
		}
	}
	for _, o := range d.Ops {
		s.Outcomes[string(o.Final())]++
	}
	s.EntryRan, s.ProbePending = d.Entry.Ran, d.Entry.Pending
	s.VerifyOK = d.Verify.Done && d.Verify.OK()
}

// ---- recording ----

// record checks a sample against the checks of its scenario, keeps it and appends it to the samples file.
func (p *perfLab) record(r perfRun, checks ...[]string) perfRun {
	p.t.Helper()
	for _, c := range checks {
		r.S.Failures = append(r.S.Failures, c...)
	}
	p.samples = append(p.samples, r.S)
	line, _ := json.Marshal(r.S)
	if _, err := p.jsonl.Write(append(line, '\n')); err != nil {
		p.t.Fatal(err)
	}
	status := "ok"
	if len(r.S.Failures) > 0 {
		status = "FAIL " + strings.Join(r.S.Failures, "; ")
		p.t.Logf("output of the failed run:\n%s", tail(r.Out, 2500))
	}
	p.t.Logf("  %-26s #%-2d exit=%d wall=%6.1fs entry=%5.1fs http=%d reads=%d writes=%d(server %d) ssh=%d/%d/%d  %s",
		r.S.Scenario, r.S.Index, r.S.Exit, r.S.Wall, r.S.EntrySeconds, r.S.HTTP, r.S.Reads, r.S.WriteCmds, r.S.Server.WriteN,
		r.S.Server.SSHConnections, r.S.Server.SSHSessions, r.S.Server.SSHReused, status)
	return r
}

// ---- the summary ----

type perfScenarioSummary struct {
	Kind        string    `json:"kind"`
	Wall        perfStats `json:"wall_seconds"`
	Entry       perfStats `json:"entry_seconds,omitempty"`
	Identity    perfStats `json:"identity_playbook_seconds,omitempty"`
	HTTP        perfStats `json:"http_requests"`
	Reads       perfStats `json:"reads"`
	WriteCmds   perfStats `json:"write_commands"`
	SSHConn     perfStats `json:"ssh_connections"`
	SSHSessions perfStats `json:"ssh_sessions"`
	SSHReused   perfStats `json:"ssh_reused_sessions"`
	Failed      int       `json:"samples_failed"`
	BatchLimit  int       `json:"batch_limit,omitempty"`
}

func (p *perfLab) writeSummary() {
	groups := map[string][]perfSample{}
	var order []string
	for _, s := range p.samples {
		key := s.Scenario
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], s)
	}
	col := func(ss []perfSample, f func(perfSample) float64) []float64 {
		var v []float64
		for _, s := range ss {
			v = append(v, f(s))
		}
		return v
	}
	scenarios := map[string]perfScenarioSummary{}
	for _, k := range order {
		ss := groups[k]
		var withEntry []perfSample
		var withIdentity []perfSample
		failed := 0
		for _, s := range ss {
			if s.EntrySeconds > 0 {
				withEntry = append(withEntry, s)
			}
			if s.IdentitySeconds > 0 {
				withIdentity = append(withIdentity, s)
			}
			if len(s.Failures) > 0 {
				failed++
			}
		}
		scenarios[k] = perfScenarioSummary{
			Kind: ss[0].Kind, BatchLimit: ss[0].BatchLimit, Failed: failed,
			Wall:        summarize(col(ss, func(s perfSample) float64 { return s.Wall })),
			Entry:       summarize(col(withEntry, func(s perfSample) float64 { return s.EntrySeconds })),
			Identity:    summarize(col(withIdentity, func(s perfSample) float64 { return s.IdentitySeconds })),
			HTTP:        summarize(col(ss, func(s perfSample) float64 { return float64(s.HTTP) })),
			Reads:       summarize(col(ss, func(s perfSample) float64 { return float64(s.Reads) })),
			WriteCmds:   summarize(col(ss, func(s perfSample) float64 { return float64(s.WriteCmds) })),
			SSHConn:     summarize(col(ss, func(s perfSample) float64 { return float64(s.Server.SSHConnections) })),
			SSHSessions: summarize(col(ss, func(s perfSample) float64 { return float64(s.Server.SSHSessions) })),
			SSHReused:   summarize(col(ss, func(s perfSample) float64 { return float64(s.Server.SSHReused) })),
		}
	}
	doc := map[string]any{"facts": p.facts, "datasets": p.shapes, "scenarios": scenarios}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.out, "summary.json"), append(data, '\n'), 0o600); err != nil {
		p.t.Fatal(err)
	}
}

// ---- running pilot in the ways the scenarios need ----

// dataDir is the one pilot data directory of the whole run, as an operator's is: every sample runs against it, so no sample
// is the first in a directory of its own.
func (p *perfLab) dataDir() string { return filepath.Join(p.lv.tmp, "data") }

func (p *perfLab) newResult(tag string) string {
	p.scenarioN[tag]++
	return filepath.Join(p.lv.tmp, fmt.Sprintf("result-%s-%d.json", tag, p.scenarioN[tag]))
}

// goApply runs the users-groups apply of the Go engine on ws and measures it.
func (p *perfLab) goApply(scenario string, idx int, ws string, binary string, batchLimit int) perfRun {
	result := p.newResult(scenario)
	return p.measure(perfInput{scenario: scenario, kind: "users-groups", idx: idx, binary: binary, batchLimit: batchLimit, data: p.dataDir(), result: result,
		args: []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--force", "--scope", "users-groups", "--result-out", result, "--timeout", "30m"}})
}

// mixedApply runs the mixed scope (the Go phase, then the identity playbook) on ws and measures it.
func (p *perfLab) mixedApply(scenario string, idx int, ws string) perfRun {
	result := p.newResult(scenario)
	return p.measure(perfInput{scenario: scenario, kind: "full", idx: idx, data: p.dataDir(), result: result,
		args: []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--force", "--scope", "full", "--result-out", result, "--timeout", "60m"}})
}

// legacyApply runs the Ansible engine's reconcile (preview, apply and the idempotency run) on ws and measures it.
func (p *perfLab) legacyApply(scenario string, idx int, ws string) perfRun {
	return p.measure(perfInput{scenario: scenario, kind: "legacy", idx: idx, data: p.dataDir(),
		args: []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--force"}})
}

// goPreview runs the read-only preview, which reports how many users and groups it read.
func (p *perfLab) goPreview(scenario string, idx int, ws string) perfRun {
	plan := filepath.Join(p.lv.tmp, fmt.Sprintf("plan-%s-%d.json", scenario, time.Now().UnixNano()))
	return p.measure(perfInput{scenario: scenario, kind: "preview", idx: idx, data: p.dataDir(), plan: plan,
		args: []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--engine", "golang", "--preview-only", "--plan-out", plan, "--timeout", "30m"}})
}

// workspace makes a workspace holding the roster of sp.
func (p *perfLab) workspace(sp perfSpec, name string) (string, perfShape) {
	roster, shape := perfRoster(sp, p.lv.cliFQDN, p.clientIP)
	p.shapes[name] = shape
	return p.lv.copyWorkspace(roster, "", nil), shape
}

func (p *perfLab) setSpec(ws string, sp perfSpec) perfShape {
	roster, shape := perfRoster(sp, p.lv.cliFQDN, p.clientIP)
	p.lv.setRoster(ws, roster)
	return shape
}

// ---- the scenarios ----

// scEnv records the facts of the environment the numbers are taken in.
func (p *perfLab) scEnv() {
	t, lv := p.t, p.lv
	facts := p.facts
	host := func(name string, args ...string) string {
		out, _ := exec.Command(name, args...).CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	facts["controller_load_avg_start"] = host("cat", "/proc/loadavg")
	facts["controller_cpus"] = host("nproc")
	facts["controller_mem"] = host("free", "-m")
	facts["controller_running_vms"] = len(strings.Fields(host("virsh", "-c", "qemu:///system", "list", "--name", "--state-running")))
	facts["controller_ssh"] = host("ssh", "-V")
	facts["controller_go"] = host("go", "version")
	facts["controller_ansible"] = strings.SplitN(host("ansible-playbook", "--version"), "\n", 2)[0]
	for name, vm := range map[string]string{"server": lv.srvVM, "client": lv.cliVM} {
		facts["vm_"+name+"_dominfo"] = host("virsh", "-c", "qemu:///system", "dominfo", vm)
	}
	srv := func(cmd string) string { out, _ := sshRun(lv.srv, cmd); return strings.TrimSpace(out) }
	facts["server_ipa_version"] = srv("ipa --version")
	facts["server_packages"] = srv("rpm -q ipa-server 389-ds-base httpd openssh-server python3-ipaserver | tr '\\n' ' '")
	facts["server_os"] = srv("grep PRETTY_NAME /etc/os-release")
	facts["server_kernel"] = srv("uname -r")
	facts["server_cpus"] = srv("nproc")
	facts["server_cpu_model"] = srv("grep -m1 'model name' /proc/cpuinfo")
	facts["server_mem"] = srv("free -m | head -2")
	facts["server_load_avg"] = srv("cat /proc/loadavg")
	facts["server_sshd_loglevel"] = srv("grep -rhi '^LogLevel' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | tr '\\n' ' '")
	facts["server_users"], facts["server_groups"] = p.serverCount("user"), p.serverCount("group")
	facts["server_search_limits"] = func() string {
		out, _ := lv.ipaCLI("ipa config-show")
		var keep []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "Search") && strings.Contains(line, "limit") {
				keep = append(keep, strings.TrimSpace(line))
			}
		}
		return strings.Join(keep, "; ")
	}()

	// The round trip: ICMP from the controller, and ssh both ways (a new connection per command, and a command over one
	// connection that is already up: what each ssh costs pilot's own use of it).
	facts["rtt_ping"] = host("ping", "-c", "20", "-i", "0.2", "-q", lv.srv.Host)
	var fresh, mux []float64
	muxDir, err := os.MkdirTemp(lv.tmp, "rtt-")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(muxDir, "m")
	base := sshArgs(lv.srv)
	for i := 0; i < 20; i++ {
		start := time.Now()
		if err := exec.Command("ssh", append(append([]string{}, base...), "-o", "ControlPath=none", sshHost(lv.srv), "true")...).Run(); err != nil {
			t.Fatalf("rtt: %v", err)
		}
		fresh = append(fresh, time.Since(start).Seconds())
	}
	muxOpts := append(append([]string{}, base...), "-o", "ControlMaster=auto", "-o", "ControlPath="+sock, "-o", "ControlPersist=60")
	if err := exec.Command("ssh", append(append([]string{}, muxOpts...), sshHost(lv.srv), "true")...).Run(); err != nil {
		t.Fatalf("rtt: %v", err)
	}
	for i := 0; i < 20; i++ {
		start := time.Now()
		if err := exec.Command("ssh", append(append([]string{}, muxOpts...), sshHost(lv.srv), "true")...).Run(); err != nil {
			t.Fatalf("rtt: %v", err)
		}
		mux = append(mux, time.Since(start).Seconds())
	}
	_ = exec.Command("ssh", "-O", "exit", "-o", "ControlPath="+sock, sshHost(lv.srv)).Run()
	facts["rtt_ssh_new_connection_seconds"] = summarize(fresh)
	facts["rtt_ssh_over_open_connection_seconds"] = summarize(mux)
	t.Logf("environment: %v", facts)
}

// d120Spec is the dataset of the 120/40 scenarios.
var d120Spec = perfSpec{Users: 120, Groups: 40}

// scD120Seed creates the 120/40 dataset from the baseline snapshot with the Go engine (the first create at this scale,
// which is a sample of its own), settles the obligation with a mixed run, warms the server and takes the snapshot every
// later 120/40 scenario starts from.
func (p *perfLab) scD120Seed() {
	t := p.t
	p.revertBoth(p.base)
	p.countSSH()
	ws, shape := p.workspace(d120Spec, "d120")
	t.Logf("dataset d120: %+v; the server held %d users and %d groups before", shape, p.serverCount("user"), p.serverCount("group"))
	first := p.goApply("d120-seed:first-create", 1, ws, "", 0)
	p.record(first, checkCreates(first.S, shape.Users), checkAgree(first.S), exitIs(first.S, 4))
	mixed := p.mixedApply("d120-seed:settle", 1, ws)
	p.record(mixed, exitIs(mixed.S, 0))
	for i := 1; i <= 2; i++ {
		w := p.goApply("d120-seed:warm", i, ws, "", 0)
		p.record(w, checkNoDiff(w.S, 0))
	}
	p.takeSnapshot("p28-d120")
}

func exitIs(s perfSample, want int) []string {
	if s.Exit != want {
		return []string{fmt.Sprintf("exit %d, want %d", s.Exit, want)}
	}
	return nil
}

func (p *perfLab) scD120NoDiff() {
	p.needSnapshot("p28-d120")
	p.revertBoth("p28-d120")
	ws, shape := p.workspace(d120Spec, "d120")
	_ = shape
	for i := 1; i <= p.n(20); i++ {
		r := p.goApply("d120-nodiff", i, ws, "", 0)
		p.record(r, checkNoDiff(r.S, 0), checkAgree(r.S))
	}
	for i := 1; i <= p.n(3); i++ {
		r := p.goPreview("d120-preview", i, ws)
		p.record(r, exitIs(r.S, 0), checkWroteNothing(r.S))
	}
}

func (p *perfLab) scD120Attr() {
	p.needSnapshot("p28-d120")
	sp := d120Spec
	sp.Shell = map[int]string{17: "/bin/sh"}
	ws, _ := p.workspace(sp, "d120-attr")
	for i := 1; i <= p.n(20); i++ {
		if i == 1 {
			p.revertBoth("p28-d120")
		} else {
			p.revertServer("p28-d120")
		}
		first := p.goApply("d120-attr:first", i, ws, "", 0)
		p.record(first, checkOneAttribute(first.S, "loginshell"), checkAgree(first.S), exitIs(first.S, 4))
		rerun := p.goApply("d120-attr:rerun", i, ws, "", 0)
		p.record(rerun, checkRerun(rerun.S), checkAgree(rerun.S), exitIs(rerun.S, 4))
	}
}

// create100Spec is the 120/40 dataset plus a hundred users who join its groups.
func create100Spec() perfSpec { return perfSpec{Users: 220, Groups: 40} }

func (p *perfLab) create100(scenario string, idx int, ws string, binary string, limit int, passwords bool) {
	if passwords {
		p.setSpec(ws, perfSpec{Users: 220, Groups: 40, Passwords: passwordsFor(121, 220)})
	}
	first := p.goApply(scenario+":first", idx, ws, binary, limit)
	checks := [][]string{checkCreates(first.S, 100), checkAgree(first.S), exitIs(first.S, 4)}
	if passwords {
		if got := first.S.Server.Commands["passwd"]; got != 100 {
			checks = append(checks, []string{fmt.Sprintf("the server logged %d passwd, want 100", got)})
		}
	}
	p.record(first, checks...)
	rerun := p.goApply(scenario+":rerun", idx, ws, binary, limit)
	p.record(rerun, checkRerun(rerun.S), checkAgree(rerun.S), exitIs(rerun.S, 4))
}

func (p *perfLab) scD120Create100() {
	p.needSnapshot("p28-d120")
	ws, shape := p.workspace(create100Spec(), "d120+100")
	p.t.Logf("dataset d120+100: %+v", shape)
	for i := 1; i <= p.n(20); i++ {
		if i == 1 {
			p.revertBoth("p28-d120")
		} else {
			p.revertServer("p28-d120")
		}
		p.create100("d120-create100", i, ws, "", 0, false)
	}
}

func (p *perfLab) scD120Create100PW() {
	p.needSnapshot("p28-d120")
	ws, _ := p.workspace(create100Spec(), "d120+100pw")
	for i := 1; i <= p.n(3); i++ {
		if i == 1 {
			p.revertBoth("p28-d120")
		} else {
			p.revertServer("p28-d120")
		}
		p.create100("d120-create100pw", i, ws, "", 0, true)
	}
}

func (p *perfLab) scD120Modify100() {
	p.needSnapshot("p28-d120")
	sp := d120Spec
	sp.Shell = shellFor(1, 100, "/bin/sh")
	ws, _ := p.workspace(sp, "d120-modify100")
	for i := 1; i <= p.n(5); i++ {
		if i == 1 {
			p.revertBoth("p28-d120")
		} else {
			p.revertServer("p28-d120")
		}
		first := p.goApply("d120-modify100:first", i, ws, "", 0)
		var f []string
		if first.S.PlanKinds["user.update"] != 100 || first.S.Server.Commands["user_mod"] != 100 || first.S.Server.WriteN != 100 {
			f = append(f, fmt.Sprintf("want 100 user.update and 100 user_mod only: plan %v, server %v", first.S.PlanKinds, first.S.Server.perfWrites()))
		}
		p.record(first, f, checkAgree(first.S), exitIs(first.S, 4))
		rerun := p.goApply("d120-modify100:rerun", i, ws, "", 0)
		p.record(rerun, checkRerun(rerun.S), checkAgree(rerun.S), exitIs(rerun.S, 4))
	}
}

// batchLimits are the batch sizes compared for the hundred creates (spec Q2).
var batchLimits = []int{10, 25, 50, 100}

// buildWithBatchLimit builds pilot from this tree with the one constant MaxBatch changed, through go build -overlay: the
// checkout is not touched, and the binary differs from the committed one only in that value.
func (p *perfLab) buildWithBatchLimit(limit int) string {
	t, lv := p.t, p.lv
	if limit == MaxBatch {
		return lv.pilot
	}
	src := filepath.Join(lv.repo, "internal", "identityreconcile", "execute.go")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	const decl = "const MaxBatch = 25"
	if strings.Count(string(data), decl) != 1 {
		t.Fatalf("%s does not declare %q exactly once", src, decl)
	}
	dir, err := os.MkdirTemp(lv.tmp, fmt.Sprintf("overlay-%d-", limit))
	if err != nil {
		t.Fatal(err)
	}
	mod := filepath.Join(dir, "execute.go")
	if err := os.WriteFile(mod, []byte(strings.Replace(string(data), decl, fmt.Sprintf("const MaxBatch = %d", limit), 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	ov := filepath.Join(dir, "overlay.json")
	raw, _ := json.Marshal(map[string]any{"Replace": map[string]string{src: mod}})
	if err := os.WriteFile(ov, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "pilot")
	run(t, lv.repo, "go", "build", "-overlay", ov, "-o", bin, "./cmd/pilot")
	return bin
}

func (p *perfLab) scBatchSweep() {
	p.needSnapshot("p28-d120")
	bins := map[int]string{}
	for _, l := range batchLimits {
		bins[l] = p.buildWithBatchLimit(l)
	}
	ws, _ := p.workspace(create100Spec(), "d120+100")
	// The limits take turns, so a slow stretch of the host falls on all of them alike.
	for i := 1; i <= p.n(5); i++ {
		for _, l := range batchLimits {
			if i == 1 && l == batchLimits[0] {
				p.revertBoth("p28-d120")
			} else {
				p.revertServer("p28-d120")
			}
			p.create100(fmt.Sprintf("batch-sweep-%d", l), i, ws, bins[l], l, false)
		}
	}
}

func (p *perfLab) scD120Mixed() {
	p.needSnapshot("p28-d120")
	ws, _ := p.workspace(d120Spec, "d120")
	// A mixed run with nothing to change: the steady state of the whole reconcile.
	p.revertBoth("p28-d120")
	for i := 1; i <= p.n(3); i++ {
		r := p.mixedApply("d120-mixed:nodiff", i, ws)
		p.record(r, exitIs(r.S, 0), checkWroteNothing(r.S))
	}
	// One attribute changed: the Go phase writes one user_mod and runs the entry, the playbook then refreshes and settles.
	sp := d120Spec
	sp.Shell = map[int]string{17: "/bin/sh"}
	wsAttr, _ := p.workspace(sp, "d120-attr")
	for i := 1; i <= p.n(3); i++ {
		p.revertBoth("p28-d120")
		r := p.mixedApply("d120-mixed:attr", i, wsAttr)
		p.record(r, exitIs(r.S, 0), checkOneAttributeMixed(r.S, "loginshell"))
	}
	// A hundred creates through the whole reconcile.
	wsCreate, _ := p.workspace(create100Spec(), "d120+100")
	for i := 1; i <= p.n(2); i++ {
		p.revertBoth("p28-d120")
		r := p.mixedApply("d120-mixed:create100", i, wsCreate)
		p.record(r, exitIs(r.S, 0), checkCreates(r.S, 100))
	}
}

func checkOneAttributeMixed(s perfSample, field string) []string {
	var f []string
	if len(s.PlanKinds) != 1 || s.PlanKinds["user.update"] != 1 || len(s.PlanFields) != 1 || s.PlanFields[field] != 1 {
		f = append(f, fmt.Sprintf("the Go phase planned %v %v, want one user.update of %s", s.PlanKinds, s.PlanFields, field))
	}
	if s.WriteCmds != 1 {
		f = append(f, fmt.Sprintf("the Go phase sent %d write commands, want 1", s.WriteCmds))
	}
	return f
}

// d120wSpec is the 120/40 dataset with a wider roster of the other sections (perfSections): the mixed run and the legacy
// engine have something of hosts, HBAC and sudo to do.
var d120wSpec = perfSpec{Users: 120, Groups: 40, Wide: true}

// scD120WideSeed makes the wide roster's other sections on top of the 120/40 snapshot, with a mixed run (the Go engine has nothing to
// write; the identity playbook creates the hosts, host groups, rules and command groups), and takes the snapshot the wide mixed
// scenario starts from.
func (p *perfLab) scD120WideSeed() {
	p.needSnapshot("p28-d120")
	p.revertBoth("p28-d120")
	ws, shape := p.workspace(d120wSpec, "d120w")
	p.t.Logf("dataset d120w: %+v", shape)
	first := p.mixedApply("d120w-seed:first-sections", 1, ws)
	p.record(first, exitIs(first.S, 0))
	again := p.mixedApply("d120w-seed:settled", 1, ws)
	p.record(again, exitIs(again.S, 0), checkWroteNothing(again.S))
	p.takeSnapshot("p28-d120w")
}

func (p *perfLab) scD120WideMixed() {
	p.needSnapshot("p28-d120w")
	ws, _ := p.workspace(d120wSpec, "d120w")
	p.revertBoth("p28-d120w")
	for i := 1; i <= p.n(3); i++ {
		r := p.mixedApply("d120w-mixed:nodiff", i, ws)
		p.record(r, exitIs(r.S, 0), checkWroteNothing(r.S))
	}
	sp := d120wSpec
	sp.Shell = map[int]string{17: "/bin/sh"}
	wsAttr, _ := p.workspace(sp, "d120w-attr")
	for i := 1; i <= p.n(1); i++ {
		p.revertBoth("p28-d120w")
		r := p.mixedApply("d120w-mixed:attr", i, wsAttr)
		p.record(r, exitIs(r.S, 0), checkOneAttributeMixed(r.S, "loginshell"))
	}
}

// d1000 stages: the growth of the dataset, each stage created on top of the one before and measured at its size.
var d1000Stages = []perfSpec{{Users: 250, Groups: 50}, {Users: 500, Groups: 100}, {Users: 1000, Groups: 200}}

func (p *perfLab) scD1000Seed() {
	t := p.t
	p.revertBoth(p.base)
	p.countSSH()
	ws, _ := p.workspace(d1000Stages[0], "d1000")
	prevUsers := 0
	for _, sp := range d1000Stages {
		shape := p.setSpec(ws, sp)
		p.shapes[fmt.Sprintf("d%d", sp.Users)] = shape
		name := fmt.Sprintf("d1000-seed:%d-%d", sp.Users, sp.Groups)
		t.Logf("stage %d/%d: %+v", sp.Users, sp.Groups, shape)
		first := p.goApply(name+":create", 1, ws, "", 0)
		p.record(first, checkCreates(first.S, sp.Users-prevUsers), checkAgree(first.S), exitIs(first.S, 4))
		prevUsers = sp.Users
		for i := 1; i <= p.n(5); i++ {
			r := p.goApply(name+":nodiff", i, ws, "", 0)
			p.record(r, checkNoDiff(r.S, 4), checkAgree(r.S))
		}
	}
	settle := p.mixedApply("d1000-seed:settle", 1, ws)
	p.record(settle, exitIs(settle.S, 0))
	for i := 1; i <= 2; i++ {
		w := p.goApply("d1000-seed:warm", i, ws, "", 0)
		p.record(w, checkNoDiff(w.S, 0))
	}
	p.takeSnapshot("p28-d1000")
}

var d1000Spec = perfSpec{Users: 1000, Groups: 200}

func (p *perfLab) scD1000NoDiff() {
	p.needSnapshot("p28-d1000")
	p.revertBoth("p28-d1000")
	ws, _ := p.workspace(d1000Spec, "d1000")
	for i := 1; i <= p.n(20); i++ {
		r := p.goApply("d1000-nodiff", i, ws, "", 0)
		p.record(r, checkNoDiff(r.S, 0), checkAgree(r.S))
	}
}

// scD1000Complete: the preview reads the whole directory and says how many users and groups it saw; the server's own count
// is the other side. A read cut short would be an error in the engine, and a count that is merely smaller would show here.
func (p *perfLab) scD1000Complete() {
	p.needSnapshot("p28-d1000")
	p.revertBoth("p28-d1000")
	ws, shape := p.workspace(d1000Spec, "d1000")
	srvUsers, srvGroups := p.serverCount("user"), p.serverCount("group")
	p.t.Logf("the server holds %d users and %d groups; the roster declares %d and %d", srvUsers, srvGroups, shape.Users, shape.Groups)
	for i := 1; i <= p.n(5); i++ {
		r := p.goPreview("d1000-preview", i, ws)
		p.record(r, exitIs(r.S, 0), checkWroteNothing(r.S), checkComplete(r.S.ObservedUsers, r.S.ObservedGroups, srvUsers, srvGroups, shape.Users, shape.Groups))
	}
}

func (p *perfLab) scD1000Attr() {
	p.needSnapshot("p28-d1000")
	sp := d1000Spec
	sp.Shell = map[int]string{517: "/bin/sh"}
	ws, _ := p.workspace(sp, "d1000-attr")
	for i := 1; i <= p.n(5); i++ {
		if i == 1 {
			p.revertBoth("p28-d1000")
		} else {
			p.revertServer("p28-d1000")
		}
		first := p.goApply("d1000-attr:first", i, ws, "", 0)
		p.record(first, checkOneAttribute(first.S, "loginshell"), checkAgree(first.S), exitIs(first.S, 4))
		rerun := p.goApply("d1000-attr:rerun", i, ws, "", 0)
		p.record(rerun, checkRerun(rerun.S), checkAgree(rerun.S), exitIs(rerun.S, 4))
	}
}

// scD1000Delete: three users and a group are declared absent in a 1,000/200 roster; the names the server holds afterwards
// are the names it held minus those three users (and their private groups) and that group, and nothing else.
func (p *perfLab) scD1000Delete() {
	p.needSnapshot("p28-d1000")
	p.revertBoth("p28-d1000")
	absentUsers := map[int]bool{998: true, 999: true, 1000: true}
	absentGroups := map[int]bool{199: true}
	sp := d1000Spec
	sp.AbsentUsers, sp.AbsentGroups = absentUsers, absentGroups
	ws, _ := p.workspace(sp, "d1000-delete")
	usersBefore, groupsBefore := p.serverNames("user"), p.serverNames("group")
	r := p.goApply("d1000-delete", 1, ws, "", 0)
	var deletedUsers, deletedGroups []string
	for i := range absentUsers {
		deletedUsers = append(deletedUsers, perfUserName(i)) // the user's private group goes with it, and group-find does not list it
	}
	for g := range absentGroups {
		deletedGroups = append(deletedGroups, perfGroupName(g))
	}
	usersAfter, groupsAfter := p.serverNames("user"), p.serverNames("group")
	var f []string
	if r.S.PlanKinds["user.delete"] != 3 || r.S.PlanKinds["group.delete"] != 1 {
		f = append(f, fmt.Sprintf("the plan is %v, want 3 user.delete and 1 group.delete", r.S.PlanKinds))
	}
	f = append(f, checkDeletedExactly(usersBefore, usersAfter, deletedUsers)...)
	f = append(f, checkDeletedExactly(groupsBefore, groupsAfter, deletedGroups)...)
	p.record(r, f, checkAgree(r.S), exitIs(r.S, 4))
	again := p.goApply("d1000-delete:rerun", 1, ws, "", 0)
	p.record(again, checkRerun(again.S), exitIs(again.S, 4))
}

// scD1000BigMember: a group of five hundred members is created, left alone on a rerun, and shrunk by one member: one
// group_remove_member of one user, and 499 members are left.
func (p *perfLab) scD1000BigMember() {
	p.needSnapshot("p28-d1000")
	p.revertBoth("p28-d1000")
	sp := d1000Spec
	sp.BigGroup = 500
	ws, _ := p.workspace(sp, "d1000-big")
	create := p.goApply("d1000-big:create", 1, ws, "", 0)
	var f []string
	if n := p.groupMemberCount(perfBigGroup); n != 500 {
		f = append(f, fmt.Sprintf("the big group holds %d members after the create, want 500", n))
	}
	p.record(create, f, checkAgree(create.S), exitIs(create.S, 4))
	again := p.goApply("d1000-big:rerun", 1, ws, "", 0)
	p.record(again, checkRerun(again.S), exitIs(again.S, 4))
	sp.BigGroup = 499
	p.setSpec(ws, sp)
	shrink := p.goApply("d1000-big:shrink", 1, ws, "", 0)
	f = nil
	if n := p.groupMemberCount(perfBigGroup); n != 499 {
		f = append(f, fmt.Sprintf("the big group holds %d members after the shrink, want 499", n))
	}
	if shrink.S.PlanKinds["group.member_user.remove"] != 1 || shrink.S.PlanOps != 1 {
		f = append(f, fmt.Sprintf("the plan is %v, want one group.member_user.remove", shrink.S.PlanKinds))
	}
	p.record(shrink, f, checkAgree(shrink.S), exitIs(shrink.S, 4))
}

// scLegacy is the Ansible engine on the wide 120/40 roster and the same VMs: the whole identity reconcile (the preview, the
// apply and the idempotency run over every section of the roster), for the numbers the Go paths are not compared with by a
// factor. It starts from the baseline snapshot, so its first apply creates everything, users and groups included.
func (p *perfLab) scLegacy() {
	p.revertBoth(p.base)
	p.countSSH()
	ws, _ := p.workspace(d120wSpec, "legacy-d120w")
	first := p.legacyApply("legacy-d120w:first-apply", 1, ws)
	p.record(first, exitIs(first.S, 0))
	for i := 1; i <= p.n(1); i++ {
		r := p.legacyApply("legacy-d120w:nodiff", i, ws)
		p.record(r, exitIs(r.S, 0))
	}
	p.takeSnapshot("p28-legacy-d120w")
	sp := d120wSpec
	sp.Shell = map[int]string{17: "/bin/sh"}
	wsAttr, _ := p.workspace(sp, "legacy-d120w-attr")
	for i := 1; i <= p.n(1); i++ {
		p.revertBoth("p28-legacy-d120w")
		r := p.legacyApply("legacy-d120w:attr", i, wsAttr)
		p.record(r, exitIs(r.S, 0))
	}
}

// scProfile shows where the identity playbook's time goes in a mixed run: the playbook is run once by itself on the settled
// dataset, with the command line pilot gives it (the users/groups engine variable set to go, the observation file) and the
// profile_tasks callback, at 120/40, at 120/40 with the wide roster and at 1,000/200. The callback's recap (every task, the
// slowest twenty and the seconds by what the task name says it is about) goes into the summary.
func (p *perfLab) scProfile() {
	for _, d := range []struct {
		snapshot string
		spec     perfSpec
		key      string
	}{{"p28-d120", d120Spec, "profile_d120"}, {"p28-d120w", d120wSpec, "profile_d120w"}, {"p28-d1000", d1000Spec, "profile_d1000"}} {
		p.needSnapshot(d.snapshot)
		p.revertBoth(d.snapshot)
		ws, _ := p.workspace(d.spec, d.key)
		obs := filepath.Join(p.lv.tmp, d.key+"-observation.json")
		if err := os.WriteFile(obs, nil, 0o600); err != nil {
			p.t.Fatal(err)
		}
		extra, _ := json.Marshal(map[string]string{"pilot_identity_auth_cache_output": obs})
		cmd := exec.Command("ansible-playbook", "playbooks/apply/freeipa-identity-apply.yml", "-i", filepath.Join(ws, "inventory.yml"),
			"--limit", "ipa1,"+p.lv.cliFQDN, "-e", "stage=sandbox", "-e", "pilot_identity_users_groups_engine=go",
			"-e", "@"+filepath.Join(ws, ".vault", "main.yaml"), "-e", string(extra))
		cmd.Dir = p.lv.repo
		cmd.Env = append(p.lv.pilotEnv(), "ANSIBLE_CALLBACKS_ENABLED=ansible.posix.profile_tasks", "PROFILE_TASKS_TASK_OUTPUT_LIMIT=all", "PROFILE_TASKS_SORT_ORDER=descending", "ANSIBLE_NOCOLOR=1")
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		start := time.Now()
		err := cmd.Run()
		wall := time.Since(start).Seconds()
		tasks := parseProfileTasks(out.String())
		p.facts[d.key] = map[string]any{"wall_seconds": wall, "exit": exitCodeOf(err), "tasks_listed": len(tasks),
			"slowest_tasks": tasks[:min(len(tasks), 20)], "seconds_by_task_name_bucket": bucketProfile(tasks)}
		p.t.Logf("profile %s: exit %d, %.1fs, %d task lines; by bucket: %v; slowest: %v", d.key, exitCodeOf(err), wall, len(tasks), bucketProfile(tasks), tasks[:min(len(tasks), 6)])
		if err != nil || len(tasks) == 0 {
			p.t.Errorf("profile %s: %v, %d task lines:\n%s", d.key, err, len(tasks), tail(out.String(), 1500))
		}
	}
}

// expectFires records a control: a gate of the benchmark must report something for a run built to break it. A gate that stays
// quiet here would be quiet on a bad measurement too, and the driver fails.
func (p *perfLab) expectFires(name string, reasons []string) {
	p.t.Helper()
	controls, _ := p.facts["controls"].([]map[string]any)
	if len(reasons) == 0 {
		p.t.Errorf("control %q: the gate did not fire on the run built to break it", name)
	}
	p.facts["controls"] = append(controls, map[string]any{"gate": name, "fired": len(reasons) > 0, "reasons": reasons})
	p.t.Logf("  control %-40s fired=%v %v", name, len(reasons) > 0, reasons)
}

// scControls runs the benchmark's own gates against real runs built to break each of them: a second attribute changed
// where a rerun with nothing to write is asserted, two attributes where one is, a deletion declared wrongly, and a count of the
// server's users that is one too many. Every control must fire; the runs that must pass (the same checks on the runs they are
// meant for) are recorded as samples and pass or fail as any other.
func (p *perfLab) scControls() {
	p.needSnapshot("p28-d120")
	sp := d120Spec
	sp.Shell = map[int]string{17: "/bin/sh"}
	ws, _ := p.workspace(sp, "controls")
	p.revertBoth("p28-d120")
	one := p.goApply("controls:one-attribute", 1, ws, "", 0)
	p.record(one, checkOneAttribute(one.S, "loginshell"), checkAgree(one.S), exitIs(one.S, 4))

	// A second attribute, where the next run is asserted to be a rerun with nothing to write.
	sp.Shell = map[int]string{17: "/bin/sh", 18: "/bin/sh"}
	p.setSpec(ws, sp)
	second := p.goApply("controls:second-attribute", 1, ws, "", 0)
	p.record(second, checkOneAttribute(second.S, "loginshell"), exitIs(second.S, 4))
	p.expectFires("rerun writes nothing (a run that wrote)", checkRerun(second.S))
	p.expectFires("no diff (a run that wrote)", checkNoDiff(second.S, 4))

	// Two attributes where one is asserted.
	p.revertServer("p28-d120")
	sp.Shell = map[int]string{17: "/bin/sh", 18: "/bin/sh", 19: "/bin/sh"}
	p.setSpec(ws, sp)
	three := p.goApply("controls:three-attributes", 1, ws, "", 0)
	p.record(three, exitIs(three.S, 4))
	p.expectFires("one attribute (a run that changed three)", checkOneAttribute(three.S, "loginshell"))

	// A deletion: declared right it passes, declared wrongly the gate fires.
	p.revertServer("p28-d120")
	del := d120Spec
	del.AbsentUsers = map[int]bool{120: true}
	wsDel, _ := p.workspace(del, "controls-delete")
	usersBefore, groupsBefore := p.serverNames("user"), p.serverNames("group")
	r := p.goApply("controls:delete-one-user", 1, wsDel, "", 0)
	usersAfter, groupsAfter := p.serverNames("user"), p.serverNames("group")
	right := append(checkDeletedExactly(usersBefore, usersAfter, []string{perfUserName(120)}), checkDeletedExactly(groupsBefore, groupsAfter, nil)...)
	p.record(r, right, exitIs(r.S, 4))
	p.expectFires("deleted exactly (the wrong user declared)", checkDeletedExactly(usersBefore, usersAfter, []string{perfUserName(119)}))
	p.expectFires("deleted exactly (nothing declared)", checkDeletedExactly(usersBefore, usersAfter, nil))

	// Completeness: the preview's own count against a server count that is one too many, and the counts cut at the default limit.
	pv := p.goPreview("controls:preview", 1, wsDel)
	srvUsers, srvGroups := p.serverCount("user"), p.serverCount("group")
	p.record(pv, exitIs(pv.S, 0), checkComplete(pv.S.ObservedUsers, pv.S.ObservedGroups, srvUsers, srvGroups, d120Spec.Users-1, d120Spec.Groups))
	p.expectFires("complete (the server holds one more user)", checkComplete(pv.S.ObservedUsers, pv.S.ObservedGroups, srvUsers+1, srvGroups, d120Spec.Users-1, d120Spec.Groups))
	p.expectFires("complete (a read cut at 100)", checkComplete(100, 100, srvUsers, srvGroups, d120Spec.Users-1, d120Spec.Groups))
}
