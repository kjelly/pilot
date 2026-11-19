package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/identitylock"
	"github.com/kjelly/pilot/internal/identityreconcile"
)

// `pilot reconcile --engine golang --scope full` runs the roster's HBAC as the Go engine's second stage (spec
// 2026-11-19 phase 3a §7): Go(users/groups) -> the playbook's first apply run (the settlement deferred) ->
// Go(HBAC) -> the playbook's second apply run (--tags client-cache), the one that settles. Through the real cobra
// tree over the fake FreeIPA of the users-groups apply tests, an HBAC model of its own (hbacFake) and the
// ansible-playbook script of the mixed CLI tests; what these prove is the plumbing: which runs happen in which order
// with which variables, what a failure of each part does to the rest, the exit code and the result file. What
// the stage does to a real server is the live driver's.

const hbacRosterTail = `hbac:
  rules:
    - name: p3-login
      subjects: {users: [p1-self]}
      targets: {hostcat: all}
      services: [sshd]
`

func hbacRoster(users string) string {
	return users + hbacRosterTail
}

func newHBACMixedEnv(t *testing.T, roster string) (*mixedCLIEnv, *hbacFake) {
	t.Helper()
	e := newMixedCLIEnv(t, roster)
	h := newHBACFake(t)
	h.install(e.applyEnv)
	h.onWrite = func(w []string) {
		line, _ := json.Marshal(append([]string{"HBAC-WRITE"}, w...))
		appendEvent(t, e.log, string(line))
	}
	return e, h
}

// applyRuns are the arguments of every apply run of the identity playbook, in order.
func (e *mixedCLIEnv) applyRuns() [][]string {
	var out [][]string
	for _, args := range e.playbookCalls() {
		if len(args) == 0 || args[0] == "IPA-WRITE" || args[0] == "HBAC-WRITE" {
			continue
		}
		if strings.Contains(strings.Join(args, " "), "freeipa-identity-apply.yml") && !slices.Contains(args, "--check") {
			out = append(out, args)
		}
	}
	return out
}

// after is the runs of e after the first "freeipa-identity-apply.yml apply", with consecutive writes of the HBAC
// stage folded into one.
func foldedRuns(runs []string) []string {
	var out []string
	for _, r := range runs {
		if r == "hbac-write" && len(out) > 0 && out[len(out)-1] == "hbac-write" {
			continue
		}
		out = append(out, r)
	}
	return out
}

const (
	hbacEngineArg = identityreconcile.HBACEngineVar + "=" + identityreconcile.HBACEngineGo
	deferArg      = identityreconcile.CacheSettleVar + "=" + identityreconcile.CacheSettleDefer
)

// The run that goes well: the users and groups, the playbook's first run (told to defer), the HBAC stage (its own
// entry, then its writes), the playbook's second run (--tags client-cache, no deferral) which acknowledges. The rule
// is on the server afterwards, the result file has the stage, and the obligation is settled.
func TestMixedRunWritesTheHBACStageBetweenTheTwoPlaybookRuns(t *testing.T) {
	e, h := newHBACMixedEnv(t, hbacRoster(rosterWithNewUser()))
	result := filepath.Join(e.dir, "result.json")
	out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
	if err != nil || processExitCode(err) != 0 {
		t.Fatalf("exit %d: %v\n%s", processExitCode(err), err, out)
	}
	want := []string{
		"preflight.yml apply", "freeipa-server-apply.yml check", "freeipa-server-apply.yml apply",
		"preflight.yml apply", "freeipa-identity-apply.yml check",
		"freeipa-identity-auth-cache.yml apply", "ipa-write", // the users and groups phase: its entry and its write
		"freeipa-identity-apply.yml apply",                    // the playbook's first run
		"freeipa-identity-auth-cache.yml apply", "hbac-write", // the HBAC stage: its own entry, then its writes
		"freeipa-identity-apply.yml apply", // the playbook's second run
	}
	if got := foldedRuns(e.runs()); !slices.Equal(got, want) {
		t.Fatalf("runs:\n got %v\nwant %v\n%s", got, want, out)
	}
	runs := e.applyRuns()
	if len(runs) != 2 {
		t.Fatalf("the identity playbook's apply ran %d times, want 2: %v", len(runs), runs)
	}
	first, second := runs[0], runs[1]
	for name, args := range map[string][]string{"first": first, "second": second, "check": e.identityArgs("check")} {
		if !hasExtraVar(args, engineArg) || !hasExtraVar(args, hbacEngineArg) || !hasExtraVar(args, obsKey) {
			t.Errorf("the %s run was not told the engines and handed the observation file: %v", name, args)
		}
	}
	if !hasExtraVar(first, deferArg) || slices.Contains(first, "--tags") {
		t.Errorf("the first apply run must defer the settlement and select no tags: %v", first)
	}
	if hasExtraVar(second, deferArg) || !slices.Contains(second, "--tags") || !slices.Contains(second, identityreconcile.ClientCacheTag) {
		t.Errorf("the second apply run must select --tags %s and not defer: %v", identityreconcile.ClientCacheTag, second)
	}
	if chk := e.identityArgs("check"); hasExtraVar(chk, deferArg) || slices.Contains(chk, "--tags") {
		t.Errorf("the preview's check run was told to defer or select tags: %v", chk)
	}
	r := h.rule("p3-login")
	if r == nil || r.hostCat != "all" || !r.users["p1-self"] || !r.services["sshd"] || !r.enabled {
		t.Fatalf("the rule on the server: %+v", r)
	}
	doc := readApplyDoc(t, result)
	if doc.Scope != reconcileScopeFull || doc.Verdict != identityreconcile.VerdictOK || doc.ExitCode != 0 || doc.HBAC == nil || !doc.HBAC.Ran ||
		doc.HBAC.Result == nil || !doc.HBAC.Result.Verify.OK() || !doc.HBAC.Result.Entry.Ran || doc.Authorization.Owed || !doc.Authorization.ObservedAcked {
		t.Fatalf("result file: scope %q verdict %q exit %d hbac %+v authorization %+v", doc.Scope, doc.Verdict, doc.ExitCode, doc.HBAC, doc.Authorization)
	}
	var created bool
	for _, op := range doc.HBAC.Result.Ops {
		created = created || (op.Operation.Kind == identityreconcile.KindHBACRuleCreate && op.Final() == identityreconcile.OutcomeSuccess)
	}
	if !created || doc.HBAC.Stats.Writes == 0 {
		t.Errorf("the result's HBAC part does not say the rule was created: %+v", doc.HBAC)
	}
	if slices.Contains(doc.Plan1.Reports.NotInScope, "hbac") {
		t.Errorf("hbac is reported as left to the playbook in a run that writes it: %v", doc.Plan1.Reports.NotInScope)
	}
	if !strings.Contains(out, "HBAC 階段") {
		t.Errorf("the output does not say what the HBAC stage did:\n%s", out)
	}
	run := identityRun(t)
	if run.Metadata["hbac_engine"] != identityreconcile.HBACEngineGo {
		t.Errorf("the run's metadata does not say the HBAC engine: %v", run.Metadata)
	}
	types := eventTypes(runEvents(t, run.RunID))
	var hbacEvents int
	for _, ev := range runEvents(t, run.RunID) {
		if strings.HasPrefix(ev.op, "identity:hbac:") {
			hbacEvents++
		}
	}
	if hbacEvents == 0 || !slices.Contains(types, "identity.op") {
		t.Errorf("the HBAC stage's events are not in the run's journal: %v", types)
	}
	assertNoSecretAnywhere(t, err, out, result)
}

// A first playbook run that fails ends the apply: no HBAC stage (no read of it after the first run, no entry, no write)
// and no second run, the obligation stays owed, and the result file says why the stage did not run.
func TestMixedRunNeverStartsTheHBACStageAfterAFailedFirstRun(t *testing.T) {
	t.Setenv("P27_IDENTITY_EXIT", "2")
	e, h := newHBACMixedEnv(t, hbacRoster(rosterWithNewUser()))
	result := filepath.Join(e.dir, "result.json")
	out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
	if code := processExitCode(err); code != 1 {
		t.Fatalf("exit %d (%v), want 1\n%s", code, err, out)
	}
	if n := len(e.applyRuns()); n != 1 {
		t.Fatalf("the identity playbook's apply ran %d times after a failed first run, want 1: %v", n, e.runs())
	}
	if len(h.written()) != 0 {
		t.Fatalf("the HBAC stage wrote after a failed first run: %v", h.written())
	}
	entries := 0
	for _, r := range e.runs() {
		if r == "freeipa-identity-auth-cache.yml apply" {
			entries++
		}
	}
	if entries != 1 {
		t.Errorf("the entry ran %d times, want only the users and groups phase's: %v", entries, e.runs())
	}
	doc := readApplyDoc(t, result)
	if doc.HBAC == nil || doc.HBAC.Ran || doc.HBAC.Skipped == "" || !doc.Authorization.Owed {
		t.Fatalf("result file: hbac %+v authorization %+v", doc.HBAC, doc.Authorization)
	}
}

// An HBAC plan that is blocked when the stage reads (after the playbook): a hostgroup the roster declares and the
// playbook was to create is not on the server. The preview, made before the playbook, assumed it would be and let the
// run start; the stage writes nothing, says so, and the run is a failure with exit 1 (not 3: the playbook's first run
// has run), the playbook's second run still runs, and the users and groups part, which wrote nothing, makes this an
// ordinary failure and not a partial application.
func TestMixedRunWithAHostgroupThePlaybookDidNotCreateFailsInTheHBACStage(t *testing.T) {
	roster := strings.Replace(captureRoster, "%s", "/bin/sh", 1) + `hostgroups:
  - {name: hg-x}
hbac:
  rules:
    - name: p3-hosts
      subjects: {users: [p1-self]}
      targets: {hostgroups: [hg-x]}
      services: [sshd]
`
	e, h := newHBACMixedEnv(t, roster)
	result := filepath.Join(e.dir, "result.json")
	out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
	if code := processExitCode(err); code != 1 {
		t.Fatalf("exit %d (%v), want 1, not the 3 of a plan blocked with nothing written\n%s", code, err, out)
	}
	if !strings.Contains(err.Error(), "沒有寫入任何東西") || errors.Is(err, delivery.ErrPartiallyApplied) || errors.Is(err, identityreconcile.ErrBlocked) {
		t.Fatalf("err = %v: want HBAC's own failure that says nothing was written, not a partial application and not blocked", err)
	}
	if len(h.written()) != 0 {
		t.Fatalf("a blocked HBAC plan wrote %v", h.written())
	}
	if n := len(e.applyRuns()); n != 2 {
		t.Fatalf("the playbook's apply ran %d times, want both (the second settles whatever was written): %v", n, e.runs())
	}
	doc := readApplyDoc(t, result)
	if doc.HBAC == nil || !doc.HBAC.Ran || doc.HBAC.Result == nil || len(doc.HBAC.Result.Plan1.Blocked) == 0 || doc.Verdict != identityreconcile.VerdictFailed {
		t.Fatalf("result file: verdict %q hbac %+v", doc.Verdict, doc.HBAC)
	}
}

// What fails after the playbook's first run: a stage that fails part way (a member the server does not have) and a second
// run that fails. In both the step fails and the run is a partial application with exit 1, since the stage wrote the
// rule; what the stage wrote stays; and the second run runs after a failed stage, because what was written needs the
// refresh.
func TestMixedRunWhoseHBACStageOrSecondPlaybookRunFailsIsAPartialApplication(t *testing.T) {
	for _, tc := range []struct {
		name     string
		gate     string
		env      map[string]string
		setup    func(h *hbacFake)
		wantText string
		wantRule func(t *testing.T, r *hbacFakeRule)
	}{
		{name: "a stage that fails part way", gate: "mixed-hbac-result,mixed-hbac-or-second-run-failed", setup: func(h *hbacFake) { h.failMember["hbacrule_add_user:p3-login"] = true },
			wantText: "HBAC 階段沒有完成", wantRule: func(t *testing.T, r *hbacFakeRule) {
				if r == nil || r.users["p1-self"] {
					t.Fatalf("the rule on the server: %+v", r)
				}
			}},
		{name: "a second run that fails", gate: "mixed-hbac-or-second-run-failed", env: map[string]string{"P27_SECOND_EXIT": "2"}, wantText: "第 2 次執行",
			wantRule: func(t *testing.T, r *hbacFakeRule) {
				if r == nil || !r.users["p1-self"] {
					t.Fatalf("the rule on the server: %+v", r)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			e, h := newHBACMixedEnv(t, hbacRoster(strings.Replace(captureRoster, "%s", "/bin/sh", 1)))
			if tc.setup != nil {
				tc.setup(h)
			}
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
			if code := processExitCode(err); code != 1 {
				t.Fatalf("exit %d (%v), want 1\n%s", code, err, out)
			}
			if !errors.Is(err, delivery.ErrPartiallyApplied) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("err = %v, want a partial application that says %q", err, tc.wantText)
			}
			if n := len(e.applyRuns()); n != 2 {
				t.Fatalf("the playbook's apply ran %d times, want 2: %v", n, e.runs())
			}
			tc.wantRule(t, h.rule("p3-login"))
			doc := readApplyDoc(t, result)
			if doc.Verdict != identityreconcile.VerdictPartial || doc.HBAC == nil || doc.HBAC.Result == nil || !doc.HBAC.Result.Committed() {
				t.Fatalf("result file: verdict %q hbac %+v", doc.Verdict, doc.HBAC)
			}
		})
	}
}

// The second run's observation is what settles: it does not acknowledge (a client that did not finish): exit 4, the
// obligation is owed from this run (the HBAC stage's entry ran), and the stage's work is applied and verified.
func TestMixedRunWhoseSecondPlaybookRunDoesNotAcknowledgeIsUnsettledExit4(t *testing.T) {
	t.Setenv("P27_SECOND_OBSERVE", "notacked")
	e, _ := newHBACMixedEnv(t, hbacRoster(strings.Replace(captureRoster, "%s", "/bin/sh", 1)))
	result := filepath.Join(e.dir, "result.json")
	out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
	if code := processExitCode(err); code != 4 || !errors.Is(err, identityreconcile.ErrUnsettled) {
		t.Fatalf("exit %d (%v), want 4 unsettled\n%s", code, err, out)
	}
	doc := readApplyDoc(t, result)
	if doc.Verdict != identityreconcile.VerdictUnsettled || !doc.Authorization.Owed || doc.Authorization.Source != identityreconcile.ObligationThisRun ||
		doc.Playbook == nil || doc.Playbook.Observation == nil || doc.Playbook.Observation.Acked || doc.HBAC == nil || !doc.HBAC.Result.Verify.OK() {
		t.Fatalf("result file: verdict %q authorization %+v playbook %+v hbac %+v", doc.Verdict, doc.Authorization, doc.Playbook, doc.HBAC)
	}
}

// An observation of the first run alone must not settle: a second run that wrote none leaves the obligation owed even
// though the first run's file (told to defer) was accepted.
func TestMixedRunSettlesByTheLastRunsObservationOnly(t *testing.T) {
	t.Setenv("P27_SECOND_OBSERVE", "none")
	e, _ := newHBACMixedEnv(t, hbacRoster(strings.Replace(captureRoster, "%s", "/bin/sh", 1)))
	out, err := runReconcileCLI(t, mixedArgs()...)
	if code := processExitCode(err); code != 4 {
		t.Fatalf("exit %d (%v), want 4: a second run that observed nothing settles nothing\n%s", code, err, out)
	}
	if n := len(e.applyRuns()); n != 2 {
		t.Fatalf("apply runs %d, want 2", n)
	}
}

// A preview with an HBAC plan that blocks: the Go preview fails with exit 3 before any playbook task, and the plan file
// (--plan-out) is the whole of it, the HBAC plan next to the users and groups plan, in a document whose scope is full.
func TestMixedPreviewPlansTheHBACAndBlocksBeforeThePlaybook(t *testing.T) {
	previewArgs := func(more ...string) []string {
		return append([]string{"--engine", "golang", "--preview-only", "--scope", "full", "--component", "freeipa-identity", "--timeout", "2m"}, more...)
	}
	t.Run("a clean plan is in the plan file", func(t *testing.T) {
		e, h := newHBACMixedEnv(t, hbacRoster(rosterWithNewUser()))
		plan := filepath.Join(e.dir, "plan.json")
		out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
		if err != nil {
			t.Fatalf("exit %d: %v\n%s", processExitCode(err), err, out)
		}
		data, rerr := os.ReadFile(plan)
		if rerr != nil {
			t.Fatal(rerr)
		}
		var doc identityreconcile.Document
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Scope != reconcileScopeFull || doc.HBAC == nil || !doc.HBAC.Preview || doc.Schema != identityreconcile.DocumentSchema {
			t.Fatalf("plan document: scope %q hbac %+v schema %q", doc.Scope, doc.HBAC, doc.Schema)
		}
		kinds := map[string]bool{}
		for _, op := range doc.HBAC.Operations {
			kinds[op.Kind] = true
		}
		if !kinds[identityreconcile.KindHBACRuleCreate] || !kinds[identityreconcile.KindHBACUserAdd] || !strings.Contains(string(data), "user.create") {
			t.Fatalf("the plan file lacks the HBAC operations or the users: %v\n%s", kinds, data)
		}
		if len(h.written()) != 0 || len(e.a.writeMethods()) != 0 || len(readEvents(t, e.events)) != 0 {
			t.Fatalf("a preview wrote %v %v or took the lock %v", h.written(), e.a.writeMethods(), readEvents(t, e.events))
		}
		if check := e.identityArgs("check"); check == nil || !hasExtraVar(check, hbacEngineArg) {
			t.Fatalf("the playbook's check was not told the HBAC engine: %v", check)
		}
		if !strings.Contains(out, "HBAC") || strings.Contains(out, "不在 Go engine 範圍（由 Ansible engine 處理）：hbac") {
			t.Errorf("the preview does not show the HBAC plan, or says hbac is left to the Ansible engine:\n%s", out)
		}
	})
	t.Run("a blocked HBAC plan is exit 3 and the playbook is never asked", func(t *testing.T) {
		roster := strings.Replace(captureRoster, "%s", "/bin/sh", 1) + `hbac:
  rules:
    - name: p3-ghost
      subjects: {users: [p1-self]}
      targets: {hosts: [ghost.example.test]}
      services: [sshd]
`
		e, _ := newHBACMixedEnv(t, roster)
		out, err := runReconcileCLI(t, previewArgs()...)
		if code := processExitCode(err); code != 3 {
			t.Fatalf("exit %d (%v), want 3\n%s", code, err, out)
		}
		if e.identityArgs("check") != nil || !strings.Contains(out, "阻擋 HBAC p3-ghost") {
			t.Fatalf("the playbook's check ran after a blocked HBAC plan, or the plan does not say what is blocked: %v\n%s", e.runs(), out)
		}
	})
	// Reaches the gate for a read that fails and one that is not a roster the HBAC reader accepts.
	for _, tc := range []struct {
		name    string
		gate    string
		setup   func(e *mixedCLIEnv, h *hbacFake)
		roster  string
		wantErr string
	}{
		{name: "the HBAC read fails", gate: "preview-hbac,mixed-hbac-plan-observe",
			setup: func(e *mixedCLIEnv, h *hbacFake) {
				h.failFind["hbacrule_find"] = string(e.f.fixture("hbacrule-show-not-found"))
			}, roster: rosterWithNewUser(), wantErr: "read HBAC rules"},
		{name: "an hbac section that is not a list of rules", gate: "mixed-hbac-plan-desired",
			roster: strings.Replace(captureRoster, "%s", "/bin/sh", 1) + "hbac:\n  rules: nope\n", wantErr: "roster 的 HBAC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			e, h := newHBACMixedEnv(t, tc.roster)
			if tc.setup != nil {
				tc.setup(e, h)
			}
			out, err := runReconcileCLI(t, previewArgs()...)
			if code := processExitCode(err); code != 1 || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("exit %d (%v), want 1 and %q\n%s", code, err, tc.wantErr, out)
			}
			if e.identityArgs("check") != nil {
				t.Fatalf("the playbook's check ran after the HBAC read failed: %v", e.runs())
			}
		})
	}
}

// The users-groups scope and the default engine are what they were: no HBAC is read, no variable of the HBAC is
// passed, the plan document is the users and groups plan, and hbac is still reported as left to the playbook.
func TestUsersGroupsScopeAndTheAnsibleEngineKnowNothingOfTheHBACStage(t *testing.T) {
	t.Run("--scope users-groups", func(t *testing.T) {
		e := newApplyEnv(t, hbacRoster(rosterWithNewUser()))
		out, err := runReconcileCLI(t, applyArgs()...)
		// A users-groups apply that writes owes the authorization cache (no playbook settles it): exit 4, as before.
		if code := processExitCode(err); code != golangUnsettledExitCode {
			t.Fatalf("exit %d: %v\n%s", code, err, out)
		}
		for _, m := range e.f.methods {
			if strings.HasPrefix(m, "hbac") || m == "env" || m == "host_find" || m == "hostgroup_find" {
				t.Fatalf("the users-groups scope sent %s: %v", m, e.f.methods)
			}
		}
		for _, args := range e.playbookCalls() {
			if hasExtraVar(args, hbacEngineArg) || hasExtraVar(args, deferArg) || slices.Contains(args, "--tags") {
				t.Fatalf("the users-groups scope passed the HBAC variables: %v", args)
			}
		}
	})
	t.Run("--preview-only without --scope full", func(t *testing.T) {
		e := newApplyEnv(t, hbacRoster(rosterWithNewUser()))
		plan := filepath.Join(e.dir, "plan.json")
		out, err := runGolangPreview(t, "--plan-out", plan)
		if err != nil {
			t.Fatalf("exit %d: %v\n%s", processExitCode(err), err, out)
		}
		data, _ := os.ReadFile(plan)
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if _, has := doc["hbac"]; has || doc["scope"] != reconcileScopeUsersGroups {
			t.Fatalf("the users-groups plan document: scope %v, hbac present %v", doc["scope"], has)
		}
		for _, m := range e.f.methods {
			if strings.HasPrefix(m, "hbac") {
				t.Fatalf("the users-groups preview read the HBAC: %v", e.f.methods)
			}
		}
		if !strings.Contains(out, "不在 Go engine 範圍") || !strings.Contains(out, "hbac") {
			t.Errorf("the users-groups preview does not say hbac is left to the Ansible engine:\n%s", out)
		}
	})
}

// ---- the mixed step, below the command ----

// hbacStep is a mixed run's identity transaction at the point after the Go users and groups phase, with an HBAC
// model behind the fake FreeIPA.
func newHBACStepEnv(t *testing.T, roster string) (*mixedEnv, *hbacFake) {
	t.Helper()
	m := newMixedEnv(t, roster)
	h := newHBACFake(t)
	h.install(m.applyEnv)
	return m, h
}

// okRun is a run of the playbook that exits 0 and writes an acknowledging observation when it was not told to defer.
func okRun(t *testing.T, m *mixedEnv, calls *[][]string) playbookRun {
	t.Helper()
	return func(_ context.Context, extra []string) (*ansible.Result, error) {
		*calls = append(*calls, slices.Clone(extra))
		var vars map[string]string
		if err := json.Unmarshal([]byte(extra[1]), &vars); err != nil {
			t.Fatal(err)
		}
		deferred := slices.Contains(extra, deferArg)
		r := identityreconcile.AuthCacheResult{Action: identityreconcile.AuthCacheObserve, Host: m.step.host, FQDN: m.step.fqdn, Prepared: true, Refreshed: !deferred, Acked: !deferred}
		data, err := identityreconcile.RenderAuthCacheResult(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vars[identityreconcile.AuthCacheOutputVar], data, 0o600); err != nil {
			t.Fatal(err)
		}
		return &ansible.Result{ExitCode: 0}, nil
	}
}

func hbacStepRoster() string { return hbacRoster(strings.Replace(captureRoster, "%s", "/bin/sh", 1)) }

// The HBAC stage takes the lock the apply step holds: a context without one starts neither the stage nor the
// second run, and connects to nothing.
func TestMixedHBACStageNeedsTheHeldLock(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate string
		ctx  func(m *mixedEnv, t *testing.T) context.Context
	}{
		{name: "a context without the lock", gate: "mixed-hbac-lock", ctx: func(*mixedEnv, *testing.T) context.Context { return context.Background() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			m, h := newHBACStepEnv(t, hbacStepRoster())
			if _, err := m.goPhase(t); err != nil {
				t.Fatal(err)
			}
			var calls [][]string
			_, err := m.step.RunPlaybook(tc.ctx(m, t), "apply", okRun(t, m, &calls))
			if !errors.Is(err, identitylock.ErrNoLock) {
				t.Fatalf("err = %v, want the missing lock", err)
			}
			if len(calls) != 1 || len(h.written()) != 0 || m.step.hbacRan || m.step.secondRun || m.step.hbacSkipped == "" {
				t.Fatalf("playbook runs %d, hbac writes %v, stage ran %v, second run %v, skipped %q", len(calls), h.written(), m.step.hbacRan, m.step.secondRun, m.step.hbacSkipped)
			}
		})
	}
}

// The stage writes only to the server the lock is on, and only after the Go phase prepared the run.
func TestMixedHBACStageRefusesWhatItCannotWriteSafely(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gate    string
		mutate  func(s *mixedStep)
		want    string
		connect bool
	}{
		{name: "no preflight of the Go phase", gate: "mixed-hbac-no-prep", mutate: func(s *mixedStep) { s.prep = nil }, want: "沒有留下這一輪的 preflight"},
		{name: "another server's lock", gate: "mixed-hbac-host", mutate: func(s *mixedStep) { s.prep.host = "ipa-2" }, want: "鎖在 ipa-1"},
		{name: "an hbac section the reader refuses", gate: "mixed-hbac-desired", mutate: func(s *mixedStep) { s.prep.root["hbac"] = map[string]any{"rules": "nope"} }, want: "roster 的 HBAC"},
		{name: "a server that cannot be reached", gate: "mixed-hbac-connect", mutate: func(s *mixedStep) { golangDialerFaults.fqdnErr = errors.New("ssh: connection refused") }, want: "connection refused", connect: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			m, h := newHBACStepEnv(t, hbacStepRoster())
			held, err := m.goPhase(t)
			if err != nil {
				t.Fatal(err)
			}
			loginsBefore := len(m.f.paths)
			tc.mutate(m.step)
			err = mixedHBACStage(held.Attach(context.Background()), held, m.step)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if m.step.hbacRan || m.step.hbacSkipped == "" || len(h.written()) != 0 {
				t.Fatalf("the stage ran = %v, skipped %q, wrote %v", m.step.hbacRan, m.step.hbacSkipped, h.written())
			}
			if !tc.connect && len(m.f.paths) != loginsBefore {
				t.Fatalf("a refused stage connected to FreeIPA: %v", m.f.paths[loginsBefore:])
			}
		})
	}
}

// The run's context ends between the playbook's runs: after the first (neither the stage nor the second run starts),
// and during the stage (the second run does not start, and the error says the obligation is owed).
func TestMixedRunStopsStartingThingsOnceItsContextEnded(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate string
		run  func(t *testing.T)
	}{
		{name: "after the first run", gate: "mixed-hbac-ctx", run: func(t *testing.T) {
			m, h := newHBACStepEnv(t, hbacStepRoster())
			if _, err := m.goPhase(t); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(m.applyCtx(t))
			var calls [][]string
			first := okRun(t, m, &calls)
			_, err := m.step.RunPlaybook(ctx, "apply", func(c context.Context, extra []string) (*ansible.Result, error) {
				res, err := first(c, extra)
				cancel()
				return res, err
			})
			if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "沒有啟動") {
				t.Fatalf("err = %v, want the context's end and that nothing was started", err)
			}
			if len(calls) != 1 || len(h.written()) != 0 || m.step.hbacRan || m.step.secondRun || m.step.hbacSkipped == "" {
				t.Fatalf("playbook runs %d, hbac writes %v, stage %v, second run %v, skipped %q", len(calls), h.written(), m.step.hbacRan, m.step.secondRun, m.step.hbacSkipped)
			}
		}},
		{name: "during the stage", gate: "mixed-second-run-ctx", run: func(t *testing.T) {
			m, h := newHBACStepEnv(t, hbacStepRoster())
			if _, err := m.goPhase(t); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(m.applyCtx(t))
			h.onWrite = func([]string) { cancel() }
			var calls [][]string
			_, err := m.step.RunPlaybook(ctx, "apply", okRun(t, m, &calls))
			if err == nil || !strings.Contains(err.Error(), "第二次 playbook 執行沒有啟動") {
				t.Fatalf("err = %v, want that the second run did not start and the obligation is owed", err)
			}
			if len(calls) != 1 || m.step.secondRun || !m.step.hbacRan {
				t.Fatalf("playbook runs %d, second run %v, stage ran %v", len(calls), m.step.secondRun, m.step.hbacRan)
			}
			if err := m.step.settled(); !errors.Is(err, identityreconcile.ErrUnsettled) {
				t.Fatalf("settled() = %v: with the second run never started the obligation is owed", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			tc.run(t)
		})
	}
}

// A first run that did not start (its observation file could not be made) and one that was started and failed
// (an error or an exit code) end the apply without the stage; the exit code is the playbook's and is never pilot's.
func TestMixedApplyPlaybookEndsAtAFirstRunThatDidNotSucceed(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate string
		run  func(calls *int) playbookRun
		want string
	}{
		{name: "an error", gate: "mixed-first-run-failed", want: "no ansible-playbook",
			run: func(n *int) playbookRun {
				return func(context.Context, []string) (*ansible.Result, error) {
					*n++
					return nil, errors.New("no ansible-playbook")
				}
			}},
		{name: "an exit code", gate: "mixed-first-run-failed", want: "",
			run: func(n *int) playbookRun {
				return func(context.Context, []string) (*ansible.Result, error) {
					*n++
					return &ansible.Result{ExitCode: 2}, nil
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			m, h := newHBACStepEnv(t, hbacStepRoster())
			if _, err := m.goPhase(t); err != nil {
				t.Fatal(err)
			}
			var n int
			res, err := m.step.RunPlaybook(m.applyCtx(t), "apply", tc.run(&n))
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.want == "" && (err != nil || res == nil || res.ExitCode != 2) {
				t.Fatalf("the failed run's result was changed: %+v, %v", res, err)
			}
			if n != 1 || len(h.written()) != 0 || m.step.hbacRan || m.step.hbacSkipped == "" {
				t.Fatalf("runs %d, writes %v, stage %v, skipped %q", n, h.written(), m.step.hbacRan, m.step.hbacSkipped)
			}
		})
	}
}

// The idempotency check holds both Go plans to zero operations, and says which one is not.
func TestMixedIdempotencyHoldsTheUsersAndTheHBACPlanToZeroOperations(t *testing.T) {
	cases := []struct {
		name    string
		roster  string
		setup   func(m *mixedEnv, h *hbacFake)
		wantErr string
	}{
		{name: "both empty", roster: hbacStepRoster(), setup: func(m *mixedEnv, h *hbacFake) {
			r := h.newRule("p3-login")
			r.hostCat, r.users["p1-self"], r.services["sshd"] = "all", true, true
		}},
		{name: "the HBAC plan still has an operation", roster: hbacStepRoster(), wantErr: "HBAC 的 Go 唯讀 plan 仍有"},
		{name: "the users plan still has an operation", roster: hbacRoster(rosterWithNewUser()), setup: func(m *mixedEnv, h *hbacFake) {
			r := h.newRule("p3-login")
			r.hostCat, r.users["p1-self"], r.services["sshd"] = "all", true, true
		}, wantErr: "users／groups 的 Go 唯讀 plan 仍有"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, h := newHBACStepEnv(t, tc.roster)
			if tc.setup != nil {
				tc.setup(m, h)
			}
			err := m.step.WrapStep("idempotency", func(context.Context) error { return nil })(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// The mixed step's settlement is the last run's: a first run's acknowledgement is not the second's.
func TestMixedStepRecordsTheLastApplyRunsObservation(t *testing.T) {
	m, _ := newHBACStepEnv(t, hbacStepRoster())
	if _, err := m.goPhase(t); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	if _, err := m.step.RunPlaybook(m.applyCtx(t), "apply", okRun(t, m, &calls)); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !slices.Contains(calls[0], deferArg) || slices.Contains(calls[1], deferArg) || !slices.Contains(calls[1], "--tags") {
		t.Fatalf("playbook calls: %v", calls)
	}
	if m.step.obs == nil || !m.step.obs.Acked || !m.step.secondRun || !m.step.hbacRan {
		t.Fatalf("obs %+v, second run %v, stage ran %v", m.step.obs, m.step.secondRun, m.step.hbacRan)
	}
	if err := m.step.settled(); err != nil {
		t.Fatal(err)
	}
}

// mixedHBACError: the shape of what the apply step reports.
func TestMixedHBACErrorShapes(t *testing.T) {
	committed := &identityreconcile.HBACResult{Ops: []identityreconcile.OpResult{{Outcome: identityreconcile.OutcomeSuccess}}}
	for _, tc := range []struct {
		name        string
		res         *identityreconcile.HBACResult
		err         error
		wantNil     bool
		wantPartial bool
		wantBlocked bool
		wantText    string
	}{
		{name: "nothing wrong", wantNil: true},
		{name: "committed", res: committed, err: identityreconcile.ErrWrites, wantPartial: true, wantText: "不回滾"},
		{name: "blocked: nothing written, and not the exit code 3", err: identityreconcile.ErrBlocked, wantText: "沒有寫入任何東西"},
		{name: "the entry ran and nothing was written", res: &identityreconcile.HBACResult{Entry: identityreconcile.EntryReport{Ran: true}}, err: errors.New("boom"), wantText: "入口已執行"},
		{name: "an ordinary failure", err: errors.New("boom"), wantText: "HBAC 階段沒有完成"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mixedHBACError(tc.res, tc.err)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("got %v", got)
				}
				return
			}
			if got == nil || !strings.Contains(got.Error(), tc.wantText) {
				t.Fatalf("got %v, want %q", got, tc.wantText)
			}
			if errors.Is(got, delivery.ErrPartiallyApplied) != tc.wantPartial {
				t.Errorf("partial application = %v, want %v", errors.Is(got, delivery.ErrPartiallyApplied), tc.wantPartial)
			}
			if errors.Is(got, identityreconcile.ErrBlocked) || golangApplyExitCode(got) == golangPreviewBlockedExitCode {
				t.Errorf("an HBAC stage's failure reads as the exit code 3 of a plan blocked with nothing written: %v", got)
			}
		})
	}
}

// The printed lines of the stage, for a run that did not reach it and for one that did.
func TestPrintMixedHBAC(t *testing.T) {
	var out strings.Builder
	printMixedHBAC(&out, &mixedStep{hbacSkipped: "identity playbook 的第 1 次執行失敗"})
	if !strings.Contains(out.String(), "沒有執行（identity playbook 的第 1 次執行失敗）") {
		t.Errorf("skipped: %q", out.String())
	}
	out.Reset()
	printMixedHBAC(&out, &mixedStep{})
	if !strings.Contains(out.String(), "這一輪在 HBAC 階段之前就停了") {
		t.Errorf("no reason given: %q", out.String())
	}
}

// The verification line of the stage says what happened: a converged run has nothing to read back, and is not
// a roster the read-back disagrees with (the lab run of the second apply printed that).
func TestHBACVerifyLine(t *testing.T) {
	op := identityreconcile.OpResult{}
	for _, tc := range []struct {
		name string
		res  *identityreconcile.HBACResult
		want string
	}{
		{"converged, nothing to write", &identityreconcile.HBACResult{Observed: true}, "沒有寫入，不需要讀回"},
		{"wrote and read back clean", &identityreconcile.HBACResult{Observed: true, Ops: []identityreconcile.OpResult{op}, Verify: identityreconcile.Verification{Done: true}}, "讀回與 roster 一致"},
		{"wrote and the read-back differs", &identityreconcile.HBACResult{Observed: true, Ops: []identityreconcile.OpResult{op}, Verify: identityreconcile.Verification{Done: true, Remaining: []string{"hbac.rule.create:x"}}}, "讀回與 roster 不一致"},
		{"wrote and never read back", &identityreconcile.HBACResult{Observed: true, Ops: []identityreconcile.OpResult{op}}, "沒有讀回"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hbacVerifyLine(tc.res); !strings.Contains(got, tc.want) {
				t.Errorf("got %q, want it to say %q", got, tc.want)
			}
		})
	}
}
