package cmd

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The terminal sinks of spec 2026-11-06 phase 2 §4.4 (T1 to T8): every place that records the
// result of a run after its context may have been cancelled (Ctrl-C, --timeout, a lost lock)
// must not fail because of the cancellation, or the real result is hidden behind "event NOT
// durable" or "evidence failed". The rule has been broken twice by a context that was passed on
// by habit, so it is one rule with a register, and a test that fails when a call of a sink is
// not on it (AGENTS.md §5.7, §5.10): a new sink must be added here with how it survives.

// terminalSink is one registered call of a sink.
type terminalSink struct {
	File string // repo-relative
	Func string // the function the call is in ("Type.Method" for a method)
	Call string // the selector or function called
	Sink string // T1..T8
	PR   string // who is responsible for it
	// How: where the call leaves the run's cancellation, or why it is exempt.
	How string
}

// terminalSinkCalls are what the scan looks for: the calls that write a run's evidence, publish its
// result or create its result file.
var terminalSinkCalls = []string{"AppendEvent", "AppendEvidence", "Finish", "EnqueueBatch", "CheckWorkspaceBinding", "ReconcileWebhookConfig", "FlushWebhooks", "commitOutput"}

// terminalSinkPackages are the directories scanned (non-test sources).
var terminalSinkPackages = []string{"cmd/pilot/cmd/", "internal/identityreconcile/", "internal/delivery/", "internal/outbound/", "internal/tools/"}

var terminalSinks = []terminalSink{
	{"cmd/pilot/cmd/reconcile_golang_apply.go", "storeJournal.Record", "AppendEvent", "T1", "P2-5 (the executor), P2-6 (the store sink)",
		"identityreconcile.Execute calls Journal.Record only through record(), which runs it on context.WithoutCancel bounded by evidenceAppendTimeout, whatever the sink does with its context"},
	{"internal/delivery/transaction.go", "Transaction.runStep", "AppendEvent", "T2", "P2-6",
		"the append runs on context.WithoutCancel bounded by stepEvidenceTimeout (5 s); a store that really fails is still evidence_failed"},
	{"internal/delivery/transaction.go", "Transaction.RunResult", "Finish", "T3", "already (RunWriter.Finish)",
		"RunWriter.Finish runs on context.WithoutCancel bounded by 5 s itself"},
	{"cmd/pilot/cmd/deploy.go", "executeRecordedDeploymentCore", "Finish", "T3", "already (RunWriter.Finish)",
		"RunWriter.Finish detaches from the cancellation itself"},
	{"cmd/pilot/cmd/verify.go", "runVerifyOne", "Finish", "T3", "already (RunWriter.Finish)",
		"RunWriter.Finish detaches from the cancellation itself (and the one with context.Background() never had a cancellation)"},
	{"cmd/pilot/cmd/reconcile_golang_apply.go", "finishGolangApply", "commitOutput", "T4", "P2-6",
		"a local file write that takes no context: it is made on the way out of a cancelled run like any other"},
	{"cmd/pilot/cmd/reconcile_golang.go", "golangPreview", "commitOutput", "T4", "P2-6",
		"the preview's --plan-out: a local file write that takes no context (a preview writes nothing to FreeIPA, so there is no committed result to lose to a cancellation)"},
	{"cmd/pilot/cmd/outbound_workflow.go", "publishTerminalWorkflow", "CheckWorkspaceBinding", "T6", "P2-6",
		"publishTerminalWorkflow continues on context.WithoutCancel bounded by outboundPublishTimeout when ctx was cancelled on entry"},
	{"cmd/pilot/cmd/outbound_workflow.go", "publishTerminalWorkflow", "ReconcileWebhookConfig", "T6", "P2-6", "the same"},
	{"cmd/pilot/cmd/outbound_workflow.go", "publishTerminalWorkflow", "EnqueueBatch", "T6", "P2-6", "the same"},
	{"cmd/pilot/cmd/outbound_workflow.go", "publishTerminalWorkflow", "FlushWebhooks", "T7", "P2-6",
		"the same, and the delivery is bounded by webhookFlushTimeout on that path; an event not delivered stays in the outbox for pilot webhook flush"},
	{"cmd/pilot/cmd/webhook.go", "openWebhookOutbox", "CheckWorkspaceBinding", "exempt", "-",
		"not the record of a run: `pilot webhook flush`/`test`, an operator's command that starts on its own context and is what delivers what a cancelled run left in the outbox"},
	{"cmd/pilot/cmd/webhook.go", "openWebhookOutbox", "ReconcileWebhookConfig", "exempt", "-", "the same"},
	{"cmd/pilot/cmd/webhook.go", "runWebhookFlush", "FlushWebhooks", "exempt", "-", "the same: context.Background()"},
	{"internal/tools/verify_spec.go", "VerifySpecTool.appendEvidence", "AppendEvent", "T8", "justified exemption",
		"it records a verification that a cancellation interrupts: when cancelled the verify step does not run or stops, so there is no result left to record after the cancellation; the run's result is T2 and T3's"},
	{"internal/tools/verify_spec.go", "VerifySpecTool.appendEvidence", "AppendEvidence", "T8", "justified exemption", "the same"},
	{"cmd/pilot/cmd/portal_session_connect.go", "runPortalTargetSessionRecorded", "Finish", "exempt", "-",
		"not a delivery run: the session recorder's own Finish (internal/sessionrecording), which already runs on its own bounded context (fctx)"},
}

type sinkCall struct{ File, Func, Call string }

func (c sinkCall) key() string { return c.File + "|" + c.Func + "|" + c.Call }

// scanTerminalSinks finds the calls of terminalSinkCalls in the non-test sources of the scanned
// packages: a selector call or a function call by one of those names, in a function or method or
// in the initializer of a package-level variable (which is where a function literal assigned to
// one lives: `var f = func() { ... }`).
func scanTerminalSinks(t *testing.T, src lockSources) []sinkCall {
	t.Helper()
	names := map[string]bool{}
	for _, n := range terminalSinkCalls {
		names[n] = true
	}
	var out []sinkCall
	fset := token.NewFileSet()
	for _, name := range sortedKeys(src) {
		in := false
		for _, p := range terminalSinkPackages {
			if strings.HasPrefix(name, p) {
				in = true
			}
		}
		if !in {
			continue
		}
		file := parseLockSource(t, fset, name, src[name])
		// find records the sink calls inside node, once per call name, under the function's name.
		find := func(fn string, node ast.Node) {
			seen := map[string]bool{}
			ast.Inspect(node, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var called string
				switch f := call.Fun.(type) {
				case *ast.SelectorExpr:
					called = f.Sel.Name
				case *ast.Ident:
					called = f.Name
				}
				if names[called] && !seen[called] {
					seen[called] = true
					out = append(out, sinkCall{File: name, Func: fn, Call: called})
				}
				return true
			})
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				fn := d.Name.Name
				if d.Recv != nil && len(d.Recv.List) == 1 {
					typ := d.Recv.List[0].Type
					if star, ok := typ.(*ast.StarExpr); ok {
						typ = star.X
					}
					if id, ok := typ.(*ast.Ident); ok {
						fn = id.Name + "." + fn
					}
				}
				find(fn, d.Body)
			case *ast.GenDecl:
				// A package-level variable can hold a function (`var f = func() { ... }`, a table of
				// handlers, a test seam): a sink called from it is as much a sink as one in a FuncDecl.
				// It is registered as "var <name>".
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, v := range vs.Values {
						ident := vs.Names[0]
						if i < len(vs.Names) {
							ident = vs.Names[i]
						}
						find("var "+ident.Name, v)
					}
				}
			}
		}
	}
	return out
}

// terminalSinkProblems compares the calls found with the register, both ways.
func terminalSinkProblems(found []sinkCall, register []terminalSink) []string {
	var problems []string
	known := map[string]terminalSink{}
	for _, r := range register {
		if strings.TrimSpace(r.How) == "" || strings.TrimSpace(r.Sink) == "" || strings.TrimSpace(r.PR) == "" {
			problems = append(problems, r.File+" "+r.Func+" "+r.Call+": a register entry needs its sink, its owner and how it survives a cancellation")
		}
		known[sinkCall{r.File, r.Func, r.Call}.key()] = r
	}
	seen := map[string]bool{}
	for _, c := range found {
		seen[c.key()] = true
		if _, ok := known[c.key()]; !ok {
			problems = append(problems, c.File+" "+c.Func+": calls "+c.Call+", which records the result of a run, and is not in the terminal sink register (terminal_sinks_test.go): say which sink it is and how it survives a cancelled context, or why it is exempt")
		}
	}
	for k, r := range known {
		if !seen[k] {
			problems = append(problems, r.File+" "+r.Func+": the register lists a call of "+r.Call+" that is no longer there: drop the entry or find where the call went")
		}
	}
	sort.Strings(problems)
	return problems
}

func TestTerminalSinksAreRegistered(t *testing.T) {
	problems := terminalSinkProblems(scanTerminalSinks(t, readLockSources(t)), terminalSinks)
	if len(problems) != 0 {
		t.Fatalf("the terminal sinks and their register disagree:\n%s", strings.Join(problems, "\n"))
	}
}

// The register would be vacuous if the scan could not fail: a synthetic sink call that is not on
// it must be reported, a register entry whose call is gone must be, and an entry without its
// reason must be.
func TestTerminalSinkRegisterFailsOnWhatItShouldCatch(t *testing.T) {
	real := readLockSources(t)
	with := func(extra string) lockSources {
		out := lockSources{}
		for k, v := range real {
			out[k] = v
		}
		out["cmd/pilot/cmd/new_sink.go"] = extra
		return out
	}
	cases := map[string]struct {
		src  lockSources
		want string
	}{
		"a new AppendEvent": {with("package cmd\nfunc recordTheEnd(w EventWriter) { _ = w.AppendEvent(ctx, ev) }\n"), "recordTheEnd: calls AppendEvent"},
		"a new Finish":      {with("package cmd\nfunc endTheRun(w W) { _ = w.Finish(ctx, fin) }\n"), "endTheRun: calls Finish"},
		"a new enqueue":     {with("package cmd\nfunc announce(o O) { _, _ = o.EnqueueBatch(ctx, d) }\n"), "announce: calls EnqueueBatch"},
		"a new result file": {with("package cmd\nfunc writeTheResult(o *outputFile) { _ = commitOutput(o, nil) }\n"), "writeTheResult: calls commitOutput"},
		"a new flush":       {with("package cmd\nfunc flushNow(d D) { d.FlushWebhooks(ctx, w, o) }\n"), "flushNow: calls FlushWebhooks"},
		// The scan used to read FuncDecl bodies only: a sink called from a function literal that
		// a package-level variable holds was never seen.
		"a sink in a package-level function literal":   {with("package cmd\nvar recordLater = func(w W) { _ = w.AppendEvent(ctx, ev) }\n"), "var recordLater: calls AppendEvent"},
		"a sink in a literal of a package-level table": {with("package cmd\nvar handlers = map[string]func(O){\"end\": func(o O) { _, _ = o.EnqueueBatch(ctx, d) }}\n"), "var handlers: calls EnqueueBatch"},
		"a sink in a grouped package-level var":        {with("package cmd\nvar (\n\tquiet = 1\n\tfinish = func(w W) { _ = w.Finish(ctx, fin) }\n)\n"), "var finish: calls Finish"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := terminalSinkProblems(scanTerminalSinks(t, tc.src), terminalSinks)
			if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), tc.want) {
				t.Fatalf("problems = %v, want one containing %q", p, tc.want)
			}
		})
	}
	t.Run("a call that moved: the entry is stale", func(t *testing.T) {
		moved := lockSources{}
		for k, v := range real {
			moved[k] = v
		}
		moved["internal/delivery/transaction.go"] = strings.Replace(moved["internal/delivery/transaction.go"], "t.Writer.AppendEvent(actx,", "t.Writer.AppendEvidence2(actx,", 1)
		p := terminalSinkProblems(scanTerminalSinks(t, moved), terminalSinks)
		if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), "Transaction.runStep: the register lists a call of AppendEvent that is no longer there") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("an entry without its reason", func(t *testing.T) {
		bad := append([]terminalSink{}, terminalSinks...)
		bad[0].How = ""
		if p := terminalSinkProblems(scanTerminalSinks(t, real), bad); len(p) == 0 || !strings.Contains(p[0], "needs its sink, its owner and how it survives") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("the real tree is clean", func(t *testing.T) {
		if p := terminalSinkProblems(scanTerminalSinks(t, real), terminalSinks); len(p) != 0 {
			t.Fatalf("%v", p)
		}
	})
}

// rosterForTwoStages adds a user and a group the user is a member of: a group created in S1, its
// history marker in S2, the user in S3 and the membership in S6, so a run can end between stages.
func rosterForTwoStages() string {
	return strings.Replace(captureRoster, "%s", "/bin/sh", 1) + "  - {name: p26-new, first: P26, last: New}\n" +
		"groups:\n  - {name: team-p26, category: team, membership: {users: [p26-new]}}\n"
}

// TestTerminalSinksSurviveCancel is the behavior half of the register above (spec §4.4): a
// users-groups run that has committed something is ended by a cancellation (the first Ctrl-C,
// --timeout, a lost lock) at the moment it is writing, and every sink that records its result still
// holds it: the journal's events of the batch and of the verification, the step evidence, the run's
// terminal row, the result file, and the failure event in the outbox. Each row below is a way the
// run's context ends; each sink is asserted for each. Before the class rule the step evidence
// failed on the cancelled context (evidence_failed, the step's own error dropped) and the
// publication failed with "event NOT durable".
//
// The mixed run (Go stage and playbook stage, P2-7) has no row here: it does not exist yet. Its rows
// are added with it.
func TestTerminalSinksSurviveCancel(t *testing.T) {
	type outcome struct {
		exit       int
		outcome    string
		failedStep string
		failClass  string
		verdict    string
	}
	for _, tc := range []struct {
		name   string
		roster string
		// cut ends the run's context at the moment the first write batch is being answered.
		cut  func(t *testing.T, e *applyEnv, cancel context.CancelFunc)
		args []string
		want outcome
		// opSent: the journal holds the batch's "sending" event.
	}{
		{
			name: "the first Ctrl-C while the write is in flight", roster: rosterWithNewUser(),
			cut: func(t *testing.T, e *applyEnv, cancel context.CancelFunc) {
				e.a.onWrite = func([]string) {
					cancel()
					time.Sleep(400 * time.Millisecond) // the answer comes after the client has given up
				}
			},
			want: outcome{exit: 4, outcome: "partial_failed", failedStep: "verify", failClass: "verify_failed", verdict: "unsettled"},
		},
		{
			name: "--timeout ends while the write is in flight", roster: rosterWithNewUser(),
			args: []string{"--timeout", "3s"},
			cut: func(t *testing.T, e *applyEnv, cancel context.CancelFunc) {
				e.a.onWrite = func([]string) { time.Sleep(5 * time.Second) }
			},
			want: outcome{exit: 4, outcome: "partial_failed", failedStep: "verify", failClass: "verify_failed", verdict: "unsettled"},
		},
		{
			name: "the lock is lost after the first stage was sent", roster: rosterForTwoStages(),
			cut: func(t *testing.T, e *applyEnv, cancel context.CancelFunc) {
				e.a.onWrite = func([]string) { e.lock.Lose() }
			},
			want: outcome{exit: 1, outcome: "partial_failed", failedStep: "apply", failClass: "apply_failed", verdict: "partial"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newApplyEnv(t, tc.roster)
			capture := newWebhookCapture(0)
			srv := newWebhookServer(t, capture)
			writeOutboundWorkflowIntegrationsYAML(t, e.dir, srv.URL, "      - operation: reconcile\n        result: failure\n        payload: snapshot\n")
			t.Setenv("PILOT_W_TEST_TOKEN", "w-test-secret")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.cut(t, e, cancel)
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLIContext(t, ctx, append(applyArgs("--result-out", result), tc.args...)...)
			if got := processExitCode(err); got != tc.want.exit {
				t.Fatalf("exit %d (err %v), want %d\n%s", got, err, tc.want.exit, out)
			}
			run := onlyRun(t)
			// The run's terminal row: partial_failed, not evidence_failed.
			if run.outcome != tc.want.outcome {
				t.Fatalf("the run's terminal row says %q, want %q: the evidence of a cancelled run must not fail with it\n%s", run.outcome, tc.want.outcome, out)
			}
			stored := runEvents(t, run.id)
			// The step evidence: the step the run ended at is in the record, failed.
			ev := findEvent(stored, "step-"+tc.want.failedStep)
			if ev == nil || !ev.exit.Valid || ev.exit.Int64 != 1 {
				t.Fatalf("no failed step_finished event for %s: %v", tc.want.failedStep, eventTypes(stored))
			}
			// The journal: the batch before it was sent, and what was found after the writes.
			var sending, verify bool
			for _, s := range stored {
				if s.typ == "identity.op" && strings.HasSuffix(s.op, ":sending") {
					sending = true
				}
				if s.typ == "identity.verify" {
					verify = true
				}
			}
			if !sending || !verify {
				t.Fatalf("the journal lacks the batch's sending event (%v) or the verification (%v) after the cancellation: %v", sending, verify, eventTypes(stored))
			}
			// The result file: written, parseable, and it says how the run ended.
			doc := readApplyDoc(t, result)
			if doc.Verdict != tc.want.verdict || doc.Outcome != tc.want.outcome || doc.FailedStep != tc.want.failedStep {
				t.Errorf("result file: verdict %s outcome %s step %q; want %s %s %q", doc.Verdict, doc.Outcome, doc.FailedStep, tc.want.verdict, tc.want.outcome, tc.want.failedStep)
			}
			if !doc.Committed() {
				t.Errorf("the result file does not show what the run committed: %+v", doc.Ops)
			}
			// The outbox and the receiver: a failure event whose class follows the step.
			if got := outboxResults(t); len(got) != 1 || got[0] != "failure" {
				t.Fatalf("the outbox holds %v, want one failure event\n%s", got, out)
			}
			if capture.count() != 1 {
				t.Fatalf("webhook deliveries = %d, want 1\n%s", capture.count(), out)
			}
			var body map[string]any
			if err := json.Unmarshal(capture.last(), &body); err != nil {
				t.Fatal(err)
			}
			failure, _ := body["failure"].(map[string]any)
			if failure["class"] != tc.want.failClass {
				t.Errorf("failure.class = %v, want %s (FailedStep %s)", failure["class"], tc.want.failClass, tc.want.failedStep)
			}
			if strings.Contains(out, "NOT durable") {
				t.Errorf("a publication failed on the cancelled context:\n%s", out)
			}
			// The lock was given back in every case.
			if evs := readEvents(t, e.events); evs[len(evs)-1] != "release ipa-1" {
				t.Errorf("lock events %v: the lock is not given back", evs)
			}
			assertNoSecretAnywhere(t, err, out, result)
		})
	}
}
