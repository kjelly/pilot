package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/identityreconcile"
	"github.com/kjelly/pilot/internal/store"
)

// `pilot reconcile --engine golang --scope full` through the real cobra tree (spec 2026-11-06 phase 2 §8.3,
// §6.3, §10.2 A16 and H1 to H5 at the level of this machine): the Ansible engine's own reconcile path (the
// wizard's defaults driver, the freeipa-server dependency, preflight, availability, preview, apply, verify) over
// the fake FreeIPA and the fake lock of the users-groups apply tests, with an ansible-playbook of its own that
// answers for every playbook the path runs and writes the observation the identity playbook writes. What these
// prove is the command's plumbing from the flags to the exit code, which playbooks ran and in what order, and
// that the identity playbook is told to skip users and groups; what the playbook then does to a real server is
// the live driver's.

// fakeMixedPlaybook is ansible-playbook for the mixed path. It logs its argv, answers every run with a PLAY
// RECAP for ipa-1, and for the identity playbook's apply writes the observation the real playbook writes (the
// captured shape), as the scenario's environment says:
//
//	P27_OBSERVE   acked (default), notacked, none (writes nothing, as `no hosts matched` does), otherhost
//	P27_IDENTITY_EXIT  the exit code of the identity playbook's apply run (default 0)
//	P27_CHECK_EXIT     the exit code of a --check run of the identity playbook (default 0)
//	P27_BLOCK     a file: the identity playbook's apply writes its pid there and then waits (killed by the test's cancel)
//
// The entry playbook is answered as fakeEntryPlaybook does.
const fakeMixedPlaybook = `#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["P26_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
play = next((a for a in args if a.endswith(".yml")), "")
recap = "PLAY RECAP *********\nipa-1 : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n"
vars = {}
for a in args:
    if a.startswith("{"):
        vars.update(json.loads(a))
check = "--check" in args
if play.endswith("freeipa-identity-auth-cache.yml"):
    mode = os.environ.get("P26_ENTRY", "ok")
    if mode == "fail":
        sys.stdout.write("fatal: the entry failed\n")
        sys.exit(2)
    action = vars["pilot_identity_auth_cache_action"]
    res = {"schema": "pilot.identity-auth-cache/v1", "action": action, "host": "ipa-1", "fqdn": "ipa.example.test"}
    if action == "prepare":
        res["previous"] = os.environ.get("P26_PREVIOUS", "false") == "true"
    else:
        res["pending"] = os.environ.get("P26_PENDING", "false") == "true"
    with open(vars["pilot_identity_auth_cache_output"], "w") as f:
        json.dump(res, f)
    sys.exit(0)
if play.endswith("freeipa-identity-apply.yml"):
    engine = [a for a in args if a.startswith("pilot_identity_users_groups_engine=")]
    out = vars.get("pilot_identity_auth_cache_output")
    if engine and not out:
        sys.stdout.write("fatal: go without the observation file\n")
        sys.exit(2)
    sys.stdout.write(recap)
    sys.stdout.flush()
    if check:
        sys.exit(int(os.environ.get("P27_CHECK_EXIT", "0")))
    if os.environ.get("P27_BLOCK"):
        with open(os.environ["P27_BLOCK"], "w") as f:
            f.write(str(os.getpid()))
        import time
        time.sleep(120)
    mode = os.environ.get("P27_OBSERVE", "acked")
    if out and mode != "none":
        res = {"schema": "pilot.identity-auth-cache/v1", "action": "observe", "host": "ipa-9" if mode == "otherhost" else "ipa-1",
               "fqdn": "ipa.example.test", "prepared": True, "dirty": True, "refreshed": mode == "acked", "acked": mode == "acked"}
        with open(out, "w") as f:
            json.dump(res, f)
    sys.exit(int(os.environ.get("P27_IDENTITY_EXIT", "0")))
sys.stdout.write(recap)
sys.exit(0)
`

// mixedCLIEnv is applyEnv with the mixed path's ansible-playbook and every host reachable.
type mixedCLIEnv struct {
	*applyEnv
}

func newMixedCLIEnv(t *testing.T, roster string) *mixedCLIEnv {
	t.Helper()
	// The contracts, the catalog and the playbooks are the repository's (the reconcile path reads them from the
	// root); the workspace is the test's, and the working directory moves there.
	root := repoRootForTest(t)
	e := newApplyEnv(t, roster)
	t.Setenv("PILOT_ROOT", root)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(fakeMixedPlaybook), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	// The admin password reaches the dependency's required input the way a real run's does, from the
	// variables of the host; the workspace's own fake inventory has none.
	inv := map[string]any{"_meta": map[string]any{"hostvars": map[string]any{"ipa-1": map[string]any{
		"freeipa_roster_file": ".vault/ipa-identity.yaml", "ansible_host": "192.0.2.10", "ansible_user": "root", "ipa_admin_password": golangTestPassword,
	}}}, "freeipa-server": map[string]any{"hosts": []string{"ipa-1"}}}
	invJSON, _ := json.Marshal(inv)
	// P27_INV_FAIL names a file: once it exists, ansible-inventory exits with the status written in it (a test makes it
	// appear after the lock is taken, so that the Go phase's own preflight is what fails).
	if err := os.WriteFile(filepath.Join(bin, "ansible-inventory"), []byte("#!/bin/sh\nif [ -n \"$P27_INV_FAIL\" ] && [ -e \"$P27_INV_FAIL\" ]; then exit \"$(cat \"$P27_INV_FAIL\")\"; fi\ncat <<'EOF'\n"+string(invJSON)+"\nEOF\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := deployAvailabilityProber
	t.Cleanup(func() { deployAvailabilityProber = prev })
	deployAvailabilityProber = fakeDownHostsProber{}
	// The writes the fake FreeIPA receives are in the playbook log, in order with the runs.
	e.a.onWrite = func(methods []string) {
		line, _ := json.Marshal(append([]string{"IPA-WRITE"}, methods...))
		appendEvent(t, e.log, string(line))
	}
	return &mixedCLIEnv{e}
}

func mixedArgs(more ...string) []string {
	return append([]string{"--engine", "golang", "--force", "--scope", "full", "--component", "freeipa-identity", "--timeout", "2m"}, more...)
}

// runs are the playbooks the path ran, in order, as the base name of the playbook and whether it was a check.
func (e *mixedCLIEnv) runs() []string {
	var out []string
	for _, args := range e.playbookCalls() {
		name, kind := "", "apply"
		if len(args) > 0 && args[0] == "IPA-WRITE" {
			out = append(out, "ipa-write")
			continue
		}
		for _, a := range args {
			if strings.HasSuffix(a, ".yml") && name == "" {
				name = filepath.Base(a)
			}
			if a == "--check" {
				kind = "check"
			}
		}
		out = append(out, name+" "+kind)
	}
	return out
}

// identityArgs are the arguments of the identity playbook's run of the kind (check or apply), or nil.
func (e *mixedCLIEnv) identityArgs(kind string) []string {
	for _, args := range e.playbookCalls() {
		if len(args) == 0 || args[0] == "IPA-WRITE" {
			continue
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "freeipa-identity-apply.yml") && slices.Contains(args, "--check") == (kind == "check") {
			return args
		}
	}
	return nil
}

// hasExtraVar reports whether args carry -e with exactly this value, or (for a JSON object) with this key.
func hasExtraVar(args []string, want string) bool {
	for i, a := range args {
		if i > 0 && args[i-1] == "-e" && (a == want || strings.HasPrefix(a, "{") && strings.Contains(a, `"`+want+`"`)) {
			return true
		}
	}
	return false
}

// identityRun is the delivery run of the identity transaction (the freeipa-server dependency has its own).
func identityRun(t *testing.T) store.DeliveryRun {
	t.Helper()
	st, err := openSpecStore()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runs, err := st.ListRuns(store.RunFilter{Component: "freeipa-identity", Limit: 10})
	if err != nil || len(runs) != 1 {
		t.Fatalf("the identity runs: %d, %v", len(runs), err)
	}
	return runs[0]
}

const (
	obsKey    = identityreconcile.AuthCacheOutputVar
	engineArg = identityreconcile.UsersGroupsEngineVar + "=" + identityreconcile.UsersGroupsEngineGo
)

// A full mixed run that goes well (H1's plumbing): the dependency first, then the identity transaction: the Go
// plan, the playbook's check told to skip users and groups, the lock, the entry, the Go write, and only then the
// identity playbook's apply, handed the observation file; it acknowledged, so the run succeeds, exit 0, the
// run's record says what engine and scope it was, and `runs last-success` counts it (it ran the playbook).
func TestMixedRunWritesThroughTheGoEngineThenRunsThePlaybook(t *testing.T) {
	t.Logf("gate: entry-golang-mixed-dispatch")
	e := newMixedCLIEnv(t, rosterWithNewUser())
	result := filepath.Join(e.dir, "result.json")
	out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
	if err != nil || processExitCode(err) != 0 {
		t.Fatalf("exit %d: %v\n%s", processExitCode(err), err, out)
	}
	wantRuns := []string{
		"preflight.yml apply", "freeipa-server-apply.yml check", "freeipa-server-apply.yml apply", // the dependency, as in the Ansible engine
		"preflight.yml apply", "freeipa-identity-apply.yml check", // the identity transaction: the Go plan came before this check
		"freeipa-identity-auth-cache.yml apply", "ipa-write", "freeipa-identity-apply.yml apply", // the entry, the Go write, the playbook
	}
	if got := e.runs(); !slices.Equal(got, wantRuns) {
		t.Fatalf("runs:\n got %v\nwant %v\n%s", got, wantRuns, out)
	}
	for _, kind := range []string{"check", "apply"} {
		args := e.identityArgs(kind)
		if !hasExtraVar(args, engineArg) || !hasExtraVar(args, obsKey) {
			t.Errorf("the identity playbook's %s run was not told to skip users and groups and handed the observation file: %v", kind, args)
		}
	}
	for _, args := range e.playbookCalls() {
		joined := strings.Join(args, " ")
		if len(args) > 0 && args[0] != "IPA-WRITE" && !strings.Contains(joined, "freeipa-identity-apply.yml") && !strings.Contains(joined, "auth-cache") &&
			(hasExtraVar(args, engineArg) || hasExtraVar(args, obsKey)) {
			t.Errorf("a playbook that is not the identity playbook was handed the mixed run's variables: %v", args)
		}
	}
	doc := readApplyDoc(t, result)
	if doc.Scope != reconcileScopeFull || doc.Verdict != identityreconcile.VerdictOK || doc.Outcome != "success" || doc.ExitCode != 0 ||
		doc.Playbook == nil || !doc.Playbook.Ran || doc.Playbook.Observation == nil || !doc.Playbook.Observation.Acked || doc.Authorization.Owed {
		t.Fatalf("result file: scope %q verdict %q outcome %q playbook %+v authorization %+v", doc.Scope, doc.Verdict, doc.Outcome, doc.Playbook, doc.Authorization)
	}
	run := identityRun(t)
	if run.Outcome != "success" || run.Metadata["engine"] != "golang" || run.Metadata["scope"] != "full" {
		t.Fatalf("the run's record: outcome %q engine %v scope %v", run.Outcome, run.Metadata["engine"], run.Metadata["scope"])
	}
	// The path of the observation file is in no record of the run: it is handed to each run of the playbook.
	if raw, _ := json.Marshal(run.Metadata); strings.Contains(string(raw), "pilot-auth-cache") {
		t.Fatalf("the metadata holds the observation file's path: %s", raw)
	}
	st, serr := openSpecStore()
	if serr != nil {
		t.Fatal(serr)
	}
	defer st.Close()
	if last, lerr := st.LastSuccess("ipa-1"); lerr != nil || last.RunID != run.RunID {
		t.Fatalf("last-success = %q, %v: a mixed run ran the playbook, and counts", last.RunID, lerr)
	}
	types := eventTypes(runEvents(t, run.RunID))
	for _, want := range []string{"identity.op", "identity.verify", "identity.auth_cache"} {
		if !slices.Contains(types, want) {
			t.Errorf("the journal lacks %s: %v", want, types)
		}
	}
	if evs := readEvents(t, e.events); evs[0] != "lock ipa-1" || evs[len(evs)-1] != "release ipa-1" {
		t.Errorf("lock events %v", evs)
	}
	assertNoSecretAnywhere(t, err, out, result)
}

// Verification of the obligation (§8.3, §6.2): the playbook ran and every Go write was applied, but its
// observation does not say acknowledged, is missing, or is another host's: exit 4, the run is partial_failed at
// verify, and the result file says unsettled. The obligation a users-groups run always owes, a full run settles.
func TestMixedRunThatDoesNotAcknowledgeIsUnsettledExit4(t *testing.T) {
	for _, mode := range []string{"notacked", "none", "otherhost"} {
		t.Run(mode, func(t *testing.T) {
			e := newMixedCLIEnv(t, rosterWithNewUser())
			t.Setenv("P27_OBSERVE", mode)
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
			if processExitCode(err) != 4 {
				t.Fatalf("exit %d (%v), want 4\n%s", processExitCode(err), err, out)
			}
			doc := readApplyDoc(t, result)
			if doc.Verdict != identityreconcile.VerdictUnsettled || doc.Outcome != "partial_failed" || doc.FailedStep != "verify" || !doc.Authorization.Owed || doc.ExitCode != 4 {
				t.Fatalf("result file: verdict %q outcome %q step %q authorization %+v exit %d", doc.Verdict, doc.Outcome, doc.FailedStep, doc.Authorization, doc.ExitCode)
			}
			if doc.Playbook == nil || !doc.Playbook.Ran || (mode == "notacked") != (doc.Playbook.Observation != nil) {
				t.Fatalf("playbook report %+v for %s", doc.Playbook, mode)
			}
			if !strings.Contains(out, "授權快取義務未結清") {
				t.Fatalf("the operator is not told the obligation is owed:\n%s", out)
			}
			run := identityRun(t)
			if run.Outcome != "partial_failed" {
				t.Fatalf("run outcome %q", run.Outcome)
			}
			// Not a success of the host: neither form of last-success returns it.
			st, serr := openSpecStore()
			if serr != nil {
				t.Fatal(serr)
			}
			defer st.Close()
			for _, include := range []bool{false, true} {
				if last, lerr := st.LastSuccessWith("ipa-1", store.LastSuccessOptions{IncludeUsersGroups: include}); lerr == nil && last.RunID == run.RunID {
					t.Fatalf("last-success (include=%v) counted a run that owes the obligation", include)
				}
			}
		})
	}
}

// §7.6 and I7, A16: when the Go phase did not apply and verify its plan, the identity playbook is not run, and with
// a blocked plan nothing of it is run at all (not its check either): its tasks never reach the server. The exit code
// is the Go engine's: blocked is 3, anything else 1, and a partial application is partial_failed.
func TestMixedRunNeverStartsThePlaybookAfterAGoPhaseThatFailed(t *testing.T) {
	for _, tc := range []struct {
		name         string
		roster       string
		setup        func(t *testing.T, e *mixedCLIEnv)
		wantExit     int
		wantOutcome  string
		wantVerdict  string // "" = no result file: the run never read FreeIPA
		wantCheckRun bool
		wantEntry    bool
		wantWrites   []string
	}{
		{name: "a plan with a blocked object (A16): exit 3, the preview ends before the playbook's check",
			roster: strings.Replace(captureRoster, "%s", "/bin/sh, uid: 1", 1), wantExit: 3, wantOutcome: "failed"},
		{name: "the entry fails: exit 1, nothing written, no playbook apply",
			roster: rosterWithNewUser(), setup: func(t *testing.T, e *mixedCLIEnv) { t.Setenv("P26_ENTRY", "fail") },
			wantExit: 1, wantOutcome: "failed", wantVerdict: identityreconcile.VerdictFailed, wantCheckRun: true, wantEntry: true},
		{name: "a write is refused after another was applied (H5's Go half): partial, no playbook apply",
			roster:   rosterWithNewUser() + "  - {name: p26-two, first: P26, last: Two}\n",
			setup:    func(t *testing.T, e *mixedCLIEnv) { e.a.failItem["user_add:p26-two"] = "user-add-duplicate" },
			wantExit: 1, wantOutcome: "partial_failed", wantVerdict: identityreconcile.VerdictPartial, wantCheckRun: true, wantEntry: true,
			wantWrites: []string{"user_add", "user_add"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newMixedCLIEnv(t, tc.roster)
			if tc.setup != nil {
				tc.setup(t, e)
			}
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
			if processExitCode(err) != tc.wantExit {
				t.Fatalf("exit %d (%v), want %d\n%s", processExitCode(err), err, tc.wantExit, out)
			}
			if e.identityArgs("apply") != nil {
				t.Fatalf("the identity playbook's apply ran after a Go phase that failed: %v\n%s", e.runs(), out)
			}
			if got := e.identityArgs("check") != nil; got != tc.wantCheckRun {
				t.Fatalf("the playbook's check ran = %v, want %v: %v", got, tc.wantCheckRun, e.runs())
			}
			if entry := slices.Contains(e.runs(), "freeipa-identity-auth-cache.yml apply"); entry != tc.wantEntry {
				t.Fatalf("the entry ran = %v, want %v: %v", entry, tc.wantEntry, e.runs())
			}
			if got := e.a.writeMethods(); !slices.Equal(got, tc.wantWrites) && !(len(got) == 0 && len(tc.wantWrites) == 0) {
				t.Fatalf("writes %v, want %v", got, tc.wantWrites)
			}
			if tc.wantExit == 3 && len(readEvents(t, e.events)) != 0 {
				t.Fatalf("a blocked preview took the lock: %v", readEvents(t, e.events))
			}
			if tc.wantVerdict != "" {
				if run := identityRun(t); run.Outcome != tc.wantOutcome {
					t.Fatalf("run outcome %q, want %q\n%s", run.Outcome, tc.wantOutcome, out)
				}
				if doc := readApplyDoc(t, result); doc.Verdict != tc.wantVerdict || doc.FailedStep != "apply" || doc.Playbook == nil || doc.Playbook.Ran {
					t.Fatalf("result file: verdict %q step %q playbook %+v", doc.Verdict, doc.FailedStep, doc.Playbook)
				}
			} else if data, rerr := os.ReadFile(result); rerr == nil && len(data) != 0 {
				t.Fatalf("a result file for a run that never read FreeIPA: %s", data)
			}
			assertNoSecretAnywhere(t, err, out, result)
		})
	}
}

// The playbook's own exit status is never pilot's (§6.3): a mixed run whose playbook fails with ansible's 3 or 4
// ends with pilot's exit 1, and not with 3 (blocked) or 4 (the obligation owed). A Go phase that committed makes
// the failure partial_failed at apply, and nothing is rolled back.
func TestMixedRunPlaybookFailureNeverBecomesTheEnginesExitCode(t *testing.T) {
	for _, code := range []string{"2", "3", "4"} {
		t.Run("ansible-playbook exits "+code, func(t *testing.T) {
			e := newMixedCLIEnv(t, rosterWithNewUser())
			t.Setenv("P27_IDENTITY_EXIT", code)
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
			if got := processExitCode(err); got != 1 {
				t.Fatalf("exit %d (%v), want 1: a child's status must not be pilot's\n%s", got, err, out)
			}
			if run := identityRun(t); run.Outcome != "partial_failed" {
				t.Fatalf("run outcome %q, want partial_failed after a committed Go phase\n%s", run.Outcome, out)
			}
			doc := readApplyDoc(t, result)
			if doc.Verdict != identityreconcile.VerdictPartial || doc.FailedStep != "apply" || doc.Playbook == nil || !doc.Playbook.Ran || doc.ExitCode != 1 {
				t.Fatalf("result file: verdict %q step %q playbook %+v exit %d", doc.Verdict, doc.FailedStep, doc.Playbook, doc.ExitCode)
			}
			if !doc.Committed() {
				t.Fatalf("the result file does not show the Go phase's write: %+v", doc.Ops)
			}
			if evs := readEvents(t, e.events); evs[len(evs)-1] != "release ipa-1" {
				t.Fatalf("lock events %v", evs)
			}
		})
	}
	t.Run("a playbook that fails after a Go phase that wrote nothing is an ordinary failure", func(t *testing.T) {
		e := newMixedCLIEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
		t.Setenv("P27_IDENTITY_EXIT", "2")
		out, err := runReconcileCLI(t, mixedArgs()...)
		if processExitCode(err) != 1 {
			t.Fatalf("exit %d (%v)\n%s", processExitCode(err), err, out)
		}
		if run := identityRun(t); run.Outcome != "failed" {
			t.Fatalf("run outcome %q, want failed: the Go phase committed nothing", run.Outcome)
		}
		if len(e.a.writeMethods()) != 0 {
			t.Fatalf("writes %v", e.a.writeMethods())
		}
	})
}

// The exit status of a child is never pilot's (§6.3), where it matters: an error that WRAPS a child's *exec.ExitError
// is an ExitCoder too, so returned as it is it would end pilot with ansible's 3 (read as blocked) or 4 (read as the
// obligation owed). In the mixed run the Go phase's preflight runs ansible-inventory under the lock, and its failure
// is such an error (it wraps the exit status): here it fails with 3 and with 4, and the command's exit code is 1.
func TestMixedRunChildExitStatusInAWrappedErrorIsNeverPilots(t *testing.T) {
	for _, code := range []string{"3", "4"} {
		t.Run("ansible-inventory exits "+code+" in the Go phase", func(t *testing.T) {
			e := newMixedCLIEnv(t, rosterWithNewUser())
			flag := filepath.Join(e.dir, "inventory-fails")
			t.Setenv("P27_INV_FAIL", flag)
			e.lock.OnAcquire = func(context.Context) {
				if err := os.WriteFile(flag, []byte(code), 0o600); err != nil {
					t.Error(err)
				}
			}
			out, err := runReconcileCLI(t, mixedArgs()...)
			if err == nil || !strings.Contains(err.Error(), "ansible-inventory --list") {
				t.Fatalf("err = %v, want the Go phase's failed preflight\n%s", err, out)
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != mustAtoi(t, code) {
				t.Fatalf("the error does not wrap the child's status %s (the test would prove nothing): %v", code, err)
			}
			if got := processExitCode(err); got != 1 {
				t.Fatalf("exit %d, want 1: the child's status %s must not be pilot's", got, code)
			}
			if e.identityArgs("apply") != nil || len(e.a.writeMethods()) != 0 {
				t.Fatalf("something ran after the Go phase failed: %v, writes %v", e.runs(), e.a.writeMethods())
			}
		})
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// H3's plumbing: nothing for the Go engine to write, so no entry and no write, and the playbook runs and
// acknowledges on its own: exit 0.
func TestMixedRunWithNothingToWriteLeavesTheObligationToThePlaybook(t *testing.T) {
	e := newMixedCLIEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh", 1))
	result := filepath.Join(e.dir, "result.json")
	out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
	if err != nil {
		t.Fatalf("exit %d: %v\n%s", processExitCode(err), err, out)
	}
	if slices.Contains(e.runs(), "freeipa-identity-auth-cache.yml apply") || slices.Contains(e.runs(), "ipa-write") {
		t.Fatalf("a run with nothing to write ran the entry or wrote: %v", e.runs())
	}
	if e.identityArgs("apply") == nil {
		t.Fatalf("the identity playbook did not run: %v", e.runs())
	}
	doc := readApplyDoc(t, result)
	if doc.Verdict != identityreconcile.VerdictOK || doc.Authorization.EntryRan || doc.Authorization.Owed || doc.Playbook == nil || doc.Playbook.Observation == nil || !doc.Playbook.Observation.Acked {
		t.Fatalf("result file: verdict %q authorization %+v playbook %+v", doc.Verdict, doc.Authorization, doc.Playbook)
	}
}

// --preview-only --scope full: the Go engine's read-only plan and the playbook's check, no lock, no entry, no write,
// no apply; --plan-out is the Go plan, and a blocked plan ends it with exit 3 before the playbook's check.
func TestMixedPreviewIsReadOnly(t *testing.T) {
	previewArgs := func(more ...string) []string {
		return append([]string{"--engine", "golang", "--preview-only", "--scope", "full", "--component", "freeipa-identity", "--timeout", "2m"}, more...)
	}
	t.Run("a clean plan", func(t *testing.T) {
		e := newMixedCLIEnv(t, rosterWithNewUser())
		plan := filepath.Join(e.dir, "plan.json")
		out, err := runReconcileCLI(t, previewArgs("--plan-out", plan)...)
		if err != nil {
			t.Fatalf("exit %d: %v\n%s", processExitCode(err), err, out)
		}
		for _, r := range e.runs() {
			if strings.HasSuffix(r, " apply") && !strings.HasPrefix(r, "preflight") {
				t.Fatalf("a preview applied %q: %v", r, e.runs())
			}
		}
		if check := e.identityArgs("check"); check == nil || !hasExtraVar(check, engineArg) || !hasExtraVar(check, obsKey) {
			t.Fatalf("the playbook's check was not run with the engine variable and the observation file: %v", check)
		}
		if len(e.a.writeMethods()) != 0 || len(readEvents(t, e.events)) != 0 {
			t.Fatalf("a preview wrote %v or took the lock %v", e.a.writeMethods(), readEvents(t, e.events))
		}
		data, rerr := os.ReadFile(plan)
		if rerr != nil || !strings.Contains(string(data), "user.create") {
			t.Fatalf("the plan file: %v\n%s", rerr, data)
		}
	})
	t.Run("a blocked plan", func(t *testing.T) {
		e := newMixedCLIEnv(t, strings.Replace(captureRoster, "%s", "/bin/sh, uid: 1", 1))
		out, err := runReconcileCLI(t, previewArgs()...)
		if processExitCode(err) != 3 {
			t.Fatalf("exit %d (%v), want 3\n%s", processExitCode(err), err, out)
		}
		if e.identityArgs("check") != nil {
			t.Fatalf("the playbook's check ran after a blocked plan: %v", e.runs())
		}
	})
}

// The cancellation arms at the level of this machine: the first Ctrl-C (the context of the command ends) in the Go
// phase while a write is in flight, and in the playbook phase while the playbook runs. Every record of the run is
// still written on the way out (the journal, the step evidence, the run's row, the outbox's failure event, the
// result file), the playbook is killed or never started, the run is partial_failed at apply, exit 1, and the lock
// is given back.
func TestMixedRunRecordsEverythingAfterTheFirstCtrlC(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cut      func(t *testing.T, e *mixedCLIEnv, cancel context.CancelFunc)
		wantPlay bool // the playbook was started
	}{
		{name: "in the Go phase, while a write is in flight", cut: func(t *testing.T, e *mixedCLIEnv, cancel context.CancelFunc) {
			prev := e.a.onWrite
			e.a.onWrite = func(m []string) {
				prev(m)
				cancel()
				time.Sleep(400 * time.Millisecond) // the answer comes after the client has given up
			}
		}},
		{name: "in the playbook phase, while the playbook runs", wantPlay: true, cut: func(t *testing.T, e *mixedCLIEnv, cancel context.CancelFunc) {
			pid := filepath.Join(e.dir, "playbook.pid")
			t.Setenv("P27_BLOCK", pid)
			go func() {
				for i := 0; i < 600; i++ {
					if _, err := os.Stat(pid); err == nil {
						cancel()
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
			}()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newMixedCLIEnv(t, rosterWithNewUser())
			capture := newWebhookCapture(0)
			srv := newWebhookServer(t, capture)
			writeOutboundWorkflowIntegrationsYAML(t, e.dir, srv.URL, "      - operation: reconcile\n        result: failure\n        payload: snapshot\n")
			t.Setenv("PILOT_W_TEST_TOKEN", "w-test-secret")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tc.cut(t, e, cancel)
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLIContext(t, ctx, mixedArgs("--result-out", result)...)
			if processExitCode(err) != 1 {
				t.Fatalf("exit %d (%v), want 1\n%s", processExitCode(err), err, out)
			}
			if started := e.identityArgs("apply") != nil; started != tc.wantPlay {
				t.Fatalf("the identity playbook's apply started = %v, want %v: %v", started, tc.wantPlay, e.runs())
			}
			run := identityRun(t)
			if run.Outcome != "partial_failed" {
				t.Fatalf("the run's terminal row says %q, want partial_failed: the evidence of a cancelled run must not fail with it\n%s", run.Outcome, out)
			}
			stored := runEvents(t, run.RunID)
			if ev := findEvent(stored, "step-apply"); ev == nil || !ev.exit.Valid || ev.exit.Int64 != 1 {
				t.Fatalf("no failed step_finished event for apply: %v", eventTypes(stored))
			}
			if !slices.Contains(eventTypes(stored), "identity.verify") {
				t.Fatalf("the read after the writes is not in the journal: %v", eventTypes(stored))
			}
			doc := readApplyDoc(t, result)
			if doc.Verdict != identityreconcile.VerdictPartial || doc.FailedStep != "apply" || !doc.Committed() || doc.Playbook == nil || doc.Playbook.Ran != tc.wantPlay {
				t.Fatalf("result file: verdict %q step %q committed %v playbook %+v", doc.Verdict, doc.FailedStep, doc.Committed(), doc.Playbook)
			}
			if got := outboxResults(t); len(got) != 1 || got[0] != "failure" || capture.count() != 1 {
				t.Fatalf("the outbox holds %v and %d deliveries, want one failure\n%s", got, capture.count(), out)
			}
			var body map[string]any
			if err := json.Unmarshal(capture.last(), &body); err != nil {
				t.Fatal(err)
			}
			if failure, _ := body["failure"].(map[string]any); failure["class"] != "apply_failed" {
				t.Errorf("failure.class = %v, want apply_failed", failure["class"])
			}
			if strings.Contains(out, "NOT durable") {
				t.Errorf("a publication failed on the cancelled context:\n%s", out)
			}
			if tc.wantPlay {
				data, _ := os.ReadFile(filepath.Join(e.dir, "playbook.pid"))
				pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
				if pid == 0 || !processGone(pid) {
					t.Errorf("the identity playbook (pid %d) outlived the cancellation", pid)
				}
			}
			if evs := readEvents(t, e.events); evs[len(evs)-1] != "release ipa-1" {
				t.Errorf("lock events %v: the lock is not given back", evs)
			}
			assertNoSecretAnywhere(t, err, out, result)
		})
	}
}

// The refusals of the command's own, each on a row (the gate ledger ties the ids to the code): what the Go engine
// refuses before anything is read stays refused for the mixed run, and the files it owns are reserved first.
func TestMixedRunRefusals(t *testing.T) {
	previewArgs := func(more ...string) []string {
		return append([]string{"--engine", "golang", "--preview-only", "--scope", "full", "--component", "freeipa-identity"}, more...)
	}
	for _, tc := range []struct {
		name string
		gate string
		args []string
		want string
	}{
		{name: "--result-out that exists", gate: "entry-golang-mixed-dispatch,exit-code-mixed,mixed-result-out,output-exists", args: mixedArgs("--result-out", "EXISTING"), want: "已存在；不覆寫"},
		{name: "--plan-out that exists, in a preview", gate: "mixed-plan-out,output-exists", args: previewArgs("--plan-out", "EXISTING"), want: "已存在；不覆寫"},
		{name: "a bad --timeout", gate: "mixed-timeout-parse", args: mixedArgs("--timeout", "soon"), want: "--timeout 不是合法的 duration"},
		{name: "--plan-out of a --force run", gate: "engine-plan-out-with-force", args: mixedArgs("--plan-out", "p.json"), want: "--result-out"},
		{name: "--result-out of a preview", gate: "engine-result-out-needs-force", args: previewArgs("--result-out", "r.json"), want: "只能與 --force"},
		{name: "--lock-wait of a preview", gate: "entry-lock-wait-preview-only", args: previewArgs("--lock-wait", "1m"), want: "--lock-wait 只對會取鎖的執行有意義"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			e := newMixedCLIEnv(t, rosterWithNewUser())
			args := tc.args
			for i, a := range args {
				if a == "EXISTING" {
					writePrivateFile(t, filepath.Join(e.dir, "EXISTING"), "keep")
					args[i] = filepath.Join(e.dir, "EXISTING")
				}
			}
			out, err := runReconcileCLI(t, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d), want %q and exit 1\n%s", err, processExitCode(err), tc.want, out)
			}
			if len(e.runs()) != 0 || len(e.a.writeMethods()) != 0 {
				t.Fatalf("something ran before the refusal: %v, writes %v", e.runs(), e.a.writeMethods())
			}
			assertNoLogin(t, e.f)
		})
	}
}
