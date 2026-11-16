package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

// The identity lock gate's repo-wide lint (AGENTS.md §5.10;
// docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §4.6):
// every non-test path that runs freeipa-identity-apply.yml holds the FreeIPA
// server's /etc/ipa lock for the run, because two runs interleaved on one
// server lose each other's authorization cache obligation
// (identity_lock_interleaving_test.go reproduces both interleavings).
//
// A lock a new caller can leave out is no lock, so the lint has six parts:
//
//  1. every reference to the playbook in non-test code is on a list that says
//     what it is (a funnel that locks, or data that reaches one);
//  2. each funnel on the list takes the lock before its first execution call
//     (a decommission's lock is the run's, taken after the approval and before
//     decommission.Apply, so before the client's uninstall; its converge step only
//     reads it: E41);
//  3. the contract of freeipa-identity keeps the shape that leaves the funnels
//     of (1) as the only ways to run it (no dependency on it, no canonical_apply
//     remediation, not part of site.yml, no other lifecycle playbook);
//  4. the dev paths are NOT funnels, on purpose: `pilot vm-target run`,
//     `vm-target test` and `vm-target topology test` run playbooks against
//     disposable machines the operator created for the purpose, from
//     docs/runbooks/vm-target.md, with their own snapshot and rollback; there
//     is no production authorization cache to lose, and holding a remote lock
//     on a VM that is about to be rolled back protects nothing. A manual
//     `ansible-playbook` is out of reach for any lint (spec R3);
//  5. executeDeploymentTransaction refuses the identity playbook at run time
//     when it was handed no lock (TestExecuteDeploymentRefusesTheIdentityPlaybookWithoutALock),
//     the one thing (1) cannot see: a caller that builds its own options;
//  6. every funnel also runs the no-ssh precheck of its lock target
//     (checkIdentityLockTarget) first, before its first execution call and, for
//     the ones that ask or record something, before that: the lock-time refusal
//     of an inventory comes too late (spec §4.2, "在任何 ansible-playbook 之前拒絕").
//     The entry points that call a funnel (identityPrecheckFunnels) are on a list
//     with what must come before what, a call of a funnel from a function that is
//     not on it fails, and the places that build a lock's Acquirer directly are
//     counted.
//
// The functions below take the sources as a map so the same code runs on the
// real tree and on the synthetic and mutated sources that prove it can fail.

const (
	lockFilePlaybookApply     = "freeipa-identity-apply.yml"
	lockFilePlaybookAuthCache = "freeipa-identity-auth-cache.yml"
)

// lockReference is one place non-test code names the identity playbook, with
// what it is. Token is `lit:<string>` for a string literal without
// whitespace that contains one of the two file names, or `ref:<name>` for a use
// of a constant that holds it. Count is how many times: a second use in the
// same file fails until it is looked at.
type lockReference struct {
	File   string
	Token  string
	Count  int
	Role   string
	Reason string
}

var identityLockReferences = []lockReference{
	{File: "cmd/pilot/cmd/deploy_catalog.go", Token: "lit:playbooks/apply/freeipa-identity-apply.yml", Count: 1, Role: "data",
		Reason: "the catalog entry of the freeipa-identity component. Every deploy and reconcile of it reaches executeRecordedDeploymentCore, which sets IdentityLock (funnel check), and executeDeploymentTransaction refuses the playbook without one"},
	{File: "cmd/pilot/cmd/host_decommission.go", Token: "lit:playbooks/apply/freeipa-identity-apply.yml", Count: 1, Role: "data",
		Reason: "wires the path into providers.FreeIPAClientProviderConfig; the converge step that runs it is a funnel ((*freeipaIdentityConvergeStep).Execute, which refuses without the lock runHostDecommissionApply holds for the run) and the read-only queries do not mutate"},
	{File: "cmd/pilot/cmd/access_cli.go", Token: "ref:accessgrants.DefaultPlaybook", Count: 1, Role: "data",
		Reason: "the default of the --playbook flag; whatever it names reaches accessgrants.applyPlan, which locks unconditionally"},
	{File: "cmd/pilot/cmd/access_breakglass_cli.go", Token: "ref:accessgrants.DefaultPlaybook", Count: 2, Role: "data",
		Reason: "the defaults of the --playbook flags of breakglass activate and deactivate; accessgrants.applyPlan locks unconditionally"},
	{File: "internal/accessgrants/reconcile.go", Token: "ref:identitylock.ApplyPlaybook", Count: 1, Role: "funnel",
		Reason: "DefaultPlaybook, the playbook applyPlan runs"},
	{File: "internal/accessgrants/reconcile.go", Token: "ref:DefaultPlaybook", Count: 1, Role: "funnel input",
		Reason: "ReconcileOnce hands the default playbook to applyPlan, the funnel"},
	{File: "internal/accessgrants/breakglass.go", Token: "ref:DefaultPlaybook", Count: 2, Role: "funnel input",
		Reason: "Activate and Deactivate hand the default playbook to applyPlan, the funnel"},
	{File: "cmd/pilot/cmd/reconcile_golang_apply.go", Token: "ref:identitylock.AuthCachePlaybook", Count: 1, Role: "funnel",
		Reason: "runGoAuthCacheEntry runs the entry playbook on the host whose /etc/ipa lock the run holds, under a context bound to that lock; it takes the *identitylock.Held (entryProblems), and its callers, runGolangApplyUnderLock (reached only from golangApply after the lock) and runMixedGoPhase (reached only from PrepareApply, which the apply step of the deploy transaction calls after the lock), hold it"},
	{File: "internal/identitylock/identitylock.go", Token: "lit:playbooks/apply/freeipa-identity-apply.yml", Count: 1, Role: "data",
		Reason: "the definition of the name the funnels and this lint are keyed on"},
	{File: "internal/identitylock/identitylock.go", Token: "lit:playbooks/apply/freeipa-identity-auth-cache.yml", Count: 1, Role: "data",
		Reason: "the definition of the entry playbook's name; a function that runs it must take a *identitylock.Held (checked below)"},
}

// lockSources maps a repo-relative path to its source.
type lockSources map[string]string

// readLockSources reads the non-test Go sources under cmd and internal.
func readLockSources(t *testing.T) lockSources {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	out := lockSources{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			out[filepath.ToSlash(rel)] = string(data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) < 100 {
		t.Fatalf("read only %d sources: the walk is not looking at the repo", len(out))
	}
	return out
}

func parseLockSource(t *testing.T, fset *token.FileSet, name, src string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return file
}

func sortedKeys(m lockSources) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// referencesIn lists the tokens of one file: how often it names the playbook.
func referencesIn(file *ast.File) map[string]int {
	found := map[string]int{}
	isSel := map[*ast.Ident]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			isSel[sel.Sel] = true
		}
		return true
	})
	decl := map[*ast.Ident]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if vs, ok := n.(*ast.ValueSpec); ok {
			for _, name := range vs.Names {
				decl[name] = true
			}
		}
		return true
	})
	pkgIsAccessgrants := file.Name.Name == "accessgrants"
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BasicLit:
			if n.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(n.Value)
			if err != nil || strings.ContainsAny(s, " \t\n") {
				return true
			}
			if strings.Contains(s, lockFilePlaybookApply) || strings.Contains(s, lockFilePlaybookAuthCache) {
				found["lit:"+s]++
			}
		case *ast.SelectorExpr:
			x, ok := n.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case x.Name == "accessgrants" && n.Sel.Name == "DefaultPlaybook",
				x.Name == "identitylock" && (n.Sel.Name == "ApplyPlaybook" || n.Sel.Name == "AuthCachePlaybook"):
				found["ref:"+x.Name+"."+n.Sel.Name]++
			}
		case *ast.Ident:
			if pkgIsAccessgrants && n.Name == "DefaultPlaybook" && !isSel[n] && !decl[n] {
				found["ref:DefaultPlaybook"]++
			}
		}
		return true
	})
	return found
}

// referenceProblems is part 1: every reference is on the list, with the right
// count, and nothing on the list is stale.
func referenceProblems(t *testing.T, src lockSources, allow []lockReference) []string {
	t.Helper()
	var problems []string
	fset := token.NewFileSet()
	type key struct{ file, token string }
	seen := map[key]int{}
	for _, name := range sortedKeys(src) {
		for tok, n := range referencesIn(parseLockSource(t, fset, name, src[name])) {
			seen[key{name, tok}] = n
		}
	}
	listed := map[key]lockReference{}
	for _, a := range allow {
		if strings.TrimSpace(a.Reason) == "" || strings.TrimSpace(a.Role) == "" {
			problems = append(problems, a.File+" "+a.Token+": an entry needs a role and a reason")
		}
		listed[key{a.File, a.Token}] = a
	}
	for k, n := range seen {
		a, ok := listed[k]
		switch {
		case !ok:
			problems = append(problems, k.file+": "+k.token+" is a reference to the identity playbook that is not on the funnel list: either it is a funnel and must take the lock (add it to identityLockFunnels), or it is data that reaches one (add it to identityLockReferences with the reason)")
		case a.Count != n:
			problems = append(problems, k.file+": "+k.token+" appears "+strconv.Itoa(n)+" times, the list says "+strconv.Itoa(a.Count)+": look at the new one")
		}
	}
	for k := range listed {
		if _, ok := seen[k]; !ok {
			problems = append(problems, k.file+": "+k.token+" is on the list but no longer in the source: drop the entry")
		}
	}
	sort.Strings(problems)
	return problems
}

// lockFunnel names a function (or a closure in it) that runs the identity
// playbook, and what takes the lock and what runs the playbook in it. Names are
// matched, not receivers' types: the funnels are reached through interfaces.
type lockFunnel struct {
	File    string
	Recv    string // receiver type name, "" for a function
	Func    string
	Closure string // a closure assigned to this name inside Func; "" for the function body
	Acquire callMatcher
	Execute callMatcher
	Before  []callMatcher // calls that must also come after the lock
	// Confirm are the calls that make the confirmation the lock comes after (D1:
	// the lock is taken after the confirmation, before the first thing that runs):
	// each must exist, and none may come after the lock.
	Confirm  []callMatcher
	Requires string // when set, the lock call must be unconditional (top level of the body) unless it sits in `if <Requires> {` (compared as source text: an identifier or a condition)
	// Nested is for a funnel whose lock call sits in a closure the function hands
	// to something else (a TUI screen's handler): the branch check cannot look
	// into it, only the order of the calls is checked.
	Nested bool
}

// callMatcher matches a call expression by the shape of what it calls.
type callMatcher struct {
	Desc string
	Fun  string // "ident:name" | "sel:name" (any receiver) | "method:recv.name"
}

func (m callMatcher) matches(call *ast.CallExpr) bool {
	kind, name, _ := strings.Cut(m.Fun, ":")
	switch kind {
	case "ident":
		id, ok := call.Fun.(*ast.Ident)
		return ok && id.Name == name
	case "sel":
		sel, ok := call.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == name
	case "method":
		recv, method, _ := strings.Cut(name, ".")
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != method {
			return false
		}
		x, ok := sel.X.(*ast.Ident)
		return ok && x.Name == recv
	}
	return false
}

var identityLockFunnels = []lockFunnel{
	{
		File: "internal/accessgrants/reconcile.go", Func: "applyPlan",
		Acquire: callMatcher{"the lock acquirer", "ident:lock"},
		Execute: callMatcher{"runner.Run", "method:runner.Run"},
	},
	{
		// The converge step does not take the lock: it reads the one the run holds
		// from its context before it runs the playbook, and refuses without it.
		File: "internal/decommission/providers/freeipa_client.go", Recv: "freeipaIdentityConvergeStep", Func: "Execute",
		Acquire: callMatcher{"identitylock.Require", "method:identitylock.Require"},
		Execute: callMatcher{"e.provider.exec", "sel:exec"},
	},
	{
		// The decommission's lock is the run's, and the converge is its last step: the
		// first change is the client's uninstall. The lock comes after the approval
		// (the confirmation) and before decommission.Apply, so before the first
		// step; only a plan that is not completed and runs the converge step takes it.
		File: "cmd/pilot/cmd/host_decommission.go", Func: "runHostDecommissionApply",
		Acquire:  callMatcher{"the run's lock acquirer", "ident:acquire"},
		Execute:  callMatcher{"decommission.Apply", "method:decommission.Apply"},
		Confirm:  []callMatcher{{"ds.RecordApproval", "sel:RecordApproval"}},
		Requires: "needsLock",
	},
	{
		// The Go writer's lock is the run's: taken after the preflight and the no-ssh
		// precheck, before the first connection, held through runGolangApplyUnderLock (the
		// entry playbook and every write) and given back after it. Unconditional: the
		// users-groups scope has no path without the lock.
		File: "cmd/pilot/cmd/reconcile_golang_apply.go", Func: "golangApply",
		Acquire: callMatcher{"the run's lock acquirer", "ident:acquire"},
		Execute: callMatcher{"runGolangApplyUnderLock", "ident:runGolangApplyUnderLock"},
	},
	{
		// The apply closure: after every confirmation (announce), before
		// PrepareApply and the command (execute). Conditional only on the
		// playbook being the identity one.
		File: "cmd/pilot/cmd/deploy.go", Func: "executeDeploymentTransaction", Closure: "apply",
		Acquire:  callMatcher{"options.IdentityLock", "sel:IdentityLock"},
		Execute:  callMatcher{"execute", "ident:execute"},
		Before:   []callMatcher{{"options.PrepareApply", "sel:PrepareApply"}},
		Requires: "identity",
	},
}

// identityPrecheckFunnels is part 6: the entry points that reach a funnel, and
// what each does first. Acquire is the no-ssh precheck (checkIdentityLockTarget,
// reached through identityLockFor, tuiIdentityLockFor, or a function that
// wraps it); Execute is the first thing the entry does that runs, asks or
// changes something; Before are the other things that must come after it. The
// funnels of identityLockFunnels refuse an inventory at the moment they take the
// lock, which for most of them is late: a deploy's after preflight, the
// freeipa-server dependency and the `--check`, a drift repair's after its probe
// (a decommission's was after the client's uninstall and the roster tombstone
// until E41 moved the lock to the front of the run; its precheck still comes
// before the approval).
var identityPrecheckFunnels = []lockFunnel{
	{
		File: "cmd/pilot/cmd/identity_lock.go", Func: "identityLockFor",
		Acquire: callMatcher{"checkIdentityLockTarget", "ident:checkIdentityLockTarget"},
		Execute: callMatcher{"newIdentityLock", "ident:newIdentityLock"},
	},
	{
		File: "cmd/pilot/cmd/access_cli.go", Func: "runAccessReconcileCmd",
		Acquire: callMatcher{"identityLockFor", "ident:identityLockFor"},
		Execute: callMatcher{"accessgrants.ReconcileOnce", "method:accessgrants.ReconcileOnce"},
	},
	{
		File: "cmd/pilot/cmd/access_breakglass_cli.go", Func: "runAccessBreakglassActivateCmd",
		Acquire: callMatcher{"identityLockFor", "ident:identityLockFor"},
		Execute: callMatcher{"accessgrants.Activate", "method:accessgrants.Activate"},
	},
	{
		File: "cmd/pilot/cmd/access_breakglass_cli.go", Func: "runAccessBreakglassDeactivateCmd",
		Acquire: callMatcher{"identityLockFor", "ident:identityLockFor"},
		Execute: callMatcher{"accessgrants.Deactivate", "method:accessgrants.Deactivate"},
	},
	{
		File: "cmd/pilot/cmd/access_drift_cli.go", Func: "runAccessDriftCmd",
		Acquire: callMatcher{"identityLockFor", "ident:identityLockFor"},
		Execute: callMatcher{"accessgrants.RepairManaged", "method:accessgrants.RepairManaged"},
	},
	{
		File: "cmd/pilot/cmd/identity_drift_cli.go", Func: "runIdentityDriftCmd",
		Acquire: callMatcher{"identityLockFor", "ident:identityLockFor"},
		Execute: callMatcher{"accessgrants.RepairManaged", "method:accessgrants.RepairManaged"},
	},
	{
		File: "cmd/pilot/cmd/edit_tui_roster_breakglass.go", Func: "pushBreakglassActivateTicket", Nested: true,
		Acquire: callMatcher{"tuiIdentityLockFor", "ident:tuiIdentityLockFor"},
		Execute: callMatcher{"accessgrants.Activate", "method:accessgrants.Activate"},
	},
	{
		File: "cmd/pilot/cmd/edit_tui_roster_breakglass.go", Func: "pushBreakglassDeactivateConfirm", Nested: true,
		Acquire: callMatcher{"tuiIdentityLockFor", "ident:tuiIdentityLockFor"},
		Execute: callMatcher{"accessgrants.Deactivate", "method:accessgrants.Deactivate"},
	},
	{
		// A plan already completed replays its receipt and runs nothing, and a plan
		// without the converge step never runs the identity playbook: the precheck is
		// for the plans that take the lock (needsLock) and comes before the approval
		// is recorded. identityLockFor makes it and builds the run's Acquirer, which
		// is called after the approval (the funnel above).
		File: "cmd/pilot/cmd/host_decommission.go", Func: "runHostDecommissionApply",
		Acquire:  callMatcher{"identityLockFor", "ident:identityLockFor"},
		Execute:  callMatcher{"decommission.Apply", "method:decommission.Apply"},
		Before:   []callMatcher{{"ds.RecordApproval", "sel:RecordApproval"}},
		Requires: "needsLock",
	},
	{
		// The Go writer: the precheck (identityLockFor) comes before the dialer is made
		// and before the lock is taken or anything is connected to.
		File: "cmd/pilot/cmd/reconcile_golang_apply.go", Func: "golangApply",
		Acquire: callMatcher{"identityLockFor", "ident:identityLockFor"},
		Execute: callMatcher{"newGolangDialer", "ident:newGolangDialer"},
		Before:  []callMatcher{{"runGolangApplyUnderLock", "ident:runGolangApplyUnderLock"}},
	},
	{
		// Before the plan is rendered or the operator is asked, before the
		// freeipa-server dependency is applied, before any core run.
		File: "cmd/pilot/cmd/deploy.go", Func: "executeRecordedDeploymentWithAuthorizationResult",
		Acquire: callMatcher{"precheckIdentityDeploy", "ident:precheckIdentityDeploy"},
		Execute: callMatcher{"applyDeploymentDependencyChain", "ident:applyDeploymentDependencyChain"},
		Before: []callMatcher{
			{"renderReconcileExecutionPlan", "ident:renderReconcileExecutionPlan"},
			{"promptReconcileExecutionAuthorization", "ident:promptReconcileExecutionAuthorization"},
			{"executeRecordedDeploymentCore", "ident:executeRecordedDeploymentCore"},
		},
	},
	{
		// The batch (pilot reconcile, a multi-component pilot deploy) shows its
		// plan and asks for one authorization for everything in it.
		File: "cmd/pilot/cmd/deploy.go", Func: "executeCatalogBatch",
		Acquire: callMatcher{"precheckIdentityBatch", "ident:precheckIdentityBatch"},
		Execute: callMatcher{"promptReconcileExecutionAuthorization", "ident:promptReconcileExecutionAuthorization"},
		Before: []callMatcher{
			{"prepareReconcileExecutionPlan", "ident:prepareReconcileExecutionPlan"},
			{"executeRecordedDeploymentWithAuthorizationResult", "ident:executeRecordedDeploymentWithAuthorizationResult"},
		},
	},
}

// A funnel is reached only through the entry points above. protectedCalls are the
// calls that run one: made from a function that is not listed, they would run
// a funnel without the precheck, which the list cannot see. Core is allowed
// from the dependency chain too: freeipa-identity is no component's dependency
// (identityContractProblems), so what the chain applies is never the identity
// playbook.
type protectedCall struct {
	Call    callMatcher
	Allowed []string // "file func"
}

var identityProtectedCalls = []protectedCall{
	{callMatcher{"executeRecordedDeploymentCore", "ident:executeRecordedDeploymentCore"}, []string{
		"cmd/pilot/cmd/deploy.go executeRecordedDeploymentWithAuthorizationResult",
		"cmd/pilot/cmd/deploy.go applyDeploymentDependencyChain",
	}},
	{callMatcher{"accessgrants.ReconcileOnce", "method:accessgrants.ReconcileOnce"}, []string{"cmd/pilot/cmd/access_cli.go runAccessReconcileCmd"}},
	{callMatcher{"accessgrants.RepairManaged", "method:accessgrants.RepairManaged"}, []string{
		"cmd/pilot/cmd/access_drift_cli.go runAccessDriftCmd",
		"cmd/pilot/cmd/identity_drift_cli.go runIdentityDriftCmd",
	}},
	{callMatcher{"accessgrants.Activate", "method:accessgrants.Activate"}, []string{
		"cmd/pilot/cmd/access_breakglass_cli.go runAccessBreakglassActivateCmd",
		"cmd/pilot/cmd/edit_tui_roster_breakglass.go pushBreakglassActivateTicket",
	}},
	{callMatcher{"accessgrants.Deactivate", "method:accessgrants.Deactivate"}, []string{
		"cmd/pilot/cmd/access_breakglass_cli.go runAccessBreakglassDeactivateCmd",
		"cmd/pilot/cmd/edit_tui_roster_breakglass.go pushBreakglassDeactivateConfirm",
	}},
	{callMatcher{"decommission.Apply", "method:decommission.Apply"}, []string{"cmd/pilot/cmd/host_decommission.go runHostDecommissionApply"}},
	{callMatcher{"runGolangApplyUnderLock", "ident:runGolangApplyUnderLock"}, []string{"cmd/pilot/cmd/reconcile_golang_apply.go golangApply"}},
	{callMatcher{"identityreconcile.Execute", "method:identityreconcile.Execute"}, []string{
		"cmd/pilot/cmd/reconcile_golang_apply.go runGolangApplyUnderLock",
		"cmd/pilot/cmd/reconcile_golang_mixed.go runMixedGoPhase",
	}},
	// The mixed run's Go phase (P2-7): reached only from PrepareApply, which the apply step of
	// executeDeploymentTransaction calls after it has taken the lock (identityLockFunnels, Before), and
	// which requires the lock in its context before it calls the phase.
	{callMatcher{"runMixedGoPhase", "ident:runMixedGoPhase"}, []string{"cmd/pilot/cmd/reconcile_golang_mixed.go PrepareApply"}},
}

// identityLockBuilders are the places that build a funnel's Acquirer by calling
// newIdentityLock themselves, with how many calls each makes. The others get
// theirs from identityLockFor, which makes the precheck first (a decommission's
// run does: runHostDecommissionApply, and no provider registry builds a lock any
// more, so `plan`, which builds the registry too, never builds one). The deploy
// runner cannot: it learns the host it locks in two steps (the candidates for the
// precheck, the included hosts after availability for the lock). It has its
// precheck on identityPrecheckFunnels.
var identityLockBuilders = []struct {
	File   string
	Count  int
	Reason string
}{
	{"cmd/pilot/cmd/identity_lock.go", 1, "identityLockFor: the precheck, then the Acquirer"},
	{"cmd/pilot/cmd/deploy.go", 1, "executeRecordedDeploymentCore builds the apply step's Acquirer from the included hosts; precheckIdentityDeploy (called first by executeRecordedDeploymentWithAuthorizationResult) asks about the candidates"},
}

// enclosingFuncs lists, for every call in file that m matches, the name of the
// top-level function it sits in (closures included).
func enclosingFuncs(file *ast.File, m callMatcher) []string {
	var out []string
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && m.matches(call) {
				out = append(out, fd.Name.Name)
			}
			return true
		})
	}
	return out
}

// precheckProblems is part 6.
func precheckProblems(t *testing.T, src lockSources) []string {
	t.Helper()
	problems := funnelProblems(t, src, identityPrecheckFunnels)
	fset := token.NewFileSet()
	// A protected call from a function that is not on the list.
	for _, name := range sortedKeys(src) {
		if strings.HasPrefix(name, "internal/accessgrants/") || strings.HasPrefix(name, "internal/decommission/") {
			continue // the packages that define the funnels
		}
		file := parseLockSource(t, fset, name, src[name])
		for _, pc := range identityProtectedCalls {
			for _, fn := range enclosingFuncs(file, pc.Call) {
				if !slices.Contains(pc.Allowed, name+" "+fn) {
					problems = append(problems, name+" "+fn+": calls "+pc.Call.Desc+" but is not on the list of entry points that run the precheck first (identityPrecheckFunnels, identityProtectedCalls): add it to both, with the precheck before the call, or it would run a funnel with the lock checked only when it is taken")
				}
			}
		}
	}
	// Every allowed caller still makes its call, so a stale entry does not hide a
	// moved one.
	for _, pc := range identityProtectedCalls {
		for _, allowed := range pc.Allowed {
			file, fn, _ := strings.Cut(allowed, " ")
			text, ok := src[file]
			if !ok {
				problems = append(problems, allowed+": the file is gone: update identityProtectedCalls")
				continue
			}
			if !slices.Contains(enclosingFuncs(parseLockSource(t, fset, file, text), pc.Call), fn) {
				problems = append(problems, allowed+": no longer calls "+pc.Call.Desc+": drop the entry or find where the call went")
			}
		}
	}
	// Where an Acquirer is built without identityLockFor.
	build := callMatcher{"newIdentityLock", "ident:newIdentityLock"}
	counts := map[string]int{}
	for _, name := range sortedKeys(src) {
		counts[name] = len(enclosingFuncs(parseLockSource(t, fset, name, src[name]), build))
	}
	listed := map[string]bool{}
	for _, b := range identityLockBuilders {
		listed[b.File] = true
		if counts[b.File] != b.Count {
			problems = append(problems, b.File+": calls newIdentityLock "+strconv.Itoa(counts[b.File])+" times, the list says "+strconv.Itoa(b.Count)+": a funnel that builds its own Acquirer needs its precheck on identityPrecheckFunnels, then update identityLockBuilders ("+b.Reason+")")
		}
	}
	for name, n := range counts {
		if n > 0 && !listed[name] {
			problems = append(problems, name+": calls newIdentityLock directly: go through identityLockFor, which runs the precheck first (or list it in identityLockBuilders with its precheck)")
		}
	}
	sort.Strings(problems)
	return problems
}

// funcBody finds the body of a function or method, or of the closure assigned
// to closure inside it.
func funcBody(file *ast.File, recv, name, closure string) *ast.BlockStmt {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Name.Name != name {
			continue
		}
		if recv != "" {
			if fd.Recv == nil || len(fd.Recv.List) != 1 {
				continue
			}
			typ := fd.Recv.List[0].Type
			if star, ok := typ.(*ast.StarExpr); ok {
				typ = star.X
			}
			if id, ok := typ.(*ast.Ident); !ok || id.Name != recv {
				continue
			}
		} else if fd.Recv != nil {
			continue
		}
		if closure == "" {
			return fd.Body
		}
		var found *ast.BlockStmt
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			lit, isLit := as.Rhs[0].(*ast.FuncLit)
			if ok && isLit && id.Name == closure {
				found = lit.Body
			}
			return true
		})
		return found
	}
	return nil
}

// firstCall is the position of the first call in body (source order, closures
// included) that m matches.
func firstCall(body *ast.BlockStmt, m callMatcher) (token.Pos, bool) {
	var first token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && m.matches(call) {
			if first == token.NoPos || call.Pos() < first {
				first = call.Pos()
			}
		}
		return true
	})
	return first, first != token.NoPos
}

// lastCallAfter reports whether any call in body that m matches comes after pos.
func lastCallAfter(body *ast.BlockStmt, m callMatcher, pos token.Pos) bool {
	after := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && m.matches(call) && call.Pos() > pos {
			after = true
		}
		return !after
	})
	return after
}

// lockIsUnconditional reports whether the call that m matches is a statement of
// the body itself (or of `if <cond> {` when cond is not empty), not behind a
// branch that could skip it.
func lockIsUnconditional(body *ast.BlockStmt, m callMatcher, cond string) bool {
	// A statement that decides whether to go on (a branch, a loop, a switch)
	// does not count, and neither does what a closure would do later.
	has := func(stmts []ast.Stmt) bool {
		for _, st := range stmts {
			switch st.(type) {
			case *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.ForStmt, *ast.RangeStmt, *ast.BlockStmt:
				continue
			}
			found := false
			ast.Inspect(st, func(n ast.Node) bool {
				if _, ok := n.(*ast.FuncLit); ok {
					return false
				}
				if call, ok := n.(*ast.CallExpr); ok && m.matches(call) {
					found = true
				}
				return !found
			})
			if found {
				return true
			}
		}
		return false
	}
	if has(body.List) {
		return true
	}
	if cond == "" {
		return false
	}
	for _, st := range body.List {
		ifs, ok := st.(*ast.IfStmt)
		if !ok {
			continue
		}
		if types.ExprString(ifs.Cond) == cond && ifs.Else == nil && has(ifs.Body.List) {
			return true
		}
	}
	return false
}

// funnelProblems is part 2.
func funnelProblems(t *testing.T, src lockSources, funnels []lockFunnel) []string {
	t.Helper()
	var problems []string
	fset := token.NewFileSet()
	for _, f := range funnels {
		where := f.File + " " + f.Func
		if f.Closure != "" {
			where += " (" + f.Closure + " closure)"
		}
		text, ok := src[f.File]
		if !ok {
			problems = append(problems, where+": the file is gone: a funnel was moved, update identityLockFunnels")
			continue
		}
		body := funcBody(parseLockSource(t, fset, f.File, text), f.Recv, f.Func, f.Closure)
		if body == nil {
			problems = append(problems, where+": the funnel function was not found: a funnel was renamed, update identityLockFunnels")
			continue
		}
		lockAt, locks := firstCall(body, f.Acquire)
		runAt, runs := firstCall(body, f.Execute)
		switch {
		case !runs:
			problems = append(problems, where+": no call of "+f.Execute.Desc+": the lint no longer recognizes where this funnel runs the playbook")
		case !locks:
			problems = append(problems, where+": runs the playbook ("+f.Execute.Desc+") without taking the lock: no call of "+f.Acquire.Desc)
		case lockAt > runAt:
			problems = append(problems, where+": takes the lock ("+f.Acquire.Desc+") after "+f.Execute.Desc+": the playbook runs before it")
		}
		for _, b := range f.Before {
			if at, ok := firstCall(body, b); ok && locks && at < lockAt {
				problems = append(problems, where+": "+b.Desc+" is called before the lock is taken")
			}
		}
		for _, c := range f.Confirm {
			first, found := firstCall(body, c)
			switch {
			case !found:
				problems = append(problems, where+": no call of "+c.Desc+": the lint no longer recognizes where the confirmation is made")
			case locks && lastCallAfter(body, c, lockAt):
				problems = append(problems, where+": "+c.Desc+" is called after the lock is taken: the lock comes after the confirmation and before the first step (D1)")
			case locks && first > lockAt:
				problems = append(problems, where+": "+c.Desc+" is called after the lock is taken")
			}
		}
		if locks && !f.Nested && !lockIsUnconditional(body, f.Acquire, f.Requires) {
			problems = append(problems, where+": the lock is taken behind a branch that can skip it")
		}
	}
	return problems
}

// optionsLiteralProblems is part of 2 for executeRecordedDeploymentCore: the
// options literal handed to executeDeploymentTransaction sets IdentityLock.
func optionsLiteralProblems(t *testing.T, src lockSources) []string {
	t.Helper()
	const file = "cmd/pilot/cmd/deploy.go"
	text, ok := src[file]
	if !ok {
		return []string{file + ": the file is gone"}
	}
	body := funcBody(parseLockSource(t, token.NewFileSet(), file, text), "", "executeRecordedDeploymentCore", "")
	if body == nil {
		return []string{file + " executeRecordedDeploymentCore: not found: update the lint"}
	}
	setsLock := false
	sawLiteral := false
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "deploymentTransactionOptions" {
			return true
		}
		sawLiteral = true
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "IdentityLock" {
					setsLock = true
				}
			}
		}
		return true
	})
	switch {
	case !sawLiteral:
		return []string{file + " executeRecordedDeploymentCore: no deploymentTransactionOptions literal: the lint no longer sees how it calls executeDeploymentTransaction"}
	case !setsLock:
		return []string{file + " executeRecordedDeploymentCore: the deploymentTransactionOptions literal does not set IdentityLock: the apply step of every deploy of the identity playbook would refuse"}
	}
	return nil
}

// lockedOptionTypes are the option structs a caller builds for a funnel, and
// the field that must carry its lock. The funnels refuse to run when it is
// nil, which is the safety net; this check makes the omission fail a test of the
// caller too, at the literal, before anyone runs it.
var lockedOptionTypes = map[string]string{
	"accessgrants.ReconcileOptions":  "Lock",
	"accessgrants.ActivateOptions":   "Lock",
	"accessgrants.DeactivateOptions": "Lock",
}

// optionLiteralProblems: every composite literal of one of those types in
// non-test code outside the package that defines it sets the lock.
func optionLiteralProblems(t *testing.T, src lockSources) []string {
	t.Helper()
	var problems []string
	fset := token.NewFileSet()
	for _, name := range sortedKeys(src) {
		file := parseLockSource(t, fset, name, src[name])
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			field, locked := lockedOptionTypes[x.Name+"."+sel.Sel.Name]
			if !locked {
				return true
			}
			for _, el := range lit.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == field {
						return true
					}
				}
			}
			problems = append(problems, name+": a "+x.Name+"."+sel.Sel.Name+" literal without "+field+": that funnel refuses to run without a lock")
			return true
		})
	}
	return problems
}

// refusalProblems is part 5's static half: executeDeploymentTransaction begins
// with the refusal of the identity playbook without a lock.
func refusalProblems(t *testing.T, src lockSources) []string {
	t.Helper()
	const file = "cmd/pilot/cmd/deploy.go"
	text, ok := src[file]
	if !ok {
		return []string{file + ": the file is gone"}
	}
	body := funcBody(parseLockSource(t, token.NewFileSet(), file, text), "", "executeDeploymentTransaction", "")
	if body == nil {
		return []string{file + " executeDeploymentTransaction: not found: update the lint"}
	}
	for _, st := range body.List {
		ifs, ok := st.(*ast.IfStmt)
		if !ok {
			continue
		}
		refuses := false
		ast.Inspect(ifs.Cond, func(n ast.Node) bool {
			if be, ok := n.(*ast.BinaryExpr); ok && be.Op == token.EQL {
				if sel, ok := be.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "IdentityLock" {
					refuses = true
				}
			}
			return true
		})
		if refuses {
			if _, ret := ifs.Body.List[0].(*ast.ReturnStmt); ret {
				return nil
			}
		}
	}
	return []string{file + " executeDeploymentTransaction: no `if ... options.IdentityLock == nil { return }`: a caller that builds its own options could run the identity playbook without the lock"}
}

// entryProblems: a function that runs the auth-cache entry playbook must take
// the *identitylock.Held of the run it is part of: the entry changes the
// obligation the lock protects.
func entryProblems(t *testing.T, src lockSources) []string {
	t.Helper()
	var problems []string
	fset := token.NewFileSet()
	for _, name := range sortedKeys(src) {
		if strings.HasPrefix(name, "internal/identitylock/") {
			continue // the definition
		}
		file := parseLockSource(t, fset, name, src[name])
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			names := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BasicLit:
					if s, err := strconv.Unquote(n.Value); n.Kind == token.STRING && err == nil && !strings.ContainsAny(s, " \t\n") && strings.Contains(s, lockFilePlaybookAuthCache) {
						names = true
					}
				case *ast.SelectorExpr:
					if x, ok := n.X.(*ast.Ident); ok && x.Name == "identitylock" && n.Sel.Name == "AuthCachePlaybook" {
						names = true
					}
				}
				return true
			})
			if !names {
				continue
			}
			takesHeld := false
			for _, p := range fd.Type.Params.List {
				if star, ok := p.Type.(*ast.StarExpr); ok {
					if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Held" {
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == "identitylock" {
							takesHeld = true
						}
					}
				}
			}
			if !takesHeld {
				problems = append(problems, name+" "+fd.Name.Name+": runs the auth-cache entry playbook without taking a *identitylock.Held: it changes the obligation the lock protects")
			}
		}
	}
	return problems
}

// writerProblems: a function that calls the Go writer (identityreconcile.Execute) must take the
// *identitylock.Held of the run it is part of. Execute refuses a context with no lock, but a
// caller that takes no Held cannot have one to put there on purpose.
func writerProblems(t *testing.T, src lockSources) []string {
	t.Helper()
	var problems []string
	fset := token.NewFileSet()
	call := callMatcher{"identityreconcile.Execute", "method:identityreconcile.Execute"}
	for _, name := range sortedKeys(src) {
		if strings.HasPrefix(name, "internal/identityreconcile/") {
			continue // the definition
		}
		file := parseLockSource(t, fset, name, src[name])
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			calls := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok && call.matches(c) {
					calls = true
				}
				return true
			})
			if !calls {
				continue
			}
			takesHeld := false
			for _, p := range fd.Type.Params.List {
				if star, ok := p.Type.(*ast.StarExpr); ok {
					if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Held" {
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == "identitylock" {
							takesHeld = true
						}
					}
				}
			}
			if !takesHeld {
				problems = append(problems, name+" "+fd.Name.Name+": calls the Go writer (identityreconcile.Execute) without taking a *identitylock.Held: every write of the engine is made under the run's /etc/ipa lock")
			}
		}
	}
	return problems
}

// seamProblems: the test seams of the lock exist for tests. Non-test code
// does not assign newIdentityLock, newIdentityLockDialer or
// identityLockPrecheck, and nothing but a test imports the fake.
func seamProblems(t *testing.T, src lockSources) []string {
	t.Helper()
	var problems []string
	fset := token.NewFileSet()
	for _, name := range sortedKeys(src) {
		file := parseLockSource(t, fset, name, src[name])
		for _, imp := range file.Imports {
			if strings.HasSuffix(strings.Trim(imp.Path.Value, `"`), "internal/identitylock/identitylocktest") {
				problems = append(problems, name+": imports identitylocktest, a package for tests only")
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && (id.Name == "newIdentityLock" || id.Name == "newIdentityLockDialer" || id.Name == "identityLockPrecheck") {
					problems = append(problems, name+": assigns "+id.Name+", a test seam: production code builds the lock through it, it does not replace it")
				}
			}
			return true
		})
	}
	return problems
}

// allIdentityLockProblems runs every static part on src.
func allIdentityLockProblems(t *testing.T, src lockSources) []string {
	t.Helper()
	var all []string
	all = append(all, referenceProblems(t, src, identityLockReferences)...)
	all = append(all, funnelProblems(t, src, identityLockFunnels)...)
	all = append(all, optionsLiteralProblems(t, src)...)
	all = append(all, optionLiteralProblems(t, src)...)
	all = append(all, refusalProblems(t, src)...)
	all = append(all, entryProblems(t, src)...)
	all = append(all, writerProblems(t, src)...)
	all = append(all, seamProblems(t, src)...)
	all = append(all, precheckProblems(t, src)...)
	return all
}

func TestRegression_EveryRunOfTheIdentityPlaybookHoldsTheLock(t *testing.T) {
	if problems := allIdentityLockProblems(t, readLockSources(t)); len(problems) != 0 {
		t.Fatalf("the identity lock gate has holes:\n%s", strings.Join(problems, "\n"))
	}
}

// The contract part (3): the ways freeipa-identity could be reached without
// going through a funnel of the lint. When any of them changes, the path it
// opens must take the lock first, and this test is what makes someone notice.
func TestRegression_IdentityContractLeavesNoWayAroundTheFunnels(t *testing.T) {
	root := repoRootForTest(t)
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range identityContractProblems(catalog) {
		t.Error(problem)
	}
}

func identityContractProblems(catalog contract.Catalog) []string {
	var problems []string
	identity, ok := catalog.Component("freeipa-identity")
	if !ok {
		return []string{"freeipa-identity is not in the catalog: update the lint"}
	}
	for _, c := range catalog.Components() {
		for _, dep := range c.Dependencies {
			if dep.Component == "freeipa-identity" {
				problems = append(problems, c.ID+" depends on freeipa-identity: a deploy of "+c.ID+" would apply it first through applyDeploymentDependencyChain, which is executeRecordedDeploymentCore (it locks), but a component that carries the playbook some other way would not: check the path before adding the dependency, then update this guard")
			}
		}
	}
	for _, action := range identity.Remediation.Actions {
		if action.Executor.Kind == "canonical_apply" {
			problems = append(problems, "freeipa-identity declares a canonical_apply remediation action ("+action.ID+"): repair.Execute runs the contract's apply playbook directly, with no lock")
		}
	}
	if identity.Site.Include {
		problems = append(problems, "freeipa-identity is part of site.yml: the site-wide deploy imports the playbook, and that import is not a funnel")
	}
	if identity.Playbooks.Apply != identitylockApply {
		problems = append(problems, "freeipa-identity's apply playbook is "+identity.Playbooks.Apply+", not the one the funnels are keyed on: update identitylock.ApplyPlaybook")
	}
	for name, p := range map[string]*string{"rollback": identity.Playbooks.Rollback, "upgrade": identity.Playbooks.Upgrade, "decommission": identity.Playbooks.Decommission} {
		if p != nil {
			problems = append(problems, "freeipa-identity declares a "+name+" playbook ("+*p+"): "+
				"a deploy action that runs it would not be recognized as the identity playbook by executeDeploymentTransaction")
		}
	}
	return problems
}

// identitylockApply is what the contract's apply playbook must equal.
const identitylockApply = "playbooks/apply/freeipa-identity-apply.yml"

// The lint would be vacuous if it could not fail. Each case below feeds the
// checks a source that has the hole they exist for.
func TestIdentityLockLintFailsOnSyntheticHoles(t *testing.T) {
	good := func() lockSources {
		return lockSources{
			"internal/accessgrants/reconcile.go": `package accessgrants
func applyPlan(lock Acquirer, runner R) {
	held, _ := lock(ctx)
	defer held.Release()
	runner.Run(ctx)
}`,
		}
	}
	funnel := []lockFunnel{{
		File: "internal/accessgrants/reconcile.go", Func: "applyPlan",
		Acquire: callMatcher{"the lock acquirer", "ident:lock"},
		Execute: callMatcher{"runner.Run", "method:runner.Run"},
	}}
	if p := funnelProblems(t, good(), funnel); len(p) != 0 {
		t.Fatalf("the good funnel is reported: %v", p)
	}
	for name, tc := range map[string]struct {
		src  lockSources
		want string
	}{
		"no lock call": {
			lockSources{"internal/accessgrants/reconcile.go": "package accessgrants\nfunc applyPlan(runner R) {\n\trunner.Run(ctx)\n}"},
			"without taking the lock",
		},
		"the lock after the run": {
			lockSources{"internal/accessgrants/reconcile.go": "package accessgrants\nfunc applyPlan(lock A, runner R) {\n\trunner.Run(ctx)\n\tlock(ctx)\n}"},
			"after runner.Run",
		},
		"the lock behind a branch": {
			lockSources{"internal/accessgrants/reconcile.go": "package accessgrants\nfunc applyPlan(lock A, runner R, p string) {\n\tif p == \"x\" {\n\t\tlock(ctx)\n\t}\n\trunner.Run(ctx)\n}"},
			"behind a branch",
		},
		"the funnel renamed": {
			lockSources{"internal/accessgrants/reconcile.go": "package accessgrants\nfunc applyThePlan(lock A, runner R) {\n\tlock(ctx)\n\trunner.Run(ctx)\n}"},
			"was not found",
		},
		"the run no longer recognized": {
			lockSources{"internal/accessgrants/reconcile.go": "package accessgrants\nfunc applyPlan(lock A, r R) {\n\tlock(ctx)\n\tr.Go(ctx)\n}"},
			"no longer recognizes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := funnelProblems(t, tc.src, funnel)
			if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), tc.want) {
				t.Fatalf("problems = %v, want one containing %q", p, tc.want)
			}
		})
	}

	t.Run("a new literal that is not listed", func(t *testing.T) {
		src := lockSources{"internal/newthing/run.go": "package newthing\nconst p = \"playbooks/apply/freeipa-identity-apply.yml\"\n"}
		p := referenceProblems(t, src, nil)
		if len(p) != 1 || !strings.Contains(p[0], "not on the funnel list") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("a prose string is not a reference", func(t *testing.T) {
		src := lockSources{"internal/newthing/run.go": "package newthing\nconst p = \"runs freeipa-identity-apply.yml for you\"\n"}
		if p := referenceProblems(t, src, nil); len(p) != 0 {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("a new use of the constant", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/new.go": "package cmd\nvar p = accessgrants.DefaultPlaybook\n"}
		p := referenceProblems(t, src, nil)
		if len(p) != 1 || !strings.Contains(p[0], "ref:accessgrants.DefaultPlaybook") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("a bare use inside accessgrants", func(t *testing.T) {
		src := lockSources{"internal/accessgrants/new.go": "package accessgrants\nfunc f() string { return DefaultPlaybook }\n"}
		p := referenceProblems(t, src, nil)
		if len(p) != 1 || !strings.Contains(p[0], "ref:DefaultPlaybook") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("a second use in a listed file", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/access_cli.go": "package cmd\nvar a = accessgrants.DefaultPlaybook\nvar b = accessgrants.DefaultPlaybook\n"}
		allow := []lockReference{{File: "cmd/pilot/cmd/access_cli.go", Token: "ref:accessgrants.DefaultPlaybook", Count: 1, Role: "data", Reason: "x"}}
		p := referenceProblems(t, src, allow)
		if len(p) != 1 || !strings.Contains(p[0], "appears 2 times") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("a stale entry", func(t *testing.T) {
		allow := []lockReference{{File: "cmd/pilot/cmd/gone.go", Token: "ref:accessgrants.DefaultPlaybook", Count: 1, Role: "data", Reason: "x"}}
		p := referenceProblems(t, lockSources{}, allow)
		if len(p) != 1 || !strings.Contains(p[0], "no longer in the source") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("an entry without a reason", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/new.go": "package cmd\nvar p = accessgrants.DefaultPlaybook\n"}
		allow := []lockReference{{File: "cmd/pilot/cmd/new.go", Token: "ref:accessgrants.DefaultPlaybook", Count: 1, Role: "data"}}
		if p := referenceProblems(t, src, allow); len(p) != 1 || !strings.Contains(p[0], "role and a reason") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("an entry runner that takes no Held", func(t *testing.T) {
		src := lockSources{"internal/identityreconcile/entry.go": "package identityreconcile\nimport \"x/identitylock\"\nfunc runEntry(ctx context.Context) {\n\t_ = identitylock.AuthCachePlaybook\n}\nfunc runEntryHeld(ctx context.Context, h *identitylock.Held) {\n\t_ = identitylock.AuthCachePlaybook\n}\n"}
		p := entryProblems(t, src)
		if len(p) != 1 || !strings.Contains(p[0], "runEntry:") {
			t.Fatalf("problems = %v, want only runEntry", p)
		}
	})
	t.Run("the fake imported by production code", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/new.go": "package cmd\nimport _ \"github.com/kjelly/pilot/internal/identitylock/identitylocktest\"\n"}
		if p := seamProblems(t, src); len(p) != 1 || !strings.Contains(p[0], "for tests only") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("a seam replaced by production code", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/new.go": "package cmd\nfunc init() { newIdentityLock = nil }\n"}
		if p := seamProblems(t, src); len(p) != 1 || !strings.Contains(p[0], "test seam") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("an options literal without the lock", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/deploy.go": "package cmd\nfunc executeRecordedDeploymentCore() {\n\t_ = executeDeploymentTransaction(deploymentTransactionOptions{Stage: stage})\n}\n"}
		if p := optionsLiteralProblems(t, src); len(p) != 1 || !strings.Contains(p[0], "does not set IdentityLock") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("an access options literal without the lock", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/new.go": "package cmd\nvar o = accessgrants.ReconcileOptions{Inventory: \"i\"}\nvar d = accessgrants.DeactivateOptions{Lock: l}\nvar c = providers.FreeIPAClientProviderConfig{}\n"}
		p := optionLiteralProblems(t, src)
		if len(p) != 1 || !strings.Contains(p[0], "ReconcileOptions literal without Lock") {
			t.Fatalf("problems = %v, want exactly the Reconcile literal (the decommission config carries no lock any more: the run's owner holds it)", p)
		}
	})
	// Part 6's own mechanics, on synthetic sources.
	t.Run("a precheck behind a condition that is not the required one", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/host_decommission.go": "package cmd\nfunc runHostDecommissionApply(plan P) {\n\tif plan.Status != Other {\n\t\tidentityLockFor(ctx)\n\t}\n\tds.RecordApproval()\n\tdecommission.Apply(ctx)\n}\n"}
		funnel := []lockFunnel{{
			File: "cmd/pilot/cmd/host_decommission.go", Func: "runHostDecommissionApply",
			Acquire:  callMatcher{"precheck", "ident:identityLockFor"},
			Execute:  callMatcher{"decommission.Apply", "method:decommission.Apply"},
			Requires: "needsLock",
		}}
		if p := funnelProblems(t, src, funnel); len(p) != 1 || !strings.Contains(p[0], "behind a branch") {
			t.Fatalf("problems = %v, want the branch refusal", p)
		}
		src["cmd/pilot/cmd/host_decommission.go"] = "package cmd\nfunc runHostDecommissionApply(plan P) {\n\tif needsLock {\n\t\tidentityLockFor(ctx)\n\t}\n\tdecommission.Apply(ctx)\n}\n"
		if p := funnelProblems(t, src, funnel); len(p) != 0 {
			t.Fatalf("the allowed condition is reported: %v", p)
		}
	})
	t.Run("the lock taken before the confirmation, or a confirmation that is not recognized", func(t *testing.T) {
		funnel := []lockFunnel{{
			File: "cmd/pilot/cmd/host_decommission.go", Func: "runHostDecommissionApply",
			Acquire:  callMatcher{"the run's lock acquirer", "ident:acquire"},
			Execute:  callMatcher{"decommission.Apply", "method:decommission.Apply"},
			Confirm:  []callMatcher{{"ds.RecordApproval", "sel:RecordApproval"}},
			Requires: "needsLock",
		}}
		const file = "cmd/pilot/cmd/host_decommission.go"
		good := lockSources{file: "package cmd\nfunc runHostDecommissionApply() {\n\tds.RecordApproval()\n\tif needsLock {\n\t\theld, err = acquire(ctx)\n\t}\n\tdecommission.Apply(ctx)\n}\n"}
		if p := funnelProblems(t, good, funnel); len(p) != 0 {
			t.Fatalf("the good order is reported: %v", p)
		}
		early := lockSources{file: "package cmd\nfunc runHostDecommissionApply() {\n\tif needsLock {\n\t\theld, err = acquire(ctx)\n\t}\n\tds.RecordApproval()\n\tdecommission.Apply(ctx)\n}\n"}
		if p := funnelProblems(t, early, funnel); len(p) != 1 || !strings.Contains(p[0], "ds.RecordApproval is called after the lock is taken") {
			t.Fatalf("problems = %v, want the confirmation-order refusal", p)
		}
		// One approval before the lock and a second one after it: the late one counts.
		twice := lockSources{file: "package cmd\nfunc runHostDecommissionApply() {\n\tds.RecordApproval()\n\tif needsLock {\n\t\theld, err = acquire(ctx)\n\t}\n\tds.RecordApproval()\n\tdecommission.Apply(ctx)\n}\n"}
		if p := funnelProblems(t, twice, funnel); len(p) != 1 || !strings.Contains(p[0], "called after the lock is taken") {
			t.Fatalf("problems = %v, want the late approval refused", p)
		}
		none := lockSources{file: "package cmd\nfunc runHostDecommissionApply() {\n\tif needsLock {\n\t\theld, err = acquire(ctx)\n\t}\n\tdecommission.Apply(ctx)\n}\n"}
		if p := funnelProblems(t, none, funnel); len(p) != 1 || !strings.Contains(p[0], "no longer recognizes where the confirmation is made") {
			t.Fatalf("problems = %v, want the unrecognized-confirmation refusal", p)
		}
	})
	t.Run("a nested funnel is checked for order only", func(t *testing.T) {
		funnel := []lockFunnel{{
			File: "cmd/pilot/cmd/edit_tui_roster_breakglass.go", Func: "push", Nested: true,
			Acquire: callMatcher{"tuiIdentityLockFor", "ident:tuiIdentityLockFor"},
			Execute: callMatcher{"accessgrants.Activate", "method:accessgrants.Activate"},
		}}
		good := lockSources{"cmd/pilot/cmd/edit_tui_roster_breakglass.go": "package cmd\nfunc push() {\n\treturn transition(func() {\n\t\tlock, _ := tuiIdentityLockFor(ctx)\n\t\taccessgrants.Activate(ctx, lock)\n\t})\n}\n"}
		if p := funnelProblems(t, good, funnel); len(p) != 0 {
			t.Fatalf("the good nested funnel is reported: %v", p)
		}
		late := lockSources{"cmd/pilot/cmd/edit_tui_roster_breakglass.go": "package cmd\nfunc push() {\n\treturn transition(func() {\n\t\taccessgrants.Activate(ctx)\n\t\ttuiIdentityLockFor(ctx)\n\t})\n}\n"}
		if p := funnelProblems(t, late, funnel); len(p) == 0 || !strings.Contains(p[0], "after accessgrants.Activate") {
			t.Fatalf("problems = %v, want the order refusal", p)
		}
	})
	t.Run("a protected call from a function that is not listed", func(t *testing.T) {
		src := lockSources{
			"cmd/pilot/cmd/access_cli.go": "package cmd\nfunc runAccessReconcileCmd() {\n\taccessgrants.ReconcileOnce(ctx)\n}\nfunc runAccessReconcileOther() {\n\taccessgrants.ReconcileOnce(ctx)\n}\n",
		}
		p := precheckProblems(t, src)
		joined := strings.Join(p, "\n")
		if !strings.Contains(joined, "runAccessReconcileOther: calls accessgrants.ReconcileOnce but is not on the list") {
			t.Fatalf("problems = %v, want the unlisted caller", p)
		}
		if strings.Contains(joined, "runAccessReconcileCmd: calls") {
			t.Fatalf("the listed caller is reported as unlisted: %v", p)
		}
	})
	t.Run("a stale protected-call entry", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/access_cli.go": "package cmd\nfunc runAccessReconcileCmd() {}\n"}
		if p := precheckProblems(t, src); !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, "no longer calls accessgrants.ReconcileOnce") }) {
			t.Fatalf("problems = %v, want the stale entry", p)
		}
	})
	t.Run("a second direct Acquirer builder in a listed file", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/deploy.go": "package cmd\nfunc a() {\n\tnewIdentityLock(r)\n}\nfunc b() {\n\tnewIdentityLock(r)\n}\n"}
		p := precheckProblems(t, src)
		if !slices.ContainsFunc(p, func(s string) bool {
			return strings.Contains(s, "cmd/pilot/cmd/deploy.go: calls newIdentityLock 2 times, the list says 1")
		}) {
			t.Fatalf("problems = %v, want the count refusal", p)
		}
	})
	t.Run("the precheck seam replaced by production code", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/new.go": "package cmd\nfunc init() { identityLockPrecheck = nil }\n"}
		if p := seamProblems(t, src); len(p) != 1 || !strings.Contains(p[0], "test seam") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("no refusal in executeDeploymentTransaction", func(t *testing.T) {
		src := lockSources{"cmd/pilot/cmd/deploy.go": "package cmd\nfunc executeDeploymentTransaction() error {\n\treturn nil\n}\n"}
		if p := refusalProblems(t, src); len(p) != 1 || !strings.Contains(p[0], "no `if ... options.IdentityLock == nil") {
			t.Fatalf("problems = %v", p)
		}
	})
}

// Mutations of the real sources: take the lock out of each funnel the way a
// careless edit would, and the lint has to say so (the PR record repeats this
// on a clean archive copy of the commit and adds the interleaving test).
func TestIdentityLockLintFailsOnMutationsOfTheRealFunnels(t *testing.T) {
	real := readLockSources(t)
	mutate := func(t *testing.T, file, old, repl string) lockSources {
		t.Helper()
		src, ok := real[file]
		if !ok || strings.Count(src, old) != 1 {
			t.Fatalf("the anchor %q is not exactly once in %s (found %d)", old, file, strings.Count(src, old))
		}
		out := lockSources{}
		for k, v := range real {
			out[k] = v
		}
		out[file] = strings.Replace(src, old, repl, 1)
		return out
	}
	for name, tc := range map[string]struct {
		file, old, repl, want string
	}{
		"applyPlan without the lock": {
			"internal/accessgrants/reconcile.go", "held, err := lock(ctx)", "held, err := noLock(ctx)",
			"without taking the lock",
		},
		"the converge step without the lock": {
			"internal/decommission/providers/freeipa_client.go", "held, err := identitylock.Require(ctx)", "held, err := identitylock.Skip(ctx)",
			"without taking the lock",
		},
		// E41: the decommission's lock is the run's, taken after the approval and
		// before decommission.Apply.
		"the decommission run takes no lock": {
			"cmd/pilot/cmd/host_decommission.go", "held, err = acquire(ctx)", "held, err = nil, nil",
			"runHostDecommissionApply: runs the playbook (decommission.Apply) without taking the lock: no call of the run's lock acquirer",
		},
		"the decommission run takes the lock before the approval": {
			"cmd/pilot/cmd/host_decommission.go", "acquire, err = identityLockFor(ctx, lockRequest)\n", "acquire, err = identityLockFor(ctx, lockRequest)\n\t\theld, err = acquire(ctx)\n",
			"ds.RecordApproval is called after the lock is taken",
		},
		"the decommission run takes the lock only for some plans": {
			"cmd/pilot/cmd/host_decommission.go", "\t\theld, err = acquire(ctx)\n\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"host decommission %s was not started", "\t\tif plan.Host.Name != \"\" {\n\t\t\theld, err = acquire(ctx)\n\t\t}\n\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"host decommission %s was not started",
			"the lock is taken behind a branch that can skip it",
		},
		"the deploy apply step without the lock": {
			"cmd/pilot/cmd/deploy.go", "acquired, err := options.IdentityLock(ctx)", "acquired, err := options.NoLock(ctx)",
			"without taking the lock",
		},
		"the deploy apply step runs before the lock": {
			"cmd/pilot/cmd/deploy.go", "\t\tif identity {\n\t\t\t// After every prompt", "\t\t_, _ = execute(ctx, false, args)\n\t\tif identity {\n\t\t\t// After every prompt",
			"after execute",
		},
		"Core does not hand the deploy funnel a lock": {
			"cmd/pilot/cmd/deploy.go", "\t\tIdentityLock:            identityLock,\n", "",
			"does not set IdentityLock",
		},
		"the refusal of a missing lock removed": {
			"cmd/pilot/cmd/deploy.go", "if identity && options.IdentityLock == nil {", "if identity && options.Authorization == nil {",
			"no `if ... options.IdentityLock == nil",
		},
		"the access command builds its options without the lock": {
			"cmd/pilot/cmd/access_cli.go", "\t\tLock:       lock,\n", "",
			"ReconcileOptions literal without Lock",
		},
		"the TUI builds its options without the lock": {
			"cmd/pilot/cmd/edit_tui_roster_breakglass.go", "\t\t\tLock:        lock,\n", "",
			"ActivateOptions literal without Lock",
		},
		// The Go writer (P2-6): its lock is the run's, taken after the precheck and before the
		// first connection, and everything that writes or runs the entry takes the Held.
		"the Go apply takes no lock": {
			"cmd/pilot/cmd/reconcile_golang_apply.go", "held, err := acquire(sigCtx)", "held, err := noLock(sigCtx)",
			"golangApply: runs the playbook (runGolangApplyUnderLock) without taking the lock: no call of the run's lock acquirer",
		},
		"the Go apply runs before it takes the lock": {
			"cmd/pilot/cmd/reconcile_golang_apply.go", "\theld, err := acquire(sigCtx)\n", "\t_, _ = runGolangApplyUnderLock(sigCtx, nil, prep, nil, cmd, runtime, timeout)\n\theld, err := acquire(sigCtx)\n",
			"takes the lock (the run's lock acquirer) after runGolangApplyUnderLock",
		},
		"the Go apply takes the lock only for some hosts": {
			"cmd/pilot/cmd/reconcile_golang_apply.go", "\theld, err := acquire(sigCtx)\n", "\tvar held *identitylock.Held\n\tif prep.host != \"\" {\n\t\theld, err = acquire(sigCtx)\n\t}\n",
			"golangApply: the lock is taken behind a branch that can skip it",
		},
		"the Go apply without the precheck": {
			"cmd/pilot/cmd/reconcile_golang_apply.go", "acquire, err := identityLockFor(sigCtx, identityLockRequest{", "acquire, err := wrapLock(sigCtx, identityLockRequest{",
			"golangApply: runs the playbook (newGolangDialer) without taking the lock: no call of identityLockFor",
		},
		"the Go apply makes its dialer before the precheck": {
			"cmd/pilot/cmd/reconcile_golang_apply.go", "\tacquire, err := identityLockFor(", "\t_ = newGolangDialer(prep.target)\n\tacquire, err := identityLockFor(",
			"takes the lock (identityLockFor) after newGolangDialer",
		},
		"the entry runner takes no Held": {
			"cmd/pilot/cmd/reconcile_golang_apply.go", "func runGoAuthCacheEntry(ctx context.Context, held *identitylock.Held, root string,", "func runGoAuthCacheEntry(ctx context.Context, root string,",
			"runGoAuthCacheEntry: runs the auth-cache entry playbook without taking a *identitylock.Held",
		},
		"the writer's caller takes no Held": {
			"cmd/pilot/cmd/reconcile_golang_apply.go", "func runGolangApplyUnderLock(ctx context.Context, held *identitylock.Held, prep", "func runGolangApplyUnderLock(ctx context.Context, prep",
			"runGolangApplyUnderLock: calls the Go writer (identityreconcile.Execute) without taking a *identitylock.Held",
		},
		"a new caller of the Go writer": {
			"cmd/pilot/cmd/access_cli.go", "var accessReconcileEffects", "func sneakyWrite(ctx context.Context, c *freeiparpc.Client) {\n\t_, _ = identityreconcile.Execute(ctx, c, identityreconcile.Options{})\n}\n\nvar accessReconcileEffects",
			"sneakyWrite: calls identityreconcile.Execute but is not on the list of entry points",
		},
		"the mixed run's Go phase takes no Held": {
			"cmd/pilot/cmd/reconcile_golang_mixed.go", "func runMixedGoPhase(ctx context.Context, held *identitylock.Held, s *mixedStep) error {", "func runMixedGoPhase(ctx context.Context, s *mixedStep) error {",
			"runMixedGoPhase: calls the Go writer (identityreconcile.Execute) without taking a *identitylock.Held",
		},
		"a new caller of the mixed run's Go phase": {
			"cmd/pilot/cmd/access_cli.go", "var accessReconcileEffects", "func sneakyMixed() {\n\t_ = runMixedGoPhase(ctx, held, step)\n}\n\nvar accessReconcileEffects",
			"sneakyMixed: calls runMixedGoPhase but is not on the list of entry points",
		},
		"a second caller of the Go writer inside the mixed file": {
			"cmd/pilot/cmd/reconcile_golang_mixed.go", "func (s *mixedStep) PrepareApply(ctx context.Context) error {", "func (s *mixedStep) sneakyWriter(ctx context.Context, c *freeiparpc.Client) {\n\t_, _ = identityreconcile.Execute(ctx, c, identityreconcile.Options{})\n}\n\nfunc (s *mixedStep) PrepareApply(ctx context.Context) error {",
			"sneakyWriter: calls identityreconcile.Execute but is not on the list of entry points",
		},
		"a new caller of the Go apply under the lock": {
			"cmd/pilot/cmd/access_cli.go", "var accessReconcileEffects", "func sneakyApply() {\n\t_, _ = runGolangApplyUnderLock(ctx, held, prep, d, cmd, rt, t)\n}\n\nvar accessReconcileEffects",
			"sneakyApply: calls runGolangApplyUnderLock but is not on the list of entry points",
		},
		"a new unlisted literal": {
			"cmd/pilot/cmd/access_cli.go", "var accessReconcileEffects", "var sneakyPlaybook = \"playbooks/apply/freeipa-identity-apply.yml\"\n\nvar accessReconcileEffects",
			"not on the funnel list",
		},
		// Part 6: the precheck every funnel runs first. Each case takes it out of
		// one entry point, or puts it where it no longer comes first.
		"identityLockFor without the precheck": {
			"cmd/pilot/cmd/identity_lock.go", "err := checkIdentityLockTarget(ctx, req)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\treturn newIdentityLock(req), nil", "return newIdentityLock(req), nil",
			"no call of checkIdentityLockTarget",
		},
		"access reconcile without the precheck": {
			"cmd/pilot/cmd/access_cli.go", "lock, err := identityLockFor(cmd.Context(), identityLockRequest{Inventory: accessReconcileInventory,", "lock, err := wrapLock(cmd.Context(), identityLockRequest{Inventory: accessReconcileInventory,",
			"runAccessReconcileCmd: runs the playbook (accessgrants.ReconcileOnce) without taking the lock: no call of identityLockFor",
		},
		"breakglass activate without the precheck": {
			"cmd/pilot/cmd/access_breakglass_cli.go", "lock, err := identityLockFor(cmd.Context(), identityLockRequest{Inventory: accessBreakglassActivateInventory,", "lock, err := wrapLock(cmd.Context(), identityLockRequest{Inventory: accessBreakglassActivateInventory,",
			"runAccessBreakglassActivateCmd: runs the playbook (accessgrants.Activate) without taking the lock: no call of identityLockFor",
		},
		"breakglass deactivate without the precheck": {
			"cmd/pilot/cmd/access_breakglass_cli.go", "lock, err := identityLockFor(cmd.Context(), identityLockRequest{Inventory: accessBreakglassDeactivateInventory,", "lock, err := wrapLock(cmd.Context(), identityLockRequest{Inventory: accessBreakglassDeactivateInventory,",
			"runAccessBreakglassDeactivateCmd: runs the playbook (accessgrants.Deactivate) without taking the lock: no call of identityLockFor",
		},
		"access drift repair without the precheck": {
			"cmd/pilot/cmd/access_drift_cli.go", "lock, err := identityLockFor(cmd.Context(), identityLockRequest{Inventory: accessDriftInventory,", "lock, err := wrapLock(cmd.Context(), identityLockRequest{Inventory: accessDriftInventory,",
			"runAccessDriftCmd: runs the playbook (accessgrants.RepairManaged) without taking the lock: no call of identityLockFor",
		},
		"identity drift repair without the precheck": {
			"cmd/pilot/cmd/identity_drift_cli.go", "lock, err := identityLockFor(cmd.Context(), identityLockRequest{Inventory: identityDriftInventory,", "lock, err := wrapLock(cmd.Context(), identityLockRequest{Inventory: identityDriftInventory,",
			"runIdentityDriftCmd: runs the playbook (accessgrants.RepairManaged) without taking the lock: no call of identityLockFor",
		},
		"the TUI activation without the precheck": {
			"cmd/pilot/cmd/edit_tui_roster_breakglass.go", "// cannot give the lock (see checkIdentityLockTarget).\n\t\tlock, err := tuiIdentityLockFor(", "// cannot give the lock (see checkIdentityLockTarget).\n\t\tlock, err := wrapLock(",
			"pushBreakglassActivateTicket: runs the playbook (accessgrants.Activate) without taking the lock: no call of tuiIdentityLockFor",
		},
		"the decommission apply without the precheck": {
			"cmd/pilot/cmd/host_decommission.go", "acquire, err = identityLockFor(ctx, lockRequest)", "acquire, err = wrapLock(ctx, lockRequest)",
			"runHostDecommissionApply: runs the playbook (decommission.Apply) without taking the lock: no call of identityLockFor",
		},
		"the decommission precheck after the approval": {
			"cmd/pilot/cmd/host_decommission.go",
			"\t\tacquire, err = identityLockFor(ctx, lockRequest)\n\t\tif err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t}\n\tif plan.Status != decommission.PlanStatusCompleted {\n\t\tif err := ds.RecordApproval(plan.ID, plan.PlanHash, decommissionActor(), \"approve\", reason, now); err != nil {\n\t\t\treturn nil, fmt.Errorf(\"record approval: %w\", err)\n\t\t}\n\t\tif err := decommission.RequireApproval(ds, plan.ID, plan.PlanHash, plan.Environment); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t}\n",
			"\t\tacquire, err = wrapLock(ctx, lockRequest)\n\t\tif err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t}\n\tif plan.Status != decommission.PlanStatusCompleted {\n\t\tif err := ds.RecordApproval(plan.ID, plan.PlanHash, decommissionActor(), \"approve\", reason, now); err != nil {\n\t\t\treturn nil, fmt.Errorf(\"record approval: %w\", err)\n\t\t}\n\t\tif err := decommission.RequireApproval(ds, plan.ID, plan.PlanHash, plan.Environment); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t}\n\tif needsLock {\n\t\tacquire, err = identityLockFor(ctx, lockRequest)\n\t}\n",
			"ds.RecordApproval is called before the lock is taken",
		},
		"a new direct Acquirer builder in the decommission file": {
			"cmd/pilot/cmd/host_decommission.go", "func planHasIdentityConverge(", "func sneakyDecommissionLock() {\n\t_ = newIdentityLock(identityLockRequest{})\n}\n\nfunc planHasIdentityConverge(",
			"cmd/pilot/cmd/host_decommission.go: calls newIdentityLock directly",
		},
		"the deploy precheck removed": {
			"cmd/pilot/cmd/deploy.go", "err = precheckIdentityDeploy(ctx, catalog, components, playbook, inv, limit, extraVars, vault)", "err = nil",
			"executeRecordedDeploymentWithAuthorizationResult: runs the playbook (applyDeploymentDependencyChain) without taking the lock: no call of precheckIdentityDeploy",
		},
		"the deploy precheck behind a branch": {
			"cmd/pilot/cmd/deploy.go", "err = precheckIdentityDeploy(ctx, catalog, components, playbook, inv, limit, extraVars, vault)", "if len(components) > 1 {\n\t\terr = precheckIdentityDeploy(ctx, catalog, components, playbook, inv, limit, extraVars, vault)\n\t}",
			"the lock is taken behind a branch that can skip it",
		},
		"the batch precheck removed": {
			"cmd/pilot/cmd/deploy.go", "err := precheckIdentityBatch(ctx, requests)", "var err error",
			"executeCatalogBatch: runs the playbook (promptReconcileExecutionAuthorization) without taking the lock: no call of precheckIdentityBatch",
		},
		"a new entry point that runs a funnel": {
			"cmd/pilot/cmd/access_cli.go", "var accessReconcileEffects", "func sneakyReconcile(ctx context.Context, o accessgrants.ReconcileOptions) {\n\t_, _, _ = accessgrants.ReconcileOnce(ctx, o)\n}\n\nvar accessReconcileEffects",
			"sneakyReconcile: calls accessgrants.ReconcileOnce but is not on the list of entry points",
		},
		"a new caller of the deploy core": {
			"cmd/pilot/cmd/access_cli.go", "var accessReconcileEffects", "func sneakyCore() {\n\t_ = executeRecordedDeploymentCore()\n}\n\nvar accessReconcileEffects",
			"sneakyCore: calls executeRecordedDeploymentCore but is not on the list of entry points",
		},
		"a new Acquirer built without the precheck": {
			"cmd/pilot/cmd/access_cli.go", "var accessReconcileEffects", "func sneakyLock() {\n\t_ = newIdentityLock(identityLockRequest{})\n}\n\nvar accessReconcileEffects",
			"cmd/pilot/cmd/access_cli.go: calls newIdentityLock directly",
		},
		"the precheck seam replaced by production code": {
			"cmd/pilot/cmd/access_cli.go", "var accessReconcileEffects", "func init() { identityLockPrecheck = nil }\n\nvar accessReconcileEffects",
			"a test seam",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := allIdentityLockProblems(t, mutate(t, tc.file, tc.old, tc.repl))
			if len(p) == 0 {
				t.Fatal("the lint reported nothing for the mutated source")
			}
			if !strings.Contains(strings.Join(p, "\n"), tc.want) {
				t.Fatalf("problems = %v, want one containing %q", p, tc.want)
			}
		})
	}
	// The unmodified tree is clean, so the failures above are the mutations'.
	if p := allIdentityLockProblems(t, real); len(p) != 0 {
		t.Fatalf("the real tree is not clean: %v", p)
	}
}

func TestIdentityContractProblemsFireOnTheirCases(t *testing.T) {
	root := repoRootForTest(t)
	loader, err := contract.NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if p := identityContractProblems(catalog); len(p) != 0 {
		t.Fatalf("the real catalog is not clean: %v", p)
	}
	// Each guard on a copy of the real contract with that one thing changed.
	mutated := func(edit func(c *contract.Contract)) contract.Catalog {
		return mutatedComponent(t, catalog, "freeipa-identity", edit)
	}
	t.Run("a dependency on freeipa-identity", func(t *testing.T) {
		p := identityContractProblems(mutatedComponent(t, catalog, "freeipa-dns", func(c *contract.Contract) {
			c.Dependencies = append(c.Dependencies, contract.Dependency{Component: "freeipa-identity", Required: true, Relation: "sameHosts"})
		}))
		if !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, "freeipa-dns depends on freeipa-identity") }) {
			t.Fatalf("problems = %v", p)
		}
	})
	str := func(s string) *string { return &s }
	for name, tc := range map[string]struct {
		edit func(c *contract.Contract)
		want string
	}{
		"site.yml": {func(c *contract.Contract) { c.Site.Include = true }, "part of site.yml"},
		"a canonical_apply remediation": {func(c *contract.Contract) {
			c.Remediation.Actions = append(c.Remediation.Actions, contract.RemediationAction{ID: "reapply", Executor: contract.RemediationActionExecutor{Kind: "canonical_apply"}})
		}, "canonical_apply"},
		"a rollback playbook":    {func(c *contract.Contract) { c.Playbooks.Rollback = str("playbooks/apply/x.yml") }, "rollback playbook"},
		"an upgrade playbook":    {func(c *contract.Contract) { c.Playbooks.Upgrade = str("playbooks/apply/x.yml") }, "upgrade playbook"},
		"another apply playbook": {func(c *contract.Contract) { c.Playbooks.Apply = "playbooks/apply/other.yml" }, "not the one the funnels are keyed on"},
	} {
		t.Run(name, func(t *testing.T) {
			p := identityContractProblems(mutated(tc.edit))
			if len(p) == 0 || !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, tc.want) }) {
				t.Fatalf("problems = %v, want one containing %q", p, tc.want)
			}
		})
	}
}

// mutatedComponent is catalog with one component edited. It does not skip: a
// catalog the edit makes invalid would make the case prove nothing.
func mutatedComponent(t *testing.T, catalog contract.Catalog, id string, edit func(c *contract.Contract)) contract.Catalog {
	t.Helper()
	var cs []contract.Contract
	found := false
	for _, c := range catalog.Components() {
		if c.ID == id {
			edit(&c)
			found = true
		}
		cs = append(cs, c)
	}
	if !found {
		t.Fatalf("component %s is not in the catalog", id)
	}
	out, err := contract.NewCatalog(cs)
	if err != nil {
		t.Fatalf("an edited catalog is not valid: %v", err)
	}
	return out
}
