package cmd

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The funnels hand the identity lock the -e and vault arguments their playbook
// run gets (identityLockRequest.ExtraArgs), because the lock derives its target
// from them (issue #319). These tests are about the hand-over: a funnel that
// stopped passing them would put the lock back on the inventory alone with every
// derivation test still green.

const deployIdentityPlaybook = "playbooks/apply/freeipa-identity-apply.yml"

// pilot deploy and pilot reconcile: the vault file is how `-e @.vault/main.yaml`
// reaches the playbook, and it is where a connection variable is most likely to
// hide from a reader of the inventory.
func TestDeployPrecheckReadsTheVaultFileThePlaybookWillGet(t *testing.T) {
	env := newFunnelEnv(t, "")
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	catalog := loadRepoCatalogForPrecheck(t)
	identity := []string{"freeipa-identity"}
	precheck := func(extraVars []string, vault vaultInput) error {
		return precheckIdentityDeploy(context.Background(), catalog, identity, deployIdentityPlaybook, env.inv, "", extraVars, vault)
	}

	t.Run("a connection variable in the vault file is refused like one in the inventory", func(t *testing.T) {
		vault := vaultInput{ExtraVarsFile: writeVarsFile(t, "ansible_ssh_extra_args: \"-o ProxyCommand='nc %h %p'\"\nipa_admin_password: sentinel-not-a-credential\n")}
		err := precheck(nil, vault)
		if err == nil {
			t.Fatal("a ProxyCommand in the vault file was not seen")
		}
		for _, want := range []string{"取鎖前檢查沒有通過", "ipa-1", "ProxyCommand"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want it to hold %q", err, want)
			}
		}
		if strings.Contains(err.Error(), "sentinel-not-a-credential") {
			t.Fatalf("the refusal shows a secret: %v", err)
		}
		// The twin: the same vault file without the connection variable passes,
		// so it is the variable and not the file that is refused.
		if err := precheck(nil, vaultInput{ExtraVarsFile: writeVarsFile(t, "ipa_admin_password: sentinel-not-a-credential\n")}); err != nil {
			t.Fatalf("a vault file with only a secret was refused: %v", err)
		}
	})

	t.Run("target_group in the vault file, which the scope does not see", func(t *testing.T) {
		if err := os.WriteFile(env.inv, []byte(effectiveInventory), 0o600); err != nil {
			t.Fatal(err)
		}
		// The scope is resolved from extraVars alone (resolveDeploymentScope), so
		// it picks the freeipa-server host; the vault file sends the playbook to
		// the `other` group.
		err := precheck(nil, vaultInput{ExtraVarsFile: writeVarsFile(t, "target_group: other\n")})
		if err == nil || !strings.Contains(err.Error(), "鎖與 playbook 的目標會不同台") {
			t.Fatalf("err = %v, want the refusal that the lock and the playbook are on different hosts", err)
		}
		// The twin, and what the scope already guarded: the same group given as
		// `-e target_group=other` is where resolveDeploymentScope reads it, and
		// its own contract check (same-host dependency on freeipa-server) refuses
		// the `other` hosts. Only the vault-file form got past it to the lock.
		err = precheck([]string{"target_group=other"}, vaultInput{})
		if err == nil || !strings.Contains(err.Error(), "excludes selected host") {
			t.Fatalf("target_group=other as an extra var: err = %v, want the scope's own refusal", err)
		}
		if err := precheck(nil, vaultInput{}); err != nil {
			t.Fatalf("no target_group: %v", err)
		}
	})
}

// The request the precheck makes carries what the playbook is handed, in the
// order ansibleExtraVarArgs gives it: it is that function the apply step's
// baseArgs call, so the lock and the playbook cannot read different arguments.
func TestDeployPrecheckHandsTheLockWhatThePlaybookGets(t *testing.T) {
	fake := useFakeIdentityLock(t)
	env := newFunnelEnv(t, "")
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	catalog := loadRepoCatalogForPrecheck(t)
	extraVars := []string{"stage=sandbox", "target_group=freeipa-server"}
	vault := vaultInput{ExtraVarsFile: "/work/.vault/main.yaml", VaultPasswordFile: "/work/.vault/pw", AskBecomePass: true}
	if err := precheckIdentityDeploy(context.Background(), catalog, []string{"freeipa-identity"}, deployIdentityPlaybook, env.inv, "", extraVars, vault); err != nil {
		t.Fatal(err)
	}
	prechecks := fake.Prechecks()
	if len(prechecks) != 1 {
		t.Fatalf("%d prechecks", len(prechecks))
	}
	want := ansibleExtraVarArgs(extraVars, vault)
	if !reflect.DeepEqual(prechecks[0].ExtraArgs, want) {
		t.Fatalf("ExtraArgs = %q, want what the playbook gets: %q", prechecks[0].ExtraArgs, want)
	}
	// --ask-become-pass is for ansible-playbook only: ansible-inventory takes
	// none, and it is not a connection variable.
	for _, arg := range prechecks[0].ExtraArgs {
		if arg == "--ask-become-pass" {
			t.Fatalf("ExtraArgs hold --ask-become-pass, which ansible-inventory does not accept: %q", prechecks[0].ExtraArgs)
		}
	}
}

// pilot host decommission: the converge step runs the identity playbook with the
// workspace's main vault, so the lock reads the inventory through the same file.
func TestHostDecommissionLockRequestCarriesTheWorkspaceVault(t *testing.T) {
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	oldData := dataDir
	dataDir = ""
	t.Cleanup(func() { dataDir = oldData })

	inv := writeLockInventory(t, "")
	dir := filepath.Dir(inv)
	req, err := hostDecommissionLockRequest(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.ExtraArgs) != 0 {
		t.Fatalf("a workspace without a vault file: ExtraArgs = %q", req.ExtraArgs)
	}
	if err := checkIdentityLockTarget(context.Background(), req); err != nil {
		t.Fatalf("a supported inventory was refused: %v", err)
	}

	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(vaultDir, "main.yaml")
	if err := os.WriteFile(vault, []byte("ansible_ssh_extra_args: \"-o ProxyCommand='nc %h %p'\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req, err = hostDecommissionLockRequest(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := hostDecommissionVaultArgs(inv); !reflect.DeepEqual(req.ExtraArgs, want) || len(want) != 2 {
		t.Fatalf("ExtraArgs = %q, want the workspace vault arguments %q", req.ExtraArgs, want)
	}
	err = checkIdentityLockTarget(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "ProxyCommand") {
		t.Fatalf("a ProxyCommand in the workspace vault was not refused: %v", err)
	}
}

// identityLockRequestsWithoutExtraArgs are the funnels that build an
// identityLockRequest with no ExtraArgs, and why that is the whole truth: the
// only -e arguments their playbook gets are values pilot makes itself.
var identityLockRequestsWithoutExtraArgs = map[string]string{
	"access_cli.go":             "pilot access reconcile: accessgrants.applyPlan passes -e @<pilot-made JSON> and the vault password file only (TestExtraVarsCarryNoConnectionSetting)",
	"access_drift_cli.go":       "pilot access drift --repair-managed: the same applyPlan",
	"access_breakglass_cli.go":  "pilot access breakglass activate/deactivate: the same applyPlan",
	"identity_drift_cli.go":     "pilot identity drift --repair-managed: the same applyPlan",
	"identity_lock.go":          "tuiIdentityLockFor, the TUI's break-glass: the same applyPlan",
	"reconcile_golang_apply.go": "the entry playbook's -e are the stage variables and the extra-vars JSON pilot makes, limited to the host whose lock it holds (runGoAuthCacheEntry)",
}

// saysWhatThePlaybookIsHanded reports whether the value of an ExtraArgs key is an
// expression and not a way of writing "nothing": `nil`, `[]string(nil)` and an
// empty `[]string{}` all hand the lock no argument, which is the funnel that
// forgot the field spelled out.
func saysWhatThePlaybookIsHanded(value ast.Expr) bool {
	switch v := value.(type) {
	case *ast.Ident:
		return v.Name != "nil"
	case *ast.CompositeLit:
		return len(v.Elts) > 0
	case *ast.CallExpr:
		// A conversion of nil: []string(nil).
		if _, isType := v.Fun.(*ast.ArrayType); isType && len(v.Args) == 1 {
			return saysWhatThePlaybookIsHanded(v.Args[0])
		}
	case *ast.ParenExpr:
		return saysWhatThePlaybookIsHanded(v.X)
	}
	return true
}

// identityLockExtraArgsProblems reads the identityLockRequest literals of the
// sources (file name to text) and reports each one that does not say what its
// playbook is handed and whose file is not in allowedWithout, the file names of
// the funnels allowed to hand none; and each allowedWithout entry that no
// longer builds such a request. It also returns how many literals it looked at.
func identityLockExtraArgsProblems(t *testing.T, sources map[string]string, allowedWithout map[string]string) (problems []string, literals int) {
	t.Helper()
	fset := token.NewFileSet()
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	seenWithout := map[string]bool{}
	for _, name := range names {
		parsed, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if ident, ok := lit.Type.(*ast.Ident); !ok || ident.Name != "identityLockRequest" {
				return true
			}
			// A zero literal is a return value on an error path, not a request.
			if len(lit.Elts) == 0 {
				return true
			}
			literals++
			hasExtraArgs := false
			for _, elt := range lit.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "ExtraArgs" && saysWhatThePlaybookIsHanded(kv.Value) {
						hasExtraArgs = true
					}
				}
			}
			if hasExtraArgs {
				return true
			}
			if _, listed := allowedWithout[name]; !listed {
				problems = append(problems, fmt.Sprintf("%s: an identityLockRequest without ExtraArgs (absent, nil or empty): say which -e and vault arguments the playbook is handed, or list the funnel in identityLockRequestsWithoutExtraArgs with the reason it is handed none", fset.Position(lit.Pos())))
			}
			seenWithout[name] = true
			return true
		})
	}
	var stale []string
	for file := range allowedWithout {
		if !seenWithout[file] {
			stale = append(stale, file)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		problems = append(problems, fmt.Sprintf("identityLockRequestsWithoutExtraArgs lists %v, which no longer build a request without ExtraArgs: remove the entries", stale))
	}
	return problems, literals
}

// Every identityLockRequest a funnel builds says what its playbook is handed, or
// is on the list above with the reason it hands nothing. A new funnel that
// forgot the field would lock the inventory's host while its playbook is
// retargeted by an extra var (AGENTS.md §5.10: a class that can come back in new
// code gets a repo-wide check). Writing the field as nil or as an empty list is
// forgetting it, so neither counts: the lock-time request of the deploy runner
// was once exactly `ExtraArgs: nil` away from reading the inventory alone, and
// nothing noticed.
func TestRegression_IdentityLockRequestsCarryTheirExtraArgs(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sources[file] = string(data)
	}
	problems, literals := identityLockExtraArgsProblems(t, sources, identityLockRequestsWithoutExtraArgs)
	if literals == 0 {
		t.Fatal("found no identityLockRequest literal: the check looks at nothing")
	}
	for _, problem := range problems {
		t.Error(problem)
	}
}

// The check would be vacuous if it could not fail: each way of leaving the lock
// on the inventory alone is a hole it reports, and a real expression, or a funnel
// on the list, is not.
func TestIdentityLockRequestsLintFailsOnSyntheticHoles(t *testing.T) {
	const prefix = "package cmd\nfunc f() {\n\t_ = "
	const suffix = "\n}\n"
	run := func(literal string, allowed map[string]string) []string {
		problems, literals := identityLockExtraArgsProblems(t, map[string]string{"deploy.go": prefix + literal + suffix}, allowed)
		if literals != 1 {
			t.Fatalf("looked at %d literals in %q, want 1", literals, literal)
		}
		return problems
	}
	for name, literal := range map[string]string{
		"ExtraArgs is a call":              "identityLockRequest{Inventory: inv, ExtraArgs: ansibleExtraVarArgs(extraVars, vault)}",
		"ExtraArgs is a helper's result":   "identityLockRequest{Inventory: inv, ExtraArgs: hostDecommissionVaultArgs(inv)}",
		"ExtraArgs is a list of arguments": "identityLockRequest{Inventory: inv, ExtraArgs: []string{\"-e\", \"x=1\"}}",
		"ExtraArgs is a variable":          "identityLockRequest{Inventory: inv, ExtraArgs: args}",
	} {
		t.Run("a real expression passes/"+name, func(t *testing.T) {
			if problems := run(literal, nil); len(problems) != 0 {
				t.Fatalf("problems = %v", problems)
			}
		})
	}
	for name, literal := range map[string]string{
		"the field is absent":        "identityLockRequest{Inventory: inv, Hosts: hosts}",
		"ExtraArgs: nil":             "identityLockRequest{Inventory: inv, ExtraArgs: nil}",
		"ExtraArgs: []string{}":      "identityLockRequest{Inventory: inv, ExtraArgs: []string{}}",
		"ExtraArgs: []string(nil)":   "identityLockRequest{Inventory: inv, ExtraArgs: []string(nil)}",
		"ExtraArgs: ([]string)(nil)": "identityLockRequest{Inventory: inv, ExtraArgs: ([]string(nil))}",
	} {
		t.Run("a hole is reported/"+name, func(t *testing.T) {
			problems := run(literal, nil)
			if len(problems) != 1 || !strings.Contains(problems[0], "without ExtraArgs") {
				t.Fatalf("problems = %v, want the missing ExtraArgs reported", problems)
			}
		})
	}
	t.Run("a funnel on the list may hand none", func(t *testing.T) {
		for _, literal := range []string{"identityLockRequest{Inventory: inv}", "identityLockRequest{Inventory: inv, ExtraArgs: nil}"} {
			if problems := run(literal, map[string]string{"deploy.go": "handed none, for a reason"}); len(problems) != 0 {
				t.Fatalf("%s: problems = %v", literal, problems)
			}
		}
	})
	t.Run("a listed funnel that now hands something is stale", func(t *testing.T) {
		problems := run("identityLockRequest{Inventory: inv, ExtraArgs: args}", map[string]string{"deploy.go": "handed none"})
		if len(problems) != 1 || !strings.Contains(problems[0], "remove the entries") {
			t.Fatalf("problems = %v", problems)
		}
	})
	t.Run("a zero literal is not a request", func(t *testing.T) {
		problems, literals := identityLockExtraArgsProblems(t, map[string]string{"deploy.go": prefix + "identityLockRequest{}" + suffix}, nil)
		if literals != 0 || len(problems) != 0 {
			t.Fatalf("looked at %d literals, problems = %v", literals, problems)
		}
	})
}
