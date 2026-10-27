package cmd

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// dirContents is every file under dir, lock files and temp files included,
// keyed by its path relative to dir.
func dirContents(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		out[rel] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// assertDirUnchanged fails unless dir holds exactly the files before did,
// byte for byte: no file changed, and none — a lock file, a temp file, a
// new roster — appeared.
func assertDirUnchanged(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := dirContents(t, dir)
	for rel, data := range after {
		if old, ok := before[rel]; !ok {
			t.Errorf("%s appeared in %s", rel, dir)
		} else if !bytes.Equal(old, data) {
			t.Errorf("%s changed in %s:\n%s", rel, dir, data)
		}
	}
	for rel := range before {
		if _, ok := after[rel]; !ok {
			t.Errorf("%s disappeared from %s", rel, dir)
		}
	}
}

func enableNFSScenario() editScenario {
	return editScenario{Version: 1, Steps: []editAction{
		{Action: "enable_role", Host: "nexus", Role: "freeipa-nfs-server"},
		{Action: "save_hosts"},
	}}
}

// nfsScopeWorkspace is a workspace with one host, nexus, whose
// freeipa_roster_file is ref ("" for none), and a vault password the NFS
// bootstrap reuses.
func nfsScopeWorkspace(t *testing.T, ref string) string {
	t.Helper()
	return nfsScopeWorkspaceAt(t, t.TempDir(), ref)
}

// A plan that enables freeipa-nfs-server writes the roster in its scratch
// copy, never the real one, even though hosts.yml names the real roster by
// its absolute path; and the hosts.yml it previews records the real path,
// as the apply does, not the scratch copy's (PR #148 round 4, R3 and N2).
func TestEditPlanEnablingNFSLeavesRealRostersAlone(t *testing.T) {
	for name, tc := range map[string]struct {
		existing, referenced bool
	}{
		"existing roster referenced by its absolute path": {existing: true, referenced: true},
		"new roster referenced by its absolute path":      {referenced: true},
		"new roster, no reference yet":                    {},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
			ref := ""
			if tc.referenced {
				ref = roster
			}
			dir = nfsScopeWorkspaceAt(t, dir, ref)
			if tc.existing {
				writeSyncFile(t, roster, syncTestRoster(`"Admin-pass_1"`))
			}
			before := dirContents(t, dir)

			result, err := planEditScenario(dir, enableNFSScenario(), editAgentSessionOptions{})
			if err != nil {
				t.Fatalf("planEditScenario() error = %v", err)
			}
			assertDirUnchanged(t, dir, before)
			recorded := 0
			for _, line := range strings.Split(result.Diff, "\n") {
				if strings.HasPrefix(line, "+") && strings.Contains(line, "freeipa_roster_file:") {
					recorded++
					if !strings.Contains(line, roster) || strings.Contains(line, "pilot-edit-plan-") {
						t.Errorf("plan's hosts.yml records %q, want the real roster path %s", line, roster)
					}
				}
			}
			if !tc.referenced && recorded != 1 {
				t.Errorf("plan's hosts.yml records freeipa_roster_file %d times, want once:\n%s", recorded, result.Diff)
			}
			if !slices.Contains(result.AffectedFiles, ".vault/ipa-identity.yaml") {
				t.Errorf("plan does not preview the roster write: %v", result.AffectedFiles)
			}
		})
	}
}

// nfsScopeWorkspaceAt is nfsScopeWorkspace in dir.
func nfsScopeWorkspaceAt(t *testing.T, dir, ref string) string {
	t.Helper()
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Admin-pass_1\"\n")
	host := "hosts:\n  nexus:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n"
	if ref != "" {
		host += "    freeipa_roster_file: " + ref + "\n"
	}
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), host)
	return dir
}

// A roster outside the session's .vault/ files is neither in a plan's copy
// nor in an apply's rollback set: a plan would change the real file and a
// rolled-back apply would leave it changed. Both refuse the write, naming
// the roster, and leave its directory exactly as it was — no lock files
// either (PR #148 round 4, N1).
func TestEditPlanAndApplyRefuseAnExternalRosterWrite(t *testing.T) {
	for name, existing := range map[string]bool{"existing external roster": true, "new external roster": false} {
		t.Run(name, func(t *testing.T) {
			externalDir := t.TempDir()
			roster := filepath.Join(externalDir, "ipa-identity.yaml")
			if existing {
				writeSyncFile(t, roster, syncTestRoster(`"Admin-pass_1"`))
			}
			dir := nfsScopeWorkspace(t, roster)
			external := dirContents(t, externalDir)
			workspace := dirContents(t, dir)

			_, err := planEditScenario(dir, enableNFSScenario(), editAgentSessionOptions{})
			if !errors.Is(err, errRosterOutsideEditScope) || !strings.Contains(err.Error(), roster) {
				t.Fatalf("planEditScenario() error = %v; want errRosterOutsideEditScope naming %s", err, roster)
			}
			assertDirUnchanged(t, externalDir, external)
			assertDirUnchanged(t, dir, workspace)

			result, err := applyEditScenario(dir, "issue-146-external-roster", enableNFSScenario(), editAgentSessionOptions{})
			if err != nil || result == nil || !result.RolledBack || !errors.Is(result.ScenarioErr, errRosterOutsideEditScope) {
				t.Fatalf("applyEditScenario() = %+v, %v; want errRosterOutsideEditScope and a rollback", result, err)
			}
			assertDirUnchanged(t, externalDir, external)
		})
	}
}

// At the terminal and under --actions there is no plan to preview and no
// rollback to keep, so an external roster is written as it always was.
func TestEditTerminalAndActionsStillWriteExternalRosters(t *testing.T) {
	run := map[string]func(t *testing.T, dir string) error{
		"terminal router": func(t *testing.T, dir string) error {
			r := newEditRouterModel(dir)
			d := automationDriver{dir: dir}
			return d.run(&r, enableNFSScenario())
		},
		"--actions session": func(t *testing.T, dir string) error {
			_, err := newEditAgentSession(dir, editAgentSessionOptions{}).Run(enableNFSScenario())
			return err
		},
	}
	for name, do := range run {
		t.Run(name, func(t *testing.T) {
			roster := filepath.Join(t.TempDir(), "ipa-identity.yaml")
			writeSyncFile(t, roster, syncTestRoster(`"Admin-pass_1"`))
			dir := nfsScopeWorkspace(t, roster)
			if err := do(t, dir); err != nil {
				t.Fatalf("run error = %v", err)
			}
			data, err := os.ReadFile(roster)
			if err != nil || !strings.Contains(string(data), "nexus") {
				t.Fatalf("external roster not given nexus's nfs.servers entry (err=%v):\n%s", err, data)
			}
		})
	}
}

// The editor resolves a freeipa_roster_file reference, and builds the
// absolute path it records in hosts.yml, only through its write scope
// (editRouterModel.rosterWritePath, recordedPath): a screen that resolved
// one itself would write the real roster from a plan's copy, or record
// the copy's path (PR #148 round 4, R3/N2).
func TestEditorResolvesRosterReferencesThroughItsScope(t *testing.T) {
	allowed := map[string]bool{
		// Reads every reference to find the rosters to compare and sync;
		// the sync maps each one through the scope first.
		"rosterCandidates": true,
		// The scope's own helpers.
		"rosterWritePath": true,
		"recordedPath":    true,
	}
	files, err := filepath.Glob("edit_tui*.go")
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range forbiddenRosterPathCalls(t, path, data, allowed) {
			t.Error(v)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no edit_tui*.go files found")
	}
}

// forbiddenRosterPathCalls lists the resolveRosterPath(…) calls and the
// filepath.Abs(filepath.Join(dir, …)) calls in src outside the functions
// allowed names.
func forbiddenRosterPathCalls(t *testing.T, name string, src []byte, allowed map[string]bool) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || allowed[fn.Name.Name] {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "resolveRosterPath" {
				out = append(out, fset.Position(call.Pos()).String()+": "+fn.Name.Name+" calls resolveRosterPath; use r.rosterWritePath")
			}
			if isSelectorCall(call, "filepath", "Abs") && len(call.Args) == 1 {
				if inner, ok := call.Args[0].(*ast.CallExpr); ok && isSelectorCall(inner, "filepath", "Join") && len(inner.Args) > 0 {
					if id, ok := inner.Args[0].(*ast.Ident); ok && id.Name == "dir" {
						out = append(out, fset.Position(call.Pos()).String()+": "+fn.Name.Name+" calls filepath.Abs(filepath.Join(dir, …)); use r.recordedPath")
					}
				}
			}
			return true
		})
	}
	return out
}

func isSelectorCall(call *ast.CallExpr, pkg, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func TestEditorRosterPathLintCatchesDirectResolution(t *testing.T) {
	for name, tc := range map[string]struct {
		src  string
		want int
	}{
		"resolve":        {`package cmd; func f(dir, ref string) string { return resolveRosterPath(dir, ref) }`, 1},
		"abs join dir":   {`package cmd; func f(dir string) { filepath.Abs(filepath.Join(dir, ".vault", "x.yaml")) }`, 1},
		"scoped":         {`package cmd; func f(r *editRouterModel, dir, ref string) string { return r.rosterWritePath(dir, ref) }`, 0},
		"abs other dir":  {`package cmd; func f(src string) { filepath.Abs(src) }`, 0},
		"allowed helper": {`package cmd; func rosterWritePath(dir, ref string) string { return resolveRosterPath(dir, ref) }`, 0},
	} {
		t.Run(name, func(t *testing.T) {
			got := forbiddenRosterPathCalls(t, "x.go", []byte(tc.src), map[string]bool{"rosterWritePath": true})
			if len(got) != tc.want {
				t.Fatalf("violations = %v, want %d", got, tc.want)
			}
		})
	}
}
