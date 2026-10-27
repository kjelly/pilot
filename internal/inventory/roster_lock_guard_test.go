package inventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// rosterWriteCalls are the calls that put bytes into a file in this
// package: the two secret-source write primitives and the os calls they
// are built on.
var rosterWriteCalls = map[string]bool{"writeSecretSourceFile": true, "atomicReplaceFile": true, "os.WriteFile": true, "os.Rename": true}

// rosterWriterExemptions are the only functions here that may write a file
// without a roster lock. Each must still exist and still write.
var rosterWriterExemptions = map[string]string{
	"writeSecretSourceFile":                 "the write primitive itself; its callers hold the lock",
	"atomicReplaceFile":                     "the write primitive itself; its callers hold the lock",
	"WriteMinimalFreeIPAVault":              "writes the vault vars file (.vault/main.yaml), not a roster",
	"FillFreeIPAAdminPassword":              "writes the vault vars file (.vault/main.yaml), not a roster",
	"CreateMinimalDNSManifest":              "writes the freeipa-dns manifest, not a roster",
	"writeDNSYAMLDoc":                       "writes the freeipa-dns manifest, not a roster",
	"CreateMinimalInternalEndpointManifest": "writes the internal-endpoints manifest, not a roster",
	"writeInternalEndpointYAMLDoc":          "writes the internal-endpoints manifest, not a roster",
}

// Every roster writer locks the file it changes, however the caller spells
// its path (PR #148 review: a sync through a symlink took the alias's lock
// files and rewrote a roster `pilot roster remove-*` held on its real
// path). Three rules, over this package's own source:
//
//  1. acquireMutationLock is called only by roster_lock.go: a writer that
//     took its own sidecar lock would lock its caller's spelling again.
//  2. A function that writes a file calls lockRosterFile or receives the
//     *rosterLock of a caller that did, and writes that lock's target —
//     never the path it was given, which may be a link. The exemptions
//     above are the write primitives and files that are not rosters.
//  3. A function holding a roster lock never reaches another lockRosterFile
//     through this package's calls: the lock is not reentrant, so the
//     inner call would fail with ErrMutationLocked.
func TestRegression_RosterWritersLockCanonicalTarget(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && callName(call) == "acquireMutationLock" && path != "roster_lock.go" {
				t.Errorf("%s: acquireMutationLock outside roster_lock.go; lock a roster with lockRosterFile", fset.Position(call.Pos()))
			}
			return true
		})
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil {
				funcs[fn.Name.Name] = fn
			}
		}
	}

	lockers := map[string]bool{}
	for name, fn := range funcs {
		if callsFunc(fn, "lockRosterFile") {
			lockers[name] = true
		}
	}
	exemptionsUsed := map[string]bool{}
	names := make([]string, 0, len(funcs))
	for name := range funcs {
		names = append(names, name)
	}
	sort.Strings(names)
	writers := 0
	for _, name := range names {
		fn := funcs[name]
		writes := rosterWritesIn(fn)
		if len(writes) == 0 {
			continue
		}
		if _, ok := rosterWriterExemptions[name]; ok {
			exemptionsUsed[name] = true
			continue
		}
		writers++
		lockVar := rosterLockParam(fn)
		if lockVar == "" && !lockers[name] {
			t.Errorf("%s writes a file without lockRosterFile or a *rosterLock parameter", name)
			continue
		}
		targets := lockTargetVars(fn)
		for _, call := range writes {
			if len(call.Args) == 0 || !isLockTarget(call.Args[0], targets) {
				t.Errorf("%s: %s in %s must write the lock's target (lk.target), not the path it was given", fset.Position(call.Pos()), callName(call), name)
			}
		}
	}
	for name, reason := range rosterWriterExemptions {
		if !exemptionsUsed[name] {
			t.Errorf("exemption %s (%s) no longer names a function that writes a file; remove it", name, reason)
		}
	}

	// Rule 3: which functions reach lockRosterFile, directly or not.
	reaches := map[string]bool{}
	for name := range lockers {
		reaches[name] = true
	}
	for changed := true; changed; {
		changed = false
		for name, fn := range funcs {
			if reaches[name] {
				continue
			}
			for _, callee := range calleesOf(fn) {
				if reaches[callee] {
					reaches[name], changed = true, true
					break
				}
			}
		}
	}
	for _, name := range names {
		if !lockers[name] {
			continue
		}
		for _, callee := range calleesOf(funcs[name]) {
			if callee != name && reaches[callee] {
				t.Errorf("%s holds a roster lock and calls %s, which takes one too; pass the *rosterLock to a *Locked helper instead", name, callee)
			}
		}
	}
	if writers == 0 || len(lockers) == 0 {
		t.Fatalf("found %d roster writers and %d lockers; the audit no longer sees this package", writers, len(lockers))
	}
	t.Logf("audited %d roster writers; %d functions take the roster lock", writers, len(lockers))
}

func callName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok {
			return pkg.Name + "." + fun.Sel.Name
		}
	}
	return ""
}

func callsFunc(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && callName(call) == name {
			found = true
		}
		return !found
	})
	return found
}

func calleesOf(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok {
				out = append(out, ident.Name)
			}
		}
		return true
	})
	return out
}

func rosterWritesIn(fn *ast.FuncDecl) []*ast.CallExpr {
	var out []*ast.CallExpr
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && rosterWriteCalls[callName(call)] {
			out = append(out, call)
		}
		return true
	})
	return out
}

// rosterLockParam returns the name of fn's *rosterLock parameter, if any.
func rosterLockParam(fn *ast.FuncDecl) string {
	for _, field := range fn.Type.Params.List {
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if ident, ok := star.X.(*ast.Ident); ok && ident.Name == "rosterLock" && len(field.Names) == 1 {
			return field.Names[0].Name
		}
	}
	return ""
}

// lockTargetVars returns the local names fn assigns a lock's target to,
// as in `target := lk.target` or `path, target := lk.path, lk.target`.
func lockTargetVars(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			if sel, ok := rhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "target" {
				if ident, ok := assign.Lhs[i].(*ast.Ident); ok {
					out[ident.Name] = true
				}
			}
		}
		return true
	})
	return out
}

func isLockTarget(expr ast.Expr, targets map[string]bool) bool {
	switch expr := expr.(type) {
	case *ast.SelectorExpr:
		_, ok := expr.X.(*ast.Ident)
		return ok && expr.Sel.Name == "target"
	case *ast.Ident:
		return targets[expr.Name]
	}
	return false
}
