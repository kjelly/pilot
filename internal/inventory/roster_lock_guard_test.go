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
// package: the secret-source write primitives and the os calls they are
// built on. os.OpenFile counts when its flags open for writing or creating
// (isRosterWriteCall), so does os.Create.
var rosterWriteCalls = map[string]bool{"writeLockedRoster": true, "writeSecretSourceFile": true, "atomicReplaceFile": true, "atomicReplaceFileOwned": true, "os.WriteFile": true, "os.Rename": true, "os.Create": true}

// rosterWriterExemptions are the only functions here that may write a file
// without a roster lock. Each must still exist and still write.
var rosterWriterExemptions = map[string]string{
	"writeSecretSourceFile":                 "the write primitive itself; its callers hold the lock",
	"atomicReplaceFile":                     "the write primitive itself; its callers hold the lock",
	"atomicReplaceFileOwned":                "the write primitive itself; its callers hold the lock",
	"acquireMutationLock":                   "creates a roster's lock file, never the roster; only lockRosterFile calls it (rule 1)",
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
//  2. A function or method that writes a file (rosterWriteCalls, an
//     os.OpenFile for writing) calls lockRosterFile or receives the
//     *rosterLock of a caller that did, and writes that lock's target, or
//     a path built from it — never the path it was given, which may be a
//     link, nor any other value's field named target. The exemptions
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
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[funcName(fn)] = fn
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
		locks := lockVars(fn)
		if len(locks) == 0 {
			t.Errorf("%s writes a file without lockRosterFile or a *rosterLock parameter", name)
			continue
		}
		targets := lockTargetVars(fn, locks)
		for _, call := range writes {
			if len(call.Args) == 0 || !isLockTarget(call.Args[0], locks, targets) {
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
		if call, ok := node.(*ast.CallExpr); ok && isRosterWriteCall(call) {
			out = append(out, call)
		}
		return true
	})
	return out
}

// isRosterWriteCall reports whether call writes a file: one of
// rosterWriteCalls, or os.OpenFile with a flag that writes or creates.
func isRosterWriteCall(call *ast.CallExpr) bool {
	name := callName(call)
	if rosterWriteCalls[name] {
		return true
	}
	if name != "os.OpenFile" || len(call.Args) < 2 {
		return false
	}
	writes := false
	ast.Inspect(call.Args[1], func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "O_WRONLY", "O_RDWR", "O_CREATE", "O_CREAT", "O_APPEND", "O_TRUNC":
				writes = true
			}
		}
		return true
	})
	return writes
}

// funcName is fn's name, Type.Method for a method.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	if ident, ok := recv.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// lockVars returns the names in fn that hold a roster lock: a *rosterLock
// parameter, or a variable assigned lockRosterFile's result.
func lockVars(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	for _, field := range fn.Type.Params.List {
		if star, ok := field.Type.(*ast.StarExpr); ok {
			if ident, ok := star.X.(*ast.Ident); ok && ident.Name == "rosterLock" {
				for _, name := range field.Names {
					out[name.Name] = true
				}
			}
		}
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		if call, ok := assign.Rhs[0].(*ast.CallExpr); ok && callName(call) == "lockRosterFile" {
			if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
				out[ident.Name] = true
			}
		}
		return true
	})
	return out
}

// lockTargetVars returns the local names fn assigns from a lock's target —
// `target := lk.target`, `path, target := lk.path, lk.target`, or a path
// built from it such as a backup name — for locks.
func lockTargetVars(fn *ast.FuncDecl, locks map[string]bool) map[string]bool {
	out := map[string]bool{}
	for changed := true; changed; {
		changed = false
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != len(assign.Rhs) {
				return true
			}
			for i, rhs := range assign.Rhs {
				ident, ok := assign.Lhs[i].(*ast.Ident)
				if !ok || out[ident.Name] {
					continue
				}
				derived := false
				ast.Inspect(rhs, func(inner ast.Node) bool {
					if expr, ok := inner.(ast.Expr); ok && isLockTarget(expr, locks, out) {
						derived = true
					}
					return !derived
				})
				if derived {
					out[ident.Name], changed = true, true
				}
			}
			return true
		})
	}
	return out
}

// isLockTarget reports whether expr is a lock's target: <lock>.target for
// one of locks, one of targets, or the lock itself (writeLockedRoster
// takes the lock and writes its target).
func isLockTarget(expr ast.Expr, locks, targets map[string]bool) bool {
	switch expr := expr.(type) {
	case *ast.SelectorExpr:
		x, ok := expr.X.(*ast.Ident)
		return ok && locks[x.Name] && expr.Sel.Name == "target"
	case *ast.Ident:
		return targets[expr.Name] || locks[expr.Name]
	}
	return false
}
