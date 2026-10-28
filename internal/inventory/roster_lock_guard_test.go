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

// rosterWriteCalls are the calls that change a file in this package: the
// secret-source write primitives, the os calls they are built on, and the
// removals. os.OpenFile counts when its flags open for writing or creating
// (isRosterWriteCall), so does os.Create.
var rosterWriteCalls = map[string]bool{
	"writeLockedRoster": true, "writeSecretSourceFile": true,
	"os.WriteFile": true, "os.Rename": true, "os.Create": true,
	"os.Remove": true, "os.RemoveAll": true,
}

// rosterWriteDestination is the argument of a rosterWriteCalls call that
// names the file it changes: a rename's second, every other call's first.
func rosterWriteDestination(call *ast.CallExpr) int {
	if callName(call) == "os.Rename" {
		return 1
	}
	return 0
}

// rosterWriterExemptions are the only functions here that may write a file
// without a roster lock. Each must still exist and still write.
var rosterWriterExemptions = map[string]string{
	"writeSecretSourceFile":                 "the write primitive itself; its callers hold the lock",
	"acquireMutationLock":                   "creates a roster's lock file, never the roster; only lockRosterFile calls it (rule 1)",
	"WriteMinimalFreeIPAVault":              "writes the vault vars file (.vault/main.yaml), not a roster",
	"FillFreeIPAAdminPassword":              "writes the vault vars file (.vault/main.yaml), not a roster",
	"CreateMinimalDNSManifest":              "writes the freeipa-dns manifest, not a roster",
	"writeDNSYAMLDoc":                       "writes the freeipa-dns manifest, not a roster",
	"CreateMinimalInternalEndpointManifest": "writes the internal-endpoints manifest, not a roster",
	"writeInternalEndpointYAMLDoc":          "writes the internal-endpoints manifest, not a roster",
	"openRosterForWrite":                    "opens a roster for writing without truncating and writes nothing; only writeLockedRoster writes through the file, under the lock (WriteAt is a raw primitive kept in roster_write.go), and Prepare and the probe only close it",
	"sweepRosterTemps":                      "removes only temp files a killed pilot left beside the roster (its own .<roster>.pilot-tmp-* names), never the roster; lockRosterFile calls it with the lock held",
	"decryptedScratchFile":                  "its cleanup removes its own scratch copy of a decrypted roster and the lock files a writer left beside it, never the roster",
}

// Every roster writer locks the file it changes, however the caller spells
// its path (PR #148 review: a sync through a symlink took the alias's lock
// files and rewrote a roster `pilot roster remove-*` held on its real
// path). Three rules, over this package's own source:
//
//  1. acquireMutationLock is called only by roster_lock.go: a writer that
//     took its own sidecar lock would lock its caller's spelling again.
//  2. A function or method that writes or removes a file
//     (rosterWriteCalls, an os.OpenFile for writing) calls lockRosterFile
//     or receives the *rosterLock of a caller that did, and changes that
//     lock's target, or a path built from it — never the path it was
//     given, which may be a link, nor any other value's field named
//     target. The exemptions above are the write primitives and files
//     that are not rosters.
//  3. A function holding a roster lock never reaches another lockRosterFile
//     through this package's calls: the lock is not reentrant, so the
//     inner call would fail with ErrMutationLocked.
//  4. The raw write primitives — os.Rename, os.CreateTemp, and the WriteAt
//     and Truncate methods — appear only in roster_write.go, so
//     writeLockedRoster's policy (replace or write in place, keep the
//     owner, sweep temp files) is the only one.
//  5. Only roster_lock.go builds a rosterLock (lockRosterFile), so a
//     *rosterLock always holds its locks.
func TestRegression_RosterWritersLockCanonicalTarget(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	lockFields := map[string][]string{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if callName(call) == "acquireMutationLock" && path != "roster_lock.go" {
				t.Errorf("%s: acquireMutationLock outside roster_lock.go; lock a roster with lockRosterFile", fset.Position(call.Pos()))
			}
			if path != "roster_write.go" && isRawWritePrimitive(call) {
				t.Errorf("%s: raw file write outside roster_write.go; write a roster with writeLockedRoster", fset.Position(call.Pos()))
			}
			return true
		})
		if path != "roster_lock.go" {
			for _, pos := range rosterLockLiterals(file) {
				t.Errorf("%s: a rosterLock built outside roster_lock.go; only lockRosterFile makes one, holding its locks", fset.Position(pos))
			}
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[funcName(fn)] = fn
			}
			for name, fields := range rosterLockFields(decl) {
				lockFields[name] = fields
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
		locks := lockVars(fn, lockFields)
		if len(locks) == 0 {
			t.Errorf("%s writes a file without lockRosterFile or a *rosterLock parameter", name)
			continue
		}
		targets := lockTargetVars(fn, locks)
		for _, call := range writes {
			arg := rosterWriteDestination(call)
			if len(call.Args) <= arg || !isLockTarget(call.Args[arg], locks, targets) {
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
				if inSet(reaches, callee) {
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
			if callee != name && inSet(reaches, callee) {
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

// calleesOf lists what fn calls: a function by name, and a method as
// ".Name" (any method of that name, see inSet), since a receiver's type is
// not known without type checking.
func calleesOf(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				out = append(out, fun.Name)
			case *ast.SelectorExpr:
				out = append(out, "."+fun.Sel.Name)
			}
		}
		return true
	})
	return out
}

// inSet reports whether callee — a function name, or ".Name" for a method
// call — is in set, whose methods are keyed "Type.Name".
func inSet(set map[string]bool, callee string) bool {
	if !strings.HasPrefix(callee, ".") {
		return set[callee]
	}
	for key, ok := range set {
		if ok && strings.HasSuffix(key, callee) {
			return true
		}
	}
	return false
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

// isRawWritePrimitive reports whether call is one of the primitives only
// roster_write.go may use: os.Rename, os.CreateTemp, an atomicReplaceFile*
// helper, or a WriteAt or Truncate method.
func isRawWritePrimitive(call *ast.CallExpr) bool {
	switch name := callName(call); {
	case name == "os.Rename", name == "os.CreateTemp", name == "createRosterTemp", strings.HasPrefix(name, "atomicReplaceFile"):
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && (sel.Sel.Name == "WriteAt" || sel.Sel.Name == "Truncate")
}

// isRosterWriteCall reports whether call writes a file: one of
// rosterWriteCalls, or os.OpenFile — or openLockFile, its seam for lock
// files — with a flag that writes or creates.
func isRosterWriteCall(call *ast.CallExpr) bool {
	name := callName(call)
	if rosterWriteCalls[name] {
		return true
	}
	if name != "os.OpenFile" && name != "openLockFile" || len(call.Args) < 2 {
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

// rosterLockFields returns, for a type declaration, each struct type's
// fields of type *rosterLock.
func rosterLockFields(decl ast.Decl) map[string][]string {
	out := map[string][]string{}
	gen, ok := decl.(*ast.GenDecl)
	if !ok {
		return out
	}
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			continue
		}
		for _, field := range st.Fields.List {
			if star, ok := field.Type.(*ast.StarExpr); ok {
				if ident, ok := star.X.(*ast.Ident); ok && ident.Name == "rosterLock" {
					for _, name := range field.Names {
						out[ts.Name.Name] = append(out[ts.Name.Name], name.Name)
					}
				}
			}
		}
	}
	return out
}

// lockVars returns the expressions in fn that hold a roster lock: a
// *rosterLock parameter, a variable assigned lockRosterFile's result, or —
// in a method — the receiver's *rosterLock field ("p.lk").
func lockVars(fn *ast.FuncDecl, lockFields map[string][]string) map[string]bool {
	out := map[string]bool{}
	if fn.Recv != nil && len(fn.Recv.List) == 1 && len(fn.Recv.List[0].Names) == 1 {
		recv := fn.Recv.List[0]
		typ := recv.Type
		if star, ok := typ.(*ast.StarExpr); ok {
			typ = star.X
		}
		if ident, ok := typ.(*ast.Ident); ok {
			for _, field := range lockFields[ident.Name] {
				out[recv.Names[0].Name+"."+field] = true
			}
		}
	}
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
// `target := lk.target`, `path, target := lk.path, lk.target`, a path built
// from it such as a backup name, or the first result of a call given one,
// `tmp, err := createRosterTemp(filepath.Dir(target), …)` — for locks.
func lockTargetVars(fn *ast.FuncDecl, locks map[string]bool) map[string]bool {
	out := map[string]bool{}
	derivedFrom := func(expr ast.Expr) bool {
		derived := false
		ast.Inspect(expr, func(inner ast.Node) bool {
			if expr, ok := inner.(ast.Expr); ok && isLockTarget(expr, locks, out) {
				derived = true
			}
			return !derived
		})
		return derived
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			pairs := map[ast.Expr]ast.Expr{}
			switch {
			case len(assign.Lhs) == len(assign.Rhs):
				for i, rhs := range assign.Rhs {
					pairs[assign.Lhs[i]] = rhs
				}
			case len(assign.Rhs) == 1:
				// `a, err := f(…)`: only the first result is the file.
				if _, ok := assign.Rhs[0].(*ast.CallExpr); ok {
					pairs[assign.Lhs[0]] = assign.Rhs[0]
				}
			}
			for lhs, rhs := range pairs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || out[ident.Name] {
					continue
				}
				if derivedFrom(rhs) {
					out[ident.Name], changed = true, true
				}
			}
			return true
		})
	}
	return out
}

// rosterLockLiterals returns where file builds a rosterLock value: only
// lockRosterFile may, so every rosterLock a writer holds has its locks.
func rosterLockLiterals(file *ast.File) []token.Pos {
	var out []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		if lit, ok := node.(*ast.CompositeLit); ok {
			if ident, ok := lit.Type.(*ast.Ident); ok && ident.Name == "rosterLock" {
				out = append(out, lit.Pos())
			}
		}
		return true
	})
	return out
}

// isLockTarget reports whether expr is a lock's target: <lock>.target for
// one of locks, one of targets, or the lock itself (writeLockedRoster
// takes the lock and writes its target).
func isLockTarget(expr ast.Expr, locks, targets map[string]bool) bool {
	if locks[lockExprKey(expr)] {
		return true
	}
	switch expr := expr.(type) {
	case *ast.SelectorExpr:
		return expr.Sel.Name == "target" && locks[lockExprKey(expr.X)]
	case *ast.Ident:
		return targets[expr.Name]
	}
	return false
}

// lockExprKey names an identifier or a one-level selector ("p.lk"), the
// two forms a lock is held in; "" otherwise.
func lockExprKey(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		if x, ok := expr.X.(*ast.Ident); ok {
			return x.Name + "." + expr.Sel.Name
		}
	}
	return ""
}
