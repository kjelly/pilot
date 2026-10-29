package inventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// rosterWriteInternals are writeLockedRoster's own write paths: only
// writeLockedRoster calls writeRosterBytes, and only writeRosterBytes calls
// the other two. Called from anywhere else, a write would skip the journal.
var rosterWriteInternals = map[string]string{
	"writeRosterBytes":   "writeLockedRoster",
	"writeRosterInPlace": "writeRosterBytes",
	"createLockedRoster": "writeRosterBytes",
}

// rosterTargetWriteExemptions are the only calls outside the internals that
// change a lock's target itself, by function and call.
var rosterTargetWriteExemptions = map[string]string{
	"RemoveRosterFile|os.Remove": "pilot edit's rollback removing a roster its session created; it closes its journal before rolling back",
}

// rosterByteWritePrimitives may change a roster's bytes: in roster_write.go
// they appear only in the internals (and, for the lock file, stampLockFile).
var rosterByteWritePrimitives = map[string]map[string]bool{
	"renameRosterTemp": {"writeRosterBytes": true},
	"os.Rename":        {"createLockedRoster": true},
	"writeRosterAt":    {"writeRosterInPlace": true},
	".Truncate":        {"writeRosterInPlace": true, "stampLockFile": true},
	".WriteAt":         {"stampLockFile": true},
}

// Every byte written to a roster goes through writeLockedRoster, which
// records it in an open RosterJournal (pilot edit's apply rollback undoes
// exactly what those records say its writes replaced, PR #148 review P2).
// A write path that bypassed it would change a roster the rollback then
// mistakes for another process's change, or restores over. Over this
// package's own source:
//
//  1. writeLockedRoster journals: it calls beginJournaledRosterWrite, then
//     writeRosterBytes once, then finish.
//  2. The internals (rosterWriteInternals) are called only by their one
//     caller each.
//  3. Outside the internals, nothing writes, renames over, opens for
//     writing or removes a lock's target itself — lk.target, or a variable
//     holding exactly it — but writeLockedRoster (rosterTargetWriteExemptions).
//  4. In roster_write.go, the primitives that change a file's bytes in
//     place or by rename appear only in the internals (and the lock file's
//     stamp), never in another helper a future writer could call.
func TestRegression_RosterBytesAreWrittenOnlyByWriteLockedRoster(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	funcFile := map[string]string{}
	lockFields := map[string][]string{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[funcName(fn)] = fn
				funcFile[funcName(fn)] = path
			}
			for name, fields := range rosterLockFields(decl) {
				lockFields[name] = fields
			}
		}
	}

	// Rule 1.
	writer, ok := funcs["writeLockedRoster"]
	if !ok {
		t.Fatal("writeLockedRoster not found; the audit no longer sees this package")
	}
	var sequence []string
	ast.Inspect(writer.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			switch name := calleeName(call); name {
			case "beginJournaledRosterWrite", "writeRosterBytes", ".finish":
				sequence = append(sequence, name)
			}
		}
		return true
	})
	if strings.Join(sequence, " ") != "beginJournaledRosterWrite writeRosterBytes .finish" {
		t.Errorf("writeLockedRoster calls %q; want beginJournaledRosterWrite, writeRosterBytes once, then finish", sequence)
	}

	// Rule 2.
	for name, fn := range funcs {
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if only, internal := rosterWriteInternals[calleeName(call)]; internal && name != only {
				t.Errorf("%s: %s calls %s; only %s may, so every roster write is journaled", fset.Position(call.Pos()), name, calleeName(call), only)
			}
			return true
		})
	}

	// Rule 3.
	exemptionsUsed := map[string]bool{}
	for name, fn := range funcs {
		if _, internal := rosterWriteInternals[name]; internal {
			continue
		}
		locks := lockVars(fn, lockFields)
		if len(locks) == 0 {
			continue
		}
		exact := exactLockTargetVars(fn, locks)
		for _, call := range rosterWritesIn(fn) {
			callee := callName(call)
			if callee == "writeLockedRoster" {
				continue
			}
			arg := rosterWriteDestination(call)
			if len(call.Args) <= arg || !isExactLockTarget(call.Args[arg], locks, exact) {
				continue
			}
			key := name + "|" + callee
			if _, ok := rosterTargetWriteExemptions[key]; ok {
				exemptionsUsed[key] = true
				continue
			}
			t.Errorf("%s: %s changes its lock's target with %s; write a roster only with writeLockedRoster, which journals it", fset.Position(call.Pos()), name, callee)
		}
	}
	for key, reason := range rosterTargetWriteExemptions {
		if !exemptionsUsed[key] {
			t.Errorf("exemption %s (%s) no longer matches a call; remove it", key, reason)
		}
	}

	// Rule 4.
	for name, fn := range funcs {
		if funcFile[name] != "roster_write.go" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := calleeName(call)
			if allowed, primitive := rosterByteWritePrimitives[callee]; primitive && !allowed[name] {
				t.Errorf("%s: %s uses %s, which changes a file's bytes; only writeLockedRoster's internals may", fset.Position(call.Pos()), name, callee)
			}
			return true
		})
	}
}

// calleeName is callName, or ".Name" for a method call on anything but a
// package (its receiver's type is not known without type checking).
func calleeName(call *ast.CallExpr) string {
	if name := callName(call); name != "" && !strings.Contains(name, ".") {
		return name
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok && (pkg.Name == "os" || pkg.Name == "syscall" || pkg.Name == "unix") {
			return pkg.Name + "." + sel.Sel.Name
		}
		return "." + sel.Sel.Name
	}
	return callName(call)
}

// exactLockTargetVars returns the local names fn assigns exactly a lock's
// target to — `path := lk.target`, `p, target := lk.path, lk.target` — as
// opposed to a path built from it (lockTargetVars), such as a backup's.
func exactLockTargetVars(fn *ast.FuncDecl, locks map[string]bool) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, rhs := range assign.Rhs {
			if ident, ok := assign.Lhs[i].(*ast.Ident); ok && isExactLockTarget(rhs, locks, out) {
				out[ident.Name] = true
			}
		}
		return true
	})
	return out
}

// isExactLockTarget reports whether expr is <lock>.target for one of
// locks, or one of exact.
func isExactLockTarget(expr ast.Expr, locks, exact map[string]bool) bool {
	switch expr := expr.(type) {
	case *ast.SelectorExpr:
		return expr.Sel.Name == "target" && locks[lockExprKey(expr.X)]
	case *ast.Ident:
		return exact[expr.Name]
	}
	return false
}
