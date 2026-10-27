package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Every pilot edit roster write that ends the session on failure first
// turns a busy roster — held by another pilot process, or with a lock file
// this user cannot use — into a banner (rosterBusyBanner), so the session
// stays open (PR #148 re-review, F4: a root-owned lock file left by an
// older root-run pilot ended every roster edit). The vault writers take no
// roster lock and are not checked.
func TestRegression_EditRosterWritesReportABusyRoster(t *testing.T) {
	files, err := filepath.Glob("edit_tui*.go")
	if err != nil {
		t.Fatal(err)
	}
	vaultWriters := map[string]bool{"WriteMinimalFreeIPAVault": true, "FillFreeIPAAdminPassword": true}
	fset := token.NewFileSet()
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			stmt, ok := node.(*ast.IfStmt)
			if !ok {
				return true
			}
			assign, ok := stmt.Init.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); !ok || (name.Name != "mutateRosterSource" && name.Name != "mutateRosterSourceValue") {
				return true
			}
			writesVault := false
			ast.Inspect(call, func(inner ast.Node) bool {
				if sel, ok := inner.(*ast.SelectorExpr); ok && vaultWriters[sel.Sel.Name] {
					writesVault = true
				}
				return true
			})
			// Only branches that fail on the error: a best-effort write that
			// ignores it (`err == nil && …`) ends nothing.
			cond, ok := stmt.Cond.(*ast.BinaryExpr)
			if writesVault || !ok || cond.Op != token.NEQ {
				return true
			}
			checked++
			reported := false
			ast.Inspect(stmt.Body, func(inner ast.Node) bool {
				if c, ok := inner.(*ast.CallExpr); ok {
					if name, ok := c.Fun.(*ast.Ident); ok && name.Name == "rosterBusyBanner" {
						reported = true
					}
				}
				return true
			})
			if !reported {
				t.Errorf("%s: a roster write's failure branch must report a busy roster with rosterBusyBanner before failing", fset.Position(stmt.Pos()))
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no roster writes found; the audit no longer sees pilot edit")
	}
	t.Logf("checked %d roster writes", checked)
}

// busyErrorHandlers are the only functions in this package, besides
// rosterBusyBanner, that may act on a busy roster error themselves. A new
// one would report a refused write some other way, which the automation
// driver cannot see.
var busyErrorHandlers = map[string]string{
	"rosterBusyBanner":    "the one place a busy roster becomes a banner and a step error",
	"restoreManagedFiles": "a roster a rollback cannot put back is named in the apply error",
}

// A busy roster error is turned into a banner only by rosterBusyBanner,
// which also fails the automation step (PR #148 re-review, P1: a banner
// alone let an MCP apply report "applied" for a write that never
// happened).
func TestRegression_BusyRosterErrorsGoThroughRosterBusyBanner(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	used := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				sel, ok := node.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "ErrMutationLocked" && sel.Sel.Name != "ErrRosterLockFile") {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "inventory" {
					return true
				}
				if _, ok := busyErrorHandlers[fn.Name.Name]; ok {
					used[fn.Name.Name] = true
					return true
				}
				t.Errorf("%s: %s handles inventory.%s itself; report a busy roster with rosterBusyBanner so automation fails the step", fset.Position(sel.Pos()), fn.Name.Name, sel.Sel.Name)
				return true
			})
		}
	}
	for name, reason := range busyErrorHandlers {
		if !used[name] {
			t.Errorf("busyErrorHandlers lists %s (%s), which no longer handles a busy roster error; remove it", name, reason)
		}
	}
}
