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
