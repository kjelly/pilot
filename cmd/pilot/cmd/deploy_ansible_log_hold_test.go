package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every command built by deployAnsibleCommand writes the controller Ansible
// log, so the function that runs it must hold the log while it does
// (holdDeployAnsibleLog or ansible.HoldLogUse). Without that, log
// maintenance in another goroutine (pilot mcp serve runs tools concurrently)
// can rewrite or rotate the log under it (PR #71 review).
func TestDeployAnsibleCommandsHoldTheLog(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		// The innermost function around each call must hold the log.
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			call, ok := n.(*ast.CallExpr)
			if !ok || calledName(call) != "deployAnsibleCommand" {
				return true
			}
			var body *ast.BlockStmt
			for i := len(stack) - 1; i >= 0 && body == nil; i-- {
				switch fn := stack[i].(type) {
				case *ast.FuncLit:
					body = fn.Body
				case *ast.FuncDecl:
					body = fn.Body
				}
			}
			checked++
			if body == nil || !callsAny(body, "holdDeployAnsibleLog", "HoldLogUse") {
				t.Errorf("%s: runs a deployAnsibleCommand command without holding the Ansible log", fset.Position(call.Pos()))
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("found no deployAnsibleCommand call")
	}
}

func calledName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

func callsAny(body *ast.BlockStmt, names ...string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			for _, name := range names {
				if calledName(call) == name {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
