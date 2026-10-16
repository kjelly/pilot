package ansible

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every Ansible command Pilot starts may write the controller Ansible log
// (ANSIBLE_LOG_PATH comes with the runtime environment), so it must run
// while the log is held: maintenance in another goroutine (pilot mcp serve
// runs tools concurrently) would otherwise rewrite or rotate the log under
// it (PR #71 reviews). This walks every function under cmd/ and internal/
// and checks that each Ansible command it creates is run between a hold
// for that command (HoldCommandLog, or HoldLogUseContext in the runner) and
// the hold's release.
func TestAnsibleCommandsHoldTheLog(t *testing.T) {
	fset := token.NewFileSet()
	checked := 0
	for _, dir := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch fn := n.(type) {
				case *ast.FuncDecl:
					if fn.Body != nil {
						checked += checkLogHolds(t, fset, fn.Body)
					}
				case *ast.FuncLit:
					checked += checkLogHolds(t, fset, fn.Body)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 10 {
		t.Fatalf("checked %d Ansible commands; the scan is not finding them", checked)
	}
}

type positioned struct {
	name string
	pos  token.Pos
}

// logHold is a hold of the log for command, released by calling release.
type logHold struct {
	command, release string
	pos              token.Pos
}

// checkLogHolds checks one function body, not the function literals
// inside it (they are checked on their own), and returns how many Ansible
// commands it found.
func checkLogHolds(t *testing.T, fset *token.FileSet, body *ast.BlockStmt) int {
	t.Helper()
	var creations, runs, releaseCalls []positioned
	var holds []logHold
	deferred := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			if len(node.Rhs) != 1 {
				return true
			}
			call, ok := node.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			name := identName(node.Lhs[0])
			switch {
			case isAnsibleCommand(call):
				creations = append(creations, positioned{name, call.Pos()})
			case calledFunc(call) == "HoldCommandLog" && len(call.Args) == 2:
				holds = append(holds, logHold{identName(call.Args[1]), name, call.Pos()})
			case calledFunc(call) == "HoldLogUseContext":
				holds = append(holds, logHold{"*", name, call.Pos()})
			}
		case *ast.DeferStmt:
			if id, ok := node.Call.Fun.(*ast.Ident); ok {
				deferred[id.Name] = true
			}
			return false
		case *ast.CallExpr:
			if isAnsibleCommand(node) {
				// Created without a name to hold it by.
				creations = append(creations, positioned{"", node.Pos()})
			}
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Run", "Output", "CombinedOutput", "Start":
					runs = append(runs, positioned{identName(sel.X), node.Pos()})
				}
			}
			if id, ok := node.Fun.(*ast.Ident); ok {
				releaseCalls = append(releaseCalls, positioned{id.Name, node.Pos()})
			}
		}
		return true
	})
	seen := map[token.Pos]bool{}
	count := 0
	for _, c := range creations {
		if seen[c.pos] {
			continue
		}
		seen[c.pos] = true
		count++
		where := fset.Position(c.pos)
		if c.name == "" {
			t.Errorf("%s: an Ansible command is run without a name to hold the log by", where)
			continue
		}
		ran := false
		for _, r := range runs {
			if r.name != c.name || r.pos < c.pos {
				continue
			}
			ran = true
			if !heldAround(r.pos, c.pos, c.name, holds, releaseCalls, deferred) {
				t.Errorf("%s: %s runs at %s without holding the Ansible log until it is done", where, c.name, fset.Position(r.pos))
			}
		}
		if !ran {
			t.Errorf("%s: %s is created but not run here; run it while holding the log", where, c.name)
		}
	}
	return count
}

func heldAround(run, created token.Pos, command string, holds []logHold, releaseCalls []positioned, deferred map[string]bool) bool {
	for _, h := range holds {
		if (h.command != command && h.command != "*") || h.pos > run || (h.command != "*" && h.pos < created) {
			continue
		}
		releasedEarly, releasedAfter := false, deferred[h.release]
		for _, r := range releaseCalls {
			if r.name != h.release {
				continue
			}
			if r.pos > h.pos && r.pos < run {
				releasedEarly = true
			}
			if r.pos > run {
				releasedAfter = true
			}
		}
		if !releasedEarly && releasedAfter {
			return true
		}
	}
	return false
}

// newCmdBinaryIsAnsible makes isAnsibleCommand treat newCmd with a
// variable binary as an Ansible command (TestAnsibleExecWrappersHoldTheLog).
var newCmdBinaryIsAnsible bool

// isAnsibleCommand reports whether call creates an exec.Cmd for an
// Ansible program that can write the log: exec.Command(Context) with an
// "ansible..." literal, or with the runner's Binary, and
// deployAnsibleCommand. A "--version" query writes no log.
func isAnsibleCommand(call *ast.CallExpr) bool {
	var binary ast.Expr
	var args []ast.Expr
	switch calledFunc(call) {
	case "Command":
		if len(call.Args) == 0 || !isExecPackage(call) {
			return false
		}
		binary, args = call.Args[0], call.Args[1:]
	case "CommandContext":
		if len(call.Args) < 2 || !isExecPackage(call) {
			return false
		}
		binary, args = call.Args[1], call.Args[2:]
	case "deployAnsibleCommand":
		if len(call.Args) < 2 {
			return false
		}
		binary, args = call.Args[1], call.Args[2:]
	case "newCmd":
		// cmd/pilot/cmd's swappable exec.CommandContext.
		if len(call.Args) < 2 {
			return false
		}
		binary, args = call.Args[1], call.Args[2:]
		if _, ok := binary.(*ast.Ident); ok && newCmdBinaryIsAnsible {
			return true
		}
	default:
		return false
	}
	for _, arg := range args {
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Value == `"--version"` {
			return false
		}
	}
	switch b := binary.(type) {
	case *ast.BasicLit:
		value, err := strconv.Unquote(b.Value)
		return err == nil && strings.HasPrefix(value, "ansible") && value != "ansible-lint"
	case *ast.SelectorExpr:
		return b.Sel.Name == "Binary"
	}
	return false
}

func isExecPackage(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "exec"
}

func calledFunc(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

func identName(expr ast.Expr) string {
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// The exec wrappers in cmd/pilot/cmd that run ansible-playbook take the
// binary as a parameter (execExternal) or inherit this process's environment
// with extra entries (execAnsiblePlaybookCaptured), either of which may name
// the controller Ansible log. Their commands must run inside a hold like
// every other Ansible command; TestAnsibleCommandsHoldTheLog cannot see that
// a variable binary is ansible-playbook, so this checks the wrappers by name
// (PR #90 review).
func TestAnsibleExecWrappersHoldTheLog(t *testing.T) {
	newCmdBinaryIsAnsible = true
	defer func() { newCmdBinaryIsAnsible = false }()
	fset := token.NewFileSet()
	for file, wrapper := range map[string]string{
		"../../cmd/pilot/cmd/docker_target.go":       "execExternal",
		"../../cmd/pilot/cmd/ansible_json_result.go": "execAnsiblePlaybookCaptured",
	} {
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != wrapper || fn.Body == nil {
				continue
			}
			found = true
			if n := checkLogHolds(t, fset, fn.Body); n == 0 {
				t.Errorf("%s: found no command to check in %s", file, wrapper)
			}
		}
		if !found {
			t.Errorf("%s: %s not found; update this test if it moved", file, wrapper)
		}
	}
}
