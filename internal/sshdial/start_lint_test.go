package sshdial

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// startViolations returns what in the given sources (file name -> text) starts
// an ssh outside start, or starts it without isolating it:
//
//   - a call of Start, Run, Output or CombinedOutput, which is how an
//     *exec.Cmd runs, anywhere but in func start (no type information is
//     needed: this package calls those methods on nothing else);
//   - func start not calling childproc.Isolate before it calls Start;
//   - a call of Kill or Signal on a Process: ssh and what it started end
//     through childproc.KillGroup (kill), not by signalling the one process.
//
// A new ssh that skipped start would not be isolated, so the hang the
// isolation prevents would be back (AGENTS.md §5.10).
func startViolations(t *testing.T, sources map[string]string) []string {
	t.Helper()
	var problems []string
	sawStart := false
	fset := token.NewFileSet()
	var names []string
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			inStart := fd.Recv != nil && fd.Name.Name == "start"
			var isolateAt, startAt token.Pos
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				where := fmt.Sprintf("%s:%d (%s)", name, fset.Position(call.Pos()).Line, fd.Name.Name)
				switch sel.Sel.Name {
				case "Start", "Run", "Output", "CombinedOutput":
					if !inStart {
						problems = append(problems, where+": ."+sel.Sel.Name+"() outside func start: this ssh is not isolated")
					} else if sel.Sel.Name == "Start" {
						startAt = call.Pos()
					}
				case "Isolate":
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "childproc" && inStart {
						isolateAt = call.Pos()
					}
				case "Kill", "Signal":
					if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "Process" {
						problems = append(problems, where+": ."+sel.Sel.Name+" on a Process signals one process, not ssh's group: use childproc.KillGroup")
					}
				}
				return true
			})
			if inStart {
				sawStart = true
				if startAt == token.NoPos {
					problems = append(problems, name+": func start does not call Start")
				}
				if isolateAt == token.NoPos || (startAt != token.NoPos && isolateAt > startAt) {
					problems = append(problems, name+": func start must call childproc.Isolate(cmd) before cmd.Start()")
				}
			}
		}
	}
	if !sawStart {
		problems = append(problems, "func start not found: the one place that starts ssh was renamed or removed")
	}
	return problems
}

func sshdialSources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sources[f] = string(data)
	}
	if len(sources) == 0 {
		t.Fatal("no source files found")
	}
	return sources
}

// sshdial starts ssh only through start, which isolates it (childproc.Isolate):
// every path (a remote command, a tunnel, the lock) gets a session of its own,
// a group kill and a bounded wait, and a new one cannot skip that.
func TestRegression_SSHStartsOnlyThroughStart(t *testing.T) {
	sources := sshdialSources(t)
	if problems := startViolations(t, sources); len(problems) != 0 {
		t.Fatalf("sshdial starts ssh outside the isolating start:\n%s", strings.Join(problems, "\n"))
	}

	// The lint must fail on the violations it is for: each mutation of the real
	// source below has to be reported, or the check above proves nothing.
	mutate := func(file, old, repl string) map[string]string {
		t.Helper()
		src, ok := sources[file]
		if !ok || strings.Count(src, old) != 1 {
			t.Fatalf("the anchor %q is not exactly once in %s", old, file)
		}
		out := map[string]string{}
		for k, v := range sources {
			out[k] = v
		}
		out[file] = strings.Replace(src, old, repl, 1)
		return out
	}
	for name, tc := range map[string]struct {
		sources map[string]string
		want    string
	}{
		"an ssh run in DialContext": {
			mutate("sshdial.go", "p, err := d.start(cmd)\n\tinR.Close()", "if err := cmd.Run(); err != nil {\n\t\treturn nil, err\n\t}\n\tp, err := d.start(cmd)\n\tinR.Close()"),
			".Run() outside func start",
		},
		"an ssh started in the lock": {
			mutate("lock.go", "p, err := d.start(cmd)", "if err := cmd.Start(); err != nil {\n\t\treturn nil, err\n\t}\n\tp, err := d.start(cmd)"),
			".Start() outside func start",
		},
		"start without Isolate": {
			mutate("sshdial.go", "\tchildproc.Isolate(cmd)\n", ""),
			"must call childproc.Isolate(cmd) before cmd.Start()",
		},
		"Isolate after Start": {
			mutate("sshdial.go", "\tchildproc.Isolate(cmd)\n\td.mu.Lock()\n\tdefer d.mu.Unlock()\n\tif d.closed {\n\t\treturn nil, ErrDialerClosed\n\t}\n\tif err := cmd.Start(); err != nil {\n\t\treturn nil, fmt.Errorf(\"sshdial: start ssh: %w\", err)\n\t}\n",
				"\td.mu.Lock()\n\tdefer d.mu.Unlock()\n\tif d.closed {\n\t\treturn nil, ErrDialerClosed\n\t}\n\tif err := cmd.Start(); err != nil {\n\t\treturn nil, fmt.Errorf(\"sshdial: start ssh: %w\", err)\n\t}\n\tchildproc.Isolate(cmd)\n"),
			"must call childproc.Isolate(cmd) before cmd.Start()",
		},
		"a kill of the one process": {
			mutate("sshdial.go", "_ = childproc.KillGroup(p.cmd)", "_ = p.cmd.Process.Kill()"),
			"use childproc.KillGroup",
		},
	} {
		t.Run(name, func(t *testing.T) {
			problems := startViolations(t, tc.sources)
			if len(problems) == 0 {
				t.Fatal("the lint reported nothing for the mutated source")
			}
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Fatalf("problems = %v, want one containing %q", problems, tc.want)
			}
		})
	}
}
