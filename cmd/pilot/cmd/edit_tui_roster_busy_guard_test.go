package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// busyReportExemptions are the roster writes in this package whose error
// need not reach rosterBusyBanner, keyed "<function>|<inventory API>" (the
// API the write's closure calls) or by file for commands other than pilot
// edit, each with its reason.
var busyReportExemptions = map[string]string{
	"ensureRosterSchemaCurrentBanner|EnsureRosterCurrent":                     "best effort when a roster screen opens: the screen that reads the roster reports what is wrong with it",
	"autoFillFreeIPAClientRosterHostsBanner|AutoFillFreeIPAClientRosterHosts": "best effort when a roster screen opens, as above",
	"autofixNFSRosterEntry|EnsureRosterCurrent":                               "best effort before AppendMissingNFSServerStub, whose busy roster is reported",
	"pushNFSRoleBootstrapWithPassword|WriteMinimalFreeIPAVault":               "vault writer: .vault/main.yaml takes no roster lock",
	"pushNFSRoleBootstrapWithPassword|FillFreeIPAAdminPassword":               "vault writer, as above",
	"pushRosterCreateWithPassword|WriteMinimalFreeIPAVault":                   "vault writer, as above",
	"pushRosterCreateWithPassword|FillFreeIPAAdminPassword":                   "vault writer, as above",
	"restoreManagedFiles|RemoveRosterFile":                                    "a rollback names a roster it cannot put back in the apply error",
	"restoreManagedFiles|RestoreRosterFile":                                   "a rollback names a roster it cannot put back in the apply error",
	"deploy.go":                                                               "pilot deploy, not pilot edit: it returns or warns about its own errors",
	"deploy_completeness.go":                                                  "the deploy preflight, not pilot edit: it warns about its own errors",
	"inventory.go":                                                            "pilot inventory generate, not pilot edit: it reports and skips a roster it cannot write",
}

// Every roster write in this package — mutateRosterSource(Value) — binds
// its error and hands it to rosterBusyBanner before the next roster write
// binds the same name, or is exempt with a reason: a roster held by
// another pilot process, or with a lock file this user cannot use, then
// keeps the terminal session open and fails an automation step instead of
// ending the session or being dropped (PR #148 re-review, F4; round 4,
// R9b). A discarded result always fails.
func TestRegression_EditRosterWritesReportABusyRoster(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	used := map[string]bool{}
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range unreportedRosterWrites(file) {
			checked++
			if !w.unreported {
				continue
			}
			key := w.function + "|" + w.api
			if _, ok := busyReportExemptions[key]; ok && !w.discarded {
				used[key] = true
				continue
			}
			if _, ok := busyReportExemptions[path]; ok && !w.discarded {
				used[path] = true
				continue
			}
			t.Errorf("%s: %s's roster write (%s) %s; pass its error to rosterBusyBanner or exempt it in busyReportExemptions with a reason",
				fset.Position(w.pos), w.function, w.api, w.why)
		}
	}
	if checked == 0 {
		t.Fatal("no roster writes found; the audit no longer sees pilot edit")
	}
	for key, reason := range busyReportExemptions {
		if !used[key] {
			t.Errorf("busyReportExemptions lists %s (%s), which no longer exempts any write; remove it", key, reason)
		}
	}
	t.Logf("checked %d roster writes", checked)
}

// rosterWrite is one mutateRosterSource(Value) call the busy audit found.
type rosterWrite struct {
	pos        token.Pos
	function   string // the enclosing top-level function
	api        string // the inventory function its closure calls
	unreported bool   // its error does not reach rosterBusyBanner
	discarded  bool   // its error is not even bound
	why        string
}

// unreportedRosterWrites lists every roster write in file, marking those
// whose error is not bound to a name (discarded, returned or nested) or
// not passed to rosterBusyBanner(_, _, name) in the same function between
// the write and the next roster write binding that name.
func unreportedRosterWrites(file *ast.File) []rosterWrite {
	var out []rosterWrite
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// Each function body, literal or declared, is audited on its own.
		bodies := []*ast.BlockStmt{fn.Body}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				bodies = append(bodies, lit.Body)
			}
			return true
		})
		for _, body := range bodies {
			out = append(out, rosterWritesIn(fn.Name.Name, body)...)
		}
	}
	return out
}

func rosterWritesIn(function string, body *ast.BlockStmt) []rosterWrite {
	type binding struct {
		call *ast.CallExpr
		name string
	}
	var calls []*ast.CallExpr
	bound := map[*ast.CallExpr]string{}
	var bindings []binding
	type report struct {
		pos  token.Pos
		name string
	}
	var reports []report
	// inspect walks body without entering nested function literals.
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			if len(n.Rhs) == 1 {
				if call, ok := n.Rhs[0].(*ast.CallExpr); ok && isRosterWriteCall(call) && len(n.Lhs) > 0 {
					if id, ok := n.Lhs[len(n.Lhs)-1].(*ast.Ident); ok && id.Name != "_" {
						bound[call] = id.Name
						bindings = append(bindings, binding{call, id.Name})
					}
				}
			}
		case *ast.CallExpr:
			if isRosterWriteCall(n) {
				calls = append(calls, n)
			}
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "rosterBusyBanner" && len(n.Args) == 3 {
				if arg, ok := n.Args[2].(*ast.Ident); ok {
					reports = append(reports, report{n.Pos(), arg.Name})
				}
			}
		}
		return true
	})
	var out []rosterWrite
	for _, call := range calls {
		w := rosterWrite{pos: call.Pos(), function: function, api: rosterWriteAPI(call)}
		name, ok := bound[call]
		if !ok {
			w.unreported, w.discarded, w.why = true, true, "does not bind its error to a name"
			out = append(out, w)
			continue
		}
		end := body.End()
		for _, b := range bindings {
			if b.name == name && b.call.Pos() > call.Pos() && b.call.Pos() < end {
				end = b.call.Pos()
			}
		}
		reported := false
		for _, r := range reports {
			if r.name == name && r.pos > call.Pos() && r.pos < end {
				reported = true
			}
		}
		if !reported {
			w.unreported, w.why = true, "never passes "+name+" to rosterBusyBanner"
		}
		out = append(out, w)
	}
	return out
}

func isRosterWriteCall(call *ast.CallExpr) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && (id.Name == "mutateRosterSource" || id.Name == "mutateRosterSourceValue")
}

// rosterWriteAPI is the inventory function the write's closure calls.
func rosterWriteAPI(call *ast.CallExpr) string {
	api := "?"
	lit, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
	if !ok {
		return api
	}
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if inner, ok := n.(*ast.CallExpr); ok && api == "?" {
			if sel, ok := inner.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "inventory" {
					api = sel.Sel.Name
				}
			}
		}
		return api == "?"
	})
	return api
}

// The audit sees each way Go binds or drops a roster write's error.
func TestRegression_EditRosterWritesReportABusyRosterMatcher(t *testing.T) {
	for name, tc := range map[string]struct {
		body       string
		unreported int
	}{
		"if-init reported":               {`if err := mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) }); err != nil { if b, ok := rosterBusyBanner(r, p, err); ok { _ = b } }`, 0},
		"if-init unreported":             {`if err := mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) }); err != nil { r.err = err }`, 1},
		"value := reported":              {`x, err := mutateRosterSourceValue(s, p, func() (bool, error) { return inventory.AppendMissingNFSServerStub(p, "h", "d") }); if b, busy := rosterBusyBanner(r, p, err); busy { _ = b }; _ = x`, 0},
		"value := unreported":            {`x, err := mutateRosterSourceValue(s, p, func() (bool, error) { return inventory.AppendMissingNFSServerStub(p, "h", "d") }); if err != nil { r.err = err }; _ = x`, 1},
		"= reported":                     {`var err error; err = mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) }); rosterBusyBanner(r, p, err)`, 0},
		"best-effort if-init":            {`if res, err := mutateRosterSourceValue(s, p, func() (inventory.RosterMigrationResult, error) { return inventory.EnsureRosterCurrent(p, o) }); err == nil && res.Changed { }`, 1},
		"discarded":                      {`mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) })`, 1},
		"blank":                          {`_ = mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) })`, 1},
		"blank error of a value":         {`x, _ := mutateRosterSourceValue(s, p, func() (bool, error) { return inventory.AppendMissingNFSServerStub(p, "h", "d") }); _ = x`, 1},
		"returned":                       {`return mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) })`, 1},
		"reported before the write":      {`var err error; rosterBusyBanner(r, p, err); err = mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) })`, 1},
		"second write shares the name":   {`err := mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) }); err = mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "b", nil) }); rosterBusyBanner(r, p, err)`, 1},
		"reported in another function":   {`err := mutateRosterSource(s, p, func() error { return inventory.SetRosterUser(p, "a", nil) }); later(func() { rosterBusyBanner(r, p, err) })`, 1},
		"derived error is still checked": {`x, err := mutateRosterSourceValue(s, p, func() (bool, error) { return inventory.AppendMissingNFSServerStub(p, "h", "d") }); if err == nil { err = probe() }; rosterBusyBanner(r, p, err); _ = x`, 0},
	} {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "x.go", "package cmd\nfunc f() error {\n"+tc.body+"\nreturn nil }", 0)
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			for _, w := range unreportedRosterWrites(file) {
				if w.unreported {
					got++
				}
			}
			if got != tc.unreported {
				t.Fatalf("unreported = %d, want %d", got, tc.unreported)
			}
		})
	}
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
