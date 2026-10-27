package cmd

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Audit every production caller of the derived source-writer APIs, including
// providers and non-editor entrypoints. Exempt only exact path-only CLI calls.
func TestConfigSecretPaths_AllRosterSourceWritesCarryWorkspace(t *testing.T) {
	writers := rosterSourceWriterAPIs(t)
	root := repoRootForTest(t)
	// These four commands accept only a roster path. They have no selected
	// inventory/workspace input to retain and use the lower cwd/source-path
	// guard. Count each exact API call so new writes require their own audit.
	pathOnly := map[string]string{
		"cmd/pilot/cmd/access_review_cli.go|runAccessReviewMarkCmd|MarkGrantReviewedFile":                "review mark accepts roster path, reviewer and Vault options only",
		"cmd/pilot/cmd/identity_review_cli.go|runIdentityReviewMarkCmd|MarkCredentialPolicyReviewedFile": "identity review mark accepts roster path, reviewer and Vault options only",
		"cmd/pilot/cmd/roster_lint.go|rosterLintCmd|MigrateRosterFile":                                   "standalone lint --upgrade explicitly needs no inventory",
		"cmd/pilot/cmd/roster_migrate.go|rosterMigrateCmd|MigrateRosterFile":                             "standalone migration accepts roster path and migration/Vault options only",
	}
	usedExemptions := make(map[string]int)
	total, guarded, exempted := 0, 0, 0
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "tmp" || entry.Name() == "vendor" || entry.Name() == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Contains(data, []byte(`"github.com/kjelly/pilot/internal/inventory"`)) {
			return nil
		}
		file, err := parser.ParseFile(fset, path, data, 0)
		if err != nil {
			return err
		}
		aliases := rosterInventoryAliases(file)
		missing := make(map[token.Pos]bool)
		for _, pos := range unguardedRosterWrites(file, writers) {
			missing[pos] = true
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if _, writes := rosterInventoryWriteWithAliases(call, writers, aliases); !writes {
				return true
			}
			total++
			selector := call.Fun.(*ast.SelectorExpr)
			key := filepath.ToSlash(rel) + "|" + rosterWriteOwner(file, call.Pos()) + "|" + selector.Sel.Name
			if _, ok := pathOnly[key]; ok {
				if rosterHasWorkspaceOption(file) {
					t.Errorf("%s gained a workspace/inventory option; its path-only exemption must be removed", key)
				}
				usedExemptions[key]++
				exempted++
			} else if missing[call.Pos()] {
				t.Errorf("%s: %s source write lost selected workspace; guard the actual mutation", fset.Position(call.Pos()), selector.Sel.Name)
			} else {
				guarded++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for key, reason := range pathOnly {
		if usedExemptions[key] != 1 {
			t.Errorf("path-only exemption %s used %d times, want exactly1 (%s)", key, usedExemptions[key], reason)
		}
	}
	t.Logf("audited %d writer APIs and %d production calls: %d guarded, %d path-only", len(writers), total, guarded, exempted)
}

func rosterWriteOwner(file *ast.File, pos token.Pos) string {
	for _, declaration := range file.Decls {
		if pos < declaration.Pos() || pos > declaration.End() {
			continue
		}
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			return declaration.Name.Name
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				if value, ok := spec.(*ast.ValueSpec); ok && pos >= value.Pos() && pos <= value.End() && len(value.Names) == 1 {
					return value.Names[0].Name
				}
			}
		}
	}
	return ""
}

func TestConfigSecretPaths_RosterWriteGuardMatcher(t *testing.T) {
	writers := rosterSourceWriterAPIs(t)
	for _, tc := range []struct {
		name, body string
		violations int
	}{
		{"unguarded", `inventory.SetRosterUser(path, "alice", nil)`, 1},
		{"guarded", `mutateRosterSource(r.writeScope(dir), path, func() error { return inventory.SetRosterUser(path, "alice", nil) })`, 0},
		{"guarded_literal_scope", `mutateRosterSource(editWriteScope{dir: dir}, path, func() error { return inventory.SetRosterUser(path, "alice", nil) })`, 0},
		{"guarded_scope_param", `mutateRosterSource(scope, path, func() error { return inventory.SetRosterUser(path, "alice", nil) })`, 0},
		{"screen_open_only", `validateSecretSourcePath(dir, path); later(func() { inventory.SetRosterUser(path, "alice", nil) })`, 1},
		{"delayed_inside_guard", `mutateRosterSource(r.writeScope(dir), path, func() error { later(func() { inventory.SetRosterUser(path, "alice", nil) }); return nil })`, 1},
		{"wrong_workspace", `mutateRosterSource(r.writeScope("."), path, func() error { return inventory.SetRosterUser(path, "alice", nil) })`, 1},
		{"wrong_literal_workspace", `mutateRosterSource(editWriteScope{dir: "."}, path, func() error { return inventory.SetRosterUser(path, "alice", nil) })`, 1},
		{"literal_scope_without_dir", `mutateRosterSource(editWriteScope{}, path, func() error { return inventory.SetRosterUser(path, "alice", nil) })`, 1},
		{"other_scope_variable", `mutateRosterSource(other, path, func() error { return inventory.SetRosterUser(path, "alice", nil) })`, 1},
		{"different_path", `mutateRosterSource(r.writeScope(dir), other, func() error { return inventory.SetRosterUser(path, "alice", nil) })`, 1},
		{"remove", `inventory.RemoveRosterUser(path, "alice", opts)`, 1},
		{"encrypted_mutation", `inventory.MutateEncryptedRosterFile(path, passwordFile, mutate)`, 1},
		{"nfs_without_roster_in_name", `inventory.AppendMissingNFSServerStub(path, "nfs", "example.test")`, 1},
		{"migration", `inventory.EnsureRosterCurrent(path, opts)`, 1},
		{"autofill", `inventory.AutoFillFreeIPAClientRosterHosts(dir, path)`, 1},
		{"typed_guard", `mutateRosterSourceValue(r.writeScope(dir), path, func() ([]string,error) { return inventory.AutoFillFreeIPAClientRosterHosts(dir, path) })`, 0},
		{"typed_wrong_path", `mutateRosterSourceValue(r.writeScope(dir), other, func() ([]string,error) { return inventory.AutoFillFreeIPAClientRosterHosts(dir, path) })`, 1},
		{"vault", `inventory.FillFreeIPAAdminPassword(path, "dummy")`, 1},
		{"read_only", `inventory.RosterUser(path, "alice")`, 0},
		{"provider_guard", `if err := validateDecommissionRosterSource(e.rosterPath, e.provider.cfg.ClientInventory, e.provider.cfg.ServerInventory); err != nil { return err }; inventory.SetRosterHostAbsent(e.rosterPath, e.fqdn)`, 0},
		{"provider_async_write", `if err := validateDecommissionRosterSource(e.rosterPath, e.provider.cfg.ClientInventory, e.provider.cfg.ServerInventory); err != nil { return err }; go inventory.SetRosterHostAbsent(e.rosterPath, e.fqdn)`, 1},
		{"provider_deferred_write", `if err := validateDecommissionRosterSource(e.rosterPath, e.provider.cfg.ClientInventory, e.provider.cfg.ServerInventory); err != nil { return err }; defer inventory.SetRosterHostAbsent(e.rosterPath, e.fqdn)`, 1},
		{"provider_wrong_config", `if err := validateDecommissionRosterSource(e.rosterPath, e.provider.cfg.Inventory); err != nil { return err }; inventory.SetRosterHostAbsent(e.rosterPath, e.fqdn)`, 1},
		{"provider_missing_server_context", `if err := validateDecommissionRosterSource(e.rosterPath, e.provider.cfg.ClientInventory); err != nil { return err }; inventory.SetRosterHostAbsent(e.rosterPath, e.fqdn)`, 1},
		{"provider_wrong_path", `if err := validateDecommissionRosterSource(other, e.provider.cfg.ClientInventory, e.provider.cfg.ServerInventory); err != nil { return err }; inventory.SetRosterHostAbsent(e.rosterPath, e.fqdn)`, 1},
		{"nfs_provider_guard", `if err := validateDecommissionRosterSource(e.rosterPath, e.provider.cfg.Inventory); err != nil { return err }; inventory.SetRosterNFSServerAbsent(e.rosterPath, e.fqdn)`, 0},
		{"remove_plain_guard", `if err := validateRosterRemoveSource(rosterPath, rosterRemoveUserInventory); err != nil { return err }; inventory.RemoveRosterUser(plainPath, name, opts)`, 0},
		{"remove_wrong_inventory", `if err := validateRosterRemoveSource(rosterPath, rosterRemoveGroupInventory); err != nil { return err }; inventory.RemoveRosterUser(plainPath, name, opts)`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "test.go", "package cmd; func f() {"+tc.body+"}", 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(unguardedRosterWrites(file, writers)); got != tc.violations {
				t.Fatalf("violations=%d want=%d", got, tc.violations)
			}
		})
	}
}

func unguardedRosterWrites(file *ast.File, writers map[string]int) []token.Pos {
	aliases := rosterInventoryAliases(file)
	if len(aliases) == 0 {
		aliases["inventory"] = true
	} // synthetic matcher fixtures
	guarded := make(map[*ast.CallExpr]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || (name.Name != "mutateRosterSource" && name.Name != "mutateRosterSourceValue") || !rosterGuardScope(call.Args[0]) {
			return true
		}
		body, ok := call.Args[2].(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(body.Body, func(inner ast.Node) bool {
			switch inner.(type) {
			case *ast.FuncLit, *ast.GoStmt, *ast.DeferStmt:
				// A nested callback or asynchronous/deferred call does not
				// establish an immediate persistence boundary.
				return false
			}
			if write, ok := inner.(*ast.CallExpr); ok {
				if index, ok := rosterInventoryWriteWithAliases(write, writers, aliases); ok && len(write.Args) > index && sameRosterGuardExpression(write.Args[index], call.Args[1]) {
					guarded[write] = true
				}
			}
			return true
		})
		return true
	})
	// Direct provider/CLI guards must dominate the next statement in the
	// same block; a screen-open check or a different callback does not count.
	ast.Inspect(file, func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i := 1; i < len(block.List); i++ {
			guard := rosterDirectSourceGuard(block.List[i-1])
			if guard == nil {
				continue
			}
			ast.Inspect(block.List[i], func(inner ast.Node) bool {
				switch inner.(type) {
				case *ast.BlockStmt, *ast.FuncLit, *ast.GoStmt, *ast.DeferStmt:
					return false
				}
				write, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if index, ok := rosterInventoryWriteWithAliases(write, writers, aliases); ok && len(write.Args) > index && rosterDirectGuardMatches(guard, write.Args[index], write.Fun.(*ast.SelectorExpr).Sel.Name, rosterWriteOwner(file, write.Pos())) {
					guarded[write] = true
				}
				return true
			})
		}
		return true
	})
	var violations []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if _, writes := rosterInventoryWriteWithAliases(call, writers, aliases); writes && !guarded[call] {
				violations = append(violations, call.Pos())
			}
		}
		return true
	})
	return violations
}

// rosterGuardScope reports whether expr is the write scope of the selected
// workspace dir: r.writeScope(dir), editWriteScope{dir: dir, ...}, or a
// scope parameter a caller built that way.
func rosterGuardScope(expr ast.Expr) bool {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name == "scope"
	case *ast.CallExpr:
		selector, ok := expr.Fun.(*ast.SelectorExpr)
		return ok && selector.Sel.Name == "writeScope" && len(expr.Args) == 1 && rosterGuardIdent(expr.Args[0], "dir")
	case *ast.CompositeLit:
		if !rosterGuardIdent(expr.Type, "editWriteScope") {
			return false
		}
		for _, element := range expr.Elts {
			if field, ok := element.(*ast.KeyValueExpr); ok && rosterGuardIdent(field.Key, "dir") {
				return rosterGuardIdent(field.Value, "dir")
			}
		}
	}
	return false
}

func rosterGuardIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

func rosterInventoryWriteWithAliases(call *ast.CallExpr, writers map[string]int, aliases map[string]bool) (int, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, false
	}
	name, ok := selector.X.(*ast.Ident)
	if !ok || !aliases[name.Name] {
		return 0, false
	}
	index, ok := writers[selector.Sel.Name]
	return index, ok
}

func rosterInventoryAliases(file *ast.File) map[string]bool {
	aliases := make(map[string]bool)
	for _, spec := range file.Imports {
		if spec.Path.Value != `"github.com/kjelly/pilot/internal/inventory"` {
			continue
		}
		name := "inventory"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		aliases[name] = true
	}
	return aliases
}

func rosterDirectSourceGuard(statement ast.Stmt) *ast.CallExpr {
	gate, ok := statement.(*ast.IfStmt)
	if !ok || gate.Else != nil || len(gate.Body.List) == 0 {
		return nil
	}
	assign, ok := gate.Init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return nil
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil
	}
	condition, ok := gate.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ || !sameRosterGuardExpression(condition.X, assign.Lhs[0]) || !rosterGuardIdent(condition.Y, "nil") {
		return nil
	}
	if _, ok := gate.Body.List[len(gate.Body.List)-1].(*ast.ReturnStmt); !ok {
		return nil
	}
	return call
}

func rosterDirectGuardMatches(guard *ast.CallExpr, path ast.Expr, api, owner string) bool {
	name, ok := guard.Fun.(*ast.Ident)
	if !ok || len(guard.Args) < 2 {
		return false
	}
	samePath := sameRosterGuardExpression(path, guard.Args[0])
	if name.Name == "validateRosterRemoveSource" && len(guard.Args) == 2 {
		plaintextRemoval := (api == "RemoveRosterUser" || api == "RemoveRosterGroup") && rosterGuardIdent(path, "plainPath") && rosterGuardIdent(guard.Args[0], "rosterPath")
		if !samePath && !plaintextRemoval {
			return false
		}
		switch api {
		case "RemoveRosterUser":
			return rosterGuardIdent(guard.Args[1], "rosterRemoveUserInventory")
		case "RemoveRosterGroup":
			return rosterGuardIdent(guard.Args[1], "rosterRemoveGroupInventory")
		case "MutateEncryptedRosterFile":
			return owner == "runRosterRemoveUser" && rosterGuardIdent(guard.Args[1], "rosterRemoveUserInventory") || owner == "runRosterRemoveGroup" && rosterGuardIdent(guard.Args[1], "rosterRemoveGroupInventory")
		}
		return false
	}
	if name.Name == "validateDecommissionRosterSource" && samePath {
		var arguments []string
		for _, arg := range guard.Args[1:] {
			var buf bytes.Buffer
			if format.Node(&buf, token.NewFileSet(), arg) != nil {
				return false
			}
			arguments = append(arguments, buf.String())
		}
		switch api {
		case "RemoveRosterHostReferences", "SetRosterHostAbsent":
			return strings.Join(arguments, ",") == "e.provider.cfg.ClientInventory,e.provider.cfg.ServerInventory"
		case "SetRosterNFSServerAbsent":
			return strings.Join(arguments, ",") == "e.provider.cfg.Inventory"
		}
	}
	return false
}

func rosterHasWorkspaceOption(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (selector.Sel.Name != "StringVar" && selector.Sel.Name != "StringVarP" && selector.Sel.Name != "String" && selector.Sel.Name != "StringP") {
			return true
		}
		for _, arg := range call.Args {
			if literal, ok := arg.(*ast.BasicLit); ok && (literal.Value == `"dir"` || literal.Value == `"inventory"` || literal.Value == `"workspace"`) {
				found = true
			}
		}
		return true
	})
	return found
}

// Removing any real provider/CLI pre-write guard must make precisely its
// source write fail the global invariant. This challenges current source
// structure without editing or executing production mutation code.
func TestConfigSecretPaths_GlobalGuardDetectsRemovedProviderAndCLIGuards(t *testing.T) {
	writers := rosterSourceWriterAPIs(t)
	root := repoRootForTest(t)
	checked := 0
	for _, path := range []string{"internal/decommission/providers/freeipa_client.go", "internal/decommission/providers/freeipa_nfs_server.go", "cmd/pilot/cmd/roster_remove_user.go", "cmd/pilot/cmd/roster_remove_group.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if missing := unguardedRosterWrites(file, writers); len(missing) != 0 {
			t.Fatalf("%s has %d unguarded writes before challenge", path, len(missing))
		}
		ast.Inspect(file, func(node ast.Node) bool {
			block, ok := node.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i := 1; i < len(block.List); i++ {
				guard := rosterDirectSourceGuard(block.List[i-1])
				if guard == nil {
					continue
				}
				matches := false
				ast.Inspect(block.List[i], func(inner ast.Node) bool {
					switch inner.(type) {
					case *ast.BlockStmt, *ast.FuncLit, *ast.GoStmt, *ast.DeferStmt:
						return false
					}
					if write, ok := inner.(*ast.CallExpr); ok {
						if index, writes := rosterInventoryWriteWithAliases(write, writers, rosterInventoryAliases(file)); writes && len(write.Args) > index && rosterDirectGuardMatches(guard, write.Args[index], write.Fun.(*ast.SelectorExpr).Sel.Name, rosterWriteOwner(file, write.Pos())) {
							matches = true
						}
					}
					return true
				})
				if !matches {
					continue
				}
				original := block.List
				challenged := append([]ast.Stmt{}, original[:i-1]...)
				block.List = append(challenged, original[i:]...)
				missing := unguardedRosterWrites(file, writers)
				block.List = original
				if len(missing) != 1 {
					t.Errorf("%s guard removal revealed %d writes, want1", path, len(missing))
				}
				checked++
			}
			return true
		})
	}
	if checked != 7 {
		t.Fatalf("challenged %d direct guards, want7 (3 provider +4 CLI source writes)", checked)
	}
}

func sameRosterGuardExpression(a, b ast.Expr) bool {
	var left, right bytes.Buffer
	fset := token.NewFileSet()
	return format.Node(&left, fset, a) == nil && format.Node(&right, fset, b) == nil && left.String() == right.String()
}

// Derive writer APIs from the actual original-source mutation sinks rather
// than API spelling. Read-only, validation and simulation helpers cannot
// reach these sinks. Migration backup creation counts because it copies
// secrets; decrypt scratch files and lock files do not mutate the source.
// A function that hands out a value whose method writes (the prepared
// sync PrepareRosterAdminSync returns, written by its Commit) is a writer
// too: the write is decided, and the roster locked, when it is called.
func rosterSourceWriterAPIs(t *testing.T) map[string]int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repoRootForTest(t), "internal", "inventory", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	graph := make(map[string][]string)
	declarations := make(map[string]*ast.FuncDecl)
	returnsType := make(map[string][]string)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			node := fn.Name.Name
			if fn.Recv != nil {
				// A method is "<receiver type>.<name>" in the graph.
				node = receiverTypeName(fn.Recv.List[0].Type) + "." + fn.Name.Name
			} else {
				declarations[node] = fn
				// A function returning a type points at its methods
				// ("<type>.") through returnsType.
				if fn.Type.Results != nil {
					for _, result := range fn.Type.Results.List {
						returnsType[node] = append(returnsType[node], receiverTypeName(result.Type))
					}
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if name, ok := call.Fun.(*ast.Ident); ok {
						graph[node] = append(graph[node], name.Name)
					}
				}
				return true
			})
		}
	}
	mutates := map[string]bool{"writeSecretSourceFile": true, "writeLockedRoster": true, "createRosterBackup": true}
	for sink := range mutates {
		if declarations[sink] == nil {
			t.Fatalf("credential source sink %s disappeared; update the mutation audit", sink)
		}
	}
	for changed := true; changed; {
		changed = false
		for name, calls := range graph {
			if mutates[name] {
				continue
			}
			for _, callee := range calls {
				if mutates[callee] {
					mutates[name], changed = true, true
					break
				}
			}
		}
	}
	for name, types := range returnsType {
		for method := range mutates {
			for _, typ := range types {
				if typ != "" && strings.HasPrefix(method, typ+".") {
					mutates[name] = true
				}
			}
		}
	}
	writers := make(map[string]int)
	for name := range mutates {
		if declarations[name] == nil || !ast.IsExported(name) {
			continue
		}
		index, found := 0, false
		for _, field := range declarations[name].Type.Params.List {
			for _, param := range field.Names {
				if param.Name == "path" {
					writers[name], found = index, true
				}
				index++
			}
		}
		if !found {
			t.Fatalf("writer %s needs an explicit source-path parameter audit", name)
		}
	}
	for _, name := range []string{"EnsureRosterCurrent", "AppendMissingNFSServerStub", "AutoFillFreeIPAClientRosterHosts", "FillFreeIPAAdminPassword", "WriteMinimalFreeIPAVault", "PrepareRosterAdminSync"} {
		if _, ok := writers[name]; !ok {
			t.Errorf("source call graph missed writer %s", name)
		}
	}
	for _, name := range []string{"RosterUser", "SimulateSetRosterUser", "ValidateRosterFile", "DecryptRosterToTempFile", "ProbeRosterLock", "RosterAdminPasswordDiffers"} {
		if _, ok := writers[name]; ok {
			t.Errorf("read-only source operation %s classified as an original-source mutation", name)
		}
	}
	return writers
}

// receiverTypeName is the type name in a receiver or result type, pointer
// or not: "PreparedRosterAdminSync" for *PreparedRosterAdminSync.
func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}
