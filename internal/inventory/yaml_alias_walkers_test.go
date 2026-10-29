package inventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// aliasWalkers are the functions that follow aliases or merge keys through a
// node tree. They must be handed a tree parseYAMLDocument has checked, never
// parse one themselves: yaml.Unmarshal into a yaml.Node keeps every alias
// unexpanded and checks nothing, so a walker that parses its own input walks
// a graph that may refer to itself (PR #148 round 11).
var aliasWalkers = []string{"mappingValue", "mappingValueSeen", "resolveAlias", "rosterAdminPassword"}

// walkersThatParse names the functions in src that call both an alias walker
// and yaml.Unmarshal, other than the walkers themselves.
func walkersThatParse(t *testing.T, name string, src any) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || slices.Contains(aliasWalkers, fn.Name.Name) {
			continue
		}
		var walks, parses bool
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := call.Fun.(type) {
			case *ast.Ident:
				walks = walks || slices.Contains(aliasWalkers, f.Name)
			case *ast.SelectorExpr:
				if pkg, ok := f.X.(*ast.Ident); ok && pkg.Name == "yaml" && f.Sel.Name == "Unmarshal" {
					parses = true
				}
			}
			return true
		})
		if walks && parses {
			found = append(found, fn.Name.Name)
		}
	}
	return found
}

func TestAliasWalkersNeverParseYAMLThemselves(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if got := walkersThatParse(t, f, nil); len(got) != 0 {
			t.Errorf("%s: %v parse YAML and walk aliases; parse with parseYAMLDocument", f, got)
		}
	}
	// The check must fire: the shape it forbids, and the shape it allows.
	bad := "package p\nfunc read(d []byte) {\n var doc yaml.Node\n _ = yaml.Unmarshal(d, &doc)\n mappingValue(&doc, \"k\")\n}\n"
	if got := walkersThatParse(t, "bad.go", bad); !slices.Equal(got, []string{"read"}) {
		t.Fatalf("walkersThatParse(bad) = %v, want [read]", got)
	}
	good := "package p\nfunc read(d []byte) {\n doc, _ := parseYAMLDocument(d)\n mappingValue(doc, \"k\")\n}\nfunc other(d []byte) {\n var v any\n _ = yaml.Unmarshal(d, &v)\n}\n"
	if got := walkersThatParse(t, "good.go", good); len(got) != 0 {
		t.Fatalf("walkersThatParse(good) = %v, want none", got)
	}
}
