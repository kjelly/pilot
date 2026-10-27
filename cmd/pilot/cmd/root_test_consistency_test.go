// root_test_consistency_test.go keeps the root-only tests running in CI:
// internal/inventory tests that call requireRoot skip as a normal user, so
// the Go test job never runs them; `make root-test` runs them as root, and
// CI's "Root-only ownership tests" job runs that target.
package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var rootTestsVarRE = regexp.MustCompile(`(?m)^ROOT_TESTS\s*:=\s*(.*)$`)

// rootOnlyTests lists the top-level tests in the test files srcs (name →
// source) that reach requireRoot, directly or through helpers in those
// files.
func rootOnlyTests(t *testing.T, srcs map[string]string) []string {
	t.Helper()
	calls := map[string][]string{}
	var tests []string
	fset := token.NewFileSet()
	for name, src := range srcs {
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "Test") {
				tests = append(tests, fn.Name.Name)
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok {
						calls[fn.Name.Name] = append(calls[fn.Name.Name], id.Name)
					}
				}
				return true
			})
		}
	}
	reaches := map[string]bool{"requireRoot": true}
	for changed := true; changed; {
		changed = false
		for fn, callees := range calls {
			if reaches[fn] {
				continue
			}
			for _, callee := range callees {
				if reaches[callee] {
					reaches[fn], changed = true, true
					break
				}
			}
		}
	}
	var out []string
	for _, name := range tests {
		if reaches[name] {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// checkRootTests reports why the Makefile or ci.yml does not run every
// root-only test as root, or "" when they do.
func checkRootTests(t *testing.T, want []string, makefile, ciYAML string) string {
	t.Helper()
	m := rootTestsVarRE.FindStringSubmatch(makefile)
	if m == nil {
		return "the Makefile sets no ROOT_TESTS"
	}
	listed := strings.Split(strings.TrimSpace(m[1]), "|")
	slices.Sort(listed)
	for _, name := range want {
		if !slices.Contains(listed, name) {
			return name + " calls requireRoot but is not in the Makefile's ROOT_TESTS"
		}
	}
	for _, name := range listed {
		if !slices.Contains(want, name) {
			return "ROOT_TESTS lists " + name + ", which does not call requireRoot (renamed or removed?)"
		}
	}
	recipe := strings.Join(makeTargetRecipe(t, makefile, "root-test"), "\n")
	for _, part := range []string{"go test -c", "./internal/inventory/", "cd internal/inventory", "sudo -n", "PILOT_REQUIRE_ROOT_TESTS=1", "-test.run '^($(ROOT_TESTS))$$'"} {
		if !strings.Contains(recipe, part) {
			return "root-test does not contain " + part + ": " + recipe
		}
	}
	var wf struct {
		Jobs map[string]struct {
			Name           string `yaml:"name"`
			TimeoutMinutes int    `yaml:"timeout-minutes"`
			Steps          []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if strings.TrimSpace(step.Run) != "make root-test" {
				continue
			}
			if job.TimeoutMinutes == 0 {
				return "the job running make root-test sets no timeout-minutes"
			}
			return ""
		}
	}
	return "no ci.yml job runs `make root-test`"
}

func TestRootOnlyTestsRunInCI(t *testing.T) {
	root := repoRootForTest(t)
	files, err := filepath.Glob(filepath.Join(root, "internal", "inventory", "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string]string{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		srcs[path] = string(data)
	}
	want := rootOnlyTests(t, srcs)
	if len(want) == 0 {
		t.Fatal("no internal/inventory test calls requireRoot; update this check")
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if msg := checkRootTests(t, want, string(mk), string(ci)); msg != "" {
		t.Fatal(msg)
	}
}

func TestRootOnlyTestsCheckCatchesDrift(t *testing.T) {
	srcs := map[string]string{"x_test.go": `package inventory
func requireRoot(t *testing.T) {}
func helper(t *testing.T) { requireRoot(t) }
func TestDirect(t *testing.T) { requireRoot(t) }
func TestThroughHelper(t *testing.T) { t.Run("sub", func(t *testing.T) { helper(t) }) }
func TestNormal(t *testing.T) {}
`}
	want := rootOnlyTests(t, srcs)
	if !slices.Equal(want, []string{"TestDirect", "TestThroughHelper"}) {
		t.Fatalf("rootOnlyTests() = %v", want)
	}
	const goodMake = "ROOT_TESTS := TestDirect|TestThroughHelper\n\nroot-test: ## x\n" +
		"\t@tmp=$$(mktemp -d) && go test -c -o \"$$tmp/inventory.test\" ./internal/inventory/ && cd internal/inventory && " +
		"sudo -n env PILOT_REQUIRE_ROOT_TESTS=1 \"$$tmp/inventory.test\" -test.run '^($(ROOT_TESTS))$$' -test.count=1\n\nnext:\n\ttrue\n"
	const goodCI = "jobs:\n  root-tests:\n    timeout-minutes: 10\n    steps:\n      - run: make root-test\n"
	for name, tc := range map[string]struct{ makefile, ci, want string }{
		"agree":              {goodMake, goodCI, ""},
		"test missing":       {strings.Replace(goodMake, "|TestThroughHelper", "", 1), goodCI, "TestThroughHelper calls requireRoot but is not in"},
		"stale name":         {strings.Replace(goodMake, "TestDirect|", "TestDirect|TestGone|", 1), goodCI, "lists TestGone"},
		"no sudo":            {strings.Replace(goodMake, "sudo -n ", "", 1), goodCI, "does not contain sudo -n"},
		"skips allowed":      {strings.Replace(goodMake, "PILOT_REQUIRE_ROOT_TESTS=1 ", "", 1), goodCI, "PILOT_REQUIRE_ROOT_TESTS=1"},
		"CI does not run it": {goodMake, strings.Replace(goodCI, "make root-test", "make test", 1), "no ci.yml job runs"},
		"no job timeout":     {goodMake, strings.Replace(goodCI, "    timeout-minutes: 10\n", "", 1), "sets no timeout-minutes"},
	} {
		t.Run(name, func(t *testing.T) {
			got := checkRootTests(t, want, tc.makefile, tc.ci)
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("checkRootTests() = %q, want %q", got, tc.want)
			}
		})
	}
}
