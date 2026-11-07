// ci_tagged_test.go keeps CI's step for the identity_live_hooks build in step with the tests
// that exist only in that build.
//
// The live driver of the Go identity reconcile builds pilot with the tag identity_live_hooks
// (internal/livehooks, spec 2026-11-06 phase 2 D31). Where the executor stops under it
// (TestExecuteStopsAt...) is what the driver's arms rely on, and such a test is compiled only
// with the tag, so a plain `go test` never runs it: CI had a step that built and vetted the
// tagged tree and tested only internal/livehooks, and the placement tests of the executor
// ran in nobody's CI. The check below finds every test function in a file with that build
// constraint and requires the step to run it, with the tag, so a placement test added
// later cannot be left out the same way.
package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	ciTaggedStepName = "go build, vet and test with the live-driver hooks"
	liveHooksTag     = "identity_live_hooks"
)

// taggedTestFunctions lists the test functions of the _test.go files under cmd and internal
// whose build constraint is the tag, by package directory (repo-relative, slash-separated).
func taggedTestFunctions(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !strings.Contains(string(data), "//go:build "+liveHooksTag+"\n") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			for _, decl := range file.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Test") {
					out[filepath.ToSlash(rel)] = append(out[filepath.ToSlash(rel)], fd.Name.Name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, names := range out {
		sort.Strings(names)
	}
	return out
}

var (
	ciGoTestTagsRE = regexp.MustCompile(`-tags[ =](\S+)`)
	ciGoTestRunRE  = regexp.MustCompile(`-run[ =]('[^']*'|"[^"]*"|\S+)`)
)

// ciTaggedProblems reports the tagged tests the step does not run, or "" lines when it runs them all.
func ciTaggedProblems(t *testing.T, ciYAML string, tagged map[string][]string) []string {
	t.Helper()
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	var run string
	found := false
	for _, step := range wf.Jobs["test"].Steps {
		if step.Name == ciTaggedStepName {
			run, found = step.Run, true
		}
	}
	if !found {
		return []string{"ci.yml has no step " + `"` + ciTaggedStepName + `"` + " in the test job: nothing builds or tests the " + liveHooksTag + " tree"}
	}
	// What each `go test -tags identity_live_hooks` line runs: package directory -> run patterns ("" = all).
	runs := map[string][]string{}
	for _, line := range strings.Split(run, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "go test ") {
			continue
		}
		tags := ciGoTestTagsRE.FindStringSubmatch(line)
		if tags == nil || !strings.Contains(","+tags[1]+",", ","+liveHooksTag+",") {
			continue
		}
		pattern := ""
		if m := ciGoTestRunRE.FindStringSubmatch(line); m != nil {
			pattern = strings.Trim(m[1], `'"`)
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "./") {
				dir := strings.TrimSuffix(strings.TrimPrefix(field, "./"), "/")
				runs[dir] = append(runs[dir], pattern)
			}
		}
	}
	var problems []string
	dirs := make([]string, 0, len(tagged))
	for dir := range tagged {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		patterns, ok := runs[dir]
		if !ok {
			problems = append(problems, dir+": has tests that exist only in the "+liveHooksTag+" build ("+strings.Join(tagged[dir], ", ")+") and the CI step does not run `go test -tags "+liveHooksTag+"` on it")
			continue
		}
	tests:
		for _, name := range tagged[dir] {
			for _, pattern := range patterns {
				if pattern == "" {
					continue tests // no -run: every test of the package
				}
				top, _, _ := strings.Cut(pattern, "/")
				re, err := regexp.Compile(top)
				if err != nil {
					problems = append(problems, dir+": the -run pattern "+pattern+" is not a regexp: "+err.Error())
					continue tests
				}
				if re.MatchString(name) {
					continue tests
				}
			}
			problems = append(problems, dir+": "+name+" exists only in the "+liveHooksTag+" build and no -run pattern of the CI step ("+strings.Join(patterns, ", ")+") selects it")
		}
	}
	return problems
}

func TestCITaggedStepRunsThePlacementTests(t *testing.T) {
	root := repoRootForTest(t)
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	tagged := taggedTestFunctions(t, root)
	// The tests this check exists for are there: if the scan stops finding them, it protects nothing.
	for dir, want := range map[string]string{
		"internal/identityreconcile": "TestExecuteStopsAtThePointsTheLiveDriverNames",
		"internal/livehooks":         "TestPauseStopsUntilTheDriverAnswersAndOnlyAtTheNamedPoints",
	} {
		found := false
		for _, name := range tagged[dir] {
			found = found || name == want
		}
		if !found {
			t.Fatalf("the scan does not find %s in %s (found %v): the check would pass for nothing", want, dir, tagged[dir])
		}
	}
	if problems := ciTaggedProblems(t, string(ci), tagged); len(problems) != 0 {
		t.Fatalf("CI does not run the tests of the %s build:\n%s", liveHooksTag, strings.Join(problems, "\n"))
	}
}

// The check fails on what it is for: the step without the executor's placement test (how CI was),
// a -run pattern that does not select it, a tagged test in a package the step does not test, the
// step gone, and a test line without the tag.
func TestCITaggedStepCheckCatchesDrift(t *testing.T) {
	tagged := map[string][]string{
		"internal/identityreconcile": {"TestExecuteStopsAtThePoints"},
		"internal/livehooks":         {"TestPause"},
	}
	ci := func(lines ...string) string {
		return "jobs:\n  test:\n    steps:\n      - name: " + ciTaggedStepName + "\n        run: |\n          " + strings.Join(lines, "\n          ") + "\n"
	}
	good := ci(
		"go build -tags identity_live_hooks ./...",
		"go test -count=1 -timeout 10m -tags identity_live_hooks ./internal/livehooks/",
		"go test -count=1 -timeout 10m -tags identity_live_hooks -run 'TestExecuteStopsAt' ./internal/identityreconcile/",
	)
	cases := []struct {
		name, ci, want string
	}{
		{"as it should be", good, ""},
		{"how CI was: only livehooks", ci("go test -count=1 -tags identity_live_hooks ./internal/livehooks/"), "internal/identityreconcile: has tests that exist only"},
		{"a -run pattern that selects nothing of it", strings.Replace(good, "TestExecuteStopsAt", "TestSomethingElse", 1), "TestExecuteStopsAtThePoints exists only in the identity_live_hooks build and no -run pattern"},
		{"the test line without the tag", strings.Replace(good, "-tags identity_live_hooks -run", "-run", 1), "internal/identityreconcile: has tests that exist only"},
		{"the step is gone", "jobs:\n  test:\n    steps:\n      - name: go test\n        run: make test-race\n", "has no step"},
	}
	extra := map[string][]string{"cmd/pilot/cmd": {"TestMixedPlacement"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := strings.Join(ciTaggedProblems(t, tc.ci, tagged), "\n")
			if tc.want == "" && problems != "" || tc.want != "" && !strings.Contains(problems, tc.want) {
				t.Fatalf("problems = %q, want %q", problems, tc.want)
			}
		})
	}
	t.Run("a new tagged test in a package the step never tests", func(t *testing.T) {
		more := map[string][]string{}
		for k, v := range tagged {
			more[k] = v
		}
		for k, v := range extra {
			more[k] = v
		}
		if problems := strings.Join(ciTaggedProblems(t, good, more), "\n"); !strings.Contains(problems, "cmd/pilot/cmd: has tests that exist only") {
			t.Fatalf("problems = %q", problems)
		}
	})
}
