// ci_impact_narrow_readers_test.go closes the class behind a PR #357 finding.
//
// scripts/ci-impact.py gives a PR whose paths all sit under .agents/skills/**,
// .claude/skills/**, .claude/agents/** (profile "skills") or under
// docs/superpowers/{plans,specs}/** and docs/evidence/** Markdown (profile
// "docs") a reduced CI: the Go test shards, and with them internal/spec, do not
// run. A Go test that reads those paths, most often by walking the repository
// root, then has no run on exactly the PRs that can break it, and main's full
// push run turns red afterwards (a ControlPath template in
// .agents/skills/x/connect.py, a gopkg.in/yaml.v3 import in
// .agents/skills/x/tool/main.go).
//
// The invariant: every Test* function that walks the repository root, or that
// opens a path under .agents, .claude, docs/superpowers or docs/evidence, is
// either selected by the `skills` job of ci.yml (the Makefile targets and
// `go test -run` steps it runs, read from the workflow and the Makefile, so
// there is one source) or listed in narrowPathReaderExemptions with a reason
// that was checked by reading the test.
//
// Blind spots (the guard reads syntax, it does not run the tests):
//   - a root held in a variable that is not assigned, in the same function, a
//     repoRoot*() call, filepath.Join("..", "..", ...) or a "../.." literal
//     (for example a root passed in as a parameter, or a package-level var);
//   - walks and reads hidden in helper functions of non-test files, methods, or
//     closures stored in package-level variables (only top-level functions of
//     the same package's _test.go files are followed, by plain identifier call);
//   - tools the test runs (exec of python3, git, find) that read those paths;
//   - a path assembled from variables or constants instead of string literals;
//   - Go test files outside cmd/, internal/ and images/.
//
// A new reader that escapes those shapes still needs a reviewer; the common
// shapes (the two that broke, and every shape the existing tests use) are
// covered, and the detector's own cases below show each one firing.
package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// narrowPathDirs are the repository paths whose changes can be a narrow PR on
// their own (path_kind in scripts/ci-impact.py).
var narrowPathDirs = [][]string{
	{".agents"}, {".claude"}, {"docs", "superpowers"}, {"docs", "evidence"},
}

// narrowReaderRoots are the top-level directories whose _test.go files are
// scanned.
var narrowReaderRoots = []string{"cmd", "internal", "images"}

// narrowPathReaderExemptions lists tests that match the guard's shapes but
// are not exposed to a narrow PR. Key: "<package dir>.<test name>". Every
// entry was checked by reading the test; the guard also fails when an entry is
// not needed any more, so the map cannot go stale.
var narrowPathReaderExemptions = map[string]string{
	"cmd/pilot/cmd.TestConfigSecretPaths_AllRosterSourceWritesCarryWorkspace": "walks the repository root but reads only non-test .go files and skips every dot-directory (.agents, .claude) and the .md-only docs/superpowers and docs/evidence",
	"cmd/pilot/cmd.TestEvidenceCapturesChildStderrAndPreservesChannels":       evidenceFixtureReason,
	"cmd/pilot/cmd.TestEvidenceCapturesControllerDiagnosticsForRedaction":     evidenceFixtureReason,
	"cmd/pilot/cmd.TestEvidenceFreezesInputsBeforeRunAndRejectsDrift":         evidenceFixtureReason,
	"cmd/pilot/cmd.TestEvidenceSanitizesFailureMetadata":                      evidenceFixtureReason,
	"cmd/pilot/cmd.TestEvidenceSessionFailureRecordsTheStepAndSkipsLatest":    evidenceFixtureReason,
	"cmd/pilot/cmd.TestEvidenceSessionWritesARecordAndLatest":                 evidenceFixtureReason,
	"cmd/pilot/cmd.TestEvidenceUnsupportedDispatchOmitsSecretPayload":         evidenceFixtureReason,
	"cmd/pilot/cmd.TestRecordedIdempotencySemanticsAndRollbackAttribution":    evidenceFixtureReason,
}

const evidenceFixtureReason = "reads and writes docs/evidence only under a t.TempDir copy of internal/evidence/testdata/closure (copyFixtureTree); never the real tree"

// narrowHit is a Test* function with a reason it can read narrow-PR paths.
type narrowHit struct {
	Dir, Test, Why string
}

func (h narrowHit) key() string { return h.Dir + "." + h.Test }

var fsAccessFuncs = map[string]bool{
	"os.ReadFile": true, "os.Open": true, "os.OpenFile": true, "os.Stat": true, "os.Lstat": true,
	"os.ReadDir": true, "filepath.Glob": true, "fs.Glob": true, "fs.ReadFile": true,
}

func selectorName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return id.Name + "." + sel.Sel.Name
		}
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

var parentsOnlyRE = regexp.MustCompile(`^(\.\./?)+$`)

// isRepoRootExpr reports whether e denotes the repository root: a repoRoot*()
// helper call, filepath.Join of only ".." literals, a "../.." literal, or an
// identifier the same function assigned one of those.
func isRepoRootExpr(e ast.Expr, roots map[string]bool) bool {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return isRepoRootExpr(v.X, roots)
	case *ast.Ident:
		return roots[v.Name]
	case *ast.BasicLit:
		s, ok := stringLit(v)
		return ok && parentsOnlyRE.MatchString(s) && strings.Contains(s, "/")
	case *ast.CallExpr:
		name := selectorName(v.Fun)
		if strings.HasPrefix(name, "repoRoot") {
			return true
		}
		if name == "filepath.Join" || name == "path.Join" {
			if len(v.Args) < 2 {
				return false
			}
			for _, a := range v.Args {
				if s, ok := stringLit(a); !ok || s != ".." {
					return false
				}
			}
			return true
		}
	}
	return false
}

// walkRootArg returns the root argument of a Walk call, or nil.
func walkRootArg(call *ast.CallExpr) ast.Expr {
	switch selectorName(call.Fun) {
	case "filepath.Walk", "filepath.WalkDir":
		if len(call.Args) >= 1 {
			return call.Args[0]
		}
	case "fs.WalkDir":
		if len(call.Args) >= 2 {
			return call.Args[1]
		}
	}
	return nil
}

// hasNarrowComponents reports whether the slash-separated components of s
// contain one of narrowPathDirs as a contiguous run.
func hasNarrowComponents(parts []string) string {
	for _, dir := range narrowPathDirs {
		for i := 0; i+len(dir) <= len(parts); i++ {
			if slicesEqualStr(parts[i:i+len(dir)], dir) {
				return strings.Join(dir, "/")
			}
		}
	}
	return ""
}

func slicesEqualStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func splitPathLit(s string) []string {
	return strings.Split(path.Clean(strings.ReplaceAll(s, "\\", "/")), "/")
}

// narrowLiteral returns the narrow directory a path literal or the literal
// components of a filepath.Join call name, or "".
func narrowLiteral(n ast.Node) string {
	switch v := n.(type) {
	case *ast.BasicLit:
		if s, ok := stringLit(v); ok {
			return hasNarrowComponents(splitPathLit(s))
		}
	case *ast.CallExpr:
		if name := selectorName(v.Fun); name == "filepath.Join" || name == "path.Join" {
			var parts []string
			for _, a := range v.Args {
				if s, ok := stringLit(a); ok {
					parts = append(parts, splitPathLit(s)...)
				} else {
					// A non-literal argument breaks adjacency.
					parts = append(parts, "\x00")
				}
			}
			return hasNarrowComponents(parts)
		}
	}
	return ""
}

// funcFacts is what one top-level function does and calls.
type funcFacts struct {
	test  bool
	why   []string
	calls map[string]bool
}

func scanFuncDecl(fn *ast.FuncDecl) funcFacts {
	facts := funcFacts{test: fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test"), calls: map[string]bool{}}
	if fn.Body == nil {
		return facts
	}
	roots := map[string]bool{}
	// Repo-root identifiers may be assigned anywhere before use; iterate to a
	// fixed point so `a := repoRoot(t); b := a` is followed.
	for changed := true; changed; {
		changed = false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			mark := func(lhs ast.Expr, rhs ast.Expr) {
				if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && !roots[id.Name] && isRepoRootExpr(rhs, roots) {
					roots[id.Name] = true
					changed = true
				}
			}
			if len(assign.Lhs) == len(assign.Rhs) {
				for i := range assign.Lhs {
					mark(assign.Lhs[i], assign.Rhs[i])
				}
			} else if len(assign.Rhs) == 1 {
				// root, err := repoRootForRepairClientTest(): the first result.
				mark(assign.Lhs[0], assign.Rhs[0])
			}
			return true
		})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range vs.Names {
				if i < len(vs.Values) && name.Name != "_" && !roots[name.Name] && isRepoRootExpr(vs.Values[i], roots) {
					roots[name.Name] = true
					changed = true
				}
			}
			return true
		})
	}
	var narrow []string
	access := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				facts.calls[id.Name] = true
			}
			if root := walkRootArg(call); root != nil && isRepoRootExpr(root, roots) {
				facts.why = append(facts.why, "walks the repository root")
			}
			if fsAccessFuncs[selectorName(call.Fun)] {
				access = true
			}
		}
		if dir := narrowLiteral(n); dir != "" {
			narrow = append(narrow, dir)
		}
		return true
	})
	if access && len(narrow) > 0 {
		sort.Strings(narrow)
		facts.why = append(facts.why, "opens a path under "+narrow[0])
	}
	return facts
}

// scanNarrowPathReaders returns the Test* functions of one package (one
// directory's parsed files) that read narrow-PR paths, directly or through
// the package's other top-level test-file functions.
func scanNarrowPathReaders(dir string, files []*ast.File) []narrowHit {
	facts := map[string]funcFacts{}
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				facts[fn.Name.Name] = scanFuncDecl(fn)
			}
		}
	}
	var hits []narrowHit
	var names []string
	for name, f := range facts {
		if f.test {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, test := range names {
		seen := map[string]bool{}
		var why []string
		var visit func(name string)
		visit = func(name string) {
			if seen[name] {
				return
			}
			seen[name] = true
			f, ok := facts[name]
			if !ok {
				return
			}
			for _, w := range f.why {
				if name != test {
					w += " (via " + name + ")"
				}
				why = append(why, w)
			}
			for callee := range f.calls {
				visit(callee)
			}
		}
		visit(test)
		if len(why) > 0 {
			sort.Strings(why)
			hits = append(hits, narrowHit{Dir: dir, Test: test, Why: why[0]})
		}
	}
	return hits
}

type goTestSelector struct{ pkg, run string }

var (
	goTestPkgRE = regexp.MustCompile(`(?:^|\s)(\./[A-Za-z0-9_./-]+)`)
	goTestRunRE = regexp.MustCompile(`-run[ =](?:'([^']*)'|"([^"]*)"|(\S+))`)
)

// skillsJobSelectors returns every `go test <pkg> -run <re>` the workflow's
// skills job runs, directly or through a `make <target>` step.
func skillsJobSelectors(t *testing.T, ciYAML, makefile string) []goTestSelector {
	t.Helper()
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	job, ok := wf.Jobs["skills"]
	if !ok {
		t.Fatal("ci.yml has no skills job")
	}
	var selectors []goTestSelector
	for _, step := range job.Steps {
		var lines []string
		if m := makeStepRE.FindStringSubmatch(strings.TrimSpace(step.Run)); m != nil {
			lines = makeTargetRecipe(t, makefile, m[1])
			for i := range lines {
				// make passes `$$` to the shell as `$`.
				lines[i] = strings.ReplaceAll(lines[i], "$$", "$")
			}
		} else {
			lines = strings.Split(step.Run, "\n")
		}
		for _, line := range lines {
			if !strings.Contains(line, "go test") {
				continue
			}
			pkg := goTestPkgRE.FindStringSubmatch(line)
			run := goTestRunRE.FindStringSubmatch(line)
			if pkg == nil || run == nil {
				continue
			}
			re := run[1] + run[2] + run[3]
			// go test -run splits on '/' per subtest level; the first
			// element selects the top-level test.
			if i := strings.Index(re, "/"); i >= 0 {
				re = re[:i]
			}
			selectors = append(selectors, goTestSelector{pkg: strings.TrimPrefix(pkg[1], "./"), run: re})
		}
	}
	return selectors
}

func (s goTestSelector) selects(dir, test string) bool {
	if s.pkg != dir {
		return false
	}
	ok, err := regexp.MatchString(s.run, test)
	return err == nil && ok
}

// unselectedNarrowReaders returns the hits no skills-job selector runs and no
// exemption covers, plus the exemptions that are not needed.
func unselectedNarrowReaders(hits []narrowHit, selectors []goTestSelector, exempt map[string]string) (missing []string, stale []string) {
	used := map[string]bool{}
	for _, h := range hits {
		selected := false
		for _, s := range selectors {
			if s.selects(h.Dir, h.Test) {
				selected = true
			}
		}
		if _, ok := exempt[h.key()]; ok {
			used[h.key()] = true
			if selected {
				stale = append(stale, h.key()+" is exempt but the skills job already runs it")
			}
			continue
		}
		if !selected {
			missing = append(missing, h.key()+" "+h.Why)
		}
	}
	for key := range exempt {
		if !used[key] {
			stale = append(stale, key+" is exempt but no longer matches a narrow-path reader")
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	return missing, stale
}

func parseTestPackages(t *testing.T, root string) map[string][]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string][]*ast.File{}
	for _, top := range narrowReaderRoots {
		start := filepath.Join(root, top)
		if _, err := os.Stat(start); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		err := filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, filepath.Dir(p))
			if err != nil {
				return err
			}
			dir := filepath.ToSlash(rel)
			pkgs[dir] = append(pkgs[dir], f)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return pkgs
}

func scanAllNarrowPathReaders(t *testing.T, root string) []narrowHit {
	t.Helper()
	pkgs := parseTestPackages(t, root)
	dirs := make([]string, 0, len(pkgs))
	for dir := range pkgs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	var hits []narrowHit
	for _, dir := range dirs {
		hits = append(hits, scanNarrowPathReaders(dir, pkgs[dir])...)
	}
	return hits
}

// TestCIImpactNarrowPathReadersRunInSkillsJob is the class guard.
func TestCIImpactNarrowPathReadersRunInSkillsJob(t *testing.T) {
	root := repoRootForTest(t)
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	selectors := skillsJobSelectors(t, string(ci), string(mk))
	hits := scanAllNarrowPathReaders(t, root)
	if len(hits) == 0 {
		t.Fatal("the scan found no narrow-path reader at all: the guard no longer detects the shapes it is meant to")
	}
	missing, stale := unselectedNarrowReaders(hits, selectors, narrowPathReaderExemptions)
	for _, m := range missing {
		t.Errorf("%s, but the skills job does not run it: a skills/docs-only PR would skip it and break main's full run.\n"+
			"Add it to the `skill-repo-lint` Makefile target's -run pattern, or list it in narrowPathReaderExemptions with the reason it cannot read those paths", m)
	}
	for _, s := range stale {
		t.Error(s)
	}
}

// Detector cases: each source is parsed as a package with one file.
const (
	srcWalkRootJoin = `package p
import ("io/fs";"path/filepath";"testing")
func TestA(t *testing.T) {
	root := filepath.Join("..", "..")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { return nil })
}`
	srcWalkRootLiteral = `package p
import ("path/filepath";"testing")
func TestA(t *testing.T) { _ = filepath.Walk("../..", nil) }`
	srcWalkRootHelper = `package p
import ("io/fs";"path/filepath";"testing")
func TestA(t *testing.T) {
	root, err := repoRootForSomething()
	_ = err
	dir := root
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error { return nil })
}`
	srcWalkFSRoot = `package p
import ("io/fs";"os";"testing")
func TestA(t *testing.T) { _ = fs.WalkDir(os.DirFS("."), repoRootForTest(t), nil) }`
	srcWalkViaHelper = `package p
import ("io/fs";"path/filepath";"testing")
func scanRepo(t *testing.T) {
	_ = filepath.WalkDir(repoRootForTest(t), func(p string, d fs.DirEntry, err error) error { return nil })
}
func TestA(t *testing.T) { scanRepo(t) }
func TestB(t *testing.T) {}`
	srcReadSkillFile = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) {
	p := filepath.Join(repoRootForTest(t), ".agents", "skills", "x", "SKILL.md")
	_, _ = os.ReadFile(p)
}`
	srcReadDocsSpecs = `package p
import ("os";"testing")
func TestA(t *testing.T) { _, _ = os.ReadDir("../../docs/superpowers/specs") }`
	srcReadDocsEvidenceGlob = `package p
import ("path/filepath";"testing")
func TestA(t *testing.T) { _, _ = filepath.Glob("../../docs/evidence/*/*.md") }`
	srcWalkSubtree = `package p
import ("io/fs";"path/filepath";"testing")
func TestA(t *testing.T) {
	root := repoRootForTest(t)
	_ = filepath.WalkDir(filepath.Join(root, "playbooks"), func(p string, d fs.DirEntry, err error) error { return nil })
	_ = filepath.WalkDir("../../playbooks", func(p string, d fs.DirEntry, err error) error { return nil })
}`
	srcTempDirWalk = `package p
import ("io/fs";"path/filepath";"testing")
func TestA(t *testing.T) {
	root := t.TempDir()
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { return nil })
}`
	srcMentionOnly = `package p
import "testing"
func TestA(t *testing.T) { _ = ".agents/skills"; _ = []string{".claude"} }`
	srcJoinBreaksAdjacency = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { dir := "docs"; _, _ = os.ReadDir(filepath.Join("docs", dir, "superpowers")) }`
)

func TestCIImpactNarrowPathReaderDetector(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string // Test names expected to be reported
	}{
		{"walk of filepath.Join(..,..)", srcWalkRootJoin, []string{"TestA"}},
		{"walk of a ../.. literal", srcWalkRootLiteral, []string{"TestA"}},
		{"walk of a repoRoot*() result through an alias", srcWalkRootHelper, []string{"TestA"}},
		{"fs.WalkDir takes the root as its second argument", srcWalkFSRoot, []string{"TestA"}},
		{"walk in a helper reaches only its callers", srcWalkViaHelper, []string{"TestA"}},
		{"read under .agents via filepath.Join", srcReadSkillFile, []string{"TestA"}},
		{"read under docs/superpowers", srcReadDocsSpecs, []string{"TestA"}},
		{"glob under docs/evidence", srcReadDocsEvidenceGlob, []string{"TestA"}},
		{"walk of a subtree is not a root walk", srcWalkSubtree, nil},
		{"walk of a temp dir", srcTempDirWalk, nil},
		{"mentioning the paths without reading anything", srcMentionOnly, nil},
		{"a variable in the middle breaks the component run", srcJoinBreaksAdjacency, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "x_test.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, h := range scanNarrowPathReaders("p", []*ast.File{f}) {
				got = append(got, h.Test)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("reported %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCIImpactNarrowPathSelectionCases(t *testing.T) {
	const ci = "jobs:\n  skills:\n    steps:\n" +
		"      - run: make skill-repo-lint\n" +
		"      - run: go test -count=1 -timeout 5m ./cmd/pilot/cmd -run '^TestAgentSkill'\n" +
		"      - run: python3 scripts/check-yaml-duplicate-keys.py\n"
	const mk = "skill-repo-lint: ## x\n\tgo test -count=1 -timeout 10m ./internal/spec -run '^(TestOne|TestTwo)$'\n"
	selectors := skillsJobSelectors(t, ci, mk)
	hit := func(dir, test string) narrowHit {
		return narrowHit{Dir: dir, Test: test, Why: "walks the repository root"}
	}
	cases := []struct {
		name    string
		hits    []narrowHit
		exempt  map[string]string
		missing int
		stale   int
	}{
		{"selected through make", []narrowHit{hit("internal/spec", "TestOne")}, nil, 0, 0},
		{"selected by the layout step", []narrowHit{hit("cmd/pilot/cmd", "TestAgentSkillLayout")}, nil, 0, 0},
		{"a lint dropped from the selector", []narrowHit{hit("internal/spec", "TestThree")}, nil, 1, 0},
		{"same name in another package is not selected", []narrowHit{hit("internal/other", "TestOne")}, nil, 1, 0},
		{"exempt with a reason", []narrowHit{hit("internal/spec", "TestThree")}, map[string]string{"internal/spec.TestThree": "r"}, 0, 0},
		{"exemption that is already selected is stale", []narrowHit{hit("internal/spec", "TestOne")}, map[string]string{"internal/spec.TestOne": "r"}, 0, 1},
		{"exemption without a hit is stale", nil, map[string]string{"internal/spec.TestGone": "r"}, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			missing, stale := unselectedNarrowReaders(tc.hits, selectors, tc.exempt)
			if len(missing) != tc.missing || len(stale) != tc.stale {
				t.Fatalf("missing %v stale %v, want %d and %d", missing, stale, tc.missing, tc.stale)
			}
		})
	}
}
