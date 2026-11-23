// ci_impact_narrow_readers_test.go closes the class behind a PR #357 finding,
// and the same class for the PR-loop runner (issue #431).
//
// scripts/ci-impact.py gives a PR whose paths all sit under .agents/skills/**,
// .claude/skills/**, .claude/agents/** or are scripts/pr_loop.py (profile
// "skills"), or under docs/superpowers/{plans,specs}/** and docs/evidence/**
// Markdown (profile "docs"), a reduced CI: the Go test shards, and with them
// internal/spec, do not run, and neither do the other heavy jobs. Something
// that reads those paths then has no run on exactly the PRs that can break it,
// and main's full push run turns red afterwards (a ControlPath template in
// .agents/skills/x/connect.py, a gopkg.in/yaml.v3 import in
// .agents/skills/x/tool/main.go). The paths come from the constants of
// scripts/ci-impact.py (SKILL_PREFIXES, SKILL_FILES, DOC_PREFIXES, read by
// loadCIFastPaths); no list in this file repeats them.
//
// Two invariants:
//
//  1. Every Test* function that walks the repository root, or that reads a
//     fast-path path, is either selected by the `skills` job of ci.yml (the
//     Makefile targets and `go test -run` steps it runs, read from the workflow
//     and the Makefile, so there is one source) or listed in
//     narrowPathReaderExemptions with a reason that was checked by reading the
//     test. "Reads a fast-path path" means one of the access calls
//     (fsAccessFuncs: file reads and stats, Glob, Walk, os/exec) in a function
//     with a literal that equals, lies under, is an ancestor of or glob-matches
//     a fast-path path (ciFastPaths.match). The literal is anchored at the
//     repository root: the first argument of a filepath.Join is a repoRoot*()
//     call or an identifier assigned one (or a path below it), or the string
//     climbs exactly from the package directory to the root with "../" (a
//     package-level string constant counts). A directory prefix the constants
//     name (.agents/skills, docs/evidence, ...) also counts anywhere in a
//     literal. A path like .claude/settings.json is a full-profile path, so it
//     is no reader.
//  2. No heavy job (HEAVY_JOBS and ci-receipt) has a fast-path path among its
//     inputs other than through a Go test: its `run:` commands, the Makefile
//     recipes they run (variables expanded, prerequisites and $(MAKE) followed),
//     the repository scripts those commands run (one level), the
//     `unittest discover` directories, and the Dockerfile's COPY and ADD
//     sources. A heavy job only skipped on the fast path would otherwise stop
//     checking the file silently. A construct the test cannot expand or parse
//     is a failure naming it, never a pass.
//
// Blind spots (the guards read syntax, they do not run anything):
//   - a root held in a variable that the same function does not assign from a
//     repoRoot*() call, filepath.Join of ".." literals or a "../.." literal
//     (for example a root passed in as a parameter, or a package-level
//     variable assigned a call); a package-level string constant or variable
//     with a "../.." value is followed for the literals that name a path, not
//     for a walk of the root;
//   - walks and reads hidden in helper functions of non-test files, methods, or
//     closures stored in package-level variables (only top-level functions of
//     the same package's _test.go files are followed, by plain identifier call);
//   - tools the test runs (python3, git, find) that read those paths, unless
//     the path is a literal argument of the exec call itself (a repository-
//     relative literal passed to a helper that sets cmd.Dir to the root, as
//     `run("python3", "scripts/x.py")` does, is not anchored and is missed);
//   - a path assembled from variables, string concatenation or Go code embedded
//     in a string (a Python snippet in a raw string literal), or by
//     filepath.Join with a non-literal in the middle (the part before it counts);
//   - Go test files outside cmd/, internal/ and images/;
//   - in the heavy jobs: only `docker/build-push-action` is followed into a
//     Dockerfile (a `docker build` command is a failure), a script is read as
//     text one level deep (comments and docstrings count; a bare word without
//     a slash counts in commands but not in script text, and a glob without a
//     slash such as `.*` counts nowhere), a command inside `bash -c '...'` or
//     `$(...)` in quotes is scanned for paths but not followed (no make
//     target, script or discovery), a `cd` changes no path the test resolves
//     (a step's working-directory does), `if:` conditions are ignored (every
//     step is scanned) and the Go tests a job runs are guard 1's business.
//
// A new reader that escapes those shapes still needs a reviewer; the common
// shapes (the two that broke, the runner's, and every shape the existing tests
// use) are covered, and the detector's own cases below show each one firing.
package cmd

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"go.yaml.in/yaml/v3"
)

// narrowReaderRoots are the top-level directories whose _test.go files are
// scanned.
var narrowReaderRoots = []string{"cmd", "internal", "images"}

// narrowPathReaderExemptions lists tests that match the guard's shapes but
// are not exposed to a narrow PR. Key: "<package dir>.<test name>". Every
// entry was checked by reading the test; the guard also fails when an entry is
// not needed any more, so the map cannot go stale.
var narrowPathReaderExemptions = map[string]string{
	"cmd/pilot/cmd.TestConfigSecretPaths_AllRosterSourceWritesCarryWorkspace": "walks the repository root but opens only non-test .go files, and skips every dot-directory (.agents, .claude); docs/superpowers and docs/evidence hold only Markdown and scripts/pr_loop.py is not a .go file, so no fast-path path is ever opened",
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

// fsAccessFuncs are the calls that read a path the function names: file reads
// and stats, Glob, Walk and running a tool on it.
var fsAccessFuncs = map[string]bool{
	"os.ReadFile": true, "os.Open": true, "os.OpenFile": true, "os.Stat": true, "os.Lstat": true,
	"os.ReadDir": true, "filepath.Glob": true, "fs.Glob": true, "fs.ReadFile": true,
	"fs.ReadDir": true, "fs.Stat": true, "os.DirFS": true,
	"filepath.Walk": true, "filepath.WalkDir": true, "fs.WalkDir": true,
	"exec.Command": true, "exec.CommandContext": true,
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

// relComponents splits a slash-separated repository-relative path (it may hold
// glob characters) into its components. It returns nil for the repository
// root itself and for anything that is absolute or climbs out of the root.
func relComponents(p string) []string {
	p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if p == "." || strings.HasPrefix(p, "/") || p == ".." || strings.HasPrefix(p, "../") {
		return nil
	}
	return strings.Split(p, "/")
}

// componentsMatch reports whether every component of name matches the glob
// component of pattern at the same position; the two must be equally long.
func componentsMatch(pattern, name []string) bool {
	if len(pattern) != len(name) {
		return false
	}
	for i := range pattern {
		if ok, err := path.Match(pattern[i], name[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// dirs returns the components of every directory prefix of the fast path.
func (p ciFastPaths) dirs() [][]string {
	var out [][]string
	for _, prefix := range slices.Concat(p.SkillPrefixes, p.DocPrefixes) {
		if c := relComponents(prefix); len(c) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// match returns the fast-path entry that rel, a repository-relative path that
// may hold glob characters, equals, lies under, is an ancestor of or
// glob-matches; "" when there is none. The repository root is no match
// (everything is below it), and neither is a path below a fast-path file:
// scripts/pr_loop.py/x.go is a Go package directory, not the runner.
func (p ciFastPaths) match(rel string) string {
	comps := relComponents(rel)
	if len(comps) == 0 {
		return ""
	}
	for _, d := range p.dirs() {
		n := min(len(comps), len(d))
		if componentsMatch(comps[:n], d[:n]) {
			return strings.Join(d, "/") + "/"
		}
	}
	for _, file := range p.SkillFiles {
		fc := relComponents(file)
		if len(comps) <= len(fc) && componentsMatch(comps, fc[:len(comps)]) {
			return file
		}
	}
	return ""
}

// dirRun returns the fast-path directory whose components appear as one
// contiguous run in parts, "" if none does. It needs no anchoring: it is how a
// test mentioning .agents/skills or docs/evidence has always been found.
func (p ciFastPaths) dirRun(parts []string) string {
	for _, d := range p.dirs() {
		for i := 0; i+len(d) <= len(parts); i++ {
			if slices.Equal(parts[i:i+len(d)], d) {
				return strings.Join(d, "/")
			}
		}
	}
	return ""
}

func splitPathLit(s string) []string {
	return strings.Split(path.Clean(strings.ReplaceAll(s, "\\", "/")), "/")
}

// narrowLiteral returns the fast-path directory a path literal or the literal
// components of a filepath.Join call name, or "".
func (p ciFastPaths) narrowLiteral(n ast.Node) string {
	switch v := n.(type) {
	case *ast.BasicLit:
		if s, ok := stringLit(v); ok {
			return p.dirRun(splitPathLit(s))
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
			return p.dirRun(parts)
		}
	}
	return ""
}

// anchorScope is what one function knows about the repository root.
type anchorScope struct {
	depth   int               // directory levels between the package and the repository root
	roots   map[string]bool   // identifiers holding the repository root
	anchors map[string]string // identifiers holding a repository-relative path ("" is the root)
	consts  map[string]string // the package's string constants and variables with a literal value
}

// hopsAnchor resolves a path literal that climbs exactly from the package
// directory to the repository root, and returns what is below the root.
func (c *anchorScope) hopsAnchor(s string) (string, bool) {
	comps := splitPathLit(s)
	hops := 0
	for hops < len(comps) && comps[hops] == ".." {
		hops++
	}
	if hops == 0 || hops != c.depth {
		return "", false
	}
	rest := comps[hops:]
	if len(rest) == 1 && rest[0] == "." {
		rest = nil
	}
	return strings.Join(rest, "/"), true
}

// anchorOf returns the repository-relative path e denotes, when e is anchored
// at the repository root. A filepath.Join counts up to its first non-literal
// argument after the anchor.
func (c *anchorScope) anchorOf(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return c.anchorOf(v.X)
	case *ast.Ident:
		if c.roots[v.Name] {
			return "", true
		}
		if rel, ok := c.anchors[v.Name]; ok {
			return rel, true
		}
		if s, ok := c.consts[v.Name]; ok {
			return c.hopsAnchor(s)
		}
	case *ast.BasicLit:
		if s, ok := stringLit(v); ok {
			return c.hopsAnchor(s)
		}
	case *ast.CallExpr:
		name := selectorName(v.Fun)
		if strings.HasPrefix(name, "repoRoot") {
			return "", true
		}
		if name == "filepath.Join" || name == "path.Join" {
			return c.joinAnchor(v.Args)
		}
	}
	return "", false
}

func (c *anchorScope) joinAnchor(args []ast.Expr) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	var lits []string
	for _, a := range args {
		s, ok := stringLit(a)
		if !ok {
			break
		}
		lits = append(lits, s)
	}
	if len(lits) > 0 {
		// Starts with literals: anchored only when they climb to the root.
		return c.hopsAnchor(strings.Join(lits, "/"))
	}
	rel, ok := c.anchorOf(args[0])
	if !ok {
		return "", false
	}
	parts := []string{"."}
	if rel != "" {
		parts = append(parts, rel)
	}
	for _, a := range args[1:] {
		s, ok := stringLit(a)
		if !ok {
			break
		}
		parts = append(parts, s)
	}
	joined := path.Clean(strings.ReplaceAll(strings.Join(parts, "/"), "\\", "/"))
	if joined == "." {
		return "", true
	}
	if strings.HasPrefix(joined, "/") || joined == ".." || strings.HasPrefix(joined, "../") {
		return "", false
	}
	return joined, true
}

// funcFacts is what one top-level function does and calls.
type funcFacts struct {
	test  bool
	why   []string
	calls map[string]bool
}

func scanFuncDecl(fn *ast.FuncDecl, dir string, paths ciFastPaths, consts map[string]string) funcFacts {
	facts := funcFacts{test: fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test"), calls: map[string]bool{}}
	if fn.Body == nil {
		return facts
	}
	scope := &anchorScope{
		depth:   len(strings.Split(dir, "/")),
		roots:   map[string]bool{},
		anchors: map[string]string{},
		consts:  consts,
	}
	// Repo-root identifiers may be assigned anywhere before use; iterate to a
	// fixed point so `a := repoRoot(t); b := a` is followed.
	assignments := func(visit func(lhs, rhs ast.Expr)) {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				if len(v.Lhs) == len(v.Rhs) {
					for i := range v.Lhs {
						visit(v.Lhs[i], v.Rhs[i])
					}
				} else if len(v.Rhs) == 1 {
					// root, err := repoRootForRepairClientTest(): the first result.
					visit(v.Lhs[0], v.Rhs[0])
				}
			case *ast.ValueSpec:
				for i, name := range v.Names {
					if i < len(v.Values) {
						visit(name, v.Values[i])
					}
				}
			}
			return true
		})
	}
	for changed := true; changed; {
		changed = false
		assignments(func(lhs, rhs ast.Expr) {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" && !scope.roots[id.Name] && isRepoRootExpr(rhs, scope.roots) {
				scope.roots[id.Name] = true
				changed = true
			}
		})
	}
	for name := range scope.roots {
		scope.anchors[name] = ""
	}
	for changed := true; changed; {
		changed = false
		assignments(func(lhs, rhs ast.Expr) {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				return
			}
			if _, done := scope.anchors[id.Name]; done {
				return
			}
			if rel, ok := scope.anchorOf(rhs); ok {
				scope.anchors[id.Name] = rel
				changed = true
			}
		})
	}
	// The right-hand side that defines an anchored identifier is not a read of
	// its own: where the identifier is used decides what is named.
	skip := map[ast.Node]bool{}
	skipTree := func(n ast.Node) {
		ast.Inspect(n, func(c ast.Node) bool {
			if c != nil {
				skip[c] = true
			}
			return true
		})
	}
	assignments(func(lhs, rhs ast.Expr) {
		if id, ok := lhs.(*ast.Ident); ok {
			if _, anchored := scope.anchors[id.Name]; anchored {
				if _, ok := scope.anchorOf(rhs); ok {
					skipTree(rhs)
				}
			}
		}
	})

	var narrow, named []string
	access := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok {
				facts.calls[id.Name] = true
			}
			if root := walkRootArg(v); root != nil && isRepoRootExpr(root, scope.roots) {
				facts.why = append(facts.why, "walks the repository root")
			}
			if fsAccessFuncs[selectorName(v.Fun)] {
				access = true
			}
			if skip[v] {
				break
			}
			if name := selectorName(v.Fun); name == "filepath.Join" || name == "path.Join" {
				if rel, ok := scope.anchorOf(v); ok {
					named = append(named, rel)
					for _, a := range v.Args {
						skipTree(a)
					}
				}
				break
			}
			for _, a := range v.Args {
				if id, ok := a.(*ast.Ident); ok && !skip[a] {
					if rel, ok := scope.anchors[id.Name]; ok {
						named = append(named, rel)
					}
				}
			}
		case *ast.BasicLit:
			if s, ok := stringLit(v); ok && !skip[v] {
				if rel, ok := scope.hopsAnchor(s); ok {
					named = append(named, rel)
				}
			}
		}
		if dir := paths.narrowLiteral(n); dir != "" {
			narrow = append(narrow, dir)
		}
		return true
	})
	if access && len(narrow) > 0 {
		sort.Strings(narrow)
		facts.why = append(facts.why, "opens a path under "+narrow[0])
	}
	if access {
		for _, rel := range named {
			if entry := paths.match(rel); entry != "" {
				facts.why = append(facts.why, fmt.Sprintf("names the repository path %q, which is or contains the fast-path entry %s", rel, entry))
			}
		}
	}
	return facts
}

// packageConsts returns the package's string constants and variables whose
// value is a string literal: "../.." held in a const is still a root.
func packageConsts(files []*ast.File) map[string]string {
	consts := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						if s, ok := stringLit(vs.Values[i]); ok {
							consts[name.Name] = s
						}
					}
				}
			}
		}
	}
	return consts
}

// scanNarrowPathReaders returns the Test* functions of one package (one
// directory's parsed files) that read narrow-PR paths, directly or through
// the package's other top-level test-file functions.
func scanNarrowPathReaders(dir string, files []*ast.File, paths ciFastPaths) []narrowHit {
	consts := packageConsts(files)
	facts := map[string]funcFacts{}
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				facts[fn.Name.Name] = scanFuncDecl(fn, dir, paths, consts)
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

func scanAllNarrowPathReaders(t *testing.T, root string, paths ciFastPaths) []narrowHit {
	t.Helper()
	pkgs := parseTestPackages(t, root)
	dirs := make([]string, 0, len(pkgs))
	for dir := range pkgs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	var hits []narrowHit
	for _, dir := range dirs {
		hits = append(hits, scanNarrowPathReaders(dir, pkgs[dir], paths)...)
	}
	return hits
}

// TestCIImpactNarrowPathReadersRunInSkillsJob is the class guard for Go tests.
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
	hits := scanAllNarrowPathReaders(t, root, loadCIFastPaths(t))
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
func TestA(t *testing.T) { _ = ".agents/skills"; _ = []string{".claude/agents"} }`
	srcJoinBreaksAdjacency = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { dir := "docs"; _, _ = os.ReadDir(filepath.Join("docs", dir, "superpowers")) }`

	// The runner (issue #431): every way a test can read scripts/pr_loop.py.
	srcReadRunner = `package p
import ("os";"testing")
func TestA(t *testing.T) { _, _ = os.ReadFile("../../scripts/pr_loop.py") }`
	srcReadRunnerViaRoot = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { _, _ = os.ReadFile(filepath.Join(repoRootForTest(t), "scripts", "pr_loop.py")) }`
	srcReadRunnerViaJoinedHops = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { _, _ = os.ReadFile(filepath.Join("..", "..", "scripts", "pr_loop.py")) }`
	srcReadRunnerViaConst = `package p
import ("os";"path/filepath";"testing")
const repoTop = "../.."
func TestA(t *testing.T) { _, _ = os.ReadFile(filepath.Join(repoTop, "scripts", "pr_loop.py")) }`
	srcGlobScripts = `package p
import ("path/filepath";"testing")
func TestA(t *testing.T) { _, _ = filepath.Glob("../../scripts/*.py") }`
	srcGlobScriptsViaRoot = `package p
import ("path/filepath";"testing")
func TestA(t *testing.T) { _, _ = filepath.Glob(filepath.Join(repoRootForTest(t), "scripts", "pr_*.py")) }`
	srcExecRunner = `package p
import ("os/exec";"testing")
func TestA(t *testing.T) { _ = exec.Command("python3", "../../scripts/pr_loop.py", "--help").Run() }`
	srcExecContextRunner = `package p
import ("context";"os/exec";"testing")
func TestA(t *testing.T) { _ = exec.CommandContext(context.Background(), "python3", "../../scripts/pr_loop.py").Run() }`
	srcListScriptsDir = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { _, _ = os.ReadDir(filepath.Join(repoRootForTest(t), "scripts")) }`
	srcWalkScriptsDir = `package p
import ("io/fs";"path/filepath";"testing")
func TestA(t *testing.T) {
	root := repoRootForTest(t)
	_ = filepath.WalkDir(filepath.Join(root, "scripts"), func(p string, d fs.DirEntry, err error) error { return nil })
}`
	srcScriptsDirIdentifierThenJoin = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) {
	root := repoRootForTest(t)
	scripts := filepath.Join(root, "scripts")
	_, _ = os.ReadFile(filepath.Join(scripts, "pr_loop.py"))
}`
	srcScriptsDirIdentifierListed = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) {
	scripts := filepath.Join(repoRootForTest(t), "scripts")
	_, _ = os.ReadDir(scripts)
}`
	srcScriptsDirIdentifierOtherFile = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) {
	scripts := filepath.Join(repoRootForTest(t), "scripts")
	_, _ = os.ReadFile(filepath.Join(scripts, "topology-checkmode-test.sh"))
}`
	srcJoinWithAVariableAfterTheDir = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { name := "x"; _, _ = os.ReadFile(filepath.Join(repoRootForTest(t), "scripts", name)) }`
	srcReadDocsDir = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { _, _ = os.ReadDir(filepath.Join(repoRootForTest(t), "docs")) }`
	srcReadOtherDocsDir = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { _, _ = os.ReadDir(filepath.Join(repoRootForTest(t), "docs", "verification")) }`
	// Stay green.
	srcGlobShellScripts = `package p
import ("path/filepath";"testing")
func TestA(t *testing.T) { _, _ = filepath.Glob(filepath.Join(repoRootForTest(t), "scripts", "*.sh")) }`
	srcGlobShellScriptsViaConst = `package p
import ("path/filepath";"testing")
const fcRepoRoot = "../.."
func TestA(t *testing.T) { _, _ = filepath.Glob(filepath.Join(fcRepoRoot, "scripts", "*.sh")) }`
	srcExecOtherScript = `package p
import ("os/exec";"testing")
func TestA(t *testing.T) { _ = exec.Command("python3", "../../scripts/test-freeipa-gateway-scope.py").Run() }`
	srcTempScripts = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { _, _ = os.ReadDir(filepath.Join(t.TempDir(), "scripts")) }`
	srcTempRunner = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { _, _ = os.ReadFile(filepath.Join(t.TempDir(), "scripts", "pr_loop.py")) }`
	srcRelativeRunner = `package p
import ("os";"testing")
func TestA(t *testing.T) { _, _ = os.ReadFile("scripts/pr_loop.py") }`
	srcRunnerMentioned = `package p
import "testing"
// scripts/pr_loop.py is read by the skills job.
func TestA(t *testing.T) { _ = "../../scripts/pr_loop.py"; _ = []string{"scripts/pr_loop.py"} }`
	srcRunnerLookalikes = `package p
import ("os";"testing")
func TestA(t *testing.T) {
	_, _ = os.ReadFile("../../scripts/pr_loop.py/x.go")
	_, _ = os.ReadFile("../../scripts/pr_loop_result.py")
	_, _ = os.ReadFile("../../scripts/pr_loop.py.bak")
	_, _ = os.ReadFile("../../x/scripts/pr_loop.py")
}`
	srcWrongHopCount = `package p
import ("os";"testing")
func TestA(t *testing.T) { _, _ = os.ReadFile("../scripts/pr_loop.py"); _, _ = os.ReadFile("../../../scripts/pr_loop.py") }`
	srcRootWithAVariable = `package p
import ("os";"path/filepath";"testing")
func TestA(t *testing.T) { name := "x"; _, _ = os.ReadFile(filepath.Join(repoRootForTest(t), name)) }`
	srcDeepRunnerRead = `package p
import ("os";"testing")
func TestA(t *testing.T) { _, _ = os.ReadFile("../../../scripts/pr_loop.py") }`
	srcCustomEntry = `package p
import ("os";"testing")
func TestA(t *testing.T) { _, _ = os.ReadFile("../../tools/runner.py"); _, _ = os.ReadFile("../../scripts/pr_loop.py") }`
)

func TestCIImpactNarrowPathReaderDetector(t *testing.T) {
	real := loadCIFastPaths(t)
	custom := ciFastPaths{SkillFiles: []string{"tools/runner.py"}}
	cases := []struct {
		name, src string
		dir       string // package directory; internal/spec by default
		paths     *ciFastPaths
		want      []string // Test names expected to be reported
	}{
		{name: "walk of filepath.Join(..,..)", src: srcWalkRootJoin, want: []string{"TestA"}},
		{name: "walk of a ../.. literal", src: srcWalkRootLiteral, want: []string{"TestA"}},
		{name: "walk of a repoRoot*() result through an alias", src: srcWalkRootHelper, want: []string{"TestA"}},
		{name: "fs.WalkDir takes the root as its second argument", src: srcWalkFSRoot, want: []string{"TestA"}},
		{name: "walk in a helper reaches only its callers", src: srcWalkViaHelper, want: []string{"TestA"}},
		{name: "read under .agents via filepath.Join", src: srcReadSkillFile, want: []string{"TestA"}},
		{name: "read under docs/superpowers", src: srcReadDocsSpecs, want: []string{"TestA"}},
		{name: "glob under docs/evidence", src: srcReadDocsEvidenceGlob, want: []string{"TestA"}},
		{name: "walk of a subtree is not a root walk", src: srcWalkSubtree},
		{name: "walk of a temp dir", src: srcTempDirWalk},
		{name: "mentioning the paths without reading anything", src: srcMentionOnly},
		{name: "a variable in the middle breaks the component run", src: srcJoinBreaksAdjacency},

		{name: "read of the runner by a ../ literal", src: srcReadRunner, want: []string{"TestA"}},
		{name: "read of the runner below the root helper", src: srcReadRunnerViaRoot, want: []string{"TestA"}},
		{name: "read of the runner by joined .. literals", src: srcReadRunnerViaJoinedHops, want: []string{"TestA"}},
		{name: "read of the runner below a package-level root constant", src: srcReadRunnerViaConst, want: []string{"TestA"}},
		{name: "glob of scripts/*.py contains the runner", src: srcGlobScripts, want: []string{"TestA"}},
		{name: "glob of scripts/pr_*.py below the root helper", src: srcGlobScriptsViaRoot, want: []string{"TestA"}},
		{name: "exec of the runner", src: srcExecRunner, want: []string{"TestA"}},
		{name: "exec with a context of the runner", src: srcExecContextRunner, want: []string{"TestA"}},
		{name: "listing the directory that holds the runner", src: srcListScriptsDir, want: []string{"TestA"}},
		{name: "walking the directory that holds the runner", src: srcWalkScriptsDir, want: []string{"TestA"}},
		{name: "a directory identifier joined with the runner's name", src: srcScriptsDirIdentifierThenJoin, want: []string{"TestA"}},
		{name: "a directory identifier that is itself listed", src: srcScriptsDirIdentifierListed, want: []string{"TestA"}},
		{name: "a directory identifier joined with another file is not a read of the runner", src: srcScriptsDirIdentifierOtherFile},
		{name: "a variable after the directory could name the runner", src: srcJoinWithAVariableAfterTheDir, want: []string{"TestA"}},
		{name: "listing docs holds docs/evidence", src: srcReadDocsDir, want: []string{"TestA"}},
		{name: "listing docs/verification holds no fast-path path", src: srcReadOtherDocsDir},
		{name: "glob of scripts/*.sh holds no fast-path path", src: srcGlobShellScripts},
		{name: "glob of scripts/*.sh below a package constant holds no fast-path path", src: srcGlobShellScriptsViaConst},
		{name: "exec of another script", src: srcExecOtherScript},
		{name: "a scripts directory in a temp dir", src: srcTempScripts},
		{name: "a runner in a temp dir", src: srcTempRunner},
		{name: "a path relative to the package directory is no repository path", src: srcRelativeRunner},
		{name: "mentioning the runner without reading it", src: srcRunnerMentioned},
		{name: "look-alikes of the runner", src: srcRunnerLookalikes},
		{name: "a ../ literal that does not reach the root", src: srcWrongHopCount},
		{name: "a root joined with a variable names only the root", src: srcRootWithAVariable},
		{name: "the same literal from a package three levels deep reaches the root", src: srcDeepRunnerRead, dir: "cmd/pilot/cmd", want: []string{"TestA"}},
		{name: "two ../ do not reach the root of a package three levels deep", src: srcReadRunner, dir: "cmd/pilot/cmd"},
		{name: "an entry the constants do not have is not a reader", src: srcCustomEntry, paths: &custom, want: []string{"TestA"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "x_test.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			dir, paths := tc.dir, real
			if dir == "" {
				dir = "internal/spec"
			}
			if tc.paths != nil {
				paths = *tc.paths
			}
			var got []string
			for _, h := range scanNarrowPathReaders(dir, []*ast.File{f}, paths) {
				got = append(got, h.Test)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("reported %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCIImpactNarrowPathMatching shows what ciFastPaths.match decides, on the
// constants of scripts/ci-impact.py and on a made-up set.
func TestCIImpactNarrowPathMatching(t *testing.T) {
	real := loadCIFastPaths(t)
	cases := []struct {
		name  string
		paths ciFastPaths
		rel   string
		want  bool
	}{
		{"the runner", real, "scripts/pr_loop.py", true},
		{"a glob of the runner", real, "scripts/*.py", true},
		{"a glob of the runner by its prefix", real, "scripts/pr_*", true},
		{"the directory that holds the runner", real, "scripts", true},
		{"a skill file", real, ".agents/skills/x/SKILL.md", true},
		{"the skills directory", real, ".agents/skills", true},
		{"the directory that holds the skills", real, ".agents", true},
		{"a design document", real, "docs/superpowers/plans/x.md", true},
		{"the directory that holds the design documents", real, "docs/superpowers", true},
		{"the evidence directory", real, "docs/evidence", true},
		{"the repository root", real, ".", false},
		{"nothing", real, "", false},
		{"another script", real, "scripts/other.py", false},
		{"shell scripts", real, "scripts/*.sh", false},
		{"the result helper", real, "scripts/pr_loop_result.py", false},
		{"a package directory named like the runner", real, "scripts/pr_loop.py/x.go", false},
		{"the runner below another directory", real, "x/scripts/pr_loop.py", false},
		{"a path that climbs out", real, "../scripts/pr_loop.py", false},
		{"an absolute path", real, "/scripts/pr_loop.py", false},
		{"verification docs", real, "docs/verification/x.md", false},
		{"agent settings are not a skill", real, ".agents/config.toml", false},
		{"only a file the constants name matches", ciFastPaths{SkillFiles: []string{"tools/runner.py"}}, "scripts/pr_loop.py", false},
		{"a file of a made-up set", ciFastPaths{SkillFiles: []string{"tools/runner.py"}}, "tools/runner.py", true},
		{"a directory of a made-up set", ciFastPaths{SkillPrefixes: []string{"a/b/"}}, "a/b/c", true},
		{"the parent of a made-up directory", ciFastPaths{SkillPrefixes: []string{"a/b/"}}, "a", true},
		{"a sibling of a made-up directory", ciFastPaths{SkillPrefixes: []string{"a/b/"}}, "a/c", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.paths.match(tc.rel) != ""; got != tc.want {
				t.Fatalf("match(%q) = %q, want a match: %v", tc.rel, tc.paths.match(tc.rel), tc.want)
			}
		})
	}
}

// TestCIImpactNarrowPathMatchingAgreesWithPathKind makes sure the matcher
// never misses what path_kind calls a reduced path, and does not take paths
// that path_kind calls full: a corpus built from the constants, and look-alikes,
// is asked of both.
func TestCIImpactNarrowPathMatchingAgreesWithPathKind(t *testing.T) {
	paths := loadCIFastPaths(t)
	var corpus []string
	for _, prefix := range slices.Concat(paths.SkillPrefixes, paths.DocPrefixes) {
		corpus = append(corpus, prefix+"x", prefix+"x.md", prefix+"x.yaml", prefix+"a/b/c.py", prefix+"a b/c.md")
	}
	for _, file := range paths.SkillFiles {
		corpus = append(corpus, file, file+"/x.go", file+".bak", file+"~", file+"/")
	}
	// Paths no reduced profile may be asked about: matched by neither.
	unrelated := []string{
		"README.md", "AGENTS.md", "Makefile", "go.mod", ".github/workflows/ci.yml", "scripts/other.py",
		"scripts/ci-impact.py", "scripts/tests/test_ci_impact.py", "cmd/pilot/cmd/x_test.go", ".agents/config.toml",
		".claude/settings.json", "docs/verification/x.md", "docs/runbooks/x.md", "docs/superpowers/other/x.md",
		"playbooks/apply/x.yml", "internal/spec/x.go", "x/scripts/pr_loop.py", "Scripts/pr_loop.py",
	}
	corpus = append(corpus, unrelated...)
	kinds := ciImpactPathKinds(t, corpus)
	reduced := 0
	for i, p := range corpus {
		matched := paths.match(p) != ""
		switch {
		case kinds[i] != "full":
			reduced++
			if !matched {
				t.Errorf("path_kind(%q) = %q but the matcher does not find it", p, kinds[i])
			}
		case slices.Contains(unrelated, p) && matched:
			t.Errorf("path_kind(%q) is full and the matcher takes it for %s", p, paths.match(p))
		}
	}
	if reduced == 0 {
		t.Fatal("no path of the corpus is a reduced-profile path: the comparison proves nothing")
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

// ---------------------------------------------------------------------------
// Guard 2: the inputs of the heavy jobs.

// heavyJobReadExemptions lists what a heavy job's inputs name without reading
// it. Key: "<job>|<where>|<token>". Every entry was checked by reading the
// file; the guard also fails for an entry it does not need any more.
var heavyJobReadExemptions = map[string]string{
	"ci-receipt|scripts/ci-validation-reuse.py|docs/evidence": "compares the prefix docs/evidence/ with the paths `git diff --name-only` prints to decide whether a delta is evidence-only; it never opens a file there (the diff is read from the git object store, not the working tree)",
}

// ciHeavyRead is one fast-path path that a heavy job's input names.
type ciHeavyRead struct {
	Job   string
	Where string // the workflow step, Makefile target, script or Dockerfile
	Token string // the path as it appears, normalized
	Entry string // the fast-path entry it equals, lies under, contains or matches
}

func (r ciHeavyRead) key() string { return r.Job + "|" + r.Where + "|" + r.Token }

func (r ciHeavyRead) String() string {
	return fmt.Sprintf("job %s: %s names %q, which is or contains the fast-path entry %s", r.Job, r.Where, r.Token, r.Entry)
}

type ciWorkflowStep struct {
	Name             string
	Uses             string
	Run              string
	WorkingDirectory string `yaml:"working-directory"`
	Env              map[string]any
	With             map[string]any
}

type ciWorkflowJob struct {
	Strategy struct{ Matrix any }
	Defaults struct {
		Run struct {
			WorkingDirectory string `yaml:"working-directory"`
		}
	}
	Steps []ciWorkflowStep
}

// makeFile is a Makefile as far as the guard follows it: every right-hand side
// a variable is assigned (every branch of a conditional counts) and every rule.
type makeFile struct {
	vars  map[string][]string
	rules map[string]*makeRule
}

type makeRule struct {
	prereqs []string
	recipe  []string
}

var (
	makeAssignRE = regexp.MustCompile(`^(?:(?:export|override)\s+)*([A-Za-z_][A-Za-z0-9_.-]*)\s*(?::=|::=|\+=|\?=|=)\s*(.*)$`)
	makeIdentRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
)

// makeDirectives are the Makefile lines that are neither a rule nor an assignment.
var makeDirectives = []string{"ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "include", "-include", "sinclude", "define", "endef", "unexport", "vpath"}

// makeFunctions are the GNU make functions whose arguments the guard scans as
// text: their result is made of them.
var makeFunctions = map[string]bool{
	"if": true, "or": true, "and": true, "filter": true, "filter-out": true, "origin": true, "shell": true,
	"subst": true, "patsubst": true, "strip": true, "findstring": true, "sort": true, "word": true, "words": true,
	"wordlist": true, "firstword": true, "lastword": true, "dir": true, "notdir": true, "basename": true,
	"suffix": true, "addsuffix": true, "addprefix": true, "join": true, "wildcard": true, "realpath": true,
	"abspath": true, "foreach": true, "call": true, "value": true, "flavor": true,
}

// makeBuiltinVars are the variables make itself defines.
var makeBuiltinVars = map[string]string{"MAKE": "make", "MAKEFILE_LIST": "Makefile", "CURDIR": ".", "MAKEFLAGS": "", "MFLAGS": ""}

func stripMakeComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '#' {
			return s[:i]
		}
	}
	return s
}

func parseMakefile(text string) *makeFile {
	mk := &makeFile{vars: map[string][]string{}, rules: map[string]*makeRule{}}
	var logical []string
	physical := strings.Split(text, "\n")
	for i := 0; i < len(physical); i++ {
		line := physical[i]
		for strings.HasSuffix(line, "\\") && i+1 < len(physical) {
			i++
			line = strings.TrimSuffix(line, "\\") + " " + strings.TrimLeft(physical[i], " \t")
		}
		logical = append(logical, line)
	}
	var current []*makeRule
	for _, line := range logical {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "\t") {
			// A recipe line; blank and comment lines between recipe lines do not end it.
			for _, r := range current {
				r.recipe = append(r.recipe, trimmed)
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		current = nil
		first, _, _ := strings.Cut(trimmed, " ")
		if slices.Contains(makeDirectives, first) {
			continue
		}
		if m := makeAssignRE.FindStringSubmatch(trimmed); m != nil {
			mk.vars[m[1]] = append(mk.vars[m[1]], strings.TrimSpace(stripMakeComment(m[2])))
			continue
		}
		colon := strings.Index(trimmed, ":")
		if colon < 0 {
			continue
		}
		targets := strings.Fields(trimmed[:colon])
		rest := strings.TrimPrefix(trimmed[colon+1:], ":")
		if m := makeAssignRE.FindStringSubmatch(strings.TrimSpace(rest)); m != nil {
			// A target-specific variable: `target: NAME := value`.
			mk.vars[m[1]] = append(mk.vars[m[1]], strings.TrimSpace(stripMakeComment(m[2])))
			continue
		}
		rest = stripMakeComment(rest)
		inline := ""
		if semi := strings.Index(rest, ";"); semi >= 0 {
			rest, inline = rest[:semi], strings.TrimSpace(rest[semi+1:])
		}
		var prereqs []string
		for _, p := range strings.Fields(rest) {
			if p != "|" {
				prereqs = append(prereqs, p)
			}
		}
		for _, target := range targets {
			if strings.HasPrefix(target, ".") {
				continue
			}
			rule := mk.rules[target]
			if rule == nil {
				rule = &makeRule{}
				mk.rules[target] = rule
			}
			rule.prereqs = append(rule.prereqs, prereqs...)
			if inline != "" {
				rule.recipe = append(rule.recipe, inline)
			}
			current = append(current, rule)
		}
	}
	return mk
}

// matchingClose returns the index of the bracket that closes the one opened at
// text[open], or -1.
func matchingClose(text string, open int) int {
	o, c := text[open], byte(')')
	if o == '{' {
		c = '}'
	}
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case o:
			depth++
		case c:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// expand replaces $(NAME), ${NAME} and $$ in text the way make would, as far
// as a scan for paths needs: a variable becomes every right-hand side it is
// assigned (then the environment, which make also sees), a function becomes its
// arguments. Anything it cannot resolve is added to unresolved.
func (m *makeFile) expand(text string, env map[string]string, depth int, unresolved map[string]bool) string {
	if depth > 10 {
		unresolved["a variable that refers to itself"] = true
		return ""
	}
	var out strings.Builder
	for i := 0; i < len(text); {
		if text[i] != '$' || i+1 >= len(text) {
			out.WriteByte(text[i])
			i++
			continue
		}
		switch next := text[i+1]; next {
		case '$':
			out.WriteByte('$')
			i += 2
		case '(', '{':
			end := matchingClose(text, i+1)
			if end < 0 {
				unresolved["an unterminated reference in "+text[i:]] = true
				return out.String()
			}
			out.WriteString(m.expandRef(text[i+2:end], env, depth, unresolved))
			i = end + 1
		default:
			out.WriteString(m.expandRef(string(next), env, depth, unresolved))
			i += 2
		}
	}
	return out.String()
}

func (m *makeFile) expandRef(inner string, env map[string]string, depth int, unresolved map[string]bool) string {
	name := strings.TrimSpace(inner)
	if makeIdentRE.MatchString(name) {
		if v, ok := makeBuiltinVars[name]; ok {
			return v
		}
		if vals, ok := m.vars[name]; ok {
			var parts []string
			for _, v := range vals {
				parts = append(parts, m.expand(v, env, depth+1, unresolved))
			}
			return strings.Join(parts, " ")
		}
		if v, ok := env[name]; ok {
			return v
		}
		unresolved["$("+name+")"] = true
		return ""
	}
	fn, args, _ := strings.Cut(name, " ")
	if makeFunctions[fn] {
		return " " + strings.ReplaceAll(m.expand(args, env, depth+1, unresolved), ",", " ") + " "
	}
	unresolved["$("+fn+" ...)"] = true
	return ""
}

var (
	pathTokenRE = regexp.MustCompile(`[A-Za-z0-9_.@%+~/*?\[\]-]+`)
	ghExprRE    = regexp.MustCompile(`(?s)\$\{\{\s*(.*?)\s*\}\}`)
	shellVarRE  = regexp.MustCompile(`\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))`)
	shellAsnRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// ghSubst fills ${{ matrix.<key> }} from one combination of the job's matrix;
// any other expression becomes a NUL, which no path token contains and no
// make target or script may contain.
func ghSubst(v string, variant map[string]string) string {
	return ghExprRE.ReplaceAllStringFunc(v, func(expr string) string {
		inner := strings.TrimSpace(ghExprRE.FindStringSubmatch(expr)[1])
		if key, ok := strings.CutPrefix(inner, "matrix."); ok {
			if value, ok := variant[key]; ok {
				return value
			}
		}
		return "\x00"
	})
}

// matrixVariants returns every combination of a job's static matrix; a matrix
// that is an expression (fromJSON of another job's output) yields one empty
// combination, and its keys read as NUL.
func matrixVariants(matrix any) ([]map[string]string, string) {
	m, ok := matrix.(map[string]any)
	if !ok {
		return []map[string]string{{}}, ""
	}
	variants := []map[string]string{{}}
	for _, key := range slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}) {
		if key == "include" || key == "exclude" {
			return nil, "matrix." + key + " is not expanded by the guard"
		}
		var options []string
		switch v := m[key].(type) {
		case []any:
			for _, o := range v {
				options = append(options, fmt.Sprint(o))
			}
		case string:
			continue // an expression: unknown, reads as NUL
		default:
			options = []string{fmt.Sprint(v)}
		}
		var next []map[string]string
		for _, base := range variants {
			for _, o := range options {
				combo := map[string]string{key: o}
				for k, v := range base {
					combo[k] = v
				}
				next = append(next, combo)
			}
		}
		variants = next
		if len(variants) > 64 {
			return nil, "matrix has more than 64 combinations"
		}
	}
	return variants, ""
}

// shellCommands splits shell text into simple commands, each a list of words:
// quotes are removed, comments dropped, backslash-newline joined, and a
// command ends at a newline, ; & | ( or ).
func shellCommands(text string) [][]string {
	rs := []rune(strings.ReplaceAll(text, "\\\n", " "))
	var cmds [][]string
	var cur []string
	var word strings.Builder
	inWord := false
	flushWord := func() {
		if inWord {
			cur = append(cur, word.String())
			word.Reset()
			inWord = false
		}
	}
	flushCmd := func() {
		flushWord()
		if len(cur) > 0 {
			cmds = append(cmds, cur)
			cur = nil
		}
	}
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\'':
			inWord = true
			for i++; i < len(rs) && rs[i] != '\''; i++ {
				word.WriteRune(rs[i])
			}
		case c == '"':
			inWord = true
			for i++; i < len(rs) && rs[i] != '"'; i++ {
				if rs[i] == '\\' && i+1 < len(rs) {
					i++
				}
				word.WriteRune(rs[i])
			}
		case c == '\\' && i+1 < len(rs):
			inWord = true
			i++
			word.WriteRune(rs[i])
		case c == '#' && !inWord:
			for i+1 < len(rs) && rs[i+1] != '\n' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\r':
			flushWord()
		case c == '\n' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			flushCmd()
		default:
			inWord = true
			word.WriteRune(c)
		}
	}
	flushCmd()
	return cmds
}

var shellWrappers = map[string]bool{
	"sudo": true, "env": true, "time": true, "exec": true, "command": true, "nohup": true, "then": true, "do": true,
	"else": true, "elif": true, "if": true, "while": true, "until": true, "!": true, "$": true,
}

// commandWords drops what precedes the command a simple command runs:
// variable assignments, wrappers like sudo and env, and their flags.
func commandWords(words []string) []string {
	i := 0
	for i < len(words) {
		w := words[i]
		switch {
		case shellWrappers[w] || shellAsnRE.MatchString(w):
			i++
		case i > 0 && strings.HasPrefix(w, "-") && shellWrappers[words[i-1]]:
			i++
		default:
			return words[i:]
		}
	}
	return nil
}

var scriptInterpreters = map[string]bool{"python": true, "python3": true, "bash": true, "sh": true, "dash": true, "zsh": true}

// interpreterScript returns the index in cmd of the script an interpreter
// runs, or -1 when cmd is not an interpreter run of a script (-m and -c run a
// module or code).
func interpreterScript(cmd []string) int {
	if !scriptInterpreters[path.Base(cmd[0])] {
		return -1
	}
	for i := 1; i < len(cmd); i++ {
		switch w := cmd[i]; {
		case w == "-m" || w == "-c":
			return -1
		case w == "-o" || w == "+o" || w == "-O" || w == "+O" || w == "-W" || w == "-X":
			i++
		case strings.HasPrefix(w, "-") || strings.HasPrefix(w, "+"):
		default:
			return i
		}
	}
	return -1
}

func isScriptName(w string) bool {
	return (strings.HasSuffix(w, ".py") || strings.HasSuffix(w, ".sh") || strings.HasSuffix(w, ".bash")) &&
		!strings.ContainsAny(w, "*?[") && !strings.HasPrefix(w, "/")
}

// normalizeToken turns what the token pattern found into a repository-relative
// path to match, or "" when it is not a path to look at.
func normalizeToken(tok string, bare bool) string {
	for strings.HasPrefix(tok, "./") {
		tok = tok[2:]
	}
	tok = strings.TrimRight(tok, "/")
	if !strings.Contains(tok, "/") {
		tok = strings.TrimRight(tok, ".")
	}
	if tok == "" || strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "/") ||
		strings.Trim(tok, ".") == "" || strings.Trim(tok, "*?[]-") == "" {
		return ""
	}
	if !strings.Contains(tok, "/") && (strings.ContainsAny(tok, "*?[") || !bare) {
		// A word without a slash is a path only in a command (`find scripts`), and
		// never as a glob: `.*` is a regular expression as often as a path.
		return ""
	}
	tok = path.Clean(tok)
	if tok == "." || tok == ".." || strings.HasPrefix(tok, "../") {
		return ""
	}
	return tok
}

// heavyScan walks the inputs of the heavy jobs.
type heavyScan struct {
	paths ciFastPaths
	fsys  fs.FS
	mk    *makeFile

	reads    map[string]ciHeavyRead
	problems []string

	job         string
	step        string
	seenScripts map[string]bool
	seenTargets map[string]bool
}

func (s *heavyScan) problem(where, format string, args ...any) {
	s.problems = append(s.problems, fmt.Sprintf("job %s: %s: %s", s.job, where, fmt.Sprintf(format, args...)))
}

// check matches the path tokens of text (and, under workdir, the same tokens
// relative to it) against the fast path. bare lets a word without a slash count.
func (s *heavyScan) check(where, text, workdir string, bare bool) {
	for _, tok := range pathTokenRE.FindAllString(text, -1) {
		tok = normalizeToken(tok, bare)
		if tok == "" {
			continue
		}
		for _, cand := range []string{tok, joinWorkdir(workdir, tok)} {
			if cand == "" {
				continue
			}
			if entry := s.paths.match(cand); entry != "" {
				r := ciHeavyRead{Job: s.job, Where: where, Token: cand, Entry: entry}
				s.reads[r.key()] = r
			}
		}
	}
}

func joinWorkdir(workdir, tok string) string {
	workdir = path.Clean(workdir)
	if workdir == "." || workdir == "" || strings.HasPrefix(workdir, "/") {
		return ""
	}
	return path.Join(workdir, tok)
}

func (s *heavyScan) scanJob(name string, job ciWorkflowJob) {
	s.job = name
	s.seenScripts = map[string]bool{}
	variants, problem := matrixVariants(job.Strategy.Matrix)
	if problem != "" {
		s.problem("strategy", "%s", problem)
	}
	for _, variant := range variants {
		for i, step := range job.Steps {
			s.scanStep(job, i, step, variant)
		}
	}
}

func (s *heavyScan) scanStep(job ciWorkflowJob, index int, step ciWorkflowStep, variant map[string]string) {
	label := step.Name
	if label == "" {
		label = step.Uses
	}
	where := fmt.Sprintf("ci.yml step %d (%s)", index+1, label)
	env := map[string]string{}
	for k, v := range step.Env {
		env[k] = ghSubst(fmt.Sprint(v), variant)
	}
	workdir := ghSubst(step.WorkingDirectory, variant)
	if workdir == "" {
		workdir = ghSubst(job.Defaults.Run.WorkingDirectory, variant)
	}
	s.check(where+" working-directory", workdir, "", true)
	for _, v := range env {
		s.check(where+" env", v, workdir, true)
	}
	with := map[string]string{}
	for k, v := range step.With {
		with[k] = ghSubst(fmt.Sprint(v), variant)
		s.check(where+" with."+k, with[k], workdir, true)
	}
	if strings.HasPrefix(step.Uses, "./") {
		s.problem(where, "runs the local action %s, which the guard does not read", step.Uses)
	}
	if strings.HasPrefix(step.Uses, "docker/build-push-action@") {
		s.scanDockerfile(where, with)
	}
	if step.Run == "" {
		return
	}
	s.step = where
	s.seenTargets = map[string]bool{}
	s.scanCommandText(where, ghSubst(step.Run, variant), workdir, env)
}

func (s *heavyScan) scanCommandText(where, text, workdir string, env map[string]string) {
	for _, words := range shellCommands(text) {
		for _, w := range words {
			s.check(where, w, workdir, true)
		}
		s.examine(where, words, workdir, env)
	}
}

// examine follows what one simple command runs: make, a script, a unittest
// discovery. It fails for a command it would have to follow and cannot.
func (s *heavyScan) examine(where string, words []string, workdir string, env map[string]string) {
	cmd := commandWords(words)
	if len(cmd) == 0 {
		return
	}
	switch path.Base(cmd[0]) {
	case "make":
		s.makeInvocation(where, cmd[1:], env)
	case "docker":
		if rest := cmd[1:]; len(rest) > 0 && (rest[0] == "build" || (rest[0] == "buildx" && len(rest) > 1 && rest[1] == "build")) {
			s.problem(where, "runs %q: only docker/build-push-action is followed into a Dockerfile", strings.Join(cmd, " "))
		}
	}
	scriptAt := interpreterScript(cmd)
	for i, w := range cmd {
		if isScriptName(w) {
			s.readScript(where, w, workdir, i == scriptAt || i == 0)
		}
	}
	if slices.Contains(cmd, "unittest") && slices.Contains(cmd, "discover") {
		s.discover(where, cmd, workdir)
	}
}

func (s *heavyScan) readScript(where, name, workdir string, mustExist bool) {
	if strings.ContainsAny(name, "$\x00") {
		if mustExist {
			s.problem(where, "runs the script %q, whose name has a variable the guard cannot expand", name)
		}
		return
	}
	for _, cand := range []string{strings.TrimPrefix(name, "./"), joinWorkdir(workdir, strings.TrimPrefix(name, "./"))} {
		cand = path.Clean(cand)
		if cand == "." || !fs.ValidPath(cand) {
			continue
		}
		if info, err := fs.Stat(s.fsys, cand); err == nil && !info.IsDir() {
			s.readScriptFile(cand)
			return
		}
	}
	if mustExist {
		s.problem(where, "runs the script %q, which the guard cannot read in the repository", name)
	}
}

func (s *heavyScan) readScriptFile(file string) {
	if s.seenScripts[file] {
		return
	}
	s.seenScripts[file] = true
	data, err := fs.ReadFile(s.fsys, file)
	if err != nil {
		s.problem(file, "cannot read the script: %v", err)
		return
	}
	s.check(file, string(data), "", false)
}

// discover reads the files `python3 -m unittest discover -s DIR -p PATTERN` loads.
func (s *heavyScan) discover(where string, cmd []string, workdir string) {
	dir, pattern := ".", "test*.py"
	for i := 0; i+1 < len(cmd); i++ {
		switch cmd[i] {
		case "-s", "--start-directory":
			dir = cmd[i+1]
		case "-p", "--pattern":
			pattern = cmd[i+1]
		}
	}
	full := path.Clean(path.Join(workdir, dir))
	if strings.ContainsAny(full, "$\x00") || !fs.ValidPath(full) {
		s.problem(where, "unittest discover -s %q: the guard cannot resolve the directory", dir)
		return
	}
	entries, err := fs.ReadDir(s.fsys, full)
	if err != nil {
		s.problem(where, "unittest discover -s %q: cannot list %s: %v", dir, full, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ok, err := path.Match(pattern, e.Name())
		if err != nil {
			s.problem(where, "unittest discover -p %q: %v", pattern, err)
			return
		}
		if ok {
			s.readScriptFile(path.Join(full, e.Name()))
		}
	}
}

func (s *heavyScan) makeInvocation(where string, args []string, env map[string]string) {
	merged := map[string]string{}
	for k, v := range env {
		merged[k] = v
	}
	var targets []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-C" || a == "-f" || a == "-I" || a == "-o" || a == "-W" || strings.HasPrefix(a, "--directory") ||
			strings.HasPrefix(a, "--file") || strings.HasPrefix(a, "--makefile") || strings.HasPrefix(a, "--include-dir"):
			s.problem(where, "make %s changes the Makefile or directory read, which the guard does not follow", a)
			return
		case strings.HasPrefix(a, "-"):
			if (a == "-j" || a == "--jobs") && i+1 < len(args) {
				if _, err := strconv.Atoi(args[i+1]); err == nil {
					i++
				}
			}
		case shellAsnRE.MatchString(a):
			k, v, _ := strings.Cut(a, "=")
			merged[k] = v
		default:
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		s.problem(where, "make without a target: the default goal is not followed")
		return
	}
	for _, raw := range targets {
		target, ok := shellExpand(raw, env)
		if !ok || target == "" {
			s.problem(where, "make target %q has a variable or expression the guard cannot expand", raw)
			continue
		}
		s.follow(target, merged, where)
	}
}

// shellExpand expands $NAME and ${NAME} from env; ok is false when a name is
// not there or the word still holds an unresolved expression.
func shellExpand(word string, env map[string]string) (string, bool) {
	ok := true
	out := shellVarRE.ReplaceAllStringFunc(word, func(ref string) string {
		m := shellVarRE.FindStringSubmatch(ref)
		name := m[1] + m[2]
		v, found := env[name]
		if !found {
			ok = false
		}
		return v
	})
	return out, ok && !strings.ContainsAny(out, "$\x00")
}

func (s *heavyScan) follow(target string, env map[string]string, from string) {
	if s.seenTargets[target] {
		return
	}
	s.seenTargets[target] = true
	where := "Makefile target " + target
	rule := s.mk.rules[target]
	if rule == nil {
		s.problem(from, "make target %q has no rule in the Makefile", target)
		return
	}
	report := func(unresolved map[string]bool) {
		for _, name := range slices.Sorted(func(yield func(string) bool) {
			for k := range unresolved {
				if !yield(k) {
					return
				}
			}
		}) {
			s.problem(where, "cannot expand %s: it is neither assigned in the Makefile nor in the step's env", name)
		}
	}
	for _, pre := range rule.prereqs {
		unresolved := map[string]bool{}
		text := s.mk.expand(pre, env, 0, unresolved)
		report(unresolved)
		for _, w := range strings.Fields(text) {
			if s.mk.rules[w] != nil {
				s.follow(w, env, where)
			} else if info, err := fs.Stat(s.fsys, path.Clean(w)); err == nil && !info.IsDir() {
				s.check(where, w, "", true)
			} else {
				s.problem(where, "prerequisite %q is neither a rule nor a file", w)
			}
		}
	}
	for _, line := range rule.recipe {
		unresolved := map[string]bool{}
		text := s.mk.expand(strings.TrimLeft(line, "@-+ \t"), env, 0, unresolved)
		report(unresolved)
		s.scanCommandText(where, text, "", env)
	}
}

// scanDockerfile reads what a docker/build-push-action step copies from its
// build context: COPY and ADD sources (not --from=) and bind-mount sources.
func (s *heavyScan) scanDockerfile(where string, with map[string]string) {
	if ctx := path.Clean(with["context"]); with["context"] != "" && ctx != "." {
		s.problem(where, "the build context is %q: the guard follows only the repository root", with["context"])
		return
	}
	file := with["file"]
	if file == "" {
		file = "Dockerfile"
	}
	data, err := fs.ReadFile(s.fsys, path.Clean(file))
	if err != nil {
		s.problem(where, "cannot read the Dockerfile %q: %v", file, err)
		return
	}
	var logical []string
	physical := strings.Split(string(data), "\n")
	for i := 0; i < len(physical); i++ {
		line := strings.TrimSpace(physical[i])
		if strings.HasPrefix(line, "#") {
			continue
		}
		for strings.HasSuffix(line, "\\") && i+1 < len(physical) {
			i++
			next := strings.TrimSpace(physical[i])
			if strings.HasPrefix(next, "#") {
				continue
			}
			line = strings.TrimSuffix(line, "\\") + " " + next
		}
		logical = append(logical, line)
	}
	here := path.Clean(file)
	for _, line := range logical {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var args []string
		fromStage := false
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "--from=") {
				fromStage = true
			}
			if strings.HasPrefix(f, "--mount=") && strings.ToUpper(fields[0]) == "RUN" {
				for _, kv := range strings.Split(strings.TrimPrefix(f, "--mount="), ",") {
					k, v, _ := strings.Cut(kv, "=")
					if (k == "source" || k == "src") && !strings.Contains(f, "from=") {
						s.checkSource(here, v)
					}
				}
			}
			if !strings.HasPrefix(f, "--") {
				args = append(args, f)
			}
		}
		switch strings.ToUpper(fields[0]) {
		case "COPY", "ADD":
			if fromStage || len(args) < 2 {
				continue
			}
			if strings.HasPrefix(args[0], "[") {
				var list []string
				if err := json.Unmarshal([]byte(strings.Join(args, " ")), &list); err != nil || len(list) < 2 {
					s.problem(here, "cannot parse %q", line)
					continue
				}
				args = list
			}
			for _, src := range args[:len(args)-1] {
				s.checkSource(here, src)
			}
		}
	}
}

func (s *heavyScan) checkSource(where, src string) {
	if strings.Contains(src, "://") {
		return
	}
	cand := normalizeToken(src, true)
	if cand == "" {
		return
	}
	if entry := s.paths.match(cand); entry != "" {
		r := ciHeavyRead{Job: s.job, Where: where, Token: cand, Entry: entry}
		s.reads[r.key()] = r
	}
}

// scanHeavyJobs returns the fast-path paths the named jobs' inputs name, and
// the constructs it could not follow.
func scanHeavyJobs(ciYAML, makefile string, fsys fs.FS, paths ciFastPaths, jobs []string) ([]ciHeavyRead, []string) {
	var wf struct{ Jobs map[string]ciWorkflowJob }
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return nil, []string{"parse ci.yml: " + err.Error()}
	}
	s := &heavyScan{paths: paths, fsys: fsys, mk: parseMakefile(makefile), reads: map[string]ciHeavyRead{}}
	for _, name := range jobs {
		job, ok := wf.Jobs[name]
		if !ok {
			s.job = name
			s.problem("ci.yml", "no such job")
			continue
		}
		s.scanJob(name, job)
	}
	reads := make([]ciHeavyRead, 0, len(s.reads))
	for _, r := range s.reads {
		reads = append(reads, r)
	}
	sort.Slice(reads, func(i, j int) bool { return reads[i].key() < reads[j].key() })
	sort.Strings(s.problems)
	return reads, slices.Compact(s.problems)
}

// unexemptedHeavyReads returns the reads no exemption covers, and the
// exemptions that cover nothing.
func unexemptedHeavyReads(reads []ciHeavyRead, exempt map[string]string) (missing, stale []string) {
	used := map[string]bool{}
	for _, r := range reads {
		if _, ok := exempt[r.key()]; ok {
			used[r.key()] = true
			continue
		}
		missing = append(missing, r.String())
	}
	for key := range exempt {
		if !used[key] {
			stale = append(stale, key+" is exempt but no heavy job input names a fast-path path there any more")
		}
	}
	sort.Strings(stale)
	return missing, stale
}

// heavyJobNames returns the jobs whose inputs guard 2 scans: the jobs the
// result checker expects skipped outside the full profile. main() prints the
// same set (HEAVY_JOBS | {"ci-receipt"}). RESULT_JOBS minus the jobs that run
// in every profile (changes, skills) must be exactly that set, so a new result
// job is a decision here, not a gap.
func heavyJobNames(paths ciFastPaths) ([]string, string) {
	heavy := append(slices.Clone(paths.HeavyJobs), "ci-receipt")
	var rest []string
	for _, job := range paths.ResultJobs {
		if job != "changes" && job != "skills" {
			rest = append(rest, job)
		}
	}
	slices.Sort(heavy)
	slices.Sort(rest)
	if !slices.Equal(heavy, rest) {
		return nil, fmt.Sprintf("scripts/ci-impact.py RESULT_JOBS minus changes and skills is %v, but HEAVY_JOBS plus ci-receipt is %v: decide whether the new job is heavy", rest, heavy)
	}
	return heavy, ""
}

// TestCIImpactHeavyJobsDoNotNameFastPathInputs is guard 2: a path that the
// fast path skips must not be an input of a job that is skipped with it.
func TestCIImpactHeavyJobsDoNotNameFastPathInputs(t *testing.T) {
	root := repoRootForTest(t)
	paths := loadCIFastPaths(t)
	jobs, problem := heavyJobNames(paths)
	if problem != "" {
		t.Fatal(problem)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	reads, problems := scanHeavyJobs(readCIYAML(t), string(mk), os.DirFS(root), paths, jobs)
	for _, p := range problems {
		t.Errorf("%s\nThe guard cannot follow this construct of a heavy job, so it cannot show that the job reads no fast-path path.", p)
	}
	missing, stale := unexemptedHeavyReads(reads, heavyJobReadExemptions)
	for _, m := range missing {
		t.Errorf("%s: scripts/ci-impact.py would skip this job for a PR that changes that path, and the job would stop checking it silently.\n"+
			"Take the path out of SKILL_FILES (or the prefix lists), or list the input in heavyJobReadExemptions with the reason it never reads the file", m)
	}
	for _, s := range stale {
		t.Error(s)
	}
}

// A workflow, Makefile and repository for the self-test of guard 2.
const heavyCaseCI = `
jobs:
  changes:
    steps:
      - run: python3 scripts/pr_loop.py --help
  skills:
    steps:
      - run: python3 scripts/pr_loop.py --help
  heavy:
    strategy:
      matrix:
        target: [one, two]
    steps:
      - uses: actions/checkout@v4
      - name: run a target
        env:
          TARGET: ${{ matrix.target }}
        run: make "$TARGET"
`

const heavyCaseMakefile = `
SHARED = scripts/shared.py
one: ## the first target
	@echo one
two: three
	python3 $(SHARED)
three:
	echo three
`

type heavyCase struct {
	name      string
	ci        string
	makefile  string
	files     map[string]string
	jobs      []string
	wantReads []string // "job|token" of the expected reads
	wantProb  string   // a substring of an expected problem
}

func (c heavyCase) run(t *testing.T) {
	t.Helper()
	// The scripts the cases run exist, empty of paths, unless a case says otherwise.
	fsys := fstest.MapFS{
		"scripts/pr_loop.py": &fstest.MapFile{Data: []byte("pass")},
		"scripts/other.py":   &fstest.MapFile{Data: []byte("import os")},
		"scripts/shared.py":  &fstest.MapFile{Data: []byte("import os")},
	}
	for name, body := range c.files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	paths := ciFastPaths{
		SkillPrefixes: []string{".agents/skills/", ".claude/skills/", ".claude/agents/"},
		SkillFiles:    []string{"scripts/pr_loop.py"},
		DocPrefixes:   []string{"docs/superpowers/plans/", "docs/superpowers/specs/", "docs/evidence/"},
	}
	jobs := c.jobs
	if jobs == nil {
		jobs = []string{"heavy"}
	}
	reads, problems := scanHeavyJobs(c.ci, c.makefile, fsys, paths, jobs)
	var got []string
	for _, r := range reads {
		// The same path can be named by more than one input (a step's env and the recipe that uses it).
		if id := r.Job + "|" + r.Token; !slices.Contains(got, id) {
			got = append(got, id)
		}
	}
	if strings.Join(got, ",") != strings.Join(c.wantReads, ",") {
		t.Errorf("reads %v, want %v", got, c.wantReads)
	}
	if c.wantProb == "" && len(problems) > 0 {
		t.Errorf("unexpected problems: %v", problems)
	}
	if c.wantProb != "" && !strings.Contains(strings.Join(problems, "\n"), c.wantProb) {
		t.Errorf("problems %v, want one containing %q", problems, c.wantProb)
	}
}

func heavyWith(runLine string) string {
	return "jobs:\n  heavy:\n    steps:\n      - run: " + runLine + "\n"
}

func TestCIImpactHeavyJobScanner(t *testing.T) {
	const runnerLine = "python3 -B scripts/pr_loop.py --help"
	cases := []heavyCase{
		// The reads it must find, each through a different route.
		{name: "a run step names the runner", ci: heavyWith(runnerLine), wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a run step in a multi-line script", ci: "jobs:\n  heavy:\n    steps:\n      - run: |\n          set -e\n          echo ok\n          python3 scripts/pr_loop.py\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a glob of the runner", ci: heavyWith("ls scripts/*.py"), wantReads: []string{"heavy|scripts/*.py"}},
		{name: "the directory that holds the runner", ci: heavyWith("find scripts -name '*.py'"), wantReads: []string{"heavy|scripts"}},
		{name: "a skills directory", ci: heavyWith("ls .agents/skills"), wantReads: []string{"heavy|.agents/skills"}},
		{name: "a design document", ci: heavyWith("cat docs/superpowers/plans/x.md"), wantReads: []string{"heavy|docs/superpowers/plans/x.md"}},
		{name: "a path with a leading ./", ci: heavyWith("python3 ./scripts/pr_loop.py"), wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a path after an option", ci: heavyWith("tool --input=scripts/pr_loop.py"), wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a path inside inline code", ci: heavyWith(`python3 -c "open('scripts/pr_loop.py')"`), wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a working directory that holds the runner", ci: "jobs:\n  heavy:\n    steps:\n      - working-directory: scripts\n        run: echo hi\n", wantReads: []string{"heavy|scripts"}},
		{name: "a relative path under a working directory", ci: "jobs:\n  heavy:\n    steps:\n      - working-directory: scripts\n        run: python3 pr_loop.py\n", files: map[string]string{"scripts/pr_loop.py": "x"}, wantReads: []string{"heavy|scripts", "heavy|scripts/pr_loop.py"}},
		{name: "a with value", ci: "jobs:\n  heavy:\n    steps:\n      - uses: actions/upload-artifact@v4\n        with:\n          path: scripts/pr_loop.py\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "an env value", ci: "jobs:\n  heavy:\n    steps:\n      - run: echo hi\n        env:\n          FILE: scripts/pr_loop.py\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a make recipe the step runs", ci: heavyWith("make x"), makefile: "x:\n\t" + runnerLine + "\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a prerequisite of the target", ci: heavyWith("make x"), makefile: "x: y\n\techo x\ny:\n\t" + runnerLine + "\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a target run through $(MAKE)", ci: heavyWith("make x"), makefile: "x:\n\t$(MAKE) y\ny:\n\t" + runnerLine + "\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a make variable", ci: heavyWith("make x"), makefile: "RUNNER = scripts/pr_loop.py\nx:\n\tpython3 $(RUNNER)\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a variable inside a make function", ci: heavyWith("make x"), makefile: "RUNNER = scripts/pr_loop.py\nPREFIX = $(if $(RUNNER),python3 $(RUNNER) , )\nx:\n\t$(PREFIX) go test\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a variable assigned in one branch of a conditional", ci: heavyWith("make x"), makefile: "ifeq ($(A),1)\nP = echo\nelse\nP = python3 scripts/pr_loop.py\nendif\nx:\n\t$(P) hi\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a variable from the step's env", ci: "jobs:\n  heavy:\n    steps:\n      - run: make x\n        env:\n          RUNNER: scripts/pr_loop.py\n", makefile: "x:\n\tpython3 $(RUNNER)\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a continued recipe line", ci: heavyWith("make x"), makefile: "x:\n\techo a && \\\n\t  python3 scripts/pr_loop.py\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a recipe after a comment line", ci: heavyWith("make x"), makefile: "x:\n\techo a\n# a comment\n\tpython3 scripts/pr_loop.py\n", wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a matrix target", ci: heavyCaseCI, makefile: heavyCaseMakefile, files: map[string]string{"scripts/shared.py": "x"}, wantReads: nil},
		{name: "the other matrix target reads the runner", ci: heavyCaseCI, makefile: strings.Replace(heavyCaseMakefile, "SHARED = scripts/shared.py", "SHARED = scripts/pr_loop.py", 1), files: map[string]string{"scripts/pr_loop.py": "x"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a script the step runs", ci: heavyWith("bash tools/run.sh"), files: map[string]string{"tools/run.sh": "python3 scripts/pr_loop.py"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a script run by its path", ci: heavyWith("./tools/run.sh"), files: map[string]string{"tools/run.sh": "python3 scripts/pr_loop.py"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a script named after an interpreter option", ci: heavyWith("bash -o pipefail tools/run.sh"), files: map[string]string{"tools/run.sh": "cat scripts/pr_loop.py"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a script a recipe runs", ci: heavyWith("make x"), makefile: "x:\n\t./tools/run.sh\n", files: map[string]string{"tools/run.sh": "cat scripts/pr_loop.py"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a script under a working directory", ci: "jobs:\n  heavy:\n    steps:\n      - working-directory: tools\n        run: python3 run.py\n", files: map[string]string{"tools/run.py": "open('scripts/pr_loop.py')"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a unittest discovery", ci: heavyWith("python3 -m unittest discover -s tools/tests -p 'test_*.py'"), files: map[string]string{"tools/tests/test_a.py": "open('scripts/pr_loop.py')", "tools/tests/helper.py": "open('scripts/other.py')"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a unittest module under a working directory", ci: "jobs:\n  heavy:\n    steps:\n      - working-directory: tools\n        run: python3 -m unittest test_a.py -v\n", files: map[string]string{"tools/test_a.py": "open('scripts/pr_loop.py')"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a Dockerfile COPY of the scripts directory", ci: dockerCI(".", "images/Dockerfile"), files: map[string]string{"images/Dockerfile": "FROM x\nCOPY scripts/ scripts/\n"}, wantReads: []string{"heavy|scripts"}},
		{name: "a Dockerfile COPY of the runner", ci: dockerCI(".", "images/Dockerfile"), files: map[string]string{"images/Dockerfile": "FROM x\nCOPY scripts/pr_loop.py /usr/bin/\n"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a Dockerfile ADD with a flag", ci: dockerCI(".", "images/Dockerfile"), files: map[string]string{"images/Dockerfile": "FROM x\nADD --chown=1:1 scripts/pr_loop.py /usr/bin/\n"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a Dockerfile COPY in JSON form", ci: dockerCI(".", "images/Dockerfile"), files: map[string]string{"images/Dockerfile": "FROM x\nCOPY [\"scripts/pr_loop.py\", \"/usr/bin/\"]\n"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a Dockerfile continued COPY", ci: dockerCI(".", "images/Dockerfile"), files: map[string]string{"images/Dockerfile": "FROM x\nCOPY a/ b/ \\\n    scripts/pr_loop.py /usr/bin/\n"}, wantReads: []string{"heavy|scripts/pr_loop.py"}},
		{name: "a Dockerfile bind mount", ci: dockerCI(".", "images/Dockerfile"), files: map[string]string{"images/Dockerfile": "FROM x\nRUN --mount=type=bind,source=scripts,target=/s true\n"}, wantReads: []string{"heavy|scripts"}},

		// What must stay green.
		{name: "the runner in the skills job", ci: heavyWith(runnerLine), jobs: []string{"skills"}, wantProb: "no such job"},
		{name: "the runner in a job that is not scanned", ci: "jobs:\n  skills:\n    steps:\n      - run: " + runnerLine + "\n  heavy:\n    steps:\n      - run: echo hi\n"},
		{name: "a name that only starts like the runner", ci: heavyWith("python3 scripts/pr_loop_result.py; echo pr_loop; cat scripts/pr_loop.pyc"), files: map[string]string{"scripts/pr_loop_result.py": "x"}},
		{name: "the runner below another directory", ci: heavyWith("cat x/scripts/pr_loop.py y/.agents/skills"), wantReads: nil},
		{name: "a comment in the workflow", ci: "jobs:\n  heavy:\n    steps:\n      # scripts/pr_loop.py is tested by the skills job\n      - run: echo hi\n"},
		{name: "a shell comment in a run script", ci: "jobs:\n  heavy:\n    steps:\n      - run: |\n          # scripts/pr_loop.py is not run here\n          echo hi # nor scripts/pr_loop.py\n"},
		{name: "a step name that mentions the runner", ci: "jobs:\n  heavy:\n    steps:\n      - name: scripts/pr_loop.py is a skills path\n        run: echo hi\n"},
		{name: "the whole repository is not the runner", ci: heavyWith("go vet ./... && go test . && docker run -v .:/src x"), wantReads: nil},
		{name: "another script", ci: heavyWith("python3 scripts/other.py"), files: map[string]string{"scripts/other.py": "import os"}},
		{name: "a make target that is not run", ci: heavyWith("make x"), makefile: "x:\n\techo x\ny:\n\t" + runnerLine + "\n"},
		{name: "an unreachable prerequisite chain", ci: heavyWith("make x"), makefile: "x: y\n\techo x\ny:\n\techo y\nz: y\n\t" + runnerLine + "\n"},
		{name: "a COPY from another stage", ci: dockerCI(".", "images/Dockerfile"), files: map[string]string{"images/Dockerfile": "FROM x AS b\nFROM y\nCOPY --from=b scripts/pr_loop.py /x\nCOPY cmd/ cmd/\nCOPY docs/verification/ docs/verification/\n"}},
		{name: "the same line in a script with a bare word", ci: heavyWith("bash tools/run.sh"), files: map[string]string{"tools/run.sh": "echo scripts docs .agents && ls ."}},
		{name: "a script that only has a bare word and a short glob", ci: heavyWith("python3 tools/run.py"), files: map[string]string{"tools/run.py": "def f(*args): return '*' + '.agents'"}},
		{name: "an unittest pattern that matches no file with the runner", ci: heavyWith("python3 -m unittest discover -s tools/tests -p 'test_b.py'"), files: map[string]string{"tools/tests/test_a.py": "open('scripts/pr_loop.py')", "tools/tests/test_b.py": "pass"}},

		// What it cannot follow must fail, naming the item.
		{name: "a make target with no rule", ci: heavyWith("make nope"), makefile: "x:\n\techo x\n", wantProb: `make target "nope" has no rule`},
		{name: "a prerequisite with no rule", ci: heavyWith("make x"), makefile: "x: gone\n\techo x\n", wantProb: `prerequisite "gone"`},
		{name: "a recursive target with no rule", ci: heavyWith("make x"), makefile: "x:\n\t$(MAKE) gone\n", wantProb: `make target "gone" has no rule`},
		{name: "a variable nobody defines", ci: heavyWith("make x"), makefile: "x:\n\tpython3 $(UNKNOWN)\n", wantProb: "cannot expand $(UNKNOWN)"},
		{name: "a make function the guard does not know", ci: heavyWith("make x"), makefile: "x:\n\techo $(frobnicate a b)\n", wantProb: "cannot expand $(frobnicate ...)"},
		{name: "a variable that refers to itself", ci: heavyWith("make x"), makefile: "A = $(A)\nx:\n\techo $(A)\n", wantProb: "refers to itself"},
		{name: "a make target held in an unknown shell variable", ci: heavyWith(`make "$NOPE"`), makefile: "x:\n\techo x\n", wantProb: "make target"},
		{name: "a make target held in an expression", ci: heavyWith("make ${{ needs.x.outputs.target }}"), makefile: "x:\n\techo x\n", wantProb: "make target"},
		{name: "a make target of a matrix that is an expression", ci: "jobs:\n  heavy:\n    strategy:\n      matrix: ${{ fromJSON(needs.x.outputs.m) }}\n    steps:\n      - run: make ${{ matrix.target }}\n", makefile: "x:\n\techo x\n", wantProb: "make target"},
		{name: "make without a target", ci: heavyWith("make"), makefile: "x:\n\techo x\n", wantProb: "make without a target"},
		{name: "make -C", ci: heavyWith("make -C sub x"), makefile: "x:\n\techo x\n", wantProb: "make -C"},
		{name: "a script that is not in the repository", ci: heavyWith("python3 scripts/missing.py"), wantProb: `script "scripts/missing.py"`},
		{name: "a script run by an interpreter flag and path that is missing", ci: heavyWith("bash -e -o pipefail scripts/missing.sh"), wantProb: `script "scripts/missing.sh"`},
		{name: "a script name with a variable", ci: heavyWith(`bash "$SCRIPT.sh"`), wantProb: "variable the guard cannot expand"},
		{name: "a docker build command", ci: heavyWith("docker build -f images/Dockerfile ."), wantProb: "only docker/build-push-action"},
		{name: "a docker buildx build command", ci: heavyWith("docker buildx build ."), wantProb: "only docker/build-push-action"},
		{name: "a local action", ci: "jobs:\n  heavy:\n    steps:\n      - uses: ./.github/actions/x\n", wantProb: "local action"},
		{name: "a build context that is not the root", ci: dockerCI("images", "images/Dockerfile"), files: map[string]string{"images/Dockerfile": "FROM x\n"}, wantProb: "build context"},
		{name: "a Dockerfile that is missing", ci: dockerCI(".", "images/Dockerfile"), wantProb: "cannot read the Dockerfile"},
		{name: "a unittest directory that is missing", ci: heavyWith("python3 -m unittest discover -s nowhere"), wantProb: "unittest discover -s"},
		{name: "a job the workflow does not have", ci: heavyWith("echo hi"), jobs: []string{"gone"}, wantProb: "no such job"},
		{name: "a matrix with include", ci: "jobs:\n  heavy:\n    strategy:\n      matrix:\n        include:\n          - a: b\n    steps:\n      - run: echo hi\n", wantProb: "matrix.include"},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

func dockerCI(context, file string) string {
	return "jobs:\n  heavy:\n    steps:\n      - uses: docker/build-push-action@v7\n        with:\n          context: " + context + "\n          file: " + file + "\n"
}

// TestCIImpactHeavyJobGuardCountsTheMatrixTarget shows the matrix is expanded:
// a target that only one combination runs is followed.
func TestCIImpactHeavyJobGuardCountsTheMatrixTarget(t *testing.T) {
	mk := "one:\n\techo one\ntwo:\n\tpython3 scripts/pr_loop.py\n"
	heavyCase{name: "the second target of the matrix", ci: heavyCaseCI, makefile: mk, wantReads: []string{"heavy|scripts/pr_loop.py"}}.run(t)
	heavyCase{name: "a matrix of the first target only", ci: strings.Replace(heavyCaseCI, "[one, two]", "[one]", 1), makefile: mk}.run(t)
}

// overlayFS serves the repository with some files replaced, for the cases that
// mutate a real input of a heavy job in memory.
type overlayFS struct {
	fs.FS
	over fstest.MapFS
}

func (o overlayFS) Open(name string) (fs.File, error) {
	if _, ok := o.over[name]; ok {
		return o.over.Open(name)
	}
	return o.FS.Open(name)
}

// TestCIImpactHeavyJobGuardCatchesTheRealInputs puts the runner's path into the
// real workflow, Makefile and Dockerfile, one route at a time, and asks the
// guard what it finds: every route into a heavy job is a read, the skills job
// and the changes job's targets are not, and a path added to the constants is
// followed the same way, so nothing here knows the runner's name.
func TestCIImpactHeavyJobGuardCatchesTheRealInputs(t *testing.T) {
	root := repoRootForTest(t)
	paths := loadCIFastPaths(t)
	jobs, problem := heavyJobNames(paths)
	if problem != "" {
		t.Fatal(problem)
	}
	ci := readCIYAML(t)
	mkBytes, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(mkBytes)
	dockerBytes, err := os.ReadFile(filepath.Join(root, "images", "Dockerfile.pilot-cli"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(dockerBytes)
	runner := paths.SkillFiles[0]
	runnerLine := "python3 -B " + runner + " --help"
	edit := func(body, old, replacement string) string {
		t.Helper()
		if !strings.Contains(body, old) {
			t.Fatalf("mutation anchor missing: %q", old)
		}
		return strings.Replace(body, old, replacement, 1)
	}
	cases := []struct {
		name       string
		ci         string
		makefile   string
		dockerfile string
		paths      ciFastPaths
		want       []string // "<job>|<token>" of every new read
	}{
		{"the unmodified inputs", ci, makefile, dockerfile, paths, nil},
		{"a recipe the test job runs", ci, edit(makefile, "ci-go-runtime-test: ## Verify Go CI evidence against small real race binaries\n",
			"ci-go-runtime-test: ## Verify Go CI evidence against small real race binaries\n\t"+runnerLine+"\n"), dockerfile, paths, []string{"test|" + runner}},
		{"a step of the lint job", edit(ci, "    name: golangci-lint\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n",
			"    name: golangci-lint\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - run: "+runnerLine+"\n"), makefile, dockerfile, paths, []string{"lint|" + runner}},
		{"a step of the matrix job that runs make", edit(ci, "        run: make \"$TARGET\"\n", "        run: make \"$TARGET\" && "+runnerLine+"\n"), makefile, dockerfile, paths, []string{"playbook-integration|" + runner}},
		{"a COPY of the scripts directory into the image", ci, makefile, edit(dockerfile, "COPY monitoring/ monitoring/\n", "COPY monitoring/ monitoring/\nCOPY scripts/ scripts/\n"), paths, []string{"image|scripts"}},
		{"the same line in the skills job", edit(ci, "      - name: Install PyYAML\n        run: python3 -m pip install pyyaml\n      # scripts/", "      - name: Install PyYAML\n        run: python3 -m pip install pyyaml\n      - run: "+runnerLine+"\n      # scripts/"), makefile, dockerfile, paths, nil},
		{"the same line in the changes job's make target", ci, edit(makefile, "ci-workflow-test: ## Verify CI impact selection, candidate reuse and shard evidence controls\n",
			"ci-workflow-test: ## Verify CI impact selection, candidate reuse and shard evidence controls\n\t"+runnerLine+"\n"), dockerfile, paths, nil},
		{"a script a heavy job runs becomes a fast-path file", ci, makefile, dockerfile,
			ciFastPaths{SkillPrefixes: paths.SkillPrefixes, DocPrefixes: paths.DocPrefixes, SkillFiles: []string{runner, "scripts/ci-go-test-shards.py"}},
			[]string{"go-test-results|scripts/ci-go-test-shards.py", "test|scripts/ci-go-test-shards.py"}},
	}
	baseline, _ := scanHeavyJobs(ci, makefile, os.DirFS(root), paths, jobs)
	known := map[string]bool{}
	for _, r := range baseline {
		known[r.Job+"|"+r.Token] = true
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := overlayFS{FS: os.DirFS(root), over: fstest.MapFS{"images/Dockerfile.pilot-cli": &fstest.MapFile{Data: []byte(tc.dockerfile)}}}
			reads, problems := scanHeavyJobs(tc.ci, tc.makefile, fsys, tc.paths, jobs)
			if len(problems) > 0 {
				t.Fatalf("the guard could not follow the mutated input: %v", problems)
			}
			var got []string
			for _, r := range reads {
				if id := r.Job + "|" + r.Token; !known[id] && !slices.Contains(got, id) {
					got = append(got, id)
				}
			}
			// A script a mutation makes the job run is read too, so the extra reads of
			// its text are no failure: each route must find its path, and a route that
			// no heavy job runs must find nothing.
			for _, id := range tc.want {
				if !slices.Contains(got, id) {
					t.Errorf("the guard did not find %s; new reads: %v", id, got)
				}
			}
			if tc.want == nil && len(got) > 0 {
				t.Errorf("new reads %v, want none", got)
			}
		})
	}
}

func TestCIImpactHeavyReadExemptions(t *testing.T) {
	reads := []ciHeavyRead{
		{Job: "a", Where: "w", Token: "scripts/pr_loop.py", Entry: "scripts/pr_loop.py"},
		{Job: "b", Where: "scripts/x.py", Token: "docs/evidence", Entry: "docs/evidence/"},
	}
	cases := []struct {
		name    string
		exempt  map[string]string
		missing int
		stale   int
	}{
		{"nothing exempt", nil, 2, 0},
		{"one exempt", map[string]string{"b|scripts/x.py|docs/evidence": "r"}, 1, 0},
		{"both exempt", map[string]string{"a|w|scripts/pr_loop.py": "r", "b|scripts/x.py|docs/evidence": "r"}, 0, 0},
		{"an exemption that names nothing is stale", map[string]string{"a|w|scripts/pr_loop.py": "r", "b|scripts/x.py|docs/evidence": "r", "c|y|scripts/z": "r"}, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			missing, stale := unexemptedHeavyReads(reads, tc.exempt)
			if len(missing) != tc.missing || len(stale) != tc.stale {
				t.Fatalf("missing %v stale %v, want %d and %d", missing, stale, tc.missing, tc.stale)
			}
		})
	}
}

func TestCIImpactHeavyJobSetMatchesTheResultChecker(t *testing.T) {
	cases := []struct {
		name  string
		paths ciFastPaths
		want  string
	}{
		{"the real set", loadCIFastPaths(t), ""},
		{"a result job that is neither heavy nor always run", ciFastPaths{HeavyJobs: []string{"a"}, ResultJobs: []string{"a", "changes", "skills", "ci-receipt", "b"}}, "decide whether the new job is heavy"},
		{"a heavy job the result checker lost", ciFastPaths{HeavyJobs: []string{"a", "b"}, ResultJobs: []string{"a", "changes", "skills", "ci-receipt"}}, "decide whether the new job is heavy"},
		{"the made-up consistent set", ciFastPaths{HeavyJobs: []string{"a"}, ResultJobs: []string{"a", "changes", "skills", "ci-receipt"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jobs, problem := heavyJobNames(tc.paths)
			if tc.want == "" && (problem != "" || len(jobs) == 0) {
				t.Fatalf("jobs %v problem %q, want a set", jobs, problem)
			}
			if tc.want != "" && !strings.Contains(problem, tc.want) {
				t.Fatalf("problem %q, want %q", problem, tc.want)
			}
		})
	}
}

// TestCIImpactMakefileParser shows what the guard reads from a Makefile, on
// constructs of this repository's Makefile.
func TestCIImpactMakefileParser(t *testing.T) {
	mk := parseMakefile("A := 1\nB ?= $(A) two # c\nifeq ($(X),1)\nP = x\nelse\nP = y\nendif\n" +
		".PHONY: t\nt: u ## doc\n\techo $(P)\n\n# c\n\t$(MAKE) u\nu: v | w\n\ttrue\nu: z\npilot-cli-image: IMG := a:b\nv w z:\n\tfalse\n")
	if got := mk.vars["B"]; len(got) != 1 || got[0] != "$(A) two" {
		t.Errorf("B = %q, a trailing comment is not part of the value", got)
	}
	if got := mk.vars["P"]; len(got) != 2 {
		t.Errorf("P = %q, want both branches of the conditional", got)
	}
	if got := mk.vars["IMG"]; len(got) != 1 || got[0] != "a:b" {
		t.Errorf("IMG = %q, a target-specific variable is a variable", got)
	}
	if mk.rules["pilot-cli-image"] != nil || mk.rules[".PHONY"] != nil {
		t.Error("a target-specific variable and .PHONY are not rules")
	}
	rt := mk.rules["t"]
	if rt == nil || !slices.Equal(rt.prereqs, []string{"u"}) || len(rt.recipe) != 2 {
		t.Fatalf("rule t = %+v, want prerequisite u (the doc comment dropped) and two recipe lines across a comment", rt)
	}
	if ru := mk.rules["u"]; ru == nil || !slices.Equal(ru.prereqs, []string{"v", "w", "z"}) {
		t.Errorf("rule u = %+v, want its two definitions merged (order-only marker dropped)", ru)
	}
	for _, name := range []string{"v", "w", "z"} {
		if mk.rules[name] == nil {
			t.Errorf("no rule %s: a rule with several targets", name)
		}
	}
	unresolved := map[string]bool{}
	// A function becomes its arguments, so every word either branch could print is there.
	got := strings.Fields(mk.expand("$(B) $$HOME $(if $(filter 1,$(A)),yes,no) $(MAKE) $(NOPE)", nil, 0, unresolved))
	slices.Sort(got)
	if got = slices.Compact(got); !slices.Equal(got, []string{"$HOME", "1", "make", "no", "two", "yes"}) {
		t.Errorf("expansion = %q", got)
	}
	if !unresolved["$(NOPE)"] || len(unresolved) != 1 {
		t.Errorf("unresolved = %v, want only $(NOPE)", unresolved)
	}
}
