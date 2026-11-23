package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Keep the workflow's dependency graph and expressions aligned with the result
// checker. A skipped required job must not turn a failed validation green.
func checkCIImpactWorkflow(body string) string {
	var wf struct {
		Jobs map[string]struct {
			Needs any
			If    string
			Steps []struct {
				Run string
				If  string
				Env map[string]string
			}
		}
	}
	if err := yaml.Unmarshal([]byte(body), &wf); err != nil {
		return err.Error()
	}
	gate := wf.Jobs["ci-results"]
	if gate.If != "always()" {
		return "result gate must always run, even after failure or skip"
	}
	var want []string
	for name := range wf.Jobs {
		if name != "ci-results" && name != "promote" {
			want = append(want, name)
		}
	}
	got := ciNeedsList(gate.Needs)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return fmt.Sprintf("result gate dependencies: got %v, want %v", got, want)
	}
	if len(gate.Steps) != 2 || gate.Steps[1].Run != "python3 scripts/ci-impact.py --check-results" || gate.Steps[1].If != "" {
		return "result gate must unconditionally execute the result checker"
	}
	env := gate.Steps[1].Env
	for key, value := range map[string]string{
		"NEEDS_JSON":       "${{ toJSON(needs) }}",
		"CI_PROFILE":       "${{ needs.changes.outputs.profile }}",
		"EVIDENCE_ONLY":    "${{ needs.changes.outputs.evidence_only }}",
		"RECEIPT_REQUIRED": "${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository }}",
	} {
		if env[key] != value {
			return "result checker input drift: " + key
		}
	}
	if wf.Jobs["skills"].If != "" || !slices.Contains(ciNeedsList(wf.Jobs["skills"].Needs), "changes") {
		return "skill contract job must run for every profile"
	}
	foundSkillTests, foundLayout, foundRepoLint := false, false, false
	for _, step := range wf.Jobs["skills"].Steps {
		if step.Run == "make skill-test" {
			foundSkillTests = step.If == "needs.changes.outputs.profile != 'docs'"
		}
		if strings.Contains(step.Run, "-run '^TestAgentSkill'") {
			foundLayout = step.If == ""
		}
		if step.Run == "make skill-repo-lint" {
			foundRepoLint = step.If == ""
		}
	}
	if !foundSkillTests || !foundLayout {
		return "narrow validation lost skill tests or the unconditional layout contract"
	}
	if !foundRepoLint {
		return "narrow validation lost the unconditional repo-wide lints that read .agents and .claude (make skill-repo-lint)"
	}
	const receiptGuard = "github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository && needs.changes.outputs.profile == 'full' && needs.changes.outputs.evidence_only != 'true'"
	if wf.Jobs["ci-receipt"].If != receiptGuard {
		return "only full validation may issue a reusable receipt"
	}
	return ""
}

func TestCIImpactWorkflowContract(t *testing.T) {
	if problem := checkCIImpactWorkflow(readCIYAML(t)); problem != "" {
		t.Fatal(problem)
	}
}

func TestCIImpactWorkflowContractCatchesDrift(t *testing.T) {
	body := readCIYAML(t)
	for _, tc := range []struct{ old, new, want string }{
		{"    name: CI required checks\n    if: always()", "    name: CI required checks\n    if: success()", "must always run"},
		{"mcp-remote, skills, image, ci-receipt]", "mcp-remote, skills, image]", "result gate dependencies"},
		{"python3 scripts/ci-impact.py --check-results", "echo success", "execute the result checker"},
		{"NEEDS_JSON: ${{ toJSON(needs) }}", "NEEDS_JSON: '{}'", "input drift"},
		{"    if: needs.changes.outputs.profile != 'docs'", "    if: false", "lost skill tests"},
		{"        run: make skill-repo-lint\n", "        if: needs.changes.outputs.profile == 'full'\n        run: make skill-repo-lint\n", "lost the unconditional repo-wide lints"},
		{"      - name: Repo-wide lints that read .agents and .claude (make skill-repo-lint)\n        run: make skill-repo-lint\n", "", "lost the unconditional repo-wide lints"},
		{"needs.changes.outputs.profile == 'full' && needs.changes.outputs.evidence_only != 'true'\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:", "needs.changes.outputs.evidence_only != 'true'\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:", "only full validation"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if !strings.Contains(body, tc.old) {
				t.Fatalf("mutation anchor missing: %q", tc.old)
			}
			if problem := checkCIImpactWorkflow(strings.Replace(body, tc.old, tc.new, 1)); !strings.Contains(problem, tc.want) {
				t.Fatalf("mutation was not rejected: got %q, want %q", problem, tc.want)
			}
		})
	}
}

func TestCIImpactWorkflowResultJobsMatchChecker(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-B", "-c", "import json,runpy; print(json.dumps(sorted(runpy.run_path('scripts/ci-impact.py')['RESULT_JOBS'])))")
	cmd.Dir = repoRootForTest(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("read result checker contract: %v\n%s", err, out)
	}
	var expected []string
	if err := json.Unmarshal(out, &expected); err != nil {
		t.Fatal(err)
	}
	var wf ciNeedsWorkflow
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	actual := ciNeedsList(wf.Jobs["ci-results"].Needs)
	slices.Sort(actual)
	if !slices.Equal(actual, expected) {
		t.Fatalf("workflow needs %v differ from checker jobs %v", actual, expected)
	}
}

// ciFastPaths is what scripts/ci-impact.py gives a reduced CI profile. It is
// read from the script (runpy) so no Go test keeps a list of its own: a path
// added to SKILL_FILES is checked against the heavy jobs' inputs and the Go
// tests that read the repository (ci_impact_narrow_readers_test.go) at once.
type ciFastPaths struct {
	// SkillPrefixes are directory prefixes with a trailing slash: path_kind "skills".
	SkillPrefixes []string `json:"skill_prefixes"`
	// SkillFiles are exact paths: path_kind "skills", never a prefix.
	SkillFiles []string `json:"skill_files"`
	// DocPrefixes are directory prefixes of the Markdown that is path_kind "docs".
	DocPrefixes []string `json:"doc_prefixes"`
	// HeavyJobs are the jobs the checker expects skipped outside the full profile.
	HeavyJobs []string `json:"heavy_jobs"`
	// ResultJobs are the jobs the result checker knows.
	ResultJobs []string `json:"result_jobs"`
}

// runCIImpactPython loads scripts/ci-impact.py with runpy as m, decodes req
// (JSON on stdin) as req in python3 -B, runs program and decodes the JSON it
// prints into out. Nothing is written into the checkout: -B keeps bytecode out.
func runCIImpactPython(t *testing.T, program string, req, out any) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-B", "-c", "import json,runpy,sys\nm=runpy.run_path('scripts/ci-impact.py')\nreq=json.load(sys.stdin)\n"+program)
	cmd.Dir = repoRootForTest(t)
	cmd.Env = append(cmd.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("scripts/ci-impact.py: %v\n%s", err, stderr.String())
	}
	if err := json.Unmarshal(stdout, out); err != nil {
		t.Fatalf("scripts/ci-impact.py printed %q: %v", stdout, err)
	}
}

// loadCIFastPaths reads the fast-path constants of scripts/ci-impact.py.
func loadCIFastPaths(t *testing.T) ciFastPaths {
	t.Helper()
	var paths ciFastPaths
	runCIImpactPython(t, `print(json.dumps({"skill_prefixes": list(m["SKILL_PREFIXES"]), "skill_files": sorted(m["SKILL_FILES"]),
"doc_prefixes": list(m["DOC_PREFIXES"]), "heavy_jobs": sorted(m["HEAVY_JOBS"]), "result_jobs": sorted(m["RESULT_JOBS"])}))`, nil, &paths)
	return paths
}

// ciImpactPathKinds returns path_kind of every path.
func ciImpactPathKinds(t *testing.T, paths []string) []string {
	t.Helper()
	var kinds []string
	runCIImpactPython(t, `print(json.dumps([m["path_kind"](p) for p in req]))`, paths, &kinds)
	return kinds
}

// ciImpactProfiles returns classify of every set of changed paths.
func ciImpactProfiles(t *testing.T, sets [][]string) []string {
	t.Helper()
	var profiles []string
	runCIImpactPython(t, `print(json.dumps([m["classify"](s) for s in req]))`, sets, &profiles)
	return profiles
}

const ciSkillsFile = ".agents/skills/a/SKILL.md"

// TestCIImpactSelectsTheFastPathForThePRLoopRunner is the acceptance test of
// issue #431: scripts/pr_loop.py is read only by the skills job's tests, so a
// PR that changes it, alone or with skill files and design documents, is a
// reduced profile; every other input stays full, and a path that only looks
// like the runner is full too.
func TestCIImpactSelectsTheFastPathForThePRLoopRunner(t *testing.T) {
	const runner = "scripts/pr_loop.py"
	cases := []struct {
		name  string
		paths []string
		want  string
	}{
		{"the runner alone", []string{runner}, "skills"},
		{"the runner and a skill file", []string{runner, ciSkillsFile}, "skills"},
		{"the runner and a design document stay skills, so skill-test still runs", []string{runner, "docs/superpowers/plans/x.md"}, "skills"},
		{"a skill file and a design document", []string{ciSkillsFile, "docs/superpowers/plans/x.md"}, "skills"},
		{"only a design document", []string{"docs/evidence/x/y.md"}, "docs"},
		{"a Go file next to the runner", []string{runner, "internal/spec/x.go"}, "full"},
		{"a Go test next to the runner", []string{runner, "cmd/pilot/cmd/x_test.go"}, "full"},
		{"another script next to the runner", []string{runner, "scripts/other.py"}, "full"},
		{"the impact script next to the runner", []string{runner, "scripts/ci-impact.py"}, "full"},
		{"a script test next to the runner", []string{runner, "scripts/tests/test_x.py"}, "full"},
		{"the workflow next to the runner", []string{runner, ".github/workflows/ci.yml"}, "full"},
		{"the root README next to the runner", []string{runner, "README.md"}, "full"},
		{"the Makefile next to the runner", []string{runner, "Makefile"}, "full"},
		{"README alone", []string{"README.md"}, "full"},
		{"no path", nil, "full"},
		// Exact equality: any other spelling is a different path, so a package
		// directory named like the runner still gets go build, vet and test.
		{"a backup of the runner", []string{"scripts/pr_loop.py.bak"}, "full"},
		{"compiled runner", []string{"scripts/pr_loop.pyc"}, "full"},
		{"a directory named like the runner", []string{"scripts/pr_loop.py/x"}, "full"},
		{"a Go package directory named like the runner", []string{"scripts/pr_loop.py/x.go"}, "full"},
		{"editor backup of the runner", []string{"scripts/pr_loop.py~"}, "full"},
		{"the runner without its extension", []string{"scripts/pr_loop"}, "full"},
		{"the result helper", []string{"scripts/pr_loop_result.py"}, "full"},
		{"the runner below another directory", []string{"x/scripts/pr_loop.py"}, "full"},
		{"the directory in another case", []string{"Scripts/pr_loop.py"}, "full"},
		{"a path with a leading dot segment", []string{"./scripts/pr_loop.py"}, "full"},
		{"a path with a doubled slash", []string{"scripts//pr_loop.py"}, "full"},
		{"an absolute path", []string{"/scripts/pr_loop.py"}, "full"},
		{"a path that climbs out and back", []string{"scripts/../scripts/pr_loop.py"}, "full"},
		{"a trailing slash", []string{"scripts/pr_loop.py/"}, "full"},
		{"a leading space", []string{" scripts/pr_loop.py"}, "full"},
		{"a trailing newline", []string{"scripts/pr_loop.py\n"}, "full"},
	}
	sets := make([][]string, len(cases))
	for i, tc := range cases {
		sets[i] = append([]string{}, tc.paths...) // an empty set, not JSON null
	}
	got := ciImpactProfiles(t, sets)
	if len(got) != len(cases) {
		t.Fatalf("classified %d sets, want %d", len(got), len(cases))
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got[i] != tc.want {
				t.Fatalf("classify(%q) = %q, want %q", tc.paths, got[i], tc.want)
			}
		})
	}
}

// TestCIImpactFastPathConstantsAreWhatPathKindUses ties the constants the Go
// guards read to the classifier: an entry that path_kind ignores would make
// those guards check a list nobody uses.
func TestCIImpactFastPathConstantsAreWhatPathKindUses(t *testing.T) {
	paths := loadCIFastPaths(t)
	if !slices.Contains(paths.SkillFiles, "scripts/pr_loop.py") {
		t.Fatalf("SKILL_FILES = %q, want it to name scripts/pr_loop.py (issue #431)", paths.SkillFiles)
	}
	var probes, want []string
	for _, prefix := range paths.SkillPrefixes {
		if !strings.HasSuffix(prefix, "/") || strings.ContainsAny(prefix, "*?[") {
			t.Fatalf("SKILL_PREFIXES entry %q must be a plain directory prefix with a trailing slash", prefix)
		}
		probes, want = append(probes, prefix+"x/y"), append(want, "skills")
	}
	for _, file := range paths.SkillFiles {
		if strings.HasSuffix(file, "/") || strings.ContainsAny(file, "*?[") {
			t.Fatalf("SKILL_FILES entry %q must be one exact file path", file)
		}
		// The entry itself is skills; a prefix match would also take what is below it.
		probes, want = append(probes, file, file+"/x.go", file+".bak"), append(want, "skills", "full", "full")
	}
	for _, prefix := range paths.DocPrefixes {
		if !strings.HasSuffix(prefix, "/") || strings.ContainsAny(prefix, "*?[") {
			t.Fatalf("DOC_PREFIXES entry %q must be a plain directory prefix with a trailing slash", prefix)
		}
		probes, want = append(probes, prefix+"x.md", prefix+"x.yaml"), append(want, "docs", "full")
	}
	got := ciImpactPathKinds(t, probes)
	for i, probe := range probes {
		if got[i] != want[i] {
			t.Errorf("path_kind(%q) = %q, want %q", probe, got[i], want[i])
		}
	}
}
