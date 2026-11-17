package cmd

import (
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
