package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// The receipt and reuse jobs must observe the same frozen merge as validation.
// Default actions/checkout uses github.sha; explicit refs must preserve it.
func checkCIFrozenMergeCheckouts(ciYAML string) error {
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string
				With map[string]any
			}
		}
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return err
	}
	required := map[string]bool{"changes": false, "ci-receipt": false}
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "actions/checkout@") {
				continue
			}
			ref, explicit := step.With["ref"]
			if explicit && ref != "${{ github.sha }}" {
				return fmt.Errorf("%s checkout must use the frozen github.sha", name)
			}
			if _, needsHistory := required[name]; needsHistory {
				if !explicit || fmt.Sprint(step.With["fetch-depth"]) != "0" {
					return fmt.Errorf("%s checkout must explicitly pin github.sha and fetch full history", name)
				}
				required[name] = true
			}
		}
	}
	for _, name := range []string{"changes", "ci-receipt"} {
		if !required[name] {
			return fmt.Errorf("%s must check out the frozen merge", name)
		}
	}
	return nil
}

func TestCIFrozenMergeCheckouts(t *testing.T) {
	if err := checkCIFrozenMergeCheckouts(readCIYAML(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCIFrozenMergeCheckoutCheckCatchesDrift(t *testing.T) {
	const checkout = "    steps:\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n          ref: ${{ github.sha }}\n"
	for _, name := range []string{"changes", "ci-receipt"} {
		for _, mutation := range []struct{ name, body string }{
			{"raw head", strings.ReplaceAll(checkout, "${{ github.sha }}", "${{ github.event.pull_request.head.sha }}")},
			{"moving ref", strings.ReplaceAll(checkout, "${{ github.sha }}", "refs/pull/7/merge")},
			{"implicit ref", strings.ReplaceAll(checkout, "          ref: ${{ github.sha }}\n", "")},
			{"shallow", strings.ReplaceAll(checkout, "fetch-depth: 0", "fetch-depth: 1")},
			{"no checkout", "    steps: []\n"},
		} {
			t.Run(name+"/"+mutation.name, func(t *testing.T) {
				ci := "jobs:\n"
				for _, job := range []string{"changes", "ci-receipt"} {
					ci += "  " + job + ":\n"
					if job == name {
						ci += mutation.body
					} else {
						ci += checkout
					}
				}
				if err := checkCIFrozenMergeCheckouts(ci); err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("got %v, want checkout rejection for %s", err, name)
				}
			})
		}
	}
}

func TestCIGoShardsCoverAllPackagesExactlyOnce(t *testing.T) {
	root := repoRootForTest(t)
	run := func(command string, args ...string) string {
		t.Helper()
		cmd := exec.Command(command, args...)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", command, args, err, out)
		}
		return string(out)
	}
	all := strings.Fields(run("go", "list", "-race", "./..."))
	var got []string
	for _, shard := range []string{"spec", "cmd", "rest"} {
		packages := strings.Fields(run("bash", "scripts/ci-go-test-packages.sh", shard))
		if len(packages) == 0 {
			t.Fatalf("empty shard %s", shard)
		}
		if shard != "rest" && len(packages) != 1 {
			t.Fatalf("%s: %v", shard, packages)
		}
		got = append(got, packages...)
	}
	slices.Sort(got)
	slices.Sort(all)
	if !slices.Equal(got, all) {
		t.Fatalf("shards %v != all packages %v", got, all)
	}
	var wf struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix      yaml.Node
				MaxParallel string `yaml:"max-parallel"`
			}
			Outputs map[string]string
			If      string
		}
	}
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	if wf.Jobs["test"].Strategy.Matrix.Value != "${{ fromJSON(needs.changes.outputs.go_test_matrix) }}" ||
		wf.Jobs["test"].Strategy.MaxParallel != "${{ fromJSON(needs.changes.outputs.go_test_max_parallel) }}" ||
		wf.Jobs["changes"].Outputs["go_test_matrix"] != "${{ steps.go_matrix.outputs.matrix }}" ||
		wf.Jobs["changes"].Outputs["go_test_max_parallel"] != "${{ steps.go_matrix.outputs.max_parallel }}" {
		t.Fatal("CI must consume the generated matrix and matching parallel limit")
	}
	var generated struct {
		Include []struct {
			Shard, Group string
			Index, Total int
		}
	}
	if err := json.Unmarshal([]byte(run("python3", "scripts/ci-go-test-shards.py", "matrix")), &generated); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	ids := map[string]bool{}
	for _, entry := range generated.Include {
		if ids[entry.Shard] || entry.Index != counts[entry.Group] || entry.Total < 1 {
			t.Fatalf("invalid matrix entry: %+v", entry)
		}
		counts[entry.Group]++
		ids[entry.Shard] = true
	}
	for _, entry := range generated.Include {
		if counts[entry.Group] != entry.Total {
			t.Fatalf("incomplete matrix group: %+v", entry)
		}
	}
	if len(counts) != 3 || counts["spec"] == 0 || counts["cmd"] == 0 || counts["rest"] != 1 {
		t.Fatalf("matrix lost a required group: %v", counts)
	}
	if wf.Jobs["test"].If != "needs.changes.outputs.evidence_only != 'true'" {
		t.Fatal("Go suite skip must depend only on evidence diff")
	}
}

func TestCIIntegrationSuitesRemainParallelAndBlocking(t *testing.T) {
	var wf struct {
		Jobs map[string]struct {
			Needs    any
			If       string
			Timeout  int `yaml:"timeout-minutes"`
			Strategy struct {
				FailFast bool `yaml:"fail-fast"`
				Matrix   yaml.Node
			}
			Steps []struct{ Run string }
		}
	}
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["playbook-integration"]
	var integrationMatrix struct{ Target []string }
	if err := job.Strategy.Matrix.Decode(&integrationMatrix); err != nil {
		t.Fatal(err)
	}
	want := []string{"alert-rules-test", "identity-noop-test", "identity-ssh-cache-test", "identity-secret-test", "freeipa-server-pool-test"}
	if !slices.Equal(integrationMatrix.Target, want) || job.Strategy.FailFast {
		t.Fatal("each required runtime suite must run in its own non-fail-fast matrix job")
	}
	if job.If != "needs.changes.outputs.evidence_only != 'true'" || !slices.Contains(ciNeedsList(job.Needs), "changes") {
		t.Fatal("runtime reuse must depend on candidate validation")
	}
	mk, err := os.ReadFile(filepath.Join(repoRootForTest(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range want {
		if time.Duration(job.Timeout)*time.Minute < makeTargetTimeoutCaps(t, string(mk), target)+ciGoTestSetupMargin {
			t.Fatalf("integration job budget does not cover %s and setup", target)
		}
		for _, step := range wf.Jobs["playbook-lint"].Steps {
			if strings.Contains(step.Run, target) {
				t.Fatalf("%s is still serialized in lint", target)
			}
		}
	}
	found := false
	for _, step := range job.Steps {
		if step.Run == `make "$TARGET"` {
			found = true
		}
	}
	if !found {
		t.Fatal("matrix target must actually execute")
	}
	if !slices.Contains(ciNeedsList(wf.Jobs["image"].Needs), "playbook-integration") {
		t.Fatal("image must wait for integration")
	}
	if !slices.Contains(ciNeedsList(wf.Jobs["ci-receipt"].Needs), "image") {
		t.Fatal("receipt must wait for full image validation")
	}
}

func checkCIGoShardEvidence(ci string) error {
	var wf struct {
		Jobs map[string]struct {
			Needs    any
			If       string
			Strategy struct{ Matrix yaml.Node }
			Steps    []struct {
				Name            string
				Run             string
				Uses            string
				If              string
				Env             map[string]string
				With            map[string]any
				ContinueOnError any `yaml:"continue-on-error"`
			}
		}
	}
	if err := yaml.Unmarshal([]byte(ci), &wf); err != nil {
		return err
	}
	foundTest, foundUpload, foundRuntime := false, false, false
	for _, step := range wf.Jobs["test"].Steps {
		switch step.Name {
		case "go test":
			foundTest = step.Run == "make test-race" && step.Env["GO_TEST_JSON"] == "1" &&
				step.Env["PILOT_TEST_SHARD"] == "${{ matrix.group }}" &&
				step.Env["CI_SHARD_INDEX"] == "${{ matrix.index }}" &&
				step.Env["GO_TEST_REPORT_DIR"] == ".verification/go-shard-${{ matrix.shard }}" &&
				(step.ContinueOnError == nil || fmt.Sprint(step.ContinueOnError) == "false")
		case "Upload Go shard evidence":
			foundUpload = step.Uses == "actions/upload-artifact@v4" && step.If == "always()" &&
				step.With["name"] == "go-shard-${{ github.run_attempt }}-${{ matrix.shard }}" &&
				step.With["path"] == ".verification/go-shard-${{ matrix.shard }}/" &&
				step.With["if-no-files-found"] == "error" && step.With["include-hidden-files"] == true &&
				fmt.Sprint(step.With["retention-days"]) == "7"
		case "Go CI evidence runtime tests":
			foundRuntime = step.If == "matrix.group == 'rest'" && step.Run == "make ci-go-runtime-test"
		}
	}
	if !foundTest || !foundUpload || !foundRuntime {
		return fmt.Errorf("Go shard evidence contract: test=%v upload=%v runtime=%v", foundTest, foundUpload, foundRuntime)
	}
	gate := wf.Jobs["go-test-results"]
	if gate.If != "" || !slices.Contains(ciNeedsList(gate.Needs), "test") || !slices.Contains(ciNeedsList(gate.Needs), "changes") {
		return fmt.Errorf("result gate must depend unconditionally on the entire test matrix and changes")
	}
	verified, downloaded := false, false
	for _, step := range gate.Steps {
		if step.Run == `python3 scripts/ci-go-test-shards.py verify-run .verification/go-shards --artifact-prefix "go-shard-${GITHUB_RUN_ATTEMPT}-" --output .verification/go-shards-summary.json` && step.If == "" &&
			(step.ContinueOnError == nil || fmt.Sprint(step.ContinueOnError) == "false") {
			verified = true
		}
		if step.Uses == "actions/download-artifact@v4" && step.With["pattern"] == "go-shard-${{ github.run_attempt }}-*" {
			downloaded = true
		}
	}
	if !verified || !downloaded || !slices.Contains(ciNeedsList(wf.Jobs["image"].Needs), "go-test-results") {
		return fmt.Errorf("image must wait for downloaded and independently verified shard events")
	}
	// Full controls exist only during rollout, and must run exactly the unfiltered suite.
	if control, exists := wf.Jobs["go-test-control"]; exists {
		var controlMatrix struct{ Group []string }
		if err := control.Strategy.Matrix.Decode(&controlMatrix); err != nil {
			return err
		}
		if !slices.Equal(controlMatrix.Group, []string{"spec", "cmd"}) || control.If != "needs.changes.outputs.evidence_only != 'true'" {
			return fmt.Errorf("full comparison requires both complete package controls")
		}
		full := false
		for _, step := range control.Steps {
			if step.Name == "go test" && step.Run == "make test-race" && step.Env["GO_TEST_JSON"] == "1" &&
				step.Env["PILOT_TEST_SHARD"] == "${{ matrix.group }}" && step.Env["CI_SHARD_INDEX"] == "" &&
				step.Env["GO_TEST_REPORT_DIR"] == ".verification/go-control-${{ matrix.group }}" {
				full = true
			}
		}
		comparison := wf.Jobs["go-test-comparison"]
		compared := false
		for _, step := range comparison.Steps {
			if strings.HasPrefix(step.Run, "python3 scripts/ci-go-test-shards.py compare --shards ") && step.If == "" && step.ContinueOnError == nil {
				compared = true
			}
		}
		if !full || !compared || comparison.If != "" || !slices.Contains(ciNeedsList(comparison.Needs), "go-test-control") ||
			!slices.Contains(ciNeedsList(comparison.Needs), "go-test-results") ||
			!slices.Contains(ciNeedsList(wf.Jobs["image"].Needs), "go-test-comparison") {
			return fmt.Errorf("image must wait for actual same-candidate full/shard comparison")
		}
	}
	for _, step := range wf.Jobs["changes"].Steps {
		if strings.Contains(step.Run, "scripts/ci-go-test-shards.py matrix --github-output") {
			return nil
		}
	}
	return fmt.Errorf("missing matrix generator")
}

func TestCIGoShardEvidence(t *testing.T) {
	if err := checkCIGoShardEvidence(readCIYAML(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCIGoShardEvidenceCatchesDrift(t *testing.T) {
	ci := readCIYAML(t)
	mutations := []struct{ old, replacement string }{
		{"GO_TEST_JSON: '1'", "GO_TEST_JSON: '0'"},
		{"go-shard-${{ github.run_attempt }}-${{ matrix.shard }}", "shared-evidence"},
		{"if-no-files-found: error", "if-no-files-found: warn"},
		{"run: make ci-go-runtime-test", "run: true"},
		{"CI_SHARD_INDEX: ${{ matrix.index }}", "CI_SHARD_INDEX: '0'"},
		{"needs: [changes, test]", "needs: changes"},
		{"scripts/ci-go-test-shards.py verify-run", "scripts/ci-go-test-shards.py summarize"},
		{"run: python3 scripts/ci-go-test-shards.py verify-run", "run: echo python3 scripts/ci-go-test-shards.py verify-run"},
	}
	if strings.Contains(ci, "  go-test-control:\n") {
		mutations = append(mutations, []struct{ old, replacement string }{
			{"group: [spec, cmd]", "group: [spec]"},
			{".verification/go-control-${{ matrix.group }}", ".verification/wrong-control"},
			{"needs: [changes, test, go-test-control, go-test-results]", "needs: [changes, test, go-test-results]"},
			{"run: python3 scripts/ci-go-test-shards.py compare --shards", "run: echo python3 scripts/ci-go-test-shards.py compare --shards"},
		}...)
	}
	for _, mutation := range mutations {
		if !strings.Contains(ci, mutation.old) {
			t.Fatalf("missing mutation anchor %q", mutation.old)
		}
		if err := checkCIGoShardEvidence(strings.Replace(ci, mutation.old, mutation.replacement, 1)); err == nil {
			t.Fatalf("accepted drift: %s", mutation.old)
		}
	}
}
