package cmd

import (
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
	all := strings.Fields(run("go", "list", "./..."))
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
			Strategy struct{ Matrix struct{ Shard []string } }
			If       string
		}
	}
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(wf.Jobs["test"].Strategy.Matrix.Shard, []string{"spec", "cmd", "rest"}) {
		t.Fatal("CI must run all three package shards")
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
				Matrix   struct{ Target []string }
			}
			Steps []struct{ Run string }
		}
	}
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["playbook-integration"]
	want := []string{"alert-rules-test", "identity-noop-test", "identity-ssh-cache-test", "identity-secret-test", "freeipa-server-pool-test"}
	if !slices.Equal(job.Strategy.Matrix.Target, want) || job.Strategy.FailFast {
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

func checkCIGoBaselineEvidence(ci string) error {
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string
				Run  string
				Uses string
				If   string
				Env  map[string]string
				With map[string]any
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
				step.Env["PILOT_TEST_SHARD"] == "${{ matrix.shard }}" &&
				step.Env["GO_TEST_REPORT_DIR"] == ".verification/go-baseline-${{ matrix.shard }}"
		case "Upload Go baseline evidence":
			foundUpload = step.Uses == "actions/upload-artifact@v4" && step.If == "always()" &&
				step.With["name"] == "go-baseline-${{ github.run_attempt }}-${{ matrix.shard }}" &&
				step.With["path"] == ".verification/go-baseline-${{ matrix.shard }}/" &&
				step.With["if-no-files-found"] == "error" && step.With["include-hidden-files"] == true &&
				fmt.Sprint(step.With["retention-days"]) == "7"
		case "Go CI evidence runtime tests":
			foundRuntime = step.If == "matrix.shard == 'rest'" && step.Run == "make ci-go-runtime-test"
		}
	}
	if !foundTest || !foundUpload || !foundRuntime {
		return fmt.Errorf("Go baseline evidence contract: test=%v upload=%v runtime=%v", foundTest, foundUpload, foundRuntime)
	}
	return nil
}

func TestCIGoBaselineEvidence(t *testing.T) {
	if err := checkCIGoBaselineEvidence(readCIYAML(t)); err != nil {
		t.Fatal(err)
	}
}

func TestCIGoBaselineEvidenceCatchesDrift(t *testing.T) {
	ci := readCIYAML(t)
	for _, mutation := range []struct{ old, replacement string }{
		{"GO_TEST_JSON: '1'", "GO_TEST_JSON: '0'"},
		{"go-baseline-${{ github.run_attempt }}-${{ matrix.shard }}", "shared-evidence"},
		{"if-no-files-found: error", "if-no-files-found: warn"},
		{"run: make ci-go-runtime-test", "run: true"},
	} {
		if !strings.Contains(ci, mutation.old) {
			t.Fatalf("missing mutation anchor %q", mutation.old)
		}
		if err := checkCIGoBaselineEvidence(strings.Replace(ci, mutation.old, mutation.replacement, 1)); err == nil {
			t.Fatalf("accepted drift: %s", mutation.old)
		}
	}
}
