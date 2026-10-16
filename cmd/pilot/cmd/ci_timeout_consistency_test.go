// ci_timeout_consistency_test.go keeps CI's Go test job and the Makefile's
// test-race target in step. The go test flags live only in the Makefile; CI
// runs `make test-race`. The job's timeout-minutes is the one value left in
// ci.yml, and it must stay above go test's -timeout plus setup time.
// Otherwise a hung test is cut off by a job cancellation that names
// nothing, instead of go test's stack dump that names the test.
package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// ciGoTestSetupMargin covers what CI's Go test job runs before go test's
// -timeout starts counting: the earlier steps (checkout, setup-go, vet,
// build) and compiling the -race test binaries. With a warm cache on
// 2026-10-16 these took 32 s and about 155 s; the margin leaves room for a
// cold cache.
const ciGoTestSetupMargin = 10 * time.Minute

var makeTimeoutFlagRE = regexp.MustCompile(`-timeout[ =](\S+)`)

// makeTargetRecipe returns the tab-indented recipe lines of target in a
// Makefile.
func makeTargetRecipe(t *testing.T, makefile, target string) []string {
	t.Helper()
	var recipe []string
	in := false
	for _, line := range strings.Split(makefile, "\n") {
		if strings.HasPrefix(line, target+":") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(line, "\t") {
			break
		}
		recipe = append(recipe, strings.TrimSpace(line))
	}
	if len(recipe) == 0 {
		t.Fatalf("Makefile has no recipe for %q", target)
	}
	return recipe
}

// checkCIGoTestTimeout reports why ci.yml and the Makefile disagree, or ""
// when they agree.
func checkCIGoTestTimeout(t *testing.T, ciYAML, makefile string) string {
	t.Helper()
	var wf struct {
		Jobs map[string]struct {
			TimeoutMinutes int `yaml:"timeout-minutes"`
			Steps          []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	job, ok := wf.Jobs["test"]
	if !ok {
		return "ci.yml has no `test` job"
	}
	var run string
	for _, step := range job.Steps {
		if step.Name == "go test" {
			run = strings.TrimSpace(step.Run)
		}
	}
	if run != "make test-race" {
		return "the `go test` step runs `" + run + "`, want `make test-race` so the flags have one source"
	}

	recipe := strings.Join(makeTargetRecipe(t, makefile, "test-race"), "\n")
	if !strings.Contains(recipe, "go test -race") {
		return "test-race does not run `go test -race`: " + recipe
	}
	m := makeTimeoutFlagRE.FindStringSubmatch(recipe)
	if m == nil {
		return "test-race sets no -timeout, so go test uses its 10m default: " + recipe
	}
	goTimeout, err := time.ParseDuration(m[1])
	if err != nil {
		return "test-race -timeout " + m[1] + ": " + err.Error()
	}
	if job.TimeoutMinutes == 0 {
		return "the `test` job sets no timeout-minutes"
	}
	jobLimit := time.Duration(job.TimeoutMinutes) * time.Minute
	if jobLimit < goTimeout+ciGoTestSetupMargin {
		return "job timeout-minutes " + jobLimit.String() + " is not above go test -timeout " +
			goTimeout.String() + " plus " + ciGoTestSetupMargin.String() + " setup"
	}
	return ""
}

func TestCIGoTestTimeoutFiresBeforeJobLimit(t *testing.T) {
	root := repoRootForTest(t)
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if msg := checkCIGoTestTimeout(t, string(ci), string(mk)); msg != "" {
		t.Fatal(msg)
	}
}

func TestCIGoTestTimeoutCheckCatchesDrift(t *testing.T) {
	const goodCI = "jobs:\n  test:\n    timeout-minutes: 45\n    steps:\n      - name: go test\n        run: make test-race\n"
	const goodMake = "test-race:     \t## Run tests\n\tgo test -race -count=1 -timeout 30m ./...\n\nclean:\n\trm -f x\n"
	cases := []struct {
		name, ci, makefile, want string
	}{
		{"agree", goodCI, goodMake, ""},
		{"job limit below go timeout", strings.Replace(goodCI, "45", "20", 1), goodMake, "is not above"},
		{"job limit without setup margin", strings.Replace(goodCI, "45", "39", 1), goodMake, "is not above"},
		{"CI runs go test directly", strings.Replace(goodCI, "make test-race", "go test -race -count=1 -timeout 30m ./...", 1), goodMake, "want `make test-race`"},
		{"no -timeout in Makefile", goodCI, strings.Replace(goodMake, " -timeout 30m", "", 1), "sets no -timeout"},
		{"no job timeout", strings.Replace(goodCI, "    timeout-minutes: 45\n", "", 1), goodMake, "sets no timeout-minutes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCIGoTestTimeout(t, tc.ci, tc.makefile)
			if tc.want == "" && got != "" {
				t.Fatalf("want no error, got %q", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("want error containing %q, got %q", tc.want, got)
			}
		})
	}
}
