// ci_timeout_consistency_test.go keeps CI's Go test job and the Makefile's
// test-race target in step. The go test flags live only in the Makefile; CI
// runs `make test-race`. The job's timeout-minutes is the one value left in
// ci.yml, and it must stay above go test's -timeout plus setup time.
// Otherwise a hung test is cut off by a job cancellation that names
// nothing, instead of go test's stack dump that names the test.
// TestCIJobTimeoutCoversMakeTargetCaps extends that to every job that runs
// several `make <target>` steps: their -timeout caps add up, and the job's
// timeout-minutes may not be below the sum.
// TestCIJobBudgetsCoverTheSlowestObservedRun adds a floor from measurement:
// a job's timeout-minutes may not be lowered until its slowest recorded run
// is within 70% of it (kjelly/pilot#449).
package cmd

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
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
	const goodCI = "jobs:\n  test:\n    timeout-minutes: 60\n    steps:\n      - name: go test\n        run: make test-race\n"
	const goodMake = "test-race:     \t## Run tests\n\tgo test -race -count=1 -timeout 45m ./...\n\nclean:\n\trm -f x\n"
	cases := []struct {
		name, ci, makefile, want string
	}{
		{"agree", goodCI, goodMake, ""},
		{"job limit below go timeout", strings.Replace(goodCI, "60", "20", 1), goodMake, "is not above"},
		{"job limit one minute short of the setup margin", strings.Replace(goodCI, "60", "54", 1), goodMake, "is not above"},
		{"old 45m job budget with the 45m go timeout", strings.Replace(goodCI, "60", "45", 1), goodMake, "is not above"},
		{"job limit exactly at go timeout plus setup margin", strings.Replace(goodCI, "60", "55", 1), goodMake, ""},
		{"CI runs go test directly", strings.Replace(goodCI, "make test-race", "go test -race -count=1 -timeout 45m ./...", 1), goodMake, "want `make test-race`"},
		{"no -timeout in Makefile", goodCI, strings.Replace(goodMake, " -timeout 45m", "", 1), "sets no -timeout"},
		{"no job timeout", strings.Replace(goodCI, "    timeout-minutes: 60\n", "", 1), goodMake, "sets no timeout-minutes"},
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

// makeTimeoutCapsRE finds the explicit Go timeout of a recipe line: go test's
// -timeout and a compiled test binary's -test.timeout.
var makeTimeoutCapsRE = regexp.MustCompile(`-(?:test\.)?timeout[ =](\S+)`)

// makeTargetTimeoutCaps is the sum of the explicit Go timeouts in target's
// recipe. A command without one (go test then caps each package at 10m, which
// this does not count) adds nothing.
func makeTargetTimeoutCaps(t *testing.T, makefile, target string) time.Duration {
	t.Helper()
	var sum time.Duration
	for _, line := range makeTargetRecipe(t, makefile, target) {
		for _, m := range makeTimeoutCapsRE.FindAllStringSubmatch(line, -1) {
			d, err := time.ParseDuration(m[1])
			if err != nil {
				t.Fatalf("target %s: -timeout %s: %v", target, m[1], err)
			}
			sum += d
		}
	}
	return sum
}

var makeStepRE = regexp.MustCompile(`^make\s+([A-Za-z0-9_.-]+)$`)

// checkCIJobTimeoutCoversCaps reports the first job whose timeout-minutes is
// below the sum of the Go timeouts of the Makefile targets its `run: make
// <target>` steps invoke, or "" when every job covers its caps. A job with
// no such step, or whose targets set no explicit timeout, is not checked.
func checkCIJobTimeoutCoversCaps(t *testing.T, ciYAML, makefile string) string {
	t.Helper()
	var wf struct {
		Jobs map[string]struct {
			TimeoutMinutes int `yaml:"timeout-minutes"`
			Steps          []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		t.Fatalf("parse ci.yml: %v", err)
	}
	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		job := wf.Jobs[name]
		var sum time.Duration
		var targets []string
		for _, step := range job.Steps {
			m := makeStepRE.FindStringSubmatch(strings.TrimSpace(step.Run))
			if m == nil {
				continue
			}
			targets = append(targets, m[1])
			sum += makeTargetTimeoutCaps(t, makefile, m[1])
		}
		if sum == 0 {
			continue
		}
		if job.TimeoutMinutes == 0 {
			return "job " + name + " sets no timeout-minutes but runs " + strings.Join(targets, ", ")
		}
		if limit := time.Duration(job.TimeoutMinutes) * time.Minute; limit < sum {
			return "job " + name + " timeout-minutes " + limit.String() + " is below the sum " +
				sum.String() + " of the -timeout caps of " + strings.Join(targets, ", ")
		}
	}
	return ""
}

func TestCIJobTimeoutCoversMakeTargetCaps(t *testing.T) {
	root := repoRootForTest(t)
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if msg := checkCIJobTimeoutCoversCaps(t, string(ci), string(mk)); msg != "" {
		t.Fatal(msg)
	}
}

func TestCIJobTimeoutCoversMakeTargetCapsCatchesDrift(t *testing.T) {
	const goodCI = "jobs:\n  lint:\n    timeout-minutes: 40\n    steps:\n" +
		"      - run: make a-test\n      - run: make b-test\n      - run: make c-test\n" +
		"      - run: echo not a make target\n"
	const goodMake = "a-test: ## a\n\tgo test -count=1 -timeout 5m ./x/\n\n" +
		"b-test: ## b\n\tgo test -count=1 -timeout 10m ./y/\n\tgo test -count=1 -timeout=10m ./z/\n\n" +
		"c-test: ## c\n\tgo test -c -o t ./w/ && ./t -test.timeout 10m\n\tgo test ./v/\n"
	// goodMake sums to 5m + 20m + 10m = 35m.
	cases := []struct {
		name, ci, makefile, want string
	}{
		{"covers the sum", goodCI, goodMake, ""},
		{"exactly the sum", strings.Replace(goodCI, "40", "35", 1), goodMake, ""},
		{"one minute below the sum", strings.Replace(goodCI, "40", "34", 1), goodMake, "is below the sum 35m0s"},
		{"each cap alone fits but the sum does not", strings.Replace(goodCI, "40", "20", 1), goodMake, "a-test, b-test, c-test"},
		{"a target gained a cap", goodCI, strings.Replace(goodMake, "./x/", "./x/\n\tgo test -timeout 6m ./x2/", 1), "is below the sum 41m0s"},
		{"no job timeout", strings.Replace(goodCI, "    timeout-minutes: 40\n", "", 1), goodMake, "sets no timeout-minutes"},
		{"targets without an explicit cap are not checked", strings.Replace(goodCI, "40", "1", 1), "a-test:\n\tgo test ./x/\nb-test:\n\tgo test ./y/\nc-test:\n\tgo test ./z/\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCIJobTimeoutCoversCaps(t, tc.ci, tc.makefile)
			if tc.want == "" && got != "" {
				t.Fatalf("want no error, got %q", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("want error containing %q, got %q", tc.want, got)
			}
		})
	}
}

// ciJobObservation is the slowest run measured of one CI job, with where the
// number comes from.
type ciJobObservation struct {
	slowest time.Duration
	source  string
}

// ciJobSlowestObserved records, per CI job, the slowest run measured when its
// timeout-minutes was last set. It records the observation and its source, not
// a copy of the budget: the budget stays in ci.yml, and
// checkCIJobBudgetsCoverObserved compares the two.
//
// skills (kjelly/pilot#449): the job ran 292..909 s in 109 runs of
// 2026-11-17..26 (median 465 s, last 30 runs 576..909 s) against a 15m budget,
// and the 909 s run was a timeout cancellation that also failed the required
// checks. 909 s is only a lower bound, because that run was cut off, so the
// real worst case is at least this. When the job is measured again and a run
// is slower, raise the observation here with its source and the budget in
// ci.yml.
var ciJobSlowestObserved = map[string]ciJobObservation{
	"skills": {
		slowest: 909 * time.Second,
		source:  "run 45750335818, 2026-11-26, cancelled at the old 15m limit so a lower bound; 109 runs of 2026-11-17..26 ranged 292..909 s",
	},
}

// ciJobBudgetSharePercent is the share of a job's timeout-minutes its slowest
// observed run may use (kjelly/pilot#449): at most 70%, so runner variance
// (1.45x was seen on the same job) and the suites growing between two
// measurements do not turn a normal run into a timeout cancellation. It is
// an integer percent so the exact-70% boundary is exact; a float share
// rounds differently from one platform and value to the next.
const ciJobBudgetSharePercent = 70

// checkCIJobBudgetsCoverObserved reports the first job in observed whose
// timeout-minutes in ciYAML leaves its slowest observed run above
// ciJobBudgetSharePercent of the budget, or "" when every job has the
// margin. It also reports a recorded job that ci.yml no longer has, a job
// with no timeout-minutes (GitHub then allows 360 minutes, so the guard would
// check nothing), an observation with no time or source, and a ci.yml that
// does not parse. A job with no recorded observation is not checked.
//
// Limitation: this blocks lowering a budget below what the recorded
// measurement justifies. It does not notice the suites slowing down, because
// nothing here measures a run: re-measure the job, update
// ciJobSlowestObserved and the budget together.
func checkCIJobBudgetsCoverObserved(ciYAML string, observed map[string]ciJobObservation) string {
	var wf struct {
		Jobs map[string]struct {
			TimeoutMinutes int `yaml:"timeout-minutes"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return "parse ci.yml: " + err.Error()
	}
	for _, name := range slices.Sorted(maps.Keys(observed)) {
		obs := observed[name]
		if obs.slowest <= 0 || obs.source == "" {
			return "ciJobSlowestObserved[" + name + "] needs a positive time and the source of the measurement"
		}
		job, ok := wf.Jobs[name]
		if !ok {
			return "ci.yml has no `" + name + "` job, but ciJobSlowestObserved records a run of it"
		}
		if job.TimeoutMinutes == 0 {
			return "job " + name + " sets no timeout-minutes, so its slowest observed run " + obs.slowest.String() + " is not checked against a budget"
		}
		budget := time.Duration(job.TimeoutMinutes) * time.Minute
		if obs.slowest*100 <= budget*ciJobBudgetSharePercent {
			continue
		}
		// Smallest whole number of minutes whose 70% covers the run:
		// ceil(slowest / 0.70), in integers.
		share := ciJobBudgetSharePercent * time.Minute
		need := int64((obs.slowest*100 + share - 1) / share)
		return fmt.Sprintf("job %s timeout-minutes %s leaves its slowest observed run %s above %d%% of the budget (%s); at least %d minutes are needed, or measure the job again and update ciJobSlowestObserved (%s)",
			name, budget, obs.slowest, ciJobBudgetSharePercent, budget*ciJobBudgetSharePercent/100, need, obs.source)
	}
	return ""
}

func TestCIJobBudgetsCoverTheSlowestObservedRun(t *testing.T) {
	// The check skips a job with no recorded observation, so deleting the
	// entry would turn it off without a failure: make that a failure.
	if _, ok := ciJobSlowestObserved["skills"]; !ok {
		t.Fatal("ciJobSlowestObserved lost its `skills` entry (kjelly/pilot#449): the Skill and repository contracts job would have no measured floor under its timeout-minutes")
	}
	ci, err := os.ReadFile(filepath.Join(repoRootForTest(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if msg := checkCIJobBudgetsCoverObserved(string(ci), ciJobSlowestObserved); msg != "" {
		t.Fatal(msg)
	}
}

func TestCIJobBudgetCheckCatchesDrift(t *testing.T) {
	ciWith := func(job, timeout string) string {
		s := "jobs:\n  " + job + ":\n"
		if timeout != "" {
			s += "    timeout-minutes: " + timeout + "\n"
		}
		return s + "    steps:\n      - run: echo hi\n"
	}
	minutes := strconv.Itoa

	// Synthetic numbers, so the boundary cases do not move with the recorded
	// constant: the run took 7 minutes, so 70% is reached at a 10 minute budget.
	const src = "synthetic source"
	slow := map[string]ciJobObservation{"slow": {slowest: 7 * time.Minute, source: src}}
	type budgetCase struct {
		name     string
		ci       string
		observed map[string]ciJobObservation
		want     []string // all must be in the problem; none means the check passes
	}
	cases := []budgetCase{
		{"exactly 70% of the budget", ciWith("slow", minutes(10)), slow, nil},
		{"far below 70%", ciWith("slow", minutes(30)), slow, nil},
		{"one minute short of 70%", ciWith("slow", minutes(9)), slow, []string{"job slow", "timeout-minutes 9m0s", "run 7m0s", "70%", "at least 10 minutes", src}},
		{"one second over 70%", ciWith("slow", minutes(10)), map[string]ciJobObservation{"slow": {slowest: 421 * time.Second, source: src}}, []string{"job slow", "run 7m1s", "at least 11 minutes", src}},
		{"the budget is below the run itself", ciWith("slow", minutes(5)), slow, []string{"job slow", "at least 10 minutes"}},
		{"no timeout-minutes", ciWith("slow", ""), slow, []string{"job slow sets no timeout-minutes"}},
		{"timeout-minutes 0", ciWith("slow", "0"), slow, []string{"job slow sets no timeout-minutes"}},
		{"no such job", ciWith("other", minutes(1)), slow, []string{"no `slow` job"}},
		{"a job without a recorded run is not checked", ciWith("other", minutes(1)), nil, nil},
		{"observation without a time", ciWith("slow", minutes(30)), map[string]ciJobObservation{"slow": {source: src}}, []string{"ciJobSlowestObserved[slow]"}},
		{"observation without a source", ciWith("slow", minutes(30)), map[string]ciJobObservation{"slow": {slowest: 7 * time.Minute}}, []string{"ciJobSlowestObserved[slow]"}},
		{"ci.yml that does not parse", "jobs: [", slow, []string{"parse ci.yml"}},
		{"the first problem in job-name order", "jobs:\n  b:\n    timeout-minutes: 1\n  a:\n    timeout-minutes: 1\n",
			map[string]ciJobObservation{"b": {slowest: 7 * time.Minute, source: src}, "a": {slowest: 7 * time.Minute, source: src}}, []string{"job a "}},
	}

	// The recorded skills observation (909 s, so a budget of 21.65 minutes is
	// the least that keeps it within 70%): the old 15m budget and 20m fail, 25m
	// and 30m pass. These literals hold for a recorded run between 840 s (20m
	// must still fail) and 1050 s (25m must still pass); a re-measurement
	// outside that range changes them on purpose.
	for _, tc := range []struct {
		budget int
		fails  bool
	}{{15, true}, {20, true}, {25, false}, {30, false}} {
		var want []string
		if tc.fails {
			want = []string{"job skills", "timeout-minutes " + (time.Duration(tc.budget) * time.Minute).String(), "run 15m9s", "run 45750335818"}
		}
		cases = append(cases, budgetCase{"recorded skills run at " + minutes(tc.budget) + "m", ciWith("skills", minutes(tc.budget)), ciJobSlowestObserved, want})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCIJobBudgetsCoverObserved(tc.ci, tc.observed)
			if len(tc.want) == 0 {
				if got != "" {
					t.Fatalf("want no problem, got %q", got)
				}
				return
			}
			if got == "" {
				t.Fatalf("want a problem containing %q, got none", tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("want a problem containing %q, got %q", w, got)
				}
			}
		})
	}
}
