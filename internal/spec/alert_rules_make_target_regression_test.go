package spec

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// alertRulesHelperCall marks a file whose tests use the helpers that need
// docker images or ansible-playbook. The Go test job skips those tests;
// only `make alert-rules-test` (CI's Playbook lint job,
// PILOT_REQUIRE_CONTAINER_TESTS=1) runs them.
var alertRulesHelperCall = regexp.MustCompile(`requireContainerImage\(|runLocalPlays?\(|hostHealthPromtest\(|renderHostHealthRules\(`)

// alertRulesTestFiles returns every test file in this package that uses
// those helpers, except this one.
func alertRulesTestFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		if f == "alert_rules_make_target_regression_test.go" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if alertRulesHelperCall.Match(data) {
			out = append(out, f)
		}
	}
	return out
}

// externalToolCall marks a test body that renders, runs promtool or
// Alertmanager, or runs ansible-playbook.
var externalToolCall = regexp.MustCompile(`requireContainerImage\(|runLocalPlays?\(|hostHealthPromtest\(|renderHostHealthRules\(|LookPath\("ansible-playbook"\)|LookPath\("docker"\)`)

// alertRulesMakeRun returns the -run pattern of the alert-rules-test target.
func alertRulesMakeRun(t *testing.T) *regexp.Regexp {
	t.Helper()
	data, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^alert-rules-test:.*\n\t.*-run '([^']+)' \./internal/spec/`).FindSubmatch(data)
	if m == nil {
		t.Fatal("Makefile alert-rules-test has no -run '<pattern>' ./internal/spec/ recipe")
	}
	return regexp.MustCompile(string(m[1]))
}

// unselectedToolTests returns the Test functions in src that call an
// external tool and that run does not select.
func unselectedToolTests(src string, run *regexp.Regexp) []string {
	var out []string
	funcs := regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\) \{`).FindAllStringSubmatchIndex(src, -1)
	for i, f := range funcs {
		end := len(src)
		if i+1 < len(funcs) {
			end = funcs[i+1][0]
		}
		name := src[f[2]:f[3]]
		if externalToolCall.MatchString(src[f[1]:end]) && !run.MatchString(name) {
			out = append(out, name)
		}
	}
	return out
}

// TestRegression_AlertRulesMakeTargetSelectsEveryToolTest keeps the
// alert-rules-test -run pattern in step with the tests that need its tools
// (AGENTS.md §5.7): a promtool, Alertmanager or ansible-playbook test the
// pattern misses is skipped everywhere in CI and never runs.
func TestRegression_AlertRulesMakeTargetSelectsEveryToolTest(t *testing.T) {
	run := alertRulesMakeRun(t)
	if !strings.Contains(run.String(), "TestRegression_HostHealth") {
		t.Errorf("alert-rules-test pattern %q must select TestRegression_HostHealth*", run)
	}
	files := alertRulesTestFiles(t)
	for _, want := range []string{"host_health_alert_rules_regression_test.go", "alertmanager_inhibit_regression_test.go", "login_probe_regression_test.go", "host_monitoring_textfile_checkmode_regression_test.go"} {
		found := false
		for _, f := range files {
			found = found || f == want
		}
		if !found {
			t.Errorf("%s no longer uses the container/ansible helpers; the file scan missed it", want)
		}
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if miss := unselectedToolTests(string(data), run); len(miss) > 0 {
			t.Errorf("%s: make alert-rules-test does not select %v", f, miss)
		}
	}
	// The check must notice such a test.
	probe := "func TestNewPromtoolCase(t *testing.T) {\n\tout, ok := hostHealthPromtest(t, nil, \"\")\n}\n"
	if miss := unselectedToolTests(probe, run); len(miss) != 1 {
		t.Errorf("a promtool test outside the pattern went unnoticed: %v", miss)
	}
}
