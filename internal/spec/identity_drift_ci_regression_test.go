package spec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The users/groups drift observer is proved with real ansible-playbook. A Go
// test job without Ansible skips those tests, so `make identity-secret-test`
// (PILOT_REQUIRE_CONTAINER_TESTS=1, run by CI's Playbook lint job) must select
// every one of them, and must fail rather than skip when Ansible is missing.

// makeRunPatterns returns the -run pattern of every `go test` line of a Makefile
// target, keyed by the package argument.
func makeRunPatterns(t *testing.T, target string) map[string]*regexp.Regexp {
	t.Helper()
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	patterns := map[string]*regexp.Regexp{}
	in := false
	for _, line := range strings.Split(string(makefile), "\n") {
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
		m := regexp.MustCompile(`PILOT_REQUIRE_CONTAINER_TESTS=1 go test .* -run '([^']+)' (\./\S+)`).FindStringSubmatch(line)
		if m == nil {
			continue
		}
		patterns[strings.TrimSuffix(m[2], "/")] = regexp.MustCompile(strings.ReplaceAll(m[1], "$$", "$"))
	}
	return patterns
}

func testFuncs(t *testing.T, file string) []string {
	t.Helper()
	src, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, decl := range src.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
			names = append(names, fn.Name.Name)
		}
	}
	return names
}

func TestRegression_IdentityDriftObjectTestsRunInRequiredCI(t *testing.T) {
	patterns := makeRunPatterns(t, "identity-secret-test")
	// Each real-ansible test file, the package it lives in, and the tests in it
	// that need Ansible (the others run in the ordinary Go test job).
	for _, tc := range []struct {
		file, pkg    string
		needsAnsible func(name string) bool
	}{
		{"identity_drift_normalization_test.go", "./internal/spec", func(string) bool { return true }},
		{"../accessgrants/identity_objects_probe_real_test.go", "./internal/accessgrants", func(n string) bool { return strings.HasPrefix(n, "TestRegression_IdentitySecretDriftProbe") }},
		{"../../cmd/pilot/cmd/identity_drift_objects_cli_test.go", "./cmd/pilot/cmd", func(string) bool { return true }},
	} {
		re := patterns[tc.pkg]
		if re == nil {
			t.Fatalf("identity-secret-test has no go test line for %s", tc.pkg)
		}
		count := 0
		for _, name := range testFuncs(t, tc.file) {
			if !tc.needsAnsible(name) {
				continue
			}
			count++
			if !re.MatchString(name) {
				t.Errorf("identity-secret-test does not run %s (%s); CI would skip it without Ansible", name, tc.pkg)
			}
		}
		if count == 0 {
			t.Errorf("found no real-ansible test in %s", tc.file)
		}
	}
	// The matrix tests that gained the --include-users-groups command.
	if re := patterns["./cmd/pilot/cmd"]; re == nil || !re.MatchString("TestIdentitySecretDriftCommandsDefaultScopeSurvivesAVaultTargetGroup") {
		t.Error("identity-secret-test no longer selects the TestIdentitySecretDriftCommands matrix")
	}

	makefile, _ := os.ReadFile("../../Makefile")
	if !strings.Contains(string(makefile), "\tpython3 -I playbooks/check/files/test_identity_object_observer.py\n") {
		t.Error("identity-secret-test must run the observer's Python tests")
	}
}

// TestRegression_IdentityDriftObjectTestsFailWithoutAnsible: under the required
// job's environment a missing ansible-playbook is a failure, not a skip, for
// every real-ansible test the observer work added.
func TestRegression_IdentityDriftObjectTestsFailWithoutAnsible(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	for _, tc := range []struct{ pkg, test string }{
		{"../../internal/spec", "TestIdentityDriftSharedNormalizationInAnsible"},
		{"../../internal/accessgrants", "TestRegression_IdentitySecretDriftProbeUsersGroupsConverged"},
		{"../../cmd/pilot/cmd", "TestIdentitySecretDriftCommandsUsersGroupsFromCapturedFixtures"},
	} {
		t.Run(filepath.Base(tc.pkg)+"/"+tc.test, func(t *testing.T) {
			cmd := exec.Command(goBin, "test", "-count=1", "-v", "-run", "^"+tc.test+"$", tc.pkg)
			// A PATH with go and nothing that provides ansible-playbook.
			cmd.Env = append(os.Environ(), "PILOT_REQUIRE_CONTAINER_TESTS=1", "PATH="+filepath.Dir(goBin))
			out, err := cmd.CombinedOutput()
			if err == nil || strings.Contains(string(out), "--- SKIP") || !strings.Contains(string(out), "required ansible-playbook not installed") {
				t.Fatalf("a missing ansible-playbook must fail the required job, not skip: err=%v\n%s", err, out)
			}
		})
	}
}
