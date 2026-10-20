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

	"go.yaml.in/yaml/v3"
)

// The Go CI job may have no Ansible. Every test in these three files must
// also run in the required-Ansible job, including tests using computeOnly
// rather than runIdentityTasks.
func TestRegression_IdentityNoopCISelectsEveryCase(t *testing.T) {
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^identity-noop-test:.*\n\tPILOT_REQUIRE_CONTAINER_TESTS=1 go test .* -run '([^']+)' ./internal/spec/`).FindSubmatch(makefile)
	if m == nil {
		t.Fatal("identity-noop-test must require its Ansible dependency")
	}
	run := regexp.MustCompile(strings.ReplaceAll(string(m[1]), "$$", "$"))
	count := 0
	for _, file := range []string{"freeipa_identity_user_listing_regression_test.go", "freeipa_identity_group_noop_regression_test.go", "freeipa_identity_membership_case_regression_test.go"} {
		src, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range src.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			count++
			if !run.MatchString(fn.Name.Name) {
				t.Errorf("identity-noop-test misses %s", fn.Name.Name)
			}
		}
	}
	if count < 7 {
		t.Fatalf("only %d identity cases found", count)
	}
	data, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct{ Run, Uses string }
		}
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	ansible, goSetup, selected := -1, -1, -1
	for i, step := range workflow.Jobs["playbook-lint"].Steps {
		if strings.Contains(step.Run, "pip install") && strings.Contains(step.Run, "ansible-core") {
			ansible = i
		}
		if strings.HasPrefix(step.Uses, "actions/setup-go@") {
			goSetup = i
		}
		if strings.TrimSpace(step.Run) == "make identity-noop-test" {
			selected = i
		}
	}
	if selected < 0 || ansible < 0 || goSetup < 0 || ansible >= selected || goSetup >= selected {
		t.Fatalf("required identity CI recipe must follow Ansible and Go setup: ansible=%d go=%d recipe=%d", ansible, goSetup, selected)
	}
}

func TestRegression_IdentityRequiredToolDoesNotSkip(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.v", "-test.run=^TestRegression_IdentityUserListingSkipsNoOpCalls$/^users_already_in_the_declared_state_get_no_calls$")
	cmd.Env = append(os.Environ(), "PILOT_REQUIRE_CONTAINER_TESTS=1", "PATH="+filepath.Join(t.TempDir(), "missing-tools"))
	out, err := cmd.CombinedOutput()
	if err == nil || strings.Contains(string(out), "--- SKIP") || !strings.Contains(string(out), "ansible-playbook") {
		t.Fatalf("required Ansible dependency must fail instead of skipping: err=%v\n%s", err, out)
	}
}
