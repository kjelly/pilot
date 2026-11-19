package identityreconcile

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The variable names a mixed run hands the identity playbook are written in three places that cannot import
// one another: these constants, the playbook that reads them, and the regression tests of internal/spec that
// lock the playbook's guards (AGENTS.md §5.7). A name that drifted in one of them would make the guard a
// no-op without a failing test, so the three are compared as text.
func TestEngineVarsAreTheOnesThePlaybookAndItsRegressionTestsUse(t *testing.T) {
	playbook, err := os.ReadFile(filepath.Join("..", "..", "playbooks", "apply", "freeipa-identity-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"UsersGroupsEngineVar": UsersGroupsEngineVar, "HBACEngineVar": HBACEngineVar, "CacheSettleVar": CacheSettleVar,
		"AuthCacheOutputVar": AuthCacheOutputVar,
	} {
		if !strings.Contains(string(playbook), want) {
			t.Errorf("%s = %q is not in the identity playbook", name, want)
		}
	}
	for name, want := range map[string]string{"HBACEngineGo": HBACEngineGo, "UsersGroupsEngineGo": UsersGroupsEngineGo, "CacheSettleDefer": CacheSettleDefer} {
		if want != "go" && want != "defer" {
			t.Errorf("%s = %q: the playbook accepts go and defer", name, want)
		}
	}
	if !strings.Contains(string(playbook), "'"+CacheSettleDefer+"'") || !strings.Contains(string(playbook), "'"+HBACEngineGo+"'") {
		t.Error("the playbook does not compare the variables with the values the constants name")
	}
	if !strings.Contains(string(playbook), "--tags "+ClientCacheTag) || !strings.Contains(string(playbook), "tags: [identity, client-cache]") {
		t.Errorf("the playbook does not name the %q tag the second run selects", ClientCacheTag)
	}

	// internal/spec's regression test of the HBAC guard names the same variables.
	spec, err := os.ReadFile(filepath.Join("..", "spec", "freeipa_identity_hbac_engine_regression_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ ident, want string }{
		{"hbacEngineVar", HBACEngineVar}, {"settleVar", CacheSettleVar},
	} {
		m := regexp.MustCompile(c.ident + `\s*=\s*"([^"]+)"`).FindSubmatch(spec)
		if m == nil || string(m[1]) != c.want {
			t.Errorf("internal/spec's %s is %q, want %q", c.ident, m, c.want)
		}
	}
	old, err := os.ReadFile(filepath.Join("..", "spec", "freeipa_identity_users_groups_engine_regression_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`engineVar\s*=\s*"([^"]+)"`).FindSubmatch(old); m == nil || string(m[1]) != UsersGroupsEngineVar {
		t.Errorf("internal/spec's engineVar is %q, want %q", m, UsersGroupsEngineVar)
	}
}
