package spec

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_OsPatchSlaSpec locks the structure of the
// `docs/verification/os-patch-sla.md` spec which implements the
// "OS 套件定期更新: Critical 15d / High 30d / Medium 90d" rule.
//
// Pinning the row IDs and content here means a refactor that drops
// a row, renames an ID, or weakens an expected value fails this
// test loudly — instead of silently changing the policy contract.
func TestRegression_OsPatchSlaSpec(t *testing.T) {
	const specPath = "../../docs/verification/os-patch-sla.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	// C1..C8 inclusive, no gaps, no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"}
	if len(s.Rows) != 8 {
		t.Fatalf("rows=%d want=8", len(s.Rows))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	// C1 and C4 expect anchored regex `^0$`. Other rows must be
	// concrete values (not vague words like "OK" or "合理").
	for _, r := range s.Rows {
		if strings.Contains(strings.ToLower(strings.TrimSpace(r.Expected)), "ok") {
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}
	// C7 is the "no prod-direct-push" marker — its command must
	// mention the marker file path so the safety contract is
	// preserved.
	for _, r := range s.Rows {
		if r.ID == "C7" && !strings.Contains(r.Command, "/etc/no-prod-direct-push") {
			t.Errorf("C7 must guard the /etc/no-prod-direct-push marker; got %q", r.Command)
		}
	}
	// C8 (issue #167) is the package-installed row: it must read dpkg's
	// state for unattended-upgrades and compare the exact `installed` status.
	// `dpkg-query -W` alone exits 0 for a removed-but-not-purged package
	// (`config-files`), so a bare rc check would pass without the package.
	for _, r := range s.Rows {
		if r.ID != "C8" {
			continue
		}
		for _, want := range []string{"dpkg-query", "unattended-upgrades", "grep -qx installed"} {
			if !strings.Contains(r.Command, want) {
				t.Errorf("C8 command %q must contain %q", r.Command, want)
			}
		}
		if strings.TrimSpace(r.Expected) != "0" {
			t.Errorf("C8 expected=%q want 0", r.Expected)
		}
	}
	// Lint must not produce errors.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}

// TestRegression_OsPatchSlaTargetsAreEnvironmentGroups locks the §1 targets
// table of os-patch-sla.md to the stage vocabulary (issue #174).
//
// Why the §1 groups are not compared with one inventory (AGENTS.md §1.3): that
// comparison assumes the spec declares the group set of one concrete inventory.
// os-patch-sla is applied per stage, each stage with its own inventory, so the
// §1 rows are environment GROUPS (sandbox/staging/prod) resolved against
// whatever inventory `pilot verify -i` is given. The vm-target reference
// environment gets its group via `vm-target up --hosts sandbox`; alignment
// responsibility lives there, not in a fixed host list in this spec.
//
// The table must never contain a group `all` (or empty) row: pilot verify's
// v1TargetGroups then switches the whole table to LITERAL hostnames and fails
// with "absent from inventory" on every inventory that lacks those names
// (`test-vm`, ...). So the groups must equal the stage vocabulary the apply
// playbook's own `patch_stage in [...]` gate accepts; the vocabulary is read
// from the playbook rather than hard-coded a second time.
func TestRegression_OsPatchSlaTargetsAreEnvironmentGroups(t *testing.T) {
	s, err := Parse("../../docs/verification/os-patch-sla.md")
	if err != nil {
		t.Fatal(err)
	}
	vocab := osPatchSlaPlaybookStages(t)
	if len(vocab) == 0 {
		t.Fatal("playbook stage vocabulary is empty")
	}
	if len(s.Hosts) == 0 {
		t.Fatal("spec §1 declares no targets")
	}
	for _, problem := range osPatchSlaTargetProblems(s.Hosts, vocab) {
		t.Error(problem)
	}
}

// osPatchSlaTargetProblems is the single predicate for the §1 contract, shared
// by the "should pass" test (real spec) and the "should trigger" test.
func osPatchSlaTargetProblems(hosts []Host, vocab []string) []string {
	var problems []string
	var groups []string
	for _, h := range hosts {
		g := strings.TrimSpace(h.Group)
		if g == "" || g == "all" {
			problems = append(problems, fmt.Sprintf("§1 row %q has group %q: an all/empty group makes pilot verify match the table as literal hostnames", h.Hostname, h.Group))
		}
		if h.Hostname != g {
			problems = append(problems, fmt.Sprintf("§1 row hostname %q must equal its group %q (rows are environment groups, not hosts)", h.Hostname, g))
		}
		groups = append(groups, g)
	}
	sort.Strings(groups)
	if got, want := strings.Join(groups, ","), strings.Join(vocab, ","); got != want {
		problems = append(problems, fmt.Sprintf("§1 groups=%s, playbook patch_stage vocabulary=%s", got, want))
	}
	return problems
}

// osPatchSlaPlaybookStages reads the stage list from the `patch_stage in [...]`
// assert of playbooks/apply/os-patch-sla-apply.yml, sorted.
func osPatchSlaPlaybookStages(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../playbooks/apply/os-patch-sla-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []struct {
		Tasks []struct {
			Name   string `yaml:"name"`
			Assert struct {
				That []string `yaml:"that"`
			} `yaml:"ansible.builtin.assert"`
		} `yaml:"tasks"`
	}
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	const prefix = "patch_stage in ["
	for _, p := range plays {
		for _, task := range p.Tasks {
			for _, cond := range task.Assert.That {
				cond = strings.TrimSpace(cond)
				if !strings.HasPrefix(cond, prefix) || !strings.HasSuffix(cond, "]") {
					continue
				}
				var out []string
				for _, v := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(cond, prefix), "]"), ",") {
					out = append(out, strings.Trim(strings.TrimSpace(v), "'\""))
				}
				sort.Strings(out)
				return out
			}
		}
	}
	t.Fatal("no `patch_stage in [...]` assert found in os-patch-sla-apply.yml")
	return nil
}

// TestRegression_OsPatchSlaTargetsGateTriggers is the "should trigger" half
// (AGENTS.md section 5.12): the previous §1 shape (a literal test host in group
// `all` instead of the sandbox row) must be rejected by the same predicate the
// test above applies. The old shape is built from the parsed Hosts, so
// re-aligning the markdown table cannot break this test.
func TestRegression_OsPatchSlaTargetsGateTriggers(t *testing.T) {
	s, err := Parse("../../docs/verification/os-patch-sla.md")
	if err != nil {
		t.Fatal(err)
	}
	vocab := osPatchSlaPlaybookStages(t)
	if p := osPatchSlaTargetProblems(s.Hosts, vocab); len(p) != 0 {
		t.Fatalf("precondition: real spec must be clean, got %v", p)
	}
	old := make([]Host, 0, len(s.Hosts))
	replaced := false
	for _, h := range s.Hosts {
		if h.Group == "sandbox" {
			h = Host{Hostname: "test-vm", Group: "all"}
			replaced = true
		}
		old = append(old, h)
	}
	if !replaced {
		t.Fatal("real spec §1 has no sandbox row to replace")
	}
	problems := osPatchSlaTargetProblems(old, vocab)
	if len(problems) == 0 {
		t.Fatal("old-shape §1 (test-vm in group all) was not rejected")
	}
	if !strings.Contains(strings.Join(problems, "\n"), `group "all"`) {
		t.Errorf("old shape rejected for the wrong reason: %v", problems)
	}
}
