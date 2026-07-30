package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaDNSSpec locks the Phase 1 shape of
// docs/verification/freeipa-dns.md (docs/specs/freeipa-dns.md §14.2): all
// twelve rows exist with a non-empty command/expected, and the spec lints
// clean.
func TestRegression_FreeipaDNSSpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-dns.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	gotIDs := make([]string, 0, len(s.Rows))
	seen := map[string]bool{}
	for _, row := range s.Rows {
		if seen[row.ID] {
			t.Errorf("duplicate row ID %q", row.ID)
		}
		seen[row.ID] = true
		gotIDs = append(gotIDs, row.ID)
		if strings.TrimSpace(row.Command) == "" || strings.TrimSpace(row.Expected) == "" {
			t.Errorf("row %s has an empty command or expected value", row.ID)
		}
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("row IDs=%v want=%v", gotIDs, wantIDs)
	}
	if findings := Lint(s); HasErrors(findings) {
		t.Errorf("spec lint errors:\n%s", fsToString(findings))
	}
}

// freeipaDNSContract is a minimal local decode of contracts/freeipa-dns.yaml
// — just the fields this test locks — so this test doesn't need to import
// internal/contract (which itself imports internal/spec).
type freeipaDNSContract struct {
	ID              string                     `yaml:"id"`
	Role            string                     `yaml:"role"`
	HostCardinality string                     `yaml:"hostCardinality"`
	Dependencies    []freeipaDNSDependency     `yaml:"dependencies"`
	Traceability    freeipaDNSTraceability     `yaml:"traceability"`
	Site            freeipaDNSSite             `yaml:"site"`
	Playbooks       map[string]string          `yaml:"playbooks"`
	RegressionTests []string                   `yaml:"regressionTests"`
	Specs           []freeipaDNSContractedSpec `yaml:"specs"`
}

type freeipaDNSDependency struct {
	Component string `yaml:"component"`
	Required  bool   `yaml:"required"`
	Relation  string `yaml:"relation"`
}

type freeipaDNSTraceability struct {
	Mode       string                         `yaml:"mode"`
	Rows       map[string]freeipaDNSTrow      `yaml:"rows"`
	Exemptions map[string]freeipaDNSExemption `yaml:"exemptions"`
}

type freeipaDNSTrow struct {
	Tags   []string `yaml:"tags"`
	Reason string   `yaml:"reason"`
}

type freeipaDNSExemption struct {
	Kind   string `yaml:"kind"`
	Reason string `yaml:"reason"`
}

type freeipaDNSSite struct {
	Include bool `yaml:"include"`
	OptIn   bool `yaml:"optIn"`
}

type freeipaDNSContractedSpec struct {
	Path string `yaml:"path"`
}

// TestRegression_FreeipaDNSContract locks docs/specs/freeipa-dns.md §14.2's
// contract-shape requirements: day-2 (site.include: false), dependency on
// freeipa-server via sameHosts, and hostCardinality: exactly-one.
func TestRegression_FreeipaDNSContract(t *testing.T) {
	const contractPath = "../../contracts/freeipa-dns.yaml"
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	var c freeipaDNSContract
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse %s: %v", contractPath, err)
	}

	if c.ID != "freeipa-dns" {
		t.Errorf("id = %q, want freeipa-dns", c.ID)
	}
	if c.HostCardinality != "exactly-one" {
		t.Errorf("hostCardinality = %q, want exactly-one (docs/specs/freeipa-dns.md §3.3)", c.HostCardinality)
	}
	if c.Site.Include {
		t.Error("site.include must be false — freeipa-dns is a day-2 reconciler, not part of site.yml (§3.1)")
	}
	if !c.Site.OptIn {
		t.Error("site.optIn must be true")
	}

	foundDep := false
	for _, dep := range c.Dependencies {
		if dep.Component == "freeipa-server" {
			foundDep = true
			if dep.Relation != "sameHosts" {
				t.Errorf("freeipa-server dependency relation = %q, want sameHosts", dep.Relation)
			}
			if !dep.Required {
				t.Error("freeipa-server dependency must be required")
			}
		}
	}
	if !foundDep {
		t.Error("contract must declare a dependency on freeipa-server")
	}

	if c.Traceability.Mode != "mapped" {
		t.Fatalf("traceability.mode = %q, want mapped", c.Traceability.Mode)
	}
	// C12 (idempotent rerun) is exempted (verifyOnly): it's a multi-run
	// property, not something a single tagged task implements — same
	// reasoning as freeipa-identity.md's own §7 dynamic SOPs.
	exemptRows := map[string]bool{"C12": true}
	for _, id := range []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12"} {
		ref := "docs/verification/freeipa-dns.md#" + id
		if exemptRows[id] {
			exemption, ok := c.Traceability.Exemptions[ref]
			if !ok {
				t.Errorf("traceability.exemptions is missing %s", ref)
				continue
			}
			if exemption.Kind != "verifyOnly" || exemption.Reason == "" {
				t.Errorf("exemption %s must be kind: verifyOnly with a reason", ref)
			}
			continue
		}
		row, ok := c.Traceability.Rows[ref]
		if !ok {
			t.Errorf("traceability.rows is missing %s", ref)
			continue
		}
		if len(row.Tags) == 0 || row.Reason == "" {
			t.Errorf("traceability row %s must have tags and a reason", ref)
		}
	}

	if c.Playbooks["apply"] != "playbooks/apply/freeipa-dns-apply.yml" {
		t.Errorf("playbooks.apply = %q, want playbooks/apply/freeipa-dns-apply.yml", c.Playbooks["apply"])
	}
	wantSpec := "docs/verification/freeipa-dns.md"
	foundSpec := false
	for _, s := range c.Specs {
		if s.Path == wantSpec {
			foundSpec = true
		}
	}
	if !foundSpec {
		t.Errorf("contract must reference spec %s", wantSpec)
	}
}

// TestRegression_FreeipaDNSApplyPlaybookCoversContractTags locks that every
// tag the contract's traceability maps a row to actually exists somewhere in
// the apply playbook (docs/specs/freeipa-dns.md §14.2 "apply playbook tags
// covered"). This mirrors cmd/pilot/cmd/tag_coverage_test.go's own check —
// duplicated narrowly here so this package's regression suite stands alone.
func TestRegression_FreeipaDNSApplyPlaybookCoversContractTags(t *testing.T) {
	contractRaw, err := os.ReadFile("../../contracts/freeipa-dns.yaml")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var c freeipaDNSContract
	if err := yaml.Unmarshal(contractRaw, &c); err != nil {
		t.Fatalf("parse contract: %v", err)
	}

	const playbookPath = "../../playbooks/apply/freeipa-dns-apply.yml"
	playbookRaw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(playbookRaw, &doc); err != nil {
		t.Fatalf("parse %s: %v", playbookPath, err)
	}
	tags := map[string]bool{}
	collectFreeipaDNSPlaybookTags(&doc, tags)

	for ref, row := range c.Traceability.Rows {
		for _, tag := range row.Tags {
			if !tags[tag] {
				t.Errorf("traceability row %s references tag %q, but %s has no such tag", ref, tag, playbookPath)
			}
		}
	}
}

func collectFreeipaDNSPlaybookTags(n *yaml.Node, out map[string]bool) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind == yaml.ScalarNode && k.Value == "tags" {
				switch v.Kind {
				case yaml.ScalarNode:
					out[v.Value] = true
				case yaml.SequenceNode:
					for _, item := range v.Content {
						if item.Kind == yaml.ScalarNode {
							out[item.Value] = true
						}
					}
				}
			}
			collectFreeipaDNSPlaybookTags(v, out)
		}
		return
	}
	for _, c := range n.Content {
		collectFreeipaDNSPlaybookTags(c, out)
	}
}

// TestRegression_FreeipaDNSApplyPlaybookHasFullCRUDMutation locks
// docs/specs/freeipa-dns.md §15 Phase 1-3's complete mutation surface: the
// apply playbook must call every zone/record create, reconcile, and
// delete subcommand — no phase is silently missing its mutation half.
func TestRegression_FreeipaDNSApplyPlaybookHasFullCRUDMutation(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-dns-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)
	for _, required := range []string{
		"dnszone-add", "dnszone-del",
		"dnsrecord-add", "dnsrecord-mod", "dnsrecord-del",
	} {
		if !strings.Contains(playbook, required) {
			t.Errorf("playbook must call %q (docs/specs/freeipa-dns.md §15 Phase 1-3 mutation surface)", required)
		}
	}
}
