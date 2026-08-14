package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaCaTrustSpec locks the Phase 1 shape (spec.md §63) of
// docs/verification/freeipa-ca-trust.md: all six rows exist with a
// non-empty command/expected, and the spec lints clean.
func TestRegression_FreeipaCaTrustSpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-ca-trust.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6"}
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

// freeipaCaTrustContract is a minimal local decode of
// contracts/freeipa-ca-trust.yaml — just the fields this test locks — so
// this test doesn't need to import internal/contract (which itself
// imports internal/spec).
type freeipaCaTrustContract struct {
	ID              string                         `yaml:"id"`
	Role            string                         `yaml:"role"`
	HostCardinality string                         `yaml:"hostCardinality"`
	Dependencies    []freeipaCaTrustDependency     `yaml:"dependencies"`
	Traceability    freeipaCaTrustTraceability     `yaml:"traceability"`
	Site            freeipaCaTrustSite             `yaml:"site"`
	Playbooks       map[string]string              `yaml:"playbooks"`
	RegressionTests []string                       `yaml:"regressionTests"`
	Specs           []freeipaCaTrustContractedSpec `yaml:"specs"`
}

type freeipaCaTrustDependency struct {
	Component string `yaml:"component"`
	Required  bool   `yaml:"required"`
	Relation  string `yaml:"relation"`
	Reason    string `yaml:"reason"`
}

type freeipaCaTrustTraceability struct {
	Mode       string                             `yaml:"mode"`
	Tag        *freeipaCaTrustTagStrategy         `yaml:"tag"`
	Exemptions map[string]freeipaCaTrustExemption `yaml:"exemptions"`
}

type freeipaCaTrustTagStrategy struct {
	Kind   string `yaml:"kind"`
	Prefix string `yaml:"prefix"`
}

type freeipaCaTrustExemption struct {
	Kind   string   `yaml:"kind"`
	Tags   []string `yaml:"tags"`
	Reason string   `yaml:"reason"`
}

type freeipaCaTrustSite struct {
	Include bool `yaml:"include"`
	OptIn   bool `yaml:"optIn"`
}

type freeipaCaTrustContractedSpec struct {
	Path string `yaml:"path"`
}

// TestRegression_FreeipaCaTrustContract locks spec.md §43.1's contract-shape
// requirements: day-2 (site.include: false), a planOnly dependency on
// freeipa-server, and hostCardinality: one-or-more.
func TestRegression_FreeipaCaTrustContract(t *testing.T) {
	const contractPath = "../../contracts/freeipa-ca-trust.yaml"
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	var c freeipaCaTrustContract
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse %s: %v", contractPath, err)
	}

	if c.ID != "freeipa-ca-trust" {
		t.Errorf("id = %q, want freeipa-ca-trust", c.ID)
	}
	if c.HostCardinality != "one-or-more" {
		t.Errorf("hostCardinality = %q, want one-or-more (spec.md §5.2)", c.HostCardinality)
	}
	if c.Site.Include {
		t.Error("site.include must be false — freeipa-ca-trust is a day-2/opt-in component (spec.md §43.1)")
	}
	if !c.Site.OptIn {
		t.Error("site.optIn must be true")
	}

	foundDep := false
	for _, dep := range c.Dependencies {
		if dep.Component == "freeipa-server" {
			foundDep = true
			if dep.Relation != "planOnly" {
				t.Errorf("freeipa-server dependency relation = %q, want planOnly", dep.Relation)
			}
			if dep.Reason == "" {
				t.Error("planOnly dependency on freeipa-server must have a reason")
			}
		}
	}
	if !foundDep {
		t.Error("contract must declare a dependency on freeipa-server")
	}

	if c.Traceability.Mode != "rowTags" {
		t.Fatalf("traceability.mode = %q, want rowTags", c.Traceability.Mode)
	}
	if c.Traceability.Tag == nil || c.Traceability.Tag.Kind != "bare" {
		t.Fatal("traceability.tag.kind must be bare")
	}
	// C1, C3, C4, C5, and C6 observe effective state produced by the
	// single C2 mutation and are exempted (spec.md §45).
	exemptRows := map[string]bool{"C1": true, "C3": true, "C4": true, "C5": true, "C6": true}
	for _, id := range []string{"C1", "C2", "C3", "C4", "C5", "C6"} {
		ref := "docs/verification/freeipa-ca-trust.md#" + id
		if exemptRows[id] {
			exemption, ok := c.Traceability.Exemptions[ref]
			if !ok {
				t.Errorf("traceability.exemptions is missing %s", ref)
				continue
			}
			if exemption.Reason == "" {
				t.Errorf("exemption %s must have a reason", ref)
			}
			continue
		}
		if _, exempt := c.Traceability.Exemptions[ref]; exempt {
			t.Errorf("row %s must not be exempted — it should be tagged", ref)
		}
	}

	if c.Playbooks["apply"] != "playbooks/apply/freeipa-ca-trust-apply.yml" {
		t.Errorf("playbooks.apply = %q, want playbooks/apply/freeipa-ca-trust-apply.yml", c.Playbooks["apply"])
	}
	wantSpec := "docs/verification/freeipa-ca-trust.md"
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

// TestRegression_FreeipaCaTrustApplyPlaybookCoversContractTags locks that
// the bare row tag C2 (the only non-exempt row) actually exists in the
// apply playbook, and that no exempted row's bare tag leaked in (which
// would make the exemption stale).
func TestRegression_FreeipaCaTrustApplyPlaybookCoversContractTags(t *testing.T) {
	contractRaw, err := os.ReadFile("../../contracts/freeipa-ca-trust.yaml")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var c freeipaCaTrustContract
	if err := yaml.Unmarshal(contractRaw, &c); err != nil {
		t.Fatalf("parse contract: %v", err)
	}

	const playbookPath = "../../playbooks/apply/freeipa-ca-trust-apply.yml"
	playbookRaw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(playbookRaw, &doc); err != nil {
		t.Fatalf("parse %s: %v", playbookPath, err)
	}
	tags := map[string]bool{}
	collectFreeipaCaTrustPlaybookTags(&doc, tags)

	if !tags["C2"] {
		t.Errorf("%s has no tag %q required by traceability", playbookPath, "C2")
	}
	for id := range map[string]bool{"C1": true, "C3": true, "C4": true, "C5": true, "C6": true} {
		if tags[id] {
			t.Errorf("%s unexpectedly has tag %q — its exemption is now stale", playbookPath, id)
		}
	}
}

func collectFreeipaCaTrustPlaybookTags(n *yaml.Node, out map[string]bool) {
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
			collectFreeipaCaTrustPlaybookTags(v, out)
		}
		return
	}
	for _, c := range n.Content {
		collectFreeipaCaTrustPlaybookTags(c, out)
	}
}
