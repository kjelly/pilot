package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_ReverseProxySpec locks the Phase 1 shape (spec.md §63) of
// docs/verification/reverse-proxy.md: all six rows exist with a non-empty
// command/expected, and the spec lints clean.
func TestRegression_ReverseProxySpec(t *testing.T) {
	const specPath = "../../docs/verification/reverse-proxy.md"
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

// reverseProxyContract is a minimal local decode of
// contracts/reverse-proxy.yaml — just the fields this test locks — so this
// test doesn't need to import internal/contract (which itself imports
// internal/spec).
type reverseProxyContract struct {
	ID              string                       `yaml:"id"`
	Role            string                       `yaml:"role"`
	HostCardinality string                       `yaml:"hostCardinality"`
	Dependencies    []reverseProxyDependency     `yaml:"dependencies"`
	Traceability    reverseProxyTraceability     `yaml:"traceability"`
	Site            reverseProxySite             `yaml:"site"`
	Playbooks       map[string]string            `yaml:"playbooks"`
	RegressionTests []string                     `yaml:"regressionTests"`
	Specs           []reverseProxyContractedSpec `yaml:"specs"`
}

type reverseProxyDependency struct {
	Component string `yaml:"component"`
	Required  bool   `yaml:"required"`
	Relation  string `yaml:"relation"`
	Reason    string `yaml:"reason"`
}

type reverseProxyTraceability struct {
	Mode       string                           `yaml:"mode"`
	Tag        *reverseProxyTagStrategy         `yaml:"tag"`
	Exemptions map[string]reverseProxyExemption `yaml:"exemptions"`
}

type reverseProxyTagStrategy struct {
	Kind   string `yaml:"kind"`
	Prefix string `yaml:"prefix"`
}

type reverseProxyExemption struct {
	Kind   string   `yaml:"kind"`
	Tags   []string `yaml:"tags"`
	Reason string   `yaml:"reason"`
}

type reverseProxySite struct {
	Include bool     `yaml:"include"`
	Order   int      `yaml:"order"`
	Tags    []string `yaml:"tags"`
	OptIn   bool     `yaml:"optIn"`
}

type reverseProxyContractedSpec struct {
	Path string `yaml:"path"`
}

// TestRegression_ReverseProxyContract locks spec.md §43.2's contract-shape
// requirements: site.include: true (base runtime, unlike the day-2
// components in this feature) with a positive order, and
// hostCardinality: one-or-more.
func TestRegression_ReverseProxyContract(t *testing.T) {
	const contractPath = "../../contracts/reverse-proxy.yaml"
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	var c reverseProxyContract
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse %s: %v", contractPath, err)
	}

	if c.ID != "reverse-proxy" {
		t.Errorf("id = %q, want reverse-proxy", c.ID)
	}
	if c.HostCardinality != "one-or-more" {
		t.Errorf("hostCardinality = %q, want one-or-more", c.HostCardinality)
	}
	if !c.Site.Include {
		t.Error("site.include must be true — reverse-proxy is a base runtime component (spec.md §43.2)")
	}
	if c.Site.Order <= 0 {
		t.Error("site.order must be positive when site.include is true")
	}
	if c.Site.OptIn {
		t.Error("site.optIn must be false for reverse-proxy (spec.md §43.2)")
	}

	if c.Traceability.Mode != "rowTags" {
		t.Fatalf("traceability.mode = %q, want rowTags", c.Traceability.Mode)
	}
	if c.Traceability.Tag == nil || c.Traceability.Tag.Kind != "bare" {
		t.Fatal("traceability.tag.kind must be bare")
	}
	// C3 and C6 are verify-only effective-behavior rows (spec.md §46).
	exemptRows := map[string]bool{"C3": true, "C6": true}
	for _, id := range []string{"C1", "C2", "C3", "C4", "C5", "C6"} {
		ref := "docs/verification/reverse-proxy.md#" + id
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

	if c.Playbooks["apply"] != "playbooks/apply/reverse-proxy-apply.yml" {
		t.Errorf("playbooks.apply = %q, want playbooks/apply/reverse-proxy-apply.yml", c.Playbooks["apply"])
	}
	wantSpec := "docs/verification/reverse-proxy.md"
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

// TestRegression_ReverseProxyApplyPlaybookCoversContractTags locks that
// every non-exempt row's bare tag exists in the apply playbook, and that
// no exempted row's bare tag leaked in (which would make the exemption
// stale).
func TestRegression_ReverseProxyApplyPlaybookCoversContractTags(t *testing.T) {
	contractRaw, err := os.ReadFile("../../contracts/reverse-proxy.yaml")
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var c reverseProxyContract
	if err := yaml.Unmarshal(contractRaw, &c); err != nil {
		t.Fatalf("parse contract: %v", err)
	}

	const playbookPath = "../../playbooks/apply/reverse-proxy-apply.yml"
	playbookRaw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(playbookRaw, &doc); err != nil {
		t.Fatalf("parse %s: %v", playbookPath, err)
	}
	tags := map[string]bool{}
	collectReverseProxyPlaybookTags(&doc, tags)

	for _, id := range []string{"C1", "C2", "C4", "C5"} {
		if !tags[id] {
			t.Errorf("%s has no tag %q required by traceability", playbookPath, id)
		}
	}
	for _, id := range []string{"C3", "C6"} {
		if tags[id] {
			t.Errorf("%s unexpectedly has tag %q — its exemption is now stale", playbookPath, id)
		}
	}
}

func collectReverseProxyPlaybookTags(n *yaml.Node, out map[string]bool) {
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
			collectReverseProxyPlaybookTags(v, out)
		}
		return
	}
	for _, c := range n.Content {
		collectReverseProxyPlaybookTags(c, out)
	}
}
