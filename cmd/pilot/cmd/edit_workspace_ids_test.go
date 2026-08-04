package cmd

import "testing"

func TestNewPlanID_UniqueAndNonEmpty(t *testing.T) {
	a, err := newID()
	if err != nil {
		t.Fatalf("newID() error = %v", err)
	}
	b, err := newID()
	if err != nil {
		t.Fatalf("newID() error = %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("expected non-empty plan IDs")
	}
	if a == b {
		t.Fatal("expected two calls to newID() to differ")
	}
}

func TestComputeScenarioHash_DeterministicAndSensitiveToContent(t *testing.T) {
	scenario := editScenario{Version: 1, Title: "t", Steps: []editAction{{Action: "create_host", Host: "web-1"}}}
	first, err := computeScenarioHash(scenario)
	if err != nil {
		t.Fatalf("computeScenarioHash() error = %v", err)
	}
	second, err := computeScenarioHash(scenario)
	if err != nil {
		t.Fatalf("computeScenarioHash() error = %v", err)
	}
	if first != second {
		t.Fatalf("hash not deterministic: %q != %q", first, second)
	}

	changed := scenario
	changed.Steps = []editAction{{Action: "create_host", Host: "web-2"}}
	third, err := computeScenarioHash(changed)
	if err != nil {
		t.Fatalf("computeScenarioHash() error = %v", err)
	}
	if first == third {
		t.Fatal("expected hash to change when scenario content changes")
	}
}
