package tools

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolveExpectedHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        expectedHostInput
		wantHosts    []string
		wantFindings []string
		wantErr      string
	}{
		{
			name:    "no targets or selector fails closed",
			input:   expectedHostInput{InventoryHosts: []string{"beta", "alpha", "alpha"}},
			wantErr: "spec has no declared targets; provide an explicit --host/--limit selector",
		},
		{
			name: "host pattern narrows inventory",
			input: expectedHostInput{
				InventoryHosts: []string{"a", "b", "c"},
				ExecutionSelections: []hostSelection{
					{Name: "host pattern", Provided: true, Hosts: []string{"b", "a"}},
				},
			},
			wantHosts: []string{"a", "b"},
		},
		{
			name: "limit intersects host pattern",
			input: expectedHostInput{
				InventoryHosts: []string{"a", "b", "c"},
				ExecutionSelections: []hostSelection{
					{Name: "host pattern", Provided: true, Hosts: []string{"a", "b"}},
					{Name: "--limit", Provided: true, Hosts: []string{"b", "c"}},
				},
			},
			wantHosts: []string{"b"},
		},
		{
			name: "explicit selector matching zero hosts fails",
			input: expectedHostInput{
				InventoryHosts: []string{"a"},
				ExecutionSelections: []hostSelection{
					{Name: "--limit", Provided: true},
				},
			},
			wantErr: "--limit matched zero inventory hosts",
		},
		{
			name: "selectors with empty intersection fail",
			input: expectedHostInput{
				InventoryHosts: []string{"a", "b"},
				ExecutionSelections: []hostSelection{
					{Name: "host pattern", Provided: true, Hosts: []string{"a"}},
					{Name: "--limit", Provided: true, Hosts: []string{"b"}},
				},
			},
			wantErr: "empty intersection after --limit",
		},
		{
			name: "selector cannot invent inventory host",
			input: expectedHostInput{
				InventoryHosts: []string{"a"},
				ExecutionSelections: []hostSelection{
					{Name: "host pattern", Provided: true, Hosts: []string{"missing"}},
				},
			},
			wantErr: `host pattern contains host "missing" that is absent from inventory`,
		},
		{
			name: "spec targets constrain normal execution scope",
			input: expectedHostInput{
				InventoryHosts:      []string{"client", "server"},
				SpecTargetsDeclared: true,
				SpecTargetHosts:     []string{"server"},
				ExecutionSelections: []hostSelection{
					{Name: "--limit", Provided: true, Hosts: []string{"server"}},
				},
			},
			wantHosts: []string{"server"},
		},
		{
			name: "spec targets become default scope without explicit selector",
			input: expectedHostInput{
				InventoryHosts:      []string{"client", "server"},
				SpecTargetsDeclared: true,
				SpecTargetHosts:     []string{"server"},
			},
			wantHosts: []string{"server"},
		},
		{
			name: "execution outside spec targets fails without override",
			input: expectedHostInput{
				InventoryHosts:      []string{"client", "server"},
				SpecTargetsDeclared: true,
				SpecTargetHosts:     []string{"server"},
				ExecutionSelections: []hostSelection{
					{Name: "--limit", Provided: true, Hosts: []string{"client"}},
				},
			},
			wantErr: "execution scope contains hosts outside spec targets: client",
		},
		{
			name: "unresolved spec targets fail without override",
			input: expectedHostInput{
				InventoryHosts:      []string{"vm"},
				SpecTargetsDeclared: true,
			},
			wantErr: "spec targets matched zero inventory hosts and no target_group override was provided",
		},
		{
			name: "target group override permits deliberate group mismatch",
			input: expectedHostInput{
				InventoryHosts:      []string{"vm"},
				SpecTargetsDeclared: true,
				TargetGroupOverride: true,
				ExecutionSelections: []hostSelection{
					{Name: "target_group override", Provided: true, Hosts: []string{"vm"}},
				},
			},
			wantHosts:    []string{"vm"},
			wantFindings: []string{"target_group override replaced spec targets that matched no inventory hosts"},
		},
		{
			name: "target group override records changed scope",
			input: expectedHostInput{
				InventoryHosts:      []string{"client", "server"},
				SpecTargetsDeclared: true,
				SpecTargetHosts:     []string{"server"},
				TargetGroupOverride: true,
				ExecutionSelections: []hostSelection{
					{Name: "target_group override", Provided: true, Hosts: []string{"client"}},
				},
			},
			wantHosts:    []string{"client"},
			wantFindings: []string{"target_group override replaced the spec target scope"},
		},
		{
			name: "target group override still cannot select zero hosts",
			input: expectedHostInput{
				InventoryHosts:      []string{"vm"},
				SpecTargetsDeclared: true,
				TargetGroupOverride: true,
				ExecutionSelections: []hostSelection{
					{Name: "target_group override", Provided: true},
				},
			},
			wantErr: "target_group override matched zero inventory hosts",
		},
		{
			name:    "empty inventory fails closed",
			input:   expectedHostInput{},
			wantErr: "inventory host set is empty",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveExpectedHosts(tt.input)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveExpectedHosts() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveExpectedHosts() error = %v", err)
			}
			if !reflect.DeepEqual(got.Hosts, tt.wantHosts) {
				t.Errorf("hosts = %v, want %v", got.Hosts, tt.wantHosts)
			}
			if !reflect.DeepEqual(got.Findings, tt.wantFindings) {
				t.Errorf("findings = %v, want %v", got.Findings, tt.wantFindings)
			}
		})
	}
}
