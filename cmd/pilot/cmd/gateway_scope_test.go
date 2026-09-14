package cmd

import (
	"strings"
	"testing"
)

func TestBuildGatewayScopeArgsPlan(t *testing.T) {
	args, err := buildGatewayScopeArgs("gpu", []string{"gpu-a.example.com", "gpu-b.example.com"}, "inv.yml", "all", "/vault/main.yaml", true)
	if err != nil {
		t.Fatalf("buildGatewayScopeArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		gatewayScopeApplyPlaybook,
		"-i inv.yml",
		"-e target_group=all",
		"-e gateway_scope=gpu",
		`-e {"gateway_scope_hosts":["gpu-a.example.com","gpu-b.example.com"]}`,
		"-e @/vault/main.yaml",
		"-e gateway_scope_plan_only=true",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %v missing %q", args, want)
		}
	}
}

func TestBuildGatewayScopeArgsReconcileOmitsPlanOnly(t *testing.T) {
	args, err := buildGatewayScopeArgs("gpu", []string{"gpu-a.example.com"}, "inv.yml", "all", "/vault/main.yaml", false)
	if err != nil {
		t.Fatalf("buildGatewayScopeArgs: %v", err)
	}
	if strings.Contains(strings.Join(args, " "), "gateway_scope_plan_only") {
		t.Fatalf("reconcile (planOnly=false) must not set gateway_scope_plan_only: %v", args)
	}
}

func TestBuildGatewayScopeArgsRequiresScopeAndHosts(t *testing.T) {
	if _, err := buildGatewayScopeArgs("", []string{"h"}, "inv.yml", "all", "v.yml", false); err == nil {
		t.Fatalf("expected an error for empty scope")
	}
	if _, err := buildGatewayScopeArgs("gpu", nil, "inv.yml", "all", "v.yml", false); err == nil {
		t.Fatalf("expected an error for empty hosts")
	}
}
