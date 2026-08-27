package cmd

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestInspectHandler_IdentityHardeningIncludedWithRosterAndOmittedOtherwise(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "alice"},
		{Action: "create_group", Name: "role-privileged", Category: "role"},
		{Action: "create_password_policy", Name: "privileged-users", Group: "role-privileged", Priority: "10"},
		{Action: "set_password_policy_field", Name: "privileged-users", Field: "min_length", Value: "16"},
		{Action: "create_credential_policy", Name: "privileged-ssh"},
		{Action: "set_credential_policy_field", Name: "privileged-ssh", Field: "match.groups", Groups: []string{"role-privileged"}},
		{Action: "set_credential_policy_field", Name: "privileged-ssh", Field: "ssh.require_comment", Value: "true"},
		{Action: "set_user_authentication_types", User: "alice", Users: []string{"otp"}},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeRoster: true})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}

	if len(out.PasswordPolicies) != 1 {
		t.Fatalf("PasswordPolicies = %+v, want exactly one entry", out.PasswordPolicies)
	}
	pp := out.PasswordPolicies[0]
	if pp.Name != "privileged-users" || pp.Group != "role-privileged" || pp.State != "present" {
		t.Fatalf("pp = %+v", pp)
	}
	if pp.Priority == nil || *pp.Priority != 10 {
		t.Fatalf("pp.Priority = %v, want 10", pp.Priority)
	}
	if pp.MinLength == nil || *pp.MinLength != 16 {
		t.Fatalf("pp.MinLength = %v, want 16", pp.MinLength)
	}

	if len(out.CredentialPolicies) != 1 {
		t.Fatalf("CredentialPolicies = %+v, want exactly one entry", out.CredentialPolicies)
	}
	cp := out.CredentialPolicies[0]
	if cp.Name != "privileged-ssh" || len(cp.MatchGroups) != 1 || cp.MatchGroups[0] != "role-privileged" {
		t.Fatalf("cp = %+v", cp)
	}
	if !cp.SSHRequireComment {
		t.Fatal("cp.SSHRequireComment = false, want true")
	}

	found := false
	for _, u := range out.RosterUsers {
		if u.Name == "alice" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected alice to appear in RosterUsers")
	}

	_, out2, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeRoster: false})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out2.PasswordPolicies != nil || out2.CredentialPolicies != nil || out2.PrivilegedIdentity != nil {
		t.Fatalf("expected nil identity-hardening fields when include_roster is false, got PasswordPolicies=%+v CredentialPolicies=%+v PrivilegedIdentity=%+v",
			out2.PasswordPolicies, out2.CredentialPolicies, out2.PrivilegedIdentity)
	}
}

func TestCapabilitiesHandler_ListsIdentityHardeningActions(t *testing.T) {
	handler := capabilitiesHandler(editMCPToolsOptions{Dir: "/workspace"})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, capabilitiesInput{})
	if err != nil {
		t.Fatalf("capabilitiesHandler() error = %v", err)
	}
	seen := map[string]bool{}
	for _, a := range out.Actions {
		seen[a.Name] = true
	}
	for _, name := range []string{
		"create_password_policy", "set_password_policy_field", "delete_password_policy",
		"set_user_authentication_types",
		"create_credential_policy", "set_credential_policy_field", "delete_credential_policy",
	} {
		if !seen[name] {
			t.Fatalf("expected capabilities to list %q — registering an action in editActionRegistry() should be enough for it to reach MCP automatically", name)
		}
	}
}

// TestPlanHandler_PasswordPolicyScenarioRoundTrip confirms §19's write
// side needs zero identity-hardening-specific plan/apply code — same as
// TestPlanAndApplyHandler_RosterScenarioRoundTrip's own point for roster
// user actions: planEditScenario is already generic over editScenario.
func TestPlanHandler_PasswordPolicyScenarioRoundTrip(t *testing.T) {
	dir := t.TempDir()
	auditDir := t.TempDir()
	writeMinimalRosterFixture(t, dir)
	rev, err := computeWorkspaceRevision(dir)
	if err != nil {
		t.Fatalf("computeWorkspaceRevision() error = %v", err)
	}

	scenario := editScenario{Version: 1, Title: "password policy plan", Steps: []editAction{
		{Action: "create_group", Name: "role-privileged", Category: "role"},
		{Action: "create_password_policy", Name: "privileged-users", Group: "role-privileged", Priority: "10"},
	}}

	planH := planHandler(editMCPToolsOptions{Dir: dir, AuditDir: auditDir})
	planResult, _, err := planH(context.Background(), &mcp.CallToolRequest{}, planInput{BaseRevision: rev, Scenario: scenario})
	if err != nil {
		t.Fatalf("planHandler() error = %v", err)
	}
	if planResult != nil {
		t.Fatalf("expected a successful plan, got error result: %+v", planResult.Content)
	}
}

func TestInspectHandler_PrivilegedIdentityNilWhenNotDeclared(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "alice"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeRoster: true})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out.PrivilegedIdentity != nil {
		t.Fatalf("PrivilegedIdentity = %+v, want nil (no privileged_identity block declared)", out.PrivilegedIdentity)
	}
}
