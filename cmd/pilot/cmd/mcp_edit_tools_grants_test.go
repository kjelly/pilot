package cmd

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestInspectHandler_GrantsIncludedWithRosterAndOmittedOtherwise(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "vendor01"},
		{Action: "create_hostgroup", Name: "webhosts"},
		{
			Action: "create_grant", Name: "vendor-project-x", Kind: "temporary_grant",
			Users: []string{"vendor01"}, Hostgroups: []string{"webhosts"}, Services: []string{"sshd"},
			NotAfter: "2099-12-31T23:59:59Z", Reason: "vendor access",
		},
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
	if len(out.Grants) != 1 {
		t.Fatalf("Grants = %+v, want exactly one entry", out.Grants)
	}
	g := out.Grants[0]
	if g.Name != "vendor-project-x" || g.Kind != "temporary_grant" || g.State != "present" {
		t.Fatalf("g = %+v", g)
	}
	if len(g.SubjectUsers) != 1 || g.SubjectUsers[0] != "vendor01" {
		t.Fatalf("g.SubjectUsers = %v, want [vendor01]", g.SubjectUsers)
	}
	if len(g.TargetHostgroups) != 1 || g.TargetHostgroups[0] != "webhosts" {
		t.Fatalf("g.TargetHostgroups = %v, want [webhosts]", g.TargetHostgroups)
	}
	if g.ValidityNotAfter != "2099-12-31T23:59:59Z" {
		t.Fatalf("g.ValidityNotAfter = %q", g.ValidityNotAfter)
	}
	if g.Lifecycle != "active" {
		t.Fatalf("g.Lifecycle = %q, want active (validity window covers now, no not_before)", g.Lifecycle)
	}

	_, out2, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeRoster: false})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out2.Grants != nil {
		t.Fatalf("Grants = %+v, want nil when include_roster is false", out2.Grants)
	}
}

func TestInspectHandler_BreakglassStatusOnlyWhenRequested(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = "" })

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "emergency-admin"},
		{Action: "create_hostgroup", Name: "prodweb"},
		{
			Action: "create_grant", Name: "infra-emergency", Kind: "breakglass",
			Users: []string{"emergency-admin"}, Hostgroups: []string{"prodweb"},
			Services: []string{"sshd"}, MaxDuration: "1h",
		},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeBreakglass: true})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if len(out.BreakglassStatus) != 1 || out.BreakglassStatus[0].Name != "infra-emergency" {
		t.Fatalf("BreakglassStatus = %+v, want exactly one entry named infra-emergency", out.BreakglassStatus)
	}
	if len(out.BreakglassStatus[0].Activations) != 0 {
		t.Fatalf("Activations = %+v, want none — this grant was never activated", out.BreakglassStatus[0].Activations)
	}

	_, out2, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeBreakglass: false})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out2.BreakglassStatus != nil {
		t.Fatalf("BreakglassStatus = %+v, want nil when include_breakglass is false", out2.BreakglassStatus)
	}
}

// TestInspectHandler_ExplainAccessRequiresAllThreeQueryFields exercises
// spec.md §16's explain surface via inspect: a static_hbac rule granting
// alice ssh to web1.ipa.pilot.internal must appear in explain_access when
// all three explain_user/explain_host/explain_service are set, and must
// stay nil (no error) when any one of the three is missing — the same
// lenient "empty rather than error" posture every other inspect flag uses.
func TestInspectHandler_ExplainAccessRequiresAllThreeQueryFields(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRosterFixture(t, dir)
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = "" })

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "create_user", User: "alice"},
		{Action: "create_hostgroup", Name: "webhosts"},
		{Action: "set_hostgroup_field", Name: "webhosts", Field: "membership.hosts", Value: "web1.ipa.pilot.internal"},
		{Action: "create_hbac_rule", Name: "web-login", Users: []string{"alice"}, Hostgroups: []string{"webhosts"}, Services: []string{"sshd"}},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})
	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{
		ExplainUser: "alice", ExplainHost: "web1.ipa.pilot.internal", ExplainService: "sshd",
	})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if len(out.ExplainAccess) != 1 {
		t.Fatalf("ExplainAccess = %+v, want exactly one source", out.ExplainAccess)
	}
	src := out.ExplainAccess[0]
	if src.Kind != "static_hbac" || src.Rule != "web-login" || !src.DirectUserHit ||
		len(src.HostgroupPath) != 1 || src.HostgroupPath[0] != "webhosts" {
		t.Fatalf("ExplainAccess[0] = %+v, want a direct-user/hostgroup-path static_hbac hit on web-login via webhosts", src)
	}

	_, out2, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{ExplainUser: "alice", ExplainHost: "web1.ipa.pilot.internal"})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if out2.ExplainAccess != nil {
		t.Fatalf("ExplainAccess = %+v, want nil when explain_service is missing", out2.ExplainAccess)
	}
}
