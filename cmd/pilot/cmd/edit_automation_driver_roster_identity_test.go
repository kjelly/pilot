package cmd

import (
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestEditAutomationDriverRosterIdentityFlow_PasswordPolicyCreateAndSetFields(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_group", Name: "role-privileged", Category: "role"},
			{Action: "create_password_policy", Name: "privileged-users", Group: "role-privileged", Priority: "10"},
			{Action: "set_password_policy_field", Name: "privileged-users", Field: "min_length", Value: "16"},
			{Action: "set_password_policy_field", Name: "privileged-users", Field: "max_life", Value: "90d"},
			{Action: "set_password_policy_field", Name: "privileged-users", Field: "min_life", Value: "1h"},
			{Action: "set_password_policy_field", Name: "privileged-users", Field: "lockout.max_failures", Value: "5"},
			{Action: "set_password_policy_field", Name: "privileged-users", Field: "lockout.failure_reset_interval", Value: "15m"},
			{Action: "set_password_policy_field", Name: "privileged-users", Field: "lockout.lockout_duration", Value: "15m"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	f, found, err := inventory.RosterPasswordPolicy(path, "privileged-users")
	if err != nil {
		t.Fatalf("RosterPasswordPolicy() error = %v", err)
	}
	if !found {
		t.Fatal("expected password_policy privileged-users to exist")
	}
	if f["group"] != "role-privileged" {
		t.Fatalf("group = %v, want role-privileged", f["group"])
	}
	if n, ok := f["priority"].(int); !ok || n != 10 {
		t.Fatalf("priority = %v (%T), want int 10", f["priority"], f["priority"])
	}
	if f["max_life"] != "90d" {
		t.Fatalf("max_life = %v, want 90d", f["max_life"])
	}
	lockout, _ := f["lockout"].(map[string]any)
	if lockout == nil {
		t.Fatal("expected lockout block to exist")
	}
	if n, ok := lockout["max_failures"].(int); !ok || n != 5 {
		t.Fatalf("lockout.max_failures = %v (%T), want int 5", lockout["max_failures"], lockout["max_failures"])
	}

	if v, err := inventory.ValidateRosterFile(path); err != nil || len(v) != 0 {
		t.Fatalf("expected the roster to validate clean, got: %v, err=%v", v, err)
	}
}

func TestEditAutomationDriverRosterIdentityFlow_PasswordPolicyDelete(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_group", Name: "role-privileged", Category: "role"},
			{Action: "create_password_policy", Name: "privileged-users", Group: "role-privileged", Priority: "10"},
			{Action: "delete_password_policy", Name: "privileged-users"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	f, found, err := inventory.RosterPasswordPolicy(path, "privileged-users")
	if err != nil || !found {
		t.Fatalf("RosterPasswordPolicy() found=%v err=%v", found, err)
	}
	if f["state"] != "absent" {
		t.Fatalf("state = %v, want absent", f["state"])
	}
}

func TestEditAutomationDriverRosterIdentityFlow_CredentialPolicyCreateAndSetFields(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
			{Action: "create_group", Name: "role-privileged", Category: "role"},
			{Action: "create_credential_policy", Name: "privileged-ssh"},
			{Action: "set_credential_policy_field", Name: "privileged-ssh", Field: "match.groups", Groups: []string{"role-privileged"}},
			{Action: "set_credential_policy_field", Name: "privileged-ssh", Field: "match.users", Users: []string{"alice"}},
			{Action: "set_credential_policy_field", Name: "privileged-ssh", Field: "ssh.allowed_algorithms", Value: "ssh-ed25519, ecdsa-sha2-nistp256"},
			{Action: "set_credential_policy_field", Name: "privileged-ssh", Field: "ssh.require_comment", Value: "true"},
			{Action: "set_credential_policy_field", Name: "privileged-ssh", Field: "ssh.max_age", Value: "365d"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	f, found, err := inventory.RosterCredentialPolicy(path, "privileged-ssh")
	if err != nil {
		t.Fatalf("RosterCredentialPolicy() error = %v", err)
	}
	if !found {
		t.Fatal("expected credential_policy privileged-ssh to exist")
	}
	match, _ := f["match"].(map[string]any)
	if match == nil {
		t.Fatal("expected match block to exist")
	}
	groups, _ := match["groups"].([]any)
	if len(groups) != 1 || groups[0] != "role-privileged" {
		t.Fatalf("match.groups = %v, want [role-privileged]", groups)
	}
	users, _ := match["users"].([]any)
	if len(users) != 1 || users[0] != "alice" {
		t.Fatalf("match.users = %v, want [alice]", users)
	}
	ssh, _ := f["ssh"].(map[string]any)
	if ssh == nil {
		t.Fatal("expected ssh block to exist")
	}
	algs, _ := ssh["allowed_algorithms"].([]any)
	if len(algs) != 2 {
		t.Fatalf("ssh.allowed_algorithms = %v, want 2 entries", algs)
	}
	if ssh["require_comment"] != true {
		t.Fatalf("ssh.require_comment = %v, want true", ssh["require_comment"])
	}
	if ssh["max_age"] != "365d" {
		t.Fatalf("ssh.max_age = %v, want 365d", ssh["max_age"])
	}

	if v, err := inventory.ValidateRosterFile(path); err != nil || len(v) != 0 {
		t.Fatalf("expected the roster to validate clean, got: %v, err=%v", v, err)
	}
}

func TestEditAutomationDriverRosterIdentityFlow_CredentialPolicyDelete(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_group", Name: "role-privileged", Category: "role"},
			{Action: "create_credential_policy", Name: "privileged-ssh"},
			{Action: "set_credential_policy_field", Name: "privileged-ssh", Field: "match.groups", Groups: []string{"role-privileged"}},
			{Action: "delete_credential_policy", Name: "privileged-ssh"},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	f, found, err := inventory.RosterCredentialPolicy(path, "privileged-ssh")
	if err != nil || !found {
		t.Fatalf("RosterCredentialPolicy() found=%v err=%v", found, err)
	}
	if f["state"] != "absent" {
		t.Fatalf("state = %v, want absent", f["state"])
	}
}

func TestEditAutomationDriverRosterIdentityFlow_SetUserAuthenticationTypes(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
			{Action: "set_user_authentication_types", User: "alice", Users: []string{"otp", "pkinit"}},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	f, found, err := inventory.RosterUser(path, "alice")
	if err != nil || !found {
		t.Fatalf("RosterUser() found=%v err=%v", found, err)
	}
	auth, _ := f["authentication"].(map[string]any)
	if auth == nil {
		t.Fatal("expected authentication block to exist")
	}
	allowed, _ := auth["allowed"].([]any)
	if len(allowed) != 2 {
		t.Fatalf("authentication.allowed = %v, want 2 entries", allowed)
	}

	if v, err := inventory.ValidateRosterFile(path); err != nil || len(v) != 0 {
		t.Fatalf("expected the roster to validate clean, got: %v, err=%v", v, err)
	}
}

func TestEditAutomationDriverRosterIdentityFlow_SetUserAuthenticationTypesClearsOnEmpty(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalRosterFixture(t, dir)

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_user", User: "alice"},
			{Action: "set_user_authentication_types", User: "alice", Users: []string{"otp"}},
			{Action: "set_user_authentication_types", User: "alice", Users: nil},
		},
	}

	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	f, found, err := inventory.RosterUser(path, "alice")
	if err != nil || !found {
		t.Fatalf("RosterUser() found=%v err=%v", found, err)
	}
	if _, has := f["authentication"]; has {
		t.Fatalf("expected authentication block to be cleared entirely, got: %v", f["authentication"])
	}
}
