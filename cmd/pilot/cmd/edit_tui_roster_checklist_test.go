package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/inventory"
)

func writeChecklistRoster(t *testing.T) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "roster.yaml")
	fixture := `schema_version: 1
freeipa: {domain: ipa.pilot.internal}
groups:
  - {name: access-infra, state: present, category: access}
  - {name: role-ops, state: present, category: role}
hostgroups:
  - {name: infra-hosts, state: present, membership: {hosts: [infra-1.ipa.pilot.internal]}}
hbac:
  disable_allow_all: false
  rules:
    - name: infra-ssh
      state: present
      enabled: true
      subjects: {users: [], groups: [access-infra]}
      targets: {hosts: [], hostgroups: [infra-hosts]}
      services: [sshd]
sudo:
  command_groups:
    - {name: ops-read, state: present, commands: [/usr/bin/id]}
  rules:
    - name: ops-read-sudo
      state: present
      enabled: true
      subjects: {users: [], groups: [role-ops]}
      targets: {hostcat: all, hosts: [], hostgroups: []}
      allow: {command_groups: [ops-read], commands: []}
      deny: {command_groups: [], commands: []}
      run_as: {users: [root], groups: []}
      options: ['!authenticate']
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

// TestRosterChecklistEscapeRoutesEveryChecklist verifies every current
// checklist call-site returns to its own parent screen. This is intentionally
// a table rather than a single services regression: access and sudo pages use
// different callbacks, and evaluating one of them too early leaves a finished
// checklist on screen that ignores subsequent keyboard input.
func TestRosterChecklistEscapeRoutesEveryChecklist(t *testing.T) {
	dir, path := writeChecklistRoster(t)
	tests := []struct {
		name      string
		open      func(*editRouterModel)
		wantTitle string
	}{
		{"add HBAC access groups", func(r *editRouterModel) { pushRosterAddHBACGroups(r, dir, path, "new-rule") }, "HBAC rules"},
		{"add HBAC hostgroups", func(r *editRouterModel) {
			pushRosterAddHBACHostgroups(r, dir, path, "new-rule", []string{"access-infra"})
		}, "HBAC rules"},
		{"add HBAC services", func(r *editRouterModel) {
			pushRosterAddHBACServices(r, dir, path, "new-rule", []string{"access-infra"}, []string{"infra-hosts"})
		}, "HBAC rules"},
		{"edit HBAC access groups", func(r *editRouterModel) { pushRosterHBACGroups(r, dir, path, "infra-ssh") }, "HBAC rule infra-ssh"},
		{"edit HBAC hostgroups", func(r *editRouterModel) { pushRosterHBACTargets(r, dir, path, "infra-ssh") }, "HBAC rule infra-ssh"},
		{"edit HBAC services", func(r *editRouterModel) { pushRosterHBACServices(r, dir, path, "infra-ssh") }, "HBAC rule infra-ssh"},
		{"add sudo role groups", func(r *editRouterModel) { pushRosterAddSudoRuleGroups(r, dir, path, "new-sudo") }, "Sudo rules"},
		{"add sudo command groups", func(r *editRouterModel) {
			pushRosterAddSudoRuleCommandGroups(r, dir, path, "new-sudo", []string{"role-ops"})
		}, "Sudo rules"},
		{"edit sudo role groups", func(r *editRouterModel) { pushRosterSudoRuleGroups(r, dir, path, "ops-read-sudo") }, "Sudo rule ops-read-sudo"},
		{"edit sudo command groups", func(r *editRouterModel) { pushRosterSudoRuleCommandGroups(r, dir, path, "ops-read-sudo") }, "Sudo rule ops-read-sudo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var router editRouterModel
			tt.open(&router)
			if _, ok := router.current.(multiSelectModel); !ok {
				t.Fatalf("initial screen = %T, want multiSelectModel", router.current)
			}
			next, _ := router.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{27}})
			router = next.(editRouterModel)
			if _, stuck := router.current.(multiSelectModel); stuck {
				t.Fatalf("raw Escape left the finished checklist on screen:\n%s", router.View())
			}
			if !strings.Contains(router.View(), tt.wantTitle) {
				t.Fatalf("cancel destination missing %q:\n%s", tt.wantTitle, router.View())
			}
		})
	}
}

func TestRosterServicesChecklistRawLFCompletesAndPersists(t *testing.T) {
	dir, path := writeChecklistRoster(t)
	var router editRouterModel
	pushRosterHBACServices(&router, dir, path, "infra-ssh")

	next, _ := router.Update(tea.KeyMsg{Type: tea.KeyDown})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyMsg{Type: tea.KeySpace})
	router = next.(editRouterModel)
	next, _ = router.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'\n'}})
	router = next.(editRouterModel)
	if !strings.Contains(router.View(), "✅ 已更新") {
		t.Fatalf("raw LF did not return to the updated detail screen:\n%s", router.View())
	}

	rule, found, err := inventory.RosterHBACRule(path, "infra-ssh")
	if err != nil || !found {
		t.Fatalf("read updated HBAC rule: found=%t err=%v", found, err)
	}
	if got := rosterStringSlice(rule, "services"); strings.Join(got, ",") != "sshd,sudo" {
		t.Fatalf("services = %v, want [sshd sudo]", got)
	}
}
