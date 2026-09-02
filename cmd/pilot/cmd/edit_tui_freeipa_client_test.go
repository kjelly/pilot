// edit_tui_freeipa_client_test.go covers spec.md §18.3's `pilot edit`
// requirements for the freeipa-client Day-2 IP replacement
// acknowledgement: the trigger condition (edit_tui_freeipa_client.go's
// pushAnsibleHostFieldEdit/pushFreeipaClientDNSReplaceConfirm) and its
// automation-driver parity (edit_automation_driver.go's setHostField).
package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestFreeipaClientDNSReplaceCandidate(t *testing.T) {
	freeipaClient := &inventory.Host{Roles: []string{"freeipa-client"}}
	other := &inventory.Host{Roles: []string{"docker"}}

	cases := []struct {
		name      string
		h         *inventory.Host
		old, new_ string
		want      bool
	}{
		{"ip to ip on freeipa-client", freeipaClient, "10.20.30.41", "10.20.30.61", true},
		{"ipv6 to ipv6 on freeipa-client", freeipaClient, "2001:db8::41", "2001:db8::61", true},
		{"same address", freeipaClient, "10.20.30.41", "10.20.30.41", false},
		{"non-freeipa-client role", other, "10.20.30.41", "10.20.30.61", false},
		{"old is a hostname", freeipaClient, "host1.example", "10.20.30.61", false},
		{"new is a hostname", freeipaClient, "10.20.30.41", "host1.example", false},
		{"old value did not exist yet", freeipaClient, "", "10.20.30.61", false},
		{"malformed old literal", freeipaClient, "10.20.30.999", "10.20.30.61", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := freeipaClientDNSReplaceCandidate(tc.h, tc.old, tc.new_); got != tc.want {
				t.Errorf("freeipaClientDNSReplaceCandidate(%v, %q, %q) = %v, want %v", tc.h.Roles, tc.old, tc.new_, got, tc.want)
			}
		})
	}
}

// runAnsibleHostEdit drives pushAnsibleHostFieldEdit directly (bypassing
// the top-menu/host-list navigation, matching
// TestEditRouter_Teatest_RoleChecklistFlow_AddingFreeIPANFSServerAutofixesRoster's
// pattern) for one host already present in hf: clear the input's
// default, type newValue, submit, then optionally answer a confirm
// screen with confirmKey ('y'/'n'/0 for "don't send one").
func runAnsibleHostEdit(t *testing.T, hf *inventory.HostsFile, name, newValue string, confirmKey rune) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	var router editRouterModel
	pushAnsibleHostFieldEdit(&router, dir, path, hf, name)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	tm.Send(keyCtrlU())
	tm.Type(newValue)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	if confirmKey != 0 {
		tm.Send(keyRuneMsg(confirmKey))
	}
	if err := tm.Quit(); err != nil {
		t.Fatalf("quit test model: %v", err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestEditRouter_AnsibleHostFreeipaClientReplace_ConfirmYesWritesBothFields(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{
		Name: "host1", Roles: []string{"freeipa-client"}, AnsibleHost: "10.20.30.41",
	}}}
	runAnsibleHostEdit(t, hf, "host1", "10.20.30.61", 'y')

	h := hf.Hosts[0]
	if h.AnsibleHost != "10.20.30.61" {
		t.Errorf("ansible_host = %q, want 10.20.30.61", h.AnsibleHost)
	}
	if got := h.Extra[freeipaClientDNSReplaceFromKey]; got != "10.20.30.41" {
		t.Errorf("%s = %q, want 10.20.30.41", freeipaClientDNSReplaceFromKey, got)
	}
}

func TestEditRouter_AnsibleHostFreeipaClientReplace_ConfirmNoWritesOnlyAnsibleHost(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{
		Name: "host1", Roles: []string{"freeipa-client"}, AnsibleHost: "10.20.30.41",
	}}}
	runAnsibleHostEdit(t, hf, "host1", "10.20.30.61", 'n')

	h := hf.Hosts[0]
	if h.AnsibleHost != "10.20.30.61" {
		t.Errorf("ansible_host = %q, want 10.20.30.61", h.AnsibleHost)
	}
	if _, ok := h.Extra[freeipaClientDNSReplaceFromKey]; ok {
		t.Errorf("expected no %s written on confirm=no, got %q", freeipaClientDNSReplaceFromKey, h.Extra[freeipaClientDNSReplaceFromKey])
	}
}

// TestEditRouter_AnsibleHostFreeipaClientReplace_SecondChangeOverwritesCAS
// locks spec.md §11.5: confirming Yes a second time must overwrite the
// acknowledgement to the immediately-previous address, never keep
// stacking or reuse the original one.
func TestEditRouter_AnsibleHostFreeipaClientReplace_SecondChangeOverwritesCAS(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{
		Name:        "host1",
		Roles:       []string{"freeipa-client"},
		AnsibleHost: "10.20.30.61",
		Extra:       map[string]string{freeipaClientDNSReplaceFromKey: "10.20.30.41"},
	}}}
	runAnsibleHostEdit(t, hf, "host1", "10.20.30.81", 'y')

	h := hf.Hosts[0]
	if h.AnsibleHost != "10.20.30.81" {
		t.Errorf("ansible_host = %q, want 10.20.30.81", h.AnsibleHost)
	}
	if got := h.Extra[freeipaClientDNSReplaceFromKey]; got != "10.20.30.61" {
		t.Errorf("%s = %q, want 10.20.30.61 (the immediately-previous address, not the original 10.20.30.41)", freeipaClientDNSReplaceFromKey, got)
	}
}

func TestEditRouter_AnsibleHostEdit_NonFreeipaClientHostNeverPrompts(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{
		Name: "host1", Roles: []string{"docker"}, AnsibleHost: "10.20.30.41",
	}}}
	// No confirm key sent: if a confirm screen wrongly appeared, the
	// field-apply callback (which only runs when the screen finishes)
	// would never fire, and this assertion would catch the stale value.
	runAnsibleHostEdit(t, hf, "host1", "10.20.30.61", 0)

	h := hf.Hosts[0]
	if h.AnsibleHost != "10.20.30.61" {
		t.Errorf("ansible_host = %q, want 10.20.30.61 (applied directly, no confirm)", h.AnsibleHost)
	}
	if len(h.Extra) != 0 {
		t.Errorf("expected no Extra vars written, got %v", h.Extra)
	}
}

func TestEditRouter_AnsibleHostEdit_HostnameToIPNeverPrompts(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{
		Name: "host1", Roles: []string{"freeipa-client"}, AnsibleHost: "host1.old.example",
	}}}
	runAnsibleHostEdit(t, hf, "host1", "10.20.30.61", 0)

	h := hf.Hosts[0]
	if h.AnsibleHost != "10.20.30.61" {
		t.Errorf("ansible_host = %q, want 10.20.30.61 (applied directly, no confirm)", h.AnsibleHost)
	}
	if len(h.Extra) != 0 {
		t.Errorf("expected no Extra vars written, got %v", h.Extra)
	}
}

func TestEditRouter_AnsibleHostEdit_IPToHostnameNeverPrompts(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{
		Name: "host1", Roles: []string{"freeipa-client"}, AnsibleHost: "10.20.30.41",
	}}}
	runAnsibleHostEdit(t, hf, "host1", "host1.new.example", 0)

	h := hf.Hosts[0]
	if h.AnsibleHost != "host1.new.example" {
		t.Errorf("ansible_host = %q, want host1.new.example (applied directly, no confirm)", h.AnsibleHost)
	}
	if len(h.Extra) != 0 {
		t.Errorf("expected no Extra vars written, got %v", h.Extra)
	}
}

// ---- automation driver parity (spec.md §11.7/§18.3.6) ---------------------

func TestEditAutomationDriverSetHostField_AnsibleHostFreeipaClientConfirmYes(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "ipa-client-1"},
			{Action: "set_host_field", Host: "ipa-client-1", Field: "ansible_host", Value: "10.20.30.41"},
			{Action: "enable_role", Host: "ipa-client-1", Role: "freeipa-client"},
			{Action: "set_host_field", Host: "ipa-client-1", Field: "ansible_host", Value: "10.20.30.61", Confirm: "yes"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	hf := readHostsFileForTest(t, dir)
	h := hf.Hosts[0]
	if h.AnsibleHost != "10.20.30.61" {
		t.Errorf("ansible_host = %q, want 10.20.30.61", h.AnsibleHost)
	}
	if got := h.Extra[freeipaClientDNSReplaceFromKey]; got != "10.20.30.41" {
		t.Errorf("%s = %q, want 10.20.30.41", freeipaClientDNSReplaceFromKey, got)
	}
}

func TestEditAutomationDriverSetHostField_AnsibleHostFreeipaClientConfirmNo(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "ipa-client-1"},
			{Action: "set_host_field", Host: "ipa-client-1", Field: "ansible_host", Value: "10.20.30.41"},
			{Action: "enable_role", Host: "ipa-client-1", Role: "freeipa-client"},
			{Action: "set_host_field", Host: "ipa-client-1", Field: "ansible_host", Value: "10.20.30.61", Confirm: "no"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	hf := readHostsFileForTest(t, dir)
	h := hf.Hosts[0]
	if h.AnsibleHost != "10.20.30.61" {
		t.Errorf("ansible_host = %q, want 10.20.30.61", h.AnsibleHost)
	}
	if _, ok := h.Extra[freeipaClientDNSReplaceFromKey]; ok {
		t.Errorf("expected no %s written on confirm=no, got %q", freeipaClientDNSReplaceFromKey, h.Extra[freeipaClientDNSReplaceFromKey])
	}
}

// TestEditAutomationDriverSetHostField_AnsibleHostFreeipaClientMissingConfirmErrors
// locks spec.md §11.7: automation MUST NOT silently bypass the explicit
// authorization requirement by omitting confirm.
func TestEditAutomationDriverSetHostField_AnsibleHostFreeipaClientMissingConfirmErrors(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "ipa-client-1"},
			{Action: "set_host_field", Host: "ipa-client-1", Field: "ansible_host", Value: "10.20.30.41"},
			{Action: "enable_role", Host: "ipa-client-1", Role: "freeipa-client"},
			{Action: "set_host_field", Host: "ipa-client-1", Field: "ansible_host", Value: "10.20.30.61"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	err := d.run(&r, scenario)
	if err == nil {
		t.Fatal("expected an error when ansible_host changes on a freeipa-client host without an explicit confirm")
	}
	if !strings.Contains(err.Error(), "explicit DNS-replacement acknowledgement") {
		t.Errorf("error = %v, want it to explain the missing acknowledgement", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); err == nil {
		t.Fatal("expected hosts.yml not to be written: save_hosts must never run after an earlier step failed")
	}
}

func TestValidateSetHostField_RejectsUnsupportedConfirmValue(t *testing.T) {
	step := editAction{Action: "set_host_field", Host: "h", Field: "ansible_host", Value: "10.0.0.1", Confirm: "maybe"}
	if err := validateSetHostField(step); err == nil {
		t.Fatal("expected an error for an unsupported confirm value")
	}
}

// TestEditAutomationDriverSetHostField_AnsibleHostFreeipaClient_TUIParity
// locks spec.md §18.3.6: driving the same edit through the automation
// action and through the interactive push functions directly must reach
// the same end state, because both paths animate the identical screens
// (edit_automation_driver.go's design note).
func TestEditAutomationDriverSetHostField_AnsibleHostFreeipaClient_TUIParity(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "ipa-client-1"},
			{Action: "set_host_field", Host: "ipa-client-1", Field: "ansible_host", Value: "10.20.30.41"},
			{Action: "enable_role", Host: "ipa-client-1", Role: "freeipa-client"},
			{Action: "set_host_field", Host: "ipa-client-1", Field: "ansible_host", Value: "10.20.30.61", Confirm: "yes"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	viaAutomation := readHostsFileForTest(t, dir).Hosts[0]

	viaTUI := &inventory.HostsFile{Hosts: []inventory.Host{{
		Name: "ipa-client-1", Roles: []string{"freeipa-client"}, AnsibleHost: "10.20.30.41",
	}}}
	runAnsibleHostEdit(t, viaTUI, "ipa-client-1", "10.20.30.61", 'y')

	if viaAutomation.AnsibleHost != viaTUI.Hosts[0].AnsibleHost {
		t.Errorf("ansible_host mismatch: automation=%q tui=%q", viaAutomation.AnsibleHost, viaTUI.Hosts[0].AnsibleHost)
	}
	if viaAutomation.Extra[freeipaClientDNSReplaceFromKey] != viaTUI.Hosts[0].Extra[freeipaClientDNSReplaceFromKey] {
		t.Errorf("%s mismatch: automation=%q tui=%q", freeipaClientDNSReplaceFromKey,
			viaAutomation.Extra[freeipaClientDNSReplaceFromKey], viaTUI.Hosts[0].Extra[freeipaClientDNSReplaceFromKey])
	}
}
