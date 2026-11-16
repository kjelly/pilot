package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// The preflight half of issue #165: `pilot deploy` and `pilot reconcile` refuse,
// before anything runs, a roster whose secret strings refer to a variable that
// nothing the run defines — the failure apply reports only inside a no_log
// task. Every refusal below has its twin that goes on (AGENTS.md §5.12), and
// every funnel is run for real, with the real `ansible-inventory` and a recorder
// in place of `ansible-playbook` and `ssh`.

// refusalMarker is what the precheck's error starts with.
const refusalMarker = "roster 變數引用檢查沒有通過"

// rosterRefRoster is a roster the identity and NFS playbooks' structural gates
// accept, with the given admin password and alice's initial password (YAML
// scalars) and freeipa.server declared or not.
func rosterRefRoster(server bool, admin, initial string) string {
	var b strings.Builder
	b.WriteString("schema_version: 3\nnetgroups: []\ngrants: []\nfreeipa:\n")
	if server {
		b.WriteString("  server: ipa-1.ipa.pilot.internal\n")
	}
	b.WriteString("  admin:\n    principal: admin\n    password: " + admin + "\n")
	b.WriteString("users:\n  - name: alice\n    password:\n      initial: " + initial + "\n    ssh_keys: {authoritative: true, values: []}\n")
	// The nfs-1 entry the deploy completeness gate looks for.
	b.WriteString("nfs:\n  servers:\n    - host: nfs-1.ipa.pilot.internal\n      state: present\n      service_principal: {ensure: true, principal: nfs/nfs-1.ipa.pilot.internal}\n      shares: []\n")
	return b.String()
}

// rosterRefEnv is a workspace with a real inventory (freeipa-server ipa-1 and
// freeipa-nfs-server nfs-1, both naming roster as freeipa_roster_file), the
// roster, the recorders of funnelEnv, and a vault vars file when given one.
type rosterRefEnv struct {
	*funnelEnv
	ws, roster, vars string
}

func newRosterRefEnv(t *testing.T, roster, vars string) *rosterRefEnv {
	t.Helper()
	inv := writeEffectiveInventory(t, "placeholder: true\n")
	ws := filepath.Dir(inv)
	vault := filepath.Join(ws, ".vault")
	if err := os.MkdirAll(vault, 0o700); err != nil {
		t.Fatal(err)
	}
	rosterPath := filepath.Join(vault, "ipa-identity.yaml")
	if err := os.WriteFile(rosterPath, []byte(roster), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "group_vars"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "group_vars", "freeipa.yml"), []byte("freeipa_domain: ipa.pilot.internal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	varsPath := ""
	if vars != "" {
		varsPath = filepath.Join(vault, "main.yaml")
		if err := os.WriteFile(varsPath, []byte(vars), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(inv, []byte(rosterRefInventory(rosterPath, "", false)), 0o600); err != nil {
		t.Fatal(err)
	}
	// The recorders of newFunnelEnv, on this inventory.
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "calls.log")
	for _, name := range []string{"ansible-playbook", "ssh"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> '" + log + "'\nexit 0\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	oldData := dataDir
	dataDir = ""
	t.Cleanup(func() { dataDir = oldData })
	oldPrompt := activePromptAutomation
	activePromptAutomation = &promptAutomation{useDefaults: true, previewOnly: true}
	t.Cleanup(func() { activePromptAutomation = oldPrompt })
	stubDeploymentAvailabilityAllReachable(t)
	return &rosterRefEnv{
		funnelEnv: &funnelEnv{t: t, inv: inv, log: log, seam: useLocalLockDialer(t)},
		ws:        ws, roster: rosterPath, vars: varsPath,
	}
}

func (e *rosterRefEnv) vault() vaultInput { return vaultInput{ExtraVarsFile: e.vars} }

// rosterRefInventory is the workspace inventory: freeipa-server ipa-1 and
// freeipa-nfs-server nfs-1 (also a freeipa-client, which NFS requires on the
// same host), both naming the roster; nfs1Vars are more variables for nfs-1
// (lines indented ten spaces), and secondNFS adds nfs-2, which names the roster
// too and does not get nfs1Vars.
func rosterRefInventory(rosterPath, nfs1Vars string, secondNFS bool) string {
	second, secondClient := "", ""
	if secondNFS {
		second = "        nfs-2:\n          freeipa_roster_file: " + rosterPath + "\n"
		secondClient = "        nfs-2:\n          ansible_host: 192.0.2.31\n          ansible_user: root\n"
	}
	return fmt.Sprintf(`all:
  children:
    freeipa-server:
      hosts:
        ipa-1:
          ansible_host: 192.0.2.10
          ansible_user: root
%s          freeipa_roster_file: %s
    freeipa-client:
      hosts:
        nfs-1:
          ansible_host: 192.0.2.30
          ansible_user: root
%s    freeipa-nfs-server:
      hosts:
        nfs-1:
          freeipa_roster_file: %s
%s%s`, lockCommonArgs, rosterPath, secondClient, rosterPath, nfs1Vars, second)
}

// withSecondNFSHost is rewriteInventory's option that adds nfs-2.
const withSecondNFSHost = true

// rewriteInventory replaces the workspace inventory (see rosterRefInventory).
func (e *rosterRefEnv) rewriteInventory(t *testing.T, nfs1Vars string, secondNFS ...bool) {
	t.Helper()
	body := rosterRefInventory(e.roster, nfs1Vars, len(secondNFS) > 0 && secondNFS[0])
	if err := os.WriteFile(e.inv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// funnel runs the single-run funnel of deploy and reconcile for one component.
func (e *rosterRefEnv) funnel(playbook, component string, extraVars []string, vault vaultInput) (string, error) {
	var out bytes.Buffer
	_, err := executeRecordedDeploymentWithAuthorizationResult(context.Background(), ansible.NewRunner(), &out, playbook, e.inv, "", "", extraVars, vault, "sandbox", []string{component}, nil, nil)
	return out.String(), err
}

const (
	identityPlaybook = "playbooks/apply/freeipa-identity-apply.yml"
	nfsPlaybook      = "playbooks/apply/freeipa-nfs-server-apply.yml"
)

// assertRefusedByRosterReferences: the run ended at the precheck, naming every
// wanted "field references name", before anything ran or was shown.
func (e *rosterRefEnv) assertRefusedByRosterReferences(err error, out string, wants ...string) {
	e.t.Helper()
	if err == nil || !strings.Contains(err.Error(), refusalMarker) {
		e.t.Fatalf("the run was not refused by the roster reference precheck: err = %v\n%s", err, out)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			e.t.Fatalf("err = %v, want it to hold %q", err, want)
		}
	}
	if got := e.ran(); len(got) != 0 {
		e.t.Fatalf("the funnel ran %q before refusing", got)
	}
	if got := e.seam.started(); len(got) != 0 {
		e.t.Fatalf("an ssh for the lock was started before the refusal: %+v", got)
	}
	if strings.Contains(out, "Deployment execution plan") || strings.Contains(out, "batch execution plan") {
		e.t.Fatalf("the plan was shown before the refusal:\n%s", out)
	}
}

// assertNotRefused: the precheck let the run through (it may stop later, for
// reasons of its own).
func (e *rosterRefEnv) assertNotRefused(err error, out string) {
	e.t.Helper()
	if err != nil && strings.Contains(err.Error(), refusalMarker) {
		e.t.Fatalf("a run that works was refused: %v\n%s", err, out)
	}
	if strings.Contains(out, "roster 變數引用檢查已略過") {
		e.t.Fatalf("the check was skipped, not passed:\n%s", out)
	}
}

// call is precheckRosterReferences itself, for one component, against the real
// inventory and the real `ansible-inventory`.
func (e *rosterRefEnv) call(t *testing.T, component string, extraVars []string, vault vaultInput) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := precheckRosterReferences(context.Background(), &out, loadRepoCatalogForPrecheck(t), []string{component}, e.inv, "", extraVars, vault)
	return out.String(), err
}

// The verdict of the precheck for every shape, in both directions: a run
// whose roster refers to a variable nothing defines is refused with the field
// and the name; one that defines it (in the vars file, by a null value, in the
// inventory, by -e), that no variable can fail (filters, !unsafe, literals), whose
// field the playbook does not render, or that has no vault vars file, is not.
func TestPrecheckRosterReferencesVerdicts(t *testing.T) {
	admin := lintRunSentinel(t)
	adminLit := `"` + admin + `"`
	initialLit := `"` + lintRunSentinel(t) + `"`
	const idc, nfs = "freeipa-identity", "freeipa-nfs-server"
	vars := "ipa_admin_password: " + admin + "\n"
	rows := []struct {
		name      string
		component string
		roster    string
		vars      string
		extra     []string
		noVault   bool
		nfs1Vars  string   // inventory variables of nfs-1
		wantNames []string // "field references name" parts of the refusal; none: not refused
	}{
		// ---- freeipa-identity: users' initial passwords ----
		{name: "identity: a user's password refers to a variable the vars file lacks", component: idc, roster: rosterRefRoster(true, adminLit, `"{{ ipa_default_initial_password }}"`), vars: vars,
			wantNames: []string{"users[alice].password.initial references ipa_default_initial_password"}},
		{name: "identity: the vars file defines it", component: idc, roster: rosterRefRoster(true, adminLit, `"{{ ipa_default_initial_password }}"`), vars: vars + "ipa_default_initial_password: x\n"},
		{name: "identity: the vars file defines it with a null value", component: idc, roster: rosterRefRoster(true, adminLit, `"{{ ipa_default_initial_password }}"`), vars: vars + "ipa_default_initial_password:\n"},
		{name: "identity: -e defines it", component: idc, roster: rosterRefRoster(true, adminLit, `"{{ pw_from_e }}"`), vars: vars, extra: []string{"pw_from_e=x"}},
		{name: "identity: no vault vars file is not judged", component: idc, roster: rosterRefRoster(true, adminLit, `"{{ ipa_default_initial_password }}"`), vars: vars, noVault: true},
		{name: "identity: a mixed literal and reference", component: idc, roster: rosterRefRoster(true, adminLit, `"prefix-{{ lacking }}"`), vars: vars,
			wantNames: []string{"users[alice].password.initial references lacking"}},
		{name: "identity: a default filter is not judged", component: idc, roster: rosterRefRoster(true, adminLit, `"{{ lacking | default('') }}"`), vars: vars},
		{name: "identity: !unsafe is not judged", component: idc, roster: rosterRefRoster(true, adminLit, `!unsafe "{{ lacking }}"`), vars: vars},
		{name: "identity: a literal", component: idc, roster: rosterRefRoster(true, adminLit, initialLit), vars: vars},
		// ---- freeipa-identity: the admin password ----
		{name: "identity: admin refers to a variable the vars file lacks (no ipa_admin_password)", component: idc, roster: rosterRefRoster(true, `"{{ lacking_admin }}"`, initialLit), vars: "other: 1\n",
			wantNames: []string{"freeipa.admin.password references lacking_admin"}},
		{name: "identity: admin refers to ipa_admin_password the vars file has", component: idc, roster: rosterRefRoster(true, `"{{ ipa_admin_password }}"`, initialLit), vars: vars},
		{name: "identity: ipa_admin_password set and a server declared: the admin reference is never rendered", component: idc, roster: rosterRefRoster(true, `"{{ lacking_admin }}"`, initialLit), vars: vars},
		{name: "identity: ipa_admin_password set but no server declared: the server fill-in renders it", component: idc, roster: rosterRefRoster(false, `"{{ lacking_admin }}"`, initialLit), vars: vars,
			wantNames: []string{"freeipa.admin.password references lacking_admin"}},
		{name: "identity: ipa_admin_password empty falls back to the roster", component: idc, roster: rosterRefRoster(true, `"{{ lacking_admin }}"`, initialLit), vars: "ipa_admin_password: \"\"\n",
			wantNames: []string{"freeipa.admin.password references lacking_admin"}},
		{name: "identity: admin and user together", component: idc, roster: rosterRefRoster(true, `"{{ lacking_admin }}"`, `"{{ lacking_user }}"`), vars: "other: 1\n",
			wantNames: []string{"freeipa.admin.password references lacking_admin", "users[alice].password.initial references lacking_user"}},
		// ---- freeipa-nfs-server: the admin password only ----
		{name: "nfs-server: admin refers to a variable the vars file lacks", component: nfs, roster: rosterRefRoster(true, `"{{ lacking_admin }}"`, initialLit), vars: vars,
			wantNames: []string{"freeipa.admin.password references lacking_admin"}},
		{name: "nfs-server: admin refers to ipa_admin_password the vars file has", component: nfs, roster: rosterRefRoster(true, `"{{ ipa_admin_password }}"`, initialLit), vars: vars},
		{name: "nfs-server: a user's password reference is never rendered", component: nfs, roster: rosterRefRoster(true, adminLit, `"{{ lacking_user }}"`), vars: vars},
		{name: "nfs-server: defined by the inventory host", component: nfs, roster: rosterRefRoster(true, `"{{ from_inventory }}"`, initialLit), vars: vars, nfs1Vars: "          from_inventory: x\n"},
		{name: "nfs-server: no vault vars file is not judged", component: nfs, roster: rosterRefRoster(true, `"{{ lacking_admin }}"`, initialLit), vars: vars, noVault: true},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			env := newRosterRefEnv(t, tc.roster, tc.vars)
			if tc.nfs1Vars != "" {
				env.rewriteInventory(t, tc.nfs1Vars)
			}
			vault := env.vault()
			if tc.noVault {
				vault = vaultInput{}
			}
			out, err := env.call(t, tc.component, tc.extra, vault)
			if len(tc.wantNames) == 0 {
				if err != nil || out != "" {
					t.Fatalf("a run that works: err = %v, output = %q", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), refusalMarker) {
				t.Fatalf("err = %v, want the precheck's refusal", err)
			}
			for _, want := range tc.wantNames {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to name %q", err, want)
				}
			}
			if want := fmt.Sprintf("(%d 項)", len(tc.wantNames)); !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want exactly %s", err, want)
			}
		})
	}
}

// Each host is judged on what its own run defines: one roster, two NFS hosts,
// the variable defined for only one of them. The finding names the other.
func TestPrecheckRosterReferencesJudgesEveryHost(t *testing.T) {
	env := newRosterRefEnv(t, rosterRefRoster(true, `"{{ only_nfs_1 }}"`, `"`+lintRunSentinel(t)+`"`), "other: 1\n")
	env.rewriteInventory(t, "          only_nfs_1: x\n", withSecondNFSHost)
	out, err := env.call(t, "freeipa-nfs-server", nil, env.vault())
	if err == nil || !strings.Contains(err.Error(), "freeipa.admin.password references only_nfs_1") || !strings.Contains(err.Error(), "for nfs-2") {
		t.Fatalf("err = %v, output %q, want the finding for nfs-2", err, out)
	}
	if strings.Contains(err.Error(), "for nfs-1") || strings.Contains(err.Error(), "(2 項)") {
		t.Fatalf("err = %v: nfs-1 defines the variable and the roster is one file: one finding, for nfs-2", err)
	}
}

// The refusal comes from the funnel every deploy and reconcile goes through, before
// the plan is shown, anything is applied or any ssh is started; the twin
// (the vars file defines the name) goes on to its plan and its playbooks.
func TestPrecheckRosterReferencesInTheFunnel(t *testing.T) {
	admin := lintRunSentinel(t)
	vars := "ipa_admin_password: " + admin + "\n"
	for _, tc := range []struct {
		name, playbook, component, roster string
		wantIn                            string
	}{
		{"identity", identityPlaybook, "freeipa-identity", rosterRefRoster(true, `"`+admin+`"`, `"{{ ipa_default_initial_password }}"`), "users[alice].password.initial references ipa_default_initial_password"},
		{"nfs-server", nfsPlaybook, "freeipa-nfs-server", rosterRefRoster(true, `"{{ lacking_admin }}"`, `"`+lintRunSentinel(t)+`"`), "freeipa.admin.password references lacking_admin"},
	} {
		t.Run(tc.name+" is refused before anything runs", func(t *testing.T) {
			env := newRosterRefEnv(t, tc.roster, vars)
			out, err := env.funnel(tc.playbook, tc.component, nil, env.vault())
			env.assertRefusedByRosterReferences(err, out, tc.wantIn)
		})
		t.Run(tc.name+" twin: the vars file defines it and the run goes on", func(t *testing.T) {
			env := newRosterRefEnv(t, tc.roster, vars+"ipa_default_initial_password: x\nlacking_admin: "+admin+"\n")
			out, err := env.funnel(tc.playbook, tc.component, nil, env.vault())
			env.assertNotRefused(err, out)
			if !strings.Contains(out, "Deployment execution plan") || len(env.ran()) == 0 {
				t.Fatalf("the run did not get to its plan and playbooks (err = %v)\n%s", err, out)
			}
		})
		if tc.component != "freeipa-identity" {
			continue
		}
		t.Run(tc.name+" twin: no vault vars file goes on", func(t *testing.T) {
			env := newRosterRefEnv(t, tc.roster, vars)
			out, err := env.funnel(tc.playbook, tc.component, nil, vaultInput{})
			env.assertNotRefused(err, out)
			if !strings.Contains(out, "Deployment execution plan") || len(env.ran()) == 0 {
				t.Fatalf("the run did not get to its plan and playbooks (err = %v)\n%s", err, out)
			}
		})
	}
	// A run for another component of the same workspace is not asked.
	t.Run("a component that is not a consumer is not asked", func(t *testing.T) {
		env := newRosterRefEnv(t, rosterRefRoster(true, `"{{ lacking_admin }}"`, `"{{ lacking_user }}"`), vars)
		out, err := env.call(t, "freeipa-client", nil, env.vault())
		if err != nil || out != "" {
			t.Fatalf("err = %v, output = %q, want nothing for freeipa-client", err, out)
		}
	})
}

// The batch (pilot reconcile with its one authorization, a multi-component
// pilot deploy) refuses before it shows its plan and asks, whichever of its
// requests it is, and nothing of the others runs.
func TestPrecheckRosterReferencesInTheBatch(t *testing.T) {
	admin := lintRunSentinel(t)
	vars := "ipa_admin_password: " + admin + "\n"
	roster := rosterRefRoster(true, `"`+admin+`"`, `"{{ ipa_default_initial_password }}"`)
	identity := func(env *rosterRefEnv) catalogDeploymentRequest {
		return catalogDeploymentRequest{playbook: identityPlaybook, inv: env.inv, stage: "sandbox", componentHints: []string{"freeipa-identity"}, workspaceDir: env.ws, vault: env.vault()}
	}
	other := func(env *rosterRefEnv) catalogDeploymentRequest {
		return catalogDeploymentRequest{playbook: "playbooks/apply/freeipa-dns-apply.yml", inv: env.inv, stage: "sandbox", componentHints: []string{"freeipa-dns"}, workspaceDir: env.ws, vault: env.vault()}
	}
	t.Run("one request", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, vars)
		var out bytes.Buffer
		err := executeCatalogReconcileBatch(context.Background(), ansible.NewRunner(), &out, []catalogDeploymentRequest{identity(env)})
		env.assertRefusedByRosterReferences(err, out.String(), "users[alice].password.initial references ipa_default_initial_password")
	})
	t.Run("the identity request is second", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, vars)
		var out bytes.Buffer
		err := executeCatalogReconcileBatch(context.Background(), ansible.NewRunner(), &out, []catalogDeploymentRequest{other(env), identity(env)})
		env.assertRefusedByRosterReferences(err, out.String(), "users[alice].password.initial references ipa_default_initial_password")
	})
	t.Run("twin: the vars file defines it and the plan is shown", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, vars+"ipa_default_initial_password: x\n")
		var out bytes.Buffer
		err := executeCatalogReconcileBatch(context.Background(), ansible.NewRunner(), &out, []catalogDeploymentRequest{identity(env)})
		env.assertNotRefused(err, out.String())
		if !strings.Contains(out.String(), "batch execution plan") {
			t.Fatalf("the batch did not get to its plan (err = %v)\n%s", err, out.String())
		}
	})
}

// The real entries: `pilot reconcile --component freeipa-identity --preview-only`
// and `pilot deploy --component freeipa-nfs-server --preview-only`, through
// cobra, with the workspace's .vault/main.yaml they pick by default.
func TestPrecheckRosterReferencesThroughCobra(t *testing.T) {
	admin := lintRunSentinel(t)
	vars := "ipa_admin_password: " + admin + "\n"
	t.Run("reconcile freeipa-identity --preview-only is refused", func(t *testing.T) {
		env := newRosterRefEnv(t, rosterRefRoster(true, `"`+admin+`"`, `"{{ ipa_default_initial_password }}"`), vars)
		out, err := runReconcileCLI(t, "--dir", env.ws, "--component", "freeipa-identity", "--preview-only")
		env.assertRefusedByRosterReferences(err, out, "users[alice].password.initial references ipa_default_initial_password")
	})
	t.Run("reconcile freeipa-identity --preview-only twin goes on", func(t *testing.T) {
		env := newRosterRefEnv(t, rosterRefRoster(true, `"`+admin+`"`, `"{{ ipa_default_initial_password }}"`), vars+"ipa_default_initial_password: x\n")
		out, err := runReconcileCLI(t, "--dir", env.ws, "--component", "freeipa-identity", "--preview-only")
		env.assertNotRefused(err, out)
		if !strings.Contains(out, "Deployment execution plan") && !strings.Contains(out, "execution plan") {
			t.Fatalf("reconcile did not get to its plan (err = %v)\n%s", err, out)
		}
	})
	t.Run("deploy freeipa-nfs-server --preview-only is refused", func(t *testing.T) {
		env := newRosterRefEnv(t, rosterRefRoster(true, `"{{ lacking_admin }}"`, `"`+lintRunSentinel(t)+`"`), vars)
		out, err := executeSelectedDeployCLI(t, "--dir", env.ws, "--component", "freeipa-nfs-server", "--preview-only")
		env.assertRefusedByRosterReferences(err, out, "freeipa.admin.password references lacking_admin")
	})
}

func TestJinjaTruthy(t *testing.T) {
	for name, tc := range map[string]struct {
		v    any
		want bool
	}{
		"missing":           {nil, false},
		"empty string":      {"", false},
		"a string":          {"x", true},
		"a template string": {"{{ vault_admin }}", true},
		"false":             {false, false},
		"true":              {true, true},
		"zero":              {float64(0), false},
		"a number":          {float64(7), true},
		"an empty list":     {[]any{}, false},
		"a list":            {[]any{"a"}, true},
		"an empty mapping":  {map[string]any{}, false},
		"a mapping":         {map[string]any{"a": 1}, true},
	} {
		if got := jinjaTruthy(tc.v); got != tc.want {
			t.Errorf("%s: jinjaTruthy(%v) = %v, want %v", name, tc.v, got, tc.want)
		}
	}
}

// The components the precheck judges are the ones whose playbooks the oracle
// test (internal/inventory TestRosterRenderedFieldsMatchAnsible) runs: a
// renamed playbook or a changed consumer fails here instead of silently
// checking nothing.
func TestRosterReferenceConsumersAreTheOraclePlaybooks(t *testing.T) {
	catalog := loadRepoCatalogForPrecheck(t)
	want := map[string]string{
		"freeipa-identity":   "playbooks/apply/freeipa-identity-apply.yml",
		"freeipa-nfs-server": "playbooks/apply/freeipa-nfs-server-apply.yml",
	}
	if len(rosterReferenceConsumers) != len(want) {
		t.Fatalf("rosterReferenceConsumers has %d components, the oracle runs %d playbooks: add the oracle for a new consumer", len(rosterReferenceConsumers), len(want))
	}
	for id, playbook := range want {
		component, ok := catalog.Component(id)
		if !ok || component.Playbooks.Apply != playbook {
			t.Errorf("%s: apply playbook = %q (found %v), want %s", id, component.Playbooks.Apply, ok, playbook)
		}
		if _, ok := rosterReferenceConsumers[id]; !ok {
			t.Errorf("%s is not a roster reference consumer", id)
		}
	}
}
