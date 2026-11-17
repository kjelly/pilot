package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kjelly/pilot/internal/rosteroracletest"
)

// The end-to-end oracle of the precheck's facts (issue #165): for every row the
// real `ansible-inventory` and precheckRosterReferences judge a roster and a
// vault vars file, and the real apply playbook's pre_tasks (the same harness
// the inventory package's oracle uses) run the same two files under
// ansible-playbook. The precheck's refusals must be a subset of what Ansible
// fails on (never refuse a run that works), and the rows that Ansible fails on
// for a reason the precheck can know must be refused (a check that never fires
// proves nothing, AGENTS.md section 5.12). What it cannot know it does not
// refuse and says so, in one line of names.
//
// Every row's roster refers to a variable nothing defines (missing_admin) from
// the admin password, so Ansible fails on a row exactly when it renders the
// admin password: freeipa.server and ipa_admin_password decide that, and each
// row varies one of them.
func TestPrecheckRosterReferencesFactsMatchAnsible(t *testing.T) {
	rosteroracletest.RequireAnsiblePlaybook(t)
	secret := lintRunSentinel(t)
	lit := `"` + secret + `"`
	setAdmin := "ipa_admin_password: " + secret + "\n"
	adminRef := `"{{ missing_admin }}"`
	const idc, nfs = "freeipa-identity", "freeipa-nfs-server"
	idRoster := func(server string) string { return rosterRefRosterServer(server, adminRef, lit) }

	type row struct {
		name      string
		component string
		roster    string
		vars      string
		// ansibleFails is what the table says Ansible does with the row (and is
		// checked against the real run); refused is the precheck's verdict.
		ansibleFails bool
		refused      bool
		// note is a part of the one line the precheck prints for a run it
		// let through because it could not decide; "" means it prints nothing.
		note string
	}
	rows := []row{
		// ---- freeipa.server is a template: Ansible renders it before it counts its length ----
		{name: "S1 server | default('', true) of a null variable: unknowable, not refused, said so", component: idc, roster: idRoster(`"{{ empty_server | default('', true) }}"`), vars: setAdmin + "empty_server:\n",
			ansibleFails: true, note: "freeipa.admin.password 引用 missing_admin"},
		{name: "S2 server {{ srv }}, srv empty", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin + "srv: ''\n", ansibleFails: true, refused: true},
		{name: "S3 server {{ srv }}, srv set", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin + "srv: ipa.example.test\n"},
		{name: "S4 server {{ srv }}, srv undefined (Ansible fails on srv itself too)", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin, ansibleFails: true, refused: true},
		{name: "S5 server {{ srv }}, srv null", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin + "srv:\n"},
		{name: "S6 server {{ srv }}, srv blank", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin + "srv: '   '\n", ansibleFails: true, refused: true},
		{name: "S7 server x{{ srv }}, srv empty: not a bare reference, not judged", component: idc, roster: idRoster(`"x{{ srv }}"`), vars: setAdmin + "srv: ''\n", note: "freeipa.admin.password 引用 missing_admin"},
		{name: "S8 server !unsafe {{ srv }}", component: idc, roster: idRoster(`!unsafe "{{ srv }}"`), vars: setAdmin},
		{name: "S9 server {{ srv }}, srv is {{ srv2 }}, srv2 empty", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin + "srv: '{{ srv2 }}'\nsrv2: ''\n", ansibleFails: true, refused: true},
		{name: "S10 server {{ srv }}, srv is !unsafe '{{ x }}'", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin + "srv: !unsafe '{{ x }}'\n"},
		{name: "S11 server {{ srv }}, srv is 0", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin + "srv: 0\n"},
		{name: "S12 server {{ srv }}, srv is []", component: idc, roster: idRoster(`"{{ srv }}"`), vars: setAdmin + "srv: []\n"},
		{name: "server: a name", component: idc, roster: idRoster("ipa.example.test"), vars: setAdmin},
		{name: "server: missing", component: idc, roster: idRoster(""), vars: setAdmin, ansibleFails: true, refused: true},
		// ---- ipa_admin_password: the admin password is its default(x, true) fallback ----
		{name: "A1 ipa_admin_password {{ empty_admin }}, empty", component: idc, roster: idRoster("ipa.example.test"), vars: "ipa_admin_password: '{{ empty_admin }}'\nempty_admin: ''\n", ansibleFails: true, refused: true},
		{name: "A2 ipa_admin_password is !unsafe text", component: idc, roster: idRoster("ipa.example.test"), vars: "ipa_admin_password: !unsafe '{{ xxxxxxxx }}'\n"},
		{name: "A3 ipa_admin_password {{ undefined_admin }}", component: idc, roster: idRoster("ipa.example.test"), vars: "ipa_admin_password: '{{ undefined_admin }}'\n", ansibleFails: true, refused: true},
		{name: "A4 ipa_admin_password {{ vault_ipa_admin_password }}, undefined", component: idc, roster: idRoster("ipa.example.test"), vars: "ipa_admin_password: '{{ vault_ipa_admin_password }}'\n", ansibleFails: true, refused: true},
		{name: "A5 ipa_admin_password {{ vault_ipa_admin_password }}, empty", component: idc, roster: idRoster("ipa.example.test"), vars: "ipa_admin_password: '{{ vault_ipa_admin_password }}'\nvault_ipa_admin_password: ''\n", ansibleFails: true, refused: true},
		{name: "A6 ipa_admin_password {{ vault_ipa_admin_password }}, set", component: idc, roster: idRoster("ipa.example.test"), vars: "ipa_admin_password: '{{ vault_ipa_admin_password }}'\nvault_ipa_admin_password: " + secret + "\n"},
		{name: "A7 ipa_admin_password with a filter: unknowable, not refused, said so", component: idc, roster: idRoster("ipa.example.test"), vars: "ipa_admin_password: \"{{ empty_admin | default('') }}\"\n", ansibleFails: true, note: "freeipa.admin.password 引用 missing_admin"},
		{name: "A8 no ipa_admin_password at all", component: idc, roster: idRoster("ipa.example.test"), vars: "other: 1\n", ansibleFails: true, refused: true},
		// ---- a roster without schema_version is ignored by the identity playbook ----
		{name: "V1 no schema_version", component: idc, roster: strings.Replace(idRoster("ipa.example.test"), "schema_version: 3\n", "", 1), vars: setAdmin},
		// ---- !unsafe above the admin password (freeipa-nfs-server renders it always) ----
		{name: "nfs: the admin reference is refused", component: nfs, roster: idRoster("ipa.example.test"), vars: setAdmin, ansibleFails: true, refused: true},
		{name: "nfs: freeipa: !unsafe", component: nfs, roster: strings.Replace(idRoster("ipa.example.test"), "freeipa:", "freeipa: !unsafe", 1), vars: "other: 1\n"},
		{name: "nfs: the whole document is !unsafe", component: nfs, roster: "--- !unsafe\n" + idRoster("ipa.example.test"), vars: "other: 1\n"},
	}

	// Ansible first, every row in parallel.
	type verdict struct{ fails bool }
	var mu sync.Mutex
	ansible := map[string]verdict{}
	t.Run("ansible", func(t *testing.T) {
		for _, r := range rows {
			r := r
			t.Run(r.name, func(t *testing.T) {
				t.Parallel()
				// Not t.TempDir(): its name carries the row's, and "{{" in a path is a template.
				dir, err := os.MkdirTemp("", "precheck-oracle-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(dir) })
				play := rosteroracletest.Identity
				if r.component == nfs {
					play = rosteroracletest.NFS
				}
				rosteroracletest.WriteHarness(t, dir, play)
				rosterPath := filepath.Join(dir, "roster.yaml")
				varsPath := filepath.Join(dir, "vars.yml")
				if err := os.WriteFile(rosterPath, []byte(r.roster), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(varsPath, []byte("oracle_marker: 1\n"+r.vars), 0o600); err != nil {
					t.Fatal(err)
				}
				res := rosteroracletest.Run(t, dir, play, rosterPath, varsPath)
				if !res.OK && !res.AdminGate && res.Undefined == "" {
					t.Fatalf("the harness failed in task %q for a reason other than an undefined variable", res.Task)
				}
				mu.Lock()
				ansible[r.name] = verdict{fails: !res.OK}
				mu.Unlock()
			})
		}
	})

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := ansible[r.name].fails; got != r.ansibleFails {
				t.Fatalf("the table says Ansible fails=%v, Ansible fails=%v", r.ansibleFails, got)
			}
			env := newRosterRefEnv(t, r.roster, r.vars)
			out, err := env.call(t, r.component, nil, env.vault())
			refused := err != nil && strings.Contains(err.Error(), refusalMarker)
			if err != nil && !refused {
				t.Fatalf("the precheck failed for another reason: %v", err)
			}
			if refused != r.refused {
				t.Fatalf("refused = %v, want %v (err = %v, output %q)", refused, r.refused, err, out)
			}
			// The invariant: never refuse what Ansible accepts.
			if refused && !ansible[r.name].fails {
				t.Fatalf("the precheck refused a run Ansible accepts: %v", err)
			}
			if !refused {
				if r.note == "" && out != "" {
					t.Fatalf("a run with nothing undecided printed %q", out)
				}
				if r.note != "" && (!strings.Contains(out, r.note) || !strings.HasPrefix(out, "ℹ️  "+skippedMarker) || strings.Count(out, "\n") != 1) {
					t.Fatalf("output = %q, want one skipped line holding %q", out, r.note)
				}
			}
			// Names and labels only: nothing of the secret reaches the output or the error.
			for _, text := range []string{out, errText(err)} {
				if strings.Contains(text, secret) {
					t.Fatalf("the secret reached the output")
				}
			}
		})
	}
}
