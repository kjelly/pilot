package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// !unsafe on any mapping, list or document that encloses a roster password makes
// it a literal: `pilot roster lint --vars-file`, `pilot deploy` and
// `pilot reconcile` must not refuse the references in it, and each plain twin
// (the same reference with no !unsafe) must be refused (issue #165; the
// inventory package's oracle holds the Ansible verdict for these shapes).
func TestRosterReferencesHonorUnsafeAboveTheValue(t *testing.T) {
	secret := lintRunSentinel(t)
	lit := `"` + secret + `"`
	vars := "ipa_admin_password: " + secret + "\n"
	userRef, adminRef := `"{{ lacking_user }}"`, `"{{ lacking_admin }}"`

	const idc, nfs = "freeipa-identity", "freeipa-nfs-server"
	// A roster whose users are the given YAML block.
	withUsers := func(admin, users string) string {
		return "schema_version: 3\nnetgroups: []\ngrants: []\nfreeipa:\n  server: ipa-1.ipa.pilot.internal\n  admin:\n    principal: admin\n    password: " + admin + "\nusers:\n" + users +
			"nfs:\n  servers:\n    - host: nfs-1.ipa.pilot.internal\n      state: present\n      service_principal: {ensure: true, principal: nfs/nfs-1.ipa.pilot.internal}\n      shares: []\n"
	}
	alice := func(initial string) string {
		return "  - name: alice\n    password:\n      initial: " + initial + "\n    ssh_keys: {authoritative: true, values: []}\n"
	}
	rows := []struct {
		name      string
		component string
		roster    string
		refused   string // "" means accepted; otherwise the field the refusal names
	}{
		// The plain twins: refused.
		{"identity: a user's reference", idc, withUsers(lit, alice(userRef)), "users[alice].password.initial references lacking_user"},
		{"nfs-server: the admin reference", nfs, withUsers(adminRef, alice(lit)), "freeipa.admin.password references lacking_admin"},
		// !unsafe above the user's password.
		{"identity: users: !unsafe", idc, strings.Replace(withUsers(lit, alice(userRef)), "users:", "users: !unsafe", 1), ""},
		{"identity: the user is !unsafe", idc, strings.Replace(withUsers(lit, alice(userRef)), "  - name: alice", "  - !unsafe\n    name: alice", 1), ""},
		{"identity: password: !unsafe", idc, strings.Replace(withUsers(lit, alice(userRef)), "    password:\n      initial", "    password: !unsafe\n      initial", 1), ""},
		{"identity: the whole document is !unsafe", idc, "--- !unsafe\n" + withUsers(lit, alice(userRef)), ""},
		{"identity: an alias to an !unsafe password mapping", idc, withUsers(lit, "  - name: alice\n    password: &pw !unsafe\n      initial: "+userRef+"\n  - name: bob\n    password: *pw\n"), ""},
		{"identity: a merge key from an !unsafe password mapping", idc, withUsers(lit, "  - name: alice\n    password: &pw !unsafe\n      initial: "+userRef+"\n  - name: bob\n    password:\n      <<: *pw\n"), ""},
		// !unsafe above the admin password (both playbooks that render it).
		{"nfs-server: freeipa: !unsafe", nfs, strings.Replace(withUsers(adminRef, alice(lit)), "freeipa:", "freeipa: !unsafe", 1), ""},
		{"nfs-server: admin: !unsafe", nfs, strings.Replace(withUsers(adminRef, alice(lit)), "  admin:\n", "  admin: !unsafe\n", 1), ""},
		{"nfs-server: the whole document is !unsafe", nfs, "--- !unsafe\n" + withUsers(adminRef, alice(lit)), ""},
	}
	// A value shared between !unsafe and normal YAML is not judged, and lint
	// says which fields.
	shared := map[string]bool{"identity: a merge key from an !unsafe password mapping": true}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			env := newRosterRefEnv(t, r.roster, vars)

			// lint --vars-file (it reports every reference, whichever playbook).
			lintOut, lintErr := execRosterLint(t, "--vars-file", env.vars, env.roster)
			if strings.Contains(lintOut, secret) {
				t.Fatalf("lint printed the secret")
			}
			if r.refused == "" {
				if lintErr != nil || strings.Contains(lintOut, "[roster-reference]") {
					t.Fatalf("lint refused a value !unsafe makes a literal: %v\n%s", lintErr, lintOut)
				}
			} else if lintErr == nil || !strings.Contains(lintOut, "[roster-reference] "+r.refused) {
				t.Fatalf("lint did not report the plain reference: %v\n%s", lintErr, lintOut)
			}
			for _, field := range []string{"users[alice].password.initial", "users[bob].password.initial"} {
				want := "ℹ️  " + skippedMarker + "：" + field + " 有無法判斷的部分"
				if got := strings.Contains(lintOut, want); got != shared[r.name] {
					t.Fatalf("lint says %q = %v, want %v:\n%s", field, got, shared[r.name], lintOut)
				}
			}

			// The precheck, as deploy and reconcile run it.
			out, err := env.call(t, r.component, nil, env.vault())
			if strings.Contains(out, secret) || strings.Contains(errText(err), secret) {
				t.Fatalf("the precheck printed the secret")
			}
			if r.refused == "" {
				env.assertNotRefusedNamesOnly(err, out)
				return
			}
			if err == nil || !strings.Contains(err.Error(), refusalMarker) || !strings.Contains(err.Error(), r.refused) {
				t.Fatalf("the plain reference was not refused: err = %v, output %q", err, out)
			}
		})
	}

	// The funnel of deploy and reconcile, and a batch row, with !unsafe: they
	// get to their plan.
	t.Run("the funnel and the batch go on past an !unsafe reference", func(t *testing.T) {
		env := newRosterRefEnv(t, strings.Replace(withUsers(lit, alice(userRef)), "users:", "users: !unsafe", 1), vars)
		out, err := env.funnel(identityPlaybook, "freeipa-identity", nil, env.vault())
		env.assertNotRefusedNamesOnly(err, out)
		if !strings.Contains(out, "Deployment execution plan") || len(env.ran()) == 0 {
			t.Fatalf("the funnel did not get to its plan (err = %v)\n%s", err, out)
		}
		var batch bytes.Buffer
		request := catalogDeploymentRequest{playbook: identityPlaybook, inv: env.inv, stage: "sandbox", componentHints: []string{"freeipa-identity"}, workspaceDir: env.ws, vault: env.vault()}
		err = executeCatalogReconcileBatch(context.Background(), ansible.NewRunner(), &batch, []catalogDeploymentRequest{request})
		env.assertNotRefusedNamesOnly(err, batch.String())
		if !strings.Contains(batch.String(), "batch execution plan") {
			t.Fatalf("the batch did not get to its plan (err = %v)\n%s", err, batch.String())
		}
	})
	t.Run("the nfs-server funnel goes on past an !unsafe admin reference", func(t *testing.T) {
		env := newRosterRefEnv(t, strings.Replace(withUsers(adminRef, alice(lit)), "freeipa:", "freeipa: !unsafe", 1), vars)
		out, err := env.funnel(nfsPlaybook, "freeipa-nfs-server", nil, env.vault())
		env.assertNotRefusedNamesOnly(err, out)
		if !strings.Contains(out, "Deployment execution plan") || len(env.ran()) == 0 {
			t.Fatalf("the funnel did not get to its plan (err = %v)\n%s", err, out)
		}
	})
}

// assertNotRefusedNamesOnly is assertNotRefused for a run that may print the
// one-line notes of what it could not judge: it is not refused, and every
// "skipped" line it printed is one of the "could not judge this field" notes
// (a skip for any other reason, such as ansible-inventory failing, would mean
// the check did not run).
func (e *rosterRefEnv) assertNotRefusedNamesOnly(err error, out string) {
	e.t.Helper()
	if err != nil && strings.Contains(err.Error(), refusalMarker) {
		e.t.Fatalf("a run that works was refused: %v\n%s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		isNote := strings.HasPrefix(line, "ℹ️  "+skippedMarker) && strings.Contains(line, "無法判斷")
		if strings.Contains(line, skippedMarker) && !isNote {
			e.t.Fatalf("the check was skipped for another reason: %q", line)
		}
	}
}
