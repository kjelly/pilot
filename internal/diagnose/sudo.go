package diagnose

import "fmt"

// SudoSteps returns the fixed, read-only ad-hoc commands
// docs/verification/freeipa-client.md §2's C2/C4/C5/C6/C7/C8 rows use to
// diagnose FreeIPA-backed sudo, in the causal order BuildSudoOutput walks.
// user must already be validated (inventory.ValidRosterUserName) before
// calling this — SudoSteps never validates its input itself.
func SudoSteps(user string) []Step {
	return []Step{
		{ID: "C2", Description: "sssd service active", Module: "command", Command: "systemctl is-active sssd"},
		{ID: "C4", Description: "host has a Kerberos machine identity", Module: "command", Command: "sudo klist -k /etc/krb5.keytab"},
		{ID: "C5", Description: "sssd resolves the user account", Module: "command", Command: fmt.Sprintf("id %s", user)},
		{ID: "C6", Description: "sssd access_provider is ipa (HBAC wired)", Module: "command", Command: `sudo grep -qE "^access_provider *= *ipa" /etc/sssd/sssd.conf`},
		{ID: "C7", Description: "nsswitch routes sudoers through sss", Module: "command", Command: `grep -qE "^sudoers:.*sss" /etc/nsswitch.conf`},
		{ID: "C8", Description: "central FreeIPA sudo rule grants this user access", Module: "command", Command: fmt.Sprintf("sudo -l -U %s", user)},
	}
}

// SudoOutput is the sudo check's typed result: raw per-step evidence plus a
// synthesized verdict that names the first broken link in the causal chain
// (a later, also-broken link stays visible in Steps, just not the
// headline).
type SudoOutput struct {
	SssdActive                  bool
	HasKerberosMachineIdentity  bool
	AccountResolvesViaSSSD      bool
	AccessProviderIsIPA         bool
	SudoersRoutedThroughSSSD    bool
	CentralSudoRuleGrantsAccess bool
	Verdict                     string
	Steps                       []StepResult
}

// BuildSudoOutput synthesizes SudoOutput from SudoSteps' results. results
// must be in the exact order SudoSteps(user) returned them.
func BuildSudoOutput(user string, results []StepResult) SudoOutput {
	rc := func(id string) (int, bool) {
		for _, r := range results {
			if r.Step.ID == id && r.Result.RunErr == nil {
				return r.Result.RC, true
			}
		}
		return -1, false
	}
	out := SudoOutput{Steps: results}
	sssdRC, sssdOK := rc("C2")
	out.SssdActive = sssdOK && sssdRC == 0
	c4RC, c4OK := rc("C4")
	out.HasKerberosMachineIdentity = c4OK && c4RC == 0
	c5RC, c5OK := rc("C5")
	out.AccountResolvesViaSSSD = c5OK && c5RC == 0
	c6RC, c6OK := rc("C6")
	out.AccessProviderIsIPA = c6OK && c6RC == 0
	c7RC, c7OK := rc("C7")
	out.SudoersRoutedThroughSSSD = c7OK && c7RC == 0
	c8RC, c8OK := rc("C8")
	out.CentralSudoRuleGrantsAccess = c8OK && c8RC == 0

	switch {
	case !out.SssdActive:
		out.Verdict = "sssd is not active — no FreeIPA-backed login/sudo can work on this host until it's running (check `systemctl status sssd` / `journalctl -u sssd`)"
	case !out.HasKerberosMachineIdentity:
		out.Verdict = "host has no Kerberos machine identity (keytab missing/invalid) — enrollment is broken or incomplete"
	case !out.AccountResolvesViaSSSD:
		out.Verdict = fmt.Sprintf("sssd cannot resolve user %q on this host — the account doesn't exist here or sssd's cache is stale", user)
	case !out.AccessProviderIsIPA:
		out.Verdict = "sssd.conf's access_provider is not ipa — HBAC is not wired up on this host"
	case !out.SudoersRoutedThroughSSSD:
		out.Verdict = "nsswitch.conf does not route sudoers through sss — the central FreeIPA sudo rule is never consulted, regardless of what's configured server-side"
	case !out.CentralSudoRuleGrantsAccess:
		out.Verdict = fmt.Sprintf("no central FreeIPA sudo rule grants user %q access on this host — check pilot://roster/effective-access's effective_sudo_access for the config-level view", user)
	default:
		out.Verdict = fmt.Sprintf("sudo should work for user %q on this host — sssd is up, enrollment and HBAC/sudoers routing are correct, and a central sudo rule grants access", user)
	}
	return out
}
