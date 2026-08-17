package diagnose

import (
	"fmt"
	"regexp"
	"strings"
)

// LoginSteps returns the fixed, read-only ad-hoc commands
// pilot_diagnose_login runs to answer "why can't these users log in / sudo
// on this host" in one call: host-level facts that gate every user
// (sssd active, Kerberos machine identity, sssd domain backend
// online/offline, and — reusing DNSSteps — whether the host's own name
// resolves, since a broken self-DNS record is a common cause of Kerberos
// ticket failures), plus two per-user facts for each entry in users
// (NSS passwd resolution, and whether a live central FreeIPA sudo rule
// grants access). users must already be validated
// (inventory.ValidRosterUserName) before calling this — LoginSteps never
// validates its input itself, the same contract SudoSteps documents.
func LoginSteps(host string, users []string) []Step {
	steps := []Step{
		{ID: "sssd-active", Description: "sssd service active", Module: "command", Command: "systemctl is-active sssd"},
		{ID: "kerberos-keytab", Description: "host has a Kerberos machine identity", Module: "command", Command: "sudo klist -k /etc/krb5.keytab"},
		// Fixed literal (no substituted input), so the shell module's
		// command substitution is safe here — same reasoning dns.go's
		// daemon-listening/daemon-installed steps already rely on. There is
		// no way to ask sssctl for "the" domain without first discovering
		// its name, and a fixed allow-list can't branch on an earlier
		// step's output (RunSteps runs every step independently).
		{ID: "sssd-domain-status", Description: "sssd domain backend online/offline status", Module: "shell",
			Command: `D=$(sudo sssctl domain-list 2>/dev/null | head -n1); [ -n "$D" ] && sudo sssctl domain-status "$D" 2>&1 || echo "no sssd domain configured"`},
	}
	steps = append(steps, DNSSteps(host)...)
	for _, user := range users {
		steps = append(steps,
			Step{ID: "getent-passwd:" + user, Description: fmt.Sprintf("NSS passwd entry for %s", user), Module: "command", Command: fmt.Sprintf("getent passwd %s", user)},
			Step{ID: "sudo-l:" + user, Description: fmt.Sprintf("central FreeIPA sudo rule grants %s access", user), Module: "command", Command: fmt.Sprintf("sudo -l -U %s", user)},
		)
	}
	return steps
}

// LoginHostOutput is pilot_diagnose_login's host-level (not per-user)
// result: the shared facts that gate every user's login/sudo on this
// host, synthesized with the same causal first-broken-link ordering
// BuildSudoOutput uses — if sssd itself isn't up, no per-user verdict
// below it matters.
type LoginHostOutput struct {
	SssdActive                 bool
	HasKerberosMachineIdentity bool
	SssdDomainStatusChecked    bool
	SssdDomainOnline           bool
	SssdDomainStatusRaw        string
	DNS                        DNSOutput
	Verdict                    string
}

// BuildLoginHostOutput synthesizes LoginHostOutput from LoginSteps'
// results. results must be in the exact order LoginSteps(host, users)
// returned them (BuildDNSOutput and the getent-passwd:/sudo-l: lookups
// below find their own IDs by name, so extra per-user entries in results
// are simply ignored here).
func BuildLoginHostOutput(host string, results []StepResult) LoginHostOutput {
	rc := func(id string) (int, bool) {
		for _, r := range results {
			if r.Step.ID == id && r.Result.RunErr == nil {
				return r.Result.RC, true
			}
		}
		return -1, false
	}
	out := LoginHostOutput{}
	sssdRC, sssdOK := rc("sssd-active")
	out.SssdActive = sssdOK && sssdRC == 0
	kRC, kOK := rc("kerberos-keytab")
	out.HasKerberosMachineIdentity = kOK && kRC == 0

	for _, r := range results {
		if r.Step.ID != "sssd-domain-status" || r.Result.RunErr != nil {
			continue
		}
		raw := strings.TrimSpace(r.Result.Stdout)
		out.SssdDomainStatusRaw = raw
		switch {
		case strings.Contains(raw, "Online status: Online"):
			out.SssdDomainStatusChecked, out.SssdDomainOnline = true, true
		case strings.Contains(raw, "Online status: Offline"):
			out.SssdDomainStatusChecked, out.SssdDomainOnline = true, false
		}
	}

	out.DNS = BuildDNSOutput(host, results)

	switch {
	case !out.SssdActive:
		out.Verdict = "sssd is not active on this host — no FreeIPA-backed login/sudo can work until it's running (check `systemctl status sssd` / `journalctl -u sssd`)"
	case !out.HasKerberosMachineIdentity:
		out.Verdict = "host has no Kerberos machine identity (keytab missing/invalid) — enrollment is broken or incomplete"
	case out.SssdDomainStatusChecked && !out.SssdDomainOnline:
		out.Verdict = "sssd's domain backend is offline — this host cannot reach the FreeIPA server (check network/DNS/firewall to the IPA server)"
	case out.DNS.NameQueried && !out.DNS.ResolvesViaNSS && !out.DNS.ResolvesViaDirectQuery:
		out.Verdict = fmt.Sprintf("this host's own name (%s) does not resolve via NSS or a direct loopback query — DNS problems here commonly break Kerberos ticket issuance and FreeIPA-backed login", host)
	default:
		out.Verdict = "host-level checks pass (sssd active, kerberos identity present, domain backend reachable, self-DNS resolves) — see each user's own result for account/authorization-specific issues"
	}
	return out
}

// LoginUserOutput is pilot_diagnose_login's per-user result: live account
// resolution and central sudo rule evidence, cross-referenced against the
// roster's own declared (config-level, not live) HBAC/sudo intent for
// this user+host — the config-vs-live comparison a manual investigation
// otherwise has to assemble by hand across pilot_diagnose_sudo and a
// separate roster inspection.
type LoginUserOutput struct {
	User                        string
	RosterHBACAuthorized        bool
	RosterHBACRules             []string
	RosterSudoAuthorized        bool
	RosterSudoRules             []string
	AccountResolvesViaSSSD      bool
	PasswdEntry                 string
	CentralSudoRuleGrantsAccess bool
	Verdict                     string
}

// BuildLoginUserOutput synthesizes one user's LoginUserOutput.
// rosterAvailable distinguishes "roster read successfully and declares
// zero rules for this user" from "roster path unknown/unreadable" — the
// latter must never be reported as a fact ("no roster HBAC rule
// authorizes this user"), since that's not something this call actually
// established. rosterHBACRules/rosterSudoRules are the names of roster
// rules that already authorize user on host — resolved by the caller
// (from inventory.EffectiveHBACAccessList/EffectiveSudoAccessList, which
// internal/diagnose deliberately does not depend on) since that's a
// config-file read, not an ad-hoc step; both are ignored when
// rosterAvailable is false. hostOut lets a host-level failure take
// precedence over this user's own verdict, the same way BuildSudoOutput
// never lets a later link in the chain hide the actually-first-broken one.
func BuildLoginUserOutput(user, host string, hostOut LoginHostOutput, results []StepResult, rosterAvailable bool, rosterHBACRules, rosterSudoRules []string) LoginUserOutput {
	find := func(id string) (StepResult, bool) {
		for _, r := range results {
			if r.Step.ID == id {
				return r, true
			}
		}
		return StepResult{}, false
	}
	out := LoginUserOutput{User: user}
	if rosterAvailable {
		out.RosterHBACRules = rosterHBACRules
		out.RosterSudoRules = rosterSudoRules
		out.RosterHBACAuthorized = len(rosterHBACRules) > 0
		out.RosterSudoAuthorized = len(rosterSudoRules) > 0
	}

	if r, ok := find("getent-passwd:" + user); ok && r.Result.RunErr == nil {
		out.AccountResolvesViaSSSD = r.Result.RC == 0
		out.PasswdEntry = strings.TrimSpace(r.Result.Stdout)
	}
	if r, ok := find("sudo-l:" + user); ok && r.Result.RunErr == nil {
		out.CentralSudoRuleGrantsAccess = r.Result.RC == 0
	}

	switch {
	case !hostOut.SssdActive || !hostOut.HasKerberosMachineIdentity:
		out.Verdict = fmt.Sprintf("a host-level failure blocks every user, including %q — see the host verdict", user)
	case !out.AccountResolvesViaSSSD:
		out.Verdict = fmt.Sprintf("sssd cannot resolve user %q on this host (getent passwd found nothing) — the account doesn't exist here or sssd's cache is stale", user)
	case rosterAvailable && out.RosterSudoAuthorized && !out.CentralSudoRuleGrantsAccess:
		out.Verdict = fmt.Sprintf("roster declares a sudo rule for %q on this host, but live `sudo -l -U` reports none — the rule likely hasn't reconciled onto this host yet", user)
	case rosterAvailable && !out.RosterSudoAuthorized && out.CentralSudoRuleGrantsAccess:
		out.Verdict = fmt.Sprintf("%q has a live sudo rule on this host that the roster does not declare — likely manually configured, or a roster rule removed but never reconciled off this host", user)
	case rosterAvailable && !out.RosterHBACAuthorized:
		out.Verdict = fmt.Sprintf("account resolves and sudo access matches the roster, but no roster HBAC rule authorizes %q on this host — login may still be denied at the PAM/HBAC layer even though the account is visible via NSS", user)
	case rosterAvailable:
		out.Verdict = fmt.Sprintf("%q: account resolves and roster HBAC/sudo declarations agree with live sudo state — no config/live drift detected", user)
	default:
		out.Verdict = fmt.Sprintf("%q: account resolves and live sudo state is as shown above — roster was unavailable, so this could not be cross-checked against declared HBAC/sudo intent", user)
	}
	return out
}

// LoginSecurityLogsQuery composes the LogQL query pilot_diagnose_login
// runs for its recent-SSH/PAM-login-records section: SecurityLogsQuery's
// same job="pilot-siem" + host content-filter, extended with a regex
// alternation across every user so one query call covers all of them —
// chaining users with LogQL's line-filter AND (like SecurityLogsQuery
// does for host+search) would wrongly require every username to appear
// in the same line, which is not what "any of these users' login
// activity" means. Each user is regexp.QuoteMeta-escaped defensively,
// though inventory.ValidRosterUserName's charset never actually produces
// a regex metacharacter besides a literal '.'.
func LoginSecurityLogsQuery(host string, users []string) string {
	query := SecurityLogsQuery(host, "")
	if len(users) == 0 {
		return query
	}
	parts := make([]string, len(users))
	for i, u := range users {
		parts[i] = regexp.QuoteMeta(u)
	}
	return query + ` |~ "` + strings.Join(parts, "|") + `"`
}
