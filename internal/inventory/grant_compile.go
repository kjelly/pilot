// grant_compile.go implements spec.md §9 (temporary_grant -> managed HBAC
// rule) and §10 (sudo_grant -> managed sudo rule with native
// sudoNotBefore/sudoNotAfter). Both compilers are pure functions: they
// decide what a grant's managed FreeIPA rule should look like right now,
// given an already-evaluated GrantLifecycleState, but perform no I/O and
// make no ipa/ansible calls themselves — see cmd/pilot/cmd/access_cli.go
// for the command that feeds their output into an actual apply run.
//
// Callers MUST run ValidateRoster (checkGrants) first; these compilers
// trust the grant is already a structurally valid temporary_grant/
// sudo_grant and do not re-validate it.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// CompiledHBACRule is one managed HBAC rule a temporary_grant compiles to
// (spec.md §9). Its field shape deliberately mirrors the
// ipa_hbac_rules fact list playbooks/apply/freeipa-identity-apply.yml's
// "Normalize canonical HBAC rules" block already builds from hbac.rules
// entries — not a new shape — so that block's entire existing
// create/attach/detach/enable-disable reconcile logic applies to compiled
// grants for free once appended to the same list.
type CompiledHBACRule struct {
	Name       string
	Users      []string
	Groups     []string
	Hosts      []string
	Hostgroups []string
	Services   []string
	// Enabled mirrors HBAC's own enabled/disabled flag, pilot's stand-in
	// for HBAC's lack of native per-rule expiry (§9).
	Enabled bool
	// Present reports whether this grant's compiled rule should exist in
	// FreeIPA at all right now. false only when the grant's own `state` is
	// absent — a caller reconciling MUST prune (hbacrule-del) any
	// previously-compiled rule whose grant is now Present == false, per
	// §9's `absent -> absent` row. Pilot may safely delete these specific
	// rules (never a user-authored hbac.rules entry) because their name is
	// entirely pilot's own deterministic namespace (CompiledLoginRuleName).
	Present bool
}

// CompiledSudoRule is one managed sudo rule a sudo_grant compiles to
// (spec.md §10), mirroring the ipa_sudo_rules fact shape the same way
// CompiledHBACRule mirrors ipa_hbac_rules. Unlike HBAC, FreeIPA sudo rules
// have no enable/disable toggle this codebase's playbook wires up — sudo's
// own native SudoNotBefore/SudoNotAfter attributes are what enforce the
// time window, so there is no Enabled field here: Present is the only
// lifecycle-driven flag, and it stays true across pending/active/expired
// (only an explicit grant `state: absent` clears it) — FreeIPA/SSSD itself
// denies access outside [SudoNotBefore, SudoNotAfter).
type CompiledSudoRule struct {
	Name               string
	Users              []string
	Groups             []string
	Hosts              []string
	Hostgroups         []string
	AllowCommands      []string
	AllowCommandGroups []string
	// CommandCategory is "all" when neither AllowCommands nor
	// AllowCommandGroups is set — the same cmdcat: all default hand-
	// authored sudo.rules already fall back to (roster_validate.go's
	// checkSudo / the "Normalize canonical sudo rules" Jinja block) — and
	// left empty whenever specific commands/groups ARE set, since FreeIPA
	// rejects combining a category with specific members.
	CommandCategory string
	RunAsUsers      []string
	RunAsGroups     []string
	Options         []string
	// SudoNotBefore/SudoNotAfter are LDAP generalized-time strings
	// (GeneralizedTime), always both set for a Present rule.
	SudoNotBefore string
	SudoNotAfter  string
	Present       bool
}

var grantNameSanitizeRe = regexp.MustCompile(`[^a-z0-9-]+`)

// sanitizeGrantName lowercases name and collapses any run of characters
// outside [a-z0-9-] into a single '-', trimming leading/trailing '-' —
// the "sanitized-name" half of the pilot-grant-login-<sanitized-name>-
// <short-hash> naming spec.md §9 specifies.
func sanitizeGrantName(name string) string {
	return strings.Trim(grantNameSanitizeRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// shortHash returns an 8-hex-character deterministic fingerprint of name,
// so two grant names that sanitize to the same string (e.g. "Vendor X" and
// "vendor_x") still compile to distinct, stable managed rule names.
func shortHash(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])[:8]
}

// CompiledLoginRuleName returns the deterministic managed HBAC rule name
// for the temporary_grant named grantName (§9). The "login" wording is
// intentionally independent of the schema's `kind: temporary_grant` value
// — it is a human-readable HBAC-rule-naming convention, not a schema echo.
func CompiledLoginRuleName(grantName string) string {
	return fmt.Sprintf("pilot-grant-login-%s-%s", sanitizeGrantName(grantName), shortHash(grantName))
}

// CompiledSudoRuleName returns the deterministic managed sudo rule name
// for the sudo_grant named grantName (§10).
func CompiledSudoRuleName(grantName string) string {
	return fmt.Sprintf("pilot-grant-sudo-%s-%s", sanitizeGrantName(grantName), shortHash(grantName))
}

// GeneralizedTime formats t as an LDAP/FreeIPA generalized-time string
// (YYYYMMDDHHMMSSZ), the wire format sudoNotBefore/sudoNotAfter require
// (§10). t is converted to UTC first, matching §8's UTC-comparison rule.
func GeneralizedTime(t time.Time) string {
	return t.UTC().Format("20060102150405") + "Z"
}

// CompileTemporaryGrant compiles a single kind: temporary_grant roster
// entry into its managed HBAC rule (§9), given its already-evaluated
// lifecycle state. Both "pending" and "expired" compile to a Present,
// disabled rule rather than an absent one — spec.md §9 permits either for
// "pending"; picking the same disabled-not-absent treatment for both
// avoids repeated hbacrule-add/-del churn as a grant's window approaches
// and passes, at the cost of a dormant rule existing slightly early/late.
func CompileTemporaryGrant(grant map[string]any, lifecycle GrantLifecycleState) CompiledHBACRule {
	subjects := mapField(grant, "subjects")
	targets := mapField(grant, "targets")
	rule := CompiledHBACRule{
		Name:       CompiledLoginRuleName(stringField(grant, "name")),
		Users:      stringListField(subjects, "users"),
		Groups:     stringListField(subjects, "groups"),
		Hosts:      stringListField(targets, "hosts"),
		Hostgroups: stringListField(targets, "hostgroups"),
		Services:   stringListField(grant, "services"),
	}
	switch lifecycle {
	case GrantActive:
		rule.Present, rule.Enabled = true, true
	case GrantPending, GrantExpired:
		rule.Present, rule.Enabled = true, false
	case GrantAbsent:
		rule.Present, rule.Enabled = false, false
	}
	return rule
}

// CompileSudoGrant compiles a single kind: sudo_grant roster entry into
// its managed sudo rule (§10). lifecycle only ever gates Present here (via
// GrantAbsent) — see CompiledSudoRule's doc comment for why pending/active/
// expired all compile to the same Present=true rule, relying on FreeIPA's
// own native sudoNotBefore/sudoNotAfter enforcement instead of a pilot-side
// enable/disable simulation.
func CompileSudoGrant(grant map[string]any, lifecycle GrantLifecycleState, validity GrantValidity) CompiledSudoRule {
	subjects := mapField(grant, "subjects")
	targets := mapField(grant, "targets")
	privilege := mapField(grant, "privilege")
	runAs := mapField(grant, "run_as")
	rule := CompiledSudoRule{
		Name:               CompiledSudoRuleName(stringField(grant, "name")),
		Users:              stringListField(subjects, "users"),
		Groups:             stringListField(subjects, "groups"),
		Hosts:              stringListField(targets, "hosts"),
		Hostgroups:         stringListField(targets, "hostgroups"),
		AllowCommands:      stringListField(privilege, "commands"),
		AllowCommandGroups: stringListField(privilege, "command_groups"),
		RunAsUsers:         stringListField(runAs, "users"),
		RunAsGroups:        stringListField(runAs, "groups"),
		Options:            stringListField(grant, "options"),
		Present:            lifecycle != GrantAbsent,
	}
	if len(rule.AllowCommands)+len(rule.AllowCommandGroups) == 0 {
		rule.CommandCategory = "all"
	}
	if rule.Present {
		// validity.not_before is OPTIONAL (§7). Leaving SudoNotBefore
		// empty when unset — rather than defaulting it to "now" — is what
		// keeps repeated reconcile idempotent (§19): "now" changes on
		// every run, which would make the compiled rule differ from the
		// previous run's every single time. An empty SudoNotBefore means
		// "no lower bound", which is also FreeIPA's own default absent
		// that attribute — semantically identical to omitting not_before.
		if !validity.NotBefore.IsZero() {
			rule.SudoNotBefore = GeneralizedTime(validity.NotBefore)
		}
		rule.SudoNotAfter = GeneralizedTime(validity.NotAfter)
	}
	return rule
}

// CompileGrants walks root's grants[] and compiles every temporary_grant
// and sudo_grant entry against now (spec.md §18 step 9). kind: breakglass
// entries are intentionally skipped here — a breakglass definition never
// compiles to a standing rule; it only produces one via runtime activation
// (§14, Phase 3), a separate code path from this reconcile pass. Callers
// MUST have already run ValidateRoster (checkGrants) on root.
func CompileGrants(root map[string]any, now time.Time) (hbacRules []CompiledHBACRule, sudoRules []CompiledSudoRule, err error) {
	for _, raw := range listField(root, "grants") {
		grant := asMap(raw)
		kind := stringField(grant, "kind")
		if kind != grantKindTemporary && kind != grantKindSudo {
			continue
		}

		state := stateOrDefault(grant, "present")
		var validity GrantValidity
		if state != "absent" {
			validity, err = ParseGrantValidity(mapField(grant, "validity"))
			if err != nil {
				return nil, nil, fmt.Errorf("grant %q: %w", labelOf(grant), err)
			}
		}
		lifecycle := EvaluateGrantLifecycle(state, validity, now)

		switch kind {
		case grantKindTemporary:
			hbacRules = append(hbacRules, CompileTemporaryGrant(grant, lifecycle))
		case grantKindSudo:
			sudoRules = append(sudoRules, CompileSudoGrant(grant, lifecycle, validity))
		}
	}
	return hbacRules, sudoRules, nil
}

// CompileGrantsFile is CompileGrants' file-reading counterpart, mirroring
// RosterUserNames' read/parse/dispatch shape (roster.go). Callers still
// MUST validate the roster (ValidateRosterFile) before relying on this —
// it does not re-validate.
func CompileGrantsFile(path string, now time.Time) (hbacRules []CompiledHBACRule, sudoRules []CompiledSudoRule, err error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, nil, err
	}
	return CompileGrants(root, now)
}
