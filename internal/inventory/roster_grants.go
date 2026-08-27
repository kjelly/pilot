// roster_grants.go validates the first-class `grants:` section schema v3
// introduces (see roster_validate.go's ValidateRosterV3), per the HBAC
// simplification spec §27.3 ("Temporary authorization") and §27.5
// ("Explain / inspection") and the v3.0 Core Access Governance spec
// (spec.md) §5a/§6/§7.
//
// Baseline delta from the v2 -> v3 migration's original shipped shape
// (spec.md §5a): `kind` grew a third value, `sudo_grant`, alongside the
// already-shipped `temporary_grant`/`breakglass` — those two names are
// NOT renamed, per spec.md §2's explicit constraint that this extension
// stay additive to what v2 -> v3 migration already shipped. `knownGrantKeys`
// stopped being one flat allow-list and became kind-conditional: every kind
// shares name/kind/state/subjects/targets/services; temporary_grant and
// sudo_grant additionally require validity+justification; sudo_grant alone
// also allows privilege/run_as/options; breakglass alone also allows
// activation/auth_policy and — this is the fail-closed direction, not an
// allowance — MUST NOT carry validity or justification, because a
// breakglass definition is a template awaiting activation, not an
// already-effective time window (spec.md §6.3).
package inventory

import (
	"fmt"
	"strings"
	"time"
)

const (
	grantKindTemporary  = "temporary_grant"
	grantKindSudo       = "sudo_grant"
	grantKindBreakglass = "breakglass"
)

var (
	knownGrantKinds = []string{grantKindTemporary, grantKindSudo, grantKindBreakglass}

	// grantCommonKeys omits "services" deliberately: sudo_grant has no
	// HBAC-service concept at all (spec.md §6.2's example never lists one),
	// so it is added individually below only for the two HBAC-flavored
	// kinds (temporary_grant, breakglass).
	grantCommonKeys      = []string{"name", "kind", "state", "subjects", "targets"}
	knownGrantKeysByKind = map[string][]string{
		// "review" (v3.1 §14) is optional recertification metadata/
		// reporting — allowed on the two validity-bearing kinds only.
		// breakglass has no ongoing validity window to recertify (§6.3):
		// its access question is "is it currently activated", answered by
		// runtime activation state, not a roster-declared review cadence.
		grantKindTemporary:  append(append([]string{}, grantCommonKeys...), "services", "validity", "justification", "review"),
		grantKindSudo:       append(append([]string{}, grantCommonKeys...), "validity", "justification", "privilege", "run_as", "options", "review"),
		grantKindBreakglass: append(append([]string{}, grantCommonKeys...), "services", "activation", "auth_policy"),
	}
	// knownGrantKeysUnion is used only when kind itself is invalid, so an
	// unrecognized kind doesn't also drown the report in spurious "unknown
	// field" noise for fields that would have been legal under some kind.
	knownGrantKeysUnion = unionStrings(knownGrantKeysByKind[grantKindTemporary], knownGrantKeysByKind[grantKindSudo], knownGrantKeysByKind[grantKindBreakglass])

	knownJustificationKeys = []string{"reason", "ticket", "requested_by"}
	knownActivationKeys    = []string{"max_duration", "require_reason", "require_ticket"}
)

func unionStrings(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// checkGrants validates the grants: list per spec.md §7.
func checkGrants(root map[string]any) []RosterViolation {
	var out []RosterViolation

	groups := listField(root, "groups")
	loginSubjectGroupNames := namesWithCategoryFunc(groups, IsHBACSubjectGroupCategory)
	sudoSubjectGroupNames := namesWithCategoryFunc(groups, IsSudoSubjectGroupCategory)
	allowedUsers := append(namesOf(listField(root, "users")), "admin")
	hostgroupNames := namesOf(listField(root, "hostgroups"))

	names := namesOf(listField(root, "grants"))
	if dupes := findDuplicates(names); len(dupes) > 0 {
		out = append(out, RosterViolation{Rule: "unique grant names", Detail: fmt.Sprintf("duplicate grant name(s): %s", strings.Join(dupes, ", "))})
	}

	for _, raw := range listField(root, "grants") {
		item := asMap(raw)
		label := labelOf(item)

		kind := stringField(item, "kind")
		allowedKeys, kindKnown := knownGrantKeysByKind[kind]
		if !kindKnown {
			out = append(out, RosterViolation{Rule: "grant kind", Detail: fmt.Sprintf("grant %q: kind %q must be one of %s", label, kind, strings.Join(knownGrantKinds, "/"))})
			allowedKeys = knownGrantKeysUnion
		}
		if unk := unknownKeys(item, allowedKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "grant keys", Detail: fmt.Sprintf("grant %q: unknown field(s) %s", label, strings.Join(unk, ", "))})
		}

		state := stateOrDefault(item, "present")
		if state != "present" && state != "absent" {
			out = append(out, RosterViolation{Rule: "grant state", Detail: fmt.Sprintf("grant %q: state %q must be present/absent", label, state)})
		}

		subjects := mapField(item, "subjects")
		subjUsers := stringListField(subjects, "users")
		subjGroups := stringListField(subjects, "groups")
		if len(subjUsers)+len(subjGroups) == 0 {
			out = append(out, RosterViolation{Rule: "grant subjects", Detail: fmt.Sprintf("grant %q: needs at least one subject user or group", label)})
		}
		for _, u := range subjUsers {
			if !contains(allowedUsers, u) {
				out = append(out, RosterViolation{Rule: "grant subject user reference", Detail: fmt.Sprintf("grant %q: subjects.users references unknown user %q", label, u)})
			}
		}

		targets := mapField(item, "targets")
		targetHosts := stringListField(targets, "hosts")
		targetHostgroups := stringListField(targets, "hostgroups")
		if len(targetHosts)+len(targetHostgroups) == 0 {
			out = append(out, RosterViolation{Rule: "grant targets", Detail: fmt.Sprintf("grant %q: needs at least one target host or hostgroup", label)})
		}
		// Per spec.md §7, direct hosts are FQDN-shaped enrolled host
		// names — they do NOT have to also appear in this roster's own
		// top-level `hosts:` list (found live on a vm-target: the
		// existing `checkHBAC` never required that for hbac.rules'
		// direct hosts either, and requiring it here broke a grant
		// targeting the FreeIPA server's own already-enrolled host,
		// which this roster has no reason to redeclare under `hosts:`).
		for _, h := range targetHosts {
			if !ValidRosterHostFQDN(h) {
				out = append(out, RosterViolation{Rule: "grant target host FQDN", Detail: fmt.Sprintf("grant %q: targets.hosts %q must be FQDN-shaped", label, h)})
			}
		}
		for _, hg := range targetHostgroups {
			if !contains(hostgroupNames, hg) {
				out = append(out, RosterViolation{Rule: "grant target hostgroup reference", Detail: fmt.Sprintf("grant %q: targets.hostgroups references unknown hostgroup %q", label, hg)})
			}
		}

		switch kind {
		case grantKindTemporary:
			for _, g := range subjGroups {
				if !contains(loginSubjectGroupNames, g) {
					out = append(out, RosterViolation{Rule: "grant subject group category", Detail: fmt.Sprintf("grant %q: subjects.groups %q must be a group with category team, role, or (legacy) access", label, g)})
				}
			}
			out = append(out, checkGrantServices(item, label)...)
			out = append(out, checkGrantTimedFields(item, label)...)
			out = append(out, checkGrantReview(item, label, allowedUsers)...)
		case grantKindSudo:
			for _, g := range subjGroups {
				if !contains(sudoSubjectGroupNames, g) {
					out = append(out, RosterViolation{Rule: "grant subject group category", Detail: fmt.Sprintf("grant %q: sudo_grant subjects.groups %q must be a group with category: role", label, g)})
				}
			}
			out = append(out, checkGrantTimedFields(item, label)...)
			out = append(out, checkGrantSudoPrivilege(root, item, label)...)
			out = append(out, checkGrantReview(item, label, allowedUsers)...)
		case grantKindBreakglass:
			if len(subjGroups) > 0 {
				out = append(out, RosterViolation{Rule: "grant subject group category", Detail: fmt.Sprintf("grant %q: breakglass subjects.groups must be empty — only direct named users are accepted", label)})
			}
			out = append(out, checkGrantServices(item, label)...)
			out = append(out, checkGrantActivation(item, label)...)
		}
	}

	return out
}

var (
	knownPrivilegeKeys = []string{"commands", "command_groups", "command_category"}
	knownRunAsKeys     = []string{"users", "groups"}
)

// checkGrantSudoPrivilege validates a sudo_grant's privilege/run_as blocks
// (spec.md §6.2/§10), reusing checkSudo's exact command-group-reference and
// command-denylist rules (sudoDenylistBinaryRe/sudoDenylistMetaRe,
// roster_validate.go) rather than a second copy — §10's "Existing sudo
// command denylist and safety validation MUST be reused".
func checkGrantSudoPrivilege(root map[string]any, item map[string]any, label string) []RosterViolation {
	var out []RosterViolation

	privilege := mapField(item, "privilege")
	if unk := unknownKeys(privilege, knownPrivilegeKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "grant privilege keys", Detail: fmt.Sprintf("grant %q: unknown privilege field(s) %s", label, strings.Join(unk, ", "))})
	}
	runAs := mapField(item, "run_as")
	if unk := unknownKeys(runAs, knownRunAsKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "grant run_as keys", Detail: fmt.Sprintf("grant %q: unknown run_as field(s) %s", label, strings.Join(unk, ", "))})
	}

	commandGroupNames := namesOf(listField(mapField(root, "sudo"), "command_groups"))
	commands := stringListField(privilege, "commands")
	commandGroups := stringListField(privilege, "command_groups")
	for _, group := range commandGroups {
		if !contains(commandGroupNames, group) {
			out = append(out, RosterViolation{Rule: "sudo command group reference", Detail: fmt.Sprintf("grant %q references unknown sudo command group %q", label, group)})
		}
	}

	commandCategory := stringField(privilege, "command_category")
	hasSpecific := len(commands)+len(commandGroups) > 0
	if commandCategory != "" && commandCategory != "all" {
		out = append(out, RosterViolation{Rule: "sudo allow command category", Detail: fmt.Sprintf("grant %q: privilege.command_category must be all when set", label)})
	}
	if commandCategory == "all" && hasSpecific {
		out = append(out, RosterViolation{Rule: "sudo allow command category", Detail: fmt.Sprintf("grant %q: privilege.command_category: all can't combine with commands or command_groups", label)})
	}

	for _, cmd := range commands {
		switch {
		case sudoDenylistBinaryRe.MatchString(cmd):
			out = append(out, RosterViolation{Rule: "sudo command denylist", Detail: fmt.Sprintf("grant %q: sudo command %q is a shell-escape binary, not allowed", label, cmd)})
		case sudoDenylistMetaRe.MatchString(cmd):
			out = append(out, RosterViolation{Rule: "sudo command denylist", Detail: fmt.Sprintf("grant %q: sudo command %q contains a shell metacharacter, not allowed", label, cmd)})
		}
	}
	return out
}

// checkGrantServices requires at least one PAM service, mirroring
// checkHBAC's identical "hbac services" rule (roster_validate.go) — a
// temporary_grant or breakglass compiles to an HBAC-shaped rule (§9/§14),
// and an HBAC rule with zero services attached and no servicecat set is a
// dead rule, not a permissive one.
func checkGrantServices(item map[string]any, label string) []RosterViolation {
	if len(stringListField(item, "services")) == 0 {
		return []RosterViolation{{Rule: "grant services", Detail: fmt.Sprintf("grant %q: needs at least one service", label)}}
	}
	return nil
}

// checkGrantTimedFields validates the validity/justification pair every
// temporary_grant and sudo_grant MUST carry (spec.md §7).
func checkGrantTimedFields(item map[string]any, label string) []RosterViolation {
	var out []RosterViolation

	if _, ok := item["validity"]; !ok {
		out = append(out, RosterViolation{Rule: "grant validity", Detail: fmt.Sprintf("grant %q: validity is required", label)})
	} else if _, err := ParseGrantValidity(mapField(item, "validity")); err != nil {
		out = append(out, RosterViolation{Rule: "grant validity", Detail: fmt.Sprintf("grant %q: %v", label, err)})
	}

	justification, hasJustification := item["justification"]
	if !hasJustification {
		out = append(out, RosterViolation{Rule: "grant justification", Detail: fmt.Sprintf("grant %q: justification is required", label)})
	} else {
		j := asMap(justification)
		if unk := unknownKeys(j, knownJustificationKeys); len(unk) > 0 {
			out = append(out, RosterViolation{Rule: "grant justification keys", Detail: fmt.Sprintf("grant %q: unknown justification field(s) %s", label, strings.Join(unk, ", "))})
		}
		if stringField(j, "reason") == "" {
			out = append(out, RosterViolation{Rule: "grant justification reason", Detail: fmt.Sprintf("grant %q: justification.reason is required", label)})
		}
	}

	return out
}

// checkGrantActivation validates a breakglass grant's activation policy
// (spec.md §6.3/§7): max_duration is required and must use the shared
// duration grammar (access_duration.go); require_reason/require_ticket, if
// present, must be booleans (their default of true is applied at
// activation time, not here — see §14).
func checkGrantActivation(item map[string]any, label string) []RosterViolation {
	var out []RosterViolation

	activation, hasActivation := item["activation"]
	if !hasActivation {
		out = append(out, RosterViolation{Rule: "grant activation", Detail: fmt.Sprintf("grant %q: activation is required", label)})
		return out
	}
	a := asMap(activation)
	if unk := unknownKeys(a, knownActivationKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "grant activation keys", Detail: fmt.Sprintf("grant %q: unknown activation field(s) %s", label, strings.Join(unk, ", "))})
	}
	maxDuration := stringField(a, "max_duration")
	if maxDuration == "" {
		out = append(out, RosterViolation{Rule: "grant activation max_duration", Detail: fmt.Sprintf("grant %q: activation.max_duration is required", label)})
	} else if !ValidAccessDuration(maxDuration) {
		out = append(out, RosterViolation{Rule: "grant activation max_duration", Detail: fmt.Sprintf("grant %q: activation.max_duration %q is not a valid duration (e.g. 30m, 1h, 8h, 24h, 7d)", label, maxDuration)})
	}
	for _, key := range []string{"require_reason", "require_ticket"} {
		if v, ok := a[key]; ok {
			if _, isBool := v.(bool); !isBool {
				out = append(out, RosterViolation{Rule: "grant activation flag", Detail: fmt.Sprintf("grant %q: activation.%s must be a boolean", label, key)})
			}
		}
	}
	return out
}

var knownReviewKeys = []string{"interval", "last_reviewed_at", "reviewed_by"}

// checkGrantReview validates an optional review: block (v3.1 §14): review
// is opt-in metadata/reporting, so its absence is never a violation —
// only a malformed one is. interval is required (shared duration grammar,
// access_duration.go); last_reviewed_at, if present, must be RFC3339;
// reviewed_by, if present, must reference a known roster user (same
// pattern as account_policies' sponsor). There is deliberately no
// on_overdue key here at all — v3.1 §14.2 requires automatic-suspension
// semantics to fail closed, and the simplest way to guarantee that is to
// never accept the key in the first place: any roster author who writes
// on_overdue gets the same "unknown field" rejection as a typo, rather
// than a special-cased warning that risks reading as "recognized but
// ignored".
func checkGrantReview(item map[string]any, label string, allowedUsers []string) []RosterViolation {
	var out []RosterViolation

	review, hasReview := item["review"]
	if !hasReview {
		return out
	}
	r := asMap(review)
	if unk := unknownKeys(r, knownReviewKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "grant review keys", Detail: fmt.Sprintf("grant %q: unknown review field(s) %s", label, strings.Join(unk, ", "))})
	}
	interval := stringField(r, "interval")
	if interval == "" {
		out = append(out, RosterViolation{Rule: "grant review interval", Detail: fmt.Sprintf("grant %q: review.interval is required", label)})
	} else if !ValidAccessDuration(interval) {
		out = append(out, RosterViolation{Rule: "grant review interval", Detail: fmt.Sprintf("grant %q: review.interval %q is not a valid duration (e.g. 30d, 90d)", label, interval)})
	}
	if lastReviewedAt := stringField(r, "last_reviewed_at"); lastReviewedAt != "" {
		if _, err := time.Parse(time.RFC3339, lastReviewedAt); err != nil {
			out = append(out, RosterViolation{Rule: "grant review last_reviewed_at", Detail: fmt.Sprintf("grant %q: review.last_reviewed_at %q must be RFC3339: %v", label, lastReviewedAt, err)})
		}
	}
	if reviewedBy := stringField(r, "reviewed_by"); reviewedBy != "" && !contains(allowedUsers, reviewedBy) {
		out = append(out, RosterViolation{Rule: "grant review reviewed_by reference", Detail: fmt.Sprintf("grant %q: review.reviewed_by references unknown roster user %q", label, reviewedBy)})
	}
	return out
}
