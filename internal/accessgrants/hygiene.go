// hygiene.go implements spec.md v3.2 §14's one-shot identity hygiene
// report: `pilot identity hygiene <roster-file>`. It is read-only end to
// end — every evaluator behind it (Phases 2-4's checkers, Phase 1's
// capability probe) only inspects roster/live state, and the only write
// side effect is an audit-trail entry (§15) when StateDir is set.
package accessgrants

import (
	"context"
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/freeipa"
	"github.com/kjelly/pilot/internal/inventory"
)

// UserHygiene is one user's row in HygieneReport.Users — spec.md §14's
// example JSON shape (name/privileged/auth_compliance/
// ssh_key_compliance/credential_review).
type UserHygiene struct {
	Name       string `json:"name"`
	Privileged bool   `json:"privileged"`
	// AuthCompliance is "pass"/"fail" only when Privileged (checked
	// against security.privileged_identity.require) — "n/a" for a
	// non-privileged user, who has no strong-auth baseline to meet.
	AuthCompliance string `json:"auth_compliance"`
	// SSHKeyCompliance is "pass"/"fail" only when at least one
	// credential_policy's match covers this user — "n/a" when no policy
	// covers them at all (there is nothing to be compliant WITH).
	SSHKeyCompliance string `json:"ssh_key_compliance"`
	// CredentialReview is the worst (most urgent) review state across
	// every credential_policy covering this user that declares a
	// review: block — "n/a" when no covering policy declares one.
	CredentialReview string `json:"credential_review"`
}

// HygieneReport is spec.md §14's one-shot identity hygiene report.
type HygieneReport struct {
	EvaluatedAt time.Time     `json:"evaluated_at"`
	Users       []UserHygiene `json:"users"`

	Capabilities freeipa.FreeIPACapabilities `json:"capabilities"`
	// CapabilityError is set when the live capability probe itself
	// failed — Capabilities is then all-unknown, not fabricated
	// supported/unsupported. Hygiene still reports everything else it
	// could determine from the roster alone rather than failing the
	// whole report over an unreachable FreeIPA target.
	CapabilityError string `json:"capability_error,omitempty"`

	PrivilegedIdentityViolations []inventory.PrivilegedIdentityViolation `json:"privileged_identity_violations,omitempty"`
	SSHFindings                  []inventory.SSHHygieneFinding           `json:"ssh_findings,omitempty"`
	CredentialReviews            []inventory.CredentialReviewStatus      `json:"credential_reviews,omitempty"`

	// StaleAccountStatus is always "unsupported": this delivery has no
	// reliable source of FreeIPA last-login/activity data. spec.md §12:
	// "If reliable data is unavailable: status = unsupported. Do not
	// invent last-login from unrelated LDAP timestamps" — so this is
	// reported honestly rather than guessed at.
	StaleAccountStatus string `json:"stale_account_status"`
}

// HygieneOptions configures a single EvaluateIdentityHygiene run.
type HygieneOptions struct {
	// RosterFile is required. MUST have already passed
	// inventory.ValidateRosterFile.
	RosterFile string

	// Inventory/VaultPasswordFile/TargetGroup configure the live
	// capability probe (Phase 1). Inventory is required for the probe to
	// run at all — when empty, hygiene still produces every roster-only
	// finding, with Capabilities left all-unknown and CapabilityError
	// explaining why.
	Inventory         string
	VaultPasswordFile string
	TargetGroup       string

	// Now is the injected clock credential review classification
	// evaluates against. Zero selects time.Now().
	Now time.Time

	// StateDir enables audit-event recording (§15). Empty skips it.
	StateDir string

	// Runner overrides the ansible.Runner the capability probe uses. nil
	// selects a production ansible.NewRunner().
	Runner playbookRunner
}

// EvaluateIdentityHygiene builds a full HygieneReport for
// opts.RosterFile. It never mutates the roster or FreeIPA.
func EvaluateIdentityHygiene(ctx context.Context, opts HygieneOptions) (HygieneReport, error) {
	if opts.RosterFile == "" {
		return HygieneReport{}, fmt.Errorf("accessgrants: roster file is required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	root, err := inventory.ReadRosterAsMapFile(opts.RosterFile)
	if err != nil {
		return HygieneReport{}, err
	}

	privilegedIdentityViolations := inventory.EvaluatePrivilegedIdentityBaseline(root)
	privilegedUsers := inventory.PrivilegedUsers(root)
	privilegedSet := make(map[string]bool, len(privilegedUsers))
	for _, u := range privilegedUsers {
		privilegedSet[u] = true
	}
	nonCompliant := make(map[string]bool, len(privilegedIdentityViolations))
	for _, v := range privilegedIdentityViolations {
		nonCompliant[v.User] = true
	}

	sshFindings := inventory.EvaluateSSHKeyHygiene(root)
	sshIssueUsers := make(map[string]bool)
	for _, f := range sshFindings {
		// SSHFindingMaxAgeUnknown is purely informational (spec.md §10:
		// max_age is report-only, and "unknown" is the honest answer
		// this delivery always gives, never a guess) — it must NOT
		// count as a compliance failure, or every user covered by any
		// policy that configures max_age would always show "fail" here
		// regardless of their key's actual hygiene. Found live while
		// testing this against a real FreeIPA target (v32alice's
		// otherwise-clean key showed ssh_key_compliance: fail solely
		// because her policy set ssh.max_age).
		if f.User != "" && f.Issue != inventory.SSHFindingMaxAgeUnknown {
			sshIssueUsers[f.User] = true
		}
	}
	coverage := inventory.CredentialPolicyCoverage(root)
	sshCovered := make(map[string]bool)
	for _, users := range coverage {
		for _, u := range users {
			sshCovered[u] = true
		}
	}

	credentialReviews, err := inventory.EvaluateCredentialReviewStatuses(root, now)
	if err != nil {
		return HygieneReport{}, err
	}
	reviewStateByPolicy := make(map[string]inventory.ReviewState, len(credentialReviews))
	for _, r := range credentialReviews {
		reviewStateByPolicy[r.PolicyName] = r.State
	}
	worstReviewByUser := make(map[string]inventory.ReviewState)
	for policyName, users := range coverage {
		state, hasReview := reviewStateByPolicy[policyName]
		if !hasReview {
			continue
		}
		for _, u := range users {
			if worse, ok := worstReviewByUser[u]; !ok || reviewStateSeverity(state) > reviewStateSeverity(worse) {
				worstReviewByUser[u] = state
			}
		}
	}

	userNames, err := inventory.RosterUserNames(opts.RosterFile)
	if err != nil {
		return HygieneReport{}, err
	}
	users := make([]UserHygiene, 0, len(userNames))
	for _, name := range userNames {
		u := UserHygiene{Name: name, Privileged: privilegedSet[name], AuthCompliance: "n/a", SSHKeyCompliance: "n/a", CredentialReview: "n/a"}
		if u.Privileged {
			if nonCompliant[name] {
				u.AuthCompliance = "fail"
			} else {
				u.AuthCompliance = "pass"
			}
		}
		if sshCovered[name] {
			if sshIssueUsers[name] {
				u.SSHKeyCompliance = "fail"
			} else {
				u.SSHKeyCompliance = "pass"
			}
		}
		if state, ok := worstReviewByUser[name]; ok {
			u.CredentialReview = string(state)
		}
		users = append(users, u)
	}

	report := HygieneReport{
		EvaluatedAt: now,
		Users:       users,
		// Every control starts CapabilityUnknown, exactly like a failed
		// probe would report (§13) — a caller must never see a blank
		// zero-value CapabilityState here, whether the probe ran and
		// failed or was never attempted at all (Inventory unset).
		Capabilities: freeipa.FreeIPACapabilities{
			GroupPasswordPolicy:     freeipa.CapabilityUnknown,
			PasswordLockoutPolicy:   freeipa.CapabilityUnknown,
			UserAuthTypes:           freeipa.CapabilityUnknown,
			AuthenticationIndicator: freeipa.CapabilityUnknown,
			PrincipalExpiration:     freeipa.CapabilityUnknown,
			SudoNotBeforeAfter:      freeipa.CapabilityUnknown,
		},
		PrivilegedIdentityViolations: privilegedIdentityViolations,
		SSHFindings:                  sshFindings,
		CredentialReviews:            credentialReviews,
		StaleAccountStatus:           "unsupported",
	}
	if opts.Inventory == "" {
		report.CapabilityError = "capability probe skipped: --inventory not set"
	}

	if opts.Inventory != "" {
		caps, capErr := freeipa.ProbeCapabilities(ctx, freeipa.CapabilityProbeOptions{
			Inventory:         opts.Inventory,
			RosterFile:        opts.RosterFile,
			VaultPasswordFile: opts.VaultPasswordFile,
			TargetGroup:       opts.TargetGroup,
			Runner:            opts.Runner,
		})
		report.Capabilities = caps
		if capErr != nil {
			report.CapabilityError = capErr.Error()
		}
	}

	if opts.StateDir != "" {
		if auditErr := AppendAuditEvent(opts.StateDir, AccessAuditEvent{
			Action:     AuditActionIdentityHygieneRun,
			SourceKind: "password_policy,user_auth_type,privileged_identity,credential_policy",
			Resource:   opts.RosterFile,
			Outcome:    "success",
			Reason:     fmt.Sprintf("%d user(s) evaluated, %d privileged-identity violation(s), %d SSH finding(s)", len(users), len(privilegedIdentityViolations), len(sshFindings)),
		}); auditErr != nil {
			return report, fmt.Errorf("accessgrants: hygiene evaluated but recording the audit event failed: %w", auditErr)
		}
	}

	return report, nil
}

// reviewStateSeverity ranks ReviewState for "worst across every policy
// covering this user" — overdue is the most urgent, current the least.
func reviewStateSeverity(s inventory.ReviewState) int {
	switch s {
	case inventory.ReviewOverdue:
		return 2
	case inventory.ReviewDue:
		return 1
	default:
		return 0
	}
}
