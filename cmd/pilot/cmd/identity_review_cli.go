// identity_review_cli.go implements spec.md v3.2 §11's "explicit
// review-mark operation MAY be provided": `pilot identity review list`
// is a pure, read-only report of every review-tracked credential_policy's
// current/due/overdue state (internal/inventory.EvaluateCredentialReviewStatuses);
// `pilot identity review mark` updates one policy's review.last_reviewed_at/
// reviewed_by (internal/inventory.MarkCredentialPolicyReviewedFile).
// Mirrors `pilot access review` (v3.1 §14) exactly — same report-only
// posture, same "mark only updates an existing opt-in policy" contract.
package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/inventory"
)

var (
	identityReviewListFormat            string
	identityReviewListVaultPasswordFile string

	identityReviewMarkReviewer          string
	identityReviewMarkReason            string
	identityReviewMarkVaultPasswordFile string
)

var identityReviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Inspect and mark credential_policy recertification (report-only, spec.md v3.2 §11)",
}

var identityReviewListCmd = &cobra.Command{
	Use:   "list <roster-file>",
	Short: "Report every review-tracked credential_policy's current/due/overdue state",
	Long: `pilot identity review list evaluates every credential_policies[]
entry that declares a review: block (opt-in — a policy with no review:
block is not listed) and reports current/due/overdue against the real
clock. Observability only: no automatic consequence ever follows from an
overdue review (§11).`,
	Args: cobra.ExactArgs(1),
	RunE: runIdentityReviewListCmd,
}

var identityReviewMarkCmd = &cobra.Command{
	Use:   "mark <roster-file> <credential-policy>",
	Short: "Record an explicit review of one credential_policy",
	Long: `pilot identity review mark updates the named credential_policy's
review.last_reviewed_at (to now) and review.reviewed_by (to --reviewer) in
the roster. The policy must already declare a review: block — this
command never enrolls a policy into review on its own. --reviewer is
recorded metadata, not an Approval receipt (§11).`,
	Args: cobra.ExactArgs(2),
	RunE: runIdentityReviewMarkCmd,
}

func init() {
	identityReviewListCmd.Flags().StringVar(&identityReviewListFormat, "format", "table", "output format: table|json")
	identityReviewListCmd.Flags().StringVar(&identityReviewListVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")

	identityReviewMarkCmd.Flags().StringVar(&identityReviewMarkReviewer, "reviewer", "", "who performed this review (required)")
	identityReviewMarkCmd.Flags().StringVar(&identityReviewMarkReason, "reason", "", "why the credential_policy remains required (recorded in the audit trail, not the roster)")
	identityReviewMarkCmd.Flags().StringVar(&identityReviewMarkVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")

	identityReviewCmd.AddCommand(identityReviewListCmd)
	identityReviewCmd.AddCommand(identityReviewMarkCmd)
	identityCmd.AddCommand(identityReviewCmd)
}

func runIdentityReviewListCmd(cmd *cobra.Command, args []string) error {
	if identityReviewListFormat != "table" && identityReviewListFormat != "json" {
		return fmt.Errorf("--format must be table or json, got %q", identityReviewListFormat)
	}
	path := args[0]
	readPath, cleanup, err := resolveGrantsReadPath(path, identityReviewListVaultPasswordFile)
	if err != nil {
		return err
	}
	defer cleanup()

	violations, err := inventory.ValidateRosterFile(readPath)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(cmd.OutOrStdout(), v.String())
		}
		return fmt.Errorf("%d roster issue(s) found; fix them before checking review status", len(violations))
	}

	statuses, err := inventory.EvaluateCredentialReviewStatusesFile(readPath, time.Now())
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if identityReviewListFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(statuses)
	}
	if len(statuses) == 0 {
		fmt.Fprintln(out, "no review-tracked credential_policies")
		return nil
	}
	for _, s := range statuses {
		last := "never"
		if s.LastReviewedAt != nil {
			last = s.LastReviewedAt.Format(time.RFC3339)
		}
		reviewedBy := s.ReviewedBy
		if reviewedBy == "" {
			reviewedBy = "n/a"
		}
		fmt.Fprintf(out, "%s\tstate=%s\tinterval=%s\tlast_reviewed_at=%s\treviewed_by=%s\n", s.PolicyName, s.State, s.Interval, last, reviewedBy)
	}
	return nil
}

func runIdentityReviewMarkCmd(cmd *cobra.Command, args []string) error {
	if identityReviewMarkReviewer == "" {
		return fmt.Errorf("--reviewer is required")
	}
	path, policyName := args[0], args[1]

	// review is roster-persistent state (not a live FreeIPA read), so —
	// unlike the read-only commands above — this deliberately does NOT
	// route through resolveGrantsReadPath's decrypt-to-a-throwaway-temp-
	// file convention: the mutation must land back on the real roster.
	violations, err := inventory.ValidateRosterFile(path)
	if err != nil && err != inventory.ErrRosterEncrypted {
		return err
	}
	if err == nil && len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(cmd.OutOrStdout(), v.String())
		}
		return fmt.Errorf("%d roster issue(s) found; fix them before marking a review", len(violations))
	}

	now := time.Now()
	if err := inventory.MarkCredentialPolicyReviewedFile(path, identityReviewMarkVaultPasswordFile, policyName, identityReviewMarkReviewer, now); err != nil {
		return err
	}

	if stateDir := resolveDataDir(); stateDir != "" {
		if auditErr := accessgrants.AppendAuditEvent(stateDir, accessgrants.AccessAuditEvent{
			Action:     accessgrants.AuditActionAccessReviewMarked,
			SourceKind: "credential_policy",
			Resource:   policyName,
			Actor:      identityReviewMarkReviewer,
			Reason:     identityReviewMarkReason,
			Outcome:    "success",
		}); auditErr != nil {
			return fmt.Errorf("review marked but recording the audit event failed: %w", auditErr)
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "marked %q reviewed by %s at %s\n", policyName, identityReviewMarkReviewer, now.UTC().Format(time.RFC3339))
	return nil
}
