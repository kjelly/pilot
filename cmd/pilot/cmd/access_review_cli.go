// access_review_cli.go implements spec.md v3.1 §14's CLI surface:
// `pilot access review list` is a pure, read-only report of every
// review-tracked grant's current/due/overdue state
// (internal/inventory.EvaluateReviewStatuses — no FreeIPA call, no
// mutation); `pilot access review mark` updates one grant's
// review.last_reviewed_at/reviewed_by in the roster
// (internal/inventory.MarkGrantReviewedFile). Neither command enforces
// anything — review is report-only metadata (§14.2): there is no
// on_overdue: suspend, and the roster schema itself has no field for it
// (see roster_grants.go's checkGrantReview).
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
	accessReviewListFormat            string
	accessReviewListVaultPasswordFile string

	accessReviewMarkReviewer          string
	accessReviewMarkReason            string
	accessReviewMarkVaultPasswordFile string
)

var accessReviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Inspect and mark grant recertification (report-only, spec.md v3.1 §14)",
}

var accessReviewListCmd = &cobra.Command{
	Use:   "list <roster-file>",
	Short: "Report every review-tracked grant's current/due/overdue state",
	Long: `pilot access review list evaluates every grants[] entry that
declares a review: block (opt-in — a grant with no review: block is not
listed) and reports current/due/overdue against the real clock. This is
observability only: no grant is ever automatically suspended (§14.2).`,
	Args: cobra.ExactArgs(1),
	RunE: runAccessReviewListCmd,
}

var accessReviewMarkCmd = &cobra.Command{
	Use:   "mark <roster-file> <grant>",
	Short: "Record an explicit review of one grant",
	Long: `pilot access review mark updates the named grant's
review.last_reviewed_at (to now) and review.reviewed_by (to --reviewer)
in the roster. The grant must already declare a review: block — this
command never enrolls a grant into review on its own. --reviewer is
recorded metadata, not an Approval receipt (§14.3).`,
	Args: cobra.ExactArgs(2),
	RunE: runAccessReviewMarkCmd,
}

func init() {
	accessReviewListCmd.Flags().StringVar(&accessReviewListFormat, "format", "table", "output format: table|json")
	accessReviewListCmd.Flags().StringVar(&accessReviewListVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")

	accessReviewMarkCmd.Flags().StringVar(&accessReviewMarkReviewer, "reviewer", "", "who performed this review (required)")
	accessReviewMarkCmd.Flags().StringVar(&accessReviewMarkReason, "reason", "", "why the grant remains required (recorded in the audit trail, not the roster)")
	accessReviewMarkCmd.Flags().StringVar(&accessReviewMarkVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")

	accessReviewCmd.AddCommand(accessReviewListCmd)
	accessReviewCmd.AddCommand(accessReviewMarkCmd)
	accessCmd.AddCommand(accessReviewCmd)
}

func runAccessReviewListCmd(cmd *cobra.Command, args []string) error {
	if accessReviewListFormat != "table" && accessReviewListFormat != "json" {
		return fmt.Errorf("--format must be table or json, got %q", accessReviewListFormat)
	}
	path := args[0]
	readPath, cleanup, err := resolveGrantsReadPath(path, accessReviewListVaultPasswordFile)
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

	statuses, err := inventory.EvaluateReviewStatusesFile(readPath, time.Now())
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if accessReviewListFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(statuses)
	}
	if len(statuses) == 0 {
		fmt.Fprintln(out, "no review-tracked grants")
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
		fmt.Fprintf(out, "%s\tkind=%s\tstate=%s\tinterval=%s\tlast_reviewed_at=%s\treviewed_by=%s\n", s.Name, s.Kind, s.State, s.Interval, last, reviewedBy)
	}
	return nil
}

func runAccessReviewMarkCmd(cmd *cobra.Command, args []string) error {
	if accessReviewMarkReviewer == "" {
		return fmt.Errorf("--reviewer is required")
	}
	path, grantName := args[0], args[1]

	// review is roster-persistent state (not a live FreeIPA read), so —
	// unlike the read-only commands above — this deliberately does NOT
	// route through resolveGrantsReadPath's decrypt-to-a-throwaway-temp-
	// file convention: the mutation must land back on the real roster
	// (plaintext or re-encrypted in place), which
	// inventory.MarkGrantReviewedFile already handles itself.
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
	if err := inventory.MarkGrantReviewedFile(path, accessReviewMarkVaultPasswordFile, grantName, accessReviewMarkReviewer, now); err != nil {
		return err
	}

	if stateDir := resolveDataDir(); stateDir != "" {
		if auditErr := accessgrants.AppendAuditEvent(stateDir, accessgrants.AccessAuditEvent{
			Action:     accessgrants.AuditActionAccessReviewMarked,
			SourceKind: "temporary_grant,sudo_grant",
			Resource:   grantName,
			Actor:      accessReviewMarkReviewer,
			Reason:     accessReviewMarkReason,
			Outcome:    "success",
		}); auditErr != nil {
			return fmt.Errorf("review marked but recording the audit event failed: %w", auditErr)
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "marked %q reviewed by %s at %s\n", grantName, accessReviewMarkReviewer, now.UTC().Format(time.RFC3339))
	return nil
}
