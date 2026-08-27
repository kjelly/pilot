// credential_policy_review_mark.go implements spec.md v3.2 §11's
// "explicit review-mark operation MAY be provided" — `pilot identity
// review mark`. Mirrors review.go's MarkGrantReviewedFile (v3.1 §14)
// exactly, targeting credential_policies[] instead of grants[]: mark only
// updates an existing opt-in review: block, never silently enrolls a
// policy into review, and reviewed_by remains audit metadata only, never
// Approval proof (§11).
package inventory

import (
	"errors"
	"fmt"
	"time"
)

// markCredentialPolicyReviewedPlaintext is MarkCredentialPolicyReviewedFile's
// non-vault half: path MUST already be plaintext YAML.
func markCredentialPolicyReviewedPlaintext(path, name, reviewedBy string, now time.Time) error {
	policy, found, err := RosterCredentialPolicy(path, name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("credential_policy %q not found", name)
	}
	if stateOrDefault(policy, "present") == "absent" {
		return fmt.Errorf("credential_policy %q is state: absent; nothing to review", name)
	}
	reviewRaw, hasReview := policy["review"]
	if !hasReview {
		return fmt.Errorf("credential_policy %q has no review policy declared — review.interval must already be set in the roster before it can be marked reviewed", name)
	}

	updatedReview := map[string]any{}
	for k, v := range asMap(reviewRaw) {
		updatedReview[k] = v
	}
	updatedReview["last_reviewed_at"] = now.UTC().Format(time.RFC3339)
	updatedReview["reviewed_by"] = reviewedBy

	updated := map[string]any{}
	for k, v := range policy {
		updated[k] = v
	}
	updated["review"] = updatedReview

	violations, _, err := simulateSetRosterNested(path, "credential_policies", name, updated, "credential_policy")
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		return fmt.Errorf("marking credential_policy %q as reviewed would fail roster validation: %v", name, violations)
	}
	return replaceTopLevelRosterEntry(path, "credential_policies", name, updated)
}

// MarkCredentialPolicyReviewedFile updates the named credential_policies[]
// entry's review.last_reviewed_at (to now, UTC RFC3339) and
// review.reviewed_by (to reviewedBy) in the roster at path — plaintext or
// ansible-vault encrypted, given vaultPasswordFile. It is an error to mark
// a policy that doesn't exist, is state: absent, or has no review: block
// already declared.
func MarkCredentialPolicyReviewedFile(path, vaultPasswordFile, name, reviewedBy string, now time.Time) error {
	if reviewedBy == "" {
		return fmt.Errorf("reviewedBy is required")
	}
	err := markCredentialPolicyReviewedPlaintext(path, name, reviewedBy, now)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrRosterEncrypted) {
		return err
	}
	if vaultPasswordFile == "" {
		return fmt.Errorf("%s is ansible-vault encrypted; pass a vault password file", path)
	}
	return MutateEncryptedRosterFile(path, vaultPasswordFile, func(plaintextPath string) error {
		return markCredentialPolicyReviewedPlaintext(plaintextPath, name, reviewedBy, now)
	})
}
