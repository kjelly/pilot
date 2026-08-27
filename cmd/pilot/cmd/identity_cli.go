// identity_cli.go implements the v3.2 Identity & Credential Hardening
// spec's (spec.md §14/§15, Phase 5) one-shot CLI surface: `pilot identity
// hygiene`/`pilot identity drift` run once and exit — no recurring loop,
// daemon, or scheduler (spec.md §1's inclusion rule).
package cmd

import "github.com/spf13/cobra"

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "One-shot FreeIPA identity/credential hardening inspection",
	Long: `pilot identity groups v3.2's one-shot identity-hardening reports:

  pilot identity hygiene <roster-file>  -- read-only per-user compliance report
  pilot identity drift <roster-file>    -- compare desired vs live FreeIPA state

Both run once and exit. Neither ever starts a background process — see
spec.md v3.2 §1's explicit non-goal. Password policies, user
authentication types, and privileged-identity baseline enforcement
already run through the existing 'pilot access reconcile'/'pilot access
drift' commands (the same compiled-plan/apply-playbook machinery this
package builds on) — this command group is the read-only reporting layer
on top of that, not a separate apply path.`,
}

func init() {
	rootCmd.AddCommand(identityCmd)
}
