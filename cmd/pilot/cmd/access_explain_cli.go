// access_explain_cli.go implements `pilot access explain` (spec.md §16,
// Phase 3): a read-only report of every source (static HBAC, temporary_
// grant, sudo_grant, breakglass) that currently grants a given
// (user, host, service). It never queries live FreeIPA — see
// internal/accessgrants/explain.go's header comment.
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
	accessExplainUser              string
	accessExplainHost              string
	accessExplainService           string
	accessExplainFormat            string
	accessExplainVaultPasswordFile string
)

var accessExplainCmd = &cobra.Command{
	Use:   "explain <roster-file>",
	Short: "Show every source that currently grants a user access to a host/service",
	Long: `pilot access explain reports every static HBAC rule and every
active temporary_grant/sudo_grant/breakglass activation that currently
grants (--user, --host, --service) — preserving real provenance (which
rule, direct hit or group path) rather than collapsing everything into a
single access-* concept (spec.md §16).`,
	Args: cobra.ExactArgs(1),
	RunE: runAccessExplainCmd,
}

func init() {
	accessExplainCmd.Flags().StringVar(&accessExplainUser, "user", "", "user to explain (required)")
	accessExplainCmd.Flags().StringVar(&accessExplainHost, "host", "", "host to explain (required)")
	accessExplainCmd.Flags().StringVar(&accessExplainService, "service", "", "PAM service to explain (required for HBAC/temporary_grant/breakglass sources; ignored for sudo_grant, which has no service concept)")
	accessExplainCmd.Flags().StringVar(&accessExplainFormat, "format", "table", "output format: table|json")
	accessExplainCmd.Flags().StringVar(&accessExplainVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, for an encrypted roster")
	accessCmd.AddCommand(accessExplainCmd)
}

func runAccessExplainCmd(cmd *cobra.Command, args []string) error {
	rosterPath := args[0]
	if accessExplainUser == "" || accessExplainHost == "" {
		return fmt.Errorf("--user and --host are both required")
	}
	readPath, cleanup, err := resolveGrantsReadPath(rosterPath, accessExplainVaultPasswordFile)
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
		return fmt.Errorf("%d roster issue(s) found; fix them before explaining access", len(violations))
	}

	sources, err := accessgrants.Explain(readPath, resolveDataDir(), accessExplainUser, accessExplainHost, accessExplainService, time.Now())
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if accessExplainFormat == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(sources)
	}
	if accessExplainFormat != "table" {
		return fmt.Errorf("--format must be table or json, got %q", accessExplainFormat)
	}
	if len(sources) == 0 {
		fmt.Fprintln(out, "no access found")
		return nil
	}
	for _, s := range sources {
		path := "direct"
		if !s.DirectUserHit {
			path = fmt.Sprintf("via group %v", s.GroupPath)
		}
		targetPath := "direct"
		if s.AllHosts {
			targetPath = "hostcat: all"
		} else if !s.DirectHostHit {
			targetPath = fmt.Sprintf("via hostgroup %v", s.HostgroupPath)
		}
		next := "n/a"
		if s.NextTransition != nil {
			next = s.NextTransition.Format(time.RFC3339)
		}
		fmt.Fprintf(out, "%s\trule=%s\tuser_path=%s\thost_path=%s\tservice=%s\tnext_transition_at=%s\n",
			s.Kind, s.Rule, path, targetPath, s.Service, next)
	}
	return nil
}
