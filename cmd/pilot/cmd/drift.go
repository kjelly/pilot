package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/anomalyco/pilot/internal/app"
	"github.com/spf13/cobra"
)

var (
	driftInventory         string
	driftLimit             string
	driftVaultPasswordFile string
	driftAutoAlign         bool
)

var driftCmd = &cobra.Command{
	Use:   "drift [playbook.yml...]",
	Short: "Detect configuration drift by running playbooks in dry-run mode and optionally align state.",
	Long:  "Drift runs playbooks in --check --diff mode to find configuration differences between target hosts and playbook specs. If --auto-align is enabled, it applies playbooks where drift is found.",
	RunE:  runDrift,
}

func init() {
	driftCmd.Flags().StringVarP(&driftInventory, "inventory", "i", "", "Inventory file path")
	driftCmd.Flags().StringVarP(&driftLimit, "limit", "l", "", "Limit hosts pattern")
	driftCmd.Flags().StringVar(&driftVaultPasswordFile, "vault-password-file", "", "Vault password file path")
	driftCmd.Flags().BoolVar(&driftAutoAlign, "auto-align", false, "Automatically apply playbooks that show configuration drift")

	rootCmd.AddCommand(driftCmd)
}

type HostDrift struct {
	Host    string
	Changed int
	Failed  int
}

func runDrift(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no playbooks specified")
	}

	ctx := context.Background()
	appOpts := app.Options{
		Banner: false,
	}

	res, err := setupRunWithOpts(ctx, appOpts)
	if err != nil {
		return err
	}
	defer res.Store.Close()

	for _, playbook := range args {
		fmt.Printf("🔍 Checking drift for playbook: %s...\n", playbook)

		// 1. Syntax check first
		syntaxArgs := []string{playbook, "--syntax-check"}
		if driftInventory != "" {
			syntaxArgs = append(syntaxArgs, "-i", driftInventory)
		}
		if driftLimit != "" {
			syntaxArgs = append(syntaxArgs, "-l", driftLimit)
		}
		if driftVaultPasswordFile != "" {
			syntaxArgs = append(syntaxArgs, "--vault-password-file", driftVaultPasswordFile)
		}
		sres, err := res.Runner.Run(ctx, syntaxArgs...)
		if err != nil {
			return fmt.Errorf("syntax check failed: %w", err)
		}
		if sres.ExitCode != 0 {
			fmt.Printf("❌ Playbook %s syntax check failed:\n%s\n", playbook, sres.Stderr)
			continue
		}

		// 2. Check drift using --check --diff
		checkArgs := []string{playbook}
		if driftInventory != "" {
			checkArgs = append(checkArgs, "-i", driftInventory)
		}
		if driftLimit != "" {
			checkArgs = append(checkArgs, "-l", driftLimit)
		}
		if driftVaultPasswordFile != "" {
			checkArgs = append(checkArgs, "--vault-password-file", driftVaultPasswordFile)
		}
		cres, err := res.Runner.Check(ctx, checkArgs...)
		if err != nil {
			return fmt.Errorf("drift check failed: %w", err)
		}

		drifts := parseDrift(cres.Stdout)
		if len(drifts) == 0 {
			fmt.Printf("✓ Playbook %s is in sync. No drift detected.\n", playbook)
			continue
		}

		fmt.Printf("⚠️  Drift detected in playbook: %s\n", playbook)
		for _, d := range drifts {
			fmt.Printf("   - Host %s: %d tasks would change, %d tasks failed/drifted\n", d.Host, d.Changed, d.Failed)
		}

		// 3. Auto-align if requested
		if driftAutoAlign {
			approved := false
			if res.Approver != nil {
				approved = res.Approver.AskRollback(fmt.Sprintf("⚠️ 偵測到漂移！是否確認自動對齊套用 Playbook %s？", playbook))
			} else {
				approved = true
			}
			if !approved {
				fmt.Println("⏭ 跳過自動對齊套用。")
				continue
			}

			fmt.Printf("🔄 Auto-align: applying playbook %s...\n", playbook)
			runArgs := []string{playbook}
			if driftInventory != "" {
				runArgs = append(runArgs, "-i", driftInventory)
			}
			if driftLimit != "" {
				runArgs = append(runArgs, "-l", driftLimit)
			}
			if driftVaultPasswordFile != "" {
				runArgs = append(runArgs, "--vault-password-file", driftVaultPasswordFile)
			}
			rres, err := res.Runner.Run(ctx, runArgs...)
			if err != nil {
				return fmt.Errorf("auto-alignment failed: %w", err)
			}
			if rres.ExitCode == 0 {
				fmt.Printf("✓ Auto-alignment successful for playbook: %s\n", playbook)
			} else {
				fmt.Printf("❌ Auto-alignment failed for playbook: %s (exit=%d):\n%s\n", playbook, rres.ExitCode, rres.Stderr)
			}
		}
	}

	return nil
}

func parseDrift(stdout string) []HostDrift {
	var drifts []HostDrift
	lines := strings.Split(stdout, "\n")
	inRecap := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PLAY RECAP **************************") {
			inRecap = true
			continue
		}
		if inRecap && trimmed != "" {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				host := strings.TrimSpace(parts[0])
				metrics := parts[1]
				changed := 0
				failed := 0
				_, _ = fmt.Sscanf(extractMetric(metrics, "changed="), "%d", &changed)
				_, _ = fmt.Sscanf(extractMetric(metrics, "failed="), "%d", &failed)
				if changed > 0 || failed > 0 {
					drifts = append(drifts, HostDrift{Host: host, Changed: changed, Failed: failed})
				}
			}
		}
	}
	return drifts
}

func extractMetric(metrics, prefix string) string {
	parts := strings.Fields(metrics)
	for _, p := range parts {
		if strings.HasPrefix(p, prefix) {
			return p[len(prefix):]
		}
	}
	return "0"
}
