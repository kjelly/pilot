// detection_engine_feature_profile.go implements
// `pilot detection-engine feature-profile show/set-notify`: a management-
// plane CLI over the detection-engine feature-profile YAML files under
// monitoring/detection/feature-profiles/*.yaml (deployed unmodified by
// detection-engine-apply.yml), so an operator can configure a different
// runbook/recommended-action per alert category (e.g. storage vs cpu)
// without hand-editing YAML. This is NOT a detection-engine runtime
// component — it edits the committed profile file; the change only takes
// effect for the running engine after the usual apply/redeploy (AGENTS.md
// §0.2's authoring model: pilot stays deterministic, config lives in git).
package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/detection"
)

var (
	detectionFeatureProfileCategoryFlag          string
	detectionFeatureProfileWarningFlag           string
	detectionFeatureProfileCriticalFlag          string
	detectionFeatureProfileRunbookURLFlag        string
	detectionFeatureProfileRecommendedActionFlag string
	detectionFeatureProfileClearFlag             bool
)

var detectionEngineCmd = &cobra.Command{
	Use:   "detection-engine",
	Short: "Manage central Detection Engine configuration",
}

var detectionFeatureProfileCmd = &cobra.Command{
	Use:   "feature-profile",
	Short: "Inspect/edit a detection-engine feature-profile YAML file",
}

var detectionFeatureProfileShowCmd = &cobra.Command{
	Use:   "show <path>",
	Short: "List this profile's categories and the notify policy (runbook/recommended action) each would use",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profile, err := detection.LoadFeatureProfile(args[0])
		if err != nil {
			return fmt.Errorf("load feature profile: %w", err)
		}
		summary := profile.NotifySummaryByCategory()
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "CATEGORY\tOVERRIDDEN\tWARNING\tCRITICAL\tRUNBOOK URL\tRECOMMENDED ACTION")
		for _, s := range summary {
			fmt.Fprintf(w, "%s\t%t\t%s\t%s\t%s\t%s\n",
				s.Category, s.Overridden, s.Policy.Warning, s.Policy.Critical, s.Policy.RunbookURL, s.Policy.RecommendedAction)
		}
		return w.Flush()
	},
}

var detectionFeatureProfileSetNotifyCmd = &cobra.Command{
	Use:   "set-notify <path>",
	Short: "Set or clear one category's notify override (runbook/recommended action/destination)",
	Long: `Set or clear one category's notify override in a feature-profile YAML file.

A field left off the command line is left untouched. Passing a flag with an
empty value (e.g. --runbook-url="") clears that one field back to the
profile-wide default. --clear removes the whole per-category override,
returning that category to the profile-wide default for every field.

Only a category an existing feature in the profile actually declares (see
'pilot detection-engine feature-profile show') may be set.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if detectionFeatureProfileCategoryFlag == "" {
			return fmt.Errorf("--category is required")
		}
		edit := detection.NotifyOverrideEdit{
			Category:      detectionFeatureProfileCategoryFlag,
			ClearCategory: detectionFeatureProfileClearFlag,
		}
		if !detectionFeatureProfileClearFlag {
			if cmd.Flags().Changed("warning") {
				edit.Warning = &detectionFeatureProfileWarningFlag
			}
			if cmd.Flags().Changed("critical") {
				edit.Critical = &detectionFeatureProfileCriticalFlag
			}
			if cmd.Flags().Changed("runbook-url") {
				edit.RunbookURL = &detectionFeatureProfileRunbookURLFlag
			}
			if cmd.Flags().Changed("recommended-action") {
				edit.RecommendedAction = &detectionFeatureProfileRecommendedActionFlag
			}
			if edit.Warning == nil && edit.Critical == nil && edit.RunbookURL == nil && edit.RecommendedAction == nil {
				return fmt.Errorf("no field flags given; pass at least one of --warning/--critical/--runbook-url/--recommended-action, or --clear")
			}
		}
		if err := detection.SetFeatureProfileNotifyOverride(args[0], edit); err != nil {
			return err
		}
		profile, err := detection.LoadFeatureProfile(args[0])
		if err != nil {
			return fmt.Errorf("reload edited feature profile: %w", err)
		}
		effective := profile.EffectiveNotifyPolicyForCategory(detectionFeatureProfileCategoryFlag)
		fmt.Fprintf(cmd.OutOrStdout(), "%s: warning=%s critical=%s runbookURL=%s recommendedAction=%s\n",
			detectionFeatureProfileCategoryFlag, effective.Warning, effective.Critical, effective.RunbookURL, effective.RecommendedAction)
		return nil
	},
}

func init() {
	detectionFeatureProfileSetNotifyCmd.Flags().StringVar(&detectionFeatureProfileCategoryFlag, "category", "", "feature category to set the override for, e.g. storage (required)")
	detectionFeatureProfileSetNotifyCmd.Flags().StringVar(&detectionFeatureProfileWarningFlag, "warning", "", "notify destination for warning severity: none, dashboard, digest, or teams")
	detectionFeatureProfileSetNotifyCmd.Flags().StringVar(&detectionFeatureProfileCriticalFlag, "critical", "", "notify destination for critical severity: none, dashboard, digest, or teams")
	detectionFeatureProfileSetNotifyCmd.Flags().StringVar(&detectionFeatureProfileRunbookURLFlag, "runbook-url", "", "runbook path/URL for this category's alerts")
	detectionFeatureProfileSetNotifyCmd.Flags().StringVar(&detectionFeatureProfileRecommendedActionFlag, "recommended-action", "", "recommended-action text for this category's alerts")
	detectionFeatureProfileSetNotifyCmd.Flags().BoolVar(&detectionFeatureProfileClearFlag, "clear", false, "remove the whole per-category override (ignores the other flags)")
	detectionFeatureProfileSetNotifyCmd.MarkFlagRequired("category")

	detectionFeatureProfileCmd.AddCommand(detectionFeatureProfileShowCmd, detectionFeatureProfileSetNotifyCmd)
	detectionEngineCmd.AddCommand(detectionFeatureProfileCmd)
	rootCmd.AddCommand(detectionEngineCmd)
}
