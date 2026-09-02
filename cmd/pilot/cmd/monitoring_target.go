package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/monitoring"
)

var monitoringTargetCmd = &cobra.Command{
	Use:   "target",
	Short: "Manage external monitoring targets",
}

func init() {
	monitoringCmd.AddCommand(monitoringTargetCmd)
}

// ---- shared flags -----------------------------------------------------

var (
	monDir string

	monTargetName            string
	monTargetAddress         string
	monTargetProfile         string
	monTargetSite            string
	monTargetDetectionCohort string
	monTargetLabels          []string
	monTargetYes             bool

	monTargetTestAuthUser string
)

func addMonitoringDirFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&monDir, "dir", ".", "workspace directory containing monitoring/targets.yml and monitoring/scrape-profiles.yml")
}

// ---- list ---------------------------------------------------------------

var monitoringTargetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List external monitoring targets",
	Args:  cobra.NoArgs,
	RunE:  runMonitoringTargetList,
}

func init() {
	addMonitoringDirFlag(monitoringTargetListCmd)
	monitoringTargetCmd.AddCommand(monitoringTargetListCmd)
}

func runMonitoringTargetList(cmd *cobra.Command, _ []string) error {
	ws := resolveMonitoringWorkspace(monDir)
	tf, _, err := ws.load()
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	// spec.md §76: an empty registry is not an error.
	if len(tf.Targets) == 0 {
		fmt.Fprintln(out, "No external monitoring targets configured.")
		return nil
	}
	targets := append([]monitoring.Target(nil), tf.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tPROFILE\tSITE\tSTATUS")
	for _, t := range targets {
		status := "enabled"
		if !t.IsEnabled() {
			status = "disabled"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.Name, t.Address, t.Profile, t.Site, status)
	}
	return tw.Flush()
}

// ---- add ------------------------------------------------------------------

var monitoringTargetAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add an external monitoring target",
	Args:  cobra.NoArgs,
	RunE:  runMonitoringTargetAdd,
}

func init() {
	c := monitoringTargetAddCmd
	addMonitoringDirFlag(c)
	c.Flags().StringVar(&monTargetName, "name", "", "target name, unique within the workspace (required)")
	c.Flags().StringVar(&monTargetAddress, "address", "", "host:port to scrape (required)")
	c.Flags().StringVar(&monTargetProfile, "profile", "", "scrape profile name, must already exist (required)")
	c.Flags().StringVar(&monTargetSite, "site", "", "logical site label (optional; required for an enabled kind:snmp target)")
	c.Flags().StringVar(&monTargetDetectionCohort, "detection-cohort", "", "Detection Engine cohort ID (kind:snmp targets only; a v2-only field)")
	addFlagTargetLabel(c, &monTargetLabels)
	_ = c.MarkFlagRequired("name")
	_ = c.MarkFlagRequired("address")
	_ = c.MarkFlagRequired("profile")
	monitoringTargetCmd.AddCommand(c)
}

func runMonitoringTargetAdd(cmd *cobra.Command, _ []string) error {
	ws := resolveMonitoringWorkspace(monDir)
	tf, pf, err := ws.load()
	if err != nil {
		return err
	}
	for _, t := range tf.Targets {
		if t.Name == monTargetName {
			return fmt.Errorf("target %q already exists — use `pilot monitoring target edit` to change it", monTargetName)
		}
	}
	labels, err := parseLabelFlags(monTargetLabels)
	if err != nil {
		return err
	}
	tf.Targets = append(tf.Targets, monitoring.Target{
		Name:            monTargetName,
		Address:         monTargetAddress,
		Profile:         monTargetProfile,
		Site:            monTargetSite,
		DetectionCohort: monTargetDetectionCohort,
		Labels:          labels,
	})

	r, err := validateWorkspace(ws, tf, pf)
	if err != nil {
		return err
	}
	printViolations(cmd.OutOrStdout(), r)
	if !r.OK() {
		return fmt.Errorf("target %q not saved: validation failed", monTargetName)
	}
	if err := monitoring.SaveTargets(ws.TargetsPath, tf); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "added target %q\n", monTargetName)
	return nil
}

// ---- edit -------------------------------------------------------------

var monitoringTargetEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit an existing external monitoring target",
	Args:  cobra.NoArgs,
	RunE:  runMonitoringTargetEdit,
}

func init() {
	c := monitoringTargetEditCmd
	addMonitoringDirFlag(c)
	c.Flags().StringVar(&monTargetName, "name", "", "target name to edit (required)")
	c.Flags().StringVar(&monTargetAddress, "address", "", "new host:port")
	c.Flags().StringVar(&monTargetProfile, "profile", "", "new scrape profile name")
	c.Flags().StringVar(&monTargetSite, "site", "", "new site label")
	c.Flags().StringVar(&monTargetDetectionCohort, "detection-cohort", "", "new Detection Engine cohort ID (kind:snmp targets only)")
	addFlagTargetLabel(c, &monTargetLabels)
	_ = c.MarkFlagRequired("name")
	monitoringTargetCmd.AddCommand(c)
}

// targetFromFlags applies whichever of --address/--profile/--site/--label
// were actually passed on cmd to base, leaving every other field untouched.
// Factored out of runMonitoringTargetEdit (and taking the flag VALUES as
// plain arguments, not reading the monTarget* package globals directly) so
// it's testable with a throwaway *cobra.Command/FlagSet per test case,
// sidestepping a real footgun found while writing this command's tests:
// pflag's Changed() state (and the bound variable's value) persists across
// repeated Execute() calls on the SAME *cobra.Command — harmless for actual
// `pilot` usage (every invocation is a fresh process) but silently corrupts
// a test suite that calls rootCmd.Execute() more than once in one process
// and trusts Changed() to reflect only the current call.
func targetFromFlags(changed func(string) bool, base monitoring.Target, address, profile, site, detectionCohort string, labels []string) (monitoring.Target, error) {
	if changed("address") {
		base.Address = address
	}
	if changed("profile") {
		base.Profile = profile
	}
	if changed("site") {
		base.Site = site
	}
	if changed("detection-cohort") {
		base.DetectionCohort = detectionCohort
	}
	if changed("label") {
		parsed, err := parseLabelFlags(labels)
		if err != nil {
			return base, err
		}
		base.Labels = parsed
	}
	return base, nil
}

func runMonitoringTargetEdit(cmd *cobra.Command, _ []string) error {
	ws := resolveMonitoringWorkspace(monDir)
	tf, pf, err := ws.load()
	if err != nil {
		return err
	}
	idx := findTargetIndex(tf, monTargetName)
	if idx < 0 {
		return fmt.Errorf("target %q not found", monTargetName)
	}
	updated, err := targetFromFlags(cmd.Flags().Changed, tf.Targets[idx], monTargetAddress, monTargetProfile, monTargetSite, monTargetDetectionCohort, monTargetLabels)
	if err != nil {
		return err
	}
	tf.Targets[idx] = updated

	r, err := validateWorkspace(ws, tf, pf)
	if err != nil {
		return err
	}
	printViolations(cmd.OutOrStdout(), r)
	if !r.OK() {
		return fmt.Errorf("target %q not saved: validation failed", monTargetName)
	}
	if err := monitoring.SaveTargets(ws.TargetsPath, tf); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "updated target %q\n", monTargetName)
	return nil
}

// ---- remove -------------------------------------------------------------

var monitoringTargetRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an external monitoring target (registry only — no remote host action, spec.md §28)",
	Args:  cobra.ExactArgs(1),
	RunE:  runMonitoringTargetRemove,
}

func init() {
	c := monitoringTargetRemoveCmd
	addMonitoringDirFlag(c)
	c.Flags().BoolVar(&monTargetYes, "yes", false, "skip the interactive confirmation prompt (required for non-interactive/automation use — spec.md §28)")
	monitoringTargetCmd.AddCommand(c)
}

func runMonitoringTargetRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	ws := resolveMonitoringWorkspace(monDir)
	tf, _, err := ws.load()
	if err != nil {
		return err
	}
	idx := findTargetIndex(tf, name)
	if idx < 0 {
		return fmt.Errorf("target %q not found", name)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "target to remove: %s (address=%s profile=%s)\n", tf.Targets[idx].Name, tf.Targets[idx].Address, tf.Targets[idx].Profile)
	if !monTargetYes {
		if !confirmPrompt(cmd, fmt.Sprintf("remove target %q? [y/N] ", name)) {
			fmt.Fprintln(cmd.OutOrStdout(), "cancelled")
			return nil
		}
	}
	tf.Targets = append(tf.Targets[:idx], tf.Targets[idx+1:]...)
	if err := monitoring.SaveTargets(ws.TargetsPath, tf); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "removed target %q\n", name)
	return nil
}

// ---- enable / disable -----------------------------------------------------

var monitoringTargetEnableCmd = &cobra.Command{
	Use:   "enable <name>",
	Short: "Enable an external monitoring target",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return setTargetEnabled(cmd, args[0], true) },
}

var monitoringTargetDisableCmd = &cobra.Command{
	Use:   "disable <name>",
	Short: "Disable an external monitoring target (kept in the registry, excluded from Prometheus scraping — spec.md §8.5)",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return setTargetEnabled(cmd, args[0], false) },
}

func init() {
	addMonitoringDirFlag(monitoringTargetEnableCmd)
	addMonitoringDirFlag(monitoringTargetDisableCmd)
	monitoringTargetCmd.AddCommand(monitoringTargetEnableCmd)
	monitoringTargetCmd.AddCommand(monitoringTargetDisableCmd)
}

func setTargetEnabled(cmd *cobra.Command, name string, enabled bool) error {
	ws := resolveMonitoringWorkspace(monDir)
	tf, _, err := ws.load()
	if err != nil {
		return err
	}
	idx := findTargetIndex(tf, name)
	if idx < 0 {
		return fmt.Errorf("target %q not found", name)
	}
	tf.Targets[idx].Enabled = &enabled
	if err := monitoring.SaveTargets(ws.TargetsPath, tf); err != nil {
		return err
	}
	verb := "enabled"
	if !enabled {
		verb = "disabled"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s target %q\n", verb, name)
	return nil
}

// ---- test -----------------------------------------------------------------

var monitoringTargetTestCmd = &cobra.Command{
	Use:   "test <name>",
	Short: "Test connectivity to an external monitoring target (spec.md §29-31; read-only)",
	Args:  cobra.ExactArgs(1),
	RunE:  runMonitoringTargetTest,
}

func init() {
	c := monitoringTargetTestCmd
	addMonitoringDirFlag(c)
	c.Flags().StringVar(&monTargetTestAuthUser, "auth-username", "", "basic-auth username, if the target's profile requires one (password via PILOT_MONITORING_AUTH_PASSWORD env var — never a flag, spec.md §30: credentials must not appear in process argv)")
	monitoringTargetCmd.AddCommand(c)
}

func runMonitoringTargetTest(cmd *cobra.Command, args []string) error {
	name := args[0]
	ws := resolveMonitoringWorkspace(monDir)
	tf, pf, err := ws.load()
	if err != nil {
		return err
	}
	rt, ok := monitoring.Resolve(tf, pf, name)
	if !ok {
		return fmt.Errorf("target %q not found, or references an unknown profile", name)
	}
	var cred *monitoring.AuthCredential
	if rt.Profile.AuthRef != "" {
		password := os.Getenv("PILOT_MONITORING_AUTH_PASSWORD")
		if monTargetTestAuthUser == "" || password == "" {
			return fmt.Errorf("profile %q requires authRef %q — pass --auth-username and set PILOT_MONITORING_AUTH_PASSWORD", rt.Target.Profile, rt.Profile.AuthRef)
		}
		cred = &monitoring.AuthCredential{Type: "basic", Username: monTargetTestAuthUser, Password: password}
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Target: %s\n", rt.Target.Name)
	fmt.Fprintf(out, "Address: %s\n", rt.Target.Address)
	fmt.Fprintf(out, "Profile: %s\n\n", rt.Target.Profile)

	report := monitoring.TestConnectivity(cmd.Context(), rt, cred, monitoring.DefaultTestOptions())
	for _, s := range report.Steps {
		mark := "PASS"
		if !s.Pass {
			mark = "FAIL"
		}
		fmt.Fprintf(out, "[%s] %s -> %s\n", mark, s.Name, s.Detail)
	}
	fmt.Fprintln(out)
	if report.Pass {
		fmt.Fprintln(out, "Result: PASS")
		return nil
	}
	fmt.Fprintln(out, "Result: FAIL")
	return fmt.Errorf("target %q connectivity test failed", name)
}

// ---- shared helpers ---------------------------------------------------

func findTargetIndex(tf monitoring.TargetFile, name string) int {
	for i, t := range tf.Targets {
		if t.Name == name {
			return i
		}
	}
	return -1
}

// confirmPrompt asks a yes/no question on cmd's own stdin/stdout, matching
// spec.md §28's "interactive shell 下要求 confirmation" requirement for
// `target remove`. Automation/MCP callers must pass --yes (spec.md §28
// point 3's "explicit confirmation field" equivalent for a plain CLI).
func confirmPrompt(cmd *cobra.Command, prompt string) bool {
	fmt.Fprint(cmd.OutOrStdout(), prompt)
	var answer string
	_, _ = fmt.Fscanln(cmd.InOrStdin(), &answer)
	return answer == "y" || answer == "Y" || answer == "yes"
}
