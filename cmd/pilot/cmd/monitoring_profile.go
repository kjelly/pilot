package cmd

import (
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/monitoring"
)

var monitoringProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage scrape profiles (shared scrape behavior referenced by name from monitoring targets)",
}

func init() {
	monitoringCmd.AddCommand(monitoringProfileCmd)
}

var (
	monProfileName              string
	monProfileJobName           string
	monProfileKind              string
	monProfileSubjectKind       string
	monProfileDiagnosticProfile string
	monProfileScheme            string
	monProfileMetricsPath       string
	monProfileScrapeInterval    string
	monProfileScrapeTimeout     string
	monProfileAuthRef           string
	monProfileTLSServerName     string
	monProfileTLSInsecure       bool
	monProfileSNMPAuthProfile   string
	monProfileSNMPModules       []string
)

// ---- list -----------------------------------------------------------------

var monitoringProfileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scrape profiles",
	Args:  cobra.NoArgs,
	RunE:  runMonitoringProfileList,
}

func init() {
	addMonitoringDirFlag(monitoringProfileListCmd)
	monitoringProfileCmd.AddCommand(monitoringProfileListCmd)
}

func runMonitoringProfileList(cmd *cobra.Command, _ []string) error {
	ws := resolveMonitoringWorkspace(monDir)
	_, pf, err := ws.load()
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if len(pf.Profiles) == 0 {
		fmt.Fprintln(out, "No scrape profiles configured.")
		return nil
	}
	names := make([]string, 0, len(pf.Profiles))
	for name := range pf.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tJOB\tSCHEME\tMETRICS PATH\tAUTH REF")
	for _, name := range names {
		p := pf.Profiles[name]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, p.JobName, p.EffectiveScheme(), p.EffectiveMetricsPath(), p.AuthRef)
	}
	return tw.Flush()
}

// ---- add / edit shared flag registration ----------------------------------

func addProfileFieldFlags(c *cobra.Command) {
	c.Flags().StringVar(&monProfileJobName, "job-name", "", "Prometheus job_name for this profile (required, must be unique and non-reserved)")
	c.Flags().StringVar(&monProfileKind, "kind", "", "prometheus (default) or snmp (SNMP monitoring integration spec §7.2)")
	c.Flags().StringVar(&monProfileSubjectKind, "subject-kind", "", "Detection Engine subject kind (required for --kind snmp, e.g. network_device)")
	c.Flags().StringVar(&monProfileDiagnosticProfile, "diagnostic-profile", "", "diagnostic query-pack ID for pilot_diagnose_monitoring_target (kind snmp only)")
	c.Flags().StringVar(&monProfileScheme, "scheme", "", "http or https (default: http; kind:prometheus only)")
	c.Flags().StringVar(&monProfileMetricsPath, "metrics-path", "", "metrics HTTP path (default: /metrics; kind:prometheus only)")
	c.Flags().StringVar(&monProfileScrapeInterval, "scrape-interval", "", "scrape interval, e.g. 15s (default: Prometheus global)")
	c.Flags().StringVar(&monProfileScrapeTimeout, "scrape-timeout", "", "scrape timeout, e.g. 10s (default: Prometheus global)")
	c.Flags().StringVar(&monProfileAuthRef, "auth-ref", "", "reference into monitoring_auth (vault-backed secret map) for basic auth; kind:prometheus only")
	c.Flags().StringVar(&monProfileTLSServerName, "tls-server-name", "", "TLS server name override (only meaningful with --scheme https)")
	c.Flags().BoolVar(&monProfileTLSInsecure, "tls-insecure-skip-verify", false, "disable TLS certificate verification (warned at validate time — spec.md §44)")
	c.Flags().StringVar(&monProfileSNMPAuthProfile, "snmp-auth-profile", "", "monitoring/snmp/catalog.yml authProfile ID (required for --kind snmp)")
	c.Flags().StringArrayVar(&monProfileSNMPModules, "snmp-module", nil, "monitoring/snmp/catalog.yml module ID (repeatable, order preserved; required for --kind snmp)")
}

func profileFromFlags(cmd *cobra.Command, base monitoring.Profile) monitoring.Profile {
	if cmd.Flags().Changed("job-name") {
		base.JobName = monProfileJobName
	}
	if cmd.Flags().Changed("kind") {
		base.Kind = monProfileKind
	}
	if cmd.Flags().Changed("subject-kind") {
		base.SubjectKind = monProfileSubjectKind
	}
	if cmd.Flags().Changed("diagnostic-profile") {
		base.DiagnosticProfile = monProfileDiagnosticProfile
	}
	if cmd.Flags().Changed("scheme") {
		base.Scheme = monProfileScheme
	}
	if cmd.Flags().Changed("metrics-path") {
		base.MetricsPath = monProfileMetricsPath
	}
	if cmd.Flags().Changed("scrape-interval") {
		base.ScrapeInterval = monProfileScrapeInterval
	}
	if cmd.Flags().Changed("scrape-timeout") {
		base.ScrapeTimeout = monProfileScrapeTimeout
	}
	if cmd.Flags().Changed("auth-ref") {
		base.AuthRef = monProfileAuthRef
	}
	if cmd.Flags().Changed("tls-server-name") || cmd.Flags().Changed("tls-insecure-skip-verify") {
		tls := monitoring.TLSConfig{}
		if base.TLS != nil {
			tls = *base.TLS
		}
		if cmd.Flags().Changed("tls-server-name") {
			tls.ServerName = monProfileTLSServerName
		}
		if cmd.Flags().Changed("tls-insecure-skip-verify") {
			tls.InsecureSkipVerify = monProfileTLSInsecure
		}
		base.TLS = &tls
	}
	if cmd.Flags().Changed("snmp-auth-profile") || cmd.Flags().Changed("snmp-module") {
		snmp := monitoring.SNMPProfile{}
		if base.SNMP != nil {
			snmp = *base.SNMP
		}
		if cmd.Flags().Changed("snmp-auth-profile") {
			snmp.AuthProfile = monProfileSNMPAuthProfile
		}
		if cmd.Flags().Changed("snmp-module") {
			snmp.Modules = append([]string(nil), monProfileSNMPModules...)
		}
		base.SNMP = &snmp
	}
	return base
}

// ---- add --------------------------------------------------------------

var monitoringProfileAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a scrape profile",
	Args:  cobra.NoArgs,
	RunE:  runMonitoringProfileAdd,
}

func init() {
	c := monitoringProfileAddCmd
	addMonitoringDirFlag(c)
	c.Flags().StringVar(&monProfileName, "name", "", "profile name, unique within the workspace (required)")
	addProfileFieldFlags(c)
	_ = c.MarkFlagRequired("name")
	_ = c.MarkFlagRequired("job-name")
	monitoringProfileCmd.AddCommand(c)
}

func runMonitoringProfileAdd(cmd *cobra.Command, _ []string) error {
	ws := resolveMonitoringWorkspace(monDir)
	tf, pf, err := ws.load()
	if err != nil {
		return err
	}
	if _, exists := pf.Profiles[monProfileName]; exists {
		return fmt.Errorf("profile %q already exists — use `pilot monitoring profile edit` to change it", monProfileName)
	}
	if pf.Profiles == nil {
		pf.Profiles = map[string]monitoring.Profile{}
	}
	pf.Profiles[monProfileName] = profileFromFlags(cmd, monitoring.Profile{})

	r, err := validateWorkspace(ws, tf, pf)
	if err != nil {
		return err
	}
	printViolations(cmd.OutOrStdout(), r)
	if !r.OK() {
		return fmt.Errorf("profile %q not saved: validation failed", monProfileName)
	}
	if err := monitoring.SaveProfiles(ws.ProfilesPath, pf); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "added profile %q\n", monProfileName)
	return nil
}

// ---- edit -------------------------------------------------------------

var monitoringProfileEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit an existing scrape profile",
	Args:  cobra.NoArgs,
	RunE:  runMonitoringProfileEdit,
}

func init() {
	c := monitoringProfileEditCmd
	addMonitoringDirFlag(c)
	c.Flags().StringVar(&monProfileName, "name", "", "profile name to edit (required)")
	addProfileFieldFlags(c)
	_ = c.MarkFlagRequired("name")
	monitoringProfileCmd.AddCommand(c)
}

func runMonitoringProfileEdit(cmd *cobra.Command, _ []string) error {
	ws := resolveMonitoringWorkspace(monDir)
	tf, pf, err := ws.load()
	if err != nil {
		return err
	}
	existing, ok := pf.Profiles[monProfileName]
	if !ok {
		return fmt.Errorf("profile %q not found", monProfileName)
	}
	pf.Profiles[monProfileName] = profileFromFlags(cmd, existing)

	r, err := validateWorkspace(ws, tf, pf)
	if err != nil {
		return err
	}
	printViolations(cmd.OutOrStdout(), r)
	if !r.OK() {
		return fmt.Errorf("profile %q not saved: validation failed", monProfileName)
	}
	if err := monitoring.SaveProfiles(ws.ProfilesPath, pf); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "updated profile %q\n", monProfileName)
	return nil
}

// ---- remove -------------------------------------------------------------

var monitoringProfileRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a scrape profile (refused if any target still references it — spec.md §50)",
	Args:  cobra.ExactArgs(1),
	RunE:  runMonitoringProfileRemove,
}

func init() {
	addMonitoringDirFlag(monitoringProfileRemoveCmd)
	monitoringProfileCmd.AddCommand(monitoringProfileRemoveCmd)
}

func runMonitoringProfileRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	ws := resolveMonitoringWorkspace(monDir)
	tf, pf, err := ws.load()
	if err != nil {
		return err
	}
	if _, ok := pf.Profiles[name]; !ok {
		return fmt.Errorf("profile %q not found", name)
	}
	if inUse := monitoring.ProfileInUse(tf, name); len(inUse) > 0 {
		return fmt.Errorf("cannot remove profile %q: used by targets: %v", name, inUse)
	}
	delete(pf.Profiles, name)
	if err := monitoring.SaveProfiles(ws.ProfilesPath, pf); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "removed profile %q\n", name)
	return nil
}
