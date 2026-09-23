package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/gatewayapi"
	"github.com/kjelly/pilot/internal/gatewayconfig"
)

var (
	accessRecordingFormatFlag string
	accessRecordingConfigFlag string
)

var accessRecordingCmd = &cobra.Command{
	Use:   "recording",
	Short: "Inspect SSH session recording policy on a pilot-access-gateway host",
}

var accessRecordingShowCmd = &cobra.Command{
	Use:   "show <host-fqdn>",
	Short: "Show a host's recording policy and the mode this gateway would record it with",
	Long: `pilot access recording show reads one host's recording policy from
FreeIPA with this gateway's own service principal and keytab, and resolves
it against this gateway's configured default exactly as a Connect would
(per-host recording spec §29).

Run it as root on a pilot-access-gateway host: it reads the gateway config
and keytab, and Portal users are confined to the Portal. It only reports
the recording policy; it does not evaluate HBAC, read hosts.yml, or change
anything.`,
	Args: cobra.ExactArgs(1),
	// A runtime failure (not root, host not found) is not a usage error.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAccessRecordingShow(cmd.Context(), cmd.OutOrStdout(), args[0], accessRecordingConfigFlag, accessRecordingFormatFlag)
	},
}

func init() {
	accessRecordingShowCmd.Flags().StringVar(&accessRecordingFormatFlag, "format", "text", "output format: text|json")
	accessRecordingShowCmd.Flags().StringVar(&accessRecordingConfigFlag, "config", gatewayconfig.DefaultPath, "pilot-access-gateway config file")
	accessRecordingCmd.AddCommand(accessRecordingShowCmd)
	accessCmd.AddCommand(accessRecordingCmd)
}

// accessRecordingEUID and newAccessRecordingProvider are variables so
// tests run without root or a FreeIPA server.
var (
	accessRecordingEUID        = os.Geteuid
	newAccessRecordingProvider = func(cfg gatewayconfig.Config) (freeipaaccess.Provider, error) {
		return freeipaaccess.NewClient(freeipaaccess.Config{
			Servers: cfg.Gateway.FreeIPA.Servers, CAFile: cfg.Gateway.FreeIPA.CAFile,
			ServicePrincipal: cfg.Gateway.FreeIPA.ServicePrincipal, KeytabPath: cfg.Gateway.FreeIPA.Keytab,
			RequestTimeout: cfg.RequestTimeout(),
		})
	}
)

// accessRecordingError carries the command's exit code: 2 for running
// without root, 1 otherwise.
type accessRecordingError struct {
	err  error
	code int
}

func (e *accessRecordingError) Error() string { return e.err.Error() }
func (e *accessRecordingError) ExitCode() int { return e.code }
func (e *accessRecordingError) Unwrap() error { return e.err }

// accessRecordingReport is the json output (per-host recording spec §29).
type accessRecordingReport struct {
	Host           string `json:"host"`
	HostPolicy     string `json:"host_policy"`
	GatewayDefault string `json:"gateway_default"`
	Effective      string `json:"effective"`
	PolicySource   string `json:"policy_source"`
	Reason         string `json:"reason,omitempty"`
}

func runAccessRecordingShow(ctx context.Context, w io.Writer, host, configPath, format string) error {
	if format != "text" && format != "json" {
		return &accessRecordingError{err: fmt.Errorf("--format must be text or json, got %q", format), code: 2}
	}
	if accessRecordingEUID() != 0 {
		return &accessRecordingError{err: errors.New("must run as root on a pilot-access-gateway host"), code: 2}
	}
	cfg, err := gatewayconfig.Load(configPath)
	if err != nil {
		return &accessRecordingError{err: err, code: 1}
	}
	provider, err := newAccessRecordingProvider(cfg)
	if err != nil {
		return &accessRecordingError{err: fmt.Errorf("build FreeIPA client: %w", err), code: 1}
	}
	fqdn := accessportal.CanonicalizeFQDN(host)
	h, err := provider.HostShow(ctx, fqdn)
	switch {
	case freeipaaccess.IsNotFound(err):
		return &accessRecordingError{err: fmt.Errorf("host not found in FreeIPA: %s", fqdn), code: 1}
	case err != nil:
		return &accessRecordingError{err: fmt.Errorf("query FreeIPA host_show %s: %w", fqdn, err), code: 1}
	}

	policy := accessportal.HostRecordingAccessPolicy(h, nil)
	report := accessRecordingReport{Host: fqdn, HostPolicy: policy.Status(), GatewayDefault: cfg.RecordingDefaultModeRaw()}
	mode, source, err := gatewayapi.ResolveRecordingMode(cfg.RecordingDefaultModeRaw(), policy)
	switch {
	case err != nil:
		report.Reason = policy.Reason
	case (mode == "terminal_output" || mode == "terminal_io") && cfg.Gateway.Recording.SessionStoreURL == "":
		// The gateway refuses this connect: nothing to record into.
		report.Effective, report.PolicySource = mode, source
		report.Reason = gatewayapi.DenyReasonRecordingBackend
	default:
		report.Effective, report.PolicySource = mode, source
	}

	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	return printAccessRecordingReport(w, report)
}

func printAccessRecordingReport(w io.Writer, r accessRecordingReport) error {
	gatewayDefault := r.GatewayDefault
	if gatewayDefault == "" {
		gatewayDefault = "unset (built-in metadata)"
	}
	effective, source := r.Effective, r.PolicySource
	if effective == "" {
		effective, source = "none — Connect will be refused", "-"
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Host:\t%s\n", r.Host)
	fmt.Fprintf(tw, "Host policy:\t%s\n", r.HostPolicy)
	fmt.Fprintf(tw, "Gateway default:\t%s\n", gatewayDefault)
	fmt.Fprintf(tw, "Effective:\t%s\n", effective)
	fmt.Fprintf(tw, "Policy source:\t%s\n", source)
	fmt.Fprintf(tw, "FreeIPA source:\tuserClass pilot.policy.ssh-recording\n")
	if r.Reason != "" {
		fmt.Fprintf(tw, "Reason:\t%s\n", r.Reason)
	}
	return tw.Flush()
}
