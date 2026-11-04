package cmd

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/services"
)

var (
	svcProfile             string
	svcNetwork             string
	svcJSON                bool
	svcConfirm             bool
	svcAcknowledgeLegacy   bool
	svcConsumerID          string
	svcConfirmInterruption bool
)

var servicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Manage persistent host services used by VM targets",
}

var servicesUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Start the host service bundle",
	RunE:  runServicesUp,
}

var servicesStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show host service health and endpoint state",
	RunE:  runServicesStatus,
}

var servicesDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop host services while retaining persistent data",
	RunE:  runServicesDown,
}

var servicesPurgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Stop services and remove their persistent data",
	RunE:  runServicesPurge,
}

var servicesRepairCmd = &cobra.Command{
	Use:   "repair",
	Short: "Explicitly repair a compatible cache stack when no registered VMs use it",
	RunE:  runServicesRepair,
}

var servicesCredentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Reassociate existing Harbor credentials without changing services",
}

var servicesCredentialsImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Validate and import an authorized existing Harbor secret file",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		kindValue, _ := cmd.Flags().GetString("kind")
		source, _ := cmd.Flags().GetString("secret-file")
		if source == "" {
			return fmt.Errorf("services: --secret-file is required")
		}
		if source == "~" || strings.HasPrefix(source, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("services: cannot resolve secret source home directory")
			}
			if source == "~" {
				source = home
			} else {
				source = filepath.Join(home, source[2:])
			}
		}
		source, err := filepath.Abs(source)
		if err != nil {
			return fmt.Errorf("services: cannot resolve secret source path")
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(source))
		if err != nil {
			return fmt.Errorf("services: cannot resolve secret source directory")
		}
		source = filepath.Join(parent, filepath.Base(source))
		kind := services.CredentialKind(kindValue)
		m, err := newServiceManagerForCredential(cmd.Context(), kind)
		if err != nil {
			return err
		}
		if err := m.ImportCredential(cmd.Context(), kind, source); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Harbor credential association validated and published; services retained")
		return nil
	},
}

var servicesConsumersCmd = &cobra.Command{
	Use:   "consumers",
	Short: "List durable VM consumer registrations, including pending provisioning",
	RunE: func(cmd *cobra.Command, _ []string) error {
		m, err := newConsumptionServiceManager(cmd.Context())
		if err != nil {
			return err
		}
		consumers, err := m.Consumers(cmd.Context())
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(consumers)
	},
}

var servicesReleaseConsumerCmd = &cobra.Command{
	Use:   "release-consumer",
	Short: "Release one exact registration, accepting interruption risk for its VM",
	RunE: func(cmd *cobra.Command, _ []string) error {
		m, err := newConsumptionServiceManager(cmd.Context())
		if err != nil {
			return err
		}
		return m.ForgetConsumer(cmd.Context(), svcConsumerID, svcConfirmInterruption)
	},
}

func init() {
	rootCmd.AddCommand(servicesCmd)
	servicesCmd.AddCommand(servicesCredentialsCmd)
	servicesCredentialsCmd.AddCommand(servicesCredentialsImportCmd)
	servicesCredentialsImportCmd.Flags().String("kind", "harbor-admin", "existing credential identity: harbor-admin or harbor-database")
	servicesCredentialsImportCmd.Flags().String("secret-file", "", "owned mode-0600 regular file containing the existing secret")
	servicesCredentialsImportCmd.RunE = withServiceCommandSignals(servicesCredentialsImportCmd.RunE)
	servicesCmd.AddCommand(servicesUpCmd, servicesStatusCmd, servicesDownCmd, servicesPurgeCmd)
	servicesCmd.AddCommand(servicesRepairCmd, servicesConsumersCmd, servicesReleaseConsumerCmd)
	for _, command := range servicesCmd.Commands() {
		if command.RunE != nil {
			command.RunE = withServiceCommandSignals(command.RunE)
		}
	}
	servicesRepairCmd.Flags().StringVar(&svcProfile, "profile", "dev-lite", "service profile name or YAML path")
	servicesRepairCmd.Flags().StringVar(&svcNetwork, "network", "default", "libvirt network whose gateway receives service traffic")
	servicesRepairCmd.Flags().BoolVar(&svcJSON, "json", false, "print machine-readable status")
	for _, command := range []*cobra.Command{servicesDownCmd, servicesPurgeCmd, servicesRepairCmd} {
		command.Flags().BoolVar(&svcAcknowledgeLegacy, "acknowledge-legacy-clients", false, "accept interruption risk for unregistered guests created before consumer tracking")
	}
	servicesReleaseConsumerCmd.Flags().StringVar(&svcConsumerID, "id", "", "exact durable consumer ID to release")
	servicesReleaseConsumerCmd.Flags().BoolVar(&svcConfirmInterruption, "confirm-interruption", false, "accept that the named consumer VM may lose cache access during later maintenance")
	servicesUpCmd.Flags().StringVar(&svcProfile, "profile", "dev-lite", "service profile name or YAML path")
	servicesUpCmd.Flags().StringVar(&svcNetwork, "network", "default", "libvirt network whose gateway receives service traffic")
	servicesUpCmd.Flags().BoolVar(&svcJSON, "json", false, "print machine-readable status")
	servicesStatusCmd.Flags().BoolVar(&svcJSON, "json", false, "print machine-readable status")
	servicesPurgeCmd.Flags().BoolVar(&svcConfirm, "confirm", false, "confirm removal of persistent service data")
}

// Only service handlers consistently observe command cancellation. Intercepting
// signals at the root would suppress OS termination for unrelated handlers that
// still use background contexts (for example, an interactive remote exec).
func withServiceCommandSignals(run func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		previous := cmd.Context()
		ctx, stop := signal.NotifyContext(previous, os.Interrupt, syscall.SIGTERM)
		defer stop()
		cmd.SetContext(ctx)
		defer cmd.SetContext(previous)
		return run(cmd, args)
	}
}

func runServicesUp(cmd *cobra.Command, _ []string) error {
	return runServiceStart(cmd, false)
}

func runServicesRepair(cmd *cobra.Command, _ []string) error {
	return runServiceStart(cmd, true)
}

func runServiceStart(cmd *cobra.Command, repair bool) error {
	profile, err := services.LoadProfile(svcProfile)
	if err != nil {
		return err
	}
	ip, err := discoverLibvirtNetworkAddress(cmd.Context(), svcNetwork)
	if err != nil {
		return err
	}
	m, err := newServiceManagerContext(cmd.Context())
	if err != nil {
		return err
	}
	if repair {
		err = m.Repair(cmd.Context(), profile, ip, services.MaintenanceOptions{AcknowledgeLegacyClients: svcAcknowledgeLegacy})
	} else {
		err = m.Up(cmd.Context(), profile, ip)
	}
	if err != nil {
		return err
	}
	status, err := m.Status(cmd.Context())
	if err != nil {
		return err
	}
	return printServiceStatus(cmd, status)
}

func runServicesStatus(cmd *cobra.Command, _ []string) error {
	m, err := newConsumptionServiceManager(cmd.Context())
	if err != nil {
		return err
	}
	status, err := m.Status(cmd.Context())
	if err != nil {
		return err
	}
	return printServiceStatus(cmd, status)
}

func runServicesDown(cmd *cobra.Command, _ []string) error {
	m, err := newServiceManagerContext(cmd.Context())
	if err != nil {
		return err
	}
	if err := m.DownWithOptions(cmd.Context(), services.MaintenanceOptions{AcknowledgeLegacyClients: svcAcknowledgeLegacy}); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ host services stopped; persistent data retained")
	return nil
}

func runServicesPurge(cmd *cobra.Command, _ []string) error {
	m, err := newServiceManagerContext(cmd.Context())
	if err != nil {
		return err
	}
	if err := m.PurgeWithOptions(cmd.Context(), svcConfirm, services.MaintenanceOptions{AcknowledgeLegacyClients: svcAcknowledgeLegacy}); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ host services stopped and persistent data removed")
	return nil
}

func printServiceStatus(cmd *cobra.Command, status services.Status) error {
	if svcJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	}
	if !status.Configured {
		fmt.Fprintln(cmd.OutOrStdout(), "host services: not configured")
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "host services: running=%t profile=%s bind_ip=%s\n", status.Running, status.Profile, status.BindIP)
	for _, c := range []services.Capability{services.APT, services.RPM, services.OCI} {
		if observation, ok := status.Capabilities[c]; ok {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s: initialization=%s health=%s:%s management_auth=%s:%s data=%s:%s observed_at=%s\n", c, observation.Initialization.State, observation.Health.State, observation.Health.Reason, observation.ManagementAuth.State, observation.ManagementAuth.Reason, observation.Data.State, observation.Data.Reason, observation.ObservedAt.Format(time.RFC3339))
		}
	}
	for _, item := range status.Services {
		fmt.Fprintf(cmd.OutOrStdout(), "  %-20s %s\n", item.Name, item.State)
	}
	return nil
}

type libvirtNetworkXML struct {
	IP []struct {
		Address string `xml:"address,attr"`
	} `xml:"ip"`
}

func discoverLibvirtNetworkAddress(ctx context.Context, network string) (net.IP, error) {
	if network == "" {
		return nil, fmt.Errorf("services: libvirt network is required")
	}
	bin := os.Getenv("PILOT_VIRSH_BIN")
	if bin == "" {
		bin = "virsh"
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "net-dumpxml", network).Output()
	if err != nil {
		return nil, fmt.Errorf("services: inspect libvirt network %q: %w", network, err)
	}
	var parsed libvirtNetworkXML
	if err := xml.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("services: parse libvirt network %q: %w", network, err)
	}
	for _, entry := range parsed.IP {
		ip := net.ParseIP(strings.TrimSpace(entry.Address))
		if ip != nil && ip.To4() != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("services: libvirt network %q has no IPv4 gateway", network)
}
