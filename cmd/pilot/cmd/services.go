package cmd

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/services"
)

var (
	svcProfile string
	svcNetwork string
	svcJSON    bool
	svcConfirm bool
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

func init() {
	rootCmd.AddCommand(servicesCmd)
	servicesCmd.AddCommand(servicesUpCmd, servicesStatusCmd, servicesDownCmd, servicesPurgeCmd)
	servicesUpCmd.Flags().StringVar(&svcProfile, "profile", "dev-lite", "service profile name or YAML path")
	servicesUpCmd.Flags().StringVar(&svcNetwork, "network", "default", "libvirt network whose gateway receives service traffic")
	servicesUpCmd.Flags().BoolVar(&svcJSON, "json", false, "print machine-readable status")
	servicesStatusCmd.Flags().BoolVar(&svcJSON, "json", false, "print machine-readable status")
	servicesPurgeCmd.Flags().BoolVar(&svcConfirm, "confirm", false, "confirm removal of persistent service data")
}

func runServicesUp(cmd *cobra.Command, _ []string) error {
	cfg := loadConfig()
	profile, err := services.LoadProfile(svcProfile)
	if err != nil {
		return err
	}
	ip, err := discoverLibvirtNetworkAddress(context.Background(), svcNetwork)
	if err != nil {
		return err
	}
	m, err := services.NewManager(cfg.DataDir, nil)
	if err != nil {
		return err
	}
	if err := m.Up(context.Background(), profile, ip); err != nil {
		return err
	}
	status, err := m.Status(context.Background())
	if err != nil {
		return err
	}
	return printServiceStatus(cmd, status)
}

func runServicesStatus(cmd *cobra.Command, _ []string) error {
	cfg := loadConfig()
	m, err := services.NewManager(cfg.DataDir, nil)
	if err != nil {
		return err
	}
	status, err := m.Status(context.Background())
	if err != nil {
		return err
	}
	return printServiceStatus(cmd, status)
}

func runServicesDown(cmd *cobra.Command, _ []string) error {
	cfg := loadConfig()
	m, err := services.NewManager(cfg.DataDir, nil)
	if err != nil {
		return err
	}
	if err := m.Down(context.Background()); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ host services stopped; persistent data retained")
	return nil
}

func runServicesPurge(cmd *cobra.Command, _ []string) error {
	cfg := loadConfig()
	m, err := services.NewManager(cfg.DataDir, nil)
	if err != nil {
		return err
	}
	if err := m.Purge(context.Background(), svcConfirm); err != nil {
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
