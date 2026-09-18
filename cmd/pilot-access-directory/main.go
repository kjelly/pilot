// Command pilot-access-directory is pilot-access-directory's stateless,
// read-only FreeIPA-backed discovery/routing backend (docs/tmp/now/
// spec.md). It never reads roster, inventory, or any local persistent
// application state — every response comes from a live FreeIPA query, and
// it is a discovery/routing PROJECTION only (D1): it never replaces a
// Gateway's own fresh authorization.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kjelly/pilot/internal/directoryapi"
	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/sessionaudit"
	"github.com/kjelly/pilot/internal/systemdactivation"
	"github.com/spf13/cobra"
)

// version/commit are set at build time via -ldflags (scripts/build-pilot-access-directory.sh).
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:           "pilot-access-directory",
		Short:         "Pilot Access Directory — stateless, read-only FreeIPA-backed discovery/routing",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newVersionCmd(), newServeCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the binary version and commit",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("pilot-access-directory %s (%s)\n", version, commit)
			return nil
		},
	}
}

func newServeCmd() *cobra.Command {
	var configPath string
	var systemdSocket bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the access-directory API until terminated",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, systemdSocket)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to access-directory.yaml (required)")
	cmd.Flags().BoolVar(&systemdSocket, "systemd-socket", false, "use the systemd-activated socket (fd 3) instead of binding socket_path directly")
	cmd.MarkFlagRequired("config")
	return cmd
}

func runServe(ctx context.Context, configPath string, systemdSocket bool) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	providerCfg := freeipaaccess.Config{
		Servers:          cfg.FreeIPA.Servers,
		CAFile:           cfg.FreeIPA.CAFile,
		ServicePrincipal: cfg.FreeIPA.ServicePrincipal,
		KeytabPath:       cfg.FreeIPA.Keytab,
		RequestTimeout:   cfg.requestTimeout(),
	}
	// freeipaaccess.Client already implements both Provider and
	// HostgroupFinder (docs/tmp/now/spec.md §8 Phase 0) — no separate
	// client type is needed for hostgroup discovery.
	client, err := freeipaaccess.NewClient(providerCfg)
	if err != nil {
		return fmt.Errorf("build freeipa client: %w", err)
	}

	dirCfg := directoryapi.DirectoryConfig{
		ID:                     cfg.Directory.ID,
		TargetHostgroupPrefix:  cfg.targetHostgroupPrefix(),
		GatewayHostgroupPrefix: cfg.gatewayHostgroupPrefix(),
	}
	// NewEmitter is fail-soft (see its doc comment): an unreachable local
	// syslog never blocks this service from starting.
	emitter, _ := sessionaudit.NewEmitter("pilot-access-directory")
	srv := directoryapi.NewServer(dirCfg, client, client, emitter, logger)
	srv.PortalUserGroup = cfg.Directory.PortalUserGroup

	ln, err := listener(cfg, systemdSocket)
	if err != nil {
		return fmt.Errorf("build listener: %w", err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	logger.Info("pilot-access-directory serving",
		"directory_id", dirCfg.ID,
		"target_hostgroup_prefix", dirCfg.TargetHostgroupPrefix,
		"gateway_hostgroup_prefix", dirCfg.GatewayHostgroupPrefix,
		"socket", cfg.socketPath(), "systemd_socket", systemdSocket)

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.requestTimeout())
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// listener builds either the systemd-activated listener (fd 3) or a plain
// Unix socket bind at cfg.socketPath(), removing a stale socket file left
// behind by an unclean previous shutdown first — matching
// cmd/pilot-access-gateway's own listener() exactly.
func listener(cfg Config, systemdSocket bool) (net.Listener, error) {
	if systemdSocket {
		return systemdactivation.Listener()
	}
	path := cfg.socketPath()
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	}
	return net.Listen("unix", path)
}
