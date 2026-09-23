// Command pilot-access-gateway is the stateless, read-only FreeIPA-backed
// access gateway backend (docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md). It never reads roster,
// inventory, or any local persistent application state — every access
// decision comes from a live FreeIPA query, scoped to this gateway's own
// gateway.target_hostgroup.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kjelly/pilot/internal/accessportal"
	"github.com/kjelly/pilot/internal/freeipaaccess"
	"github.com/kjelly/pilot/internal/gatewayapi"
	"github.com/kjelly/pilot/internal/systemdactivation"
	"github.com/spf13/cobra"
)

// version/commit are set at build time via -ldflags (scripts/build-pilot-access-gateway.sh).
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:           "pilot-access-gateway",
		Short:         "Pilot Access Gateway — stateless, read-only FreeIPA-backed access gateway",
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
			fmt.Printf("pilot-access-gateway %s (%s)\n", version, commit)
			return nil
		},
	}
}

func newServeCmd() *cobra.Command {
	var configPath string
	var systemdSocket bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the access-gateway API until terminated",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, systemdSocket)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to access-gateway.yaml (required)")
	cmd.Flags().BoolVar(&systemdSocket, "systemd-socket", false, "use the systemd-activated socket (fd 3) instead of binding socket_path directly")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func runServe(ctx context.Context, configPath string, systemdSocket bool) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	providerCfg := freeipaaccess.Config{
		Servers:          cfg.Gateway.FreeIPA.Servers,
		CAFile:           cfg.Gateway.FreeIPA.CAFile,
		ServicePrincipal: cfg.Gateway.FreeIPA.ServicePrincipal,
		KeytabPath:       cfg.Gateway.FreeIPA.Keytab,
		RequestTimeout:   cfg.requestTimeout(),
	}
	provider, err := freeipaaccess.NewClient(providerCfg)
	if err != nil {
		return fmt.Errorf("build freeipa client: %w", err)
	}

	gw := accessportal.GatewayConfig{
		ID:              cfg.Gateway.ID,
		Scope:           cfg.Gateway.Scope,
		TargetHostgroup: cfg.Gateway.TargetHostgroup,
	}
	resolver := accessportal.NewResolver(provider, gw)
	srv := gatewayapi.NewServer(gw, provider, resolver, logger)
	srv.PortalUserGroup = cfg.Gateway.PortalUserGroup
	srv.RecordingPolicy = gatewayapi.RecordingPolicy{
		Mode:            cfg.recordingMode(),
		FailurePolicy:   cfg.recordingFailurePolicy(),
		QueueEvents:     cfg.recordingQueueEvents(),
		FlushIntervalMS: cfg.recordingFlushInterval().Milliseconds(),
	}
	if url := cfg.sessionStoreURL(); url != "" {
		token, err := loadSessionStoreIngestToken(cfg.Gateway.Recording.SessionStoreIngestTokenFile)
		if err != nil {
			return fmt.Errorf("load session-store ingest token: %w", err)
		}
		srv.RecordingPolicy.SessionStoreURL = url
		srv.RecordingPolicy.SessionStoreCAFile = cfg.sessionStoreCAFile()
		srv.RecordingPolicy.SessionStoreIngestToken = token
	}

	ln, err := listener(cfg, systemdSocket)
	if err != nil {
		return fmt.Errorf("build listener: %w", err)
	}
	defer ln.Close() //nolint:errcheck

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	logger.Info("pilot-access-gateway serving",
		"gateway_id", gw.ID, "gateway_scope", gw.Scope, "target_hostgroup", gw.TargetHostgroup,
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
// behind by an unclean previous shutdown first — spec.md §29: each
// gateway host owns its own local socket, never shared.
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
