// Command pilot-session-store is docs/tmp/now/spec.md §28-§29's optional,
// stateful persistence backend for internal/sessionrecording's terminal
// event stream: an encrypted, durable index (internal/sessionstore) fed
// by a TLS-mandatory ingest API and read back through a separate
// Unix-socket admin API — two listeners, two trust models, one process.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kjelly/pilot/internal/ingesttoken"
	"github.com/kjelly/pilot/internal/sessionstore"
	"github.com/spf13/cobra"
)

// version/commit are set at build time via -ldflags (scripts/build-pilot-session-store.sh).
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:           "pilot-session-store",
		Short:         "Pilot Session Store — encrypted, durable persistence for terminal session recordings",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newVersionCmd(), newServeCmd(), newRetentionSweepCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the binary version and commit",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("pilot-session-store %s (%s)\n", version, commit)
			return nil
		},
	}
}

func newServeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the ingest and read APIs until terminated",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to session-store.yaml (required)")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func newRetentionSweepCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "retention-sweep",
		Short: "Run one retention sweep pass and exit (intended for a systemd timer per spec.md §28.5)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRetentionSweepCmd(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to session-store.yaml (required)")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// openStore loads the master key and opens the index database — shared
// by both "serve" and "retention-sweep" so they never diverge on how the
// database is opened or encrypted.
func openStore(cfg Config) (*sessionstore.Store, error) {
	key, err := sessionstore.LoadMasterKeyFile(cfg.Storage.MasterKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load master key: %w", err)
	}
	enc, err := sessionstore.NewEncryptor(cfg.Storage.KeyID, key)
	if err != nil {
		return nil, fmt.Errorf("build encryptor: %w", err)
	}
	store, err := sessionstore.Open(cfg.Storage.IndexDBPath, enc)
	if err != nil {
		return nil, fmt.Errorf("open index database: %w", err)
	}
	return store, nil
}

func runRetentionSweepCmd(ctx context.Context, configPath string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	store, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	purged, err := runRetentionSweep(ctx, store, cfg.retentionPeriod(), logger)
	if err != nil {
		return err
	}
	logger.Info("retention sweep complete", "purged_sessions", purged, "retention_days", cfg.Retention.RetentionDays)
	return nil
}

func runServe(ctx context.Context, configPath string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	store, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	signingKey, err := ingesttoken.LoadKeyFile(cfg.Ingest.SigningKeyFile)
	if err != nil {
		return fmt.Errorf("load ingest signing key: %w", err)
	}
	verifier, err := ingesttoken.NewVerifier(signingKey, nil)
	if err != nil {
		return fmt.Errorf("ingest signing key: %w", err)
	}
	logger.Info("ingest token verifier ready", "kid", verifier.KeyID())

	ingestSrv := &http.Server{Handler: newIngestServer(store, verifier, logger).routes()}
	cert, err := tls.LoadX509KeyPair(cfg.Ingest.TLSCertFile, cfg.Ingest.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("load ingest TLS certificate: %w", err)
	}
	// TLS mandatory (spec.md §28.2) — there is no plain-HTTP fallback
	// listener anywhere in this binary.
	tlsListener, err := tls.Listen("tcp", cfg.Ingest.ListenAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("bind ingest listener %s: %w", cfg.Ingest.ListenAddr, err)
	}
	defer func() { _ = tlsListener.Close() }()

	readSrv := newReadServer(store, cfg.Read.AuditorGroup, logger)
	readLn, err := readListener(cfg.readSocketPath())
	if err != nil {
		return fmt.Errorf("bind read socket %s: %w", cfg.readSocketPath(), err)
	}
	defer func() { _ = readLn.Close() }()

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errCh := make(chan error, 2)
	go func() { errCh <- ingestSrv.Serve(tlsListener) }()
	go func() { errCh <- readSrv.Serve(readLn) }()

	logger.Info("pilot-session-store serving",
		"ingest_addr", cfg.Ingest.ListenAddr, "read_socket", cfg.readSocketPath())

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = ingestSrv.Shutdown(shutdownCtx)
		return readSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// readListener binds the admin read Unix socket, removing a stale socket
// file left behind by an unclean previous shutdown first — matching
// cmd/pilot-access-directory and cmd/pilot-access-gateway's own
// listener() functions exactly.
func readListener(path string) (net.Listener, error) {
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	}
	return net.Listen("unix", path)
}
