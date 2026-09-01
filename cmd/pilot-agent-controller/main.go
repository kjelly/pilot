// Command pilot-agent-controller is the Agent Monitoring incident
// orchestrator runtime binary
// (docs/superpowers/specs/2026-09-01-agent-monitoring-phase-1-observe-only-controller-spec.md,
// .../2026-09-01-agent-monitoring-phase-3-human-approved-r1-remediation.md).
// `serve` receives Alertmanager webhooks, normalizes them into
// incidents, dispatches read-only diagnosis requests to an external
// Agent Runtime through a typed interface, and persists the result. The
// `serve` daemon itself never execs a shell, never holds an SSH
// credential, and never receives mutation/raw-command MCP capability —
// that boundary is unchanged by Phase 3. `remediation`/`incident` are
// separate, human-operator-only CLI subcommands (never called by the
// serve loop or the Agent) that persist R1 repair plans and record
// explicit human approval before ever invoking pilot's own separate
// repair MCP family (internal/agentcontroller.RepairClient) — see
// design doc §2's authority-separation diagram.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kjelly/pilot/internal/agentcontroller"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

// version/commit are set at build time via -ldflags.
var (
	version = "dev"
	commit  = "unknown"
)

const defaultStatusPath = "/run/pilot/agent-controller/status.json"

// schedulerTick is how often the scheduler polls for dispatchable
// incidents and republishes status/metrics — not user-configurable in
// Phase 1 (spec §13 does not require it to be).
const schedulerTick = 2 * time.Second

func main() {
	root := &cobra.Command{
		Use:           "pilot-agent-controller",
		Short:         "Pilot Agent Controller — observe-only incident orchestrator",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(
		newVersionCmd(),
		newConfigCmd(),
		newServeCmd(),
		newStatusCmd(),
		newDBCmd(),
		newIncidentCmd(),
		newRemediationCmd(),
	)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the binary version and commit",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("pilot-agent-controller %s (%s)\n", version, commit)
			return nil
		},
	}
}

func newConfigCmd() *cobra.Command {
	var configPath string
	cfgCmd := &cobra.Command{Use: "config", Short: "Configuration operations"}
	validate := &cobra.Command{
		Use:   "validate",
		Short: "Validate config.yaml without starting the service",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := agentcontroller.LoadConfig(configPath); err != nil {
				return err
			}
			fmt.Println("config valid")
			return nil
		},
	}
	validate.Flags().StringVar(&configPath, "config", "", "path to config.yaml (required)")
	validate.MarkFlagRequired("config")
	cfgCmd.AddCommand(validate)
	return cfgCmd
}

func newServeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the webhook ingress and dispatch scheduler until terminated",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.yaml (required)")
	cmd.MarkFlagRequired("config")
	return cmd
}

func runServe(ctx context.Context, configPath string) error {
	cfg, err := agentcontroller.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	secret := os.Getenv(cfg.WebhookSecretEnv)
	if secret == "" {
		return fmt.Errorf("environment variable %s (webhookSecretEnv) is empty — unauthenticated webhooks must fail closed", cfg.WebhookSecretEnv)
	}

	store, err := agentcontroller.OpenStore(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer store.Close()

	if recovered, err := store.RecoverInFlightRuns(time.Now()); err != nil {
		return fmt.Errorf("recover in-flight runs: %w", err)
	} else if recovered > 0 {
		fmt.Printf("recovered %d in-flight run(s) from an unclean shutdown\n", recovered)
	}

	dispatcher, err := buildDispatcher(cfg.Dispatcher)
	if err != nil {
		return fmt.Errorf("build dispatcher: %w", err)
	}

	srv := &agentcontroller.Server{
		Store:        store,
		Secret:       []byte(secret),
		MaxBodyBytes: cfg.MaxBodyBytes,
	}
	scheduler := &agentcontroller.Scheduler{
		Store:               store,
		Dispatcher:          dispatcher,
		MaxConcurrentRuns:   cfg.MaxConcurrentRuns,
		MaxRunsPerHost:      cfg.MaxRunsPerHost,
		MaxDispatchAttempts: 3,
		BaseBackoff:         10 * time.Second,
		MaxBackoff:          5 * time.Minute,
		DispatchTimeout:     time.Duration(cfg.Dispatcher.TimeoutSeconds) * time.Second,
	}

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: srv.Handler(),
	}

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	ticker := time.NewTicker(schedulerTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()
			_ = httpServer.Shutdown(shutdownCtx)
			<-serveErr
			return nil
		case err := <-serveErr:
			return err
		case <-ticker.C:
			if _, err := scheduler.RunOnce(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "scheduler pass error: %v\n", err)
			}
			publishStatus(store, cfg, srv)
		}
	}
}

func buildDispatcher(cfg agentcontroller.DispatcherConfig) (agentcontroller.AgentDispatcher, error) {
	switch cfg.Kind {
	case "fake":
		return &agentcontroller.FakeDispatcher{}, nil
	case "http":
		return agentcontroller.NewHTTPDispatcher(cfg.Endpoint, time.Duration(cfg.TimeoutSeconds)*time.Second), nil
	default:
		return nil, fmt.Errorf("unknown dispatcher kind %q", cfg.Kind)
	}
}

func publishStatus(store *agentcontroller.Store, cfg agentcontroller.Config, srv *agentcontroller.Server) {
	open, _ := store.CountIncidentsByStatus(agentcontroller.StatusOpen)
	investigating, _ := store.CountIncidentsByStatus(agentcontroller.StatusInvestigating)
	active, _ := store.CountActiveRuns()

	status := agentcontroller.Status{
		SchemaVersion: 1,
		State:         "healthy",
		Incidents:     agentcontroller.StatusIncidents{Open: open, Investigating: investigating},
		Runs:          agentcontroller.StatusRuns{Active: active},
		Dispatcher:    agentcontroller.StatusDispatcher{Kind: cfg.Dispatcher.Kind},
		Ingress: agentcontroller.StatusIngress{
			AuthFailures:       srv.AuthFailures.Load(),
			OversizeRejections: srv.OversizeRejections.Load(),
			IngestErrors:       srv.IngestErrors.Load(),
			IngestedEvents:     srv.IngestedEvents.Load(),
		},
	}
	if cfg.StatusPath != "" {
		_ = agentcontroller.WriteStatus(cfg.StatusPath, status)
	}
	if cfg.TextfileMetricsPath != "" {
		metrics := agentcontroller.MetricsSnapshot{
			Up:                  true,
			IncidentsOpen:       open,
			IncidentsInvesting:  investigating,
			RunsActive:          active,
			AuthFailuresTotal:   srv.AuthFailures.Load(),
			OversizeTotal:       srv.OversizeRejections.Load(),
			IngestErrorsTotal:   srv.IngestErrors.Load(),
			IngestedEventsTotal: srv.IngestedEvents.Load(),
		}
		_ = metrics.WriteTextfile(cfg.TextfileMetricsPath)
	}
}

func newStatusCmd() *cobra.Command {
	var statusPath, field string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Read the last-published status.json — never connects to a daemon socket",
		RunE: func(cmd *cobra.Command, args []string) error {
			status, err := agentcontroller.ReadStatus(statusPath)
			if err != nil {
				return err
			}
			if field != "" {
				return printStatusField(status, field)
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(status)
			}
			fmt.Printf("state=%s incidents.open=%d runs.active=%d\n", status.State, status.Incidents.Open, status.Runs.Active)
			return nil
		},
	}
	cmd.Flags().StringVar(&statusPath, "status-path", defaultStatusPath, "path to status.json")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the full status as JSON")
	cmd.Flags().StringVar(&field, "field", "", "print a single dot-path field (e.g. incidents.open)")
	return cmd
}

func printStatusField(status agentcontroller.Status, field string) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		return err
	}
	parts := strings.Split(field, ".")
	var cur any = generic
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return fmt.Errorf("field %q: %q is not an object", field, p)
		}
		v, ok := m[p]
		if !ok {
			return fmt.Errorf("field %q: no such key %q", field, p)
		}
		cur = v
	}
	fmt.Println(cur)
	return nil
}

func newDBCmd() *cobra.Command {
	dbCmd := &cobra.Command{Use: "db", Short: "Database operations"}

	var dbPath string
	check := &cobra.Command{
		Use:   "check",
		Short: "Run PRAGMA integrity_check against the state database",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := agentcontroller.OpenStoreReadOnly(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			result, err := store.IntegrityCheck()
			if err != nil {
				return err
			}
			fmt.Println(result)
			if result != "ok" {
				return fmt.Errorf("integrity_check failed: %s", result)
			}
			return nil
		},
	}
	check.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	check.MarkFlagRequired("db")

	var backupSrc, backupDst string
	backup := &cobra.Command{
		Use:   "backup",
		Short: "Write a consistent snapshot backup via SQLite VACUUM INTO",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(backupSrc); os.IsNotExist(err) {
				fmt.Println("source database does not exist; nothing to back up")
				return nil
			}
			if err := os.Remove(backupDst); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove stale backup %s: %w", backupDst, err)
			}
			db, err := sql.Open("sqlite", backupSrc)
			if err != nil {
				return fmt.Errorf("open %s: %w", backupSrc, err)
			}
			defer db.Close()
			if _, err := db.Exec(fmt.Sprintf("VACUUM INTO %s", quoteSQLiteString(backupDst))); err != nil {
				return fmt.Errorf("VACUUM INTO %s: %w", backupDst, err)
			}
			fmt.Printf("backup written: %s\n", backupDst)
			return nil
		},
	}
	backup.Flags().StringVar(&backupSrc, "db", "", "path to state.db (required)")
	backup.Flags().StringVar(&backupDst, "output", "", "path to write the backup (required)")
	backup.MarkFlagRequired("db")
	backup.MarkFlagRequired("output")

	dbCmd.AddCommand(check, backup)
	return dbCmd
}

func quoteSQLiteString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
