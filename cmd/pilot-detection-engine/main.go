// Command pilot-detection-engine is the Detection Engine runtime binary
// (spec §7's CLI contract). It never execs, opens a shell, or accepts
// arbitrary commands — every subcommand is a fixed, narrow operation.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kjelly/pilot/internal/detection"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

// version/commit are set at build time via -ldflags (spec §6.2).
var (
	version = "dev"
	commit  = "unknown"
)

const defaultStatusPath = "/run/pilot/detection-engine/status.json"

func main() {
	root := &cobra.Command{
		Use:           "pilot-detection-engine",
		Short:         "Pilot Detection Engine — Thanos-driven adaptive anomaly detection",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(
		newVersionCmd(),
		newServeCmd(),
		newConfigCmd(),
		newStatusCmd(),
		newDBCmd(),
		newSignalsCmd(),
		newProviderCmd(),
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
			fmt.Printf("pilot-detection-engine %s (%s)\n", version, commit)
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
			if _, err := detection.LoadConfig(configPath); err != nil {
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
		Short: "Run the detection cycle scheduler until terminated",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.yaml (required)")
	cmd.MarkFlagRequired("config")
	return cmd
}

func runServe(ctx context.Context, configPath string) error {
	cfg, err := detection.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	profile, err := detection.LoadFeatureProfile(cfg.FeatureProfilePath)
	if err != nil {
		return fmt.Errorf("load feature profile: %w", err)
	}
	store, err := detection.OpenStore(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer store.Close()

	client := detection.NewThanosClient(cfg.MetricsSourceBaseURL, detection.QueryTimeout)
	engine := detection.NewEngine(profile, client, store, nil)

	provider, err := detection.NewManagedProviderFromConfig(cfg.ModelProvider)
	if err != nil {
		return fmt.Errorf("model provider: %w", err)
	}
	if provider != nil {
		engine.Provider = provider
		engine.ProviderProtocol = cfg.ModelProvider.Protocol
		engine.RateLimiter = detection.NewRateLimiter(detection.GlobalRateLimit)
	}

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	scheduler := detection.NewScheduler(detection.CycleInterval)
	var lastSuccess int64
	scheduler.Run(ctx, func(cycleCtx context.Context, evaluationTime int64) {
		start := time.Now()
		outcomes, err := engine.RunCycle(cycleCtx, evaluationTime)
		duration := time.Since(start).Seconds()
		success := err == nil
		if success {
			lastSuccess = evaluationTime
		}

		pending, _ := store.OutboxPendingCount()
		activeSignals := 0
		if episodes, err := store.ListActiveEpisodes(); err == nil {
			activeSignals = len(episodes)
		}

		modelStats := engine.LastModelStats
		modelStatus := detection.NewDisabledProviderStatus()
		if engine.Provider != nil {
			modelStatus = detection.StatusModelProvider{
				Enabled:  true,
				Healthy:  modelStats.ProviderUp,
				Protocol: engine.ProviderProtocol,
				Circuit:  engine.Provider.CircuitState(time.Now()),
			}
		}

		status := detection.Status{
			SchemaVersion: 1,
			State:         "healthy",
			Source:        detection.StatusSource{Healthy: success},
			Subjects:      detection.StatusSubjects{Active: len(outcomes)},
			ModelProvider: modelStatus,
			Signals:       detection.StatusSignals{Active: activeSignals},
			LastCycle:     detection.StatusLastCycle{Success: success},
		}
		if !success {
			status.State = "degraded"
		}
		_ = detection.WriteStatus(cfg.StatusPath, status)

		anomalyScore := map[[2]string]float64{}
		for _, o := range outcomes {
			if o.Valid && o.LocalScore.Valid {
				anomalyScore[[2]string{o.Host, o.LocalScore.Source}] = o.LocalScore.Score
			}
		}
		metrics := detection.MetricsSnapshot{
			Up:                          success,
			CycleDurationSeconds:        duration,
			CycleOverrunTotal:           scheduler.Overruns.Load(),
			LastSuccessTimestampSeconds: lastSuccess,
			SubjectsTotal:               len(outcomes),
			AnomalyScore:                anomalyScore,
			OutboxPending:               pending,
			ModelProviderUp:             modelStats.ProviderUp,
			ModelRequestTotal:           modelStats.RequestTotal,
			ModelRequestDurationSeconds: modelStats.RequestDuration,
			ModelCandidatesTotal:        modelStats.CandidatesTotal,
			ModelCandidatesDroppedTotal: modelStats.DroppedTotal,
			ModelCircuitOpen:            modelStats.CircuitOpen,
		}
		_ = metrics.WriteTextfile(cfg.TextfileMetricsPath)
	})
	return nil
}

func newStatusCmd() *cobra.Command {
	var statusPath, field string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Read the last-published status.json (spec §37) — never connects to a daemon socket",
		RunE: func(cmd *cobra.Command, args []string) error {
			status, err := detection.ReadStatus(statusPath)
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
			fmt.Printf("state=%s source.healthy=%t signals.active=%d\n", status.State, status.Source.Healthy, status.Signals.Active)
			return nil
		},
	}
	cmd.Flags().StringVar(&statusPath, "status-path", defaultStatusPath, "path to status.json")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the full status as JSON")
	cmd.Flags().StringVar(&field, "field", "", "print a single dot-path field (e.g. source.healthy)")
	return cmd
}

func printStatusField(status detection.Status, field string) error {
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
			store, err := detection.OpenStoreReadOnly(dbPath)
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
			// VACUUM INTO refuses to overwrite an existing file (spec §26
			// always backs up to the same fixed pre-upgrade.db path, so a
			// second upgrade's backup would otherwise fail on the first
			// upgrade's leftover snapshot — found via a real vm-target
			// upgrade run). This command's whole purpose is "the most
			// recent pre-upgrade snapshot", so removing a stale one here
			// is correct, not merely permissive.
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

func newSignalsCmd() *cobra.Command {
	signalsCmd := &cobra.Command{Use: "signals", Short: "Inspect SignalEvent episodes"}

	var dbPath string
	list := &cobra.Command{
		Use:   "list",
		Short: "List active (non-resolved) episodes",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := detection.OpenStoreReadOnly(dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			episodes, err := store.ListActiveEpisodes()
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(episodes)
		},
	}
	list.Flags().StringVar(&dbPath, "db", "", "path to state.db (required)")
	list.MarkFlagRequired("db")

	var showDBPath string
	show := &cobra.Command{
		Use:   "show <signal-id>",
		Short: "Show one episode by signal_id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := detection.OpenStoreReadOnly(showDBPath)
			if err != nil {
				return err
			}
			defer store.Close()
			episode, err := store.GetEpisode(args[0])
			if err != nil {
				return err
			}
			if episode == nil {
				return fmt.Errorf("no such signal_id: %s", args[0])
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(episode)
		},
	}
	show.Flags().StringVar(&showDBPath, "db", "", "path to state.db (required)")
	show.MarkFlagRequired("db")

	signalsCmd.AddCommand(list, show)
	return signalsCmd
}

// runProviderProbe exercises the real wire protocol (spec §31/§32) with a
// single synthetic candidate — no Pilot host data, no telemetry, no
// mutation — and reports the outcome. It never prints the API key or any
// request/response body (spec §33: no secret in evidence/diagnose output).
func runProviderProbe(ctx context.Context, provider *detection.ManagedProvider, protocol string) error {
	requestID, err := detection.NewULID()
	if err != nil {
		return fmt.Errorf("generate probe request_id: %w", err)
	}
	req := detection.ModelBatchRequest{
		SchemaVersion: 1,
		RequestID:     requestID,
		PromptVersion: detection.PromptVersion,
		WindowSeconds: 600,
		Candidates: []detection.ModelCandidateRequest{{
			CandidateID:    "probe",
			PilotHost:      "probe",
			Site:           "probe",
			EvaluationTime: time.Now().Unix(),
			Current:        map[string]float64{"probe_metric": 0},
		}},
	}

	start := time.Now()
	resp, err := provider.Score(ctx, req)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("provider probe failed (protocol=%s, %s): %w", protocol, elapsed.Round(time.Millisecond), err)
	}
	fmt.Printf("provider probe ok: protocol=%s status=%s elapsed=%s\n", protocol, resp.Status, elapsed.Round(time.Millisecond))
	return nil
}

func newProviderCmd() *cobra.Command {
	providerCmd := &cobra.Command{Use: "provider", Short: "Model provider operations (Stage B)"}
	var configPath string
	probe := &cobra.Command{
		Use:   "probe",
		Short: "Check model provider configuration/reachability",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := detection.LoadConfig(configPath)
			if err != nil {
				return err
			}
			if !cfg.ModelProvider.Enabled {
				fmt.Println("model provider disabled (Stage A)")
				return nil
			}
			provider, err := detection.NewManagedProviderFromConfig(cfg.ModelProvider)
			if err != nil {
				return err
			}
			return runProviderProbe(cmd.Context(), provider, cfg.ModelProvider.Protocol)
		},
	}
	probe.Flags().StringVar(&configPath, "config", "", "path to config.yaml (required)")
	probe.MarkFlagRequired("config")
	providerCmd.AddCommand(probe)
	return providerCmd
}
