// Command pilot-login-probe runs synthetic SSH logins as a least-privileged
// FreeIPA canary account against every configured host and publishes the
// outcome through node_exporter's textfile collector (GitHub issue
// kjelly/pilot#11). It never implements SSH itself and never execs
// anything but the system OpenSSH client with a pinned ssh_config.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kjelly/pilot/internal/loginprobe"
	"github.com/spf13/cobra"
)

// version/commit are set at build time via -ldflags (same contract as
// pilot-detection-engine).
var (
	version = "dev"
	commit  = "unknown"
)

// textfileWriteInterval is how often the textfile is rewritten between
// rounds (a round also writes it immediately when it finishes).
const textfileWriteInterval = 15 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit status: 0 on success,
// the code carried by an exitError (probe uses 2 for "a target failed"),
// and 1 for any other error.
func run(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.Execute()
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	fmt.Fprintln(stderr, "Error:", err)
	return 1
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pilot-login-probe",
		Short: "Pilot login probe — external SSH/PAM login canary for FreeIPA-enrolled hosts",
		// run() prints errors itself so an exitError carries only a status.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd(), newServeCmd(), newConfigCmd(), newProbeCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the binary version and commit",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "pilot-login-probe %s (%s)\n", version, commit)
			return nil
		},
	}
}

func newConfigCmd() *cobra.Command {
	var configPath string
	cfgCmd := &cobra.Command{Use: "config", Short: "Configuration operations"}
	validate := &cobra.Command{
		Use:   "validate",
		Short: "Validate config.yml without probing anything",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := loginprobe.LoadConfig(configPath); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "config valid")
			return nil
		},
	}
	validate.Flags().StringVar(&configPath, "config", "", "path to config.yml (required)")
	_ = validate.MarkFlagRequired("config")
	cfgCmd.AddCommand(validate)
	return cfgCmd
}

func newServeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Probe every target on the configured cadence until terminated",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.yml (required)")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// probeOutput is one line of `probe --json`.
type probeOutput struct {
	Target     string `json:"target"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Stage      string `json:"stage"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	Summary    string `json:"summary,omitempty"`
}

func newProbeCmd() *cobra.Command {
	var configPath, only string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Run one round now and print the outcome (no textfile write); exit 2 when any target failed",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loginprobe.LoadConfig(configPath)
			if err != nil {
				return err
			}
			if only != "" {
				var kept []loginprobe.Target
				for _, t := range cfg.Targets {
					if t.Name == only {
						kept = append(kept, t)
					}
				}
				if len(kept) == 0 {
					return fmt.Errorf("target %q is not configured", only)
				}
				cfg.Targets = kept
			}
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelError}))
			prober := loginprobe.NewProber(cfg, loginprobe.NewRunner(cfg, homeDir()), nil, logger)
			outcomes := prober.Round(cmd.Context())
			failed := false
			rows := make([]probeOutput, 0, len(outcomes))
			for _, o := range outcomes {
				if o.Canceled {
					return fmt.Errorf("interrupted before %s was probed", o.Target.Name)
				}
				if o.Stage != loginprobe.StageOK {
					failed = true
				}
				rows = append(rows, probeOutput{Target: o.Target.Name, Host: o.Target.Host, Port: o.Target.Port, Stage: string(o.Stage), ExitCode: o.ExitCode, DurationMS: o.Duration.Milliseconds(), Summary: o.Summary})
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(rows); err != nil {
					return err
				}
			} else {
				for _, r := range rows {
					fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\texit=%d\t%dms\t%s\n", r.Target, r.Host, r.Stage, r.ExitCode, r.DurationMS, r.Summary)
				}
			}
			if failed {
				return &exitError{code: 2}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.yml (required)")
	cmd.Flags().StringVar(&only, "target", "", "probe only this configured target name")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print a JSON array instead of tab-separated lines")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// exitError carries a specific exit status without a message (cobra prints
// the error text otherwise).
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func homeDir() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return d
	}
	if d, err := os.UserHomeDir(); err == nil && d != "" {
		return d
	}
	return os.TempDir()
}

func runServe(ctx context.Context, configPath string) error {
	cfg, err := loginprobe.LoadConfig(configPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	metrics := loginprobe.NewMetrics(cfg.Targets)
	prober := loginprobe.NewProber(cfg, loginprobe.NewRunner(cfg, homeDir()), metrics, logger)

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	onWriteError := func(err error) { logger.Warn("write metrics textfile", "path", cfg.Textfile, "error", err) }
	stopWriter := metrics.Registry.StartWriter(cfg.Textfile, textfileWriteInterval, metrics.LastWrite, onWriteError)
	defer stopWriter()

	logger.Info("pilot-login-probe starting", "version", version, "commit", commit, "targets", len(cfg.Targets), "interval", cfg.Interval.String(), "user", cfg.User)
	sched := loginprobe.NewScheduler(cfg.Interval)
	sched.Run(ctx, func(ctx context.Context) {
		outcomes := prober.Round(ctx)
		if ctx.Err() != nil {
			// Stopping mid-round: the canceled attempts were not recorded,
			// and this partial round must not be written or counted.
			return
		}
		metrics.RoundDone(sched.Overruns.Load())
		ok := 0
		for _, o := range outcomes {
			if o.Stage == loginprobe.StageOK {
				ok++
			}
		}
		logger.Info("round complete", "targets", len(outcomes), "ok", ok)
		metrics.LastWrite.Set(float64(time.Now().Unix()))
		if err := metrics.Registry.WriteTextfile(cfg.Textfile); err != nil {
			onWriteError(err)
		}
	})
	logger.Info("pilot-login-probe stopping")
	return nil
}
