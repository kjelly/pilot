package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/config"
	"github.com/anomalyco/pilot/internal/logx"
)

var (
	cfgFile  string
	dataDir  string
	logLevel string // --log-level (persistent); default from $PILOT_LOG_LEVEL or "warn"
)

var rootCmd = &cobra.Command{
	Use:   "pilot",
	Short: "Spec-driven Ansible deployment tool",
	Long: `pilot solves correct software delivery with a spec → verify → apply
loop, disposable test environments, and TUI wizards. It focuses on three
problems:

  1. Deriving correct playbooks from specs: verification specs
     (docs/verification/*.md) are the source of truth — "pilot spec --lint"
     gates them, apply playbooks are written against them, and
     "pilot verify" checks every row.
  2. Fast spec-conformance validation with docker/VM: "pilot vm-target" /
     "pilot docker-target" spin up disposable environments; "vm-target test"
     runs syntax → apply → verify → idempotency in one go.
  3. Fast, convenient deployment into the architecture the user wants:
     inventories and group_vars are built with the interactive "pilot edit" /
     "pilot inventory generate" wizards, and "pilot deploy" walks component,
     stage, preview, and confirmation.`,
	Version: "0.2.0",
	// PersistentPreRun installs the diagnostic logger before any command
	// runs, so every `slog.Warn/Debug/...` call is leveled and formatted
	// consistently. User-facing UX output is unaffected (it never goes
	// through slog). The default level is WARN, overridable via --log-level
	// or $PILOT_LOG_LEVEL; $PILOT_LOG_FORMAT=json switches to JSON output.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		lvl := logLevel
		if lvl == "" {
			lvl = os.Getenv("PILOT_LOG_LEVEL")
		}
		logx.Init(lvl, os.Getenv("PILOT_LOG_FORMAT"), os.Stderr)
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default ~/.config/pilot/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "data directory for the history db and target state")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "diagnostic log level: debug|info|warn|error (default warn; also $PILOT_LOG_LEVEL)")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(doctorCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("pilot %s\n", rootCmd.Version)
	},
}

func loadConfig() *config.Config {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		slog.Warn("failed to load config; using defaults", "err", err)
		cfg = config.Default()
	}
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	return cfg
}
