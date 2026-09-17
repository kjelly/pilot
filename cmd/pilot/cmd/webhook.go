// webhook.go implements `pilot webhook lint/status/flush` (design spec
// §34): the outbound state webhook's read-only inspection and
// operator-triggered flush commands. No plain deploy/reconcile/access/
// gateway-scope command ever opens the outbox store when
// integrations.yaml is absent (design spec §7.1/§37's fast path) — only
// these subcommands do, since the operator explicitly asked for them.
package cmd

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/outbound"
	"github.com/kjelly/pilot/internal/store"
)

var (
	webhookLintDir    string
	webhookStatusDir  string
	webhookFlushDir   string
	webhookFlushName  string
	webhookFlushForce bool
)

var webhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Manage the outbound state webhook (integrations.yaml)",
}

var webhookLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Validate integrations.yaml — schema, URL/auth/delivery bounds, and (for enabled entries) CA file readability; makes no network call",
	RunE:  runWebhookLint,
}

var webhookStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show outbox delivery status per configured webhook",
	RunE:  runWebhookStatus,
}

var webhookFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Attempt delivery of due webhook events",
	RunE:  runWebhookFlush,
}

func init() {
	webhookLintCmd.Flags().StringVar(&webhookLintDir, "dir", ".", "workspace directory containing integrations.yaml")
	webhookStatusCmd.Flags().StringVar(&webhookStatusDir, "dir", ".", "workspace directory containing integrations.yaml")
	webhookFlushCmd.Flags().StringVar(&webhookFlushDir, "dir", ".", "workspace directory containing integrations.yaml")
	webhookFlushCmd.Flags().StringVar(&webhookFlushName, "name", "", "flush only this webhook (default: all enabled webhooks)")
	webhookFlushCmd.Flags().BoolVar(&webhookFlushForce, "force", false, "ignore next_attempt_at — still never steals a live claim or skips a paused webhook")

	webhookCmd.AddCommand(webhookLintCmd, webhookStatusCmd, webhookFlushCmd)
	rootCmd.AddCommand(webhookCmd)
}

func runWebhookLint(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	cfgPath := outbound.DefaultConfigPath(webhookLintDir)
	cfg, err := outbound.LoadConfigFile(cfgPath)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Fprintln(out, "no integrations.yaml — outbound webhook disabled")
		return nil
	}
	fmt.Fprintln(out, "✓ integrations.yaml valid")
	for _, w := range cfg.Webhooks {
		fmt.Fprintf(out, "✓ webhook %s (enabled=%v)\n  events: %d\n  projection: %s\n", w.Name, w.Enabled, len(w.Events), w.Projection)
	}
	if err := cfg.CheckReadiness(); err != nil {
		return fmt.Errorf("readiness: %w", err)
	}
	for _, w := range cfg.Webhooks {
		if !w.Enabled {
			continue
		}
		if _, ok := os.LookupEnv(w.Auth.SecretEnv); !ok {
			fmt.Fprintf(out, "⚠ webhook %s: environment variable %s is not set — delivery will remain pending until it is\n", w.Name, w.Auth.SecretEnv)
		}
	}
	return nil
}

// openWebhookOutbox loads integrations.yaml, and — only if it exists —
// ensures the workspace's history.db schema is current (via
// store.Open), secures its permissions (design spec §37), opens a
// dedicated outbox connection, binds/reconciles it against cfg (design
// spec §7.4.1), and returns everything a status/flush command needs. A
// nil cfg (no integrations.yaml) is not an error — callers must check
// for it and never open the store in that case.
func openWebhookOutbox(dir string) (o *outbound.SQLiteOutbox, cfg *outbound.Config, workspaceKey string, closeFn func() error, err error) {
	cfgPath := outbound.DefaultConfigPath(dir)
	cfg, err = outbound.LoadConfigFile(cfgPath)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if cfg == nil {
		return nil, nil, "", nil, nil
	}

	storeDir := resolvePilotDataDir()
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		return nil, nil, "", nil, err
	}
	dbPath := filepath.Join(storeDir, "history.db")
	if err := outbound.SecureHistoryDBPermissions(dbPath); err != nil {
		return nil, nil, "", nil, fmt.Errorf("secure history.db permissions: %w", err)
	}
	s, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if err := s.Close(); err != nil {
		return nil, nil, "", nil, err
	}
	if err := outbound.SecureHistoryDBPermissions(dbPath); err != nil {
		return nil, nil, "", nil, fmt.Errorf("secure history.db permissions: %w", err)
	}

	db, err := outbound.OpenOutboxDB(dbPath)
	if err != nil {
		return nil, nil, "", nil, err
	}

	workspaceKey, err = outbound.WorkspaceKey(dir)
	if err != nil {
		_ = db.Close()
		return nil, nil, "", nil, err
	}

	o = outbound.NewSQLiteOutbox(db)
	ctx := context.Background()
	now := time.Now()
	if err := o.CheckWorkspaceBinding(ctx, workspaceKey, cfg.SourceID, now); err != nil {
		_ = db.Close()
		return nil, nil, "", nil, err
	}
	if err := o.ReconcileWebhookConfig(ctx, workspaceKey, cfg); err != nil {
		_ = db.Close()
		return nil, nil, "", nil, err
	}
	return o, cfg, workspaceKey, db.Close, nil
}

func runWebhookStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	o, cfg, workspaceKey, closeFn, err := openWebhookOutbox(webhookStatusDir)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Fprintln(out, "no integrations.yaml — outbound webhook disabled")
		return nil
	}
	defer closeFn()

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPENDING\tDELIVERING\tPAUSED\tDEAD\tBLOCKED\tORPHANED\tLAST-ACK")
	ctx := context.Background()
	for _, w := range cfg.Webhooks {
		counts, err := o.StatusCounts(ctx, workspaceKey, cfg.SourceID, w.Name)
		if err != nil {
			return err
		}
		lastAck := counts.LastAckedID
		if lastAck == "" {
			lastAck = "-"
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
			w.Name, counts.Pending, counts.Delivering, counts.Paused, counts.Dead, counts.Blocked, counts.Orphaned, lastAck)
	}
	return tw.Flush()
}

func runWebhookFlush(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	o, cfg, workspaceKey, closeFn, err := openWebhookOutbox(webhookFlushDir)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Fprintln(out, "no integrations.yaml — outbound webhook disabled")
		return nil
	}
	defer closeFn()

	var identities []outbound.WebhookIdentity
	for _, w := range cfg.Webhooks {
		if webhookFlushName != "" && w.Name != webhookFlushName {
			continue
		}
		if !w.Enabled {
			continue
		}
		identities = append(identities, outbound.WebhookIdentity{
			WorkspaceKey: workspaceKey, SourceID: cfg.SourceID, WebhookName: w.Name, Config: w,
		})
	}
	if len(identities) == 0 {
		fmt.Fprintln(out, "no matching enabled webhooks to flush")
		return nil
	}

	d := &outbound.Dispatcher{
		Outbox:       o,
		Now:          time.Now,
		RNG:          rand.New(rand.NewSource(time.Now().UnixNano())),
		PilotVersion: rootCmd.Version,
		SecretLookup: os.LookupEnv,
	}
	opts := outbound.DefaultFlushOptions()
	opts.Force = webhookFlushForce
	opts.MaxClaimsPerWebhook = 100

	outcomes := d.FlushWebhooks(context.Background(), identities, opts)
	if len(outcomes) == 0 {
		fmt.Fprintln(out, "nothing due")
		return nil
	}
	for _, oc := range outcomes {
		switch {
		case oc.Delivered:
			fmt.Fprintf(out, "✓ webhook %s delivered (event=%s)\n", oc.WebhookName, oc.EventID)
		case oc.DeadLetter:
			fmt.Fprintf(out, "✗ webhook %s dead-lettered (event=%s, reason=%s)\n", oc.WebhookName, oc.EventID, oc.ErrorClass)
		case oc.Pending:
			fmt.Fprintf(out, "⚠ webhook %s pending retry (event=%s, reason=%s)\n", oc.WebhookName, oc.EventID, oc.ErrorClass)
		}
		if oc.Err != nil {
			fmt.Fprintf(out, "  (local error recording outcome: %v)\n", oc.Err)
		}
	}
	return nil
}
