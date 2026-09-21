// webhook.go implements `pilot webhook lint/status/flush` (design spec
// §34): the outbound state webhook's read-only inspection and
// operator-triggered flush commands. No plain deploy/reconcile/access/
// gateway-scope command ever opens the outbox store when
// integrations.yaml is absent (design spec §7.1/§37's fast path) — only
// these subcommands do, since the operator explicitly asked for them.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
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

	webhookSendTestDir               string
	webhookSendTestName              string
	webhookSendTestOperation         string
	webhookSendTestResult            string
	webhookSendTestEffects           []string
	webhookSendTestInventory         string
	webhookSendTestVaultPasswordFile string
	webhookSendTestWorkflowID        string
	webhookSendTestShowRequest       bool
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

var webhookSendTestCmd = &cobra.Command{
	Use:   "send-test",
	Short: "Send one synthetic terminal event now, to test connectivity/auth/payload shape",
	Long: `pilot webhook send-test builds one event exactly the way a real
deploy/reconcile terminal event would (same auth headers, TLS, envelope
shape) and POSTs it once to the target webhook's endpoint.

It never touches the durable outbox: no row is enqueued, no sequence is
consumed, no cursor advances, and a failed attempt is never retried. Use
it to check that integrations.yaml's endpoint/auth/CA are reachable and
to see what a real payload looks like — not to actually publish state.

If --inventory is omitted, the event carries no snapshot/diff (a
metadata-only "projection unavailable" event). Pilot first auto-detects
<dir>/inventory.yml (or inventory.yaml); pass --inventory to override it.
The detected inventory exercises a real user_host_access_v1 projection
build.`,
	RunE: runWebhookSendTest,
}

func init() {
	webhookLintCmd.Flags().StringVar(&webhookLintDir, "dir", ".", "workspace directory containing integrations.yaml")
	webhookStatusCmd.Flags().StringVar(&webhookStatusDir, "dir", ".", "workspace directory containing integrations.yaml")
	webhookFlushCmd.Flags().StringVar(&webhookFlushDir, "dir", ".", "workspace directory containing integrations.yaml")
	webhookFlushCmd.Flags().StringVar(&webhookFlushName, "name", "", "flush only this webhook (default: all enabled webhooks)")
	webhookFlushCmd.Flags().BoolVar(&webhookFlushForce, "force", false, "ignore next_attempt_at — still never steals a live claim or skips a paused webhook")

	webhookSendTestCmd.Flags().StringVar(&webhookSendTestDir, "dir", ".", "workspace directory containing integrations.yaml")
	webhookSendTestCmd.Flags().StringVar(&webhookSendTestName, "name", "", "webhook to target (required if more than one is enabled)")
	webhookSendTestCmd.Flags().StringVar(&webhookSendTestOperation, "operation", "reconcile", "operation to simulate: deploy or reconcile")
	webhookSendTestCmd.Flags().StringVar(&webhookSendTestResult, "result", "success", "result to simulate: success, failure, or cancelled")
	webhookSendTestCmd.Flags().StringArrayVar(&webhookSendTestEffects, "effect", nil, "an effect to claim (e.g. access.hbac); repeatable — only needed if the target rule uses effects_any")
	webhookSendTestCmd.Flags().StringVar(&webhookSendTestInventory, "inventory", "", "inventory to build a real projection from (default: auto-detect <dir>/inventory.yml)")
	webhookSendTestCmd.Flags().StringVar(&webhookSendTestVaultPasswordFile, "vault-password-file", "", "ansible-vault password file, if --inventory needs one")
	webhookSendTestCmd.Flags().StringVar(&webhookSendTestWorkflowID, "workflow-id", "", "workflow_id to use (default: a fresh UUID)")
	webhookSendTestCmd.Flags().BoolVar(&webhookSendTestShowRequest, "show-request", false, "display the outgoing request with auth secrets redacted (body included)")

	webhookCmd.AddCommand(webhookLintCmd, webhookStatusCmd, webhookFlushCmd, webhookSendTestCmd)
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
		if w.Auth.SecretFile != "" {
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

func runWebhookSendTest(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	cfgPath := outbound.DefaultConfigPath(webhookSendTestDir)
	cfg, err := outbound.LoadConfigFile(cfgPath)
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("no integrations.yaml in %s — nothing to send", webhookSendTestDir)
	}
	if err := cfg.CheckReadiness(); err != nil {
		return fmt.Errorf("readiness: %w", err)
	}

	target, err := resolveSendTestWebhook(cfg, webhookSendTestName)
	if err != nil {
		return err
	}

	operation := outbound.OperationKind(webhookSendTestOperation)
	if operation != outbound.OperationDeploy && operation != outbound.OperationReconcile {
		return fmt.Errorf("--operation must be deploy or reconcile, got %q", webhookSendTestOperation)
	}
	result := outbound.ResultClass(webhookSendTestResult)
	switch result {
	case outbound.ResultSuccess, outbound.ResultFailure, outbound.ResultCancelled:
	default:
		return fmt.Errorf("--result must be success, failure, or cancelled, got %q", webhookSendTestResult)
	}

	rule, ok := outbound.MatchEventRule(target, operation, result, webhookSendTestEffects)
	if !ok {
		return fmt.Errorf("webhook %q has no events[] rule matching operation=%s result=%s effects=%v — check integrations.yaml, or pass --effect", target.Name, operation, result, webhookSendTestEffects)
	}

	secret, ok := outbound.ResolveAuthSecret(target.Auth, os.LookupEnv)
	if !ok {
		return fmt.Errorf("%s (webhook %q) is not available", outbound.AuthSecretSource(target.Auth), target.Name)
	}

	now := time.Now()
	workflowID := webhookSendTestWorkflowID
	if workflowID == "" {
		workflowID = newWorkflowID()
	}
	eventID := uuid.NewString()

	inventoryPath := webhookSendTestInventory
	if inventoryPath == "" {
		inventoryPath = autoDetectWebhookTestInventory(webhookSendTestDir)
		if inventoryPath != "" {
			fmt.Fprintf(out, "ℹ auto-detected inventory: %s\n", inventoryPath)
		}
	}

	proj := buildOutboundProjection(cmd.Context(), out, PublishTerminalWorkflowInput{
		WorkspaceDir: webhookSendTestDir,
		Inventory:    inventoryPath,
		Vault:        vaultInput{VaultPasswordFile: webhookSendTestVaultPasswordFile},
	}, now)

	opMeta := outbound.OperationMetadata{
		WorkflowID:             workflowID,
		Operation:              operation,
		Result:                 result,
		Effects:                webhookSendTestEffects,
		ApplicationConsistency: "confirmed_for_effects",
		ConfirmedEffects:       webhookSendTestEffects,
		StartedAt:              now,
		FinishedAt:             now,
	}
	// Authoritative is always false here — send-test never claims to be
	// a real declarative-state publication, regardless of --result.
	env, err := outbound.BuildEnvelope(outbound.BuildEnvelopeParams{
		SourceID: cfg.SourceID, PilotVersion: rootCmd.Version, WebhookName: target.Name,
		Sequence: 0, EventID: eventID, CreatedAt: now, Op: opMeta,
		Payload: rule.Payload, Projection: proj, Base: outbound.SnapshotRef{}, Bootstrap: true,
		Target: proj.Snapshot, Authoritative: false,
	})
	if err != nil {
		return fmt.Errorf("build envelope: %w", err)
	}
	body, _, err := outbound.FinalizeEnvelope(env)
	if err != nil {
		return fmt.Errorf("finalize envelope: %w", err)
	}

	if webhookSendTestShowRequest {
		request, err := outbound.BuildTestRequest(cmd.Context(), target, rootCmd.Version, secret, eventID, body, now)
		if err != nil {
			return err
		}
		printWebhookTestRequest(out, request, body)
	}

	fmt.Fprintf(out, "→ POST %s (webhook=%s, event=%s, workflow=%s, operation=%s, result=%s, payload=%s)\n",
		target.Endpoint, target.Name, eventID, workflowID, operation, result, rule.Payload)
	fmt.Fprintln(out, "  TEST event: not recorded in the outbox, no cursor advance, no retry on failure")

	res, err := outbound.SendTestEvent(cmd.Context(), target, rootCmd.Version, secret, eventID, body, now)
	if err != nil {
		return fmt.Errorf("delivery attempt failed: %w", err)
	}
	fmt.Fprintf(out, "← %d\n", res.StatusCode)
	if len(res.Body) > 0 {
		fmt.Fprintf(out, "%s\n", res.Body)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned non-2xx status %d", res.StatusCode)
	}
	return nil
}

// autoDetectWebhookTestInventory finds the workspace's generated Ansible
// inventory. hosts.yml is deliberately not a candidate: it is Pilot's
// simplified source manifest, while --inventory must be consumable by
// ansible-inventory.
func autoDetectWebhookTestInventory(dir string) string {
	for _, name := range []string{"inventory.yml", "inventory.yaml"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

func printWebhookTestRequest(out io.Writer, req *http.Request, body []byte) {
	fmt.Fprintln(out, "  REQUEST:")
	fmt.Fprintf(out, "  %s %s\n", req.Method, req.URL.String())

	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := req.Header.Values(name)
		if strings.EqualFold(name, "Authorization") {
			values = []string{redactedAuthorization(values)}
		} else if strings.EqualFold(name, outbound.HeaderSignature256) {
			values = []string{"<redacted>"}
		}
		for _, value := range values {
			fmt.Fprintf(out, "  %s: %s\n", name, value)
		}
	}

	fmt.Fprintln(out, "  Body:")
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "  ", "  "); err != nil {
		fmt.Fprintf(out, "  %s\n", body)
		return
	}
	for _, line := range strings.Split(pretty.String(), "\n") {
		fmt.Fprintf(out, "  %s\n", line)
	}
}

func redactedAuthorization(values []string) string {
	if len(values) == 0 {
		return "<redacted>"
	}
	value := values[0]
	if scheme, _, ok := strings.Cut(value, " "); ok {
		return scheme + " <redacted>"
	}
	return "<redacted>"
}

// resolveSendTestWebhook picks the single enabled webhook send-test
// should target: name must disambiguate when more than one is enabled.
func resolveSendTestWebhook(cfg *outbound.Config, name string) (outbound.WebhookConfig, error) {
	var enabled []outbound.WebhookConfig
	for _, w := range cfg.Webhooks {
		if w.Enabled {
			enabled = append(enabled, w)
		}
	}
	if name != "" {
		for _, w := range enabled {
			if w.Name == name {
				return w, nil
			}
		}
		return outbound.WebhookConfig{}, fmt.Errorf("no enabled webhook named %q", name)
	}
	switch len(enabled) {
	case 0:
		return outbound.WebhookConfig{}, fmt.Errorf("no enabled webhooks configured")
	case 1:
		return enabled[0], nil
	default:
		return outbound.WebhookConfig{}, fmt.Errorf("multiple enabled webhooks configured; pass --name to pick one")
	}
}
