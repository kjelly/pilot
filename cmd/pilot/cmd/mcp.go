// mcp.go implements `pilot mcp serve`: a stdio MCP server exposing
// pilot edit's semantic actions to external coding agents, per
// docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md.
// See mcp_edit_tools.go for the tool set: capabilities/inspect/plan are
// always registered; pilot_edit_apply is registered only when
// --allow-write is set. See mcp_diagnose_tools.go for pilot_diagnose_*, a
// separate, live-host-reaching tool family registered only when
// --enable-diagnose is set, plus pilot_diagnose_run — a caller-supplied,
// not-a-fixed-allow-list command runner gated by its own, independent
// --enable-diagnose-raw flag.
package cmd

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

var (
	mcpDir        string
	mcpTransport  string
	mcpAuditDir   string
	mcpAllowWrite bool

	mcpEnableDiagnose      bool
	mcpEnableDiagnoseRaw   bool
	mcpDiagnoseInventory   string
	mcpDiagnoseStepTimeout time.Duration

	mcpEnableRepair bool
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Model Context Protocol server for pilot edit",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve pilot edit's semantic actions over MCP",
	Long: `pilot mcp serve exposes pilot edit's semantic edit actions to external
coding agents over the Model Context Protocol. Without --allow-write it only
registers read-only tools (capabilities/inspect/plan) — no tool call can
write to the workspace. --allow-write additionally registers pilot_edit_apply,
which applies a previously-created plan under a mutation lock with automatic
rollback on failure.`,
	RunE: runMCPServe,
}

func init() {
	mcpServeCmd.Flags().StringVar(&mcpDir, "dir", ".", "workspace root this MCP server exposes (the only directory it may read or write)")
	mcpServeCmd.Flags().StringVar(&mcpTransport, "transport", "stdio", "MCP transport; only \"stdio\" is supported")
	mcpServeCmd.Flags().StringVar(&mcpAuditDir, "audit-dir", "", "directory for plan/apply audit artifacts (default <dir>/.pilot/audit/edit)")
	mcpServeCmd.Flags().BoolVar(&mcpAllowWrite, "allow-write", false, "register mutation tools (not yet implemented)")
	mcpServeCmd.Flags().BoolVar(&mcpEnableDiagnose, "enable-diagnose", false, "register live-host diagnostic tools (pilot_diagnose_sudo/pilot_diagnose_dns) that run a fixed, read-only ansible ad-hoc allow-list against --diagnose-inventory; independent of --allow-write (live-host reach is a different risk axis than local-file mutation)")
	mcpServeCmd.Flags().BoolVar(&mcpEnableDiagnoseRaw, "enable-diagnose-raw", false, "register pilot_diagnose_run, which runs a caller-supplied command (ansible's command module, no shell) against --diagnose-inventory — NOT a fixed allow-list; independent of --enable-diagnose")
	mcpServeCmd.Flags().StringVar(&mcpDiagnoseInventory, "diagnose-inventory", "", "ansible inventory path pilot_diagnose_* tools may target; defaults to <dir>/inventory.yml when --enable-diagnose or --enable-diagnose-raw is set and this is left empty")
	mcpServeCmd.Flags().DurationVar(&mcpDiagnoseStepTimeout, "diagnose-step-timeout", 20*time.Second, "per ad-hoc step timeout for pilot_diagnose_* tools")
	mcpServeCmd.Flags().BoolVar(&mcpEnableRepair, "enable-repair", false, "register the repair tool family (pilot_repair_capabilities/pilot_repair_plan/pilot_repair_apply) — a distinct, R1-only, human-approved-by-the-caller live remediation capability against --diagnose-inventory; independent of --enable-diagnose/--enable-diagnose-raw/--allow-write. The Agent Runtime must never receive a session with this flag set — only the Agent Controller or a trusted operator should")

	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}

func runMCPServe(cmd *cobra.Command, args []string) error {
	if mcpTransport != "stdio" {
		return fmt.Errorf("unsupported --transport %q: only \"stdio\" is implemented", mcpTransport)
	}

	// Canonicalize once, at startup — no tool call takes a workspace path
	// argument, so nothing after this point can redirect either root.
	canonicalDir, err := filepath.Abs(mcpDir)
	if err != nil {
		return fmt.Errorf("resolve --dir: %w", err)
	}
	auditDir := mcpAuditDir
	if auditDir == "" {
		auditDir = filepath.Join(canonicalDir, ".pilot", "audit", "edit")
	}
	canonicalAuditDir, err := filepath.Abs(auditDir)
	if err != nil {
		return fmt.Errorf("resolve --audit-dir: %w", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "pilot-edit", Version: rootCmd.Version}, nil)
	registerEditTools(server, editMCPToolsOptions{
		Dir:          canonicalDir,
		AuditDir:     canonicalAuditDir,
		WriteEnabled: mcpAllowWrite,
	})

	if mcpEnableDiagnose || mcpEnableDiagnoseRaw || mcpEnableRepair {
		// Same directory as --dir in every real deployment (hosts.yml and
		// inventory.yml are sibling files there) — default to it so a
		// flag-value-swallowing typo like `--diagnose-inventory --dir
		// /path` can't silently point diagnostics at a bogus path (it now
		// falls back to a sane default instead of an empty string).
		diagnoseInventoryPath := mcpDiagnoseInventory
		if diagnoseInventoryPath == "" {
			diagnoseInventoryPath = filepath.Join(canonicalDir, "inventory.yml")
		}
		canonicalDiagnoseInventory, err := filepath.Abs(diagnoseInventoryPath)
		if err != nil {
			return fmt.Errorf("resolve --diagnose-inventory: %w", err)
		}
		runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
		if err != nil {
			return fmt.Errorf("prepare ansible runtime for --enable-diagnose/--enable-diagnose-raw/--enable-repair: %w", err)
		}
		diagnoseOpts := diagnoseMCPToolsOptions{
			Inventory:      canonicalDiagnoseInventory,
			AuditDir:       canonicalAuditDir,
			StepTimeout:    mcpDiagnoseStepTimeout,
			AnsibleRuntime: runtime,
		}
		if mcpEnableDiagnose {
			registerDiagnoseTools(server, diagnoseOpts)
		}
		if mcpEnableDiagnoseRaw {
			registerDiagnoseRunTool(server, diagnoseOpts)
		}
		if mcpEnableRepair {
			// A SEPARATE tool family and options struct from diagnose's
			// own (see mcp_repair_tools.go) even though it shares the
			// same inventory/runtime — an Agent Runtime session started
			// with --enable-diagnose alone must never gain repair
			// capability just because the two happen to read the same
			// inventory path.
			registerRepairTools(server, repairMCPToolsOptions{
				Inventory:      canonicalDiagnoseInventory,
				AuditDir:       canonicalAuditDir,
				StepTimeout:    mcpDiagnoseStepTimeout,
				AnsibleRuntime: runtime,
			})
		}
	}

	// StdioTransport owns stdout exclusively from here on: nothing in
	// this command path writes to cmd.OutOrStdout() after this call, so
	// stdout only ever carries the transport's own newline-delimited
	// JSON-RPC (spec's "MCP stdout 不得包含 TUI 輸出" invariant).
	return server.Run(cmd.Context(), &mcp.StdioTransport{})
}
