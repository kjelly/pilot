// mcp.go implements `pilot mcp serve`: a stdio MCP server exposing
// pilot edit's semantic actions to external coding agents, per
// docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md.
// See mcp_edit_tools.go for the three tools this Phase 3 pass
// registers (capabilities/inspect/plan) — no write/apply tool exists
// yet (Phase 4).
package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

var (
	mcpDir        string
	mcpTransport  string
	mcpAuditDir   string
	mcpAllowWrite bool
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
write to the workspace. --allow-write does not yet enable anything further
in this build; the write/apply tool is not implemented.`,
	RunE: runMCPServe,
}

func init() {
	mcpServeCmd.Flags().StringVar(&mcpDir, "dir", ".", "workspace root this MCP server exposes (the only directory it may read or write)")
	mcpServeCmd.Flags().StringVar(&mcpTransport, "transport", "stdio", "MCP transport; only \"stdio\" is supported")
	mcpServeCmd.Flags().StringVar(&mcpAuditDir, "audit-dir", "", "directory for plan/apply audit artifacts (default <dir>/.pilot/audit/edit)")
	mcpServeCmd.Flags().BoolVar(&mcpAllowWrite, "allow-write", false, "register mutation tools (not yet implemented)")

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

	// StdioTransport owns stdout exclusively from here on: nothing in
	// this command path writes to cmd.OutOrStdout() after this call, so
	// stdout only ever carries the transport's own newline-delimited
	// JSON-RPC (spec's "MCP stdout 不得包含 TUI 輸出" invariant).
	return server.Run(cmd.Context(), &mcp.StdioTransport{})
}
