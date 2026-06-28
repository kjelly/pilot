package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/anomalyco/pilot/internal/app"
	"github.com/anomalyco/pilot/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start the Model Context Protocol (MCP) stdio server.",
	Long:  "mcp starts an interactive JSON-RPC 2.0 stdio server, exposing pilot's tool registry to external AI agents.",
	RunE:  runMcp,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}

func runMcp(cmd *cobra.Command, args []string) error {
	noTUI = true

	ctx := context.Background()
	appOpts := app.Options{
		NoTUI:  true,
		Banner: false,
	}

	res, err := setupRunWithOpts(ctx, appOpts)
	if err != nil {
		return err
	}
	defer res.Store.Close()

	registry := res.BuildRegistry("", "")

	server := mcp.NewServer(registry)
	fmt.Fprintln(os.Stderr, "🚀 starting pilot mcp server over stdin/stdout transport...")
	return server.Start(ctx)
}
