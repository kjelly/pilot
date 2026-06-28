package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/ollama"
)

var modelsCmd = &cobra.Command{
	Use:   "models",
	Short: "List available Ollama models",
	RunE:  runModels,
}

func runModels(cmd *cobra.Command, args []string) error {
	cfg := loadConfig()
	client := ollama.NewClient(cfg.OllamaURL, cfg.Model)
	ctx := context.Background()
	names, err := client.ListModels(ctx)
	if err != nil {
		return fmt.Errorf("list models: %w", err)
	}
	fmt.Printf("Available models on %s:\n", cfg.OllamaURL)
	for _, n := range names {
		marker := "  "
		if n == cfg.Model {
			marker = "→ "
		}
		fmt.Printf("%s%s\n", marker, n)
	}
	return nil
}
