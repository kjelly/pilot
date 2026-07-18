package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/contract"
)

var contractRoot string

var contractCmd = &cobra.Command{
	Use:   "contract",
	Short: "Inspect and validate delivery component contracts",
}

var contractLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Strictly validate canonical contracts/",
	Args:  cobra.NoArgs,
	RunE:  runContractLint,
}

func init() {
	contractLintCmd.Flags().StringVar(&contractRoot, "root", "", "repository root containing contracts/ (default: current directory)")
	contractCmd.AddCommand(contractLintCmd)
	rootCmd.AddCommand(contractCmd)
}

func runContractLint(cmd *cobra.Command, _ []string) error {
	root, err := resolveContractRoot(contractRoot)
	if err != nil {
		return err
	}
	return lintContracts(root, cmd.OutOrStdout())
}

func lintContracts(root string, out io.Writer) error {
	loader, err := contract.NewLoader(root)
	if err != nil {
		return err
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		return err
	}
	if err := contract.ValidateBundleReferences(root, catalog); err != nil {
		return err
	}
	components := catalog.Components()
	for _, component := range components {
		fmt.Fprintf(out, "✓ %s\trole=%s\n", component.ID, component.Role)
	}
	fmt.Fprintf(out, "contracts: %d component(s) loaded from %s\n", len(components), filepath.Join(root, contract.DefaultDirectory))
	return nil
}

func resolveContractRoot(flagValue string) (string, error) {
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	root, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	return root, nil
}
