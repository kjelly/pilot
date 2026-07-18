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
	if err := validateDeployCatalogProjection(catalog); err != nil {
		return err
	}
	components := catalog.Components()
	for _, component := range components {
		fmt.Fprintf(out, "✓ %s\trole=%s\n", component.ID, component.Role)
	}
	fmt.Fprintf(out, "contracts: %d component(s) loaded from %s\n", len(components), filepath.Join(root, contract.DefaultDirectory))
	return nil
}

func validateDeployCatalogProjection(catalog contract.Catalog) error {
	return validateDeployCatalogEntries(catalog, deployCatalog)
}

func validateDeployCatalogEntries(catalog contract.Catalog, entries []deployPlaybook) error {
	byPlaybook := make(map[string][]contract.Contract)
	for _, component := range catalog.Components() {
		byPlaybook[component.Playbooks.Apply] = append(byPlaybook[component.Playbooks.Apply], component)
	}
	catalogPlaybooks := make(map[string]bool, len(entries))
	for _, entry := range entries {
		components := byPlaybook[entry.Playbook]
		if len(components) == 0 {
			return fmt.Errorf("deploy catalog entry %q references playbook %s without a component contract", entry.Key, entry.Playbook)
		}
		catalogPlaybooks[entry.Playbook] = true
		for _, component := range components {
			if entry.StageVar != component.StagePolicy.Variable {
				return fmt.Errorf("deploy catalog entry %q stage variable %q differs from component %q contract %q", entry.Key, entry.StageVar, component.ID, component.StagePolicy.Variable)
			}
		}
	}
	for playbook, components := range byPlaybook {
		if catalogPlaybooks[playbook] {
			continue
		}
		ids := make([]string, 0, len(components))
		for _, component := range components {
			ids = append(ids, component.ID)
		}
		return fmt.Errorf("component contract(s) %v use playbook %s missing from deploy catalog", ids, playbook)
	}
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
