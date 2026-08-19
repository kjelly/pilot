package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kjelly/pilot/internal/inventory"
)

// prepareMinimalWorkspace creates the same generated artifacts as
// `pilot inventory generate --dir <dir>`, then fills only safe,
// unambiguous cross-role host defaults. Existing user files and active values
// remain authoritative.
func prepareMinimalWorkspace(dir string) error {
	hostsPath := filepath.Join(dir, "hosts.yml")
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", hostsPath, err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return fmt.Errorf("parse %s: %w", hostsPath, err)
	}

	copyMissingGroupVars(io.Discard, dir, inventory.GroupVarsStems(hf), hf)
	copyMissingNestedGroupVarsExamples(io.Discard, dir, inventory.UsedRoles(hf))
	writeMissingVaultSkeleton(io.Discard, filepath.Join(dir, ".vault", "main.yaml"), hf)
	writeMissingHostVarsSkeleton(io.Discard, dir, hf)
	writeMissingNFSRosterEntries(io.Discard, dir, hf)
	if err := autofillMinimalWorkspaceGroupVars(dir, hf); err != nil {
		return err
	}

	rendered, err := inventory.Generate(hf)
	if err != nil {
		return err
	}
	inventoryPath := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inventoryPath, []byte(rendered), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", inventoryPath, err)
	}
	return nil
}

func autofillMinimalWorkspaceGroupVars(dir string, hf *inventory.HostsFile) error {
	for _, stem := range inventory.GroupVarsStems(hf) {
		path := filepath.Join(dir, "group_vars", stem+".yml")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		updated := autofillCrossRoleHostVars(hf, data)
		if string(updated) == string(data) {
			continue
		}
		if err := os.WriteFile(path, updated, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

// minimalWorkspaceReadiness makes skeleton creation and the editor's existing
// completeness report one atomic quick-start check. It deliberately returns
// the raw report so quick and advanced paths show identical contracts.
func minimalWorkspaceReadiness(dir string) ([]completenessCheck, error) {
	if err := prepareMinimalWorkspace(dir); err != nil {
		return nil, err
	}
	return checkWorkspaceCompleteness(dir), nil
}
