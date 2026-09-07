package monitoring

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kjelly/pilot/monitoring/snmp/generated"
)

const standardIFMIBModulePath = "generated/if_mib.yml"

// SNMPBootstrapResult records which non-secret workspace assets were created
// by BootstrapSNMPBaseline. Existing user-managed files are never overwritten.
type SNMPBootstrapResult struct {
	CatalogCreated bool
	CatalogUpdated bool
	IFMIBCreated   bool
}

// BootstrapSNMPBaseline creates the minimum useful, non-secret SNMP catalog
// in workspaceDir: catalog.yml declares the standard if_mib module and the
// matching official generated module is written beneath generated/. It never
// creates credentials or auth profiles, and it preserves existing catalog and
// module content. A conflicting existing if_mib declaration fails closed.
func BootstrapSNMPBaseline(workspaceDir string) (SNMPBootstrapResult, error) {
	var result SNMPBootstrapResult
	catalogPath := filepath.Join(workspaceDir, "monitoring", "snmp", "catalog.yml")
	modulePath := filepath.Join(workspaceDir, "monitoring", "snmp", filepath.FromSlash(standardIFMIBModulePath))

	catalogExists, err := regularFileExists(catalogPath)
	if err != nil {
		return result, err
	}
	moduleExists, err := regularFileExists(modulePath)
	if err != nil {
		return result, err
	}

	catalog, err := LoadSNMPCatalog(catalogPath)
	if err != nil {
		return result, err
	}
	if catalog.Modules == nil {
		catalog.Modules = map[string]SNMPModule{}
	}
	if existing, ok := catalog.Modules["if_mib"]; ok && existing.File != standardIFMIBModulePath {
		return result, fmt.Errorf("%s declares if_mib at %q; expected %q and will not overwrite it", catalogPath, existing.File, standardIFMIBModulePath)
	}
	if _, ok := catalog.Modules["if_mib"]; !ok {
		catalog.Modules["if_mib"] = SNMPModule{File: standardIFMIBModulePath}
		result.CatalogUpdated = catalogExists
	}
	if !catalogExists || result.CatalogUpdated {
		if err := catalog.Validate(); err != nil {
			return result, fmt.Errorf("validate bootstrap SNMP catalog: %w", err)
		}
	}

	// Write the module before making catalog.yml reference it. If this fails,
	// the existing catalog remains usable and no dangling reference is created.
	if !moduleExists {
		if err := writeFile(modulePath, generated.IFMIB); err != nil {
			return result, fmt.Errorf("write standard if_mib module: %w", err)
		}
		result.IFMIBCreated = true
	}

	if !catalogExists || result.CatalogUpdated {
		if err := SaveSNMPCatalog(catalogPath, catalog); err != nil {
			return result, err
		}
		result.CatalogCreated = !catalogExists
	}
	return result, nil
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return false, fmt.Errorf("%s must be a file, not a directory", path)
	}
	return true, nil
}
