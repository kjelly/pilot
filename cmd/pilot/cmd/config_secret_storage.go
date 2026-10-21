package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kjelly/pilot/internal/configpolicy"
	"github.com/kjelly/pilot/internal/secretpath"
)

func validateSecretSourcePath(dir, path string) error {
	return secretpath.Validate(dir, path)
}

func inventorySecretPolicy() configpolicy.Policy {
	catalog, _ := loadContractCatalogBestEffort()
	return configpolicy.New(catalog)
}

func secretStorageError(violations []configpolicy.Violation) error {
	if len(violations) == 0 {
		return nil
	}
	lines := make([]string, 0, len(violations))
	for _, violation := range violations {
		lines = append(lines, violation.String())
	}
	return fmt.Errorf("%s", strings.Join(lines, "\n"))
}

func validateInventorySecretStorage(dir string) error {
	if err := validateSecretSourcePath(dir, filepath.Join(dir, ".vault", "main.yaml")); err != nil {
		return err
	}
	violations, err := inventorySecretPolicy().Workspace(dir)
	if err != nil {
		return err
	}
	return secretStorageError(violations)
}

func validateVarsDocument(path string, data []byte) error {
	return secretStorageError(inventorySecretPolicy().Validate(path, data))
}

func validateVarsValue(path, key string, value any) error {
	return secretStorageError(inventorySecretPolicy().ValidateValue(path, key, value))
}

func varsContentNeedsRedaction(path string, data []byte) bool {
	path = filepath.ToSlash(path)
	return (strings.HasPrefix(path, "group_vars/") || strings.HasPrefix(path, "host_vars/")) && len(data) > 0 && validateVarsDocument(path, data) != nil
}
