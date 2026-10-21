package inventory

import (
	"os"

	"github.com/kjelly/pilot/internal/secretpath"
)

func validateSecretSourceFile(path string) error { return secretpath.Validate(".", path) }

func readSecretSourceFile(path string) ([]byte, error) {
	if err := validateSecretSourceFile(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func writeSecretSourceFile(path string, data []byte, mode os.FileMode) error {
	if err := validateSecretSourceFile(path); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}
