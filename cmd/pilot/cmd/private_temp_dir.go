package cmd

import "github.com/kjelly/pilot/internal/secretpath"

// privateTempDir is secretpath.PrivateTempDir, the one way pilot makes a
// directory for a copy of files that may hold secrets — here a plan's
// scratch workspace and a simulated roster write; internal/inventory's
// decrypted roster scratch directory too — so a pilot killed before its
// cleanup leaves nothing the next run does not sweep.
func privateTempDir(prefix string) (string, error) {
	return secretpath.PrivateTempDir(prefix)
}
