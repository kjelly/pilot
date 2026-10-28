package cmd

import "github.com/kjelly/pilot/internal/secretpath"

// privateTempDir is secretpath.PrivateTempDir, how pilot makes a directory
// for a copy of files that may hold secrets — here a plan's scratch
// workspace and a simulated roster write; internal/inventory's decrypted
// roster scratch directory too — so a pilot killed before its cleanup
// leaves nothing the next run does not sweep (a roster schema migration's
// decrypted candidate is not one of these: it is a 0600 temp file beside
// the roster, swept by internal/inventory's sweepRosterTemps).
func privateTempDir(prefix string) (string, error) {
	return secretpath.PrivateTempDir(prefix)
}
