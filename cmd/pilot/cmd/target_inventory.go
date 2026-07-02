package cmd

import (
	"fmt"
	"os"
)

// writeTempInventory writes a rendered inventory to a temp file and returns
// its path plus a cleanup func the caller MUST defer. Both target backends
// (docker-target, vm-target) stage their generated inventory to a tmpfile
// before invoking ansible; this is the single implementation of that
// write/close/cleanup dance, so the two CLIs cannot drift on it (and cannot
// re-introduce the tmpfile leak that motivated vtStageInventory).
func writeTempInventory(inv string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "pilot-inv-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("create inventory tmpfile: %w", err)
	}
	path = f.Name()
	cleanup = func() { os.Remove(path) }
	if _, err := f.WriteString(inv); err != nil {
		f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}
