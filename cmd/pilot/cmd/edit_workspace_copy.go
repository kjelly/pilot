// edit_workspace_copy.go creates an inert, disposable copy of a
// workspace's managed files for a plan run to operate on — see the
// spec's "Plan 不得修改真實 workspace" invariant.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// copyManagedFilesToTemp copies managedFileEntries(dir) into a fresh
// OS-temp-dir location (never nested inside dir — mirrors
// docker_target.go's os.MkdirTemp("", "pilot-img-build-*") pattern for
// "disposable, outside the tracked tree"). Every entry is materialized
// as a plain regular file holding its already-resolved Content, even if
// the source was a symlink: recreating a symlink in the copy would let
// editAgentSession's save path follow it and mutate whatever it points
// at (possibly the original workspace, or something outside it) — an
// inert copy can never do that.
//
// One exception keeps a plan's report equal to its apply's: .vault/ names
// that are one file in dir (symlinks to it, to each other, or hard links)
// stay one file in the copy (vaultAliases). A roster written through one of
// them changes every name of it, so a copy that held each name as a file of
// its own would preview only the name the plan wrote. Only those names are
// links, each a relative symlink to a plain file of the copy, so no link in
// the copy leaves it.
//
// The returned cleanup func removes the temp dir; callers should defer
// it immediately.
func copyManagedFilesToTemp(dir string) (tempDir string, cleanup func(), err error) {
	// The copy holds the workspace's .vault/ files: privateTempDir sweeps
	// the copies a killed pilot leaves.
	tempDir, err = privateTempDir("pilot-edit-plan")
	if err != nil {
		return "", nil, fmt.Errorf("create temp workspace: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tempDir) }

	entries, err := managedFileEntries(dir)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	aliases := vaultAliases(dir, entries)
	for _, e := range entries {
		dst := filepath.Join(tempDir, filepath.FromSlash(e.RelPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("mkdir for %s: %w", e.RelPath, err)
		}
		if rep, ok := aliases[e.RelPath]; ok {
			// Both names are in .vault/ (vaultAliases), so the link is the
			// representative's bare name.
			if err := os.Symlink(filepath.Base(rep), dst); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("link temp copy of %s to %s: %w", e.RelPath, rep, err)
			}
			continue
		}
		if err := os.WriteFile(dst, e.Content, 0o644); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write temp copy of %s: %w", e.RelPath, err)
		}
	}
	return tempDir, cleanup, nil
}

// vaultAliases maps the RelPath of every .vault/ entry that is not the
// first of its file to the RelPath of the one that is — the entries of
// dir that os.SameFile calls one file, however they reach it: symlinks to
// it (a chain, or to a file outside dir), or hard links. The one kept as a
// regular file is a name that is not itself a symlink when there is one,
// else the first by RelPath; every other name of the file is a link to it.
// An entry that is the only name of its file is absent from the map.
func vaultAliases(dir string, entries []managedFileEntry) map[string]string {
	type group struct {
		info    os.FileInfo
		members []managedFileEntry
	}
	var groups []*group
	for _, e := range entries {
		if !e.IsSecret {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(e.RelPath)))
		if err != nil {
			continue
		}
		var g *group
		for _, other := range groups {
			if os.SameFile(other.info, info) {
				g = other
				break
			}
		}
		if g == nil {
			g = &group{info: info}
			groups = append(groups, g)
		}
		g.members = append(g.members, e)
	}
	aliases := map[string]string{}
	for _, g := range groups {
		if len(g.members) < 2 {
			continue
		}
		rep := g.members[0]
		for _, m := range g.members {
			if !m.IsSymlink {
				rep = m
				break
			}
		}
		for _, m := range g.members {
			if m.RelPath != rep.RelPath {
				aliases[m.RelPath] = rep.RelPath
			}
		}
	}
	return aliases
}
