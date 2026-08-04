// edit_workspace_files.go is the single source of truth for "which
// files does pilot edit's MCP planning machinery manage" — see the
// spec's "Managed files" section
// (docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md).
// computeWorkspaceRevision, copyManagedFilesToTemp, and diffManagedFiles
// all call managedFileEntries so they can never disagree about the file
// set. Vault files are deliberately excluded until Phase 5's secret-safe
// recording lands.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// managedFileEntry is one workspace file managedFileEntries considers
// in scope, with enough information to detect any change a revision
// hash, diff, or copy cares about.
type managedFileEntry struct {
	// RelPath is forward-slash, relative to the workspace root — e.g.
	// "group_vars/freeipa.yml".
	RelPath string
	// Mode is from Lstat, so it carries the symlink bit even though
	// Content below is read through the link.
	Mode      os.FileMode
	IsSymlink bool
	// Content is the file's fully resolved (symlink-following) bytes.
	Content []byte
}

// managedFileExtensions is the allowlist for group_vars/ and host_vars/
// entries — consolidates what were previously ad hoc strings.HasSuffix
// checks scattered across edit.go and edit_tui_hostvars.go.
var managedFileExtensions = []string{".yml", ".yaml"}

func hasManagedFileExtension(name string) bool {
	for _, ext := range managedFileExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// managedFileEntries enumerates every currently-existing managed file
// under dir: hosts.yml, role-presets.yml, and every *.yml/*.yaml file
// directly inside group_vars/ and host_vars/ (non-recursive — matching
// the spec's literal `group_vars/*.yml` glob, not `**/*.yml`). Missing
// files/directories are not an error; they're just absent from the
// result. The result is sorted by RelPath for canonical, deterministic
// downstream encoding.
func managedFileEntries(dir string) ([]managedFileEntry, error) {
	var entries []managedFileEntry

	addFile := func(relPath string) error {
		full := filepath.Join(dir, filepath.FromSlash(relPath))
		lst, err := os.Lstat(full)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lstat %s: %w", relPath, err)
		}
		content, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("read %s: %w", relPath, err)
		}
		entries = append(entries, managedFileEntry{
			RelPath:   relPath,
			Mode:      lst.Mode(),
			IsSymlink: lst.Mode()&os.ModeSymlink != 0,
			Content:   content,
		})
		return nil
	}

	addDirFiles := func(subdir string) error {
		full := filepath.Join(dir, subdir)
		items, err := os.ReadDir(full)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read dir %s: %w", subdir, err)
		}
		for _, item := range items {
			if item.IsDir() || !hasManagedFileExtension(item.Name()) {
				continue
			}
			if err := addFile(subdir + "/" + item.Name()); err != nil {
				return err
			}
		}
		return nil
	}

	if err := addFile("hosts.yml"); err != nil {
		return nil, err
	}
	if err := addFile(rolePresetFilename); err != nil {
		return nil, err
	}
	if err := addDirFiles("group_vars"); err != nil {
		return nil, err
	}
	if err := addDirFiles("host_vars"); err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].RelPath < entries[j].RelPath })
	return entries, nil
}
