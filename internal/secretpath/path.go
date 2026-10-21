// Package secretpath keeps credential-bearing files outside Ansible vars trees.
package secretpath

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Validate keeps editors of secret-bearing sources out of
// inventory vars trees, including destinations reached through symlinks.
func Validate(dir, path string) error {
	workspace, err := canonicalPath(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve workspace for secret source")
	}
	destination, err := canonicalPath(path)
	if err != nil {
		return fmt.Errorf("cannot resolve secret source path")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("cannot resolve secret source path")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve workspace for secret source")
	}
	// A caller can choose a secret source outside its own workspace. The
	// storage boundary applies to every vars tree, not only dir's siblings.
	for _, candidate := range []string{path, destination} {
		for _, component := range strings.Split(filepath.ToSlash(candidate), "/") {
			if component == "group_vars" || component == "host_vars" {
				return forbidden()
			}
		}
	}
	// Inspect the workspace trees even for a new destination. A vars directory
	// symlink can expose an external source without changing the source path.
	source, statErr := os.Stat(destination)
	if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("cannot inspect secret source path")
	}
	if err := inspectVarsFiles(workspace, source); err != nil {
		return err
	}
	if source != nil && !source.IsDir() {
		// Compare actual inodes rather than rejecting unrelated external files
		// solely because they have another hard link. Also check sibling trees
		// when the user chooses a source outside this workspace.
		for root := filepath.Dir(destination); ; root = filepath.Dir(root) {
			if root != workspace {
				if err := inspectVarsFiles(root, source); err != nil {
					return err
				}
			}
			if root == filepath.Dir(root) {
				break
			}
		}
	}
	for _, tree := range []string{"group_vars", "host_vars"} {
		// Check the lexical path as well: a vars-tree symlink pointing out
		// of the workspace must not become a credential storage escape.
		for _, pair := range [][2]string{{filepath.Join(absDir, tree), absPath}, {filepath.Join(workspace, tree), destination}} {
			rel, err := filepath.Rel(pair[0], pair[1])
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return forbidden()
			}
		}
	}
	return nil
}

// Resolve the nearest existing ancestor so new files and directories receive
// the same destination check as existing files. Broken links fail closed.
func canonicalPath(path string) (string, error) {
	abs := path
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		abs = cwd + string(filepath.Separator) + path
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	if _, statErr := os.Lstat(abs); statErr == nil {
		return "", err // dangling symlink, rather than a new file
	}
	parent, leaf := filepath.Split(abs)
	parent = strings.TrimRight(parent, string(filepath.Separator))
	if parent == "" {
		parent = string(filepath.Separator)
	}
	if parent == abs {
		return "", err
	}
	resolved, err = canonicalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, leaf), nil
}

func forbidden() error {
	return fmt.Errorf("secret source must be outside group_vars/ and host_vars/ and must not alias an inventory vars file; use an external Vault vars file (docs/config-secret-storage.md)")
}

// inspectVarsFiles only inspects the two relevant vars trees; it never scans
// unrelated external secret stores or exposes file contents. Directory symlinks
// and inspection failures are rejected because WalkDir cannot safely inspect
// their contents. A missing tree is the only traversal error we can ignore.
func inspectVarsFiles(root string, source os.FileInfo) error {
	for _, tree := range []string{"group_vars", "host_vars"} {
		base := filepath.Join(root, tree)
		err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if os.IsNotExist(walkErr) && path == base {
				return nil
			}
			if walkErr != nil {
				return fmt.Errorf("cannot inspect inventory vars tree %s", tree)
			}
			if entry.IsDir() {
				return nil
			}
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("cannot inspect inventory vars tree %s", tree)
			}
			if info.IsDir() || (source != nil && os.SameFile(source, info)) {
				return forbidden()
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
