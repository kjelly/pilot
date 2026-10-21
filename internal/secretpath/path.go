// Package secretpath keeps credential-bearing files outside Ansible vars trees.
package secretpath

import (
	"fmt"
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
	// Resolve the vars side of the boundary too: an external destination may
	// be exposed by a root or nested directory alias, even before it exists.
	// Include ancestor vars trees when a caller selects an external source.
	roots := []string{workspace}
	for root := filepath.Dir(destination); ; root = filepath.Dir(root) {
		roots = append(roots, root)
		if root == filepath.Dir(root) {
			break
		}
	}
	source, err := os.Stat(destination)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect secret source path")
	}
	visited := make(map[string]bool)
	for _, root := range roots {
		for _, tree := range []string{"group_vars", "host_vars"} {
			base := filepath.Join(root, tree)
			if _, err := os.Lstat(base); os.IsNotExist(err) {
				continue
			} else if err != nil {
				return fmt.Errorf("cannot inspect inventory vars tree")
			}
			if err := validateVarsAlias(base, destination, source, visited); err != nil {
				return err
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

// validateVarsAlias follows directory aliases only within the selected vars
// trees. Resolved containment also protects files that have not been created;
// inode comparison catches existing hardlinks. Unresolvable aliases fail closed.
func validateVarsAlias(path, destination string, source os.FileInfo, visited map[string]bool) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("cannot resolve inventory vars alias")
	}
	rel, err := filepath.Rel(resolved, destination)
	if err != nil {
		return fmt.Errorf("cannot compare inventory vars alias")
	}
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return forbidden()
	}
	if visited[resolved] {
		return nil
	}
	visited[resolved] = true
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("cannot inspect inventory vars alias")
	}
	if source != nil && os.SameFile(source, info) {
		return forbidden()
	}
	if !info.IsDir() {
		return nil
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return fmt.Errorf("cannot inspect inventory vars directory")
	}
	for _, entry := range entries {
		if err := validateVarsAlias(filepath.Join(resolved, entry.Name()), destination, source, visited); err != nil {
			return err
		}
	}
	return nil
}
