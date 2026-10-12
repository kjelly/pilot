package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// VarsShadow is a group_vars/host_vars file that Ansible never loads
// because a directory with the same name sits next to it. Ansible's
// host_group_vars plugin checks for a "<name>" entry first and only falls
// back to "<name>.yml/.yaml/.json" when that entry does not exist, so once
// group_vars/dns/ exists, group_vars/dns.yml is silently ignored
// (confirmed with ansible-core 2.19.2 for .yml, .yaml and .json, in both
// group_vars and host_vars — docs/verification/dns.md §0.2).
type VarsShadow struct {
	File string // the ignored file, e.g. <base>/group_vars/dns.yml
	Dir  string // the directory Ansible loads instead, e.g. <base>/group_vars/dns
}

// String renders the shadow as one human-readable line.
func (s VarsShadow) String() string {
	return fmt.Sprintf("%s is ignored by Ansible because the directory %s/ exists (Ansible loads only the directory) — merge the file into the directory or remove the directory", s.File, s.Dir)
}

// varsFileExts are the file extensions Ansible's host_group_vars plugin
// accepts for a group_vars/host_vars file.
var varsFileExts = []string{".yml", ".yaml", ".json"}

// ShadowedVarsFiles reports every <baseDir>/group_vars and
// <baseDir>/host_vars file that a same-named directory shadows, sorted by
// file path. A missing group_vars/ or host_vars/ directory is not an error.
func ShadowedVarsFiles(baseDir string) ([]VarsShadow, error) {
	var out []VarsShadow
	for _, sub := range []string{"group_vars", "host_vars"} {
		root := filepath.Join(baseDir, sub)
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", root, err)
		}
		dirs := map[string]bool{}
		for _, e := range entries {
			if e.IsDir() {
				dirs[e.Name()] = true
			}
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			for _, ext := range varsFileExts {
				stem, ok := strings.CutSuffix(e.Name(), ext)
				if ok && dirs[stem] {
					out = append(out, VarsShadow{File: filepath.Join(root, e.Name()), Dir: filepath.Join(root, stem)})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}
