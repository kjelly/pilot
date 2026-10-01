// Package factcache drops Ansible fact-cache entries for inventory host
// names that pilot creates or removes. The repo's ansible.cfg uses
// `gathering = smart` with a jsonfile cache and a 3600 s timeout, so a
// disposable target recreated under the same name within the hour would
// otherwise be served the facts (addresses, OS) of the one it replaced.
package factcache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ansibleConfigBin is the ansible-config executable; tests point it at a
// fake that prints captured output.
var ansibleConfigBin = "ansible-config"

// resolveTimeout bounds each ansible-config call (it reads local files only;
// a real call takes well under a second).
const resolveTimeout = 30 * time.Second

// Store is the fact cache Ansible would use when started from this process:
// same working directory, same environment, so the same ansible.cfg.
type Store struct {
	// Plugin is the configured cache plugin (CACHE_PLUGIN).
	Plugin string
	// Dir holds one file per host. Empty when the plugin keeps no files
	// (memory) or is not one pilot knows how to clean.
	Dir string
	// Prefix is the plugin's file name prefix; empty when unset.
	Prefix string
}

// Resolve asks ansible-config for the active cache plugin and, for the
// file-based jsonfile plugin, the directory and prefix it writes to. It
// reads the plugin's own options (`ansible-config dump -t cache`) rather
// than the base CACHE_PLUGIN_* settings, because the base prefix default
// ("ansible_facts") is not the one the jsonfile plugin applies (it has none).
func Resolve(ctx context.Context) (Store, error) {
	base, err := dump(ctx, "dump", "--format", "json")
	if err != nil {
		return Store{}, err
	}
	var settings []setting
	if err := json.Unmarshal(base, &settings); err != nil {
		return Store{}, fmt.Errorf("parse ansible-config dump: %w", err)
	}
	var store Store
	for _, s := range settings {
		if s.Name == "CACHE_PLUGIN" {
			store.Plugin, _ = s.Value.(string)
		}
	}
	if !isJSONFile(store.Plugin) {
		return store, nil
	}
	raw, err := dump(ctx, "dump", "-t", "cache", "--format", "json")
	if err != nil {
		return Store{}, err
	}
	var plugins []map[string][]setting
	if err := json.Unmarshal(raw, &plugins); err != nil {
		return Store{}, fmt.Errorf("parse ansible-config dump -t cache: %w", err)
	}
	for _, entry := range plugins {
		for _, s := range entry["jsonfile"] {
			switch s.Name {
			case "_uri":
				store.Dir, _ = s.Value.(string)
			case "_prefix":
				store.Prefix, _ = s.Value.(string)
			}
		}
	}
	if store.Dir == "" {
		return Store{}, errors.New("ansible-config reports the jsonfile fact cache without a directory (fact_caching_connection)")
	}
	if !filepath.IsAbs(store.Dir) {
		return Store{}, fmt.Errorf("ansible-config reports a relative fact cache directory %q", store.Dir)
	}
	return store, nil
}

// Purge removes the cache files of hosts and returns their paths. A host
// has at most one file, named <prefix><host> (ansible-core before 2.19) or
// <prefix>s<schema>_<host> (2.19 and later, for example s1_<host>). Removing
// an extra entry only makes Ansible gather facts again, so the match errs
// toward removing.
func (s Store) Purge(hosts []string) ([]string, error) {
	if s.Dir == "" || len(hosts) == 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read fact cache directory %s: %w", s.Dir, err)
	}
	match := cacheFileMatcher(s.Prefix, hosts)
	var removed []string
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || !match(entry.Name()) {
			continue
		}
		path := filepath.Join(s.Dir, entry.Name())
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove cached facts %s: %w", path, err))
			continue
		}
		removed = append(removed, path)
	}
	return removed, errors.Join(errs...)
}

// Drop resolves the fact cache and removes the entries of hosts. Without
// ansible-config on PATH no Ansible run can read a cache from this process
// either, so there is nothing to drop. A cache plugin other than jsonfile
// or memory is reported but not cleaned.
func Drop(ctx context.Context, hosts []string) error {
	store, err := Resolve(ctx)
	if errors.Is(err, exec.ErrNotFound) {
		slog.Debug("ansible-config not found; no fact cache to drop", "hosts", hosts)
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolve the Ansible fact cache: %w", err)
	}
	if store.Dir == "" {
		if !isMemory(store.Plugin) {
			slog.Warn("fact cache plugin keeps no files pilot can clean; cached facts of recreated hosts may be stale", "plugin", store.Plugin, "hosts", hosts)
		}
		return nil
	}
	removed, err := store.Purge(hosts)
	if len(removed) > 0 {
		slog.Debug("dropped cached facts", "files", removed)
	}
	return err
}

type setting struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

func dump(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ansibleConfigBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ansible-config %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func isJSONFile(plugin string) bool {
	return shortName(plugin) == "jsonfile"
}

func isMemory(plugin string) bool {
	p := shortName(plugin)
	return p == "" || p == "memory"
}

func shortName(plugin string) string {
	for _, prefix := range []string{"ansible.builtin.", "ansible.legacy."} {
		plugin = strings.TrimPrefix(plugin, prefix)
	}
	return plugin
}

func cacheFileMatcher(prefix string, hosts []string) func(string) bool {
	names := make(map[string]bool, len(hosts))
	quoted := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h == "" {
			continue
		}
		names[prefix+h] = true
		quoted = append(quoted, regexp.QuoteMeta(h))
	}
	if len(quoted) == 0 {
		return func(string) bool { return false }
	}
	schema := regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `s[0-9]+_(?:` + strings.Join(quoted, "|") + `)$`)
	return func(name string) bool { return names[name] || schema.MatchString(name) }
}
