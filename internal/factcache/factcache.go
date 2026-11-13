// Package factcache drops Ansible fact-cache entries for inventory host
// names that pilot creates or removes. The repo's ansible.cfg uses
// `gathering = smart` with a jsonfile cache and a 3600 s timeout, so a
// disposable target recreated under the same name within the hour would
// otherwise be served the facts (addresses, OS) of the one it replaced.
//
// Two caches can hold such entries. One is whatever Ansible resolves from
// the working directory and environment of this process (the repo's
// ansible.cfg points it at ~/.ansible/pilot-factcache). The other is the
// one pilot's own Ansible commands (`pilot deploy`, `reconcile`, the MCP
// server, ...) are pinned to under the data directory: RuntimeDir and
// RuntimeEnv are its single definition. DropAll cleans both.
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

// runtimeCachePlugin is the cache plugin pilot's Ansible commands pin.
const runtimeCachePlugin = "jsonfile"

// RuntimeDir is the fact-cache directory pilot's own Ansible commands use
// under dataDir: <dataDir>/ansible/fact-cache. dataDir is made absolute
// against the working directory once, here, so the directory Ansible is
// told about and the directory DropAll cleans are the same path whatever
// each of them is later run from.
func RuntimeDir(dataDir string) string {
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	return filepath.Join(dataDir, "ansible", "fact-cache")
}

// RuntimeEnv is the environment that points Ansible at RuntimeDir(dataDir),
// in KEY=value form for appending to a command's environment. It is the
// only place the deploy runtime's cache location is spelled out; the
// lifecycle commands that drop facts are bound to the same RuntimeDir.
func RuntimeEnv(dataDir string) []string {
	return []string{
		"ANSIBLE_CACHE_PLUGIN=" + runtimeCachePlugin,
		"ANSIBLE_CACHE_PLUGIN_CONNECTION=" + RuntimeDir(dataDir),
	}
}

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

// Drop resolves the fact cache this process's Ansible would use and removes
// the entries of hosts. Without ansible-config on PATH no Ansible run can
// read a cache from this process either, so there is nothing to drop. A
// cache plugin other than jsonfile or memory is reported but not cleaned.
//
// Drop does not touch the cache under the data directory that pilot's own
// Ansible commands use (RuntimeDir); callers that recreate or remove
// hosts use DropAll.
func Drop(ctx context.Context, hosts []string) error {
	_, err := dropAmbient(ctx, hosts)
	return err
}

// DropAll removes the entries of hosts from both caches a later pilot
// command could read: the one this process's Ansible resolves (Drop) and
// RuntimeDir(dataDir), where `pilot deploy` and the other pilot Ansible
// commands keep theirs. The second is cleaned without ansible-config and
// from any working directory, since its location is fixed by dataDir; a
// directory that does not exist is left alone, not created. The errors of
// the two are joined, so a failure in one does not skip the other.
//
// A pilot deploy run with a different data directory than dataDir reads a
// different cache; this cannot see it.
func DropAll(ctx context.Context, dataDir string, hosts []string) error {
	if dataDir == "" {
		return errors.New("factcache: the data directory is required to find the deploy fact cache")
	}
	ambient, ambientErr := dropAmbient(ctx, hosts)
	runtime := Store{Plugin: runtimeCachePlugin, Dir: RuntimeDir(dataDir)}
	// The deploy runtime inherits this process's environment and
	// ansible.cfg and only pins the plugin and its directory, so its file
	// name prefix is the one the ambient jsonfile cache resolved to.
	if isJSONFile(ambient.Plugin) {
		runtime.Prefix = ambient.Prefix
	}
	var runtimeErr error
	// An operator who exports the deploy directory as the ambient one is
	// already cleaned by the first pass (same directory means same prefix).
	if filepath.Clean(ambient.Dir) != runtime.Dir {
		var removed []string
		removed, runtimeErr = runtime.Purge(hosts)
		if len(removed) > 0 {
			slog.Debug("dropped cached facts", "files", removed)
		}
		if runtimeErr != nil {
			runtimeErr = fmt.Errorf("drop the deploy fact cache: %w", runtimeErr)
		}
	}
	return errors.Join(ambientErr, runtimeErr)
}

// Dropper returns DropAll bound to dataDir, the shape vm-target and
// docker-target keep as their fact-cache cleanup.
func Dropper(dataDir string) func(ctx context.Context, hosts []string) error {
	return func(ctx context.Context, hosts []string) error {
		return DropAll(ctx, dataDir, hosts)
	}
}

// dropAmbient is Drop; it also returns the cache it resolved (the zero
// Store when there was none) so DropAll can reuse its prefix and skip a
// second pass over the same directory.
func dropAmbient(ctx context.Context, hosts []string) (Store, error) {
	store, err := Resolve(ctx)
	if errors.Is(err, exec.ErrNotFound) {
		slog.Debug("ansible-config not found; no fact cache to drop", "hosts", hosts)
		return Store{}, nil
	}
	if err != nil {
		return Store{}, fmt.Errorf("resolve the Ansible fact cache: %w", err)
	}
	if store.Dir == "" {
		if !isMemory(store.Plugin) {
			slog.Warn("fact cache plugin keeps no files pilot can clean; cached facts of recreated hosts may be stale", "plugin", store.Plugin, "hosts", hosts)
		}
		return store, nil
	}
	removed, err := store.Purge(hosts)
	if len(removed) > 0 {
		slog.Debug("dropped cached facts", "files", removed)
	}
	return store, err
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
