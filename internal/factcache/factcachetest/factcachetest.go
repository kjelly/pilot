// Package factcachetest fakes `ansible-config` for tests of code that drops
// Ansible fact caches. The fake prints real captured output: the
// testdata files are `ansible-config dump --format json` and
// `ansible-config dump -t cache --format json` from ansible-core 2.19.2 with
// the repo ansible.cfg, trimmed to a few base settings and with local paths
// replaced (/repo/ansible.cfg for the config file, @CACHE_DIR@ for the
// jsonfile cache directory). Only tests import it.
package factcachetest

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed testdata/dump-jsonfile.json testdata/dump-cache-jsonfile.json
var fixtures embed.FS

// WriteFake writes an executable fake ansible-config into a new temporary
// directory and returns its path. It answers the base dump with the
// captured fixture (CACHE_PLUGIN set to plugin) and the `-t cache` dump with
// the cache fixture, cacheDir as the jsonfile directory and prefix as its
// file name prefix when non-empty. Every call's arguments are appended to a
// file named calls beside it.
func WriteFake(t testing.TB, plugin, cacheDir, prefix string) string {
	t.Helper()
	dir := t.TempDir()
	base := fixture(t, "dump-jsonfile.json")
	base = strings.Replace(base, `"value": "jsonfile"`, `"value": "`+plugin+`"`, 1)
	cache := strings.ReplaceAll(fixture(t, "dump-cache-jsonfile.json"), "@CACHE_DIR@", cacheDir)
	if prefix != "" {
		cache = strings.Replace(cache, `"origin": "default",
                "value": null`, `"origin": "env: ANSIBLE_CACHE_PLUGIN_PREFIX",
                "value": "`+prefix+`"`, 1)
	}
	write(t, filepath.Join(dir, "base.json"), base, 0o644)
	write(t, filepath.Join(dir, "cache.json"), cache, 0o644)
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> " + filepath.Join(dir, "calls") + "\n" +
		"case \"$*\" in\n" +
		"  *'-t cache'*) cat " + filepath.Join(dir, "cache.json") + " ;;\n" +
		"  *) cat " + filepath.Join(dir, "base.json") + " ;;\n" +
		"esac\n"
	bin := filepath.Join(dir, "ansible-config")
	write(t, bin, script, 0o755)
	return bin
}

// InstallOnPath makes the fake of WriteFake the `ansible-config` that
// anything started by the test finds first on PATH, so code that runs the
// bare name (as factcache does) sees it. PATH is restored when the test ends.
func InstallOnPath(t *testing.T, plugin, cacheDir, prefix string) {
	t.Helper()
	bin := WriteFake(t, plugin, cacheDir, prefix)
	t.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func fixture(t testing.TB, name string) string {
	t.Helper()
	data, err := fixtures.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func write(t testing.TB, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
