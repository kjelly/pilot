package mcpclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validProfiles = `version: 1
profiles:
  prod-observe:
    source:
      url: https://github.com/example/config
      ref: main
      subdir: infra/prod
    target:
      ssh_host: deploy-node
      env: prod
      env_root: /srv/env
      image: pilot-cli:latest
    mode: observe
    timeouts:
      git_seconds: 60
      ssh_seconds: 15
`

func writeProfiles(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "profiles.yaml")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadProfileAppliesDefaults(t *testing.T) {
	p, err := LoadProfile(writeProfiles(t, validProfiles, 0o600), "prod-observe")
	if err != nil {
		t.Fatal(err)
	}
	if p.Target.Docker != "docker" || p.Timeouts.StartupSeconds != 60 || p.Target.NetworkHost {
		t.Fatalf("defaults not applied: %+v", p)
	}
}

func TestLoadProfileRejects(t *testing.T) {
	mutate := func(old, new string) string { return strings.Replace(validProfiles, old, new, 1) }
	cases := map[string]string{
		"unknown field":        mutate("    mode: observe\n", "    mode: observe\n    extra: 1\n"),
		"duplicate key":        mutate("      ref: main\n", "      ref: main\n      ref: dev\n"),
		"userinfo url":         mutate("https://github.com/example/config", "https://user:pw@github.com/example/config"),
		"file url":             mutate("https://github.com/example/config", "file:///tmp/repo"),
		"ext url":              mutate("https://github.com/example/config", "ext::sh -c touch% /tmp/x"),
		"local path url":       mutate("https://github.com/example/config", "/srv/repo"),
		"three path segments":  mutate("https://github.com/example/config", "https://github.com/a/b/c"),
		"abbreviated sha":      mutate("ref: main", "ref: 4996cf3"),
		"ref with dot dot":     mutate("ref: main", "ref: a..b"),
		"subdir escapes":       mutate("subdir: infra/prod", "subdir: ../prod"),
		"absolute subdir":      mutate("subdir: infra/prod", "subdir: /prod"),
		"ssh host dash":        mutate("ssh_host: deploy-node", "ssh_host: -oProxyCommand=x"),
		"bad env":              mutate("env: prod", "env: production"),
		"relative env_root":    mutate("env_root: /srv/env", "env_root: srv/env"),
		"env_root with comma":  mutate("env_root: /srv/env", "env_root: /srv/a,b"),
		"env_root with quote":  mutate("env_root: /srv/env", `env_root: "/srv/'x"`),
		"digest image":         mutate("image: pilot-cli:latest", "image: pilot-cli@sha256:abcd"),
		"image without tag":    mutate("image: pilot-cli:latest", "image: pilot-cli"),
		"bad mode":             mutate("mode: observe", "mode: repair"),
		"timeout out of range": mutate("git_seconds: 60", "git_seconds: 99999"),
		"wrong version":        mutate("version: 1", "version: 2"),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadProfile(writeProfiles(t, content, 0o600), "prod-observe"); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
	if _, err := LoadProfile(writeProfiles(t, validProfiles, 0o664), "prod-observe"); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group-writable file: %v", err)
	}
	if _, err := LoadProfile(writeProfiles(t, validProfiles, 0o600), "missing"); err == nil {
		t.Fatal("missing profile accepted")
	}
	if _, err := LoadProfile(writeProfiles(t, validProfiles, 0o600), "Bad Name"); err == nil {
		t.Fatal("invalid profile name accepted")
	}
}

func TestRepoURLs(t *testing.T) {
	for _, ok := range []string{"git@github.com:org/repo.git", "git@github.com:org/repo", "ssh://git@github.com/org/repo", "ssh://git@github.com:2222/org/repo.git", "https://github.com/org/repo", "https://github.com/org/repo.git"} {
		if err := ValidateRepoURL(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	same := []string{"git@github.com:Org/Repo.git", "ssh://git@GitHub.com/org/repo", "https://github.com/org/repo"}
	for _, a := range same {
		for _, b := range same {
			if !SameRepo(a, b) {
				t.Errorf("SameRepo(%s, %s) = false", a, b)
			}
		}
	}
	for _, b := range []string{"https://github.com/org/other", "https://gitlab.com/org/repo", "https://github.com/other/repo"} {
		if SameRepo("https://github.com/org/repo", b) {
			t.Errorf("SameRepo matched %s", b)
		}
	}
	for _, bad := range []string{"ssh://root@github.com/org/repo", "ssh://git:pw@github.com/org/repo", "http://github.com/org/repo", "https://github.com/org/repo?x=1", "-uhttps://x/y/z"} {
		if err := ValidateRepoURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
