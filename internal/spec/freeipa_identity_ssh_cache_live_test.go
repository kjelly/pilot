package spec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in destructive fixture test belongs ONLY on a disposable vm-target
// topology. The two rosters must differ solely in this user's managed SSH keys;
// the test user must already have completed any initial password change.
// Configuration and private keys stay outside Git. A default CI skip is not
// evidence that the real SSH acceptance contract passed.
func TestRegression_IdentitySSHCacheLiveSSH(t *testing.T) {
	filename := os.Getenv("PILOT_SSH_CACHE_LIVE_CONFIG")
	if filename == "" {
		if os.Getenv("PILOT_REQUIRE_SSH_CACHE_LIVE") == "1" {
			t.Fatal("PILOT_SSH_CACHE_LIVE_CONFIG is required")
		}
		t.Skip("requires isolated enrolled multi-host vm-target topology")
	}
	var cfg struct {
		Disposable bool   `json:"disposable"`
		Inventory  string `json:"inventory"`
		Provider   string `json:"provider"`
		VarsFile   string `json:"vars_file"`
		AddRoster  string `json:"add_roster"`
		Revoke     string `json:"revoke_roster"`
		User       string `json:"user"`
		Key        string `json:"private_key"`
		KnownHosts string `json:"known_hosts"`
		Clients    []struct {
			Alias   string `json:"alias"`
			Address string `json:"address"`
			Port    int    `json:"port"`
		} `json:"clients"`
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Disposable || len(cfg.Clients) < 2 || cfg.Provider == "" || cfg.User == "" {
		t.Fatal("disposable=true, provider, user and at least two enrolled clients are mandatory")
	}
	for _, path := range []string{cfg.Inventory, cfg.VarsFile, cfg.AddRoster, cfg.Revoke, cfg.Key, cfg.KnownHosts} {
		if !filepath.IsAbs(path) {
			t.Fatal("all live fixture paths must be absolute")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	inv, err := exec.CommandContext(ctx, "ansible-inventory", "-i", cfg.Inventory, "--list").Output()
	if err != nil {
		t.Fatal(err)
	}
	var actual struct {
		Meta struct {
			Hostvars map[string]json.RawMessage `json:"hostvars"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(inv, &actual); err != nil {
		t.Fatal(err)
	}
	if _, ok := actual.Meta.Hostvars[cfg.Provider]; !ok {
		t.Fatal("provider is absent from actual inventory")
	}
	seen := map[string]bool{}
	for _, client := range cfg.Clients {
		if _, ok := actual.Meta.Hostvars[client.Alias]; !ok || client.Address == "" || strings.HasPrefix(client.Address, "-") || client.Port < 1 || client.Port > 65535 || seen[client.Alias] {
			t.Fatal("live clients must be distinct actual inventory aliases with SSH address/port")
		}
		seen[client.Alias] = true
	}
	evidenceRoot, err := filepath.Abs("../../.verification")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(evidenceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	evidence, err := os.MkdirTemp(evidenceRoot, "ssh-cache-live-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("private live evidence directory: %s", evidence)
	run := 0
	apply := func(roster string, preview, noop bool) {
		t.Helper()
		values, _ := json.Marshal(map[string]string{"target_group": cfg.Provider, "freeipa_roster_file": roster})
		args := []string{"-i", cfg.Inventory, sshKeysPlaybook, "-e", "@" + cfg.VarsFile, "-e", string(values)}
		if preview {
			args = append(args, "--check", "--diff")
		}
		command := exec.CommandContext(ctx, "ansible-playbook", args...)
		command.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1")
		out, err := command.CombinedOutput()
		// Raw output is disposable, kept only in the test's private temporary
		// directory. Do not print vault/roster material into a CI transcript.
		run++
		if writeErr := os.WriteFile(filepath.Join(evidence, fmt.Sprintf("apply-%d.log", run)), out, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		if err != nil {
			t.Fatalf("live identity apply failed: %v (raw output withheld)", err)
		}
		if noop {
			var result struct {
				Plays []struct {
					Tasks []struct {
						Task  struct{ Name string } `json:"task"`
						Hosts map[string]struct {
							Results []struct{ Skipped bool } `json:"results"`
						} `json:"hosts"`
					} `json:"tasks"`
				} `json:"plays"`
			}
			// Warnings are stderr; parse from the JSON callback's first object.
			start := strings.IndexByte(string(out), '{')
			if start < 0 || json.Unmarshal(out[start:], &result) != nil {
				t.Fatal("cannot parse live no-op evidence")
			}
			for _, play := range result.Plays {
				for _, task := range play.Tasks {
					if task.Task.Name != "Invalidate and verify the named user's SSSD SSH keys" && task.Task.Name != "Refresh SSSD caches on enrolled FreeIPA clients" {
						continue
					}
					for _, host := range task.Hosts {
						for _, item := range host.Results {
							if !item.Skipped {
								t.Fatal("identical apply performed a client cache operation")
							}
						}
					}
				}
			}
		}
	}
	probe := func(allowed bool, deadline time.Time) {
		t.Helper()
		for _, client := range cfg.Clients {
			probeCtx, stop := context.WithDeadline(ctx, deadline)
			args := []string{"-F", "/dev/null", "-i", cfg.Key, "-p", fmt.Sprint(client.Port),
				"-o", "UserKnownHostsFile=" + cfg.KnownHosts, "-o", "StrictHostKeyChecking=yes",
				"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
				"-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
				"-o", "KbdInteractiveAuthentication=no", "-o", "GSSAPIAuthentication=no",
				"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=5",
				cfg.User + "@" + client.Address, "id", "-un"}
			// Compare stdout and stderr separately: OpenSSH 10 prints a
			// post-quantum key-exchange warning to stderr on success.
			var stdout, stderr strings.Builder
			command := exec.CommandContext(probeCtx, "ssh", args...)
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			stop()
			if allowed {
				if err != nil || strings.TrimSpace(stdout.String()) != cfg.User {
					t.Fatalf("%s: new SSH key login did not succeed: %v", client.Alias, err)
				}
			} else {
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 255 || !strings.Contains(stderr.String(), "Permission denied (") || !strings.Contains(stderr.String(), "publickey") {
					t.Fatalf("%s: expected explicit public-key denial, got %v", client.Alias, err)
				}
			}
			t.Logf("client=%s SSH allowed=%t verified", client.Alias, allowed)
		}
	}
	apply(cfg.AddRoster, true, false)
	apply(cfg.AddRoster, false, false)
	probe(true, time.Now().Add(10*time.Second)) // warm all old-key caches
	apply(cfg.Revoke, false, false)
	revoked := time.Now()
	probe(false, revoked.Add(10*time.Second))
	t.Logf("post-revoke SSH denial on all clients in %s", time.Since(revoked))
	apply(cfg.Revoke, false, true)
	probe(false, time.Now().Add(10*time.Second))
	apply(cfg.AddRoster, false, false)
	probe(true, time.Now().Add(10*time.Second))
}
