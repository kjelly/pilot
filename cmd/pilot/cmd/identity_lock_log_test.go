package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The lock reads the inventory through the playbook's own -e and vault
// arguments, and `ansible-inventory --list` prints the decrypted value of every
// variable on every host. With the runtime's ANSIBLE_LOG_PATH Ansible writes
// that whole listing to the controller log; the log's redaction masks the
// variables that are named like a secret (password, token, ...) and nothing
// else, so a value under any other name would stay in ansible.log in clear
// text. The calls that carry the arguments therefore run without a log.
//
// The values below are fake: the log is real, the tool is real
// ansible-inventory, and the vars file stands in for `-e @.vault/main.yaml`.

const logSentinel = "sentinel-not-a-credential"

// ansibleLogOf runs fn in a context whose Ansible runtime logs to a fresh file,
// the way every pilot command's runtime does (prepareDeployAnsibleRuntime), and
// returns what the file holds afterwards.
func ansibleLogOf(t *testing.T, fn func(ctx context.Context)) string {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "ansible.log")
	fn(withDeployAnsibleRuntime(context.Background(), deployAnsibleRuntime{
		Env:     []string{"ANSIBLE_LOG_PATH=" + logPath},
		LogPath: logPath,
	}))
	data, err := os.ReadFile(logPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

func TestIdentityLockDerivationKeepsDecryptedValuesOutOfTheAnsibleLog(t *testing.T) {
	inv := writeEffectiveInventory(t, effectiveInventory)
	// The variable name is one the log's redaction does not mask.
	vars := writeVarsFile(t, "ansible_host: 192.0.2.99\nbind_value: "+logSentinel+"\n")
	args := []string{"-e", "@" + vars}

	// What makes the rest show something: the same listing, run the way the
	// deploy runner reads the inventory variables of an extra-vars file
	// (resolveInventoryVariables), does put the value into the log.
	t.Run("the premise: an ordinary listing with the arguments is logged in clear text", func(t *testing.T) {
		log := ansibleLogOf(t, func(ctx context.Context) {
			if _, err := resolveInventoryVariables(ctx, inv, nil, vaultInput{ExtraVarsFile: vars}); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(log, logSentinel) {
			t.Fatalf("the plain listing did not log the value (log = %q): this test shows nothing", log)
		}
	})

	t.Run("the inventory listing with the arguments", func(t *testing.T) {
		var value any
		log := ansibleLogOf(t, func(ctx context.Context) {
			snapshot, err := loadDeployInventorySnapshotWithArgs(ctx, inv, args)
			if err != nil {
				t.Fatal(err)
			}
			value = snapshot.HostVars["ipa-1"]["bind_value"]
		})
		if value != logSentinel {
			t.Fatalf("the listing did not carry the value (%v): the lock would not see the variables it asks for", value)
		}
		if strings.Contains(log, logSentinel) {
			t.Fatalf("the controller log holds a decrypted value:\n%s", log)
		}
	})

	t.Run("the extra vars listing", func(t *testing.T) {
		var group string
		log := ansibleLogOf(t, func(ctx context.Context) {
			var err error
			group, err = loadEffectiveTargetGroup(ctx, args)
			if err != nil {
				t.Fatal(err)
			}
		})
		if group != identityDefaultTargetGroup {
			t.Fatalf("target_group = %q", group)
		}
		if strings.Contains(log, logSentinel) {
			t.Fatalf("the controller log holds a decrypted value:\n%s", log)
		}
	})

	t.Run("the whole derivation still finds the host the arguments point at", func(t *testing.T) {
		var host, address string
		log := ansibleLogOf(t, func(ctx context.Context) {
			h, target, err := identityLockTarget(ctx, identityLockRequest{Inventory: inv, ExtraArgs: args})
			if err != nil {
				t.Fatal(err)
			}
			host, address = h, target.Host
		})
		if host != "ipa-1" || address != "192.0.2.99" {
			t.Fatalf("host = %q, address = %q: the arguments' ansible_host was not followed", host, address)
		}
		if strings.Contains(log, logSentinel) {
			t.Fatalf("the controller log holds a decrypted value:\n%s", log)
		}
	})

	// No runtime in the context: the command inherits this process's
	// environment, the ANSIBLE_LOG_PATH of the operator's shell included.
	t.Run("a log path from the process environment", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "operator.log")
		t.Setenv("ANSIBLE_LOG_PATH", logPath)
		if _, _, err := identityLockTarget(context.Background(), identityLockRequest{Inventory: inv, ExtraArgs: args}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(logPath)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if strings.Contains(string(data), logSentinel) {
			t.Fatalf("the operator's ANSIBLE_LOG_PATH holds a decrypted value:\n%s", data)
		}
	})
}
