package evidence

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEvidenceNativePluginDiscoveryParity(t *testing.T) {
	bin, err := exec.LookPath("ansible-playbook")
	if err != nil {
		if os.Getenv("PILOT_REQUIRE_ANSIBLE_EVIDENCE_TESTS") == "1" {
			t.Fatal(err)
		}
		t.Skip("ansible-playbook unavailable")
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	shebang, _, _ := strings.Cut(string(raw), "\n")
	interpreter := strings.Fields(strings.TrimPrefix(shebang, "#!"))
	if len(interpreter) == 0 || !strings.HasPrefix(shebang, "#!") {
		t.Fatal("cannot locate native Ansible interpreter")
	}
	program := `import json
from ansible.plugins.loader import get_all_plugin_loaders
print(json.dumps({loader.subdir: loader.config for _, loader in get_all_plugin_loaders()}))`
	args := append(interpreter[1:], "-c", program)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, interpreter[0], args...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(cmd.Dir, "ansible-tmp"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native loader discovery failed: %v\n%s", err, output)
	}
	var actual map[string][]string
	if err := json.Unmarshal(output, &actual); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string][]string{}
	for _, plugin := range ansiblePluginDirectories {
		paths := []string{"shell_plugins"}
		if plugin.defaultSuffix != "" {
			paths = []string{filepath.Join(home, ".ansible/plugins", plugin.defaultSuffix), filepath.Join("/usr/share/ansible/plugins", plugin.defaultSuffix)}
		}
		expected[plugin.subdir] = paths
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("native Ansible plugin discovery differs from bounded resolver inventory: native=%v expected=%v", actual, expected)
	}
	t.Logf("native loader directory and default-path parity: %s", output)
}
