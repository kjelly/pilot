package cmd

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/delivery"
)

func TestParseHostFactsLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want delivery.HostFacts
	}{
		{
			name: "ubuntu keeps full two-part version",
			line: "ubuntu;24.04;4;7975;38\n",
			want: delivery.HostFacts{Available: true, Distro: "ubuntu", Version: "24.04", CPU: 4, RAMMiB: 7975, DiskGiB: 38},
		},
		{
			name: "almalinux truncates point release to major version",
			line: "almalinux;9.4;2;3900;19",
			want: delivery.HostFacts{Available: true, Distro: "almalinux", Version: "9", CPU: 2, RAMMiB: 3900, DiskGiB: 19},
		},
		{
			name: "rhel truncates point release to major version",
			line: "rhel;9.4;8;16000;100",
			want: delivery.HostFacts{Available: true, Distro: "rhel", Version: "9", CPU: 8, RAMMiB: 16000, DiskGiB: 100},
		},
		{
			name: "rocky already-bare major version is left alone",
			line: "rocky;9;1;2000;10",
			want: delivery.HostFacts{Available: true, Distro: "rocky", Version: "9", CPU: 1, RAMMiB: 2000, DiskGiB: 10},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseHostFactsLine(tc.line)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseHostFactsLine(%q) = %+v, want %+v", tc.line, got, tc.want)
			}
		})
	}
}

func TestParseHostFactsLineRejectsMalformedInput(t *testing.T) {
	for _, line := range []string{
		"",
		"ubuntu;24.04",
		"ubuntu;24.04;not-a-number;7975;38",
		"ubuntu;24.04;4;not-a-number;38",
		"ubuntu;24.04;4;7975;not-a-number",
	} {
		if _, err := parseHostFactsLine(line); err == nil {
			t.Fatalf("parseHostFactsLine(%q) unexpectedly succeeded", line)
		}
	}
}

func TestExtractAdHocStdout(t *testing.T) {
	doc := `{"plays":[{"tasks":[{"hosts":{"nexus":{"stdout":"ubuntu;24.04;4;7975;38","rc":0,"failed":false,"unreachable":false}}}]}]}`
	got, err := extractAdHocStdout(doc, "nexus")
	if err != nil {
		t.Fatal(err)
	}
	if want := "ubuntu;24.04;4;7975;38"; got != want {
		t.Fatalf("extractAdHocStdout stdout = %q, want %q", got, want)
	}
}

// TestExtractAdHocStdoutRealCallbackFixture uses an actual
// `ANSIBLE_STDOUT_CALLBACK=ansible.posix.json` document captured from a real
// `ansible ... -m shell -a <hostFactsProbeCommand>` run against localhost
// (ansible.posix 2.1.0), trimmed of irrelevant fields. This guards against
// silently drifting from the real plugin's document shape, which the
// hand-written fixture in TestExtractAdHocStdout can't do on its own.
func TestExtractAdHocStdoutRealCallbackFixture(t *testing.T) {
	const doc = `{
		"plays": [{
			"tasks": [{
				"hosts": {
					"localtest": {
						"action": "shell",
						"changed": true,
						"cmd": ". /etc/os-release 2>/dev/null; printf '%s;%s;%s;%s;%s\n' \"$ID\" \"$VERSION_ID\"",
						"rc": 0,
						"stderr": "",
						"stdout": "ubuntu;24.04;12;64006;268",
						"stdout_lines": ["ubuntu;24.04;12;64006;268"]
					}
				}
			}]
		}],
		"stats": {"localtest": {"changed": 1, "failures": 0, "ok": 1, "unreachable": 0}}
	}`
	stdout, err := extractAdHocStdout(doc, "localtest")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := parseHostFactsLine(stdout)
	if err != nil {
		t.Fatal(err)
	}
	want := delivery.HostFacts{Available: true, Distro: "ubuntu", Version: "24.04", CPU: 12, RAMMiB: 64006, DiskGiB: 268}
	if !reflect.DeepEqual(facts, want) {
		t.Fatalf("facts = %+v, want %+v", facts, want)
	}
}

func TestExtractAdHocStdoutFailsClosedOnUnreachableOrFailed(t *testing.T) {
	unreachable := `{"plays":[{"tasks":[{"hosts":{"nexus":{"stdout":"","rc":-1,"failed":false,"unreachable":true}}}]}]}`
	if _, err := extractAdHocStdout(unreachable, "nexus"); err == nil {
		t.Fatal("extractAdHocStdout accepted an unreachable host result")
	}

	failed := `{"plays":[{"tasks":[{"hosts":{"nexus":{"stdout":"","rc":1,"failed":true,"unreachable":false}}}]}]}`
	if _, err := extractAdHocStdout(failed, "nexus"); err == nil {
		t.Fatal("extractAdHocStdout accepted a failed host result")
	}

	missing := `{"plays":[{"tasks":[{"hosts":{"other-host":{"stdout":"x","rc":0}}}]}]}`
	if _, err := extractAdHocStdout(missing, "nexus"); err == nil {
		t.Fatal("extractAdHocStdout accepted a document missing the requested host")
	}
}

// gatherHostFacts must fail open per host: a host that can't be probed (here,
// every host, since there is no real "ansible" reachable in this unit test
// environment) must simply be absent from the result rather than erroring
// the whole batch or blocking on the others.
func TestGatherHostFactsFailsOpenPerHostOnProbeFailure(t *testing.T) {
	runtime, err := prepareDeployAnsibleRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := withDeployAnsibleRuntime(context.Background(), runtime)
	hosts := []string{"unreachable-host-1", "unreachable-host-2"}
	facts := gatherHostFacts(ctx, "does-not-matter-for-this-test.yml", hosts, nil)
	if len(facts) != 0 {
		t.Fatalf("gatherHostFacts against unreachable hosts = %+v, want empty", facts)
	}
}

func TestHostFactsProbeCommandIsReadOnly(t *testing.T) {
	command := hostFactsProbeCommand([]string{"/var/lib/docker", "/opt/pilot/wazuh-docker"})
	for _, mutating := range []string{"rm ", "mkfs", "dd if=", "shutdown", "reboot", "> /", "mkdir", "touch"} {
		if strings.Contains(command, mutating) {
			t.Fatalf("hostFactsProbeCommand contains a mutating pattern %q: %s", mutating, command)
		}
	}
}

func TestHostFactsProbeCommandMeasuresEachDiskPath(t *testing.T) {
	if got := hostFactsProbeCommand(nil); got != hostFactsBaseProbe {
		t.Fatalf("hostFactsProbeCommand(nil) = %q, want the base probe alone", got)
	}
	got := hostFactsProbeCommand([]string{"/opt/pilot/wazuh-docker", "/var/lib/docker"})
	if want := hostFactsBaseProbe + "; for p in '/opt/pilot/wazuh-docker' '/var/lib/docker'; do " + hostFactsDiskPathProbe + "; done"; got != want {
		t.Fatalf("hostFactsProbeCommand = %q, want %q", got, want)
	}
}

// TestParseHostFactsOutputRealDiskPathFixture uses the callback document of a
// real `ansible ... -m shell -a <hostFactsProbeCommand(...)>` run (ansible-core
// 2.19.14 in the pilot-cli image, ansible.posix.json), trimmed of irrelevant
// fields. The host has 38 GiB free on / and its data directories bind-mounted
// from a separate 500 GiB filesystem; /var/lib/pilot/prometheus did not exist
// yet, so the probe measured its nearest existing ancestor, the
// /var/lib/pilot bind mount.
func TestParseHostFactsOutputRealDiskPathFixture(t *testing.T) {
	const doc = `{
		"plays": [{
			"tasks": [{
				"hosts": {
					"dev-nexus": {
						"action": "shell",
						"changed": true,
						"rc": 0,
						"stderr": "",
						"stdout": "ubuntu;24.04;8;23964;38\ndisk;/opt/pilot/wazuh-docker;467\ndisk;/var/lib/docker;467\ndisk;/var/lib/pilot/prometheus;467",
						"stdout_lines": [
							"ubuntu;24.04;8;23964;38",
							"disk;/opt/pilot/wazuh-docker;467",
							"disk;/var/lib/docker;467",
							"disk;/var/lib/pilot/prometheus;467"
						]
					}
				}
			}]
		}],
		"stats": {"dev-nexus": {"changed": 1, "failures": 0, "ok": 1, "unreachable": 0}}
	}`
	stdout, err := extractAdHocStdout(doc, "dev-nexus")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := parseHostFactsOutput(stdout)
	if err != nil {
		t.Fatal(err)
	}
	want := delivery.HostFacts{
		Available: true, Distro: "ubuntu", Version: "24.04", CPU: 8, RAMMiB: 23964, DiskGiB: 38,
		DiskGiBByPath: map[string]int{"/opt/pilot/wazuh-docker": 467, "/var/lib/docker": 467, "/var/lib/pilot/prometheus": 467},
	}
	if !reflect.DeepEqual(facts, want) {
		t.Fatalf("facts = %+v, want %+v", facts, want)
	}
}

func TestParseHostFactsOutputLeavesUnmeasuredDiskPathOut(t *testing.T) {
	facts, err := parseHostFactsOutput("ubuntu;24.04;4;7975;38\ndisk;/var/lib/docker;\ndisk;/opt/pilot;120\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"/opt/pilot": 120}; !reflect.DeepEqual(facts.DiskGiBByPath, want) {
		t.Fatalf("DiskGiBByPath = %v, want %v", facts.DiskGiBByPath, want)
	}
}

func TestParseHostFactsOutputRejectsMalformedDiskLine(t *testing.T) {
	for _, line := range []string{
		"disk;/var/lib/docker",
		"disk;/var/lib/docker;1;2",
		"disc;/var/lib/docker;10",
		"disk;;10",
		"disk;/var/lib/docker;ten",
	} {
		if _, err := parseHostFactsOutput("ubuntu;24.04;4;7975;38\n" + line); err == nil {
			t.Fatalf("parseHostFactsOutput accepted disk line %q", line)
		}
	}
}
