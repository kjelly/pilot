package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Execute the production preflight and render task. A running auto TCP queue
// may not have spilled yet, so an empty spool cannot prove classic storage.
func TestRegression_SIEMQueueEngineSurvivesTransportChanges(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	data, err := os.ReadFile("../../playbooks/apply/tasks/rsyslog-relp-capability.yml")
	if err != nil {
		t.Fatal(err)
	}
	var production []map[string]any
	if err := yaml.Unmarshal(data, &production); err != nil {
		t.Fatal(err)
	}
	if len(production) < 4 || production[0]["name"] != "Queue: preserve an explicit classic engine across transport changes" {
		t.Fatal("queue transition guard must precede all capability and TLS writes")
	}
	const auto = `local6.* action(name="siem_audit" type="omfwd" queue.filename="siem_audit")
auth,authpriv.* action(name="siem_auth" type="omfwd" queue.filename="siem_auth")
`
	pinned := strings.ReplaceAll(auto, " type=", ` queue.diskQueueType="disk" type=`)
	for _, tc := range []struct {
		name, current, transport, marker string
		bothMarkers, segmented, refused  bool
		pins                             int
	}{
		{name: "fresh RELP", transport: "relp", pins: 2},
		{name: "RELP to TCP retains classic", current: strings.ReplaceAll(pinned, "omfwd", "omrelp"), transport: "tcp", pins: 2},
		{name: "classic TCP to RELP", current: pinned, transport: "relp", pins: 2},
		{name: "legacy TCP remains compatible", current: auto, transport: "tcp"},
		{name: "unspilled auto TCP is refused", current: auto, transport: "relp", refused: true},
		{name: "one pinned action is insufficient", current: strings.Replace(pinned, `queue.diskQueueType="disk" `, "", 1), transport: "relp", refused: true},
		{name: "both existing classic markers permit migration", current: auto, transport: "relp", marker: "RSYSLOG-DA-ENGINE-V1 Disk\n", bothMarkers: true, pins: 2},
		{name: "one marker cannot prove both engines", current: auto, transport: "relp", marker: "RSYSLOG-DA-ENGINE-V1 Disk\n", refused: true},
		{name: "TCP must preserve segmented backlog", current: pinned, transport: "tcp", segmented: true, refused: true},
		{name: "unknown marker is refused", current: pinned, transport: "relp", marker: "future-format\n", refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, "forward.conf")
			if tc.current != "" {
				if err := os.WriteFile(config, []byte(tc.current), 0600); err != nil {
					t.Fatal(err)
				}
			}
			spool := filepath.Join(dir, "spool")
			if err := os.Mkdir(spool, 0700); err != nil {
				t.Fatal(err)
			}
			backlog := filepath.Join(spool, "pending-history")
			if err := os.WriteFile(backlog, []byte("retain queued audit history"), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.marker != "" {
				for _, name := range []string{"siem_audit", "siem_auth"} {
					if name == "siem_auth" && !tc.bothMarkers {
						continue
					}
					if err := os.WriteFile(filepath.Join(spool, name+".da-engine"), []byte(tc.marker), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.segmented {
				if err := os.Mkdir(filepath.Join(spool, "siem_audit.segq"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			play := loadFirstPlay(t, "audit-log-forwarding-apply.yml")
			render := findNamedTask(t, play, "Step 7: Render 99-siem-forward.conf (local6.* + auth,authpriv.* -> siem-log-server)")
			copyTask := render["ansible.builtin.copy"].(map[string]any)
			delete(copyTask, "owner")
			delete(copyTask, "group")
			// The production TLS support probe is exercised on the VM. These
			// tasks isolate only engine selection, preservation and rendering.
			tasks := []any{production[0], production[1], production[len(production)-1], render}
			vars := map[string]any{"siem_forward_conf": config, "siem_queue_spool": spool, "siem_forward_transport": tc.transport,
				"siem_forwarding_enabled": true, "siem_forward_alias": "siem-log-server", "siem_forward_port": 514,
				"siem_relp_port": 20514, "siem_relp_server_name": "receiver.test.invalid"}
			body, err := yaml.Marshal([]any{map[string]any{"hosts": "all", "gather_facts": false, "vars": vars, "tasks": tasks}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "play.yml")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", path)
			command.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "local"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(dir, "remote"), "ANSIBLE_FORKS=1")
			out, runErr := command.CombinedOutput()
			if (runErr != nil) != tc.refused {
				t.Fatalf("refused=%v want %v\n%s", runErr, tc.refused, out)
			}
			got, _ := os.ReadFile(config)
			if tc.refused && string(got) != tc.current {
				t.Fatalf("refusal modified the old forwarding configuration\n%s", out)
			}
			if !tc.refused && strings.Count(string(got), `queue.diskQueueType="disk"`) != tc.pins {
				t.Fatalf("wrong rendered engine selection:\n%s\n%s", got, out)
			}
			if history, err := os.ReadFile(backlog); err != nil || string(history) != "retain queued audit history" {
				t.Fatal("queue history was modified")
			}
		})
	}
}
