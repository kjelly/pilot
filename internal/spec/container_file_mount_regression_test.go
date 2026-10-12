package spec

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_FileMountedContainersRestartOnStaleMounts is a repo-wide
// lint over playbooks/**. ansible.builtin.copy replaces a file by renaming
// a new one over it, and a single-file bind mount keeps the inode the
// container started with, so a running container keeps reading the old
// file. Restarting only when this run's render reports `changed` misses
// every run after one that rendered the file but never reached the
// restart (a failure, --tags, a wrong restart condition): the file then
// never changes again and the container never restarts. pilot-prometheus
// served a weeks-old prometheus.yml in production that way (2026-10-12).
//
// Every docker_container task that bind-mounts a single file must be
// preceded by tasks/container-file-mount-drift.yml for the same container
// (with no other such check in between, since they share one result fact),
// tagged `always` so --tags runs keep it, with the same `when:` as the
// container (a check skipped while its container runs would leave the
// previous container's result in place), and must restart on
// container_mount_drift_stale.
func TestRegression_FileMountedContainersRestartOnStaleMounts(t *testing.T) {
	containers := 0
	for _, path := range playbookFiles(t) {
		problems, n := staleFileMountGaps(loadYAML(t, path))
		containers += n
		for _, p := range problems {
			t.Errorf("%s: %s", strings.TrimPrefix(path, "../../"), p)
		}
	}
	// playbooks/apply runs about ten containers with single-file mounts;
	// none found means the detection broke.
	if containers < 5 {
		t.Fatalf("found only %d containers with single-file bind mounts; the detection is broken", containers)
	}
}

// TestRegression_ContainerFileMountDriftHidesWhatItReads: the inspect
// result holds the container's Config.Env (the Teams proxy's webhook URL)
// and a mounted password file hashes to the unsalted SHA-256 of the
// password, while the callers' container and render tasks are no_log for
// those values. Every task in the check that registers or loops over what
// docker or the files returned must be no_log too; -v and the JSON
// callback print registered results and loop items in full. Its own error
// is reported by a separate task that prints only the module's msg.
func TestRegression_ContainerFileMountDriftHidesWhatItReads(t *testing.T) {
	path := "../../playbooks/apply/tasks/" + staleMountCheckFile
	tasks, _ := loadYAML(t, path).([]any)
	checked := 0
	for _, item := range tasks {
		task, _ := item.(map[string]any)
		_, registers := task["register"]
		_, loops := task["loop"]
		if !registers && !loops {
			continue
		}
		checked++
		if noLog, _ := task["no_log"].(bool); !noLog {
			t.Errorf("%s: task %q registers or loops over inspect/file results but is not no_log", staleMountCheckFile, task["name"])
		}
	}
	// Inspect, stat, hash and record; fewer means the file changed shape.
	if checked < 4 {
		t.Fatalf("%s: found %d tasks that register or loop, want at least 4", staleMountCheckFile, checked)
	}
}

func TestStaleFileMountGaps(t *testing.T) {
	const check = `
    - name: check
      tags: [always]
      ansible.builtin.include_tasks:
        file: tasks/container-file-mount-drift.yml
        apply: {tags: [always]}
      vars: {container_mount_drift_name: %s}
`
	cases := []struct {
		name       string
		yaml       string
		want       int
		containers int
	}{
		{"file mount restarted only on this run's render (the old prometheus-apply.yml)", `
- hosts: all
  tasks:
    - copy: {dest: /etc/x/app.yml, content: x}
      register: app_yml
    - community.docker.docker_container:
        name: app
        restart: "{{ (app_yml | default({})) is changed }}"
        volumes: ["/etc/x/app.yml:/etc/app/app.yml:ro"]
`, 2, 1},
		{"checked and restarted on a stale mount", `
- hosts: all
  tasks:` + fmt.Sprintf(check, "app") + `
    - community.docker.docker_container:
        name: app
        restart: "{{ (app_yml | default({})) is changed or container_mount_drift_stale | default(false) | bool }}"
        volumes: ["/etc/x/app.yml:/etc/app/app.yml:ro"]
`, 0, 1},
		{"check is for another container", `
- hosts: all
  tasks:` + fmt.Sprintf(check, "other") + `
    - community.docker.docker_container:
        name: app
        restart: "{{ container_mount_drift_stale | default(false) | bool }}"
        volumes: ["/etc/x/app.yml:/etc/app/app.yml:ro"]
`, 1, 1},
		{"checked but the restart ignores the result", `
- hosts: all
  tasks:` + fmt.Sprintf(check, "app") + `
    - community.docker.docker_container:
        name: app
        restart: "{{ (app_yml | default({})) is changed }}"
        volumes: ["/etc/x/app.yml:/etc/app/app.yml:ro"]
`, 1, 1},
		{"check skipped while its container runs", `
- hosts: all
  tasks:
    - name: check
      tags: [always]
      ansible.builtin.include_tasks:
        file: tasks/container-file-mount-drift.yml
        apply: {tags: [always]}
      vars: {container_mount_drift_name: app}
      when: app_mode == 'a'
    - community.docker.docker_container:
        name: app
        restart: "{{ container_mount_drift_stale | default(false) | bool }}"
        volumes: ["/etc/x/app.yml:/etc/app/app.yml:ro"]
`, 1, 1},
		{"check and container under the same when", `
- hosts: all
  tasks:
    - name: check
      tags: [always]
      ansible.builtin.include_tasks:
        file: tasks/container-file-mount-drift.yml
        apply: {tags: [always]}
      vars: {container_mount_drift_name: app}
      when: app_mode == 'a'
    - community.docker.docker_container:
        name: app
        restart: "{{ container_mount_drift_stale | default(false) | bool }}"
        volumes: ["/etc/x/app.yml:/etc/app/app.yml:ro"]
      when: app_mode == 'a'
`, 0, 1},
		{"check not tagged always", `
- hosts: all
  tasks:
    - ansible.builtin.include_tasks:
        file: tasks/container-file-mount-drift.yml
      vars: {container_mount_drift_name: app}
    - community.docker.docker_container:
        name: app
        restart: "{{ container_mount_drift_stale | default(false) | bool }}"
        volumes: ["/etc/x/app.yml:/etc/app/app.yml:ro"]
`, 1, 1},
		{"file mount inside a volumes expression, in a block (log-shipping, seaweedfs-s3)", `
- hosts: all
  tasks:
    - block:
        - community.docker.docker_container:
            name: promtail
            restart: "{{ (cfg | default({})) is changed }}"
            volumes: >-
              {{ [dir + '/promtail-config.yml:/etc/promtail/config.yml:ro', logs + ':' + logs + ':ro'] }}
`, 2, 1},
		{"directory mounts only (grafana)", `
- hosts: all
  tasks:
    - community.docker.docker_container:
        name: grafana
        volumes: ["/etc/x/provisioning:/etc/grafana/provisioning:ro", "/var/lib/g:/var/lib/grafana"]
`, 0, 0},
		{"removing a container", `
- hosts: all
  tasks:
    - community.docker.docker_container:
        name: app
        state: absent
        volumes: ["/etc/x/app.yml:/etc/app/app.yml:ro"]
`, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, n := staleFileMountGaps(doc)
			if n != tc.containers {
				t.Fatalf("found %d containers with file mounts, want %d", n, tc.containers)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d problems %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

// singleFileMount matches the container side of a bind mount that names a
// file (a path ending in a file extension), in a volumes list item or in a
// Jinja expression that builds the list.
var singleFileMount = regexp.MustCompile(`:(/[^\s:'"{}()\]]*\.[A-Za-z0-9]+)(?::r[ow])?(?:['"\]\s,]|$)`)

const staleMountCheckFile = "container-file-mount-drift.yml"

// staleFileMountGaps returns one message per docker_container task in doc
// that bind-mounts a single file without the stale-mount check described
// above, and the number of such containers found.
func staleFileMountGaps(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	type entry struct {
		task map[string]any
		tags []string
	}
	var tasks []entry
	collect := func(list any) {
		walkTaskTree(list, nil, func(task map[string]any, tags []string) { tasks = append(tasks, entry{task, tags}) })
	}
	if len(plays) > 0 {
		if first, ok := plays[0].(map[string]any); ok {
			if _, isPlay := first["hosts"]; !isPlay {
				collect(plays) // a task file
			}
		}
	}
	for _, p := range plays {
		play, _ := p.(map[string]any)
		if _, ok := play["hosts"]; !ok {
			continue
		}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			collect(play[section])
		}
	}

	var out []string
	containers := 0
	var lastCheck *entry
	for i := range tasks {
		e := &tasks[i]
		if includesStaleMountCheck(e.task) {
			lastCheck = e
			continue
		}
		args := dockerContainerArgs(e.task)
		if args == nil {
			continue
		}
		if state, _ := args["state"].(string); state == "absent" || state == "stopped" {
			continue
		}
		volumes, err := yaml.Marshal(args["volumes"])
		if err != nil || !singleFileMount.Match(volumes) {
			continue
		}
		containers++
		name := fmt.Sprint(args["name"])
		switch {
		case lastCheck == nil:
			out = append(out, fmt.Sprintf("container %s bind-mounts a single file but no %s check runs before it", name, staleMountCheckFile))
		case staleMountCheckName(lastCheck.task) != name:
			out = append(out, fmt.Sprintf("container %s: the %s check right before it is for %q", name, staleMountCheckFile, staleMountCheckName(lastCheck.task)))
		case !hasTag(lastCheck.tags, "always"):
			out = append(out, fmt.Sprintf("container %s: its %s check must be tagged always, or --tags runs skip it", name, staleMountCheckFile))
		case fmt.Sprint(lastCheck.task["when"]) != fmt.Sprint(e.task["when"]):
			out = append(out, fmt.Sprintf("container %s: its %s check has when: %v, the container has when: %v; give them the same condition", name, staleMountCheckFile, lastCheck.task["when"], e.task["when"]))
		}
		if !strings.Contains(fmt.Sprint(args["restart"]), "container_mount_drift_stale") {
			out = append(out, fmt.Sprintf("container %s bind-mounts a single file but its restart: does not read container_mount_drift_stale", name))
		}
		lastCheck = nil
	}
	return out, containers
}

func includesStaleMountCheck(task map[string]any) bool {
	for _, key := range []string{"ansible.builtin.include_tasks", "include_tasks", "ansible.builtin.import_tasks", "import_tasks"} {
		switch v := task[key].(type) {
		case string:
			return strings.HasSuffix(v, staleMountCheckFile)
		case map[string]any:
			file, _ := v["file"].(string)
			return strings.HasSuffix(file, staleMountCheckFile)
		}
	}
	return false
}

func staleMountCheckName(task map[string]any) string {
	vars, _ := task["vars"].(map[string]any)
	return fmt.Sprint(vars["container_mount_drift_name"])
}

func dockerContainerArgs(task map[string]any) map[string]any {
	for _, key := range []string{"community.docker.docker_container", "docker_container"} {
		if args, ok := task[key].(map[string]any); ok {
			return args
		}
	}
	return nil
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
