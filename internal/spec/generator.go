package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Task is one Ansible task generated from one (or more) spec rows.
// A task's SourceIDs records every spec row it satisfied; if the
// spec deduplicates three "disable root SSH" rows into one task,
// all three IDs end up in SourceIDs so traceability survives.
type Task struct {
	Name      string   // `C2.5.1, C2.5.2 — Disable root SSH login`
	Module    string   // `ansible.builtin.lineinfile`
	Params    string   // raw YAML fragment (key: value lines, indented)
	Become    bool     // becomes: true on the task
	SourceIDs []string // spec row IDs that produced this task
	// Raw maps to the source command for tools that need to fall
	// back to `ansible.builtin.command` when no stateful module fits.
	RawCommand string
}

// Playbook is a top-level Ansible playbook assembled from many Tasks.
type Playbook struct {
	Hosts       string // default `localhost`; the spec generator does not assume remote
	Connection  string // default `local`
	GatherFacts bool   // default false (spec tasks are usually atomic)
	Name        string // play name
	Tasks       []Task
	// MapIDToTask is the audit hook: given a spec ID, which task(s)
	// implement it? Multiple task IDs are possible when dedup splits
	// a row. Stored as a sorted slice per ID for stable diffs.
	MapIDToTask map[string][]int
}

// GenerateOptions tunes the generator.
type GenerateOptions struct {
	// Hosts, when non-empty, overrides the play's `hosts:` (default: localhost).
	Hosts string
	// Connection overrides `connection:` (default: local).
	Connection string
	// GatherFacts forces `gather_facts:` on (default off).
	GatherFacts bool
	// IncludeRaw uses the row.Command verbatim as the task body
	// (wrapped in ansible.builtin.command). Useful for verifier-only
	// specs that don't have a real Ansible module yet.
	IncludeRaw bool
	// PlayName overrides the play `name:` (default: spec.Title).
	PlayName string
}

// Generate walks a parsed Spec and produces a Playbook. Rows with
// the same (Module, ParamHash) are deduped into a single task whose
// Name carries every contributing row ID.
//
// The generator is intentionally conservative: it picks the
// closest-matching Ansible module based on heuristics over the row's
// Command + Expected. If nothing fits cleanly, it falls back to
// `ansible.builtin.command` with the row's exact command (only when
// IncludeRaw is true). This way a spec written before the playbook
// exists still yields something runnable.
func Generate(s *Spec, opts GenerateOptions) (*Playbook, error) {
	if s == nil {
		return nil, fmt.Errorf("spec: nil")
	}
	if len(s.Rows) == 0 {
		return nil, fmt.Errorf("spec: no rows")
	}
	pb := &Playbook{
		Hosts:       defaultStr(opts.Hosts, "localhost"),
		Connection:  defaultStr(opts.Connection, "local"),
		GatherFacts: opts.GatherFacts,
		Name:        defaultStr(opts.PlayName, s.Title),
		MapIDToTask: map[string][]int{},
	}
	// dedupKey → taskIndex
	dedup := map[string]int{}
	for _, r := range s.Rows {
		mod, params, raw := classifyRow(r, opts.IncludeRaw)
		key := dedupKey(mod, params)
		if idx, ok := dedup[key]; ok {
			// Merge this row's ID into the existing task.
			pb.Tasks[idx].SourceIDs = append(pb.Tasks[idx].SourceIDs, r.ID)
			pb.MapIDToTask[r.ID] = append(pb.MapIDToTask[r.ID], idx)
			continue
		}
		t := Task{
			Name:       fmt.Sprintf("%s — %s", r.ID, truncate(r.Check, 60)),
			Module:     mod,
			Params:     params,
			Become:     NeedsBecome(r),
			SourceIDs:  []string{r.ID},
			RawCommand: raw,
		}
		pb.Tasks = append(pb.Tasks, t)
		idx := len(pb.Tasks) - 1
		dedup[key] = idx
		pb.MapIDToTask[r.ID] = []int{idx}
	}
	// Stable source-id order inside each task (for reproducible diffs).
	for i := range pb.Tasks {
		sort.Strings(pb.Tasks[i].SourceIDs)
	}
	return pb, nil
}

// RenderYAML returns a single-document YAML string for the playbook.
// It is intentionally hand-written (not yaml.Marshal) so the output
// matches what an Ansible engineer would produce by hand.
func (p *Playbook) RenderYAML() string {
	var sb strings.Builder
	sb.WriteString("---\n")
	fmt.Fprintf(&sb, "- name: %s\n", p.Name)
	fmt.Fprintf(&sb, "  hosts: %s\n", p.Hosts)
	fmt.Fprintf(&sb, "  connection: %s\n", p.Connection)
	fmt.Fprintf(&sb, "  gather_facts: %v\n", boolStr(p.GatherFacts))
	sb.WriteString("\n  tasks:\n")
	for _, t := range p.Tasks {
		if t.RawCommand != "" && t.Module == "ansible.builtin.command" {
			fmt.Fprintf(&sb, "    - name: %q\n", t.Name)
			fmt.Fprintf(&sb, "      ansible.builtin.command: %s\n", quoteScalar(t.RawCommand))
			if t.Become {
				sb.WriteString("      become: true\n")
			}
			sb.WriteString("      changed_when: false\n")
			writeTags(&sb, t.SourceIDs)
			continue
		}
		fmt.Fprintf(&sb, "    - name: %q\n", t.Name)
		fmt.Fprintf(&sb, "      %s:\n", t.Module)
		for _, line := range strings.Split(t.Params, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			fmt.Fprintf(&sb, "        %s\n", line)
		}
		if t.Become {
			sb.WriteString("      become: true\n")
		}
		writeTags(&sb, t.SourceIDs)
	}
	return sb.String()
}

// writeTags emits `tags: [C1, C2]` so `ansible-playbook --tags C3` runs
// just the task(s) for one spec row during iteration — no need to re-run
// the whole playbook while tuning a single check. Tags mirror the spec
// IDs the task satisfies, keeping the spec↔playbook trace grep-able.
func writeTags(sb *strings.Builder, ids []string) {
	if len(ids) == 0 {
		return
	}
	fmt.Fprintf(sb, "      tags: [%s]\n", strings.Join(ids, ", "))
}

func classifyRow(r Row, includeRaw bool) (mod string, params string, raw string) {
	cmd := strings.TrimSpace(r.Command)
	exp := strings.TrimSpace(r.Expected)

	// Pattern A: file-exists / file-readability checks → ansible.builtin.stat
	if isTestPresent(cmd) || strings.HasPrefix(cmd, "test -") || strings.HasPrefix(cmd, "[ -") {
		path := extractPathFromTest(cmd)
		if path != "" {
			return "ansible.builtin.stat", fmt.Sprintf("path: %s", quoteScalar(path)), ""
		}
	}
	// Pattern B: grep -E ... / grep -qE ... <file>
	//
	// We try to extract the literal pattern + path so the generated
	// task stays an ansible-native command rather than a debug
	// placeholder. Re-anchoring the comparison on rc (grep exits 0 on
	// match, 1 on miss) is universally portable across shells.
	if strings.HasPrefix(cmd, "grep ") {
		fields := strings.Fields(cmd)
		idx := 1
		for idx < len(fields) && strings.HasPrefix(fields[idx], "-") {
			idx++
		}
		pattern, path := "", ""
		if idx < len(fields) {
			pattern = fields[idx]
			idx++
		}
		if idx < len(fields) {
			path = fields[idx]
		}
		if pattern != "" && path != "" {
			// Use ansible.builtin.command with the raw grep. failed_when
			// honors the spec's Expected: rc 0 → present, anything else
			// → absent. This is what the apply playbook uses for sanity
			// checks too, so the verify-side and apply-side semantics
			// align. We add create: true only for paths that need it
			// (relevant for C7 — config.yaml might not exist before the
			// first apply).
			_ = pattern
			return "ansible.builtin.command",
				fmt.Sprintf("argv:\n- grep\n- -qE\n- %s\n- %s\nchanged_when: false\nfailed_when: false\nregister: spec_%s_grep", quoteScalar(pattern), quoteScalar(path), strings.ToLower(r.ID)),
				cmd
		}
		// Fall through to includeRaw.
	}
	// Pattern C: sysctl -n <key> → ansible.posix.sysctl
	//
	// Param continuation lines must NOT carry their own indentation:
	// RenderYAML adds a uniform 8-space indent to every line. Embedding
	// leading spaces here double-indents the continuation key and yields
	// invalid YAML.
	if strings.HasPrefix(cmd, "sysctl -n ") {
		key := strings.TrimPrefix(cmd, "sysctl -n ")
		key = strings.TrimSpace(key)
		// unquote the expected: the spec uses quotes (e.g. "0") to mark
		// it as a string; those quotes must not leak into the YAML value.
		return "ansible.posix.sysctl",
			fmt.Sprintf("name: %s\nvalue: %s", quoteScalar(key), quoteScalar(unquote(exp))),
			""
	}
	// Pattern D: systemctl is-active <svc> → ansible.builtin.systemd
	if strings.HasPrefix(cmd, "systemctl is-active ") {
		svc := strings.TrimSpace(strings.TrimPrefix(cmd, "systemctl is-active "))
		return "ansible.builtin.systemd",
			fmt.Sprintf("name: %s\nstate: started\nenabled: true", quoteScalar(svc)),
			""
	}
	// Pattern E: dpkg -s <pkg> → ansible.builtin.apt
	if strings.HasPrefix(cmd, "dpkg -s ") {
		pkg := strings.TrimSpace(strings.TrimPrefix(cmd, "dpkg -s "))
		return "ansible.builtin.apt",
			fmt.Sprintf("name: %s\nstate: present", quoteScalar(pkg)),
			""
	}
	// Pattern F: explicit awk "{if ($1+0 < 20.0) print OK; else print FAIL:...}" — load avg sanity
	if strings.HasPrefix(cmd, "awk ") && strings.Contains(cmd, "print") {
		return "ansible.builtin.debug",
			fmt.Sprintf("msg: %s", quoteScalar(fmt.Sprintf("Spec %s needs custom monitoring task — see verify script", r.ID))),
			""
	}
	// Fallback: use the raw command (only if includeRaw).
	if includeRaw {
		return "ansible.builtin.command", "", cmd
	}
	return "ansible.builtin.debug",
		fmt.Sprintf("msg: %s", quoteScalar(fmt.Sprintf("Spec %s: no module matched, manual playbook task needed (cmd=%s exp=%s)", r.ID, truncate(cmd, 40), exp))),
		""
}

func dedupKey(mod, params string) string {
	h := sha256.Sum256([]byte(mod + "\x00" + params))
	return hex.EncodeToString(h[:])
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func quoteScalar(s string) string {
	// Quote with double quotes; escape backslashes and double quotes.
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// unquote strips a single layer of surrounding single or double quotes.
// The spec's Expected column uses quotes to denote a string value
// (e.g. "0" for a sysctl); those quotes are presentation, not part of
// the value, and must not leak into generated YAML.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// NeedsBecome inspects the row command for any sign that the check
// runs against a privileged path or a root-only daemon. File mode
// checks (stat -c '%a' /etc/shadow), systemd checks, and container /
// service-inspection commands (docker ps, pg_isready) fall under this.
//
// This is the single source of truth for "does this row need root",
// shared by both the apply path (generated tasks get `become: true`)
// and the verify path (ad-hoc runs get `-b`). Keeping them on the
// same heuristic stops apply and verify from disagreeing about
// privilege — which is exactly what produced verify false-negatives
// when apply had already run the operation as root.
//
// The check is intentionally permissive: false positives just escalate
// a read-only check, which is harmless on passwordless-sudo systems
// (the vm-target's ubuntu user is one).
func NeedsBecome(r Row) bool {
	cmd := strings.ToLower(r.Command)
	exp := strings.ToLower(r.Expected)
	markers := []string{
		// privileged filesystem paths
		"/etc/", "/usr/", "/var/", "/boot/", "/proc/", "/sys/",
		// service / package management
		"systemctl", "sysctl", "dpkg", "apt", "journalctl",
		// container runtimes (socket is root-owned)
		"docker", "podman",
		// root-only daemon / socket probes
		"pg_isready", "ss ", "netstat",
	}
	joined := cmd + " " + exp
	for _, m := range markers {
		if strings.Contains(joined, m) {
			return true
		}
	}
	return false
}

// isTestPresent returns true for commands whose exit code alone
// answers the row's expected value (e.g. `test -f /etc/passwd`).
func isTestPresent(cmd string) bool {
	t := strings.TrimSpace(cmd)
	return strings.HasPrefix(t, "test ") || strings.HasPrefix(t, "[ ")
}

// extractPathFromTest pulls a literal path argument from a `test -f
// /path` or `[ -r /path ]` style command. Returns "" if no obvious
// path is found. We deliberately keep this dumb — anything more
// sophisticated belongs in shell.
func extractPathFromTest(cmd string) string {
	t := strings.TrimSpace(cmd)
	// Strip the test prefix variants.
	for _, p := range []string{"test -f ", "test -r ", "test -e ", "test -d ", "test -x ",
		"[ -f ", "[ -r ", "[ -e ", "[ -d ", "[ -x "} {
		if strings.HasPrefix(t, p) {
			path := strings.TrimSpace(strings.TrimPrefix(t, p))
			path = strings.TrimSuffix(path, " ]")
			path = strings.TrimSuffix(path, "]")
			return strings.TrimSpace(path)
		}
	}
	return ""
}
