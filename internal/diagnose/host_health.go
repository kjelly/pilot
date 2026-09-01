package diagnose

import (
	"fmt"
	"strconv"
	"strings"
)

// HostHealthSteps returns the fixed, read-only ad-hoc commands run
// directly against the target host for pilot_diagnose_host_health (Agent
// Monitoring Phase 2 §3). Thanos (CPU saturation trend) and Detection
// Engine (active signal summary) evidence are gathered separately by the
// MCP handler against their own central singleton hosts — this function
// only covers what the target host itself can answer.
func HostHealthSteps() []Step {
	return []Step{
		{ID: "uptime", Description: "uptime/boot time", Module: "command", Command: "cat /proc/uptime"},
		{ID: "load", Description: "current load averages", Module: "command", Command: "cat /proc/loadavg"},
		{ID: "memory", Description: "memory pressure/available memory", Module: "command", Command: "cat /proc/meminfo"},
		{ID: "disk", Description: "filesystem free bytes and inode pressure (real filesystems only)", Module: "shell",
			Command: "df -P -T -x tmpfs -x devtmpfs -x squashfs 2>/dev/null; echo ---INODES---; df -Pi -T -x tmpfs -x devtmpfs -x squashfs 2>/dev/null"},
		{ID: "failed-units", Description: "bounded list of failed systemd units", Module: "command",
			Command: "systemctl list-units --state=failed --no-legend --plain --no-pager"},
		{ID: "clock-sync", Description: "clock sync state", Module: "command", Command: "timedatectl show -p NTPSynchronized --value"},
		{ID: "interfaces", Description: "network interface/link summary", Module: "shell", Command: "ip -o link show"},
		{ID: "node-exporter", Description: "node_exporter scrape/up state (the same collector Prometheus itself scrapes)", Module: "command",
			Command: "systemctl is-active node_exporter"},
		{ID: "kernel-errors", Description: "bounded OOM/kernel error evidence — best-effort, permission-dependent like every other diagnose step (no become)", Module: "shell",
			Command: "journalctl -k -p err --no-pager -n 20 2>/dev/null || true"},
	}
}

// HostHealthOutput is the target-host-only evidence host_health gathers
// directly. Thanos/Detection Engine evidence lives alongside this in the
// MCP handler's own output type, not here — they run against different
// hosts and have their own graceful-degradation rules (Phase 2 §9:
// "missing optional Loki/Detection source returns partial evidence, not
// panic").
type HostHealthOutput struct {
	Reachable                    bool
	UptimeSeconds                float64
	Load1, Load5, Load15         float64
	MemTotalKiB, MemAvailableKiB int64
	Filesystems                  []FilesystemUsage
	FailedUnits                  []string
	ClockSynchronized            bool
	Interfaces                   []string
	NodeExporterActive           bool
	KernelErrorLines             []string
	Verdict                      string // healthy | degraded | unreachable | insufficient_evidence
	Steps                        []StepResult
}

// FilesystemUsage is one `df` row's parsed free-space/inode-pressure
// evidence.
type FilesystemUsage struct {
	Mount            string
	UsedPercent      int
	InodeUsedPercent int
}

// BuildHostHealthOutput synthesizes HostHealthOutput from
// HostHealthSteps' results. results must be in the exact order
// HostHealthSteps() returned them, or nil/empty when the host was
// entirely unreachable (reachable=false short-circuits every other
// field).
func BuildHostHealthOutput(reachable bool, results []StepResult) HostHealthOutput {
	out := HostHealthOutput{Reachable: reachable, Steps: results}
	if !reachable {
		out.Verdict = "unreachable"
		return out
	}

	find := func(id string) (StepResult, bool) {
		for _, r := range results {
			if r.Step.ID == id {
				return r, true
			}
		}
		return StepResult{}, false
	}
	ok := func(r StepResult) bool { return r.Result.RunErr == nil && !r.Result.Unreachable }

	if r, found := find("uptime"); found && ok(r) {
		fields := strings.Fields(r.Result.Stdout)
		if len(fields) > 0 {
			out.UptimeSeconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	if r, found := find("load"); found && ok(r) {
		fields := strings.Fields(r.Result.Stdout)
		if len(fields) >= 3 {
			out.Load1, _ = strconv.ParseFloat(fields[0], 64)
			out.Load5, _ = strconv.ParseFloat(fields[1], 64)
			out.Load15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}
	if r, found := find("memory"); found && ok(r) {
		out.MemTotalKiB = parseMeminfoField(r.Result.Stdout, "MemTotal")
		out.MemAvailableKiB = parseMeminfoField(r.Result.Stdout, "MemAvailable")
	}
	if r, found := find("disk"); found && ok(r) {
		out.Filesystems = parseFilesystemUsage(r.Result.Stdout)
	}
	if r, found := find("failed-units"); found && ok(r) {
		out.FailedUnits = truncateLines(nonEmptyLines(r.Result.Stdout), 20)
	}
	if r, found := find("clock-sync"); found && ok(r) {
		out.ClockSynchronized = strings.TrimSpace(r.Result.Stdout) == "yes"
	}
	if r, found := find("interfaces"); found && ok(r) {
		out.Interfaces = truncateLines(nonEmptyLines(r.Result.Stdout), 20)
	}
	if r, found := find("node-exporter"); found && ok(r) {
		out.NodeExporterActive = r.Result.RC == 0
	}
	if r, found := find("kernel-errors"); found && ok(r) {
		out.KernelErrorLines = truncateLines(nonEmptyLines(r.Result.Stdout), 20)
	}

	out.Verdict = classifyHostHealth(out)
	return out
}

func classifyHostHealth(out HostHealthOutput) string {
	if out.MemTotalKiB == 0 && out.UptimeSeconds == 0 && len(out.Filesystems) == 0 {
		// Every evidence-bearing step failed/was unreachable at the
		// result level even though the ad-hoc call itself connected —
		// there isn't enough to classify healthy vs. degraded.
		return "insufficient_evidence"
	}
	degraded := !out.NodeExporterActive || len(out.FailedUnits) > 0 || len(out.KernelErrorLines) > 0 || !out.ClockSynchronized
	for _, fs := range out.Filesystems {
		if fs.UsedPercent >= 90 || fs.InodeUsedPercent >= 90 {
			degraded = true
		}
	}
	if degraded {
		return "degraded"
	}
	return "healthy"
}

func parseMeminfoField(stdout, key string) int64 {
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.TrimSuffix(fields[0], ":") == key {
			v, _ := strconv.ParseInt(fields[1], 10, 64)
			return v
		}
	}
	return 0
}

// parseFilesystemUsage parses the two-section `df -P -T` + `df -Pi -T`
// output HostHealthSteps' "disk" step produces, joining each mount's
// byte and inode usage percentage by mount point.
func parseFilesystemUsage(stdout string) []FilesystemUsage {
	sections := strings.SplitN(stdout, "---INODES---", 2)
	byMount := map[string]*FilesystemUsage{}
	var order []string

	parseSection := func(section string, setInode bool) {
		lines := strings.Split(strings.TrimSpace(section), "\n")
		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue // header row
			}
			fields := strings.Fields(line)
			if len(fields) < 7 {
				continue
			}
			mount := fields[len(fields)-1]
			pctStr := strings.TrimSuffix(fields[len(fields)-2], "%")
			pct, err := strconv.Atoi(pctStr)
			if err != nil {
				continue
			}
			fs, exists := byMount[mount]
			if !exists {
				fs = &FilesystemUsage{Mount: mount}
				byMount[mount] = fs
				order = append(order, mount)
			}
			if setInode {
				fs.InodeUsedPercent = pct
			} else {
				fs.UsedPercent = pct
			}
		}
	}
	parseSection(sections[0], false)
	if len(sections) > 1 {
		parseSection(sections[1], true)
	}

	out := make([]FilesystemUsage, 0, len(order))
	for _, m := range order {
		out = append(out, *byMount[m])
	}
	return out
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// truncateLines bounds a list to at most max entries, appending a marker
// line naming how many were dropped — every composite tool's "bounded
// list" requirement (Phase 2 §1) goes through this one function.
func truncateLines(lines []string, max int) []string {
	if len(lines) <= max {
		return lines
	}
	dropped := len(lines) - max
	out := make([]string, 0, max+1)
	out = append(out, lines[:max]...)
	out = append(out, fmt.Sprintf("... (%d more, truncated)", dropped))
	return out
}
