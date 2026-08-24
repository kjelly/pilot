// monitoring.go implements `pilot monitoring`: CLI access to the external
// monitoring target registry (spec.md §7-24, internal/monitoring). This
// file holds the root command plus the small set of helpers every child
// command (monitoring_target.go, monitoring_profile.go,
// monitoring_validate.go) shares — path resolution against --dir and
// violation-report formatting — following internal_endpoint_cli.go's shape
// (a thin CLI wrapper over an already-tested internal/ package, not new
// business logic living in cmd/).
package cmd

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/monitoring"
)

var monitoringCmd = &cobra.Command{
	Use:   "monitoring",
	Short: "Manage external Prometheus monitoring targets Pilot does not manage via Ansible (spec.md)",
	Long: `pilot monitoring 管理 monitoring/targets.yml 與 monitoring/scrape-profiles.yml
——描述 Prometheus 要 scrape 哪些「Pilot 不透過 Ansible 管理」的第三方 exporter
（NAS、UPS、switch、外部資料庫...）。

這只註冊 scrape 設定；不會、也不能對 target 做任何 SSH/Ansible 操作。`,
}

func init() {
	rootCmd.AddCommand(monitoringCmd)
}

// monitoringWorkspace resolves --dir into the two fixed file paths spec.md
// §6 declares (monitoring/targets.yml, monitoring/scrape-profiles.yml) —
// these are NOT caller-chosen manifest paths like internal-endpoint's
// --manifest flag, because spec.md's workspace layout fixes both names.
type monitoringWorkspace struct {
	Dir          string
	TargetsPath  string
	ProfilesPath string
}

func resolveMonitoringWorkspace(dir string) monitoringWorkspace {
	if dir == "" {
		dir = "."
	}
	return monitoringWorkspace{
		Dir:          dir,
		TargetsPath:  filepath.Join(dir, "monitoring", "targets.yml"),
		ProfilesPath: filepath.Join(dir, "monitoring", "scrape-profiles.yml"),
	}
}

func (w monitoringWorkspace) load() (monitoring.TargetFile, monitoring.ProfileFile, error) {
	tf, err := monitoring.LoadTargets(w.TargetsPath)
	if err != nil {
		return monitoring.TargetFile{}, monitoring.ProfileFile{}, err
	}
	pf, err := monitoring.LoadProfiles(w.ProfilesPath)
	if err != nil {
		return monitoring.TargetFile{}, monitoring.ProfileFile{}, err
	}
	return tf, pf, nil
}

// printViolations renders a monitoring.Result the same way for every
// command that can produce one (add/edit/validate) — errors first (these
// block a save), then warnings (informational only, spec.md §40/§44).
func printViolations(w io.Writer, r monitoring.Result) {
	for _, e := range r.Errors {
		fmt.Fprintf(w, "error: %s\n", e)
	}
	for _, wmsg := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", wmsg)
	}
}

func addFlagTargetLabel(cmd *cobra.Command, dst *[]string) {
	cmd.Flags().StringArrayVar(dst, "label", nil, "label as key=value (repeatable)")
}

func parseLabelFlags(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		key, value, ok := splitKV(p)
		if !ok {
			return nil, fmt.Errorf("--label %q must be key=value", p)
		}
		out[key] = value
	}
	return out, nil
}

func splitKV(s string) (key, value string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
