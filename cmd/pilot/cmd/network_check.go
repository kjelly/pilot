package cmd

// pilot network-check: a read-only command that expands the contract
// catalog's providerEndpoint dependencies against a real inventory into
// directed host-to-host reachability probes, and reports which ones the
// network actually allows before any apply/reconcile mutates anything. See
// network-connectivity-preflight-plan-2026-07-31.md for the design.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

var (
	networkCheckInventoryFlag    string
	networkCheckComponentsFlag   []string
	networkCheckLimitFlag        string
	networkCheckTimeoutFlag      time.Duration
	networkCheckFormatFlag       string
	networkCheckAllowSkippedFlag bool
)

var networkCheckCmd = &cobra.Command{
	Use:   "network-check",
	Short: "在套用前偵測 contract 宣告的跨主機網路連線是否可達",
	Long: `pilot network-check 從 contracts/*.yaml 的 providerEndpoint 依賴與
provider 的 endpoints 宣告，投影到目前這份 inventory，展開成
source host → target host:port 的探測矩陣，並透過 Ansible 在每個 source
host 上實際執行 socket connect（不是從 controller 探測後推論）。

它是唯讀的：不會修改任何主機、不會寫檔、不會啟停服務。連線資料只讀
contract；不掃描 playbook、不建立另一份手工維護的 port 對照表。

Exit code：
  0  所有 required probe PASS（或 UDP REACHABLE-UNCONFIRMED，見下）
  1  至少一個 required probe FAIL / ERROR，或 --allow-skipped 未設時
     有 required probe 落在 SKIP
  2  CLI 旗標、inventory 或 contract 無效（尚未實際探測任何東西）

UDP 沒有握手語意，REACHABLE-UNCONFIRMED 代表「本機可以送出封包」，不是
遠端服務健康；它不會讓 exit code 變成 1 —— 用 REACHABLE-UNCONFIRMED 硬性
擋掉部署，等於把探測不到的東西當成故障，違反本工具「沒證據不判死刑」的
原則。`,
	Args: cobra.NoArgs,
	RunE: runNetworkCheck,
	// A required probe FAILing is this command's normal, expected job —
	// not a CLI usage mistake — so don't dump the flags/usage block to
	// stdout on every non-zero exit (that would also corrupt --format
	// json's stdout payload for any caller piping it).
	SilenceUsage: true,
}

func init() {
	networkCheckCmd.Flags().StringVarP(&networkCheckInventoryFlag, "inventory", "i", "inventory.yml", "inventory 路徑")
	networkCheckCmd.Flags().StringArrayVar(&networkCheckComponentsFlag, "component", nil, "只檢查這個 consumer component 的依賴；可重複；省略＝檢查全部")
	networkCheckCmd.Flags().StringVar(&networkCheckLimitFlag, "limit", "", "ansible pattern，只從符合的 source host 出發")
	networkCheckCmd.Flags().DurationVar(&networkCheckTimeoutFlag, "timeout", 3*time.Second, "單一 TCP/UDP probe 的逾時")
	networkCheckCmd.Flags().StringVar(&networkCheckFormatFlag, "format", "text", "輸出格式：text 或 json")
	networkCheckCmd.Flags().BoolVar(&networkCheckAllowSkippedFlag, "allow-skipped", false, "只供診斷：required edge 落在 SKIP 時仍以 exit code 0 結束")
	rootCmd.AddCommand(networkCheckCmd)
}

// networkCheckExitError lets runNetworkCheck report exit codes 1/2 (see the
// command's Long help) through cobra's normal error-printing path instead
// of calling os.Exit directly, so it stays testable as an ordinary function.
type networkCheckExitError struct {
	err  error
	code int
}

func (e *networkCheckExitError) Error() string { return e.err.Error() }
func (e *networkCheckExitError) ExitCode() int { return e.code }
func (e *networkCheckExitError) Unwrap() error { return e.err }

func invalidNetworkCheckInput(err error) error {
	return &networkCheckExitError{err: err, code: 2}
}

func networkCheckFailed(err error) error {
	return &networkCheckExitError{err: err, code: 1}
}

func runNetworkCheck(cmd *cobra.Command, _ []string) error {
	switch networkCheckFormatFlag {
	case "text", "json":
	default:
		return invalidNetworkCheckInput(fmt.Errorf("--format 只接受 text 或 json（收到 %q）", networkCheckFormatFlag))
	}

	root, err := resolveContractRoot("")
	if err != nil {
		return invalidNetworkCheckInput(err)
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		return invalidNetworkCheckInput(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		return invalidNetworkCheckInput(fmt.Errorf("load contracts: %w", err))
	}

	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return invalidNetworkCheckInput(err)
	}
	ctx := withDeployAnsibleRuntime(cmd.Context(), runtime)

	resolvedInv, notice, cleanup, err := expandIfSimplifiedHosts(networkCheckInventoryFlag)
	if err != nil {
		return invalidNetworkCheckInput(err)
	}
	defer cleanup()
	out := cmd.OutOrStdout()
	if notice != "" && networkCheckFormatFlag == "text" {
		fmt.Fprintln(out, notice)
	}

	inv, err := resolveNetworkCheckInventory(ctx, resolvedInv)
	if err != nil {
		return invalidNetworkCheckInput(fmt.Errorf("resolve inventory: %w", err))
	}

	var sourceHosts []string
	if networkCheckLimitFlag != "" {
		sourceHosts, err = resolvePatternHosts(ctx, resolvedInv, "all", networkCheckLimitFlag)
		if err != nil {
			return invalidNetworkCheckInput(fmt.Errorf("resolve --limit: %w", err))
		}
	}

	edges, err := networkcheck.Plan(catalog, inv, networkcheck.PlanOptions{
		Components:  networkCheckComponentsFlag,
		SourceHosts: sourceHosts,
	})
	if err != nil {
		return invalidNetworkCheckInput(err)
	}

	results, err := networkcheck.Probe(ctx, edges, networkcheck.ProbeOptions{
		Inventory:      resolvedInv,
		Limit:          networkCheckLimitFlag,
		TimeoutSeconds: int(networkCheckTimeoutFlag.Seconds()),
	}, realAdHocRunner(ctx))
	if err != nil {
		return networkCheckFailed(fmt.Errorf("probe: %w", err))
	}

	switch networkCheckFormatFlag {
	case "json":
		if err := renderNetworkCheckJSON(out, results); err != nil {
			return networkCheckFailed(err)
		}
	default:
		renderNetworkCheckText(out, results)
	}

	if blocking := blockingNetworkCheckResults(results, networkCheckAllowSkippedFlag); len(blocking) > 0 {
		return networkCheckFailed(fmt.Errorf("%d required network probe(s) did not pass", len(blocking)))
	}
	return nil
}

// resolveNetworkCheckInventory runs `ansible-inventory --list` once (reusing
// the same ANSIBLE_HOME-isolated runtime every other ansible invocation in
// this repo uses — see deployAnsibleCommand) and parses it into the shape
// the planner needs: groups with children expanded, plus every host's
// fully rendered vars.
func resolveNetworkCheckInventory(ctx context.Context, inventory string) (networkcheck.ResolvedInventory, error) {
	command := deployAnsibleCommand(ctx, "ansible-inventory", "-i", inventory, "--list")
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return networkcheck.ResolvedInventory{}, fmt.Errorf("ansible-inventory --list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return networkcheck.ParseInventoryList([]byte(stdout.String()))
}

// realAdHocRunner adapts the ansible-runtime-aware exec.Cmd builder every
// other ansible invocation in this codebase uses (deployAnsibleCommand) to
// networkcheck.AdHocRunner's shape.
func realAdHocRunner(baseCtx context.Context) networkcheck.AdHocRunner {
	return func(ctx context.Context, args []string, timeoutSeconds int) (string, int, error) {
		cctx, cancel := context.WithTimeout(baseCtx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
		command := deployAnsibleCommand(cctx, "ansible", args...)
		out, err := command.CombinedOutput()
		exitCode := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			err = nil
		}
		return string(out), exitCode, err
	}
}

func blockingNetworkCheckResults(results []networkcheck.Result, allowSkipped bool) []networkcheck.Result {
	var blocking []networkcheck.Result
	for _, r := range results {
		if !r.Edge.Required {
			continue
		}
		switch r.Status {
		case networkcheck.StatusFail, networkcheck.StatusError:
			blocking = append(blocking, r)
		case networkcheck.StatusSkip:
			if !allowSkipped {
				blocking = append(blocking, r)
			}
		}
	}
	return blocking
}

type networkCheckResultJSON struct {
	Requirement       string `json:"requirement"`
	ConsumerComponent string `json:"consumerComponent"`
	ProviderComponent string `json:"providerComponent"`
	Endpoint          string `json:"endpoint"`
	Source            string `json:"source"`
	SourceAddr        string `json:"sourceAddr"`
	Target            string `json:"target"`
	ResolvedIP        string `json:"resolvedIP,omitempty"`
	Protocol          string `json:"protocol"`
	Port              int    `json:"port"`
	Required          bool   `json:"required"`
	Status            string `json:"status"`
	DurationMs        int    `json:"durationMs,omitempty"`
	Detail            string `json:"detail,omitempty"`
	Hint              string `json:"hint,omitempty"`
}

func toNetworkCheckResultJSON(r networkcheck.Result) networkCheckResultJSON {
	e := r.Edge
	return networkCheckResultJSON{
		Requirement:       e.Requirement,
		ConsumerComponent: e.ConsumerComponent,
		ProviderComponent: e.ProviderComponent,
		Endpoint:          e.EndpointName,
		Source:            e.SourceHost,
		SourceAddr:        e.SourceAddr,
		Target:            e.TargetHost,
		ResolvedIP:        r.ResolvedIP,
		Protocol:          e.Protocol,
		Port:              e.Port,
		Required:          e.Required,
		Status:            string(r.Status),
		DurationMs:        r.DurationMs,
		Detail:            r.Detail,
		Hint:              r.Hint,
	}
}

func renderNetworkCheckJSON(w io.Writer, results []networkcheck.Result) error {
	rows := make([]networkCheckResultJSON, 0, len(results))
	for _, r := range results {
		rows = append(rows, toNetworkCheckResultJSON(r))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

func renderNetworkCheckText(w io.Writer, results []networkcheck.Result) {
	counts := make(map[networkcheck.ProbeStatus]int)
	requiredCount := 0
	for _, r := range results {
		counts[r.Status]++
		if r.Edge.Required {
			requiredCount++
		}
		e := r.Edge
		target := e.TargetHost
		if target == "" {
			target = "(no target resolved)"
		} else if e.Port > 0 {
			target = fmt.Sprintf("%s:%d", target, e.Port)
		}
		fmt.Fprintf(w, "%s %s %s (%s) -> %s/%s %s\n", r.Status, e.Protocol, e.SourceHost, e.SourceAddr, e.ProviderComponent, e.EndpointName, target)
		switch r.Status {
		case networkcheck.StatusFail, networkcheck.StatusError:
			fmt.Fprintf(w, "  result: %s\n", r.Detail)
			if r.Hint != "" {
				fmt.Fprintf(w, "  hint: %s\n", r.Hint)
			}
		case networkcheck.StatusSkip:
			fmt.Fprintf(w, "  reason: %s\n", r.Detail)
		case networkcheck.StatusReachableUnconfirmed:
			fmt.Fprintf(w, "  note: %s\n", r.Detail)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d PASS, %d FAIL, %d SKIP, %d ERROR, %d REACHABLE-UNCONFIRMED (%d required)\n",
		counts[networkcheck.StatusPass], counts[networkcheck.StatusFail], counts[networkcheck.StatusSkip],
		counts[networkcheck.StatusError], counts[networkcheck.StatusReachableUnconfirmed], requiredCount)
}
