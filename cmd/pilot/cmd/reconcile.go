package cmd

import (
	"fmt"
	"os"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	reconcileInventoryFlag string
	reconcileTimeoutFlag   string
	reconcileActionsPath   string
	reconcilePresentation  bool
	reconcileTracePath     string
)

// reconcileCmd is the day-2 counterpart to deploy: it intentionally lists
// only catalog entries whose apply playbook declares a declarative reconcile
// capability. A future nginx-config entry must first have its own contract,
// apply playbook, schema, and verification evidence before it is eligible.
var reconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "互動式 day-2 設定調和精靈",
	Long: `pilot reconcile 將宣告式 roster／設定檔調和到已部署的服務。

它沿用 pilot deploy 的 contract、preflight、stage gate、preview 與確認流程，
但只列出明確標示為 day-2 reconciler 的元件；不會重新執行全站部署。`,
	Args: cobra.NoArgs,
	RunE: runReconcile,
}

func init() {
	reconcileCmd.Flags().StringVarP(&reconcileInventoryFlag, "inventory", "i", "inventory.yml", "預先填入的 inventory 路徑(精靈仍會再問一次，可直接按 Enter 採用)")
	reconcileCmd.Flags().StringVar(&reconcileTimeoutFlag, "timeout", "30m", "每次 ansible-playbook 呼叫(preflight/預覽/套用，各自獨立計時)的逾時上限")
	reconcileCmd.Flags().StringVar(&reconcileActionsPath, "actions", "", "以 JSON scenario 自動回答 reconcile TUI prompts")
	reconcileCmd.Flags().BoolVar(&reconcilePresentation, "presentation", false, "自動操作時顯示教學步驟與 prompt 畫面")
	reconcileCmd.Flags().StringVar(&reconcileTracePath, "trace-out", "", "將 automation prompt 以 JSONL 寫入指定檔案")
	rootCmd.AddCommand(reconcileCmd)
}

func runReconcile(cmd *cobra.Command, _ []string) error {
	if reconcileActionsPath != "" {
		return runStandalonePromptWorkflow(cmd, "reconcile", reconcileActionsPath, reconcilePresentation, reconcileTracePath)
	}
	return runReconcileInteractive(cmd)
}

func runReconcileInteractive(cmd *cobra.Command) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("pilot reconcile 需要互動式終端機(TTY)才能問問題")
	}
	timeout, err := parseDeployTimeout(reconcileTimeoutFlag)
	if err != nil {
		return err
	}
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return err
	}
	ctx := withDeployAnsibleRuntime(cmd.Context(), runtime)
	runner := ansible.NewRunner()
	runner.Timeout = timeout
	runner.Env = runtime.Env
	runner.StdoutWriter = cmd.OutOrStdout()
	runner.StderrWriter = cmd.ErrOrStderr()
	out := cmd.OutOrStdout()

	fmt.Fprintln(out, "═══ pilot reconcile — 互動式 day-2 設定調和精靈 ═══")
	fmt.Fprintln(out, "每一步都可以直接按 Enter 採用預設值；Ctrl-C 隨時可以取消。")
	fmt.Fprintln(out)
	inv, err := runTextProgram("Inventory 檔路徑", reconcileInventoryFlag, validateFileExists)
	if err != nil {
		return abortOrErr(err)
	}

	// Best-effort: keep inv fresh relative to a sibling hosts.yml (edited
	// via `pilot edit`) before anything below reads it — see
	// autoRegenerateInventoryFromHosts's doc comment for why this never
	// hard-fails the run.
	if regenerated, genErr := autoRegenerateInventoryFromHosts(cmd.ErrOrStderr(), inv); genErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "警告：自動重新產生 inventory.yml 失敗（沿用現有檔案）：%v\n", genErr)
	} else if regenerated {
		fmt.Fprintf(out, "已從 hosts.yml 自動重新產生 %s\n", inv)
	}

	// Fail before preflight or any component selection when the effective
	// FreeIPA target cannot load the canonical roster. Otherwise
	// freeipa-identity-apply.yml reaches its late empty-data gate after all
	// earlier checks have passed, which obscures the actual inventory defect.
	violations, err := validateDeploymentCompleteness(ctx, inv)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		return formatCompletenessViolations(violations)
	}
	if runConfirmProgram("要不要先看一下這份 inventory 的拓樸圖？(pilot deploy graph --view both)", true) {
		previewInventoryGraph(ctx, out, inv)
		fmt.Fprintln(out)
	}
	ok, err := runPreflight(ctx, runner, out, inv)
	if err != nil {
		return abortOrErr(err)
	}
	if !ok {
		return errPreflightRejected
	}
	return abortOrErr(runCatalogPlaybookDeploy(ctx, runner, out, inv, "apply", true))
}
