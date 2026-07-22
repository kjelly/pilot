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
	rootCmd.AddCommand(reconcileCmd)
}

func runReconcile(cmd *cobra.Command, _ []string) error {
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
	if runConfirmProgram("要不要先看一下這份 inventory 的 host/group 結構？(ansible-inventory --graph)", true) {
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
