package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	reconcileDirFlag         string
	reconcileInventoryFlag   string
	reconcileTimeoutFlag     string
	reconcileActionsPath     string
	reconcilePresentation    bool
	reconcileTracePath       string
	reconcileComponentFlags  []string
	reconcileForceFlag       bool
	reconcilePreviewOnlyFlag bool
)

// reconcileStdinIsTerminal is a variable so tests can simulate a missing TTY.
var reconcileStdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

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
	reconcileCmd.Flags().StringVar(&reconcileDirFlag, "dir", ".", "workspace directory containing inventory.yml and hosts.yml (default: current directory)")
	reconcileCmd.Flags().StringVarP(&reconcileInventoryFlag, "inventory", "i", "inventory.yml", "預先填入的 inventory 路徑(精靈仍會再問一次，可直接按 Enter 採用)")
	reconcileCmd.Flags().StringVar(&reconcileTimeoutFlag, "timeout", "30m", "每次 ansible-playbook 呼叫(preflight/預覽/套用，各自獨立計時)的逾時上限")
	reconcileCmd.Flags().StringVar(&reconcileActionsPath, "actions", "", "以 JSON scenario 自動回答 reconcile TUI prompts")
	reconcileCmd.Flags().BoolVar(&reconcilePresentation, "presentation", false, "自動操作時顯示教學步驟與 prompt 畫面")
	reconcileCmd.Flags().StringVar(&reconcileTracePath, "trace-out", "", "將 automation prompt 以 JSONL 寫入指定檔案")
	reconcileCmd.Flags().StringArrayVar(&reconcileComponentFlags, "component", nil, "要調和的 day-2 元件 key(可重複，例如 --component freeipa-identity)；指定後不再顯示勾選清單")
	reconcileCmd.Flags().BoolVar(&reconcileForceFlag, "force", false, "不顯示互動提示：各欄位採用預設值，計畫中所有 playbook 預覽成功後直接正式套用；需要 --component")
	reconcileCmd.Flags().BoolVar(&reconcilePreviewOnlyFlag, "preview-only", false, "不顯示互動提示：各欄位採用預設值，只預覽(--check --diff)計畫中的每一支 playbook，全部不套用；每一支都實際預覽通過才以結束碼 0 結束(目標主機全部是無法連線的 optional 主機而延後的 playbook 算沒有預覽)；需要 --component")
	reconcileCmd.Flags().StringVar(&stageFlag, "stage", "", "直接指定 stage(sandbox、staging、prod)，不再詢問；在指令列指定 staging/prod 即視為確認；--force/--preview-only 沒帶 --stage 時一律是 sandbox")
	reconcileCmd.Flags().StringVar(&stagingAttestedHoursFlag, "staging-attested-within-hours", "", "--stage prod 必填：上次 staging 驗證距今幾小時(0-168)")
	rootCmd.AddCommand(reconcileCmd)
}

func runReconcile(cmd *cobra.Command, _ []string) error {
	if reconcileForceFlag && reconcilePreviewOnlyFlag {
		return fmt.Errorf("--force 不能與 --preview-only 同時使用")
	}
	if err := validateStageFlags(stageFlag, stagingAttestedHoursFlag); err != nil {
		return err
	}
	if reconcileActionsPath != "" {
		if reconcileForceFlag || reconcilePreviewOnlyFlag || stageFlag != "" || len(reconcileComponentFlags) > 0 {
			return fmt.Errorf("--actions 不能與 --force、--preview-only、--stage 或 --component 同時使用(scenario 自己回答這些問題)")
		}
		return runStandalonePromptWorkflow(cmd, "reconcile", reconcileActionsPath, reconcilePresentation, reconcileTracePath)
	}
	if (reconcileForceFlag || reconcilePreviewOnlyFlag) && len(reconcileComponentFlags) == 0 {
		// The defaults driver would otherwise tick only the checklist's first entry.
		return fmt.Errorf("--force/--preview-only 需要用 --component 指定要調和的元件")
	}
	return runReconcileInteractive(cmd)
}

func runReconcileInteractive(cmd *cobra.Command) error {
	// Same defaults driver as deploy --force/--preview-only, installed before
	// the TTY gate so CI can run it.
	if reconcileForceFlag || reconcilePreviewOnlyFlag {
		defaults := &promptAutomation{useDefaults: true, forceApply: reconcileForceFlag, previewOnly: reconcilePreviewOnlyFlag}
		oldPrompt := activePromptAutomation
		activePromptAutomation = defaults
		defer func() { activePromptAutomation = oldPrompt }()
	}
	if !promptWorkflowAllowsNonTTY(reconcileStdinIsTerminal()) {
		return fmt.Errorf("pilot reconcile 需要互動式終端機(TTY)才能問問題；非互動場景請加 --component 與 --force 或 --preview-only，或用 --actions 指定 JSON scenario 檔")
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
	runner.LogPath = runtime.LogPath
	runner.StdoutWriter = cmd.OutOrStdout()
	runner.StderrWriter = cmd.ErrOrStderr()
	out := cmd.OutOrStdout()

	fmt.Fprintln(out, "═══ pilot reconcile — 互動式 day-2 設定調和精靈 ═══")
	fmt.Fprintln(out, "每一步都可以直接按 Enter 採用預設值；Ctrl-C 隨時可以取消。")
	fmt.Fprintln(out)
	inventoryDefault := workspacePath(reconcileDirFlag, reconcileInventoryFlag)
	invInput, err := runTextPrompt(promptInventory, "Inventory 檔路徑", inventoryDefault, func(path string) error {
		return validateFileExists(workspacePath(reconcileDirFlag, path))
	})
	if err != nil {
		return abortOrErr(err)
	}
	inv := workspacePath(reconcileDirFlag, invInput)

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
	snapshot, err := loadDeployInventorySnapshot(ctx, inv)
	if err != nil {
		return err
	}
	violations, err := validateDeploymentCompletenessSnapshot(inv, snapshot)
	if err != nil {
		return err
	}
	if len(violations) > 0 {
		return formatCompletenessViolations(violations)
	}
	if err := ensureFreeIPARostersCurrentSnapshot(out, inv, snapshot); err != nil {
		return err
	}
	if runConfirmPrompt(promptTopologyPreview, "要不要先看一下這份 inventory 的拓樸圖？(pilot deploy graph --view both)", true) {
		previewInventoryGraph(out, inv, snapshot)
		fmt.Fprintln(out)
	}
	err = runCatalogPlaybookDeploy(ctx, runner, out, inv, "apply", true, snapshot)
	if reconcilePreviewOnlyFlag && errors.Is(err, errDeployAborted) {
		// A preview-only plan that previewed everything returns nil; an abort
		// means it stopped first, which CI must not read as a clean preview.
		return fmt.Errorf("--preview-only：reconcile 在預覽完成之前就停止了")
	}
	return abortOrErr(err)
}
