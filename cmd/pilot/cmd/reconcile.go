package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

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
	reconcileLockWaitFlag    string
)

// reconcileStdinIsTerminal is a variable so tests can simulate a missing TTY.
var reconcileStdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// golangEngineHelp is what pilot reconcile --help says of --engine golang: one text, since
// the exit codes and the webhook reading are what an operator or a subscriber has to know
// before the first --force (spec §6.2, §6.3, §8.6).
const golangEngineHelp = `--engine golang --component freeipa-identity 只處理 roster 的使用者與群組(其餘 section
仍由 Ansible engine 處理)：
  --preview-only            唯讀預覽，不取鎖、不寫入；--scope 預設 users-groups，--plan-out 存 plan。
  --force --scope users-groups   套用。不執行任何 playbook：取得 FreeIPA server 的 /etc/ipa 鎖，
                            有寫入時先經入口 playbook 記下「授權快取義務」，再由 Go 寫入並重讀驗證；
                            --result-out 存這一輪的結果(plan、逐項結果、驗證、義務)，--lock-wait 設
                            等鎖的時間。
結束碼：0 成功(全部完成並驗證，且沒有義務未結清)；1 失敗(含結果不明、部分套用)；3 plan 有被阻擋的
物件(零寫入)；4 每個 Go 操作都已完成並驗證，只剩授權快取義務未結清。
義務未結清是 users-groups scope 有寫入就會有的結果：它不執行 playbook，client 在 SSSD 快取過期前可能
仍沿用舊授權；下一次選到 identity 或 client-cache 的 apply 或完整 apply 會刷新所有 enrolled client
(ipa_identity_refresh_sssd_cache 為 false 時要先改回 true)。這一輪對外的 operation.result 因此是
failure(failure.class verify_failed，application_consistency partial_or_unknown，沒有 confirmed_effects)：
訂閱 webhook 的人要用 run 的 metadata(engine、scope)與 identity.auth_cache 事件解讀，不能當成「identity
同步失敗」。只有沒有寫入、探測讀到沒有義務的一輪才是 success。鎖只約束 pilot 自己的程式碼路徑，
手動執行的 ansible-playbook 不受它約束。`

// reconcileCmd is the day-2 counterpart to deploy: it intentionally lists
// only catalog entries whose apply playbook declares a declarative reconcile
// capability. A future nginx-config entry must first have its own contract,
// apply playbook, schema, and verification evidence before it is eligible.
var reconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "互動式 day-2 設定調和精靈",
	Long: `pilot reconcile 將宣告式 roster／設定檔調和到已部署的服務。

它沿用 pilot deploy 的 contract、preflight、stage gate、preview 與確認流程，
但只列出明確標示為 day-2 reconciler 的元件；不會重新執行全站部署。

` + golangEngineHelp + `

` + identityLockDeployHelp,
	Args: cobra.NoArgs,
	RunE: runReconcile,
}

func init() {
	reconcileCmd.Flags().StringVar(&reconcileDirFlag, "dir", ".", "workspace directory containing inventory.yml and hosts.yml (default: current directory)")
	reconcileCmd.Flags().StringVarP(&reconcileInventoryFlag, "inventory", "i", "inventory.yml", "預先填入的 inventory 路徑(精靈仍會再問一次，可直接按 Enter 採用)")
	reconcileCmd.Flags().StringVar(&reconcileTimeoutFlag, "timeout", "30m", "每次 ansible-playbook 呼叫(preflight/預覽/套用，各自獨立計時)的逾時上限；--engine golang 時是整個預覽(ansible-inventory、ansible --list-hosts、ansible-vault、SSH、FreeIPA 讀取)的期限")
	reconcileCmd.Flags().StringVar(&reconcileActionsPath, "actions", "", "以 JSON scenario 自動回答 reconcile TUI prompts")
	reconcileCmd.Flags().BoolVar(&reconcilePresentation, "presentation", false, "自動操作時顯示教學步驟與 prompt 畫面")
	reconcileCmd.Flags().StringVar(&reconcileTracePath, "trace-out", "", "將 automation prompt 以 JSONL 寫入指定檔案")
	reconcileCmd.Flags().StringArrayVar(&reconcileComponentFlags, "component", nil, "要調和的 day-2 元件 key(可重複，例如 --component freeipa-identity)；指定後不再顯示勾選清單")
	reconcileCmd.Flags().BoolVar(&reconcileForceFlag, "force", false, "不顯示互動提示：各欄位採用預設值，依計畫順序逐支 playbook 先預覽、成功後隨即正式套用(後面的預覽失敗時，前面已套用的不會還原)；需要 --component")
	reconcileCmd.Flags().BoolVar(&reconcilePreviewOnlyFlag, "preview-only", false, "不顯示互動提示：各欄位採用預設值，只預覽(--check --diff)計畫中的每一支 playbook，全部不套用；每一支都實際預覽通過才以結束碼 0 結束(目標主機全部是無法連線的 optional 主機而延後的 playbook 算沒有預覽)；需要 --component")
	reconcileCmd.Flags().StringVar(&limitFlag, "limit", "", "只對這些主機(或 Ansible 的主機樣式)執行，等同回答「要限定只套用到某台主機嗎？」；--force/--preview-only 也適用")
	reconcileCmd.Flags().StringVar(&stageFlag, "stage", "", "直接指定 stage(sandbox、staging、prod)，不再詢問；在指令列指定 staging/prod 即視為確認；--force/--preview-only 沒帶 --stage 時一律是 sandbox")
	reconcileCmd.Flags().StringVar(&reconcileEngineFlag, "engine", reconcileEngineAnsible, "調和引擎：ansible(預設)或 golang。golang 只能與 --component freeipa-identity 一起使用，處理使用者與群組：--preview-only 唯讀預覽，--force --scope users-groups 套用(不執行 playbook；授權快取義務未結清時結束碼 4，見 pilot reconcile --help)")
	reconcileCmd.Flags().StringVar(&reconcilePlanOutFlag, "plan-out", "", "--engine golang --preview-only：把 plan JSON 寫到這個新檔案(0600，已存在時拒絕；寫入失敗時移除)")
	reconcileCmd.Flags().StringVar(&reconcileScopeFlag, "scope", "", "--engine golang：users-groups(只有使用者與群組，不執行 playbook)。--force 必填；--preview-only 預設 users-groups。full(混合執行)還沒有提供")
	reconcileCmd.Flags().StringVar(&reconcileResultOutFlag, "result-out", "", "--engine golang --force：把這一輪的結果(pilot.identity-apply/v1：plan、逐項結果、驗證、授權快取義務)寫到這個新檔案(0600；已存在時在任何寫入之前拒絕；沒有進到第一次讀取的失敗不寫，寫入失敗時移除)")
	reconcileCmd.Flags().StringVar(&reconcileLockWaitFlag, "lock-wait", "", "套用 freeipa-identity 前，FreeIPA server 的 /etc/ipa 鎖被另一輪執行持有時最多等多久(Go duration，例如 30m；0 表示忙碌就立即失敗；預設 30m，約一輪完整 identity 執行的時間)；預覽不持鎖，與 --preview-only 同用會被拒絕。鎖只約束 pilot 自己的程式碼路徑，手動執行的 ansible-playbook 不受它約束")
	reconcileCmd.Flags().StringVar(&stagingAttestedHoursFlag, "staging-attested-within-hours", "", "--stage prod 必填：上次 staging 驗證距今幾小時(0-168)")
	rootCmd.AddCommand(reconcileCmd)
}

func runReconcile(cmd *cobra.Command, _ []string) error {
	if err := validateReconcileEngineFlags(reconcileEngineFlag, reconcilePreviewOnlyFlag, reconcileForceFlag, reconcileComponentFlags, reconcileActionsPath, reconcilePlanOutFlag, reconcileScopeFlag, reconcileResultOutFlag); err != nil {
		return err // gate: entry-engine-flags
	}
	if reconcileForceFlag && reconcilePreviewOnlyFlag {
		return fmt.Errorf("--force 不能與 --preview-only 同時使用") // gate: ansible-force-and-preview-only
	}
	if _, err := parseReconcileLockWait(reconcileLockWaitFlag); err != nil {
		return err // gate: entry-lock-wait-value
	}
	if reconcileLockWaitFlag != "" && reconcilePreviewOnlyFlag {
		return fmt.Errorf("--lock-wait 只對會取鎖的執行有意義；--preview-only 不持鎖，請拿掉其中一個") // gate: entry-lock-wait-preview-only
	}
	if err := validateStageFlags(stageFlag, stagingAttestedHoursFlag); err != nil {
		return err // gate: entry-stage-flags
	}
	if err := validateLimitFlag(limitFlag); err != nil {
		return err // gate: entry-limit-flag
	}
	if reconcileActionsPath != "" {
		if limitFlag != "" {
			return fmt.Errorf("--limit 不能與 --actions 同時使用(scenario 自己回答 limit)") // gate: ansible-actions-with-limit
		}
		if reconcileForceFlag || reconcilePreviewOnlyFlag || stageFlag != "" || len(reconcileComponentFlags) > 0 {
			return fmt.Errorf("--actions 不能與 --force、--preview-only、--stage 或 --component 同時使用(scenario 自己回答這些問題)") // gate: ansible-actions-with-flags
		}
		return runStandalonePromptWorkflow(cmd, "reconcile", reconcileActionsPath, reconcilePresentation, reconcileTracePath) // gate: ansible-actions-dispatch
	}
	if reconcileEngineFlag == reconcileEngineGolang {
		if reconcileForceFlag {
			return runReconcileGolangApply(cmd) // gate: entry-golang-apply-dispatch
		}
		return runReconcileGolangPreview(cmd) // gate: entry-golang-dispatch
	}
	if (reconcileForceFlag || reconcilePreviewOnlyFlag) && len(reconcileComponentFlags) == 0 {
		// The defaults driver would otherwise tick only the checklist's first entry.
		return fmt.Errorf("--force/--preview-only 需要用 --component 指定要調和的元件") // gate: ansible-needs-component
	}
	return runReconcileInteractive(cmd) // gate: ansible-interactive-dispatch
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
	ctx, err := reconcileLockContext(withDeployAnsibleRuntime(cmd.Context(), runtime), cmd)
	if err != nil {
		return err
	}
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
	// Workspace-relative, not pre-joined with --dir: the validator and inv below
	// apply workspacePath to the answer, so joining here too doubled a relative
	// --dir (see runDeployInteractive), and the defaults driver skips the
	// validator that used to catch it.
	inventoryDefault := reconcileInventoryFlag
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
	return reconcileExit(runCatalogPlaybookDeploy(ctx, runner, out, inv, "apply", true, snapshot), reconcilePreviewOnlyFlag)
}

// reconcileLockContext carries --lock-wait and the stderr of cmd (where the
// "still waiting" lines go) to every funnel the run reaches: ctx is what
// executeRecordedDeploymentCore builds its identity lock request from.
func reconcileLockContext(ctx context.Context, cmd *cobra.Command) (context.Context, error) {
	wait, err := parseReconcileLockWait(reconcileLockWaitFlag)
	if err != nil {
		return nil, err
	}
	return withIdentityLockProgress(withIdentityLockWait(ctx, wait), cmd.ErrOrStderr()), nil
}

// parseReconcileLockWait reads --lock-wait: how long the freeipa-identity apply
// waits for the server's /etc/ipa lock. Empty is the default, one full
// identity run's worth. 0 fails at once when another run holds the lock.
// Anything between 0 and a second is refused: the wait is a whole number of
// seconds on the remote flock, so it would round to something nobody asked
// for.
func parseReconcileLockWait(v string) (time.Duration, error) {
	if v == "" {
		return identityLockWaitDefault, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 || (d > 0 && d < time.Second) {
		return 0, fmt.Errorf("--lock-wait %q 不是有效的等待時間：請給 0(忙碌就立即失敗)或至少 1s 的 Go duration，例如 30s、30m", v)
	}
	return d, nil
}

// reconcileExit maps the wizard's result to the command's. A preview-only plan
// that previewed everything returns nil; an abort means it stopped first,
// which CI must not read as a clean preview. Otherwise an abort is the
// operator's clean cancellation.
func reconcileExit(err error, previewOnly bool) error {
	if previewOnly && errors.Is(err, errDeployAborted) {
		return fmt.Errorf("--preview-only：reconcile 在預覽完成之前就停止了")
	}
	return abortOrErr(err)
}
