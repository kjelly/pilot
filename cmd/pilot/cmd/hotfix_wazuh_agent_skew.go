package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/hotfix"
)

var (
	hotfixSkewDirFlag         string
	hotfixSkewInventoryFlag   string
	hotfixSkewTimeoutFlag     string
	hotfixSkewForceFlag       bool
	hotfixSkewPreviewOnlyFlag bool

	// hotfixStdinIsTerminal is the TTY probe, swapped by tests.
	hotfixStdinIsTerminal = func() bool { return deployStdinIsTerminal() }
)

var hotfixWazuhAgentSkewCmd = &cobra.Command{
	Use:   "wazuh-agent-skew",
	Short: "移除版本比 Wazuh manager 新的 agent，之後可用 pilot deploy 重新安裝",
	Long: `wazuh-fim-apply 對「agent 版本高於 manager」一律拒絕、沒有降級路徑，那些主機因此
無法再用 pilot deploy 重新安裝。這個子指令把它們整理回「沒有 agent」：

  1. 唯讀偵測：讀 manager 的原生版本 M，與每台 wazuh-fim 主機實際安裝的 agent 版本比較。
  2. 印出計畫（只有版本比 M 新的主機會被動）並確認。
  3. 逐台：停 agent → 在 manager 依記錄的 ID 與名稱取消登記 → 解除 pilot 加的 hold／
     versionlock → 卸載套件 → 移除 client.keys。每一步冪等，中斷後重跑即可。

M 讀不到、版本無法判定、有進行中的 Wazuh 交易等任何無法確定的情況，整次在變更之前
拒絕，不做部分移除。版本相容或沒裝 agent 的主機完全不動。

完成後用 pilot deploy 重新安裝（版本取 wazuh_version，未設定時為 M）。`,
	Args: cobra.NoArgs,
	RunE: runHotfixWazuhAgentSkew,
}

func init() {
	f := hotfixWazuhAgentSkewCmd.Flags()
	f.StringVar(&hotfixSkewDirFlag, "dir", ".", "workspace directory containing inventory.yml and hosts.yml (default: current directory)")
	f.StringVarP(&hotfixSkewInventoryFlag, "inventory", "i", "inventory.yml", "預先填入的 inventory 路徑(仍會再問一次，可直接按 Enter 採用)")
	f.StringVar(&hotfixSkewTimeoutFlag, "timeout", "30m", "每次 ansible-playbook 呼叫(偵測、套用，各自獨立計時)的逾時上限，Go duration 格式(例如 45m、1h30m)")
	f.BoolVar(&hotfixSkewForceFlag, "force", false, "不顯示互動提示：各欄位採用預設值，偵測到需要移除的主機時略過確認直接套用")
	f.BoolVar(&hotfixSkewPreviewOnlyFlag, "preview-only", false, "不顯示互動提示：各欄位採用預設值，只做唯讀偵測並印出計畫，不變更任何東西")
	f.StringVar(&limitFlag, "limit", "", "只偵測與處理這些 agent 主機(或 Ansible 的主機樣式)；manager 一律會被讀取")
	f.StringVar(&stageFlag, "stage", "", "直接指定 stage(sandbox、staging、prod)，不再詢問；在指令列指定 staging/prod 即視為確認；--force 沒帶 --stage 時一律是 sandbox")
	f.StringVar(&stagingAttestedHoursFlag, "staging-attested-within-hours", "", "--stage prod 必填：上次 staging 驗證距今幾小時(0-168)")
	hotfixCmd.AddCommand(hotfixWazuhAgentSkewCmd)
}

func runHotfixWazuhAgentSkew(cmd *cobra.Command, _ []string) error {
	if hotfixSkewForceFlag && hotfixSkewPreviewOnlyFlag {
		return fmt.Errorf("--force 不能與 --preview-only 同時使用")
	}
	if err := validateStageFlags(stageFlag, stagingAttestedHoursFlag); err != nil {
		return err
	}
	if err := validateLimitFlag(limitFlag); err != nil {
		return err
	}
	timeout, err := parseDeployTimeout(hotfixSkewTimeoutFlag)
	if err != nil {
		return err
	}
	// Same defaults driver as deploy --force/--preview-only, installed before the TTY gate so
	// CI and cron can run it.
	if hotfixSkewForceFlag || hotfixSkewPreviewOnlyFlag {
		old := activePromptAutomation
		activePromptAutomation = &promptAutomation{useDefaults: true, forceApply: hotfixSkewForceFlag, previewOnly: hotfixSkewPreviewOnlyFlag}
		defer func() { activePromptAutomation = old }()
	}
	if !promptWorkflowAllowsNonTTY(hotfixStdinIsTerminal()) {
		return fmt.Errorf("pilot hotfix wazuh-agent-skew 需要互動式終端機(TTY)才能問問題；非互動場景請加 --preview-only(只印計畫)或 --force(採用預設值並直接套用)")
	}
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return err
	}
	ctx := withDeployAnsibleRuntime(cmd.Context(), runtime)
	out := cmd.OutOrStdout()

	runner := ansible.NewRunner()
	runner.Timeout = timeout
	runner.Env = append(append([]string{}, runtime.Env...), "ANSIBLE_NOCOLOR=1")
	runner.LogPath = runtime.LogPath
	runner.StderrWriter = cmd.ErrOrStderr()

	fmt.Fprintln(out, "═══ pilot hotfix wazuh-agent-skew — 移除版本比 manager 新的 Wazuh agent ═══")
	fmt.Fprintln(out)

	// Workspace-relative, not pre-joined with --dir (see runDeployInteractive).
	invInput, err := runTextPrompt(promptInventory, "Inventory 檔路徑", hotfixSkewInventoryFlag, func(path string) error {
		return validateFileExists(workspacePath(hotfixSkewDirFlag, path))
	})
	if err != nil {
		return abortOrErr(err)
	}
	inv := workspacePath(hotfixSkewDirFlag, invInput)
	if regenerated, genErr := autoRegenerateInventoryFromHosts(cmd.ErrOrStderr(), inv); genErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "警告：自動重新產生 inventory.yml 失敗（沿用現有檔案）：%v\n", genErr)
	} else if regenerated {
		fmt.Fprintf(out, "已從 hosts.yml 自動重新產生 %s\n", inv)
	}
	snapshot, err := loadDeployInventorySnapshot(ctx, inv)
	if err != nil {
		return err
	}
	if err := checkHotfixSkewInventory(snapshot); err != nil {
		return err
	}

	vault, err := promptVault(out, inv, "")
	if err != nil {
		return abortOrErr(err)
	}
	vault.AskBecomePass = promptBecome()
	if vault.AskVaultPass || vault.AskBecomePass {
		runner.Stdin = cmd.InOrStdin()
	}

	fmt.Fprintln(out, "→ 唯讀偵測：讀 manager 版本與每台 agent 主機實際安裝的版本…")
	plan, err := hotfixSkewObserve(ctx, runner, inv, vault)
	if err != nil {
		return err
	}
	fmt.Fprintln(out)
	plan.RenderPlan(out)
	fmt.Fprintln(out)
	skewed := plan.SkewedHosts()
	if len(skewed) == 0 {
		fmt.Fprintln(out, "✅ 沒有任何 agent 比 manager 新，什麼都不需要做。")
		return nil
	}
	if hotfixSkewPreviewOnlyFlag {
		fmt.Fprintf(out, "✅ --preview-only：偵測完成，%d 台主機需要處理，沒有變更任何東西。\n", len(skewed))
		return nil
	}

	decision, err := promptStageDecision(out, "hotfix wazuh-agent-skew")
	if err != nil {
		return abortOrErr(err)
	}
	if !runConfirmPrompt(promptExecutionConfirmApply, fmt.Sprintf("要移除上面 %d 台主機的 Wazuh agent 嗎？（不可復原：套件會被卸載、manager 的登記會被刪除）", len(skewed)), false) {
		fmt.Fprintln(out, "已取消，沒有變更任何東西。")
		return nil
	}

	fmt.Fprintln(out, "→ 套用（先重新偵測，再逐台處理）…")
	apply, results, err := hotfixSkewApply(ctx, runner, out, inv, vault, decision)
	if err != nil {
		return err
	}
	summary := hotfix.Summarize(plan, apply, results)
	fmt.Fprintln(out)
	summary.Render(out)
	if len(summary.Incomplete) > 0 {
		return fmt.Errorf("hotfix 沒有完成：%v 沒有回報移除完成", summary.Incomplete)
	}
	if len(summary.Removed) > 0 {
		fmt.Fprintln(out, "\n接著用 pilot deploy 單一元件 wazuh-fim 重新安裝，版本取 wazuh_version（未設定時為 manager 的版本）。")
	}
	return nil
}

// checkHotfixSkewInventory refuses early, with a plain message, an inventory the
// playbook would refuse anyway: the hotfix compares against exactly one manager.
func checkHotfixSkewInventory(snapshot deployInventorySnapshot) error {
	if n := len(snapshot.Groups["wazuh-manager"]); n != 1 {
		return fmt.Errorf("inventory 的 wazuh-manager group 必須恰好有一台主機（目前 %d 台）：hotfix 不會猜要跟哪個 manager 比較", n)
	}
	if len(snapshot.Groups["wazuh-fim"]) == 0 {
		return fmt.Errorf("inventory 的 wazuh-fim group 沒有任何主機，沒有 agent 可以偵測")
	}
	return nil
}

func hotfixSkewArgs(inv string, extra []string, vault vaultInput) []string {
	args := []string{hotfix.WazuhSkewPlaybook, "-i", inv}
	if limitFlag != "" {
		args = append(args, "--limit", limitFlag)
	}
	args = append(args, ansibleExtraVarArgs(extra, vault)...)
	return append(args, vault.becomeArgs()...)
}

// runHotfixSkewPlaybook runs the playbook and treats a non-zero exit as failure:
// ansible.Runner returns a nil error for a failed playbook, the failure is only in
// Result.ExitCode (AGENTS.md §5.8).
func runHotfixSkewPlaybook(ctx context.Context, runner *ansible.Runner, args []string) (*ansible.Result, error) {
	res, err := runner.Run(ctx, args...)
	if err != nil {
		return res, err
	}
	if res.ExitCode != 0 {
		return res, fmt.Errorf("ansible-playbook 結束碼 %d：沒有任何主機被變更之前的失敗代表整次拒絕；若是套用中途失敗，重跑同一個指令即可接續（每一步冪等）", res.ExitCode)
	}
	return res, nil
}

func hotfixSkewObserve(ctx context.Context, runner *ansible.Runner, inv string, vault vaultInput) (hotfix.Observation, error) {
	res, err := runHotfixSkewPlaybook(ctx, runner, hotfixSkewArgs(inv, []string{hotfix.ObserveModeVar}, vault))
	if err != nil {
		return hotfix.Observation{}, hotfixSkewFailure(res, err)
	}
	obs, err := hotfix.ParseObservation(res.Stdout)
	if err != nil {
		return hotfix.Observation{}, fmt.Errorf("無法判讀偵測結果，整次拒絕、沒有變更任何東西：%w", err)
	}
	return obs, nil
}

func hotfixSkewApply(ctx context.Context, runner *ansible.Runner, out io.Writer, inv string, vault vaultInput, decision stageDecision) (hotfix.Observation, []hotfix.Result, error) {
	extra := append([]string{"stage=" + decision.Stage}, decision.ConfirmVars...)
	applyRunner := *runner
	applyRunner.StdoutWriter = out
	res, err := runHotfixSkewPlaybook(ctx, &applyRunner, hotfixSkewArgs(inv, extra, vault))
	if err != nil {
		return hotfix.Observation{}, nil, hotfixSkewFailure(res, err)
	}
	obs, err := hotfix.ParseObservation(res.Stdout)
	if err != nil {
		return hotfix.Observation{}, nil, fmt.Errorf("套用結束了，但無法判讀它的回報，不當作成功：%w", err)
	}
	return obs, hotfix.ParseResults(res.Stdout), nil
}

func hotfixSkewFailure(res *ansible.Result, err error) error {
	if res == nil {
		return err
	}
	output := res.Stdout + "\n" + res.Stderr
	reasons := ""
	for _, reason := range hotfix.Refusals(output) {
		reasons += "原因：" + reason + "\n"
	}
	return fmt.Errorf("%w\n%s%s", err, reasons, ansible.FailureSummary(output))
}
